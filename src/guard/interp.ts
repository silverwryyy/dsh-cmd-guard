/**
 * Layer 5: interpreters.
 *
 * The plugin performs no IO and never opens the script. "The file exists" is
 * therefore not an audit, and a rule based on existence would hand out a
 * complete bypass: write a file, then run it. The only defensible line is
 * where the path comes from.
 *
 * Two identity rules here are not cosmetic. Both were measured bypasses
 * against the first draft:
 *
 *   - `INTERPRETERS.has(head)` compared the entire first token, so
 *     `C:\Python39\python.exe`, `python3.11`, `node18` and `/usr/bin/python3`
 *     all fell through as if they were ordinary programs.
 *   - `INLINE_FLAGS` was an exact-match set, so bundled short flags (`-uc`,
 *     `-pe`, `-ep`) read as an ordinary script call with no script.
 */
import type { Finding, GuardInput, GuardState } from './types.js'
import {
  baseName,
  hasParentEscape,
  isAbsolutePath,
  isInsideWorkspace,
  isVolatilePath,
  normalizePath,
  tokenize,
} from './lexical.js'

const INTERPRETERS = new Set([
  'python',
  'python3',
  'py',
  'node',
  'nodejs',
  'deno',
  'bun',
  'ruby',
  'perl',
  'php',
  'lua',
  'npx',
  'pnpx',
  'bunx',
  'pip',
  'pip3',
  'pipx',
])

/** Fetch-and-execute hosts: the payload does not exist on disk yet. */
const FETCH_EXEC = new Set(['npx', 'pnpx', 'bunx'])

/**
 * Packages that are a local build toolchain rather than an arbitrary fetch.
 *
 * This is a measured false positive, not a convenience: `npx tsc -p
 * tsconfig.json` is this project's own build, and asking for approval on every
 * run teaches the operator to click through. The allowlist is deliberately
 * short and excludes anything that downloads and runs a package's own scripts
 * (there is no `npm` here, no `create-*`, no `vite create`).
 */
const LOCAL_TOOLCHAIN = new Set([
  'tsc',
  'tsc-alias',
  'typescript',
  'eslint',
  'prettier',
  'vitest',
  'jest',
  'tsup',
  'esbuild',
  'vite',
  'rollup',
  'rimraf',
  'tsx',
  'ts-node',
])

const INLINE_FLAGS = new Set(['-c', '-e', '--eval', '-command', 'eval'])
const STDIN_TARGETS = new Set(['-', 'con', '/dev/stdin', '/dev/fd/0'])
const QUERY_FLAGS = new Set(['-v', '--version', '-h', '--help'])

function ask(code: string, reason: string): Finding {
  return { layer: 'interp', verdict: 'ask', code, reason }
}

/**
 * Resolve the interpreter behind a token: strip the path, the `.exe` suffix
 * and a version suffix, then look for a known name.
 *
 * `C:\Python39\python.exe` -> python
 * `python3.11`             -> python3
 * `node18`                 -> node
 * `py`                     -> py
 */
export function interpreterOf(token: string): string | undefined {
  const base = baseName(token).toLowerCase()
  const noExt = base.endsWith('.exe') ? base.slice(0, -4) : base

  const candidates: string[] = [noExt]

  // python3.11 -> python3 (keep the major, drop the patch series)
  const noPatch = noExt.replace(/(\.\d+)+$/, '')
  if (noPatch !== noExt) candidates.push(noPatch)

  // node18 -> node
  const noDigits = noPatch.replace(/\d+$/, '')
  if (noDigits !== noPatch) candidates.push(noDigits)

  for (const c of candidates) {
    if (INTERPRETERS.has(c)) return c
  }
  return undefined
}

/**
 * Bundled short flags. `-uc` is `-u -c`, `-pe` is `-p -e`. Only `c` and `e`
 * matter: they are the ones that carry a program body. `-Bu` carries none, so
 * treating every bundle as inline would be a false positive on normal runs.
 */
export function isInlineFlag(token: string): boolean {
  if (INLINE_FLAGS.has(token)) return true
  if (!/^-[a-z]{2,}$/i.test(token)) return false
  return /[ce]/i.test(token.slice(1))
}

/**
 * A local toolchain invocation, as opposed to fetching and running a package.
 *
 * The first non-flag word is the package. npx's own options must come before
 * that word, so a local package name in first position means every later flag
 * belongs to the package, not to npx. That distinction is not cosmetic:
 * `tsc -p tsconfig.json` uses `-p` for "project", while npx's `-p` means
 * "package". Reading them as the same thing made this project's own build ask
 * on every run.
 */
function isLocalToolchain(rest: readonly string[]): boolean {
  let i = 0
  while (i < rest.length && rest[i]?.startsWith('-') === true) i += 1

  const pkg = rest[i]?.toLowerCase()
  if (pkg === undefined || !LOCAL_TOOLCHAIN.has(pkg)) return false

  // Options before the package name belong to npx itself; `-c` / `--call` run
  // an arbitrary shell command and `-p` / `--package` swaps the package.
  return !rest.slice(0, i).some((t) => {
    const l = t.toLowerCase()
    return l === '-c' || l === '--call' || l === '-p' || l === '--package'
  })
}

/**
 * Modules reachable through `-m` whose effect is not "run this file".
 *
 * The set is about capability, not about the module's name: installing a
 * package runs its build backend, a `*.server` module publishes the working
 * directory, and a debugger is an interactive shell by another route.
 */
const RISKY_MODULE =
  /^(?:pip\d*|ensurepip|http\.server|simplehttpserver|smtpd|cgi\.?httpserver|pdb|pty|rlcompleter)$/

export function check(input: GuardInput, state: GuardState): Finding | null {
  const tokens = tokenize(input.cmd)
  const rawHead = tokens[0]
  if (rawHead === undefined) return null

  const head = interpreterOf(rawHead)
  if (head === undefined) return null

  const rest = tokens.slice(1)
  const lowered = rest.map((t) => t.toLowerCase())

  // `node -v` prints a version and runs nothing. This is the one shape that
  // may pass without inspecting a path.
  if (rest.length === 1 && QUERY_FLAGS.has(lowered[0] ?? '')) return null

  if (FETCH_EXEC.has(head) && !isLocalToolchain(rest)) {
    return ask(
      'INTERP_FETCH_EXECUTE',
      `"${head}" downloads and runs a package that does not exist on disk yet. There is nothing local to audit.`,
    )
  }

  const inline = lowered.find((t) => isInlineFlag(t))
  if (inline !== undefined) {
    return ask(
      'INTERP_INLINE_BODY',
      `Inline program body ("${inline}"). The shape is unauditable by definition, regardless of what the body does.`,
    )
  }

  if (lowered.some((t) => STDIN_TARGETS.has(t))) {
    return ask(
      'INTERP_STDIN',
      'Program text arrives on stdin or a device path. There is no file argument, so an existence check would miss this entirely.',
    )
  }

  // `-m` names an installed module. Unlike `-c` it cannot carry a body, so
  // there is no code to audit and no path to check - which is why asking on
  // every `-m` was a false positive: `python -m pytest` is an ordinary
  // read-only test run, and with no approval UI composed ask means deny.
  // The module is judged by what it can do instead: install, serve, or open a
  // shell. Everything else is a normal program invocation.
  const moduleAt = lowered.indexOf('-m')
  if (moduleAt >= 0) {
    const mod = lowered[moduleAt + 1] ?? ''
    if (RISKY_MODULE.test(mod)) {
      return ask(
        'INTERP_MODULE_SELECTOR',
        `"-m ${mod}" runs a module that installs, serves the network, or opens an interactive shell, rather than a local script.`,
      )
    }
  }

  const workspaceRoot = state.workspaceRoot ?? process.cwd()

  if (head === 'pip' || head === 'pip3' || head === 'pipx') {
    const isInstall = lowered.includes('install')
    const localSource = rest.some((t) => t === '.' || t === './' || /^[\\/]/.test(t))
    if (isInstall && localSource) {
      return ask(
        'INTERP_LOCAL_BUILD',
        'Local install runs the package build backend, which is arbitrary code at install time.',
      )
    }
  }

  // The first non-flag argument is the script target.
  const target = rest.find((t) => !t.startsWith('-'))
  if (target === undefined) return null

  if (isVolatilePath(target)) {
    return ask(
      'INTERP_VOLATILE_PATH',
      `"${target}" lives under a temp root any process on the machine can write to. That is not a provenance claim.`,
    )
  }

  if (isAbsolutePath(target)) {
    if (!isInsideWorkspace(target, workspaceRoot)) {
      return ask(
        'INTERP_OUTSIDE_WORKSPACE',
        `"${target}" is outside the workspace. The operator cannot see the target without leaving the project.`,
      )
    }
  } else if (hasParentEscape(target)) {
    return ask(
      'INTERP_PARENT_ESCAPE',
      `"${target}" climbs above the workspace root with "..". It only looks relative.`,
    )
  }

  // TOCTOU: write-then-run in the same session. Judging the two independently
  // is a complete bypass, so the guard keeps a short-lived write ledger.
  const recent = state.recentWrites ?? []
  const wanted = normalizePath(target)
  const written = recent.some((w) => {
    const n = normalizePath(w)
    return n === wanted || n.endsWith('/' + wanted)
  })
  if (written) {
    return ask(
      'INTERP_RECENT_WRITE',
      `"${target}" was written earlier in this session and is being executed immediately. Write-then-run defeats any per-command check.`,
    )
  }

  // Falls through: workspace-relative explicit script, no escape. Note what
  // this does NOT assert: the file was never opened.
  return null
}
