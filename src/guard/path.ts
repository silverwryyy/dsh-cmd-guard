/**
 * Path resolution. Nothing here produces a verdict.
 *
 * This module exists because `lexical.normalizePath` is one line -
 * `replace(/\\/g, '/').toLowerCase()` - and that is not a path, it is a string
 * that looks like one. Under it, `Remove-Item -Recurse $env:USERPROFILE\Documents`
 * and `Remove-Item -Recurse C:\Users\me\Documents` took two different routes
 * through every later layer, and the first one was invisible to the target
 * regexes entirely. Any judgement built on top of that is a judgement about
 * spelling.
 *
 * The contract here is narrow and deliberately boring:
 *
 *   in   a token that may or may not name a path
 *   out  either an absolute, case-folded comparison key, or `dynamic`
 *
 * `dynamic` is not a fallback for laziness. It means "the value depends on
 * state this process cannot read", and it must never be treated as safe. Every
 * branch that cannot be pinned down returns it instead of guessing: an
 * undefined variable, another user's home, a drive-relative `C:foo` (which
 * means the *current directory of C:*, not `C:\`), a device path, command
 * substitution, an expansion that will not settle.
 *
 * IO is minimised but not forbidden, unlike lexical.ts. Two things genuinely
 * need the filesystem: junction resolution (`C:\Users\All Users` IS
 * `C:\ProgramData`, and no string operation can know that) and whatever the
 * caller chooses to pass as `realpath`. It is injected rather than imported so
 * this file stays testable without touching a disk, and its absence degrades to
 * "no reparse resolution" rather than to an error.
 */

export type PathSource = 'resolved' | 'dynamic'

/**
 * Why a path could not be pinned down. Stable ids: tests and the layers above
 * both branch on these, so they are part of the contract.
 */
export type DynamicReason =
  | 'empty'
  | 'substitution'
  | 'device-path'
  | 'undefined-var'
  | 'unstable-expansion'
  | 'other-user-home'
  | 'drive-relative'
  | 'unknown-cwd'

export interface ResolvedPath {
  readonly source: PathSource
  /**
   * Absolute, forward slashes, lowercased, no trailing slash.
   * Roots keep theirs: `c:/`, `//server/share/`, `/`.
   * Empty string when `dynamic`.
   */
  readonly key: string
  /** Same shape as `key` but case preserved, for messages. Empty when `dynamic`. */
  readonly display: string
  /** Set when `source` is `dynamic`, null otherwise. */
  readonly reason: DynamicReason | null
  /**
   * A wildcard somewhere in the token. Still `resolved` - the parent directory
   * is known - but `isUnder` refuses to answer, because `C:\Win*\System32`
   * cannot be placed under a root by string comparison.
   */
  readonly hasGlob: boolean
}

export interface PathContext {
  /** Absolute base for relative tokens. Defaults to `process.cwd()`. */
  readonly cwd?: string | undefined
  /** `~` destination. Defaults to USERPROFILE, then HOME. */
  readonly home?: string | undefined
  /** Variable table. Defaults to `process.env`. */
  readonly env?: Readonly<Record<string, string | undefined>> | undefined
  /**
   * Junction / symlink resolution. Receives a key (absolute, forward slashes,
   * lowercase) and returns any spelling of the real target. Throw to mean "no
   * such file" - an unresolved path is normal and is not an error.
   */
  readonly realpath?: ((key: string) => string) | undefined
  /** Defaults to the host platform. Present so tests can pin it. */
  readonly platform?: 'win32' | 'posix' | undefined
}

type ExpandResult = { readonly ok: true; readonly text: string } | { readonly ok: false; readonly reason: DynamicReason }

const MAX_EXPANSIONS = 8
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_()]*$/

/** `\\?\` long-path prefix, which is transparent to Win32 arguments. */
const LONG_PREFIX = /^\\\\\?\\/
/** `\\.\` device namespace. Never a file, never resolvable. */
const DEVICE_PREFIX = /^\\\\\.\\/
/** A drive letter followed by neither separator nor end: `C:foo`. */
const DRIVE_ONLY = /^[A-Za-z]:$/
const DRIVE_RELATIVE = /^[A-Za-z]:[^\\/]/
const DRIVE_ABSOLUTE = /^[A-Za-z]:[\\/]/
/** Wildcards Win32 forbids in filenames, so a `?` is never literal here. */
const GLOB = /[*?]/

function dynamic(reason: DynamicReason, hasGlob = false): ResolvedPath {
  return { source: 'dynamic', key: '', display: '', reason, hasGlob }
}

function hostPlatform(): 'win32' | 'posix' {
  return typeof process !== 'undefined' && process.platform === 'win32' ? 'win32' : 'posix'
}

function platformOf(ctx: PathContext): 'win32' | 'posix' {
  return ctx.platform ?? hostPlatform()
}

function envOf(ctx: PathContext): Readonly<Record<string, string | undefined>> {
  if (ctx.env !== undefined) return ctx.env
  return typeof process !== 'undefined' ? process.env : {}
}

function cwdOf(ctx: PathContext): string | undefined {
  if (ctx.cwd !== undefined) return ctx.cwd
  return typeof process !== 'undefined' ? process.cwd() : undefined
}

function homeOf(ctx: PathContext): string | undefined {
  if (ctx.home !== undefined) return ctx.home
  const env = envOf(ctx)
  return env['USERPROFILE'] ?? env['HOME']
}

/**
 * Windows environment variables are case-insensitive; POSIX ones are not.
 * Lookup is not "try both" - the platform decides, because `$HOME` and `$home`
 * are two different variables on Linux and a guard that conflates them will
 * read a path the shell did not.
 */
function lookup(env: Readonly<Record<string, string | undefined>>, name: string, ci: boolean): string | undefined {
  const direct = env[name]
  if (direct !== undefined) return direct
  if (!ci) return undefined
  const upper = name.toUpperCase()
  for (const key of Object.keys(env)) {
    if (key.toUpperCase() === upper) return env[key]
  }
  return undefined
}

/** Strip one matching pair of surrounding quotes and the whitespace outside them. */
function stripQuotes(raw: string): string {
  const trimmed = raw.trim()
  if (trimmed.length < 2) return trimmed
  const first = trimmed[0]
  const last = trimmed[trimmed.length - 1]
  if ((first === '"' || first === "'") && last === first) return trimmed.slice(1, -1).trim()
  return trimmed
}

/**
 * `$(...)`, `${...}` that is not an environment reference, and paired
 * backticks all mean the value is produced by running something. A lone
 * backtick in PowerShell is an escape and is left alone.
 */
function hasSubstitution(text: string): boolean {
  if (text.includes('$(')) return true
  const first = text.indexOf('`')
  if (first !== -1 && text.indexOf('`', first + 1) !== -1) return true
  return false
}

/** One pass of `%VAR%` / `$env:VAR` / `${env:VAR}` expansion. */
function expandOnce(text: string, env: Readonly<Record<string, string | undefined>>, ci: boolean): ExpandResult {
  let out = ''
  let i = 0

  while (i < text.length) {
    const ch = text[i]

    if (ch === '%') {
      const end = text.indexOf('%', i + 1)
      if (end > i + 1) {
        const name = text.slice(i + 1, end)
        if (ENV_NAME.test(name)) {
          const value = lookup(env, name, ci)
          if (value === undefined) return { ok: false, reason: 'undefined-var' }
          // A value that expands to its own placeholder never settles.
          if (value === text.slice(i, end + 1)) return { ok: false, reason: 'unstable-expansion' }
          out += value
          i = end + 1
          continue
        }
      }
      out += ch
      i += 1
      continue
    }

    if (ch === '$') {
      // ${env:NAME} and ${NAME}
      if (text[i + 1] === '{') {
        const end = text.indexOf('}', i + 2)
        if (end === -1) return { ok: false, reason: 'unstable-expansion' }
        const inner = text.slice(i + 2, end)
        const envRef = /^env:([A-Za-z_][A-Za-z0-9_]*)$/i.exec(inner)
        if (envRef !== null) {
          const value = lookup(env, envRef[1] ?? '', ci)
          if (value === undefined) return { ok: false, reason: 'undefined-var' }
          if (value === text.slice(i, end + 1)) return { ok: false, reason: 'unstable-expansion' }
          out += value
          i = end + 1
          continue
        }
        // ${NAME} is a PowerShell *variable*, not an environment variable.
        // Its value is whatever the session put there, which we cannot see.
        return { ok: false, reason: 'undefined-var' }
      }

      const envRef = /^\$env:([A-Za-z_][A-Za-z0-9_]*)/i.exec(text.slice(i))
      if (envRef !== null) {
        const value = lookup(env, envRef[1] ?? '', ci)
        if (value === undefined) return { ok: false, reason: 'undefined-var' }
        if (value === envRef[0]) return { ok: false, reason: 'unstable-expansion' }
        out += value
        i += envRef[0].length
        continue
      }

      // A bare `$NAME` is a shell variable. It is not an environment
      // variable, so it is not in `env`, so there is no value to read.
      if (/^\$[A-Za-z_]/.test(text.slice(i))) return { ok: false, reason: 'undefined-var' }

      out += ch
      i += 1
      continue
    }

    out += ch
    i += 1
  }

  return { ok: true, text: out }
}

/**
 * Expand until the string stops changing. A value that itself contains a
 * reference (`A=%B%`) needs a second pass; a value that expands to something
 * containing itself never settles, and that is not a path we can name.
 */
function expandVars(text: string, ctx: PathContext): ExpandResult {
  const env = envOf(ctx)
  const ci = platformOf(ctx) === 'win32'
  let current = text

  for (let round = 0; round < MAX_EXPANSIONS; round += 1) {
    const step = expandOnce(current, env, ci)
    if (!step.ok) return step
    if (step.text === current) return { ok: true, text: current }
    current = step.text
  }

  return { ok: false, reason: 'unstable-expansion' }
}

/**
 * Win32 silently drops trailing dots and spaces from each component, so
 * `C:\Windows.` and `C:\Windows` name the same directory while comparing
 * unequal as strings. `.` and `..` are preserved - they are resolved later,
 * not trimmed.
 */
function trimComponent(seg: string): string {
  if (seg === '.' || seg === '..') return seg
  return seg.replace(/[. ]+$/, '')
}

function components(text: string): string[] {
  const out: string[] = []
  for (const raw of text.split('/')) {
    if (raw.length === 0) continue
    const seg = trimComponent(raw)
    if (seg.length === 0) continue
    out.push(seg)
  }
  return out
}

/**
 * Resolve `.` and `..`. A `..` above the root is spent, not carried: Win32 and
 * POSIX both clamp at the root, and carrying it would let `C:\..\..\Windows`
 * escape to a key no filesystem can produce.
 */
function fold(segs: readonly string[]): string[] {
  const out: string[] = []
  for (const seg of segs) {
    if (seg === '.') continue
    if (seg === '..') {
      out.pop()
      continue
    }
    out.push(seg)
  }
  return out
}

interface Rooted {
  /** Lowercased root including its trailing separator. */
  readonly prefix: string
  /** Remaining components, original case. */
  readonly rest: string[]
}

/** Split an absolute, forward-slash path into root + components. Null if malformed. */
function splitRoot(text: string): Rooted | null {
  if (DRIVE_ABSOLUTE.test(text)) {
    const drive = (text[0] ?? '').toLowerCase()
    return { prefix: drive + ':/', rest: components(text.slice(2)) }
  }

  if (text.startsWith('//')) {
    const parts = components(text.slice(2))
    const server = parts[0]
    const share = parts[1]
    if (server === undefined || share === undefined) return null
    return { prefix: `//${server.toLowerCase()}/${share.toLowerCase()}/`, rest: parts.slice(2) }
  }

  if (text.startsWith('/')) return { prefix: '/', rest: components(text.slice(1)) }

  return null
}

/** Absolute + folded spelling, case preserved. Null when the root is malformed. */
function absoluteDisplay(text: string): string | null {
  const rooted = splitRoot(text)
  if (rooted === null) return null
  const folded = fold(rooted.rest)
  return rooted.prefix + folded.join('/')
}

function fromAbsolute(text: string): ResolvedPath {
  const hasGlob = GLOB.test(text)
  const display = absoluteDisplay(text)
  if (display === null) return dynamic('device-path', hasGlob)
  return { source: 'resolved', key: display.toLowerCase(), display, reason: null, hasGlob }
}

/**
 * The base a relative token is resolved against, and whether the caller said so.
 *
 * `stated` is not decoration. A verdict that rests on an assumed base is a
 * verdict that changes when the hosting process is started from somewhere
 * else, and the message an operator sees has to be able to say that out loud.
 * The order is deliberate: an explicit `cwd` first, then the workspace root
 * (an explicit statement about this project even when it is not a statement
 * about the shell), then - only when nothing was said - the process cwd, which
 * is what the shell child would inherit anyway.
 */
export interface PathBase {
  readonly cwd: string | undefined
  readonly stated: boolean
}

export function baseOf(cwd: string | undefined, workspaceRoot: string | undefined): PathBase {
  if (cwd !== undefined && cwd.length > 0) return { cwd, stated: true }
  if (workspaceRoot !== undefined && workspaceRoot.length > 0) return { cwd: workspaceRoot, stated: false }
  const processCwd = typeof process !== 'undefined' ? process.cwd() : undefined
  return { cwd: processCwd, stated: false }
}

/**
 * Turn one token into either a comparison key or `dynamic`.
 *
 * Order matters. The `\\?\` prefix is stripped before anything reads the path,
 * because it hides the drive letter from every later test. Variables are
 * expanded before `~`, so `%APPDATA%` and `~` reach the same branch. The
 * absolute/relative decision comes last, because both expansion and the tilde
 * can turn a relative token into an absolute one.
 */
export function resolvePath(raw: string, ctx: PathContext = {}): ResolvedPath {
  let text = stripQuotes(raw)
  if (text.length === 0) return dynamic('empty')
  if (hasSubstitution(text)) return dynamic('substitution')

  if (DEVICE_PREFIX.test(text)) return dynamic('device-path')

  const long = LONG_PREFIX.exec(text)
  if (long !== null) {
    const rest = text.slice(long[0].length)
    // `\\?\UNC\server\share` is the long-path spelling of a network path.
    if (/^UNC\\/i.test(rest)) text = '\\\\' + rest.slice(4)
    // `\\?\Volume{...}` names a volume, not a file in it.
    else if (/^Volume\{/i.test(rest)) return dynamic('device-path')
    else text = rest
  }

  const expanded = expandVars(text, ctx)
  if (!expanded.ok) return dynamic(expanded.reason, GLOB.test(text))
  text = expanded.text

  if (text === '~' || text.startsWith('~/') || text.startsWith('~\\')) {
    const home = homeOf(ctx)
    if (home === undefined || home.length === 0) return dynamic('undefined-var')
    text = home + text.slice(1)
  } else if (/^~[^\\/]/.test(text)) {
    // `~other` is another user's home. We do not know where that is.
    return dynamic('other-user-home')
  }

  text = text.replace(/\\/g, '/')
  const hasGlob = GLOB.test(text)

  if (DRIVE_ABSOLUTE.test(text)) return fromAbsolute(text)

  if (text.startsWith('//')) {
    const rooted = splitRoot(text)
    // `\\server` alone is a server, not a share, so not a path.
    if (rooted === null) return dynamic('device-path', hasGlob)
    return fromAbsolute(text)
  }

  if (text.startsWith('/')) {
    if (platformOf(ctx) === 'posix') return fromAbsolute(text)
    // On Windows a leading separator is relative to *the current drive*, whose
    // letter lives outside the command string.
    const cwd = cwdOf(ctx)
    if (cwd === undefined) return dynamic('unknown-cwd', hasGlob)
    const drive = cwd.slice(0, 2)
    if (!DRIVE_ABSOLUTE.test(cwd) || !/^[A-Za-z]:$/.test(drive)) return dynamic('unknown-cwd', hasGlob)
    return fromAbsolute(drive + text)
  }

  if (DRIVE_ONLY.test(text) || DRIVE_RELATIVE.test(text)) {
    // `C:foo` is `foo` relative to C:'s *current directory*, which is not `C:\`.
    return dynamic('drive-relative', hasGlob)
  }

  const cwd = cwdOf(ctx)
  if (cwd === undefined || cwd.length === 0) return dynamic('unknown-cwd', hasGlob)

  const base = fromAbsolute(cwd.replace(/\\/g, '/'))
  if (base.source !== 'resolved') return dynamic('unknown-cwd', hasGlob)

  const joined = base.display.replace(/\/$/, '') + '/' + text
  const resolved = fromAbsolute(joined)
  if (resolved.source !== 'resolved') return resolved

  return { ...resolved, hasGlob: resolved.hasGlob || hasGlob }
}

/**
 * Resolve reparse points. Separate from `resolvePath` because it is the only
 * step that may touch a disk, and because a caller with no filesystem access
 * should still get correct answers for every non-junction path.
 *
 * A throw means "no such file". That is not a failure: a path that does not
 * exist cannot be a junction, so the lexical answer stands.
 */
export function resolveReparse(
  path: ResolvedPath,
  ctx: PathContext = {},
): ResolvedPath {
  if (path.source !== 'resolved' || path.hasGlob) return path
  const realpath = ctx.realpath
  if (realpath === undefined) return path

  let real: string
  try {
    real = realpath(path.key)
  } catch {
    return path
  }

  const again = resolvePath(real, { ...ctx, cwd: path.key, realpath: undefined })
  if (again.source !== 'resolved') return again
  return again
}

/** Full pipeline: lexical resolution, then reparse points. */
export function resolveFullPath(raw: string, ctx: PathContext = {}): ResolvedPath {
  return resolveReparse(resolvePath(raw, ctx), ctx)
}

/** Two resolved paths naming the same location. */
export function samePath(a: ResolvedPath, b: ResolvedPath): boolean {
  if (a.source !== 'resolved' || b.source !== 'resolved') return false
  return a.key === b.key
}

/**
 * True when `child` is `parent` or sits underneath it.
 *
 * False for anything unresolved or wildcarded. That is the point: this
 * function answers "can I prove containment", and "no" is the safe half of
 * that. A `C:\Win*\System32` token is not under `C:\Windows` by string
 * comparison, and pretending otherwise would let a wildcard walk past a root
 * check.
 */
export function isUnder(child: ResolvedPath, parent: ResolvedPath): boolean {
  if (child.source !== 'resolved' || parent.source !== 'resolved') return false
  if (child.hasGlob || parent.hasGlob) return false
  if (child.key === parent.key) return true
  const base = parent.key.endsWith('/') ? parent.key : parent.key + '/'
  return child.key.startsWith(base)
}

/** Convenience for callers that only need the comparison key. Null when dynamic. */
export function pathKey(raw: string, ctx: PathContext = {}): string | null {
  const resolved = resolvePath(raw, ctx)
  return resolved.source === 'resolved' ? resolved.key : null
}
