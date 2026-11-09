/**
 * Layer 4: unwrapping.
 *
 * A host that runs another program, or an argument that forwards a payload, is
 * a second command hidden inside the first. We do not raise the inner verdict
 * to deny: the outer layer is what the operator actually approved, and denying
 * it would deny something the operator never saw. Ask instead.
 *
 * The one exception is a hard deny inside the forwarded text. `cmd /c "rm -rf
 * /"` should be a deny, not an ask, because the inner statement is the thing
 * that runs and it is unambiguously forbidden.
 */
import type { Finding, GuardInput, GuardState } from './types.js'
import { baseName, tokenize } from './lexical.js'
import { check as rulesCheck } from './rules.js'

const SHELL_HOSTS = new Set([
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'pwsh.exe',
  'sh',
  'bash',
  'zsh',
  'wsl',
  'cscript',
  'wscript',
  'mshta',
  'rundll32',
  'regsvr32',
])

const HOST_FLAGS = new Set(['/c', '/k', '-c', '-command', '-encodedcommand', '-enc', '-e'])

/** Verbs whose presence after a passthrough marker means a real payload. */
const PAYLOAD_VERBS = new Set([
  'del',
  'erase',
  'rd',
  'rmdir',
  'rm',
  'remove-item',
  'ri',
  'format',
  'reg',
  'shutdown',
  'taskkill',
  'powershell',
  'cmd',
  'curl',
  'wget',
  'invoke-expression',
])

/**
 * Resolve the host behind a token.
 *
 * Measured bypass: `%COMSPEC% /c rm -rf /` passed. The host was written as an
 * environment expansion, so no name in the set matched. `%COMSPEC%` and
 * `$SHELL` are the shell by definition, so they are resolved rather than
 * guessed at.
 */
function hostOf(token: string): string {
  const bare = baseName(token).toLowerCase()

  const win = /^%([a-z0-9_]+)%$/.exec(bare)
  const posix = /^\$(?:\{([a-z0-9_]+)\}|([a-z0-9_]+))$/.exec(bare)
  const name = win?.[1] ?? posix?.[1] ?? posix?.[2]

  if (name === 'comspec') return 'cmd'
  if (name === 'shell') return 'sh'
  return bare
}

export function check(input: GuardInput, state: GuardState, depth = 0): Finding | null {
  const tokens = tokenize(input.cmd)
  const head = tokens[0]
  if (head === undefined) return null

  const host = hostOf(head)

  if (SHELL_HOSTS.has(host)) {
    const flagIndex = tokens.findIndex((t) => HOST_FLAGS.has(t.toLowerCase()))
    if (flagIndex !== -1) {
      // The forwarded text is what actually runs. If it is a hard deny, say
      // so; an ask here would understate a forbidden command.
      const inner = tokens.slice(flagIndex + 1).join(' ')
      if (inner.length > 0) {
        const escalated = rulesCheck({ cmd: inner }, state)
        if (escalated !== null && escalated.verdict === 'deny') return escalated

        // One level is not enough: `bash -c "bash -c 'rm -rf /'"` came back
        // ask, while the innermost statement is the one that runs. Recursion
        // is bounded because each level strips one host, but the bound is
        // explicit so a cycle cannot hang the pipeline again.
        if (depth < 4) {
          const deeper = check({ cmd: inner }, state, depth + 1)
          if (deeper !== null && deeper.verdict === 'deny') return deeper
        }
      }

      return {
        layer: 'unwrap',
        verdict: 'ask',
        code: 'UNWRAP_NESTED_SHELL',
        reason: `"${head} ${tokens[flagIndex] ?? ''}" runs a second command line. The inner command is what will actually execute.`,
      }
    }
  }

  // Argument passthrough: `--` followed by a destructive verb means the outer
  // program is a wrapper forwarding into a shell. Real case from this
  // workspace: tools\run_bg.py forwarded "del /s /q D:\".
  const sep = tokens.indexOf('--')
  if (sep !== -1) {
    const rest = tokens.slice(sep + 1)
    const verb = rest.find((t) => PAYLOAD_VERBS.has(t.toLowerCase()))
    if (verb !== undefined) {
      const escalated = rulesCheck({ cmd: rest.join(' ') }, state)
      if (escalated !== null && escalated.verdict === 'deny') return escalated

      return {
        layer: 'unwrap',
        verdict: 'ask',
        code: 'UNWRAP_ARG_PASSTHROUGH',
        reason: `Arguments after "--" forward "${verb}" into another program. The wrapper is not the whole command.`,
      }
    }
  }

  // Config injection: a benign-looking flag overrides an execution hook.
  const injected = tokens.findIndex((t) => t.toLowerCase() === '-c')
  if (injected > 0 && host === 'git') {
    const value = tokens[injected + 1]
    if (value !== undefined && value.includes('=')) {
      return {
        layer: 'unwrap',
        verdict: 'ask',
        code: 'UNWRAP_CONFIG_INJECTION',
        reason: `"-c ${value}" overrides a git execution hook (pager, alias, or similar).`,
      }
    }
  }

  return null
}
