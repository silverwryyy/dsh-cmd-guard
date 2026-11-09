/**
 * Layer 0: tool identity.
 *
 * This layer exists because of one concrete near-miss. The first draft assumed
 * the command tool was called `run_command` and took `cmd`. The shipped tools
 * are `bash` and `pwsh`, and they take `command`. A guard written against the
 * assumed names installs cleanly, activates cleanly, and intercepts nothing -
 * which is worse than failing to install, because it looks like it is working.
 *
 * So: anything that is not a known execution tool, but is passed a
 * command-shaped string, is an ask. Not a deny - a new shell tool is a
 * legitimate thing for the harness to grow. Just not something this parser
 * has any evidence about.
 */
import type { Finding, GuardInput, GuardState } from './types.js'
import { looksLikeCommandString } from './shape.js'

/**
 * Tool names DSH dispatches commands through.
 *
 * Verified against the shipped type declarations of 0.2.x: the POSIX shell
 * tool registers as `bash`, the Windows one as `pwsh`, and the persistent
 * variant reuses `bash` (same registered name, so name matching covers it).
 *
 * The rest of the set is deliberate over-inclusion. A tool that runs a command
 * and is named something obvious here should be treated as a command source,
 * even if this build never registers it.
 */
export const EXEC_TOOLS: ReadonlySet<string> = new Set([
  'bash',
  'sh',
  'zsh',
  'fish',
  'pwsh',
  'powershell',
  'powershell.exe',
  'pwsh.exe',
  'cmd',
  'cmd.exe',
  'shell',
  'terminal',
  'run_command',
  'exec',
])

/**
 * Tools that historically carried the command under `cmd`.
 *
 * Only these tolerate the short key. `bash` and `pwsh` are verified to take
 * `command`; accepting `cmd` for them would mean a call that renames the key
 * - the exact silent-rename failure this layer exists to catch - slides
 * through as if nothing happened. Measured: `pwsh` handed `{cmd: "git status"}`
 * passed, because `cmd` was globally tolerated.
 */
const LEGACY_CMD_TOOLS: ReadonlySet<string> = new Set(['run_command', 'exec'])

/**
 * Keys the command legitimately arrives under, per tool.
 *
 * `command` is the shipped key for the shell tools. Anything outside the set
 * for that tool is drift and gets surfaced rather than trusted.
 */
export function primaryKeysFor(tool: string): ReadonlySet<string> {
  return LEGACY_CMD_TOOLS.has(tool.toLowerCase())
    ? new Set(['command', 'cmd'])
    : new Set(['command'])
}

/** Keys every execution tool may carry without it being drift. */
export const PRIMARY_COMMAND_KEYS: ReadonlySet<string> = new Set(['command', 'cmd'])

/**
 * Keys whose value is document or payload data, never a command line.
 *
 * Two independent reasons this lives here rather than only in the mount:
 *
 * 1. The unknown-tool scan reads every string argument. Without an exclusion,
 *    `write_file` with a README that mentions `del /s /q` was surfaced as a
 *    command, and so was writing this package's own test corpus. With no
 *    approval UI composed, ask degrades to deny, which made `write_file`
 *    effectively unusable.
 * 2. `verify()` is exported and tests call it directly with a `commandSource`.
 *    The exclusion has to hold at the layer, not only at the seam, or the same
 *    false positive comes back through the library entry point.
 *
 * This is a name-based exclusion and therefore a residual risk: a tool that
 * genuinely executes the string in `content` would be skipped. Stated in the
 * README, not papered over.
 */
export const DATA_KEYS: ReadonlySet<string> = new Set([
  'content',
  'contents',
  'body',
  'text',
  'new_string',
  'old_string',
  'new_str',
  'old_str',
  'patch',
  'diff',
  'message',
  'query',
  'prompt',
  'note',
  'summary',
  'explanation',
  'description',
  'why',
  'reason',
  'intent',
  'purpose',
])

function ask(code: string, reason: string): Finding {
  return { layer: 'entry', verdict: 'ask', code, reason }
}

export function check(input: GuardInput, _state: GuardState): Finding | null {
  // The string came from a payload key, so it is a document, not a command
  // line - whatever the tool name is. Checked before the tool-name branch on
  // purpose: `write_file` must not be flagged for what its `content` says.
  const source = input.commandSource
  if (source !== undefined && DATA_KEYS.has(source.toLowerCase())) return null

  // Shape, not identity: how many command keys a call carries does not
  // depend on whether a tool name is set. This sat after the tool guard, so a
  // direct verify() call carrying both \`cmd\` and \`command\` was never checked.
  // Two command keys in one call: the parser read one of them, and the
  // tool may run the other. This is not drift, it is divergence, and no
  // token analysis of a single string can resolve it. Checked before the
  // tool-name branch because an unfamiliar tool returned early and the
  // comparison never happened.
  if (input.commandKeys !== undefined && input.commandKeys.length > 1) {
    return ask(
      'ENTRY_COMMAND_KEY_AMBIGUOUS',
      `The call carries more than one command key (${input.commandKeys.join(', ')}). The string below was read from "${source ?? 'an unnamed key'}", but which one runs is not something this parser can establish.`,
    )
  }

  // Direct calls (tests, the exported verify()) carry no tool name. Layer 0
  // has nothing to say about those, and inventing an opinion would make the
  // pipeline unusable as a library.
  if (input.tool === undefined) return null

  const tool = input.tool.toLowerCase()

  if (!EXEC_TOOLS.has(tool)) {
    // Not every bare string argument is a command. `read_file` carries a path,
    // and with no approval UI composed ask degrades to deny, so a shape-free
    // scan made every file read impossible. Measured false positive; the shape
    // heuristic now decides instead of the argument's existence.
    if (!looksLikeCommandString(input.cmd)) return null
    return ask(
      'ENTRY_UNKNOWN_EXEC_TOOL',
      `"${input.tool}" is not a shell tool this parser knows, yet it was handed a command-shaped argument. A new or renamed execution tool fails open, so it is surfaced instead.`,
    )
  }

  if (source !== undefined && !primaryKeysFor(tool).has(source.toLowerCase())) {
    return ask(
      'ENTRY_COMMAND_KEY_DRIFT',
      `The command arrived under "${source}", which is not a key "${tool}" takes. Either the tool schema changed or a wrapper is reshaping arguments; both invalidate the assumption that the string below is the whole command.`,
    )
  }

  return null
}
