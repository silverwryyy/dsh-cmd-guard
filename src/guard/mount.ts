/**
 * The seam between DSH and the parser.
 *
 * Everything here is driven by the shipped type declarations, not by memory:
 *
 *   exec.name       string        the tool name (`bash`, `pwsh`, ...)
 *   exec.arguments  unknown       already-parsed arguments
 *   ctx.tools.guard(ToolGuard)    (exec) => string | undefined, deny only
 *   ctx.on('tools/pre-execute')   waterfall (exec, next) => PreToolDecision
 *
 * Two facts shape the design:
 *
 * 1. `guard` has no allow exit. It runs after every pre-execute listener and
 *    after approval resolves, so a denial registered there cannot be softened
 *    by listener ordering or by an operator saying yes. That is the right home
 *    for hard rules and the wrong home for anything a human may override.
 *
 * 2. `pre-execute` is a waterfall returning a discriminated union. A handler
 *    that returns the wrong shape is not rejected - the registry simply does
 *    not see a decision. Getting this shape wrong means the gate silently
 *    does nothing, so the shape is validated in tests, not assumed.
 *
 * `cancel` is deliberately never produced. It means "the operator pressed
 * stop", which is not a statement this plugin is entitled to make.
 */
import type { GuardResult } from './types.js'
import type { GuardInput } from './types.js'
import { DATA_KEYS, EXEC_TOOLS } from './entry.js'
import { looksLikeCommandString } from './shape.js'

/** Argument keys a command has been seen under, most specific first. */
const COMMAND_KEYS: ReadonlyArray<string> = ['command', 'cmd', 'script', 'commandLine', 'command_line']

/** Argument keys a stated intent has been seen under. */
const INTENT_KEYS: ReadonlyArray<string> = ['description', 'why', 'reason', 'intent', 'purpose']


/** Values longer than this are documents; a command line is not 2 KB. */
// The exclusion itself lives in entry.ts so the library entry point and the
// mount agree. See the note there; the residual risk is stated in the README.
const MAX_COMMAND_LENGTH = 2048


/** The framework's four-state pre-dispatch decision, mirrored structurally. */
export type PreToolDecision =
  | { readonly kind: 'allow' }
  | { readonly kind: 'deny'; readonly reason: string }
  | { readonly kind: 'cancel' }
  | {
      readonly kind: 'ask'
      readonly reason?: string
      readonly displayReason?: { readonly en: string; readonly [locale: string]: string }
    }

/**
 * Runtime shape check. Discriminant plus required field per branch. Nothing
 * else - anything stricter would reject a decision the registry accepts, and
 * anything looser would let a typo through as a no-op gate.
 */
export function isPreToolDecision(value: unknown): value is PreToolDecision {
  if (typeof value !== 'object' || value === null) return false
  const v = value as { kind?: unknown; reason?: unknown }
  switch (v.kind) {
    case 'allow':
    case 'cancel':
      return true
    case 'deny':
      return typeof v.reason === 'string' && v.reason.length > 0
    case 'ask':
      return v.reason === undefined || typeof v.reason === 'string'
    default:
      return false
  }
}

/** The subset of ToolExecution this module reads. */
export interface ExecutionLike {
  readonly name?: unknown
  readonly arguments?: unknown
}

/** What the mount decided to do with one call. */
export type Mapping =
  | { readonly kind: 'call'; readonly input: GuardInput }
  | { readonly kind: 'skip'; readonly reason: string }

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {}
}

function firstString(args: Record<string, unknown>, keys: ReadonlyArray<string>): string | undefined {
  for (const key of keys) {
    const v = args[key]
    if (typeof v === 'string' && v.trim().length > 0) return v
  }
  return undefined
}

/**
 * Turn one dispatched call into parser input, or explain why it is not one.
 *
 * Key order matters: the known command keys are tried before the unknown-tool
 * scan, so a tool that carries `command` is never judged by a heuristic.
 */
export function toGuardInput(exec: ExecutionLike): Mapping {
  if (typeof exec.name !== 'string' || exec.name.length === 0) {
    return { kind: 'skip', reason: 'call carries no tool name' }
  }

  const name = exec.name
  const args = asRecord(exec.arguments)
  const intent = firstString(args, INTENT_KEYS)

  // Every populated command key, not just the one that wins. One call
  // carrying both `command` and `cmd` audits one string and may run the
  // other; the entry layer turns that into an ask.
  const populated = COMMAND_KEYS.filter((k) => {
    const v = args[k]
    return typeof v === 'string' && v.trim().length > 0
  })

  for (const key of COMMAND_KEYS) {
    const raw = args[key]
    if (typeof raw === 'string' && raw.trim().length > 0) {
      return {
        kind: 'call',
        input: { cmd: raw, why: intent, tool: name, commandSource: key, commandKeys: populated },
      }
    }
  }

  // An empty `command` on a known shell tool is its own problem, but it is not
  // this module's verdict to make: the tool itself will reject it.
  if (EXEC_TOOLS.has(name.toLowerCase())) {
    return { kind: 'skip', reason: `"${name}" carries no command argument` }
  }

  // Unknown tool: scan string arguments that are not payload data for a
  // command shape.
  for (const [key, value] of Object.entries(args)) {
    if (typeof value !== 'string') continue
    if (DATA_KEYS.has(key.toLowerCase())) continue
    if (value.length > MAX_COMMAND_LENGTH) continue
    if (!looksLikeCommandString(value)) continue
    return {
      kind: 'call',
      input: { cmd: value, why: intent, tool: name, commandSource: key },
    }
  }

  return { kind: 'skip', reason: `"${name}" carries no command-shaped argument` }
}

/**
 * Adapter for `ctx.tools.guard`, which can only deny.
 *
 * Returning a reason denies; returning undefined leaves the call untouched.
 * A pass therefore becomes undefined rather than an active allow, because this
 * mount has no way to grant anything - and claiming otherwise is how a guard
 * ends up believing it widened a permission it never held.
 */
export function toHardDeny(result: GuardResult): string | undefined {
  if (result.verdict !== 'deny') return undefined
  return `[${result.code}] ${result.reason}`
}

/**
 * Adapter for the `tools/pre-execute` waterfall.
 *
 * `null` means "defer": the handler must return `next()` instead of a decision,
 * otherwise every listener mounted after this one is skipped.
 */
export function toDecision(result: GuardResult): PreToolDecision | null {
  switch (result.verdict) {
    case 'pass':
      return null
    case 'deny':
      return { kind: 'deny', reason: `[${result.code}] ${result.reason}` }
    case 'ask':
      return {
        kind: 'ask',
        reason: `[${result.code}] ${result.reason}`,
        displayReason: {
          en: `Allow this command? ${result.code}: ${result.reason}`,
          zh: `是否允许执行该命令？${result.code}：${result.reason}`,
        },
      }
  }
}
