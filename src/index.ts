/**
 * dsh-cmd-guard
 *
 * Structural command parser with intent binding for DeepSeek Harness.
 *
 * Two modules live in this one package and are mounted from a single `apply`:
 *
 *   guard      - parse a command string into structure, emit a verdict
 *   changeset  - ledger + rollback + promotion for self-patches (NOT SHIPPED)
 *
 * Why one insert line instead of two: mounting the same package name twice
 * gives two module instances with independent state. Debugging two guards
 * that disagree is not worth the isolation.
 *
 * Mount map, verified against the shipped declarations - not assumed:
 *
 *   ctx.tools.guard(ToolGuard)          (exec) => string | undefined  (deny only)
 *   ctx.on('tools/pre-execute', ...)    waterfall (exec, next) => PreToolDecision
 *   ctx.on('tools/post-execute', ...)   waterfall (exec, result, next) => PostToolDecision
 *
 * The names matter. An earlier draft mounted `run_command` and read `cmd`; the
 * shipped tools are `bash` / `pwsh` and read `command`. That guard installs,
 * activates, and intercepts nothing. The entry layer exists because of it.
 *
 * Approval semantics, four states not two:
 *   allow / deny      the decision itself
 *   cancel            the operator pressed stop - never produced here
 *   ask               only proceeds on `allowed-once`; with no approval service
 *                     composed, or on an agent-less call, it degrades to deny
 */
import type { GuardState } from './guard/types.js'
import { verify } from './guard/verify.js'
import { isPreToolDecision, toDecision, toGuardInput, toHardDeny, type ExecutionLike } from './guard/mount.js'

export const name = 'dsh-cmd-guard'

/** ctx.tools for the hard-deny mount; the waterfall events arrive via ctx.on. */
export const inject = ['tools'] as const

export interface CmdGuardConfig {
  guard?: {
    enabled?: boolean
    /** Absolute root used for path provenance. Defaults to the process cwd. */
    workspaceRoot?: string
    /**
     * Track files written earlier in the session so write-then-run is not
     * judged as two unrelated calls. On by default: the TOCTOU hole is wide
     * open otherwise, and this listener only observes.
     */
    recordWrites?: boolean
  }
  changeset?: {
    /** Accepted by the config, not implemented. Enabling it logs a warning. */
    enabled?: boolean
    ledgerDir?: string
  }
}

interface ResolvedConfig {
  guard: { enabled: boolean; workspaceRoot: string; recordWrites: boolean }
  changeset: { enabled: boolean; ledgerDir: string | undefined }
}

const DEFAULTS = {
  guard: { enabled: true, recordWrites: true },
  changeset: { enabled: false },
} as const

/** Tools whose written path feeds the TOCTOU rule. */
const WRITE_TOOLS: ReadonlySet<string> = new Set([
  'write_file',
  'writefile',
  'create_file',
  'edit_file',
  'apply_patch',
  'str_replace_editor',
  'multiedit',
])

const PATH_KEYS: ReadonlyArray<string> = ['filepath', 'file_path', 'path', 'file', 'target']

/** Bounded so a long session cannot grow the ledger without limit. */
const MAX_RECENT_WRITES = 256

function resolve(raw: CmdGuardConfig): ResolvedConfig {
  return {
    guard: {
      ...DEFAULTS.guard,
      ...(raw.guard ?? {}),
      workspaceRoot: raw.guard?.workspaceRoot ?? process.cwd(),
    },
    changeset: {
      enabled: raw.changeset?.enabled ?? DEFAULTS.changeset.enabled,
      ledgerDir: raw.changeset?.ledgerDir,
    },
  }
}

/**
 * Log through the harness when it has a logger, fall back to the console.
 * Used only for degraded-mode notices: a guard that quietly loses half its
 * enforcement is the failure this package exists to prevent.
 */
function warn(ctx: any, message: string): void {
  const logger = ctx?.logger
  if (typeof logger?.warn === 'function') {
    logger.warn(message)
    return
  }
  console.warn(`[dsh-cmd-guard] ${message}`)
}

function asExecution(value: unknown): ExecutionLike {
  const e = value as { name?: unknown; arguments?: unknown } | null
  return { name: e?.name, arguments: e?.arguments }
}

/**
 * Did this call fail? The ledger exists to prove "this path now holds content
 * I just wrote". A failed write proves nothing, and recording it produced a
 * false INTERP_RECENT_WRITE on the next legitimate run of that path.
 */
export function isFailedResult(result: unknown): boolean {
  if (result instanceof Error) return true
  if (typeof result !== 'object' || result === null) return false

  const r = result as Record<string, unknown>
  if (r.isError === true) return true
  if (r.ok === false) return true
  if (r.error !== undefined && r.error !== null) return true
  return false
}

function recordWrite(ledger: string[], exec: ExecutionLike): void {
  if (typeof exec.name !== 'string' || !WRITE_TOOLS.has(exec.name.toLowerCase())) return

  const args =
    typeof exec.arguments === 'object' && exec.arguments !== null
      ? (exec.arguments as Record<string, unknown>)
      : {}

  for (const key of PATH_KEYS) {
    const v = args[key]
    if (typeof v !== 'string' || v.trim().length === 0) continue
    ledger.push(v)
    if (ledger.length > MAX_RECENT_WRITES) ledger.shift()
    return
  }
}

/**
 * Mount point. Deliberately does no parsing itself: guard/ owns the analysis,
 * changeset/ owns the bookkeeping.
 */
export function apply(ctx: any, raw: CmdGuardConfig = {}): void {
  const cfg = resolve(raw)

  if (cfg.guard.enabled) installGuard(ctx, cfg)
  if (cfg.changeset.enabled) installChangeset(ctx, cfg.changeset.ledgerDir)
}

function installGuard(ctx: any, cfg: ResolvedConfig): void {
  const recentWrites: string[] = []
  const state = (): GuardState => ({ workspaceRoot: cfg.guard.workspaceRoot, recentWrites })

  const dispose = (off: unknown): void => {
    if (typeof off === 'function') ctx.on('dispose', off)
  }

  // Write ledger. Observed, not intercepted: it only feeds the TOCTOU rule, so
  // it must never alter a decision.
  if (cfg.guard.recordWrites) {
    dispose(
      ctx.on('tools/post-execute', async (exec: unknown, result: unknown, next: () => Promise<unknown>) => {
        if (!isFailedResult(result)) recordWrite(recentWrites, asExecution(exec))
        return next()
      }),
    )
  }

  // Ask / deny path. Returning a decision instead of awaiting `next()` skips
  // every listener mounted after this one, so a pass defers explicitly.
  dispose(
    ctx.on('tools/pre-execute', async (exec: unknown, next: () => Promise<unknown>) => {
      const mapping = toGuardInput(asExecution(exec))
      if (mapping.kind === 'skip') return next()

      const decision = toDecision(verify(mapping.input, state()))
      if (decision === null) return next()

      // Fail closed on shape drift. An unrecognised decision is a gate that
      // silently did nothing - the exact failure this package exists to stop.
      if (!isPreToolDecision(decision)) {
        return {
          kind: 'deny',
          reason:
            '[ENTRY_BAD_DECISION_SHAPE] dsh-cmd-guard produced a decision the registry would ignore; failing closed.',
        }
      }

      return decision
    }),
  )

  // Hard-deny path. Survives approval and listener ordering because this mount
  // has no allow exit at all.
  if (typeof ctx.tools?.guard === 'function') {
    dispose(
      ctx.tools.guard((exec: unknown) => {
        const mapping = toGuardInput(asExecution(exec))
        if (mapping.kind === 'skip') return undefined
        return toHardDeny(verify(mapping.input, state()))
      }),
    )
  } else {
    // Measured gap: without this mount the deny layer is simply absent, while
    // the plugin still looks installed and active. Deny rules would only ever
    // surface as ask from the waterfall, which an operator can approve.
    warn(
      ctx,
      'ctx.tools.guard is unavailable: hard-deny rules are degraded to ask. ' +
        'This build of the harness cannot enforce non-overridable denials for this plugin.',
    )
  }
}

/**
 * Self-patch bookkeeping. Opt-in and off by default: it needs
 * danger-full-access, and a plugin that can rewrite itself should not be
 * something a user gets for free on install.
 *
 * Not implemented yet. Enabling it warns rather than pretending to work.
 */
function installChangeset(ctx: any, ledgerDir: string | undefined): void {
  void ledgerDir
  warn(
    ctx,
    'changeset module is not implemented in this version; no ledger, rollback or promotion was installed.',
  )
}
