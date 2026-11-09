/**
 * Verdict vocabulary.
 *
 * Three states, and the asymmetry matters:
 *   deny   terminal, unreachable outside the rules layer
 *   ask    a human decision is required
 *   pass   no layer objected
 *
 * Do not confuse this with the framework's four-state PreToolDecision
 * (allow / deny / cancel / ask). `cancel` belongs to the operator pressing
 * stop and is never produced by this plugin; see mount.ts.
 */
export type Verdict = 'deny' | 'ask' | 'pass'

/**
 * Layer order is fixed by verify.ts and is part of the contract.
 *
 * `entry` sits first because everything downstream assumes it is looking at a
 * command string from a known execution tool. A wrong tool name makes all of
 * it meaningless while still appearing to work.
 */
export type Layer =
  | 'entry'
  | 'rules'
  | 'capability'
  | 'split'
  | 'obfusc'
  | 'unwrap'
  | 'interp'
  | 'why'

export interface Finding {
  readonly layer: Layer
  readonly verdict: 'deny' | 'ask'
  /** Stable machine-readable id. Tests and the README both reference these. */
  readonly code: string
  readonly reason: string
}

export interface GuardInput {
  readonly cmd: string
  /**
   * Stated intent, as supplied by the model's `description` argument.
   * Optional at the type level because the caller may omit it; the why layer
   * turns an omission into an ask. Presence is not the bar - the why layer
   * also rejects placeholders, restatements, and contradictions.
   */
  readonly why?: string | undefined
  /**
   * Tool name as dispatched. Undefined means "called directly", which is the
   * only case where the entry layer stands down. In production it is always
   * set by mount.ts.
   */
  readonly tool?: string | undefined
  /** Argument key the command was read from, for key-drift detection. */
  readonly commandSource?: string | undefined

  /**
   * Every argument key that carried a non-empty command string.
   *
   * More than one is a divergence: the parser audits whichever key it read
   * first, while the tool may execute the other. `command` plus `cmd` was a
   * measured case of exactly that.
   */
  readonly commandKeys?: readonly string[] | undefined
}

export interface GuardState {
  /** Absolute workspace root used for path-provenance decisions. */
  readonly workspaceRoot?: string | undefined
  /**
   * Paths written earlier in the same session, used for the TOCTOU rule.
   * Normalised with forward slashes, compared case-insensitively.
   */
  readonly recentWrites?: readonly string[] | undefined
}

export interface GuardResult {
  readonly verdict: Verdict
  /** 'clean' when no layer produced a finding. */
  readonly layer: Layer | 'clean'
  readonly code: string
  readonly reason: string
  readonly findings: readonly Finding[]
}

export type LayerCheck = (input: GuardInput, state: GuardState) => Finding | null
