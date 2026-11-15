/**
 * The pipeline.
 *
 * Order is not arbitrary and is part of the contract:
 *
 *   data    before everything: a payload argument is not a command line
 *   entry   first, because a wrong tool name or a renamed argument key makes
 *           every later layer analyse a string it never received
 *   rules   next, because deny must win over everything else. Ordinary
 *           content denials are settled here; the one structural fact that
 *           also denies - fetched output piped into an interpreter - is read
 *           by split afterwards, never before this layer has had its say
 *   split   before anything reads tokens, since a chain means the token stream
 *           is not the whole command
 *   obfusc  before unwrapping, so `cmd /c "d^e^l ..."` is reported as what it
 *           is (a split token) rather than as what it looks like (a host call)
 *   unwrap  before interpreters, because argument passthrough turns an
 *           otherwise clean script invocation into a forwarded payload
 *   interp  path provenance
 *   why     last: it only matters once the shape is known to be acceptable
 *
 * First finding wins. A later layer never gets to soften an earlier one.
 *
 * `chain: decompose` keeps that order and changes only who it is applied to:
 * instead of asking because a chain exists, each statement of the chain is run
 * through the same layers on its own. Deny still outranks ask, and the
 * structures this layer cannot read as statements (substitution, a background
 * job, too many parts) still ask - see planChain().
 */
import type { Finding, GuardInput, GuardResult, GuardState, LayerCheck } from './types.js'
import { check as entry, DATA_KEYS } from './entry.js'
import { check as rules } from './rules.js'
import { check as capability } from './capability.js'
import { check as split, planChain } from './split.js'
import { check as obfusc } from './obfusc.js'
import { check as unwrap } from './unwrap.js'
import { check as interp } from './interp.js'
import { check as why } from './why.js'
import { canonicalCommand } from './normalize.js'

export const LAYERS: ReadonlyArray<{ layer: Finding['layer']; check: LayerCheck }> = [
  { layer: 'entry', check: entry },
  { layer: 'rules', check: rules },
  { layer: 'split', check: split },
  { layer: 'obfusc', check: obfusc },
  { layer: 'unwrap', check: unwrap },
  { layer: 'interp', check: interp },
  // Last, because it only asks: any layer that can deny must run first, or
  // its deny is replaced by this layer's weaker answer.
  { layer: 'capability', check: capability },
  { layer: 'why', check: why },
]

const EMPTY: GuardState = {}

/** Statement depth beyond which decompose stops descending and asks instead. */
const MAX_DEPTH = 2

type Prepared =
  | { readonly ok: true; readonly subject: GuardInput }
  | { readonly ok: false; readonly result: GuardResult }

/**
 * Everything the pipeline needs settled before a layer runs: unicode folding,
 * the two populated-key derivations, the empty command, and payload data.
 */
function prepare(input: GuardInput): Prepared {
  // Unicode folding before any layer reads the string. Fullwidth latin, a
  // zero-width space, a soft hyphen and a NUL were each measured reaching the
  // end of the pipeline untouched, because every comparison downstream was
  // written for ASCII. A human reads those strings as the plain command.
  // The shipped shell tools carry the command under `command`; `cmd` is the
  // legacy key. The mount normalises both, so a dispatched call never gets
  // here with only `command` set - but verify() is exported, and a direct
  // caller using the shipped key used to crash inside NFKC folding.
  const declared =
    typeof input.cmd === 'string'
      ? input.cmd
      : (input as { command?: unknown }).command
  const cmdText = canonicalCommand(typeof declared === 'string' ? declared : '')

  // Two populated command keys mean the string audited may not be the string
  // executed. The mount already reports this; a direct caller did not, and a
  // call carrying `cmd: 'echo ok'` beside `command: 'del /s /q C:\\'` came
  // back pass. Derived here so the library entry point cannot lose the fact.
  const populatedKeys: string[] = []
  if (input.commandKeys === undefined) {
    for (const key of ['cmd', 'command', 'script', 'commandLine', 'command_line']) {
      const value = (input as unknown as Record<string, unknown>)[key]
      if (typeof value === 'string' && value.trim().length > 0) populatedKeys.push(key)
    }
  }
  const derivedKeys =
    input.commandKeys === undefined && populatedKeys.length > 1 ? populatedKeys : input.commandKeys

  const subject: GuardInput = {
    ...input,
    cmd: cmdText,
    ...(derivedKeys === undefined ? {} : { commandKeys: derivedKeys }),
  }

  if (cmdText.trim().length === 0) {
    return {
      ok: false,
      result: {
        verdict: 'pass',
        layer: 'clean',
        code: 'EMPTY_COMMAND',
        reason: 'Empty command; nothing to execute.',
        findings: [],
      },
    }
  }

  // A payload argument is not a command, whatever its text looks like.
  //
  // This has to sit ahead of every layer, not inside entry. The mount already
  // strips these keys, but `verify()` is exported and callable directly - and
  // an entry-only check left `write_file` with a `content` that mentions
  // `del /s /q C:\` being judged by the rules layer afterwards. With no
  // approval UI composed, ask degrades to deny, so the tool became unusable.
  const source = input.commandSource
  if (source !== undefined && DATA_KEYS.has(source.toLowerCase())) {
    return {
      ok: false,
      result: {
        verdict: 'pass',
        layer: 'clean',
        code: 'DATA_ARGUMENT',
        reason: `"${source}" carries document or payload data, not a command line. No layer applies.`,
        findings: [],
      },
    }
  }

  return { ok: true, subject }
}

export function verify(input: GuardInput, state: GuardState = EMPTY): GuardResult {
  const prepared = prepare(input)
  if (!prepared.ok) return prepared.result
  return run(prepared.subject, state, 0)
}

/**
 * Codes that may answer deny from outside the rules layer.
 *
 * An allowlist rather than a relaxed layer rule, so a future split finding
 * cannot inherit a deny by accident. Each entry has to name a structural fact
 * about the text itself - true of the whole string and false of every part of
 * it. SPLIT_PIPE_TO_INTERPRETER is the first: "this stage executes that
 * stage's output" cannot be read off any single statement.
 */
const STRUCTURAL_DENY: ReadonlySet<string> = new Set(['SPLIT_PIPE_TO_INTERPRETER'])

/**
 * Turn one finding into the answer, applying the two invariants:
 *
 * 1. deny is reachable from the rules layer, and from split for the codes in
 *    STRUCTURAL_DENY. Anything else claiming deny is downgraded to ask rather
 *    than trusted: an ask can be approved and a deny cannot, so a layer that
 *    cannot prove its case must not be the one to end the command.
 * 2. an entry-layer ask must not outrank a hard deny the string itself earns.
 *    An unfamiliar or renamed executor cannot make a denied command
 *    recoverable, so the rules layer gets one look before the pipeline ends.
 */
function answer(
  finding: Finding,
  subject: GuardInput,
  state: GuardState,
  findings: Finding[],
): GuardResult {
  const safe: Finding =
    finding.verdict === 'deny' &&
    finding.layer !== 'rules' &&
    !STRUCTURAL_DENY.has(finding.code)
      ? { ...finding, verdict: 'ask' }
      : finding

  findings.push(safe)

  if (safe.layer === 'entry' && safe.verdict === 'ask') {
    const hard = rules(subject, state)
    if (hard !== null && hard.verdict === 'deny') {
      findings.push(hard)
      return {
        verdict: 'deny',
        layer: hard.layer,
        code: hard.code,
        reason: hard.reason,
        findings,
      }
    }
  }

  return {
    verdict: safe.verdict,
    layer: safe.layer,
    code: safe.code,
    reason: safe.reason,
    findings,
  }
}

type Outcome =
  | { readonly kind: 'result'; readonly result: GuardResult }
  | { readonly kind: 'passed' }
  | { readonly kind: 'finding'; readonly finding: Finding | null }

/**
 * Judge a chain by its statements, or step aside and let the strict path judge
 * it as one string.
 */
function decompose(subject: GuardInput, state: GuardState, depth: number): Outcome {
  if (depth >= MAX_DEPTH) {
    // Deeper than we are willing to reason about. Ask the way strict mode
    // would rather than pretend the nesting was read.
    return { kind: 'finding', finding: split(subject, state) }
  }

  const plan = planChain(subject.cmd, state)

  if (plan.kind === 'finding') return { kind: 'finding', finding: plan.finding }
  if (plan.kind === 'single') return { kind: 'finding', finding: split(subject, state) }

  const findings: Finding[] = []
  let ask: Finding | null = null

  for (const segment of plan.segments) {
    // A statement carries no tool name and no argument key: those describe the
    // call, not the statement, and re-deriving them here would report key
    // drift once per segment.
    const judged = run({ cmd: segment, why: subject.why, tool: subject.tool }, state, depth + 1)
    findings.push(...judged.findings)

    // A deny anywhere in the chain is the answer for the whole call. This is
    // the case that must never soften: `git status && rm -rf /`.
    if (judged.verdict === 'deny') {
      return {
        kind: 'result',
        result: {
          verdict: 'deny',
          layer: judged.layer,
          code: judged.code,
          reason: `${judged.reason} (segment: ${segment})`,
          findings,
        },
      }
    }

    if (judged.verdict === 'ask' && ask === null) {
      ask = {
        layer: judged.layer === 'clean' ? 'split' : judged.layer,
        verdict: 'ask',
        code: judged.code,
        reason: `${judged.reason} (segment: ${segment})`,
      }
    }
  }

  if (ask !== null) {
    return {
      kind: 'result',
      result: {
        verdict: 'ask',
        layer: ask.layer,
        code: ask.code,
        reason: ask.reason,
        findings,
      },
    }
  }

  // Every statement passed, each having faced the intent layer on its own.
  // Re-judging the chain here would only re-read its first statement - the
  // shape that let a mutating tail through unexamined.
  return { kind: 'passed' }
}

function run(subject: GuardInput, state: GuardState, depth: number): GuardResult {
  const findings: Finding[] = []

  for (const { layer, check } of LAYERS) {
    // Every layer judges a statement, the intent layer included. Skipping it
    // here was a measured hole: why() reads the command head, so a chain whose
    // first statement is harmless never faced it as a whole either -
    // `git status; git push --force` passed, and `echo hi; del x` with it.
    // A reason stated for the call applies to each statement of the call.
    if (layer === 'split' && state.chain === 'decompose') {
      const outcome = decompose(subject, state, depth)

      if (outcome.kind === 'result') return outcome.result

      if (outcome.kind === 'passed') {
        // Each statement was judged on its own. The remaining layers read the
        // raw string, and for a chain that string is not the token stream that
        // runs - so they have nothing left to say about it.
        return {
          verdict: 'pass',
          layer: 'clean',
          code: 'PASS',
          reason: 'No layer objected.',
          findings,
        }
      }

      if (outcome.finding === null) continue
      return answer(outcome.finding, subject, state, findings)
    }

    const finding = check(subject, state)
    if (finding === null) continue
    return answer(finding, subject, state, findings)
  }

  return {
    verdict: 'pass',
    layer: 'clean',
    code: 'PASS',
    reason: 'No layer objected.',
    findings,
  }
}

export { entry, rules, capability, split, obfusc, unwrap, interp, why }
