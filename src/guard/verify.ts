/**
 * The pipeline.
 *
 * Order is not arbitrary and is part of the contract:
 *
 *   data    before everything: a payload argument is not a command line
 *   entry   first, because a wrong tool name or a renamed argument key makes
 *           every later layer analyse a string it never received
 *   rules   next, because deny must win over everything else and is the only
 *           layer with a deny exit
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
 */
import type { Finding, GuardInput, GuardResult, GuardState, LayerCheck } from './types.js'
import { check as entry, DATA_KEYS } from './entry.js'
import { check as rules } from './rules.js'
import { check as capability } from './capability.js'
import { check as split } from './split.js'
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

export function verify(input: GuardInput, state: GuardState = EMPTY): GuardResult {
  const findings: Finding[] = []

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
      verdict: 'pass',
      layer: 'clean',
      code: 'EMPTY_COMMAND',
      reason: 'Empty command; nothing to execute.',
      findings,
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
      verdict: 'pass',
      layer: 'clean',
      code: 'DATA_ARGUMENT',
      reason: `"${source}" carries document or payload data, not a command line. No layer applies.`,
      findings,
    }
  }

  for (const { layer, check } of LAYERS) {
    const finding = check(subject, state)
    if (finding === null) continue

    // Invariant: deny is reachable only from the rules layer, which is the
    // only mount wired to a guard with no allow exit. Anything else claiming
    // deny is downgraded to ask rather than trusted.
    const safe: Finding =
      finding.verdict === 'deny' && finding.layer !== 'rules'
        ? { ...finding, verdict: 'ask' }
        : finding

    findings.push(safe)

    // Entry asks first, and the loop stops at the first finding, so a tool
    // name the parser does not recognise used to turn a hard deny into a
    // question. A denied string is denied for what it says; an unfamiliar or
    // renamed executor cannot make it recoverable. Fail closed: give the rules
    // layer one look before an entry-layer ask ends the pipeline.
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

  return {
    verdict: 'pass',
    layer: 'clean',
    code: 'PASS',
    reason: 'No layer objected.',
    findings,
  }
}

export { entry, rules, capability, split, obfusc, unwrap, interp, why }
