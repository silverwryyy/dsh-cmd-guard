/**
 * Layer 2: chaining.
 *
 * A pipe, a chain, or a second line means the command the operator reads is
 * not the command that runs. We do not try to decide whether the second stage
 * is dangerous; we refuse to take responsibility for a structure we did not
 * fully parse.
 *
 * One exception to "first finding wins", deliberately: if any segment or
 * substitution body is a hard deny, that deny is returned instead of the ask.
 * Measured case: `git status && rm -rf /` was an ask from this layer, which
 * masked the deny the rules layer would have produced for the second
 * statement. An ask is a weaker answer than a deny and must not outrank it.
 *
 * A second exception, in the other direction: a redirect into a relative file
 * is not a chain. `echo "const x = 1" > src/x.ts` was being asked on every
 * file write, which - with no approval UI composed - made the write tools
 * unusable. The target is what decides; see hasUnsafeRedirectTarget.
 */
import type { Finding, GuardInput, GuardState } from './types.js'
import {
  hasCommandSubstitution,
  hasProcessSubstitution,
  hasUnquotedNewline,
  scanOperators,
  splitSegments,
  substitutionBodies,
} from './lexical.js'
import { hasUnsafeRedirectTarget } from './normalize.js'
import { check as rulesCheck } from './rules.js'

/**
 * Run the hard rules against each statement the chain would actually execute.
 *
 * Returning the inner finding keeps `layer: 'rules'`, which is what the
 * deny-only mount is wired to; verify.ts's asymmetry check relies on that.
 */
function escalateToDeny(cmd: string, state: GuardState): Finding | null {
  for (const segment of splitSegments(cmd)) {
    const inner = rulesCheck({ cmd: segment }, state)
    if (inner !== null && inner.verdict === 'deny') return inner
  }

  for (const body of substitutionBodies(cmd)) {
    const inner = rulesCheck({ cmd: body }, state)
    if (inner !== null && inner.verdict === 'deny') return inner
  }

  return null
}

export function check(input: GuardInput, state: GuardState): Finding | null {
  const denied = escalateToDeny(input.cmd, state)
  if (denied !== null) return denied

  // Redirection is a chain only when the target is somewhere the operator
  // cannot see. A relative write below the workspace is one command.
  const redirectSafe = !hasUnsafeRedirectTarget(input.cmd)
  const ops = scanOperators(input.cmd).filter(
    (op) => !(redirectSafe && (op === '>' || op === '>>' || op === '<')),
  )

  if (ops.length > 0) {
    return {
      layer: 'split',
      verdict: 'ask',
      code: 'SPLIT_OPERATOR',
      reason: `Command chains with "${ops.join(' ')}". Chained stages are not inspected as one command.`,
    }
  }

  // Newline is an operator in both shells. This was a measured bypass: the
  // rules layer only ever sees tokens[0], so `echo hi\nrm -rf /` passed while
  // the same two commands joined by `;` did not.
  if (hasUnquotedNewline(input.cmd)) {
    return {
      layer: 'split',
      verdict: 'ask',
      code: 'SPLIT_NEWLINE',
      reason:
        'Command spans multiple lines. A newline separates statements exactly like ";" and only the first one would be inspected.',
    }
  }

  // Measured bypass: `echo $(rm -rf /)` and ``echo `rm -rf /` `` both passed.
  // Substitution runs a nested command whose text never reaches the rules
  // layer as tokens[0]. The deny escalation above has already run; if it found
  // nothing, this is still a structure we did not parse.
  if (hasCommandSubstitution(input.cmd)) {
    return {
      layer: 'split',
      verdict: 'ask',
      code: 'SPLIT_COMMAND_SUBSTITUTION',
      reason:
        'Command substitution runs a nested command. The inner text is what executes, not the string that was read.',
    }
  }

  if (hasProcessSubstitution(input.cmd)) {
    return {
      layer: 'split',
      verdict: 'ask',
      code: 'SPLIT_PROCESS_SUBSTITUTION',
      reason:
        'Process substitution hands the tool an anonymous pipe that never exists on disk, so no path-provenance check can apply.',
    }
  }

  return null
}
