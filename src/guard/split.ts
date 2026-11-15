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
 *
 * A third exception, and the only deny this layer answers with: a pipe that
 * feeds fetched bytes into an interpreter. Both halves are clean on their own,
 * so no statement of the chain carries the finding - only the pipe does. See
 * pipeIntoInterpreter, and STRUCTURAL_DENY in verify.ts for how a deny from
 * outside the rules layer is allowed to stay a deny.
 */
import type { Finding, GuardInput, GuardState } from './types.js'
import {
  hasCommandSubstitution,
  hasProcessSubstitution,
  hasUnquotedNewline,
  scanOperators,
  splitSegments,
  substitutionBodies,
  tokenize,
} from './lexical.js'
import { hasUnsafeRedirectTarget, headTokens, plainToken, stemVerb } from './normalize.js'
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

/**
 * Commands whose standard output is content fetched from somewhere else.
 *
 * Deliberately short. A word belongs here only when fetching is the whole
 * point of it: "cat payload.sh | sh" runs a file the operator could read
 * first, and that is not this case.
 */
const FETCHERS: ReadonlySet<string> = new Set([
  'curl',
  'wget',
  'iwr',
  'irm',
  'invoke-webrequest',
  'invoke-restmethod',
  'start-bitstransfer',
  'certutil',
  'bitsadmin',
  'tftp',
])

/** Interpreters that run the stream they read, arguments or not. */
const STDIN_IS_PROGRAM: ReadonlySet<string> = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'powershell',
  'pwsh',
  'cmd',
  'iex',
  'invoke-expression',
])

/** Interpreters that run a stream only when handed no program of their own. */
const STDIN_MAY_BE_PROGRAM: ReadonlySet<string> = new Set([
  'python',
  'python3',
  'node',
  'nodejs',
  'perl',
  'ruby',
  'php',
])

/** Stages connected by "|", inside one statement. */
type PipeRun = readonly string[]

/**
 * Cut the command into pipe runs.
 *
 * ";", a newline, "&", "&&" and "||" end a run rather than a stage: they start
 * or select a statement, and a stage in the next statement is not fed by this
 * one. "2>&1" is a descriptor redirect, not a background job, so
 * "curl x 2>&1 | sh" keeps its pipe.
 */
function pipeRuns(cmd: string): readonly PipeRun[] {
  const runs: PipeRun[] = []
  let stage = ''
  let stages: string[] = []
  let quote: string | null = null

  const endRun = (): void => {
    stages.push(stage)
    const kept = stages.map((s) => s.trim()).filter((s) => s.length > 0)
    if (kept.length > 0) runs.push(kept)
    stage = ''
    stages = []
  }

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]
    if (ch === undefined) break

    if (quote !== null) {
      stage += ch
      if (ch === quote) quote = null
      continue
    }

    if (ch === '"' || ch === "'") {
      quote = ch
      stage += ch
      continue
    }

    if (ch === '|') {
      if (cmd[i + 1] === '|') {
        endRun()
        i += 1
        continue
      }
      stages.push(stage)
      stage = ''
      continue
    }

    if (ch === ';' || ch === '\n' || ch === '\r') {
      endRun()
      continue
    }

    if (ch === '&') {
      // A descriptor redirect, not a separator.
      if (stage.trimEnd().endsWith('>')) {
        stage += ch
        continue
      }
      endRun()
      if (cmd[i + 1] === '&') i += 1
      continue
    }

    stage += ch
  }

  endRun()
  return runs
}

/**
 * Does this stage run the stream it is handed as its program?
 *
 * This is what keeps the finding a fact rather than a guess: "curl x | sh"
 * executes fetched bytes, while "curl x | bash script.sh" runs a local file and
 * only reads the fetch as data.
 */
function readsPipedProgram(stage: string): boolean {
  const eff = headTokens(tokenize(stage))
  const head = eff[0]
  if (head === undefined) return false

  const verb = stemVerb(head)
  const args = eff.slice(1).map(plainToken)

  // "-c" hands the interpreter its own string; the stream is data again.
  if (args.includes('-c')) return false

  if (STDIN_IS_PROGRAM.has(verb)) {
    // A bare positional is a script file the operator could read first.
    return !args.some((a) => a.length > 0 && !a.startsWith('-'))
  }

  if (STDIN_MAY_BE_PROGRAM.has(verb)) {
    return args.length === 0 || (args.length === 1 && args[0] === '-')
  }

  return false
}

/**
 * "curl <url> | sh", and every spelling of it that survives a path, an
 * obfuscated verb or a wrapper: fetched bytes are executed.
 *
 * Deny rather than ask, and the asymmetry is the whole reason. Neither half is
 * a finding on its own - curl downloads, sh is a shell - so the rules layer has
 * nothing to say about either, and where ask degrades to an automatic allow a
 * structural question here is an automatic yes. Measured: this was an ask, and
 * every ask in the reported session came back allowed-once.
 */
function pipeIntoInterpreter(cmd: string): Finding | null {
  for (const run of pipeRuns(cmd)) {
    if (run.length < 2) continue

    const last = run[run.length - 1]
    if (last === undefined || !readsPipedProgram(last)) continue

    for (let i = 0; i < run.length - 1; i++) {
      const stage = run[i]
      if (stage === undefined) continue

      const head = headTokens(tokenize(stage))[0]
      if (head === undefined) continue

      if (!FETCHERS.has(stemVerb(head))) continue

      return {
        layer: 'split',
        verdict: 'deny',
        code: 'SPLIT_PIPE_TO_INTERPRETER',
        reason:
          'The stage "' +
          last.trim() +
          '" executes the output of "' +
          head.trim() +
          '", so the program that runs is fetched rather than read. It is written nowhere in this command.',
      }
    }
  }

  return null
}

export function check(input: GuardInput, state: GuardState): Finding | null {
  const denied = escalateToDeny(input.cmd, state)
  if (denied !== null) return denied

  // Checked before the generic operator ask, for the same reason a deny
  // outranks an ask: strict mode would otherwise report the pipe as a
  // structure question, and approving that question runs the payload.
  const piped = pipeIntoInterpreter(input.cmd)
  if (piped !== null) return piped

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

/**
 * Statements a decompose verdict will judge before it gives up and asks.
 *
 * The point of decomposing is to keep the approval in view. A chain the
 * operator would not read in one glance is a structure, not a content,
 * finding - so beyond this count the layer asks as it always did.
 */
const MAX_DECOMPOSED_SEGMENTS = 4

/** What the split layer should do with one command under `chain: decompose`. */
export type ChainPlan =
  | { readonly kind: 'single' }
  | { readonly kind: 'segments'; readonly segments: readonly string[] }
  | { readonly kind: 'finding'; readonly finding: Finding }

/**
 * Split into statements on `;`, `|`, `&&`, `||` and unquoted newlines.
 *
 * `>` and `<` are deliberately not separators here. `echo "const x = 1" > src/x.ts`
 * is one statement, and cutting at the redirect would hand the layers a bare
 * filename to judge as a command - the same near-miss the strict path already
 * documents in check().
 *
 * Quotes are honoured, so `echo "a; b"` stays one statement.
 */
export function chainSegments(cmd: string): string[] {
  const out: string[] = []
  let cur = ''
  let quote: string | null = null

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]
    if (ch === undefined) break

    if (quote !== null) {
      cur += ch
      if (ch === quote) quote = null
      continue
    }

    if (ch === '"' || ch === "'") {
      quote = ch
      cur += ch
      continue
    }

    if (ch === '\n' || ch === '\r' || ch === ';' || ch === '|') {
      out.push(cur)
      cur = ''
      continue
    }

    if (ch === '&') {
      out.push(cur)
      cur = ''
      // The second half of && is operator, not an empty statement.
      if (cmd[i + 1] === '&') i += 1
      continue
    }

    cur += ch
  }

  out.push(cur)
  return out.map((s) => s.trim()).filter((s) => s.length > 0)
}

/**
 * Decide what `chain: decompose` means for one command.
 *
 * Order is the whole argument here. A hard deny behind a separator is settled
 * first, so decomposing can never soften it. Structures whose text is not
 * command text (substitution) are refused before splitting, because splitting
 * would cut through the nested body and hand the layers fragments that do not
 * exist as statements. Only then is the chain cut up.
 */
export function planChain(cmd: string, state: GuardState): ChainPlan {
  const denied = escalateToDeny(cmd, state)
  if (denied !== null) return { kind: 'finding', finding: denied }

  // The pipe is the one finding no statement of the chain carries: curl alone
  // passes, sh alone passes, and only the join is the payload. It has to be
  // settled before the chain is cut, or decomposing would file it as two
  // clean statements.
  const piped = pipeIntoInterpreter(cmd)
  if (piped !== null) return { kind: 'finding', finding: piped }

  if (hasCommandSubstitution(cmd)) {
    return {
      kind: 'finding',
      finding: {
        layer: 'split',
        verdict: 'ask',
        code: 'SPLIT_COMMAND_SUBSTITUTION',
        reason:
          'Command substitution runs a nested command that no statement of this chain contains. Splitting would judge the wrong text.',
      },
    }
  }

  if (hasProcessSubstitution(cmd)) {
    return {
      kind: 'finding',
      finding: {
        layer: 'split',
        verdict: 'ask',
        code: 'SPLIT_PROCESS_SUBSTITUTION',
        reason:
          'Process substitution hands the tool an anonymous pipe that never exists on disk, so no path-provenance check can apply.',
      },
    }
  }

  // A background job is not a statement whose result the operator sees: its
  // exit status is not the one being awaited, and its output arrives out of
  // band. Judging the parts would be judging a command nobody waits for.
  const background = scanOperators(cmd).some((op) => op === '&' || op === '^&')
  if (background) {
    return {
      kind: 'finding',
      finding: {
        layer: 'split',
        verdict: 'ask',
        code: 'SPLIT_BACKGROUND',
        reason:
          'A background job detaches from the approval: its exit status is not awaited and its output arrives out of band.',
      },
    }
  }

  const segments = chainSegments(cmd)
  if (segments.length <= 1) return { kind: 'single' }

  if (segments.length > MAX_DECOMPOSED_SEGMENTS) {
    return {
      kind: 'finding',
      finding: {
        layer: 'split',
        verdict: 'ask',
        code: 'SPLIT_TOO_MANY_PARTS',
        reason:
          segments.length +
          ' statements in one call; decompose inspects at most ' +
          MAX_DECOMPOSED_SEGMENTS +
          '. Beyond that the chain is a structure, not a command an operator reads at a glance.',
      },
    }
  }

  return { kind: 'segments', segments }
}
