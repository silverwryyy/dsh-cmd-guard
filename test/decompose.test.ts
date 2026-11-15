/**
 * `chain: decompose` - judge a chain by its statements instead of by the fact
 * that it is a chain.
 *
 * The reported session produced 17 SPLIT_OPERATOR asks in ten minutes: every
 * pwsh command joined with `;`, `&&` or `|` cost one approval, whatever the
 * parts did. Strict mode is right to refuse a structure it did not parse; the
 * point of this mode is that it does parse it.
 *
 * What must not change is the asymmetry. A deny anywhere in the chain is still
 * the verdict for the whole call, and the structures that are not statements
 * at all still ask. The first two tests here are the only ones that matter if
 * the rest are ever relaxed.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { verify } from '../src/guard/verify.js'
import { chainSegments } from '../src/guard/split.js'
import type { GuardInput, GuardState } from '../src/guard/types.js'

/** Same derivation as the corpus runner: stated, never inherited. */
const WORKSPACE = (
  process.env['CMD_GUARD_WORKSPACE'] ?? fileURLToPath(new URL('../../', import.meta.url))
).replace(/\\/g, '/')

const STRICT: GuardState = { workspaceRoot: WORKSPACE, cwd: WORKSPACE }
const DECOMPOSE: GuardState = { ...STRICT, chain: 'decompose' }

/** The shapes that dominated the reported session. */
const CHAINED: ReadonlyArray<readonly [string, string]> = [
  ['git status; git log --oneline -5', 'Check the working tree and the recent commit history.'],
  ['npm run build && npm test', 'Build the package and then run its test suite.'],
  ['git diff --stat && git status --short', 'Show what changed and which files are staged.'],
]

interface Case {
  id: string
  cmd: string
  expect: 'deny' | 'ask' | 'pass'
  why?: string
  tool?: string
  command_source?: string
  requires_state?: string
}

function loadCorpus(): Case[] {
  const dir = fileURLToPath(new URL('../../test/', import.meta.url))
  const files = readdirSync(dir).filter((f) => /^attacks.*\.json$/.test(f)).sort()
  return files.flatMap(
    (f) => (JSON.parse(readFileSync(dir + f, 'utf8')) as { cases: Case[] }).cases,
  )
}

function stateFor(c: Case, base: GuardState): GuardState {
  return c.requires_state === 'recent_write' ? { ...base, recentWrites: ['scripts/fresh.py'] } : base
}

function inputOf(c: Case): GuardInput {
  return { cmd: c.cmd, why: c.why, tool: c.tool, commandSource: c.command_source }
}

// ---------------------------------------------------------------------------
// The guard did not get weaker.
// ---------------------------------------------------------------------------

test('decompose never softens a deny the corpus already measures', () => {
  const cases = loadCorpus()
  let checked = 0

  for (const c of cases) {
    if (c.expect !== 'deny') continue
    checked += 1

    const result = verify(inputOf(c), stateFor(c, DECOMPOSE))
    assert.equal(
      result.verdict,
      'deny',
      `${c.id} softened to ${result.verdict} (${result.layer}/${result.code}) under decompose`,
    )
    // A structural deny is the one deny that does not come from the rules
    // layer. Named explicitly so a future layer cannot slip in unnoticed.
    assert.ok(
      result.layer === 'rules' || result.code === 'SPLIT_PIPE_TO_INTERPRETER',
      `${c.id}: a deny came from ${result.layer} (${result.code})`,
    )
  }

  assert.ok(checked > 0, 'corpus contains no deny cases; the assertion would be vacuous')
})

test('a deny behind a separator still denies the whole call', () => {
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['git status && rm -rf /', 'Check the working tree, then clean up.'],
    ['echo ok; del /s /q D:\\', 'Print a marker, then remove the build directory.'],
    ['echo ok; rd /s /q C:\\', 'Print a marker, then remove an old directory.'],
  ]

  for (const [cmd, why] of cases) {
    const result = verify({ cmd, why }, DECOMPOSE)
    assert.equal(result.verdict, 'deny', `${cmd} must stay a deny under decompose`)
    assert.equal(result.layer, 'rules')
  }
})

test('a statement that needs a human still asks for one', () => {
  // Argument passthrough inside a chain: unwrap must still see it once the
  // statement is judged on its own, or decomposing would have opened the hole
  // that U-003 exists to close.
  const result = verify(
    {
      cmd: 'echo ok && python tools\\run_bg.py start x -- del /s /q D:\\',
      why: 'Print a marker and then start the background job.',
    },
    DECOMPOSE,
  )

  assert.notEqual(result.verdict, 'pass', 'decompose must not pass a wrapped payload')
})

// ---------------------------------------------------------------------------
// What this mode is for.
// ---------------------------------------------------------------------------

test('a chain of plain statements passes on its own merits', () => {
  for (const [cmd, why] of CHAINED) {
    const result = verify({ cmd, why }, DECOMPOSE)
    assert.equal(
      result.verdict,
      'pass',
      `${cmd} should pass under decompose, got ${result.verdict} (${result.layer}/${result.code}): ${result.reason}`,
    )
  }
})

test('the same chains still ask under the default', () => {
  for (const [cmd, why] of CHAINED) {
    const result = verify({ cmd, why }, STRICT)
    assert.equal(result.verdict, 'ask', `${cmd} must keep asking without opting in`)
    assert.equal(result.code, 'SPLIT_OPERATOR')
  }
})

test('an unset chain state behaves exactly like strict', () => {
  const unset: GuardState = { workspaceRoot: WORKSPACE, cwd: WORKSPACE }
  for (const [cmd, why] of CHAINED) {
    assert.deepEqual(
      { ...verify({ cmd, why }, unset) },
      { ...verify({ cmd, why }, STRICT) },
      'omitting chain must not change any verdict',
    )
  }
})

// ---------------------------------------------------------------------------
// Structural uncertainty still asks. Splitting is not licence to guess.
// ---------------------------------------------------------------------------

test('command substitution still asks: no statement contains the nested body', () => {
  const result = verify({ cmd: 'echo $(echo hi)', why: 'Print the output of a nested command.' }, DECOMPOSE)
  assert.equal(result.verdict, 'ask')
  assert.equal(result.code, 'SPLIT_COMMAND_SUBSTITUTION')
})

test('a hard deny inside a substitution is still a deny, not an ask', () => {
  const result = verify(
    { cmd: 'echo $(rm -rf /)', why: 'Print the output of a nested command.' },
    DECOMPOSE,
  )
  assert.equal(result.verdict, 'deny')
})

test('a background job asks: nobody is waiting for its result', () => {
  const result = verify({ cmd: 'echo hi & whoami', why: 'Print a marker and check the account.' }, DECOMPOSE)
  assert.equal(result.verdict, 'ask')
  assert.equal(result.code, 'SPLIT_BACKGROUND')
})

test('more statements than the planner holds in view asks', () => {
  const result = verify({ cmd: 'a; b; c; d; e', why: 'Run the five steps in order.' }, DECOMPOSE)
  assert.equal(result.verdict, 'ask')
  assert.equal(result.code, 'SPLIT_TOO_MANY_PARTS')
})

test('four statements is still inside the planner', () => {
  const result = verify({ cmd: 'git status; git log; git diff; git branch', why: 'Inspect the repository state.' }, DECOMPOSE)
  assert.notEqual(result.code, 'SPLIT_TOO_MANY_PARTS')
})

// ---------------------------------------------------------------------------
// Boundaries the splitter must not cross.
// ---------------------------------------------------------------------------

test('a quoted semicolon is data, not a separator', () => {
  assert.deepEqual(chainSegments('echo "a; b"'), ['echo "a; b"'])
})

test('redirects are not separators', () => {
  assert.deepEqual(chainSegments('echo hello > out.txt'), ['echo hello > out.txt'])
  assert.deepEqual(chainSegments('cmd < in.txt > out.txt'), ['cmd < in.txt > out.txt'])
})

test('the splitter handles the operators it claims', () => {
  assert.deepEqual(chainSegments('a; b'), ['a', 'b'])
  assert.deepEqual(chainSegments('a && b'), ['a', 'b'])
  assert.deepEqual(chainSegments('a || b'), ['a', 'b'])
  assert.deepEqual(chainSegments('a | b | c'), ['a', 'b', 'c'])
  assert.deepEqual(chainSegments('a\nb'), ['a', 'b'])
  assert.deepEqual(chainSegments('  a  ;;  b  '), ['a', 'b'])
})

test('a redirecting statement is still judged as one statement', () => {
  for (const state of [STRICT, DECOMPOSE]) {
    const result = verify({ cmd: 'echo hello > out.txt', why: 'Write a greeting into a scratch file.' }, state)
    assert.notEqual(result.code, 'SPLIT_OPERATOR', 'a relative redirect is not a chain')
    assert.notEqual(result.code, 'SPLIT_TOO_MANY_PARTS')
  }
})

test('decompose reports which statement it objected to', () => {
  // `rm -rf build` is an ask on its own (E-003). Inside a chain it must still
  // be that ask, and the reason has to name the statement that produced it -
  // otherwise the operator reads one line for a four-part command.
  const result = verify(
    {
      cmd: 'echo ok && rm -rf build',
      why: 'Print a marker, then remove the build output directory.',
    },
    DECOMPOSE,
  )

  assert.equal(result.verdict, 'ask')
  assert.match(result.reason, /statement: rm -rf build/)
})

// ---------------------------------------------------------------------------
// The intent layer must see every statement, not just the head of the chain.
//
// Measured hole in the first cut of this mode: why() was skipped for a
// statement and re-run once against the whole chain, where it reads the
// command head. A mutating tail therefore needed no reason at all.
// ---------------------------------------------------------------------------

test('a statement that needs a reason cannot hide behind a harmless head', () => {
  const cases: ReadonlyArray<string> = [
    'git status; git push --force',
    'echo hi; del D:\\temp\\a.txt',
    'git log -1 && npm publish',
  ]

  for (const cmd of cases) {
    const result = verify({ cmd }, DECOMPOSE)
    assert.equal(result.verdict, 'ask', `${cmd} must ask: the tail changes state with no reason given`)
    assert.equal(result.layer, 'why', `${cmd} must reach the intent layer, got ${result.layer}/${result.code}`)
    assert.match(result.code, /^WHY_/)
  }
})

test('position in the chain must not change the answer', () => {
  const behind = verify({ cmd: 'echo hi; del D:\\temp\\a.txt' }, DECOMPOSE)
  const ahead = verify({ cmd: 'del D:\\temp\\a.txt; echo hi' }, DECOMPOSE)

  assert.equal(behind.verdict, ahead.verdict, 'a tail statement must be judged like a leading one')
  assert.equal(behind.code, ahead.code, 'the code must not depend on position')
})

test('one stated reason still unlocks a whole chain', () => {
  const result = verify(
    {
      cmd: 'git status && git push --force',
      why: 'Drop the abandoned experiment branch and confirm the tree is clean.',
    },
    DECOMPOSE,
  )
  assert.equal(result.verdict, 'pass', `a stated reason must still unlock an ask, got ${result.code}`)
})

test('a reason cannot unlock an irrecoverable removal inside a chain', () => {
  const result = verify(
    { cmd: 'echo ok && rm -rf ~', why: 'Clear the temporary home directory contents.' },
    DECOMPOSE,
  )
  assert.notEqual(result.verdict, 'pass', 'a fluent reason must not unlock an irrecoverable removal')
})
