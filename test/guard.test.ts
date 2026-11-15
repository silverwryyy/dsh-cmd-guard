/**
 * Regression corpus runner. One assertion per case: the verdict must match.
 *
 * Layer identity is deliberately not asserted. Several cases are reachable by
 * more than one layer (a nested `cmd /c` that also contains a caret-split
 * token, for instance) and pinning the layer would turn a reasonable
 * reordering into a test failure. What must not drift is the verdict.
 *
 * Every `attacks*.json` under test/ is loaded, so later batches are added by
 * dropping in a file rather than editing an existing one.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import { verify } from '../src/guard/verify.js'
import type { GuardInput, GuardState } from '../src/guard/types.js'

/**
 * The corpus is written against "the workspace this repository sits in", not
 * against one machine's absolute path.
 *
 * It used to be the literal `D:/AI_Assistant`, and the same corpus then
 * produced eight failures in a clone under Documents: the relative tokens were
 * resolved against the process cwd while containment was tested against a root
 * from the corpus. Two bases, one command, two answers.
 *
 * The base is now stated rather than inherited, and the root is derived from
 * this file's location. `CMD_GUARD_WORKSPACE` overrides it for the odd case of
 * running the suite against a tree somewhere else.
 */
const WORKSPACE = (
  process.env['CMD_GUARD_WORKSPACE'] ?? fileURLToPath(new URL('../../', import.meta.url))
).replace(/\\/g, '/')

/**
 * Both bases, stated. `cwd` is not inherited from the process on purpose: an
 * assertion that changes when the test is started from a different directory
 * is not an assertion.
 */
const STATE: GuardState = { workspaceRoot: WORKSPACE, cwd: WORKSPACE }

/** Corpus cases that need a populated write ledger carry it here. */
function stateFor(c: Case): GuardState {
  return c.requires_state === 'recent_write'
    ? { ...STATE, recentWrites: ['scripts/fresh.py'] }
    : STATE
}
const CORPUS_DIR = fileURLToPath(new URL('../../test/', import.meta.url))

interface Case {
  id: string
  layer: string
  cmd: string
  expect: 'deny' | 'ask' | 'pass'
  why_required?: boolean
  why?: string
  tool?: string
  command_source?: string
  requires_state?: string
  note?: string
}

interface Corpus {
  schema: number
  cases: Case[]
}

const files = readdirSync(CORPUS_DIR).filter((f) => /^attacks.*\.json$/.test(f)).sort()
const cases: Case[] = files.flatMap(
  (f) => (JSON.parse(readFileSync(CORPUS_DIR + f, 'utf8')) as Corpus).cases,
)

/** Build parser input from a corpus case, including the optional tool fields. */
export function toInput(c: Case): GuardInput {
  return {
    cmd: c.cmd,
    why: c.why,
    tool: c.tool,
    commandSource: c.command_source,
  }
}

test('corpus loaded', () => {
  assert.ok(files.length >= 3, `expected at least 3 corpus files, found ${files.length}`)
  assert.ok(cases.length >= 50, `expected at least 50 cases, found ${cases.length}`)

  // The schema field is metadata, not behaviour, but it must not drift between
  // batches: a version bump that only reaches some files is how the corpus
  // stops meaning one thing.
  const schemas = new Set(
    files.map((f) => (JSON.parse(readFileSync(CORPUS_DIR + f, 'utf8')) as Corpus).schema),
  )
  assert.equal(schemas.size, 1, `corpus schema versions differ: ${[...schemas].join(', ')}`)
})

for (const c of cases) {
  test(`${c.id} ${c.expect}: ${c.cmd}`, () => {
    const result = verify(toInput(c), stateFor(c))

    assert.equal(
      result.verdict,
      c.expect,
      `${c.id}: expected ${c.expect}, got ${result.verdict} (${result.layer}/${result.code}) - ${result.reason}`,
    )
  })
}

/**
 * The assertion the eight cross-cwd failures were missing.
 *
 * `process.cwd()` used to be an input to the verdict through `cwdOf`'s
 * fallback, so the same corpus decided differently depending on where the
 * repository sat. Both bases are stated in `state` now, which makes the
 * process cwd irrelevant - and this runs the whole corpus from a directory that
 * shares no prefix with the workspace to prove it.
 */
test('verdicts do not depend on the process working directory', () => {
  const before = process.cwd()
  try {
    process.chdir(tmpdir())
    for (const c of cases) {
      const result = verify(toInput(c), stateFor(c))
      assert.equal(
        result.verdict,
        c.expect,
        `${c.id} changed verdict when the process cwd moved: got ${result.verdict} (${result.layer}/${result.code})`,
      )
    }
  } finally {
    process.chdir(before)
  }
})

test('corpus integrity: ids are unique and every layer is represented', () => {
  const ids = cases.map((c) => c.id)
  assert.equal(new Set(ids).size, ids.length, 'duplicate case id')

  const layers = new Set(cases.map((c) => c.layer))
  for (const layer of ['entry', 'rules', 'capability', 'split', 'unwrap', 'interp', 'obfusc', 'why']) {
    assert.ok(layers.has(layer), `layer "${layer}" has no cases`)
  }
})

test('allow/deny asymmetry: only the rules layer may deny', () => {
  const state = STATE
  for (const c of cases) {
    if (c.expect !== 'deny') continue
    const result = verify(toInput(c), state)
    // Structural denials are the documented exception: the finding is about
    // the join between two clean commands, which no single statement carries.
    assert.ok(
      result.layer === 'rules' || result.code === 'SPLIT_PIPE_TO_INTERPRETER',
      `${c.id}: deny came from ${result.layer} (${result.code})`,
    )
  }
})

test('the thesis pair: identical command, different verdict on stated intent', () => {
  const state = STATE
  const silent = verify({ cmd: 'del D:\\temp\\a.txt' }, state)
  const explained = verify(
    {
      cmd: 'del D:\\temp\\a.txt',
      why: 'Remove a stale scratch file produced by the build; contents already regenerated.',
    },
    state,
  )

  assert.equal(silent.verdict, 'ask')
  assert.equal(explained.verdict, 'pass')
})

test('U-003 stays an ask: the wrapper script is a live bypass channel', () => {
  const state = STATE
  const result = verify({ cmd: 'python tools\\run_bg.py start x -- del /s /q D:\\' }, state)
  assert.notEqual(result.verdict, 'pass', 'argument passthrough must never pass')
})

test('a stated reason cannot buy a deny', () => {
  const state = STATE
  const result = verify(
    { cmd: 'rd /s /q C:\\', why: 'Everything in here is stale build output, safe to remove.' },
    state,
  )
  assert.equal(result.verdict, 'deny', 'why must not escalate past a hard rule')
})
