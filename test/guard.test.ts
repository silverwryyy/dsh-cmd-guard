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
import { verify } from '../src/guard/verify.js'
import type { GuardInput, GuardState } from '../src/guard/types.js'

const WORKSPACE = 'D:/AI_Assistant'
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
    const state: GuardState = {
      workspaceRoot: WORKSPACE,
      ...(c.requires_state === 'recent_write'
        ? { recentWrites: ['scripts/fresh.py'] }
        : {}),
    }

    const result = verify(toInput(c), state)

    assert.equal(
      result.verdict,
      c.expect,
      `${c.id}: expected ${c.expect}, got ${result.verdict} (${result.layer}/${result.code}) - ${result.reason}`,
    )
  })
}

test('corpus integrity: ids are unique and every layer is represented', () => {
  const ids = cases.map((c) => c.id)
  assert.equal(new Set(ids).size, ids.length, 'duplicate case id')

  const layers = new Set(cases.map((c) => c.layer))
  for (const layer of ['entry', 'rules', 'capability', 'split', 'unwrap', 'interp', 'obfusc', 'why']) {
    assert.ok(layers.has(layer), `layer "${layer}" has no cases`)
  }
})

test('allow/deny asymmetry: only the rules layer may deny', () => {
  const state: GuardState = { workspaceRoot: WORKSPACE }
  for (const c of cases) {
    if (c.expect !== 'deny') continue
    const result = verify(toInput(c), state)
    assert.equal(result.layer, 'rules', `${c.id}: deny came from ${result.layer}`)
  }
})

test('the thesis pair: identical command, different verdict on stated intent', () => {
  const state: GuardState = { workspaceRoot: WORKSPACE }
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
  const state: GuardState = { workspaceRoot: WORKSPACE }
  const result = verify({ cmd: 'python tools\\run_bg.py start x -- del /s /q D:\\' }, state)
  assert.notEqual(result.verdict, 'pass', 'argument passthrough must never pass')
})

test('a stated reason cannot buy a deny', () => {
  const state: GuardState = { workspaceRoot: WORKSPACE }
  const result = verify(
    { cmd: 'rd /s /q C:\\', why: 'Everything in here is stale build output, safe to remove.' },
    state,
  )
  assert.equal(result.verdict, 'deny', 'why must not escalate past a hard rule')
})
