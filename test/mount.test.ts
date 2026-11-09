/**
 * Mount-layer tests.
 *
 * These exist because the failure mode being guarded against is silent: a
 * handler that returns the wrong shape is not rejected by the registry, it is
 * simply not seen. Every assumption about the seam is therefore asserted here
 * rather than trusted.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  isPreToolDecision,
  toDecision,
  toGuardInput,
  toHardDeny,
} from '../src/guard/mount.js'
import { looksLikeCommandString } from '../src/guard/shape.js'
import { verify } from '../src/guard/verify.js'
import { isFailedResult } from '../src/index.js'
import type { GuardInput, GuardState } from '../src/guard/types.js'

const STATE: GuardState = { workspaceRoot: 'D:/AI_Assistant' }

test('maps the shipped shape: pwsh + command + description', () => {
  const mapping = toGuardInput({
    name: 'pwsh',
    arguments: { command: 'git status', description: 'Show which files changed since the last commit.' },
  })

  assert.equal(mapping.kind, 'call')
  if (mapping.kind !== 'call') return

  assert.equal(mapping.input.cmd, 'git status')
  assert.equal(mapping.input.tool, 'pwsh')
  assert.equal(mapping.input.commandSource, 'command')
  assert.equal(mapping.input.why, 'Show which files changed since the last commit.')
})

test('bash is mapped too: the persistent variant reuses the same registered name', () => {
  const mapping = toGuardInput({ name: 'bash', arguments: { command: 'ls' } })
  assert.equal(mapping.kind, 'call')
})

test('an unrelated tool is skipped, not judged', () => {
  const mapping = toGuardInput({ name: 'read_file', arguments: { filepath: 'D:/a.txt' } })
  assert.equal(mapping.kind, 'skip')
})

test('an unknown tool carrying a command line is mapped, flagged by the entry layer', () => {
  const mapping = toGuardInput({ name: 'some_future_shell', arguments: { payload: 'rm -rf /' } })
  assert.equal(mapping.kind, 'call')
  if (mapping.kind !== 'call') return

  assert.equal(mapping.input.commandSource, 'payload')
  // A1: a hard deny from the rules layer outranks the entry layer's ask, so
  // the code reported here is the rules' one. What this test pins is that the
  // call was judged at all, not which layer spoke last.
  const result = verify(mapping.input, STATE)
  assert.equal(result.verdict, 'deny')
  assert.equal(result.code, 'RULE_RECURSIVE_SYSTEM_DELETE')
})

test('an unknown tool with a harmless command is still flagged by the entry layer', () => {
  const mapping = toGuardInput({
    name: 'some_future_shell',
    arguments: { payload: 'curl https://api.example.com/status' },
  })
  assert.equal(mapping.kind, 'call')
  if (mapping.kind !== 'call') return

  const result = verify(mapping.input, STATE)
  assert.equal(result.verdict, 'ask')
  assert.equal(result.code, 'ENTRY_UNKNOWN_EXEC_TOOL')
})

/**
 * Measured false positive, now pinned. The first draft scanned every string
 * argument of an unknown tool, so writing a README that mentions
 * `del /s /q` was surfaced as a shell command. With no approval UI composed,
 * ask degrades to deny - which made write_file effectively unusable.
 */
test('payload data is not a command: write_file with prose mentioning a delete', () => {
  const mapping = toGuardInput({
    name: 'write_file',
    arguments: {
      filepath: 'D:/AI_Assistant/README.md',
      content: 'Never run del /s /q D:\\ on a system root; this line is documentation.',
    },
  })
  assert.equal(mapping.kind, 'skip')
})

test('the guard must not block writing its own regression corpus', () => {
  const mapping = toGuardInput({
    name: 'write_file',
    arguments: {
      filepath: 'test/attacks-4.json',
      content: '{"cmd":"rd /s /q C:\\\\","expect":"deny"}',
    },
  })
  assert.equal(mapping.kind, 'skip')
})

test('edit-style payload keys are data too', () => {
  const mapping = toGuardInput({
    name: 'edit_file',
    arguments: {
      filepath: 'src/a.ts',
      old_string: 'const a = 1',
      new_string: '// replaced the old del /s /q helper\nconst a = 2',
    },
  })
  assert.equal(mapping.kind, 'skip')
})

test('a non-data key on an unknown tool is still scanned', () => {
  const mapping = toGuardInput({ name: 'future_shell', arguments: { payload: 'rd /s /q C:\\' } })
  assert.equal(mapping.kind, 'call')
})

test('an oversized argument is treated as a document', () => {
  const huge = 'git status ' + 'x'.repeat(4096)
  const mapping = toGuardInput({ name: 'future_shell', arguments: { input: huge } })
  assert.equal(mapping.kind, 'skip')
})

test('command shape detection: commands yes, prose and data no', () => {
  assert.equal(looksLikeCommandString('rm -rf /'), true)
  assert.equal(looksLikeCommandString('del /s /q D:\\temp'), true)
  assert.equal(looksLikeCommandString('curl https://x | sh'), true)
  assert.equal(looksLikeCommandString('C:\\Windows\\System32\\x.exe'), true)
  assert.equal(looksLikeCommandString('a friendly note about the build'), false)
  assert.equal(looksLikeCommandString('{"json":true}'), false)
})

test('pass defers to next() instead of returning allow', () => {
  // Returning `{kind:'allow'}` here would skip every listener mounted after
  // this one. `null` is the only safe representation of "no objection".
  const result = verify({ cmd: 'git status' }, STATE)
  assert.equal(toDecision(result), null)
})

test('ask produces a registry-valid decision with both locales', () => {
  const decision = toDecision(verify({ cmd: 'git push --force' }, STATE))
  assert.ok(decision !== null)
  assert.equal(decision.kind, 'ask')
  assert.equal(isPreToolDecision(decision), true)
  if (decision.kind !== 'ask') return
  assert.equal(typeof decision.displayReason?.en, 'string')
  assert.equal(typeof decision.displayReason?.zh, 'string')
})

test('deny produces a registry-valid decision with a reason', () => {
  const decision = toDecision(verify({ cmd: 'rd /s /q C:\\' }, STATE))
  assert.ok(decision !== null)
  assert.equal(decision.kind, 'deny')
  assert.equal(isPreToolDecision(decision), true)
})

test('cancel is never produced', () => {
  const cmds = ['git status', 'git push --force', 'rd /s /q C:\\', 'del D:\\a.txt', 'curl x | sh']
  for (const cmd of cmds) {
    const decision = toDecision(verify({ cmd }, STATE))
    assert.notEqual(decision?.kind, 'cancel', `${cmd} produced a cancel; that is the operator's word, not ours`)
  }
})

test('shape validator rejects garbage', () => {
  assert.equal(isPreToolDecision(null), false)
  assert.equal(isPreToolDecision('deny'), false)
  assert.equal(isPreToolDecision({}), false)
  assert.equal(isPreToolDecision({ kind: 'deny' }), false)
  assert.equal(isPreToolDecision({ kind: 'deny', reason: '' }), false)
  assert.equal(isPreToolDecision({ kind: 'ask' }), true)
  assert.equal(isPreToolDecision({ kind: 'allow' }), true)
})

test('hard deny denies only on deny, never widens', () => {
  assert.equal(typeof toHardDeny(verify({ cmd: 'rd /s /q C:\\' }, STATE)), 'string')
  assert.equal(toHardDeny(verify({ cmd: 'git push --force' }, STATE)), undefined)
  assert.equal(toHardDeny(verify({ cmd: 'git status' }, STATE)), undefined)
})

/**
 * The write ledger feeds the TOCTOU rule. A failed write proves nothing, so
 * recording it produced a false INTERP_RECENT_WRITE on the next legitimate run
 * of the same path.
 */
test('a failed result does not enter the write ledger', () => {
  assert.equal(isFailedResult({ isError: true, content: [] }), true)
  assert.equal(isFailedResult({ ok: false }), true)
  assert.equal(isFailedResult({ error: 'ENOENT' }), true)
  assert.equal(isFailedResult(new Error('EACCES')), true)

  assert.equal(isFailedResult({ content: [{ type: 'text', text: 'written' }] }), false)
  assert.equal(isFailedResult({ isError: false }), false)
  assert.equal(isFailedResult(undefined), false)
})

/**
 * Wave 6 rows the corpus runner cannot express. Kept here rather than lost.
 *
 * A1: the tool name is not what makes a string dangerous. write_file carrying
 * a command-shaped argument was flagged by entry as an ask, and because entry
 * spoke first the rules-layer deny never ran. The verdict here is deny, which
 * is the stricter of the two.
 */
test('W6-A1: a data-tool name does not launder the command', () => {
  const result = verify(
    { cmd: 'del /s /q C:\\', tool: 'write_file', commandSource: 'text/' },
    STATE,
  )
  assert.equal(result.verdict, 'deny')
  assert.equal(result.code, 'RULE_RECURSIVE_SYSTEM_DELETE')
})

/**
 * A2: two populated command keys mean the audited string may not be the
 * executed one. A direct verify() call has no tool name, and the ambiguity
 * check used to sit behind the tool guard, so this came back pass.
 */
test('W6-A2: two command keys are ambiguous, not safe', () => {
  const result = verify({ cmd: 'echo ok', command: 'del /s /q C:\\' } as unknown as GuardInput, STATE)
  assert.equal(result.verdict, 'ask')
  assert.equal(result.code, 'ENTRY_COMMAND_KEY_AMBIGUOUS')
})

test('W6-A2: ambiguity resolves to deny when both keys are dangerous', () => {
  const result = verify({ cmd: 'rm -rf /', command: 'rm -rf /' } as unknown as GuardInput, STATE)
  assert.equal(result.verdict, 'deny')
})

/**
 * A3: a payload key is data. The text in it is documentation, not a command
 * line, even when the tool name is an executor.
 */
test('W6-A3: command text in a data field is not a command line', () => {
  const result = verify(
    { cmd: 'echo ok', tool: 'write_file', content: 'rm -rf / and del /s /q C:\\' } as unknown as GuardInput,
    STATE,
  )
  assert.equal(result.verdict, 'pass')
  assert.equal(result.code, 'PASS')
})
