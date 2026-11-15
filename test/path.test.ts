/**
 * Unit tests for path resolution.
 *
 * Two properties, and neither can be stated in a verdict:
 *
 *   1. Every spelling of one location lands on one key. This is the whole
 *      reason the module exists - before it, `%USERPROFILE%\Documents` and
 *      `C:\Users\me\Documents` were two different targets to every layer
 *      downstream, and only one of them matched a sensitive-root test.
 *
 *   2. Anything whose value depends on state outside the command string is
 *      `dynamic`, not resolved. A guard that turns "I cannot tell" into a
 *      path-shaped guess has already failed; the guess is the bypass.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import type { DynamicReason, PathContext } from '../src/guard/path.js'
import {
  isUnder,
  pathKey,
  resolveFullPath,
  resolvePath,
  samePath,
} from '../src/guard/path.js'

const CTX: PathContext = {
  cwd: 'C:\\Users\\scp57\\AppData\\Local',
  home: 'C:\\Users\\scp57',
  env: {
    USERPROFILE: 'C:\\Users\\scp57',
    // Nested reference: the %TEMP% case only resolves if expansion iterates.
    TEMP: '%USERPROFILE%\\AppData\\Local\\Temp',
    A: '%B%\\x',
    B: 'C:\\data',
    LOOP: '%LOOP%',
    mixedcase: 'C:\\lower',
  },
  platform: 'win32',
}

function keyOf(raw: string, ctx: PathContext = CTX): string {
  const resolved = resolvePath(raw, ctx)
  assert.equal(
    resolved.source,
    'resolved',
    `${JSON.stringify(raw)} should resolve, got dynamic/${resolved.reason}`,
  )
  return resolved.key
}

function reasonOf(raw: string, ctx: PathContext = CTX): DynamicReason | null {
  return resolvePath(raw, ctx).reason
}

test('every spelling of one directory collapses to one key', () => {
  const target = 'c:/users/scp57/documents'

  const spellings = [
    // Separators, case, duplication, trailing slash.
    'C:\\Users\\scp57\\Documents',
    'c:/users/scp57/documents',
    'C:\\Users\\scp57\\Documents\\',
    'C:/Users//scp57///Documents',
    'C:\\USERS\\SCP57\\DOCUMENTS',
    // Dot segments.
    'C:\\Users\\scp57\\.\\Documents',
    'C:\\Users\\scp57\\Documents\\.\\',
    'C:\\Users\\scp57\\AppData\\..\\Documents',
    'C:\\Users\\..\\Users\\scp57\\Documents',
    // Environment references, all three spellings.
    '%USERPROFILE%\\Documents',
    '%userprofile%\\Documents',
    '$env:USERPROFILE\\Documents',
    '${env:USERPROFILE}\\Documents',
    // Tilde.
    '~\\Documents',
    '~/Documents',
    // Quoting, which callers may or may not have stripped.
    '  C:\\Users\\scp57\\Documents  ',
    '"C:\\Users\\scp57\\Documents"',
    "'C:\\Users\\scp57\\Documents'",
    // Win32 long-path prefix, transparent to the argument.
    '\\\\?\\C:\\Users\\scp57\\Documents',
    // Trailing dots and spaces, which Win32 drops from each component.
    'C:\\Users\\scp57\\Documents.',
    'C:\\Users\\scp57\\Documents ',
    'C:\\Users\\scp57\\Documents. ',
    // Relative to the process cwd, including the climb back up.
    '..\\..\\Documents',
    'C:\\Users\\scp57\\AppData\\Local\\..\\..\\Documents',
    './../../Documents',
  ]

  for (const raw of spellings) assert.equal(keyOf(raw), target, raw)
})

test('a drive root is a root, and nothing climbs above it', () => {
  assert.equal(keyOf('C:\\'), 'c:/')
  assert.equal(keyOf('c:\\'), 'c:/')
  assert.equal(keyOf('C:/'), 'c:/')
  assert.equal(keyOf('C:\\..'), 'c:/')
  assert.equal(keyOf('C:\\..\\..\\..\\Windows'), 'c:/windows')
  assert.equal(keyOf('D:\\data\\'), 'd:/data')
})

test('a network path keeps its server and share in the key', () => {
  assert.equal(keyOf('\\\\server\\share\\dir'), '//server/share/dir')
  assert.equal(keyOf('\\\\SERVER\\Share\\dir'), '//server/share/dir')
  assert.equal(keyOf('\\\\server\\share'), '//server/share/')
  assert.equal(keyOf('//server/share/dir'), '//server/share/dir')
  assert.equal(keyOf('\\\\?\\UNC\\server\\share\\dir'), '//server/share/dir')
  assert.equal(keyOf('\\\\server\\share\\..\\..\\dir'), '//server/share/dir')
})

test('variable expansion iterates until it settles', () => {
  assert.equal(keyOf('%TEMP%'), 'c:/users/scp57/appdata/local/temp')
  assert.equal(keyOf('%A%'), 'c:/data/x')
  assert.equal(keyOf('C:\\Users\\scp57\\AppData\\Local\\..\\..\\..\\..'), 'c:/')
})

test('the platform decides what a leading separator means', () => {
  // POSIX: a leading separator is the filesystem root.
  assert.equal(keyOf('/etc/passwd', { platform: 'posix' }), '/etc/passwd')
  // Windows: it is the root of the *current drive*, which is not in the token.
  assert.equal(keyOf('/Windows/System32'), 'c:/windows/system32')
  assert.equal(reasonOf('/Windows/System32', { ...CTX, cwd: '' }), 'unknown-cwd')
})

const DYNAMIC: ReadonlyArray<readonly [string, DynamicReason, PathContext?]> = [
  ['', 'empty'],
  ['   ', 'empty'],
  ['""', 'empty'],
  ['%NOPE%\\x', 'undefined-var'],
  ['$env:NOPE\\x', 'undefined-var'],
  ['${env:NOPE}\\x', 'undefined-var'],
  ['${USERPROFILE}\\x', 'undefined-var'],
  // A bare `$NAME` is a shell variable, not an environment variable.
  ['$USERPROFILE\\Documents', 'undefined-var'],
  ['%LOOP%', 'unstable-expansion'],
  ['~other\\x', 'other-user-home'],
  // `C:foo` is relative to C:'s *current directory*, which is not `C:\`.
  ['C:foo', 'drive-relative'],
  ['C:', 'drive-relative'],
  ['C:..\\Windows', 'drive-relative'],
  ['\\\\.\\PhysicalDrive0', 'device-path'],
  ['\\\\?\\Volume{8f2a}\\', 'device-path'],
  ['\\\\server', 'device-path'],
  ['echo $(rm -rf /)', 'substitution'],
  ['`rm -rf /`', 'substitution'],
  ['foo\\bar', 'unknown-cwd', { ...CTX, cwd: '' }],
]

test('a path that depends on unreadable state is dynamic, never resolved', () => {
  for (const [raw, expected, ctx] of DYNAMIC) {
    const resolved = resolvePath(raw, ctx ?? CTX)
    assert.equal(resolved.source, 'dynamic', `${JSON.stringify(raw)} must not resolve`)
    assert.equal(resolved.reason, expected, raw)
    assert.equal(resolved.key, '', `${JSON.stringify(raw)} must not carry a key`)
  }
})

test('a wildcard resolves but is marked, because its parent is the only known part', () => {
  const star = resolvePath('C:\\Windows\\*', CTX)
  assert.equal(star.source, 'resolved')
  assert.equal(star.key, 'c:/windows/*')
  assert.equal(star.hasGlob, true)

  const partial = resolvePath('C:\\Win*\\System32', CTX)
  assert.equal(partial.hasGlob, true)

  const plain = resolvePath('C:\\Windows', CTX)
  assert.equal(plain.hasGlob, false)
})

test('containment respects a separator boundary', () => {
  const documents = resolvePath('C:\\Users\\scp57\\Documents', CTX)
  const inside = resolvePath('C:\\Users\\scp57\\Documents\\a.txt', CTX)
  const sibling = resolvePath('C:\\Users\\scp57\\Documents2', CTX)
  const prefixName = resolvePath('C:\\Users\\scp5', CTX)
  const windows = resolvePath('C:\\Windows', CTX)
  const root = resolvePath('C:\\', CTX)

  assert.equal(isUnder(inside, documents), true)
  assert.equal(isUnder(documents, documents), true)
  assert.equal(isUnder(sibling, documents), false)
  assert.equal(isUnder(prefixName, resolvePath('C:\\Users\\scp57', CTX)), false)
  assert.equal(isUnder(windows, root), true)
  assert.equal(isUnder(root, windows), false)
})

test('containment is not asserted for anything unresolved or wildcarded', () => {
  const windows = resolvePath('C:\\Windows', CTX)
  const globbed = resolvePath('C:\\Windows\\*', CTX)
  const relative = resolvePath('%NOPE%\\x', CTX)

  assert.equal(isUnder(globbed, windows), false)
  assert.equal(isUnder(relative, windows), false)
  assert.equal(isUnder(windows, relative), false)
})

test('reparse points are resolved only when a realpath is supplied', () => {
  const realpath = (key: string): string => {
    if (key === 'c:/users/all users') return 'C:\\ProgramData'
    if (key === 'c:/documents and settings') return 'C:\\Users'
    throw new Error('ENOENT')
  }

  const ctx: PathContext = { ...CTX, realpath }

  // The junction alias and its target are the same location.
  assert.equal(resolveFullPath('C:\\Users\\All Users', ctx).key, 'c:/programdata')
  assert.equal(resolveFullPath('C:\\ProgramData', ctx).key, 'c:/programdata')
  assert.equal(
    samePath(resolveFullPath('C:\\Users\\All Users', ctx), resolveFullPath('C:\\ProgramData', ctx)),
    true,
  )

  // A path that does not exist is not an error: the lexical answer stands.
  assert.equal(resolveFullPath('C:\\Users\\scp57\\Documents', ctx).key, 'c:/users/scp57/documents')

  // Without a realpath, the alias is only a different spelling of itself.
  assert.equal(resolvePath('C:\\Users\\All Users', CTX).key, 'c:/users/all users')
})

test('samePath refuses to compare anything unresolved', () => {
  assert.equal(samePath(resolvePath('C:\\Windows', CTX), resolvePath('c:/WINDOWS/', CTX)), true)
  assert.equal(samePath(resolvePath('C:\\Windows', CTX), resolvePath('C:\\Windows\\..', CTX)), false)
  assert.equal(samePath(resolvePath('%NOPE%', CTX), resolvePath('%NOPE%', CTX)), false)
})

test('pathKey gives the comparison key or null, never a guess', () => {
  assert.equal(pathKey('C:\\Windows\\System32', CTX), 'c:/windows/system32')
  assert.equal(pathKey('C:\\Windows\\.\\System32\\', CTX), 'c:/windows/system32')
  assert.equal(pathKey('%NOPE%\\x', CTX), null)
})
