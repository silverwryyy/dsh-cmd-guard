/**
 * The scope layer: where a command is pointed, read as a location.
 *
 * Each block locks one property that the regex table this replaced could not
 * hold. Spelling, expansion and depth are the three that were measured as
 * holes; roots, ancestors and wildcards are the three that no table can carry,
 * because they depend on the machine and on where the workspace sits.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { classifyToken, inspectTargets, type ScopeContext } from '../src/guard/scope.js'
import { verify } from '../src/guard/verify.js'
import type { GuardState } from '../src/guard/types.js'

/** Pinned environment: these answers must not depend on the host's drives. */
const CTX: ScopeContext = {
  platform: 'win32',
  cwd: 'D:/work/project',
  home: 'C:/Users/me',
  workspaceRoot: 'D:/work/project',
  env: {
    USERPROFILE: 'C:\\Users\\me',
    SystemRoot: 'C:\\Windows',
    windir: 'C:\\Windows',
    ProgramFiles: 'C:\\Program Files',
    'ProgramFiles(x86)': 'C:\\Program Files (x86)',
    ProgramData: 'C:\\ProgramData',
    SystemDrive: 'C:',
    TEMP: 'C:\\Users\\me\\AppData\\Local\\Temp',
    TMP: 'C:\\Users\\me\\AppData\\Local\\Temp',
  },
}

function level(token: string, ctx: ScopeContext = CTX): string {
  const scope = classifyToken(token, ctx)
  return scope === null ? 'not-a-location' : scope.level
}

test('one location, many spellings, one answer', () => {
  const spellings = [
    'C:\\Users\\me\\Documents',
    'C:/Users/me/Documents',
    'c:\\users\\ME\\documents',
    '"C:\\Users\\me\\Documents"',
    'C:\\Users\\me\\Documents\\',
    'C:\\Users\\me\\.\\Documents',
    'C:\\Users\\me\\Documents.\\',
    'C:\\Users\\..\\Users\\me\\Documents',
    'C:\\..\\Users\\me\\Documents',
    '\\\\?\\C:\\Users\\me\\Documents',
    '$env:USERPROFILE\\Documents',
    '${env:USERPROFILE}\\Documents',
    'C:\\Users\\me/AppData\\..\\Documents',
    '%USERPROFILE%\\Documents',
    '~\\Documents',
    '~/Documents',
    'DOCUMENTS',
  ]

  for (const token of spellings.slice(0, 16)) {
    const scope = classifyToken(token, CTX)
    assert.ok(scope !== null, `${token} should be read as a location`)
    assert.equal(scope.level, 'sensitive', `${token} should land in the home directory: ${scope.level}`)
    assert.equal(scope.key, 'c:/users/me/documents', `${token} should key to the same path`)
  }

  // A bare relative word is not a location here: it is indistinguishable from
  // an ordinary argument, and that call belongs to the rules layer.
  assert.equal(level('DOCUMENTS'), 'not-a-location')
})

test('depth is containment, not equality: the profile itself is sensitive', () => {
  assert.equal(level('C:\\Users'), 'sensitive')
  assert.equal(level('C:\\Users\\me'), 'sensitive')
  assert.equal(level('C:\\Users\\me\\Documents\\thesis'), 'sensitive')
  assert.equal(level('C:\\Windows'), 'sensitive')
  assert.equal(level('C:\\Windows\\System32\\drivers'), 'sensitive')
})

test('a volume, share or device root is structural', () => {
  assert.equal(level('C:\\'), 'root')
  assert.equal(level('C:/'), 'root')
  assert.equal(level('//server/share'), 'root')
  // A share's contents are an ordinary location: a network share is not a
  // system location, and every mapped drive would otherwise be noise. The
  // root of the share is what this layer has an opinion about.
  assert.equal(level('//server/share/dir'), 'world')
  assert.equal(level('C:'), 'root', 'a bare drive letter names a directory on a whole drive')
  assert.equal(level('\\\\.\\PhysicalDrive0'), 'root')
  // A volume guid names a whole volume. Not resolvable, but not a directory
  // either, so it is a root rather than an unanswerable path.
  assert.equal(level('\\\\?\\Volume{8f3a-11}\\x'), 'root')
})

test('a directory that contains the workspace is an ancestor', () => {
  assert.equal(level('D:\\work'), 'ancestor')
  assert.equal(level('D:\\work\\project'), 'ancestor', 'the workspace root itself')
  assert.equal(level('D:\\work\\project\\src\\a.ts'), 'workspace')
  assert.equal(level('D:\\work\\other'), 'world')
})

test('a workspace inside a personal directory mutes that directory', () => {
  // Without this, every file in a workspace under Documents reads as sensitive,
  // the layer becomes noise, and an operator who mutes noise has muted it.
  const ctx: ScopeContext = { ...CTX, workspaceRoot: 'C:/Users/me/Documents/project' }
  assert.equal(level('C:\\Users\\me\\Documents\\project\\src\\a.ts', ctx), 'workspace')
  assert.equal(level('C:\\Users\\me\\Documents\\project', ctx), 'ancestor')
  assert.equal(level('C:\\Users\\me\\Documents\\other', ctx), 'sensitive')
})

test('a regenerable root is named as one', () => {
  assert.equal(level('%TEMP%\\build'), 'regenerable')
  assert.equal(level('C:\\Windows\\Temp\\x.log'), 'regenerable')
  assert.equal(level('D:\\work\\project\\node_modules\\pkg\\index.js'), 'workspace')
  assert.equal(level('D:\\work\\project\\node_modules'), 'workspace')
})

test('a wildcard is judged by the part that is fixed', () => {
  const sensitive = classifyToken('C:\\Windows\\System32\\*.dll', CTX)
  assert.equal(sensitive?.level, 'sensitive')
  assert.equal(sensitive?.hasGlob, true)

  // A wildcard in the first component leaves only the volume root fixed. That
  // is not an answer, so it is reported as unanswerable rather than as a root.
  assert.equal(level('C:\\Win*\\System32'), 'unknown')

  assert.equal(level('%TEMP%\\*'), 'regenerable')
  assert.equal(level('D:\\work\\project\\node_modules\\*'), 'workspace')
})

test('unreadable state is unknown, and unknown is never a level', () => {
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['$dir', 'undefined-var'],
    ['${weird}', 'undefined-var'],
    ['$(Get-Location)', 'substitution'],
    ['C:foo', 'drive-relative'],
    ['~other\\x', 'other-user-home'],
  ]
  for (const [token, reason] of cases) {
    const scope = classifyToken(token, CTX)
    assert.equal(scope?.level, 'unknown', `${token} must not be given a level`)
    assert.equal(scope?.dynamic, reason, `${token} reason`)
  }
})

test('a bare word is not a location, a flag is not a location', () => {
  for (const token of ['build', 'install', '--force', '-Recurse', 'payload.zip']) {
    assert.equal(level(token), 'not-a-location', `${token} should not be scanned as a path`)
  }
  // A flag that carries a destination still is one.
  assert.equal(level('--prefix=/etc/x'), 'sensitive')
  assert.equal(level('--output-dir=C:\\Windows'), 'sensitive')
})

test('a POSIX spelling is read as POSIX, even on win32', () => {
  assert.equal(level('/etc/passwd'), 'sensitive')
  assert.equal(level('/usr/bin/env'), 'sensitive')
  assert.equal(level('/tmp/x.log'), 'regenerable')
})

test('the registry is a namespace, not a path', () => {
  assert.equal(level('HKLM\\SOFTWARE\\Run'), 'sensitive')
  assert.equal(level('HKCU\\Environment'), 'sensitive')
  // The long spellings are as legal as the short ones, and `reg` accepts both.
  // A cwd on D: is deliberate: inside the profile these would have answered
  // `sensitive` for the wrong reason.
  for (const hive of [
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Run',
    'HKEY_CURRENT_USER\\Software\\Foo',
    'HKEY_CLASSES_ROOT\\.exe',
    'HKEY_USERS\\S-1-5-21\\Environment',
  ]) {
    assert.equal(level(hive), 'sensitive', `${hive} must be read as the registry`)
  }
  // A hive named alone is still the hive, not a word.
  assert.equal(level('HKLM'), 'sensitive')
  assert.equal(level('HKEY_LOCAL_MACHINE'), 'sensitive')
  // And a name that merely starts with those letters is not the registry.
  assert.equal(level('hku.txt'), 'not-a-location')
  assert.equal(level('hkey_local'), 'not-a-location')
})

test('the whitelist is a claim about every target, not about silence', () => {
  const temp = inspectTargets(['Remove-Item', '-Recurse', '-Force', '%TEMP%\\*'], CTX)
  assert.equal(temp.regenerableOnly, true, 'every target is regenerable')

  const documents = inspectTargets(
    ['Remove-Item', '-Recurse', '-Force', '%TEMP%\\*', 'C:\\Users\\me\\Documents'],
    CTX,
  )
  assert.equal(documents.regenerableOnly, false, 'one unproven target is enough to refuse')

  const none = inspectTargets(['Remove-Item', '-Recurse'], CTX)
  assert.equal(none.regenerableOnly, false, 'no target is not proof of safety')
})

test('recursion into an unrecoverable location asks without a force flag', () => {
  const state: GuardState = { workspaceRoot: 'D:/AI_Assistant' }
  for (const cmd of [
    'Remove-Item -Recurse C:\\Users\\me',
    'Remove-Item -Recurse C:/Users/me',
    'Remove-Item -Recurse $env:USERPROFILE\\Documents',
  ]) {
    const result = verify({ cmd }, state)
    assert.equal(result.verdict, 'ask', `${cmd}: ${result.verdict} (${result.layer}/${result.code})`)
  }

  // The same target through a hard rule is denied, not asked. Stronger is
  // fine; this test only pins that it is never silent.
  const denied = verify({ cmd: 'rmdir /s C:\\Users' }, state)
  assert.equal(denied.verdict, 'deny', `${denied.layer}/${denied.code}`)
})

test('a hive answers the same in both spellings', () => {
  const state: GuardState = { workspaceRoot: 'D:/AI_Assistant' }

  const pairs: ReadonlyArray<readonly [string, string]> = [
    ['HKLM', 'HKEY_LOCAL_MACHINE'],
    ['HKCR', 'HKEY_CLASSES_ROOT'],
    ['HKU', 'HKEY_USERS'],
    ['HKCC', 'HKEY_CURRENT_CONFIG'],
    ['HKCU', 'HKEY_CURRENT_USER'],
  ]
  for (const [short, long] of pairs) {
    const a = verify({ cmd: `reg delete ${short}\\Software\\k /f` }, state).verdict
    const b = verify({ cmd: `reg delete ${long}\\Software\\k /f` }, state).verdict
    assert.equal(b, a, `${long} must answer what ${short} answers: ${b} vs ${a}`)
  }

  // The asymmetry between machine and user hives is the design: destroying a
  // machine hive has no undo, destroying your own has a backup.
  for (const hive of ['HKLM', 'HKEY_LOCAL_MACHINE', 'HKCR', 'HKEY_CLASSES_ROOT']) {
    const result = verify({ cmd: `reg delete ${hive}\\Software\\k /f` }, state)
    assert.equal(result.verdict, 'deny', `${hive}: ${result.verdict} (${result.layer}/${result.code})`)
  }
  for (const hive of ['HKCU', 'HKEY_CURRENT_USER']) {
    const result = verify({ cmd: `reg delete ${hive}\\Software\\k /f` }, state)
    assert.equal(result.verdict, 'ask', `${hive}: ${result.verdict} (${result.layer}/${result.code})`)
  }

  // Reading a hive is not a write, whatever the spelling.
  for (const hive of ['HKLM', 'HKEY_LOCAL_MACHINE']) {
    assert.equal(verify({ cmd: `reg query ${hive}\\SOFTWARE\\Microsoft` }, state).verdict, 'pass')
  }
})

test('the same recursion inside the workspace stays silent', () => {
  const state: GuardState = { workspaceRoot: 'D:/AI_Assistant' }
  for (const cmd of ['Remove-Item -Recurse D:\\AI_Assistant\\tmp\\x', 'Get-ChildItem -Recurse']) {
    const result = verify({ cmd }, state)
    assert.notEqual(result.verdict, 'deny', cmd)
  }
})
