/**
 * Where a command is pointed, decided by shape rather than by a list.
 *
 * capability.ts used to answer this with SENSITIVE_TARGET: a table of anchored
 * regexes over the raw token. That table has three blind spots, and none of
 * them is about coverage - they are about what a regex can see.
 *
 *   spelling    the patterns are written with backslashes, so `C:/Windows`
 *               never matched `[a-z]:\\windows`. One target, two spellings,
 *               one of them unpoliced.
 *   expansion   `$env:USERPROFILE\Documents` and `%USERPROFILE%\Documents`
 *               are not paths as far as a regex is concerned, so the most
 *               natural way for a model to name a home directory was
 *               invisible to every pattern in the table.
 *   depth       `^[a-z]:\\users\\?$` matches `C:\Users` and not
 *               `C:\Users\me`, so deleting a profile matched nothing: the
 *               patterns describe a location, and the command named a place
 *               inside it.
 *
 * path.ts answers the first two by resolving to a comparison key. That leaves
 * the third, and it is the one worth the most: containment is a different
 * question from equality, and `isUnder` is the shape of the answer.
 *
 * What this module adds on top of containment is what no list can hold:
 *
 *   roots       a volume root or a share root. Dangerous because of how much
 *               it contains, not because of its name - and "every path that is
 *               a drive" is not an enumerable set.
 *   ancestors   a directory that contains the workspace. Which directory that
 *               is depends on where the operator put the workspace, so a
 *               shipped list cannot name it, and it is the most destructive
 *               thing a scoped-looking command can reach: `rm -rf ..` from
 *               inside the tree.
 *   shape       recursive x wildcard x depth. `del *.py` in a project and
 *               `del C:\Windows\System32\*.dll` are the same verb and the same
 *               flag; what separates them is where the wildcard lands.
 *
 * The whitelist lives here rather than in a module of its own because it
 * exists to absorb this layer's false positives, and putting it elsewhere
 * invites widening the criteria instead. It may only name roots that a normal
 * command rebuilds - temp, package caches, build output - which is what stops
 * it becoming the next enumeration problem. It is also the only rule in this
 * file that can subtract anything; every other rule adds.
 *
 * This module produces no verdict. It reports levels; capability.ts decides
 * what a level is worth, and only the rules layer may deny.
 */
import { resolvePath, resolveFullPath, type DynamicReason, type PathContext } from './path.js'
import { REGISTRY_HIVE } from './verbs.js'

export type ScopeLevel =
  /** A volume, share or device root. Contains everything. */
  | 'root'
  /** Contains the workspace, or is the workspace root itself. */
  | 'ancestor'
  /** A system, account or personal location. */
  | 'sensitive'
  /** A root whose contents an ordinary command rebuilds. */
  | 'regenerable'
  /** Inside the workspace and not the root of it. */
  | 'workspace'
  /** An ordinary absolute location elsewhere. No opinion. */
  | 'world'
  /** Depends on state this process cannot read. Never safe, never a target. */
  | 'unknown'

export interface ScopeContext extends PathContext {
  /** Absolute workspace root. Ancestor checks are meaningless without it. */
  readonly workspaceRoot?: string | undefined
}

export interface TargetScope {
  /** The token as it appeared, after quote and `--flag=` removal. */
  readonly token: string
  readonly level: ScopeLevel
  /** Comparison key when resolved, null when not. */
  readonly key: string | null
  /** Case-preserved spelling for messages. */
  readonly display: string | null
  /** Which zone matched, for the message. Null when no zone did. */
  readonly zone: string | null
  /** Set when the value could not be read statically. */
  readonly dynamic: DynamicReason | null
  /** A wildcard is present. It changes what "inside" means, so it is tracked. */
  readonly hasGlob: boolean
}

export interface ScopeReport {
  readonly targets: readonly TargetScope[]
  /**
   * Every location-bearing token was proven to sit inside a regenerable root.
   *
   * False when there are no targets: an argument-free command has not proven
   * anything, and treating silence as proof is how a whitelist starts lying.
   */
  readonly regenerableOnly: boolean
}

/**
 * Personal directories directly under the home directory.
 *
 * These are the ones whose loss is not recoverable by re-running a command,
 * which is the only criterion for being on this list. `source`, `repos` and
 * `projects` are here because they are where a developer's work lives: a
 * recursive delete of one of those is the same class of event as a recursive
 * delete of Documents.
 */
const PERSONAL: readonly string[] = [
  'documents',
  'desktop',
  'downloads',
  'onedrive',
  'pictures',
  'videos',
  'music',
  'appdata',
  '.ssh',
  '.gnupg',
  '.aws',
  '.kube',
  '.azure',
  'source',
  'repos',
]

/**
 * Roots rebuilt by an ordinary command, relative to the workspace.
 *
 * Membership is a claim that deleting the directory costs time and nothing
 * else. A dependency cache, a build tree, a byte-compiled copy: each is a
 * function of sources that remain. Nothing here holds hand-written content.
 */
const REGENERABLE: readonly string[] = [
  'node_modules',
  'tmp',
  'temp',
  '.cache',
  'dist',
  'build',
  'out',
  'coverage',
  '__pycache__',
  '.pytest_cache',
  '.next',
  '.turbo',
  '.parcel-cache',
  '.svelte-kit',
]

/**
 * Forms that are not filesystem paths at all, on either platform.
 *
 * A registry hive is a namespace, and `-v /:/host` names the machine's root as
 * a mount source: the colon separates source from destination, so the root is
 * the token's first half. Both read as strings, and both were passing.
 */
const ROOT_MOUNT = /^\/:/
/** `C:\:C:\` - a drive root used as a volume source, so a root, split by ':'. */
const DRIVE_VOLUME = /^[a-z]:\\:/i

/**
 * A bare drive letter: `C:`.
 *
 * Drive-relative in shell terms - it means the *current directory of C:*, which
 * lives in that drive's process state and is not readable here. That is exactly
 * why it cannot be treated as harmless: the directory it names is unknown, and
 * it is a directory on a whole drive. Reported as a root, which is the
 * fail-closed reading of "some directory on this volume".
 */
const DRIVE_ONLY = /^[A-Za-z]:$/

/**
 * A POSIX absolute path, recognised on Windows too.
 *
 * On win32 `resolvePath` reads `/etc` as "etc under the current drive", which
 * is faithful to cmd and is not what the token means when it was written for a
 * POSIX shell: `unzip payload.zip -d /etc` names the system configuration
 * directory. Judged by the spelling in that case, because the platform the
 * command was written for is not necessarily the platform it runs on. Applied
 * only on win32 - on posix these already resolve into the zone table.
 */
/**
 * A token that names a remote location rather than a local one.
 *
 * `curl https://api.example.com/status` and `scp a.txt user@example.com:/tmp`
 * were both resolved as local relative paths - the first to a directory called
 * `https:` - and both passed only because the fiction happened to land inside
 * the workspace. Move the workspace, or start the process somewhere else, and
 * the same command became an ask. The token is not a path, so this layer has to
 * say so instead of resolving it.
 *
 * A drive letter is never a remote host: `C:/tmp` has no dot before the colon,
 * and `C:\` is caught by DRIVE_ABSOLUTE long before this test.
 */
const URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i
const REMOTE_PATH = /^(?:[^\s\\/@]+@)?[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9]{2,}:/i

const POSIX_SYSTEM =
  /^\/(?:etc|bin|sbin|boot|usr|lib|lib64|opt|root|home|dev|proc|sys)(?:\/|$)/i
const POSIX_TEMP = /^\/(?:tmp|var\/tmp)(?:\/|$)/i

interface Zone {
  readonly key: string
  readonly label: string
  readonly regenerate: boolean
}

interface ZoneSpec {
  readonly spec: string
  readonly label: string
  readonly regenerate: boolean
}

function platformOf(ctx: ScopeContext): 'win32' | 'posix' {
  if (ctx.platform !== undefined) return ctx.platform
  return typeof process !== 'undefined' && process.platform === 'win32' ? 'win32' : 'posix'
}

function envOf(ctx: ScopeContext): Readonly<Record<string, string | undefined>> {
  if (ctx.env !== undefined) return ctx.env
  return typeof process !== 'undefined' ? process.env : {}
}

function homeOf(ctx: ScopeContext): string | undefined {
  if (ctx.home !== undefined) return ctx.home
  const env = envOf(ctx)
  return env['USERPROFILE'] ?? env['HOME']
}

/** Every zone the current platform, environment and workspace imply. */
function zoneSpecs(ctx: ScopeContext): ZoneSpec[] {
  const env = envOf(ctx)
  const specs: ZoneSpec[] = []

  if (platformOf(ctx) === 'win32') {
    const win = env['SystemRoot'] ?? env['windir'] ?? 'C:\\Windows'
    const pf = env['ProgramFiles'] ?? 'C:\\Program Files'
    const pf86 = env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)'
    const pd = env['ProgramData'] ?? 'C:\\ProgramData'
    const drive = env['SystemDrive'] ?? 'C:'

    specs.push(
      { spec: win, label: 'the Windows directory', regenerate: false },
      { spec: `${win}\\Temp`, label: 'the system temp directory', regenerate: true },
      { spec: pf, label: 'a program files directory', regenerate: false },
      { spec: pf86, label: 'a program files directory', regenerate: false },
      { spec: pd, label: 'the shared application data directory', regenerate: false },
      { spec: `${drive}\\Users`, label: 'the user profiles directory', regenerate: false },
      { spec: `${drive}\\PerfLogs`, label: 'a system logging directory', regenerate: false },
      { spec: `${drive}\\Recovery`, label: 'the recovery directory', regenerate: false },
    )

    const home = homeOf(ctx)
    if (home !== undefined) {
      specs.push({ spec: home, label: 'the home directory', regenerate: false })
      for (const name of PERSONAL) {
        specs.push({ spec: `${home}\\${name}`, label: `"${name}" in the home directory`, regenerate: false })
      }
    }

    const temp = env['TEMP'] ?? env['TMP']
    if (temp !== undefined) specs.push({ spec: temp, label: 'the user temp directory', regenerate: true })
  } else {
    const system: ReadonlyArray<readonly [string, string]> = [
      ['/etc', 'the system configuration directory'],
      ['/bin', 'a system binary directory'],
      ['/sbin', 'a system binary directory'],
      ['/usr', 'the system software tree'],
      ['/boot', 'the boot directory'],
      ['/var', 'the variable data tree'],
      ['/lib', 'a system library directory'],
      ['/lib64', 'a system library directory'],
      ['/opt', 'the optional software tree'],
      ['/root', 'the root account home'],
      ['/home', 'the home directory root'],
      ['/dev', 'the device tree'],
      ['/proc', 'the process tree'],
      ['/sys', 'the kernel tree'],
      ['/System', 'the operating system'],
      ['/Library', 'the system library tree'],
      ['/Applications', 'the applications directory'],
    ]
    for (const [spec, label] of system) specs.push({ spec, label, regenerate: false })

    specs.push(
      { spec: '/tmp', label: 'the temp directory', regenerate: true },
      { spec: '/var/tmp', label: 'the temp directory', regenerate: true },
    )

    const home = homeOf(ctx)
    if (home !== undefined) specs.push({ spec: home, label: 'the home directory', regenerate: false })
  }

  const workspace = ctx.workspaceRoot
  if (workspace !== undefined) {
    for (const name of REGENERABLE) {
      specs.push({ spec: `${workspace}/${name}`, label: `"${name}"`, regenerate: true })
    }
  }

  return specs
}

function buildZones(ctx: ScopeContext): Zone[] {
  const zones: Zone[] = []
  for (const spec of zoneSpecs(ctx)) {
    const resolved = resolvePath(spec.spec, ctx)
    if (resolved.source !== 'resolved' || resolved.hasGlob) continue
    zones.push({ key: resolved.key, label: spec.label, regenerate: spec.regenerate })
  }
  return zones
}

/** Separator-aware containment, so `scoped` is not inside `scope`. */
function keyUnder(child: string, parent: string): boolean {
  if (child === parent) return true
  const base = parent.endsWith('/') ? parent : parent + '/'
  return child.startsWith(base)
}

/** A volume, share or device root: `c:/`, `//server/share/`, `/`. */
function isVolumeRoot(key: string): boolean {
  if (key === '/') return true
  if (/^[a-z]:\/$/.test(key)) return true
  if (/^\/\/[^/]+\/[^/]+\/$/.test(key)) return true
  return false
}

/**
 * The directory part of a key, up to its first wildcard.
 *
 * A wildcard makes containment unanswerable by string comparison, so the
 * question is re-asked about the part that is still fixed: `C:\Windows\*.dll`
 * is a wildcard inside `C:\Windows`, which is answerable. A wildcard in the
 * first component (`C:\Win*\System32`) leaves only the volume root fixed, and
 * that is not an answer - it returns null so the caller reports `unknown`
 * instead of claiming a root.
 */
function globBase(key: string): string | null {
  const at = key.search(/[*?]/)
  if (at < 0) return key
  const prefix = key.slice(0, at)
  const cut = prefix.lastIndexOf('/')
  if (cut < 0) return null
  if (cut === 0) return key.startsWith('/') ? '/' : null
  const base = prefix.slice(0, cut)
  if (/^[a-z]:$/.test(base)) return base + '/'
  return base.length === 0 ? null : base
}

interface Level {
  readonly level: ScopeLevel
  readonly zone: string | null
}

/**
 * Level of a pinned-down key.
 *
 * Order is the contract. A workspace that sits inside Documents is the reason
 * the workspace check runs before the zone check: without it, every file in
 * such a workspace would be "sensitive" and the layer would become noise, and
 * an operator who mutes noise has muted the layer.
 */
function levelOf(key: string, ctx: ScopeContext, zones: readonly Zone[]): Level {
  if (isVolumeRoot(key)) return { level: 'root', zone: null }

  const workspace = ctx.workspaceRoot
  if (workspace !== undefined) {
    const ws = resolvePath(workspace, ctx)
    if (ws.source === 'resolved') {
      if (key === ws.key) return { level: 'ancestor', zone: 'the workspace root' }
      if (keyUnder(key, ws.key)) return { level: 'workspace', zone: null }
      if (keyUnder(ws.key, key)) return { level: 'ancestor', zone: null }
    }
  }

  let best: Zone | null = null
  for (const zone of zones) {
    if (!keyUnder(key, zone.key)) continue
    if (best === null || zone.key.length > best.key.length) best = zone
  }
  if (best !== null) {
    return { level: best.regenerate ? 'regenerable' : 'sensitive', zone: best.label }
  }

  return { level: 'world', zone: null }
}

/**
 * Does this token look like it names a location?
 *
 * A bare word does not: `rm -rf build` and `rm -rf --force` are spelled the
 * same way to a string test, and treating every argument as a path is how a
 * layer ends up asking about everything. Words are left to the rules layer;
 * the price is that a bare relative name is not judged here, and that is the
 * cheap direction to be wrong in.
 */
function looksLikeLocation(token: string): boolean {
  if (/[\\/]/.test(token)) return true
  if (/^[~%$]/.test(token)) return true
  if (/^[A-Za-z]:/.test(token)) return true
  return false
}

/** Strip one option's leading `--name=` so the value is judged, not the flag. */
function stripFlag(token: string): string {
  return token.replace(/^--?[A-Za-z][A-Za-z0-9_-]*=/, '')
}

function unknownScope(token: string, dynamic: DynamicReason | null, hasGlob: boolean): TargetScope {
  return { token, level: 'unknown', key: null, display: null, zone: null, dynamic, hasGlob }
}

/**
 * Classify one token. Null when the token does not name a location at all.
 *
 * Every branch that cannot pin the value down returns `unknown` rather than a
 * guess. `unknown` is not a synonym for dangerous - it is a synonym for "this
 * layer cannot answer", and capability.ts only treats it as a signal when the
 * command also carries a shape that makes the answer matter.
 */
export function classifyToken(token: string, ctx: ScopeContext = {}): TargetScope | null {
  const plain = stripFlag(token.replace(/["'`]/g, ''))
  if (plain.length === 0) return null

  // Remote targets are not local paths, so no local question applies to them.
  // Checked before every zone test: `file:///etc/passwd` is a URL that happens
  // to contain a system path, and `user@host:/tmp` is a remote path that
  // happens to contain a slash.
  if (URL_SCHEME.test(plain) || REMOTE_PATH.test(plain)) return null

  if (REGISTRY_HIVE.test(plain)) {
    return { token: plain, level: 'sensitive', key: plain.toLowerCase(), display: plain, zone: 'the registry', dynamic: null, hasGlob: false }
  }
  if (ROOT_MOUNT.test(plain) || DRIVE_VOLUME.test(plain)) {
    return { token: plain, level: 'root', key: plain.toLowerCase(), display: plain, zone: 'a filesystem root', dynamic: null, hasGlob: false }
  }
  if (DRIVE_ONLY.test(plain)) {
    return { token: plain, level: 'root', key: plain.toLowerCase() + '/', display: plain, zone: 'a drive', dynamic: null, hasGlob: false }
  }

  if (platformOf(ctx) === 'win32') {
    if (POSIX_TEMP.test(plain)) {
      return { token: plain, level: 'regenerable', key: plain.toLowerCase(), display: plain, zone: 'a POSIX temp directory', dynamic: null, hasGlob: /[*?]/.test(plain) }
    }
    if (POSIX_SYSTEM.test(plain)) {
      return { token: plain, level: 'sensitive', key: plain.toLowerCase(), display: plain, zone: 'a POSIX system directory', dynamic: null, hasGlob: /[*?]/.test(plain) }
    }
  }

  if (!looksLikeLocation(plain)) return null

  const resolved = resolveFullPath(plain, ctx)
  if (resolved.source !== 'resolved') {
    if (resolved.reason === 'device-path') {
      return { token: plain, level: 'root', key: null, display: plain, zone: 'a device path', dynamic: resolved.reason, hasGlob: resolved.hasGlob }
    }
    return unknownScope(plain, resolved.reason, resolved.hasGlob)
  }

  const base = resolved.hasGlob ? globBase(resolved.key) : resolved.key
  if (base === null) return unknownScope(plain, null, true)
  // A wildcard whose only fixed part is a volume root names a root without
  // naming which one: reported as unanswerable rather than as a root.
  if (resolved.hasGlob && isVolumeRoot(base)) return unknownScope(plain, null, true)

  const { level, zone } = levelOf(base, ctx, buildZones(ctx))
  return {
    token: plain,
    level,
    key: resolved.key,
    display: resolved.display,
    zone,
    dynamic: null,
    hasGlob: resolved.hasGlob,
  }
}

/** Classify every token that names a location. Others are skipped. */
export function inspectTargets(tokens: readonly string[], ctx: ScopeContext = {}): ScopeReport {
  const targets: TargetScope[] = []
  for (const token of tokens) {
    const scope = classifyToken(token, ctx)
    if (scope !== null) targets.push(scope)
  }
  const regenerableOnly =
    targets.length > 0 && targets.every((t) => t.level === 'regenerable')
  return { targets, regenerableOnly }
}
