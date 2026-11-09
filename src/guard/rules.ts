/**
 * Layer 1: hard blacklist.
 *
 * This is the only layer allowed to return `deny`, and in the real mount it is
 * the only layer wired to ctx.tools.guard, which structurally has no allow
 * exit. Keep the surface small: a false deny is unrecoverable, so nothing
 * enters this list unless no legitimate intent should ever reach it.
 *
 * The head token is read after normalization (separators expanded, wrappers
 * stripped, escapes removed). Before that, only a plainly-spelled command was
 * judged, and `sudo rm -rf /`, `r\m -rf /`, `rm$IFS-rf$IFS/` and
 * `eval "rm -rf /"` all reached the end of the pipeline untouched.
 */
import type { Finding, GuardInput, GuardState } from './types.js'
import { effectiveTokens, plainToken, stemVerb } from './normalize.js'
import { splitSegments } from './lexical.js'
import { DELETE_VERBS, MUTATION_VERBS } from './verbs.js'

const SYSTEM_PATHS: readonly RegExp[] = [
  /^[a-z]:\\windows(?:\\|$)/i,
  /^[a-z]:\\program files(?: \(x86\))?(?:\\|$)/i,
  /^[a-z]:\\programdata(?:\\|$)/i,
  /^%(?:systemroot|windir)%/i,
  /^\\\\\?\\/,
  // POSIX system trees. `sed -i /etc/passwd` was measured passing, and a
  // mutation there is no more scoped than the Windows equivalent.
  /^\/(?:etc|bin|sbin|boot|lib|lib64|usr\/lib|usr\/bin|usr\/sbin|var\/lib)(?:\/|$)/i,
]

/**
 * Whole-user-tree roots. `Remove-Item -Recurse -Force C:\Users` is not a
 * scoped delete in any reading, and it was measured passing.
 */
const USER_TREE_ROOTS: readonly RegExp[] = [
  /^[a-z]:\\users\\?$/i,
  /^[a-z]:\\documents and settings\\?$/i,
]

const DRIVE_ROOT = /^[a-z]:\\?\*?$/i
/** POSIX filesystem root, including the `//` and `/*` spellings. */
const POSIX_ROOT = /^\/{1,3}(?:\*|\.)?$/

/** Delete and mutation vocabularies live in verbs.ts, shared with normalization. */
const MACHINE_HIVE = /^hk(?:lm|cr|u|cc)\\/i

/** Files whose replacement or disclosure is not recoverable afterwards. */
const SECRET_FILE = /(?:^|[\\/])(?:shadow|sudoers|gshadow|id_rsa|id_ed25519|ntds\.dit)$/i

/**
 * Places the machine resolves names and accounts through.
 *
 * A write here is neither scoped nor recoverable, which is why it denies while
 * an ordinary system-path write only asks. The redirect form already denied;
 * `copy nul ...\drivers\etc\hosts` was an ask, which is the same act spelled
 * with a different verb. Also covers /etc/passwd, /etc/shadow and the SAM
 * hives.
 */
const CRITICAL_SYSTEM_FILE =
  /^(?:[a-z]:\\windows\\(?:system32\\(?:drivers\\etc|config)\\|win\.ini$)|\/(?:etc|boot)\/)/i

/** Raw disks. Reading one is not a read of a file, and writing one is not a write. */
const DEVICE_PATH =
  /^(?:\\\\\.\\physicaldrive\d*|\\\\\.\\[a-z]:|\/dev\/(?:sd|hd|nvme|disk|mmcblk|raw|mem))/i

/**
 * Redirect targets outside quotes, in order.
 *
 * The head of `echo x > /etc/sudoers` is a harmless program; the damage is in
 * the target, and no head comparison can see it.
 */
function redirectTargets(cmd: string): string[] {
  const out: string[] = []
  const re = /(?:>>?|<(?![(<]))\s*("[^"]*"|'[^']*'|[^\s|;&<>]+)/g
  let m: RegExpExecArray | null = re.exec(cmd)
  while (m !== null) {
    const raw = m[1]
    if (raw !== undefined) out.push(plainToken(raw))
    m = re.exec(cmd)
  }
  return out
}

/**
 * `... | <delete verb>` where the feeding stage is aimed at a system root.
 *
 * Measured as an ask: each segment was judged alone, and the right one
 * (`Remove-Item -Force`) carries no path of its own, so nothing looked
 * recursive. As a pair it deletes the tree the left stage listed.
 */
function pipeIntoDelete(cmd: string): Finding | null {
  if (!cmd.includes('|')) return null
  const segments = splitSegments(cmd)
  for (let i = 1; i < segments.length; i += 1) {
    const right = segments[i]
    if (right === undefined) continue
    const rt = effectiveTokens(right)
    const rh = rt[0] === undefined ? '' : stemVerb(rt[0])
    if (!DELETE_VERBS.has(rh)) continue

    const left = segments[i - 1]
    if (left === undefined) continue
    const target = effectiveTokens(left).find((t) => {
      const p = plainToken(t)
      return isSystemPath(p) || isRootPath(p) || isUserTreeRoot(p)
    })
    if (target !== undefined) {
      return deny(
        'RULE_PIPE_INTO_DELETE',
        `Pipes into "${rh}" while the previous stage is aimed at "${plainToken(target)}". Each stage alone looks scoped; the pair does not.`,
      )
    }
  }
  return null
}

/** Raw device targets. Writing here is not a scoped operation. */
const RAW_DEVICE = /^of=(?:\/dev\/(?:sd|hd|nvme|disk|mmcblk)|\\\\\.\\physicaldrive)/i

/** Tools that run a command on another host. The payload is in the arguments. */
const REMOTE_SHELLS = new Set([
  'ssh',
  'plink',
  'rsh',
  'telnet',
  // Windows-side remote execution. `psexec \\host cmd /c del /s /q C:\`
  // was measured passing: the host argument looked like a flag, the hunt
  // stopped there, and the head was a program nobody had listed.
  'psexec',
  'paexec',
  'winrs',
  'enter-pssession',
])

/**
 * Collapse the ways of spelling one location into one.
 *
 * `rm -rf /./`, `rm -rf /../` and `del /s /q C:\*` name the same place as
 * `/` and `C:\`, and all three were measured passing: the root patterns were
 * literal, so every spelling but the canonical one missed. A path that climbs
 * (`C:\Users\..\`) resolves the way a shell would resolve it.
 *
 * Relative paths come back untouched. They are scoped to the workspace by
 * construction, and rewriting them would assert a working directory this
 * layer does not know.
 */
function canonicalTarget(token: string): string {
  const p = plainToken(token)
  if (p.length === 0) return p

  const win = /^[A-Za-z]:/.test(p)
  const posix = !win && p.startsWith('/')
  if (!win && !posix) return p

  const volume = win ? p.slice(0, 2) : ''
  const rest = win ? p.slice(2) : p
  const parts = rest.split(win ? /\\+/ : /\/+/)
  const out: string[] = []

  for (const part of parts) {
    if (part === '' || part === '.') continue
    if (part === '..') {
      out.pop()
      continue
    }
    out.push(part)
  }

  return win ? `${volume}\\${out.join('\\')}` : `/${out.join('/')}`
}

function isSystemPath(token: string): boolean {
  const p = canonicalTarget(token)
  return SYSTEM_PATHS.some((re) => re.test(p))
}

function isUserTreeRoot(token: string): boolean {
  const p = canonicalTarget(token)
  return USER_TREE_ROOTS.some((re) => re.test(p))
}

function isRootPath(token: string): boolean {
  const p = canonicalTarget(token)
  return DRIVE_ROOT.test(p) || POSIX_ROOT.test(p)
}

/** `-r`, `-rf`, `-R`, `--recursive`, `/s`, `-Recurse`. */
function isRecursive(tokens: readonly string[]): boolean {
  return tokens.some(
    (t) =>
      /^\/s$/i.test(t) ||
      /^-recurse$/i.test(t) ||
      /^--recursive$/i.test(t) ||
      /^-[a-z]*r[a-z]*$/i.test(t),
  )
}

function lower(tokens: readonly string[]): string[] {
  return tokens.map((t) => plainToken(t).toLowerCase())
}

function deny(code: string, reason: string): Finding {
  return { layer: 'rules', verdict: 'deny', code, reason }
}

function ask(code: string, reason: string): Finding {
  return { layer: 'rules', verdict: 'ask', code, reason }
}

/**
 * Account, service and policy changes.
 *
 * None of these belong in a build, and each one either persists past the
 * session or turns off a control that a later recovery would rely on. Asked
 * rather than denied: they are recoverable, and an operator diagnosing a
 * machine has a legitimate reason to run them.
 */
function policyChange(head: string, tokens: readonly string[]): string | null {
  const t = lower(tokens)
  const arg1 = t[1]
  const arg2 = t[2]

  if (head === 'net' && (arg1 === 'user' || arg1 === 'localgroup' || arg1 === 'group')) {
    return `net ${arg1}`
  }
  if (head === 'schtasks' && (arg1 === '/create' || arg1 === '/change' || arg1 === '-create')) {
    return 'schtasks create'
  }
  if (head === 'reg' && arg1 === 'add' && t.some((x) => /currentversion\\run|\\services\\/.test(x))) {
    return 'reg add on an autostart key'
  }
  if (head === 'sc' && (arg1 === 'create' || arg1 === 'config' || arg1 === 'delete')) {
    return `sc ${arg1}`
  }
  if (head === 'netsh') return 'netsh'
  if (head === 'wmic' && t.some((x) => x === 'call' || x === 'create')) return 'wmic call'
  if (head === 'bcdedit') return 'bcdedit'
  if (head === 'diskpart') return 'diskpart'
  if (head === 'shutdown' || head === 'reboot' || head === 'restart-computer' || head === 'stop-computer') {
    return head
  }
  if (head === 'set-mppreference' || head === 'add-mppreference' || head === 'set-executionpolicy') {
    return head
  }
  if (head === 'taskkill' && t.some((x) => x === '/f' || x === '-f')) return 'taskkill /f'
  if (head === 'netsh' && arg1 !== undefined) return `netsh ${arg1}`
  // Unused arg2 is kept for readability of the cases above.
  void arg2
  return null
}

function evaluate(cmd: string, depth: number): Finding | null {
  const tokens = effectiveTokens(cmd)
  const head = tokens[0] === undefined ? undefined : stemVerb(tokens[0])
  if (head === undefined) return null

  // format <drive>: — no model intent should plausibly need this.
  if (head === 'format') {
    const target = tokens[1]
    if (target !== undefined && DRIVE_ROOT.test(plainToken(target))) {
      return deny(
        'RULE_FORMAT_DRIVE',
        'Volume format wipes an entire drive. There is no scoped version of this.',
      )
    }
  }

  // mkfs.* on any target. There is no partial version of this either.
  if (/^mkfs(?:\.[a-z0-9]+)?$/i.test(head)) {
    return deny(
      'RULE_FORMAT_FILESYSTEM',
      'Creating a filesystem overwrites whatever structure was there. Not a scoped operation.',
    )
  }

  // Recursive delete aimed at a system root, a user-tree root, or a
  // filesystem root.
  if (DELETE_VERBS.has(head) && isRecursive(tokens)) {
    const target = tokens.find((t) => {
      const p = plainToken(t)
      return isSystemPath(p) || isRootPath(p) || isUserTreeRoot(p)
    })
    if (target !== undefined) {
      return deny(
        'RULE_RECURSIVE_SYSTEM_DELETE',
        `Recursive delete of "${plainToken(target)}", which is a system, user, or volume root.`,
      )
    }
  }

  // A recursive delete with no operand at all. The targets arrive on stdin,
  // so no path in this line bounds it. `xargs rm -rf` was measured passing:
  // the head was a listed wrapper, the verb behind it was a listed verb, and
  // the rule that fires on a target had no target to fire on.
  if (DELETE_VERBS.has(head) && isRecursive(tokens)) {
    const operands = tokens
      .slice(1)
      .map((t) => plainToken(t))
      .filter((t) => !/^-[A-Za-z]/.test(t) && !/^\/[A-Za-z]/.test(t))
    if (operands.length === 0) {
      return ask(
        'RULE_UNBOUNDED_DELETE',
        `"${head}" deletes recursively and names no target. What it deletes is decided by its input, not by this line.`,
      )
    }
  }

  // find -exec runs a command per match. The payload sits in the arguments,
  // so it is not seen by the head comparison at all.
  if (head === 'find' && tokens.some((t) => /^-(?:exec|execdir|ok|okdir)$/i.test(t))) {
    return ask(
      'RULE_FIND_EXEC',
      'find -exec runs a command on every match. The payload is an argument, not the command.',
    )
  }

  // Ownership takeover: after this the running account owns the tree outright.
  if (head === 'takeown') {
    return ask(
      'RULE_OWNERSHIP_TAKEOVER',
      'takeown reassigns ownership. On a system tree it hands the running account what it did not have.',
    )
  }

  // cipher /w overwrites free space on a volume. Nothing scoped survives it.
  if (head === 'cipher' && tokens.some((t) => /^\/w(?::|$)/i.test(plainToken(t)))) {
    return ask(
      'RULE_CIPHER_WIPE',
      'cipher /w overwrites free space across the whole volume, including files removed by accident.',
    )
  }

  // find <root> -delete is the same delete spelled differently.
  if (head === 'find' && tokens.some((t) => t.toLowerCase() === '-delete')) {
    const target = tokens[1] === undefined ? undefined : plainToken(tokens[1])
    if (target !== undefined && isRootPath(target)) {
      return deny(
        'RULE_FIND_ROOT_DELETE',
        `Deleting every match under "${target}", which is a filesystem root.`,
      )
    }
    return ask(
      'RULE_FIND_DELETE',
      'find -delete removes files by pattern. The pattern, not the path, decides what goes.',
    )
  }

  // Machine-wide registry hive deletion.
  if (head === 'reg' && lower(tokens)[1] === 'delete') {
    const hive = tokens.find((t) => MACHINE_HIVE.test(plainToken(t)))
    if (hive !== undefined) {
      return deny(
        'RULE_REGISTRY_HIVE_DELETE',
        `Deleting machine hive "${hive}". User-scope writes are an ask, this is not.`,
      )
    }
  }

  // Locking every principal out of a system path or a volume root.
  if (head === 'icacls') {
    const t = lower(tokens)
    const denies = t.some((x) => x === '/deny' || x === '-deny')
    const scoped = tokens.some((x) => {
      const p = plainToken(x)
      return isSystemPath(p) || isRootPath(p)
    })
    if (denies && scoped) {
      return deny(
        'RULE_ACL_LOCKOUT',
        'Denying access on a system path or volume root locks every principal out of it, including the account needed to undo it.',
      )
    }
  }

  // Volume Shadow Copy deletion. This is the first thing ransomware does, and
  // it destroys the recovery path for everything else on the machine. It was
  // measured passing.
  if (
    head === 'vssadmin' &&
    lower(tokens).includes('delete') &&
    tokens.some((t) => /^shadows?(?:\/all)?$/i.test(plainToken(t)))
  ) {
    return deny(
      'RULE_SHADOW_COPY_DELETE',
      'Deleting volume shadow copies destroys every restore point on the machine, including the ones a later recovery would depend on.',
    )
  }

  // Raw device write. `dd` is legitimate for images; writing to a block device
  // is not scoped to a file the operator can inspect.
  if (head === 'dd') {
    const target = tokens.find((t) => RAW_DEVICE.test(plainToken(t)))
    if (target !== undefined) {
      return deny(
        'RULE_RAW_DEVICE_WRITE',
        `"${plainToken(target)}" writes to a raw device, not a file. There is no undo and no path to inspect.`,
      )
    }
  }

  // Permissions opened on a filesystem root. Not a deny: the command is
  // recoverable in principle, but nobody means this on purpose.
  if (head === 'chmod' && isRecursive(tokens) && tokens.some((t) => /^\/\*?$/.test(t))) {
    return ask(
      'RULE_OPEN_PERMISSIONS_ROOT',
      'Recursive permission change on "/". Every file on the machine becomes world-writable.',
    )
  }

  // Writing a name-resolution or account database. Denies for the same reason
  // a redirect into one does: what it replaces is what the machine depends on.
  if (MUTATION_VERBS.has(head)) {
    const critical = tokens.find((t) => CRITICAL_SYSTEM_FILE.test(canonicalTarget(t)))
    if (critical !== undefined) {
      return deny(
        'RULE_CRITICAL_SYSTEM_WRITE',
        `"${head}" writes "${plainToken(critical)}", a name-resolution or account database. Replacing it is not a scoped change and has no undo.`,
      )
    }
  }

  // A write verb aimed at a system path. Scoped in principle, never ordinary.
  if (MUTATION_VERBS.has(head)) {
    const target = tokens.find((t) => isSystemPath(plainToken(t)))
    if (target !== undefined) {
      return ask(
        'RULE_SYSTEM_PATH_MUTATION',
        `"${head}" writes to "${plainToken(target)}", which is a system path.`,
      )
    }
  }

  // Raw device access. `type \\.\PhysicalDrive0` reads a disk as a byte
  // stream, so no path comparison applies and no permission on a file bounds it.
  const device = tokens.find((t) => DEVICE_PATH.test(plainToken(t)))
  if (device !== undefined) {
    return ask(
      'RULE_DEVICE_PATH_ACCESS',
      `"${plainToken(device)}" is a raw device, not a file. Every byte on it is in scope, including other accounts' data.`,
    )
  }

  // History rewrite and discarded work. Recoverable only from a reflog the
  // same command can drop, so these ask rather than pass.
  if (head === 'git') {
    const sub = lower(tokens).slice(1).filter((t) => !t.startsWith('-'))
    const [one, two] = sub
    if (one === 'filter-branch' || one === 'filter-repo') {
      return ask(
        'RULE_HISTORY_REWRITE',
        `"git ${one}" rewrites every commit it touches. Published history cannot be reconciled afterwards.`,
      )
    }
    if (one === 'stash' && (two === 'drop' || two === 'clear')) {
      return ask(
        'RULE_DISCARD_STASH',
        `"git stash ${two}" discards work that exists nowhere else.`,
      )
    }
    if (one === 'reflog' && two === 'expire') {
      return ask(
        'RULE_HISTORY_REWRITE',
        'git reflog expire drops the only record that would let a discarded commit be recovered.',
      )
    }
    if (one === 'update-ref' && tokens.some((t) => /^-d$/i.test(plainToken(t)))) {
      return ask('RULE_HISTORY_REWRITE', 'git update-ref -d deletes a branch ref directly.')
    }
  }

  // Package source override. The next install then comes from wherever this
  // points, so nothing in the repository's lock file describes what runs.
  const t = lower(tokens)
  if (head === 'npm' && t[1] === 'config' && t[2] === 'set') {
    return ask(
      'RULE_REGISTRY_OVERRIDE',
      'npm config set rewrites where every later install resolves from. It outlives this session.',
    )
  }
  if ((head === 'npm' || head === 'yarn' || head === 'pnpm') &&
      tokens.some((x) => /^--registry=/i.test(plainToken(x)))) {
    return ask('RULE_REGISTRY_OVERRIDE', 'A --registry override resolves packages from a host the lock file does not name.')
  }
  if ((head === 'pip' || head === 'pip3') &&
      tokens.some((x) => /^(?:-i|--index-url|--extra-index-url|--trusted-host)$/i.test(plainToken(x)))) {
    return ask(
      'RULE_REGISTRY_OVERRIDE',
      'An index override installs from a host the requirements file does not name.',
    )
  }
  if ((head === 'pip' || head === 'pip3') && t[1] === 'config' && t[2] === 'set') {
    return ask('RULE_REGISTRY_OVERRIDE', 'pip config set rewrites the install source persistently.')
  }

  // fsutil writes files and volume metadata without a delete verb anywhere.
  if (head === 'fsutil' && t[1] === 'file' &&
      ['createnew', 'setvaliddata', 'setzerodata', 'setshortname'].includes(t[2] ?? '')) {
    return ask(
      'RULE_FSUTIL_FILE_WRITE',
      `"fsutil file ${t[2]}" writes or resizes a file through the filesystem layer, bypassing the ordinary write path.`,
    )
  }

  const policy = policyChange(head, tokens)
  if (policy !== null) {
    return ask(
      'RULE_SYSTEM_POLICY_CHANGE',
      `"${policy}" changes machine-wide account, service or security policy. It outlives this session.`,
    )
  }

  // A command run on another host: the payload is an argument here, so it is
  // judged here. `ssh host "rm -rf /"` was measured passing.
  if (REMOTE_SHELLS.has(head) && depth < 2 && tokens.length > 2) {
    const rest = tokens.slice(2).map((t) => plainToken(t)).join(' ')
    const inner = evaluate(rest, depth + 1)
    if (inner !== null && inner.verdict === 'deny') return inner
  }

  // A redirect into a system or credential file.
  const redirected = redirectTargets(cmd).find(
    (t) => isSystemPath(t) || isRootPath(t) || isUserTreeRoot(t) || SECRET_FILE.test(t),
  )
  if (redirected !== undefined) {
    return deny(
      'RULE_REDIRECT_SYSTEM_TARGET',
      `Redirects output into "${redirected}", a system or credential file. The write replaces a file the machine depends on.`,
    )
  }

  const piped = pipeIntoDelete(cmd)
  if (piped !== null) return piped

  return null
}

export function check(input: GuardInput, _state: GuardState): Finding | null {
  return evaluate(input.cmd, 0)
}
