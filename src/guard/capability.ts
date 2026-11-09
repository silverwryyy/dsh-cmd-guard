/**
 * Layer 2: capability inference - the answer to "judge the unknown".
 *
 * Every layer before this one asks a question with no closed answer: "which
 * program is this?" Four rounds of out-of-corpus probes returned a fresh batch
 * of misses each time, and every miss had the same shape - a program, wrapper
 * or spelling that had not been listed. Unlisted `busybox`, unlisted `strace`,
 * unlisted `php -r`, a verb behind a path. Enumerating programs does not
 * converge, because the space of programs is open and the list is finite.
 *
 * This layer asks a different question, and answers it without knowing the
 * program at all: what can this line do to the machine? Each signal below is a
 * property of the target or of the argument shape, not of the tool's name. An
 * unheard-of binary pointing at C:\Windows with -r -f reads the same way as
 * `rm`, because the thing being read is the intent, not the name.
 *
 * The inversion is the point. The known list used to be a detection list: a
 * tool was judged only if recognised. It is now an exemption list: a tool is
 * exempted only if recognised, and everything else is judged on capability.
 *
 * An exemption is not a claim of safety - it is a claim that this layer adds
 * nothing. `echo`'s tail is data, and a delete it is merely printing is judged
 * by the layer that owns the shell syntax, not here.
 *
 * ask only, never deny. A capability signal is suspicion, and deny stays with
 * the hard blacklist, which is the only place a false positive is
 * unrecoverable.
 */
import type { Finding, GuardInput, GuardState } from './types.js'
import { effectiveTokens, plainToken, stemVerb, isHuntVerb, WRAPPERS } from './normalize.js'
import { HUNT_VERBS, SHELL_KEYWORDS } from './verbs.js'

/**
 * Heads whose remaining tokens are data and which cannot execute a payload.
 *
 * Deliberately narrower than HUNT_STOP: that set also holds `python`, `node`
 * and `npm`, whose tails are usually data but which can execute on request
 * (`python -c`). Those are judged, not exempted.
 *
 * Membership is a claim that the tail cannot change the machine. `sort`,
 * `less`, `rg`, `ag` and `man` were added and then removed on measurement:
 * sort -o writes a file, less -o writes a log, rg --pre and ag --pager run a
 * program, man -P runs the pager. Each of those passed with a system target.
 * `tee`,
 * `touch`, `env`, `date`, `hostname`, `ipconfig` and `ifconfig` all failed
 * that claim: each writes a file, a variable or host state, and each was
 * measured carrying a system target through this layer untouched. The
 * exemption set is an attack surface of its own, so it is now read-only only.
 */
const DATA_TAIL: ReadonlySet<string> = new Set([
  'echo',
  'printf',
  'which',
  'where',
  'type',
  'help',
  'grep',
  'cat',
  'ls',
  'dir',
  'head',
  'tail',
  'more',
  'uniq',
  'wc',
  'diff',
  'whoami',
  'pwd',
  'ping',
  'nslookup',
  'whereis',
  'findstr',
])

/** Build, packaging and VCS tools: their capability is argued by the why layer. */
const TOOLCHAINS: ReadonlySet<string> = new Set([
  'git',
  'npm',
  'npx',
  'pnpm',
  'yarn',
  'cargo',
  'go',
  'dotnet',
  'make',
  'gradle',
  'mvn',
  'tsc',
  'eslint',
  'prettier',
  'code',
])

/** Everything this layer declines to judge, for the reasons stated per set. */
const EXEMPT: ReadonlySet<string> = new Set([
  ...DATA_TAIL,
  ...TOOLCHAINS,
  ...WRAPPERS,
  ...HUNT_VERBS,
  ...SHELL_KEYWORDS,
  // Policy heads are already judged by the rules layer; repeating them here
  // would only add a second, weaker verdict for the same command.
  'reg',
  'sc',
  'netsh',
  'wmic',
  'bcdedit',
  'diskpart',
  'shutdown',
  'reboot',
  'taskkill',
  'format',
])

/**
 * Where a command is pointed, as opposed to what it is called.
 *
 * Anchored on purpose: an argument that merely mentions a system path inside a
 * sentence ("fix /etc/passwd handling") must not match, or every commit message
 * that names a file becomes an ask.
 */
const SENSITIVE_TARGET: readonly RegExp[] = [
  /^[a-z]:\\windows(?:\\|$)/i,
  /^[a-z]:\\program files(?: \(x86\))?(?:\\|$)/i,
  /^[a-z]:\\programdata(?:\\|$)/i,
  /^[a-z]:\\users\\?$/i,
  /^[a-z]:\\?$/i,
  // `-v C:\:C:\` names the drive root as the volume source.
  /^[a-z]:\\:/i,
  /^\/{1,3}$/,
  // `docker run -v /:/host` mounts the machine into the container: the colon
  // splits source from target, so the root is the part before it.
  /^\/:/,
  /^\/(?:etc|bin|sbin|boot|usr|var|lib|lib64|root|home|opt|dev)(?:\/|$)/i,
  /^hk(?:lm|cr|u|cc)\\/i,
  /^\\\\\?\\/,
]

/** Files whose disclosure or loss is not recoverable by a later step. */
const CREDENTIAL_TARGET =
  /(?:^|[\\/])(?:shadow|sudoers|gshadow|passwd|id_rsa|id_ed25519|\.git-credentials|credentials|ntds\.dit|\.bash_history)$/i

/** Registry hives and the local account database: readable, not ours to read. */
const SECRET_STORE =
  /(?:^|[\\/])config[\\/](?:sam|system|security|default|ntuser\.dat)$/i

/** Bulk-mutation flag families. Common alone, not together. */
const RECURSIVE_FLAG: readonly RegExp[] = [
  /^-[a-z]*r[a-z]*$/i,
  /^--recursive(?:=.*)?$/i,
  /^\/s$/i,
  /^-recurse$/i,
]

const FORCE_FLAG: readonly RegExp[] = [
  /^-[a-z]*f[a-z]*$/i,
  /^--force(?:=.*)?$/i,
  /^-(?:fo|force)$/i,
  /^\/[fqy]$/i,
]

/** Subcommands that remove the resource they name. */
const REMOVE_SUBCOMMAND =
  /^(?:delete|remove|rm|rmi|destroy|drop|purge|prune|uninstall|wipe|evict|terminate)$/i

/**
 * Heads with no scoped use at all.
 *
 * `ntdsutil` was measured passing with no argument: the head was unfamiliar
 * and there was nothing to look at. It is an interactive editor for the
 * directory database, so being invoked is the whole signal.
 */
const ALWAYS_SUSPICIOUS: ReadonlySet<string> = new Set([
  'ntdsutil',
  'dcpromo',
  'adsi',
  'dsacls',
  'vssadmin',
])

/**
 * Hosts that exist to run a file someone else wrote.
 *
 * `wscript payload.vbs` and `mofcomp payload.mof` have no scoped, benign
 * invocation to fall back on, and neither name nor shape matched anything, so
 * both passed. Being invoked is the signal.
 */
const SCRIPT_HOSTS: ReadonlySet<string> = new Set([
  'wscript',
  'cscript',
  'installutil',
  'mofcomp',
  'msxsl',
  'regasm',
  'regsvcs',
])

/** Flags whose value is a destination, not an option. */
const DEST_FLAG =
  /^(?:-C|-d|--directory|--prefix|--root|--target-dir|--output-dir|-v|--volume|--mount|-o|--output|--output-file|-O|--out)(?:=|$)/

/**
 * Flags whose value is a program to run rather than a file to read.
 *
 * `rg --pre "sh -c id"`, `ag --pager "rm -rf /"` and `man -P "rm -rf /"` all
 * passed: the head was exempt and the value looked like any other argument.
 */
const EXEC_FLAG = /^(?:--pre|--pager|-P)(?:=|$)/

/** Flags that pull a payload from the network rather than name a file. */
const DOWNLOAD_FLAG =
  /^-(?:urlcache|outfile|outputpath|encodedcommand|enc|e|w|windowstyle|downloadstring|downloadfile)(?:=.*)?$/i

/**
 * Heads that change host identity, clock, volume layout or service state.
 *
 * A head is only suspicious when it is followed by an argument that matches,
 * so the bare forms (`hostname`, `date`) stay silent. Stated as a capability
 * rather than an intent: renaming a host changes what every later operation
 * on this machine is talking to.
 */
const HOST_STATE: ReadonlyMap<string, RegExp> = new Map([
  ['hostname', /./],
  ['hostnamectl', /^set-/i],
  ['date', /^(?:-s|--set|-d)$/i],
  ['timedatectl', /^set-/i],
  ['w32tm', /^\/config/i],
  ['tzutil', /^\/s(?:$|\s)/i],
  ['format-volume', /./],
  ['clear-disk', /./],
  ['initialize-disk', /./],
  ['new-partition', /./],
  ['remove-partition', /./],
  ['resize-partition', /./],
  ['new-service', /./],
  ['set-service', /./],
  ['remove-service', /./],
  ['new-localuser', /./],
  ['add-localgroupmember', /./],
  ['wevtutil', /^(?:cl|clear-log)/i],
  ['auditpol', /^(?:\/set|\/clear|\/remove)/i],
  ['logman', /^(?:create|delete|update|start|stop)/i],
  ['mshta', /./],
  ['rundll32', /./],
  ['regsvr32', /./],
  // Service state and scheduled-task removal. `net stop winmgmt` and
  // `schtasks /delete` were exempt on the argument that the rules layer owns
  // these heads. It owns the create/add forms; stopping a service and
  // removing a task are the same class of state change and were unowned.
  ['net', /^(?:stop|start|pause|continue|config|share|accounts)$/i],
  ['schtasks', /^\/?(?:delete|change|run|end)$/i],
  // Persistent environment and file attributes. `setx FOO bar` writes user
  // environment for every later process; `attrib +s +h` hides a file from
  // ordinary listings. Both read as harmless and neither had a signal.
  ['setx', /./],
  ['attrib', /^\+[a-z]+$/i],
])

/** Flags whose next argument is code, not a file. */
const INLINE_FLAG: readonly RegExp[] = [
  /^-[ce]$/i,
  /^-r$/i,
  /^--eval(?:=.*)?$/i,
  /^-(?:command|encodedcommand|exec|execdir|eval)$/i,
  /^\/c$/i,
]

/**
 * Strip an option's leading `--name=` so the value is compared, not the flag.
 * `--prefix=/etc/x` writes under /etc; `/^\/(?:etc)/` never sees it otherwise.
 */
function valueOf(token: string): string {
  return token.replace(/^-{1,2}[A-Za-z][A-Za-z0-9_-]*=/, '')
}

function isSensitive(token: string): boolean {
  const v = valueOf(token)
  if (v.length === 0) return false
  if (CREDENTIAL_TARGET.test(v)) return true
  return SENSITIVE_TARGET.some((re) => re.test(v))
}

export function check(input: GuardInput, _state: GuardState): Finding | null {
  const raw = effectiveTokens(input.cmd)
  const first = raw[0]
  if (first === undefined) return null

  const head = stemVerb(first)
  if (head.length === 0) return null

  // Reading a credential file is worth a question whether or not the head is
  // exempt: `cat /etc/shadow` is a read, and the read is the whole problem.
  // This check sits before the exemption return on purpose.
  const plain = raw.map(plainToken).filter((t) => t.length > 0)
  const secret = plain.find((t) => {
    const v = valueOf(t)
    return SECRET_STORE.test(v) || CREDENTIAL_TARGET.test(v)
  })
  if (secret !== undefined) {
    return {
      layer: 'capability',
      verdict: 'ask',
      code: 'UNKNOWN_CAPABILITY',
      reason: `"${head}" reads "${secret}", a credential store. Reading it is the disclosure.`,
    }
  }

  if (EXEMPT.has(head)) return null

  // A token that came out of quotes keeps its spaces; one that did not is a
  // word the shell would pass as a single argument. Sentences are not targets.
  const tokens = raw.map(plainToken).filter((t) => t.length > 0 && !/\s/.test(t))
  if (tokens.length === 0) return null

  const signals: string[] = []

  const target = tokens.find(isSensitive)
  if (target !== undefined) {
    signals.push(`points at "${target}", a system, volume or credential location`)
  }

  const recursive = tokens.some((t) => RECURSIVE_FLAG.some((re) => re.test(t)))
  const force = tokens.some((t) => FORCE_FLAG.some((re) => re.test(t)))
  if (recursive && force) signals.push('carries recursive and force flags together')

  const inlineAt = tokens.findIndex((t) => INLINE_FLAG.some((re) => re.test(t)))
  if (inlineAt >= 0 && tokens.length > inlineAt + 1) {
    signals.push('takes code as an argument rather than a file')
  }

  // A destination flag: the target is the flag's value, not any token.
  // `tar -xf a.tar -C /etc` and `docker run -v /:/host` were both passing,
  // because no token in them looks like a path on its own.
  for (let i = 0; i < tokens.length; i += 1) {
    const flag = tokens[i] ?? ''
    const m = DEST_FLAG.exec(flag)
    if (m === null) continue
    const inline = flag.slice(m[0].length)
    const value = inline.length > 0 ? inline : (tokens[i + 1] ?? '')
    const cleaned = valueOf(plainToken(value))
    if (cleaned.length > 0 && isSensitive(cleaned)) {
      signals.push(`writes to "${cleaned}", a location outside the workspace`)
      break
    }
  }


  if (tokens.some((t) => DOWNLOAD_FLAG.test(t))) {
    signals.push('takes a download or an encoded payload')
  }

  // Host identity, clock and volume layout. These heads read as harmless and
  // `hostname ATTACKER`, `date -s ...` and `w32tm /config ...` all passed.
  const statePattern = HOST_STATE.get(head)
  if (statePattern !== undefined) {
    const hit = tokens.slice(1).find((t) => statePattern.test(plainToken(t)))
    if (hit !== undefined) signals.push(`changes machine state with "${hit}"`)
  }

  // Tools whose destructive act is spelled as a subcommand rather than a
  // verb in head position: `kubectl delete ns kube-system` passed, because
  // the head was unfamiliar and no token looked like a path. The subcommand
  // is what the tool is about to remove, so it is judged on its own.
  const sub = tokens[1]
  if (sub !== undefined && REMOVE_SUBCOMMAND.test(plainToken(sub))) {
    signals.push(`runs "${plainToken(sub)}", which removes whatever it names`)
  }

  // Tools that open a privileged console and change machine-wide identity or
  // the directory database the machine authenticates against. There is no
  // scoped invocation of these, so the head alone is enough.
  if (ALWAYS_SUSPICIOUS.has(head)) {
    signals.push('edits the machine directory database or partition table directly')
  }

  if (SCRIPT_HOSTS.has(head)) {
    signals.push('exists to run a script file rather than to do one job')
  }

  // A flag whose value is another program. The value is what runs, and the
  // value is what nothing was looking at.
  const execAt = tokens.findIndex((t) => EXEC_FLAG.test(t))
  if (execAt >= 0 && tokens.length > execAt + 1) {
    signals.push(`runs "${tokens[execAt + 1]}" as a subprocess`)
  }

  if (tokens.slice(1).some((t) => isHuntVerb(t))) {
    signals.push('carries a destructive verb as an argument')
  }

  if (signals.length === 0) return null

  return {
    layer: 'capability',
    verdict: 'ask',
    code: 'UNKNOWN_CAPABILITY',
    reason: `"${head}" is not a known tool, and it ${signals.join('; ')}. An unfamiliar program is judged by what it can do to the machine, not by its name.`,
  }
}
