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
import {
  effectiveTokens,
  isForceFlag,
  isHuntVerb,
  isRecursiveFlag,
  plainToken,
  stemVerb,
  WRAPPERS,
} from './normalize.js'
import { HUNT_VERBS, SHELL_KEYWORDS } from './verbs.js'
import { inspectTargets, type ScopeContext } from './scope.js'
import { baseOf } from './path.js'

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
 * Where a command is pointed is not decided here. scope.ts answers it by
 * resolving each token to a comparison key (path.ts) and testing containment
 * against structural roots, so a spelling, an expansion or a depth that the
 * old anchored table could not see is the same question as any other.
 */

/** Files whose disclosure or loss is not recoverable by a later step. */
const CREDENTIAL_TARGET =
  /(?:^|[\\/])(?:shadow|sudoers|gshadow|passwd|id_rsa|id_ed25519|\.git-credentials|credentials|ntds\.dit|\.bash_history)$/i

/** Registry hives and the local account database: readable, not ours to read. */
const SECRET_STORE =
  /(?:^|[\\/])config[\\/](?:sam|system|security|default|ntuser\.dat)$/i

// Bulk-mutation flags: {common alone, not together}. The spelling lives in
// normalize.ts so this layer and the rules layer cannot drift apart — they
// already had, on the same regex, one of them behind a deny.

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
  /^--eval(?:=.*)?$/i,
  /^-(?:command|encodedcommand|exec|execdir|eval)$/i,
  /^\/c$/i,
]

/**
 * `-r` is two flags spelled alike. For a language runtime it names a module or
 * library loaded before the program runs - `node -r ./hook.js`, `php -r 'code'`
 * - and that is code passed as an argument. For every other head it is the
 * POSIX recursive flag, `cp -r src dst`, which is a target flag and is read by
 * isRecursiveFlag instead.
 *
 * The head decides which, so the generic flag list above cannot. A whitelist is
 * used rather than a blacklist because the two ways of being wrong do not cost
 * the same: guessing "code" on a copy is one false ask, guessing "target" on an
 * inline payload is one silent pass.
 */
const CODE_REQUIRE_HEADS: ReadonlySet<string> = new Set([
  'node',
  'nodejs',
  'bun',
  'deno',
  'php',
  'php7',
  'php8',
  'perl',
  'perl5',
  'ruby',
])

/** The short flag whose value only a runtime's head makes into code. */
const CODE_REQUIRE_FLAG = /^-r$/

/**
 * Strip an option's leading `--name=` so the value is compared, not the flag.
 * `--prefix=/etc/x` writes under /etc; `/^\/(?:etc)/` never sees it otherwise.
 */
function valueOf(token: string): string {
  return token.replace(/^-{1,2}[A-Za-z][A-Za-z0-9_-]*=/, '')
}

export function check(input: GuardInput, state: GuardState): Finding | null {
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

  // An exempt head is a claim about the head, not about the target.
  //
  // The rules layer owns the policy heads, but it owns them by name and by a
  // table of paths, and `Remove-Item -Recurse C:\Users\me` matched neither:
  // one flag, no prompt, a home directory gone. So a head is allowed to stop
  // here only when nothing about the target makes the answer matter.
  //
  // A read-only head is exempt outright. Reading a system file is the
  // disclosure rule's business, and that rule ran above; asking `cat
  // /etc/hosts` would be noise on the ordinary case to cover nothing.
  if (EXEMPT.has(head)) {
    const exemptTokens = raw.map(plainToken).filter((t) => t.length > 0 && !/\s/.test(t))
    const exemptBase = baseOf(state.cwd, state.workspaceRoot)
    const exemptReport = inspectTargets(exemptTokens, {
      workspaceRoot: state.workspaceRoot,
      cwd: exemptBase.cwd,
    })
    // The gate is the flag, not the head's class and not the target alone.
    // `reg` is in HUNT_VERBS, so a class test cannot tell `reg query
    // HKLM\SOFTWARE` from `reg delete HKLM\... /f`; the flag can, and the
    // flag is also what makes a target scan worth running. Without one, a
    // command can name a system location and do nothing that a rename or a
    // reinstall would not fix.
    const matters =
      exemptReport.targets.some((t) => t.hasGlob) ||
      exemptTokens.some(isRecursiveFlag) || exemptTokens.some(isForceFlag)
    if (DATA_TAIL.has(head) || !matters) return null
  }

  // A token that came out of quotes keeps its spaces; one that did not is a
  // word the shell would pass as a single argument. Sentences are not targets.
  const tokens = raw.map(plainToken).filter((t) => t.length > 0 && !/\s/.test(t))
  if (tokens.length === 0) return null

  const signals: string[] = []

  // Where the command is pointed, read as a location rather than a string.
  // The base is passed down rather than inherited from the process: the whole
  // point of a second base is that the caller gets to state it.
  const scopeContext: ScopeContext = {
    workspaceRoot: state.workspaceRoot,
    cwd: baseOf(state.cwd, state.workspaceRoot).cwd,
  }
  const report = inspectTargets(tokens, scopeContext)

  for (const target of report.targets) {
    const named = target.display ?? target.token
    if (target.level === 'root') {
      signals.push(`names "${named}", a volume, share or device root`)
    } else if (target.level === 'sensitive') {
      signals.push(`points at "${named}", in ${target.zone ?? 'a system location'}`)
    } else if (target.level === 'ancestor') {
      signals.push(`names "${named}", which contains the workspace`)
    }
  }

  const recursive = tokens.some(isRecursiveFlag)
  const force = tokens.some(isForceFlag)

  // A target that cannot be read statically is not a signal on its own: it is
  // a signal once a flag makes the answer matter. `gci $env:APPDATA` names a
  // location and does nothing to it.
  const unresolved = report.targets.filter((t) => t.level === 'unknown')
  const wildcard = report.targets.some((t) => t.hasGlob)
  if (unresolved.length > 0 && (recursive || force || wildcard)) {
    const first = unresolved[0]
    // Disclosure matters here. An unstated base directory is the one reason a
    // relative path lands in this branch, and an operator who cannot see that
    // reads the ask as noise. Naming the missing input turns a mystery into a
    // line of configuration.
    signals.push(
      first?.dynamic === 'unknown-cwd'
        ? `names "${first.token}", a relative path whose base directory the caller did not state`
        : `names "${first?.token ?? '?'}", whose target cannot be resolved statically`,
    )
  }

  // Recursion into a location whose loss is not recoverable. The force flag
  // used to be required alongside it, which left `Remove-Item -Recurse
  // C:\Users\me` clean: one flag, no prompt, a home directory gone.
  const unrecoverable = report.targets.some(
    (t) => t.level === 'sensitive' || t.level === 'root' || t.level === 'ancestor',
  )
  if (recursive && unrecoverable) {
    signals.push('recurses into a location whose loss cannot be undone')
  }

  // Recursive and force together: the shape of an override. Suppressed only
  // when every location the command names is a root that a normal command
  // rebuilds - the whitelist's single subtraction, and the reason it may only
  // contain regenerable roots.
  if (recursive && force && !report.regenerableOnly) {
    signals.push('carries recursive and force flags together')
  }

  const inlineAt = tokens.findIndex(
    (t) =>
      INLINE_FLAG.some((re) => re.test(t)) ||
      (CODE_REQUIRE_HEADS.has(head) && CODE_REQUIRE_FLAG.test(t)),
  )
  if (inlineAt >= 0 && tokens.length > inlineAt + 1) {
    signals.push('takes code as an argument rather than a file')
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
