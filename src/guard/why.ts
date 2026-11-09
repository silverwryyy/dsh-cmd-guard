/**
 * Layer 6: intent binding.
 *
 * History matters here, because the original premise was wrong. The pitch was
 * "the model must say why"; the shipped schema already makes `description`
 * required and non-empty on `pwsh`. Presence is therefore free - a model can
 * always type "run command" and satisfy it. Requiring what is already required
 * is decoration, not a control.
 *
 * What this layer does instead is judge the statement against the action:
 *
 *   placeholder   a bare verb or a shrug, no object and no goal
 *   restatement   the description is the command read aloud, which adds no
 *                 information the string did not already carry
 *   contradiction it claims to inspect something it is about to overwrite
 *
 * These are weaker claims than "must say why". They are also true, which the
 * original was not.
 */
import type { Finding, GuardInput, GuardState } from './types.js'
import { effectiveTokens } from './normalize.js'

const MUTATING_VERBS = new Set([
  'del',
  'erase',
  'rd',
  'rmdir',
  'rm',
  'mv',
  'move',
  'copy',
  'xcopy',
  'robocopy',
  'ren',
  'rename',
  'mkdir',
  'md',
  'attrib',
  'icacls',
  'takeown',
  'reg',
  'sc',
  'net',
  'taskkill',
  'setx',
  'wmic',
  'diskpart',
  'bcdedit',
  'schtasks',
  'netsh',
  'cipher',
])

/**
 * Read-only subcommands of tools that also mutate.
 *
 * `reg` and `sc` sit in MUTATING_VERBS whole, so `reg query` and
 * `sc query` demanded an intent statement for a read. Measured as a false
 * ask: with no approval UI composed, ask degrades to deny, and the tool
 * becomes unusable for the one thing it is best at - inspection.
 */
const READ_ONLY_SUB: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ['reg', new Set(['query', 'export', 'compare'])],
  [
    'sc',
    new Set([
      'query',
      'queryex',
      'qc',
      'qdescription',
      'qfailure',
      'qfailureflag',
      'qprivs',
      'qsidtype',
      'qtriggerinfo',
      'querier',
      'getdisplayname',
      'getkeyname',
      'enumdepend',
      'interrogate',
      'sdshow',
    ]),
  ],
  // `wmic os get caption` puts the verb third: the second token is the alias.
  // Reading only tokens[1] made a read demand an intent statement, and then
  // read that statement as a contradiction with the command.
  ['wmic', new Set(['get', 'list', 'status', 'apath'])],
])

/** Does this invocation only read state the tool is otherwise able to change? */
function isReadOnlySubcommand(head: string, tokens: readonly string[]): boolean {
  const allowed = READ_ONLY_SUB.get(head)
  if (allowed === undefined) return false
  // wmic spells the verb after an alias (`os get caption`), so any token
  // may be the read-only verb. Judging tokens[1] alone saw 'os'.
  if (head === 'wmic') return tokens.some((t) => allowed.has(t.toLowerCase()))
  const sub = (tokens[1] ?? '').toLowerCase()
  return allowed.has(sub)
}

const HOST_CONTROL = new Set(['shutdown', 'restart', 'logoff'])

/** A reason shorter than this is a placeholder, not a reason. */
const MIN_WHY_LENGTH = 8

/**
 * Statements that pass a non-empty check and say nothing. Kept as exact
 * matches after normalisation: "test the parser against the corpus" must not
 * be caught by a substring match on "test".
 */
const PLACEHOLDERS: ReadonlySet<string> = new Set([
  'run',
  'run it',
  'run command',
  'run the command',
  'run this',
  'run this command',
  'execute',
  'execute it',
  'execute command',
  'execute the command',
  'command',
  'cmd',
  'do it',
  'do the thing',
  'test',
  'testing',
  'try',
  'fix',
  'fix it',
  'update',
  'update it',
  'change',
  'changes',
  'cleanup',
  'clean up',
  'misc',
  'todo',
  'n a',
  'na',
  'none',
  'as requested',
  'as asked',
  'per instructions',
  'because',
  'needed',
  'required',
  'no reason',
  'same as before',
  'see above',
])

/** Words that only make sense for a read. */
const READONLY_CLAIM =
  /\b(read|reads|view|views|list|lists|listing|show|shows|inspect|inspects|check|checks|print|prints|display|displays|cat|look|looking|examine|examines|verify|verifies|review|reviews|report|reports|scan|scans|monitor|query|queries)\b/

/** Words that admit to changing something. */
const MUTATION_WORD =
  /\b(delete|deletes|deleting|remove|removes|removing|wipe|wipes|wipe|overwrite|overwrites|erase|erases|force|forces|reset|resets|drop|drops|purge|purges|install|installs|uninstall|uninstalls|rewrite|rewrites|replace|replaces|clean|cleans|prune|prunes)\b/

function normalize(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function isGlobalInstall(tokens: readonly string[]): boolean {
  const head = tokens[0]?.toLowerCase()
  const second = tokens[1]?.toLowerCase()
  const lowered = tokens.map((t) => t.toLowerCase())

  if (head === 'npm' && (second === 'i' || second === 'install') && lowered.includes('-g')) return true
  if (head === 'yarn' && second === 'global') return true
  if (head === 'pnpm' && second === 'add' && lowered.includes('-g')) return true
  return false
}

/**
 * Git subcommands that rewrite or discard history. These are legitimate often
 * enough that denying them would be wrong, and destructive enough that running
 * them silently is worse. That combination is exactly what this layer is for.
 */
function isHistoryRewrite(tokens: readonly string[]): boolean {
  if (tokens[0]?.toLowerCase() !== 'git') return false

  const sub = tokens[1]?.toLowerCase()
  const rest = tokens.slice(2).map((t) => t.toLowerCase())

  if (sub === 'push') {
    return rest.some((t) => t === '--force' || t === '-f' || t === '--force-with-lease' || t.startsWith('--force-with-lease='))
  }
  if (sub === 'reset') return rest.includes('--hard')
  if (sub === 'clean') return rest.some((t) => /^-[a-z]*f[a-z]*$/i.test(t))
  if (sub === 'branch') return rest.some((t) => t === '-d' || t === '-D' || t === '--delete' || t === '--delete-force')
  if (sub === 'checkout' || sub === 'restore') return rest.includes('--')
  return false
}

/**
 * Package publication.
 *
 * Not a filesystem mutation, so no verb in MUTATING_VERBS matched, and
 * `npm publish` was a measured silent pass. A published version cannot be
 * withdrawn from mirrors, which puts it in the same class as a history
 * rewrite: legitimate often enough to allow, destructive enough that
 * running it without a stated reason is worse.
 */
function isPublish(tokens: readonly string[]): boolean {
  const head = tokens[0]?.toLowerCase()
  const sub = tokens[1]?.toLowerCase()

  if (head === 'npm' && (sub === 'publish' || sub === 'unpublish')) return true
  if ((head === 'yarn' || head === 'pnpm') && sub === 'publish') return true
  if (head === 'twine' && sub === 'upload') return true
  return false
}

/**
 * Removals a later step cannot undo.
 *
 * The stated reason unlocks an ask by design: a recoverable delete with a real
 * intent behind it is ordinary work. That trade is wrong for removals with no
 * recovery path, because the model writes its own reason and a well-phrased
 * one is then a bypass. Measured: `rm -rf ~` and `git clean -xfd` both
 * passed with a fluent why.
 */
function isIrrecoverableRemoval(tokens: readonly string[]): boolean {
  const head = tokens[0]?.toLowerCase()
  const rest = tokens.slice(1).map((t) => t.toLowerCase())

  if (head === 'git') {
    const sub = rest[0]
    const args = rest.slice(1)
    if (sub === 'clean' && args.some((t) => /^-[a-z]*f/i.test(t))) return true
    if (sub === 'reset' && args.includes('--hard')) return true
    return false
  }

  const removes =
    head === 'rm' || head === 'rd' || head === 'rmdir' || head === 'del' || head === 'erase'
  if (!removes) return false

  const recursive = rest.some((t) => /^-[a-z]*r/i.test(t) || t === '/s' || t === '-recurse')
  const home = rest.some(
    (t) => t === '~' || t === '$home' || t === '%userprofile%' || /^\/(?:root|home)(?:\/|$)/.test(t),
  )
  return recursive && home
}

function ask(code: string, reason: string): Finding {
  return { layer: 'why', verdict: 'ask', code, reason }
}

export function check(input: GuardInput, _state: GuardState): Finding | null {
  const tokens = effectiveTokens(input.cmd)
  const head = tokens[0]?.toLowerCase()
  if (head === undefined) return null

  const needsWhy =
    (MUTATING_VERBS.has(head) && !isReadOnlySubcommand(head, tokens)) ||
    HOST_CONTROL.has(head) ||
    isGlobalInstall(tokens) ||
    isHistoryRewrite(tokens) ||
    isPublish(tokens)

  if (!needsWhy) return null

  if (isIrrecoverableRemoval(tokens)) {
    return ask(
      'WHY_IRRECOVERABLE',
      `"${head}" removes data a later step cannot restore. A stated reason unlocks a recoverable delete; it cannot unlock this one.`,
    )
  }

  const why = (input.why ?? '').trim()

  if (why.length === 0) {
    return ask(
      'WHY_MISSING',
      `"${head}" changes state on disk, in the registry, in history, or on the host. State why before it runs.`,
    )
  }

  if (why.length < MIN_WHY_LENGTH) {
    return ask(
      'WHY_TOO_SHORT',
      `The stated reason is ${why.length} characters. A placeholder is not an intent statement.`,
    )
  }

  const stated = normalize(why)

  if (PLACEHOLDERS.has(stated)) {
    return ask(
      'WHY_GENERIC',
      `"${why}" names the act, not a goal. A non-empty description is already required by the tool schema, so passing that bar proves nothing.`,
    )
  }

  // The description carries no information the command string did not already
  // carry. It satisfies the schema and answers nothing.
  if (stated.length > 0 && normalize(input.cmd).includes(stated)) {
    return ask(
      'WHY_RESTATES_COMMAND',
      `The stated reason is contained in the command itself ("${why}"). Restating the command is not a statement of purpose.`,
    )
  }

  if (READONLY_CLAIM.test(stated) && !MUTATION_WORD.test(stated)) {
    return ask(
      'WHY_CONTRADICTS',
      `The stated reason describes reading, but "${head}" changes state. Either the description is wrong or the command is not what it claims.`,
    )
  }

  return null
}
