/**
 * Shell-syntax normalization, applied before any layer reads a token.
 *
 * The rules layer originally compared `tokens[0]` against a verb list. That is
 * correct only for a command typed plainly. Measured evasions that reached the
 * delete verb through a shape it never compared against:
 *
 *   r\m -rf /              backslash escape inside the word
 *   r""m -rf /             quote removal inside the word
 *   rm$IFS-rf$IFS/         $IFS as the separator
 *   sudo rm -rf /          wrapper in head position
 *   FOO=bar rm -rf /       environment prefix in head position
 *   eval "rm -rf /"        quoted payload as a single token
 *
 * Each is ordinary shell syntax, not an exotic trick, so they are normalized
 * rather than listed. The output is not a simulation of the shell - it is the
 * string a human would have read had the command been written plainly.
 *
 * De-obfuscation is applied to the command word ONLY. Paths keep their
 * backslashes: `HKLM\SOFTWARE\...\CurrentVersion\Run` was measured losing every
 * separator to the escape rule, which silently disabled the registry check.
 * A path is compared as written; only a verb gets rewritten.
 *
 * Deliberately NOT normalized: `$VAR` other than IFS, and any expansion that
 * requires running something. Those cannot be resolved statically, and the
 * layers downstream are expected to treat the unresolved form as an ask.
 */
import { tokenize, isAbsolutePath, hasParentEscape, isVolatilePath } from './lexical.js'
import { HUNT_STOP, HUNT_VERBS, SHELL_KEYWORDS } from './verbs.js'

/**
 * Fold the spellings a human reads as ASCII back to ASCII.
 *
 * Measured evasions that no layer saw as a verb, because each one contains a
 * character the comparison was not written for:
 *
 *   ｒｍ -rf /            fullwidth latin  (NFKC folds it to "rm")
 *   rm -rf /   zero-width space after the verb
 *   r-m -rf /            soft hyphen inside the verb
 *   rm -rf / junk         NUL standing in for a separator
 *
 * None of these is a trick a shell performs; they are characters that render
 * as nothing or as their ASCII twin. Folding is the whole fix, and it has to
 * happen before tokenizing, since a tokenizer that has never met U+200B will
 * happily return a token that only looks like "rm".
 */
export function canonicalCommand(cmd: string | null | undefined): string {
  // Called from the pipeline with whatever the caller supplied. A missing
  // string is an empty command, not an exception: a guard that throws on a
  // well-formed call fails in the one direction it must never fail.
  if (typeof cmd !== 'string') return ''
  return cmd
    .normalize('NFKC')
    .replace(/[\u200b-\u200f\u2060\ufeff]/g, '')
    .replace(/\u00ad/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, ' ')
}

/** `$IFS` and `${IFS}` are the field separator, i.e. whitespace. */
export function expandIfs(value: string): string {
  return value.replace(/\$\{IFS\}|\$IFS/gi, ' ')
}

/**
 * A token with quoting removed but structure intact.
 *
 * This is what path comparisons read. Quotes are syntax rather than content,
 * so `"C:\Windows"` and `C:\Windows` are the same target; backslashes are not,
 * so they stay.
 */
export function plainToken(token: string): string {
  return token.replace(/["'`]/g, '')
}

/**
 * A command word with the ways of spelling it without looking like itself
 * undone: `r\m`, `r""m`, `p^ython`, `rm$IFS-rf`.
 *
 * Applied to the head only. A verb never contains a path separator, so the
 * escape rule cannot damage anything that matters here, and it cannot damage
 * a path because paths are never passed through this function.
 */
export function deobfuscateToken(token: string): string {
  return expandIfs(token)
    .replace(/\\([A-Za-z0-9])/g, '$1')
    .replace(/\$(["'`])/g, '$1')
    .replace(/["'`^]/g, '')
}

/**
 * Programs that run the rest of the line rather than doing work themselves.
 *
 * `start /b del ...` and `call del ...` on Windows, `sudo`/`nice`/`timeout`
 * onwards on POSIX. Each hides the real head one token further along, and the
 * rules layer never looked past the first.
 */
export const WRAPPERS: ReadonlySet<string> = new Set([
  'sudo',
  'doas',
  'su',
  'runas',
  'env',
  'nice',
  'nohup',
  'timeout',
  'exec',
  'command',
  'builtin',
  'xargs',
  'start',
  'call',
  'eval',
  // Nested shells put the work one token along: `cmd /c del ...` and
  // `powershell -c "rm -rf /"` were both passing untouched.
  'cmd',
  'powershell',
  'pwsh',
  'script',
])

/** The wrapper's own flags and bare numeric arguments. */
const WRAPPER_ARG = /^[-/][A-Za-z0-9:,_=./\\-]*$/
const BARE_NUMBER = /^\d+$/

/**
 * The verb a token spells, with the ways of spelling it without looking like
 * itself undone, and with any path stripped.
 *
 * Measured evasions that reached a verb the head comparison never saw:
 * `./rm -rf /`, `/bin/rm -rf /`, `rm.exe -rf C:\`, and the full path form.
 * The verb is the last component; where it lives is not part of its identity.
 */
export function stemVerb(token: string): string {
  const plain = plainToken(token);
  const base = looksLikePath(plain) ? (plain.split(/[\\/]/).pop() ?? plain) : plain;
  return deobfuscateToken(base).toLowerCase().replace(/^\$/, '').replace(/\.exe$/, '');
}

/**
 * Does this token name a location rather than a word?
 *
 * The distinction cannot be skipped: `r\m` is one word spelled with an
 * escape, and `C:\msys64\usr\bin\rm.exe` is one word behind five
 * separators. De-obfuscating first turned the second into `c:msys64usrbinrm`.
 */
function looksLikePath(plain: string): boolean {
  if (/^[A-Za-z]:[\\/]/.test(plain)) return true;
  if (plain.includes('/')) return true;
  if (plain.includes('\\\\')) return true;
  return (plain.match(/\\/g) ?? []).length >= 2;
}

/** Is this token one of the words that decides what happens to a path? */
export function isHuntVerb(token: string): boolean {
  return HUNT_VERBS.has(stemVerb(token));
}

/** A token that could plausibly be an argument to a wrapper. */
function isPrefixArg(token: string): boolean {
  const plain = plainToken(token);
  if (plain.includes(' ')) return false;
  return WRAPPER_ARG.test(plain) || BARE_NUMBER.test(plain) || /[\\/]/.test(plain);
}

export function headTokens(tokens: readonly string[]): string[] {
  let i = 0;

  while (i < tokens.length) {
    const token = tokens[i];
    if (token === undefined) break;
    const stem = stemVerb(token);

    // FOO=bar in head position.
    if (/^[a-z_][a-z0-9_]*=/i.test(stem)) {
      i += 1;
      continue;
    }

    if (SHELL_KEYWORDS.has(stem)) {
      i += 1;
      continue;
    }

    if (WRAPPERS.has(stem)) {
      i += 1;
      // The wrapper's own flags, paths and bare numbers, but stop at a verb:
      // `sudo /bin/rm -rf /` must not read `/bin/rm` as an argument.
      while (i < tokens.length) {
        const arg = tokens[i];
        if (arg === undefined) break;
        if (isHuntVerb(arg)) break;
        if (!isPrefixArg(arg)) break;
        i += 1;
      }
      continue;
    }

    // A verb in head position is the answer.
    if (isHuntVerb(stem)) break;

    // An unrecognised head may be a wrapper nobody listed. Hunt a short way
    // ahead for the real verb, unless this head's tail is known to be data.
    if (HUNT_STOP.has(stem)) break;

    let found = -1;
    const limit = Math.min(tokens.length, i + 4);
    for (let j = i + 1; j < limit; j += 1) {
      const probe = tokens[j];
      if (probe === undefined) break;
      if (isHuntVerb(probe)) {
        found = j;
        break;
      }
      if (!isPrefixArg(probe)) break;
    }

    // Not a wrapper shape: this head is what it is.
    if (found < 0) break;

    // Found the verb behind the wrapper. Leaving it in head position and
    // looping again made `i` stand still, which hung the whole pipeline.
    i = found;
    break;
  }

  return tokens.slice(i);
}

/**
 * Effective tokens: separators expanded, wrappers stripped, and a quoted
 * payload re-tokenized so `eval "rm -rf /"` is judged as `rm -rf /`.
 */
export function effectiveTokens(cmd: string): string[] {
  let tokens = tokenize(expandIfs(cmd))

  for (let depth = 0; depth < 3; depth += 1) {
    const eff = headTokens(tokens)
    const head = eff[0]
    if (head === undefined) return eff
    if (!/\s/.test(head)) return eff
    tokens = tokenize(expandIfs(deobfuscateToken(head)))
  }

  return headTokens(tokens)
}

/**
 * Is any redirection target outside the workspace?
 *
 * `echo "const x = 1" > src/x.ts` is one command writing one relative file,
 * and it was being asked as a chain. A redirect into a relative, non-escaping
 * path is not a second stage. One into an absolute path, above the workspace,
 * or into a volatile root is still worth surfacing.
 *
 * Returns true when the command has no readable target at all, so an
 * unparseable redirect fails closed.
 */
export function hasUnsafeRedirectTarget(cmd: string): boolean {
  const re = />>?|<(?![(<])/g
  let match: RegExpExecArray | null = re.exec(cmd)

  if (match === null) return true

  while (match !== null) {
    const rest = cmd.slice(match.index + match[0].length).trim()
    const target = rest.split(/\s+/)[0] ?? ''
    if (target.length === 0) return true

    const cleaned = plainToken(target)
    if (isAbsolutePath(cleaned) || hasParentEscape(cleaned) || isVolatilePath(cleaned)) return true

    match = re.exec(cmd)
  }

  return false
}
