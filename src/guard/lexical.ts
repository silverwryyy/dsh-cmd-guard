/**
 * Lexical helpers. Pure string handling, no IO, no process access.
 *
 * Everything here is deliberately naive about shell grammar. The goal is not
 * to emulate cmd.exe; it is to make sure that anything whose shape we cannot
 * confidently read surfaces as an ask instead of sliding through as a pass.
 */

/** Split into whitespace-separated tokens, keeping quoted runs intact. */
export function tokenize(cmd: string): string[] {
  const out: string[] = []
  let cur = ''
  let quote: string | null = null
  let started = false

  for (const ch of cmd) {
    if (quote !== null) {
      if (ch === quote) {
        quote = null
        continue
      }
      cur += ch
      continue
    }

    if (ch === '"' || ch === "'") {
      quote = ch
      started = true
      continue
    }

    // Newlines are separators, not whitespace inside a token. A measured
    // bypass: `echo hi\nrm -rf /` tokenised as ["echo", "hi\nrm", "-rf", "/"],
    // so the head was `echo` and the rules layer never saw the delete. Inside
    // quotes they are kept, because there they are data (see hasUnquotedNewline).
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      if (started || cur.length > 0) {
        out.push(cur)
        cur = ''
        started = false
      }
      continue
    }

    cur += ch
  }

  if (started || cur.length > 0) out.push(cur)
  return out
}

/**
 * A newline outside quotes. Both shells treat it as a statement separator, so
 * it chains exactly like `;` - but scanOperators covered only punctuation, and
 * the chain therefore reached the rules layer as one command.
 *
 * Quoted newlines are data: `git commit -m "line one\nline two"` is one
 * command, and treating it as two would be a false positive on every
 * multi-line commit message.
 */
export function hasUnquotedNewline(cmd: string): boolean {
  let quote: string | null = null

  for (const ch of cmd) {
    if (quote !== null) {
      if (ch === quote) quote = null
      continue
    }

    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }

    if (ch === '\n' || ch === '\r') return true
  }

  return false
}

/**
 * Operators found outside quotes. Chaining is what hides a second stage
 * behind a harmless first one, so any operator at all is worth surfacing.
 */
export function scanOperators(cmd: string): string[] {
  const found: string[] = []
  let quote: string | null = null

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]
    if (ch === undefined) break

    if (quote !== null) {
      if (ch === quote) quote = null
      continue
    }

    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }

    const two = cmd.slice(i, i + 2)
    if (two === '&&' || two === '||' || two === '^|' || two === '^&' || two === '>>') {
      found.push(two)
      i += 1
      continue
    }

    if (ch === '|' || ch === '&' || ch === ';' || ch === '>' || ch === '<') {
      found.push(ch)
    }
  }

  return found
}

/**
 * Command substitution: `$(...)` and paired backticks.
 *
 * Measured bypass: `echo $(rm -rf /)` and a backtick-wrapped `rm -rf /` both
 * passed with nothing objecting. Substitution was never in scanOperators, and
 * the rules layer only ever reads tokens[0], so the inner command was invisible
 * to every layer.
 *
 * Single quotes suppress substitution in POSIX shells, so their contents are
 * skipped. Double quotes do not, so they are not.
 *
 * Backticks are ambiguous: in PowerShell a lone backtick is an escape
 * (`"a`tb"` is a tab). A backtick with a closing partner is treated as
 * substitution, a lone one as an escape. That keeps normal PowerShell strings
 * from being flagged while closing the POSIX channel.
 */
export function hasCommandSubstitution(cmd: string): boolean {
  let inSingle = false

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]
    if (ch === undefined) break

    if (inSingle) {
      if (ch === "'") inSingle = false
      continue
    }

    if (ch === "'") {
      inSingle = true
      continue
    }

    if (ch === '$' && cmd[i + 1] === '(') return true

    if (ch === '`') {
      if (cmd.indexOf('`', i + 1) !== -1) return true
      i += 1 // lone backtick: escape the next character and move on
    }
  }

  return false
}

/**
 * Bodies of every command substitution, so the split layer can run the hard
 * rules against the inner text. Without this, `echo $(rm -rf /)` would only
 * ever be an ask; the delete itself is what should decide the verdict.
 */
export function substitutionBodies(cmd: string): string[] {
  const out: string[] = []
  let inSingle = false

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]
    if (ch === undefined) break

    if (inSingle) {
      if (ch === "'") inSingle = false
      continue
    }

    if (ch === "'") {
      inSingle = true
      continue
    }

    if (ch === '$' && cmd[i + 1] === '(') {
      let depth = 1
      let j = i + 2
      for (; j < cmd.length; j++) {
        const c = cmd[j]
        if (c === '(') depth += 1
        else if (c === ')') {
          depth -= 1
          if (depth === 0) break
        }
      }
      out.push(cmd.slice(i + 2, j))
      i = j
      continue
    }

    if (ch === '`') {
      const close = cmd.indexOf('`', i + 1)
      if (close === -1) {
        i += 1
        continue
      }
      out.push(cmd.slice(i + 1, close))
      i = close
    }
  }

  return out
}

/**
 * Split into the individual statements a chain would run. Used only to escalate
 * a hard deny that sits behind a separator: `git status && rm -rf /` used to be
 * an ask from the split layer, which hid the deny the rules layer would have
 * produced for the second statement. Deny must win.
 *
 * Quotes are honoured, so `echo "a;b"` stays one segment.
 */
export function splitSegments(cmd: string): string[] {
  const out: string[] = []
  let cur = ''
  let quote: string | null = null

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]
    if (ch === undefined) break

    if (quote !== null) {
      cur += ch
      if (ch === quote) quote = null
      continue
    }

    if (ch === '"' || ch === "'") {
      quote = ch
      cur += ch
      continue
    }

    if (
      ch === '\n' ||
      ch === '\r' ||
      ch === ';' ||
      ch === '|' ||
      ch === '&' ||
      ch === '>' ||
      ch === '<'
    ) {
      out.push(cur)
      cur = ''
      continue
    }

    cur += ch
  }

  out.push(cur)
  return out.map((s) => s.trim()).filter((s) => s.length > 0)
}

/**
 * Process substitution. The path handed to the tool is an anonymous pipe that
 * never exists on disk, so no provenance check can apply to it. Checked with
 * quotes ignored on purpose: it is legal inside a quoted shell argument.
 */
export function hasProcessSubstitution(cmd: string): boolean {
  return /[<>]\(/.test(cmd)
}

/**
 * A caret wedged inside a word (`d^e^l`). Outside the word, `^|` is an
 * escaped operator and belongs to the split layer instead.
 */
export function hasCaretInsideWord(cmd: string): boolean {
  return /[A-Za-z0-9_]+\^[A-Za-z0-9_]+/.test(cmd)
}

/** Forward slashes, lowercase. Used for every path comparison. */
export function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').toLowerCase()
}

/** Last segment of a Windows or POSIX path, quotes already stripped. */
export function baseName(p: string): string {
  const parts = p.split(/[\\/]+/)
  return parts[parts.length - 1] ?? p
}

/** True when `p` is `root` itself or sits underneath it. */
export function isInsideWorkspace(p: string, root: string): boolean {
  const target = normalizePath(p)
  const base = normalizePath(root).replace(/\/+$/, '')
  return target === base || target.startsWith(base + '/')
}

/** `C:\x`, `C:/x`, `\\server\share`, `/usr/x`. */
export function isAbsolutePath(p: string): boolean {
  return /^[a-z]:[\\/]/i.test(p) || /^\\\\/.test(p) || p.startsWith('/')
}

/** Any `..` segment, which may climb above the workspace root. */
export function hasParentEscape(p: string): boolean {
  return p.split(/[\\/]+/).includes('..')
}

/** Roots any process on the machine can write to. Not a provenance claim. */
export function isVolatilePath(p: string): boolean {
  return /%temp%|%tmp%/i.test(p) || /appdata[\\/]local[\\/]temp/i.test(p)
}
