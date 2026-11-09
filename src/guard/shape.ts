/**
 * Is this string a command line, or is it a path / sentence / document?
 *
 * Used in two places that must agree:
 *
 *   entry  an unknown tool handed a bare string argument - only a
 *          command-shaped string is worth asking about
 *   mount  the same scan at the seam, for tools that carry no known key
 *
 * Sharing one implementation is the point. When these two disagreed, the
 * library entry point and the mounted plugin produced different verdicts for
 * the same call, which is the sort of inconsistency that makes an operator
 * stop trusting the guard.
 *
 * The heuristic is deliberately conservative in the false-positive direction:
 * a missed signal costs one unaudited shell only if the string is also not
 * caught by any later layer, while a false signal costs the operator a prompt
 * on an ordinary file read.
 */

/** Shell executables that may carry a command as their first argument. */
export const SHELLS = 'sh|bash|zsh|fish|cmd|powershell|pwsh'

/** Interpreters with an inline-program flag. */
export const INTERPRETERS = 'python|python3|py|node|deno|bun|ruby|perl|php'

/**
 * Shapes that identify a string as a command line rather than prose or data.
 *
 * A bare drive-absolute path is deliberately NOT a signal. `read_file` takes
 * `D:/a.txt`, and treating that as a command was a measured false positive:
 * with no approval UI composed, ask degrades to deny, so every file read
 * became impossible. An executable extension or a command-shaped argument is
 * what distinguishes the two.
 */
export const COMMAND_SHAPES: ReadonlyArray<RegExp> = [
  // A path that names an executable, optionally with arguments after it.
  /(^|\s)([a-z]:[\\/]|\\\\)[^<>|&;]*\.(exe|bat|cmd|ps1|com|scr|vbs)(\s|$)/i,
  /(^|\s)[^\s<>|&;]*\.(exe|bat|cmd|ps1|com|scr|vbs)(\s|$)/i,
  // A destructive verb in head position.
  /(^|\s)(del|erase|rd|rmdir|format|diskpart|bcdedit|reg|sc|taskkill|shutdown|mkfs|rm)\s/i,
  // Recursive / forced / history-rewriting flags.
  /(^|\s)\/s\b/i,
  /(^|[\s=])-rf\b|--force\b|--hard\b|--force-with-lease\b/,
  // Piping into a shell, or fetching.
  new RegExp(`\\|\\s*(${SHELLS})\\b`, 'i'),
  /\b(curl|wget|iwr|invoke-webrequest)\b/i,
  // An interpreter with a program argument.
  new RegExp(`(^|\\s)(${INTERPRETERS}|${SHELLS})(\\.exe)?\\s`, 'i'),
  // Redirect into a path, or command chaining.
  /[<>]{1,2}\s*[a-z]:/i,
  /&&|\|\||;|\|/,
  /\$\(|`|\{\(/,
]

export function looksLikeCommandString(value: string): boolean {
  return COMMAND_SHAPES.some((re) => re.test(value))
}
