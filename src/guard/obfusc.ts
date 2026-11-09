/**
 * Layer 3: obfuscation.
 *
 * These are signals, not proofs. Any one of them means the literal text is not
 * a faithful description of what will run, so the ask is about readability
 * rather than about intent.
 */
import type { Finding, GuardInput, GuardState } from './types.js'
import { hasCaretInsideWord } from './lexical.js'

const SIGNALS: ReadonlyArray<{ code: string; test: (cmd: string) => boolean; reason: string }> = [
  {
    code: 'OBF_BASE64_EXEC',
    test: (c) => /b64decode|base64[^;]*decode/i.test(c) && /exec|eval|compile/i.test(c),
    reason: 'Base64 decoding feeding an evaluator: the executed text is not in the command.',
  },
  {
    code: 'OBF_CHAR_ASSEMBLY',
    test: (c) => /\[char\]\s*\d+/i.test(c) || /fromcharcode/i.test(c),
    reason: 'Character codes assembled at runtime: the literal command never appears in the string.',
  },
  {
    code: 'OBF_DYNAMIC_IMPORT',
    test: (c) => /__import__|__builtins__|getattr\s*\(\s*__/i.test(c),
    reason: 'Dynamic import via dunder access, used to dodge static inspection.',
  },
  {
    code: 'OBF_BINARY_LOADER',
    test: (c) => /ctypes|mmap\s*\(|virtualalloc|memcpy\s*\(/i.test(c),
    reason: 'Native-code loader primitives.',
  },
  {
    code: 'OBF_HEX_ESCAPES',
    test: (c) => /(?:\\x[0-9a-f]{2}){4,}/i.test(c),
    reason: 'Long hex-escape run: an encoded payload with no readable form.',
  },
  {
    code: 'OBF_DOWNLOAD_EXECUTE',
    // `iex (iwr ...)` is the canonical one-liner. Downloading alone is not a
    // signal - `iwr` to a file is ordinary - but feeding the response into an
    // evaluator means the command on screen is not what runs.
    test: (c) => /\b(iex|invoke-expression)\b/i.test(c),
    reason: 'Invoke-Expression evaluates text fetched at runtime. The executed command is not in this string.',
  },
  {
    code: 'OBF_CERTUTIL_DECODE',
    // certutil is legitimate for hashing and certificate work; only the
    // download and decode verbs turn it into a payload carrier. Measured
    // bypass: `certutil -urlcache -f <url> a.exe` and `-decode a.b64 a.exe`
    // both passed with nothing objecting.
    test: (c) =>
      /\bcertutil(?:\.exe)?\b/i.test(c) && /(?:^|\s)-(?:urlcache|decode|decodehex)\b/i.test(c),
    reason: 'certutil used as a downloader or decoder. The real payload is not readable in this command.',
  },
  {
    code: 'OBF_STRING_CONCAT',
    // Measured bypass: `"pyth"+"on" -c x` passed. The head token is a quoted
    // fragment, so no interpreter or verb matching can see what it builds.
    test: (c) => /(^|\s)['"][^'"\s]*['"]\s*\+\s*['"]/.test(c),
    reason: 'A word is assembled by concatenation. The literal text is not the command that runs.',
  },
  {
    code: 'OBF_BITSADMIN_TRANSFER',
    // Measured bypass: `bitsadmin /transfer j <url> C:\a.exe` passed. It is a
    // downloader built into Windows, used for exactly this.
    test: (c) => /\bbitsadmin(?:\.exe)?\b/i.test(c) && /\/transfer\b/i.test(c),
    reason: 'BITS is being used to transfer a payload. What lands on disk is not in this command.',
  },
  {
    code: 'OBF_DOWNLOAD_TO_EXECUTABLE',
    // Fetching an executable image to local disk is the first half of a
    // download-and-run chain, and the second half is not visible here.
    // Measured bypass: `iwr <url>/a.exe -OutFile a.exe` passed.
    test: (c) =>
      /\b(curl|wget|iwr|invoke-webrequest|start-bitstransfer)\b/i.test(c) &&
      /\.(exe|dll|ps1|bat|cmd|scr|vbs|jse|wsf|hta)\b/i.test(c),
    reason: 'A remote executable is being fetched to local disk. Running it is one step away and not visible here.',
  },
]

export function check(input: GuardInput, _state: GuardState): Finding | null {
  for (const signal of SIGNALS) {
    if (signal.test(input.cmd)) {
      return {
        layer: 'obfusc',
        verdict: 'ask',
        code: signal.code,
        reason: signal.reason,
      }
    }
  }

  if (hasCaretInsideWord(input.cmd)) {
    return {
      layer: 'obfusc',
      verdict: 'ask',
      code: 'OBF_CARET_SPLIT',
      reason: 'Caret inserted inside a word, splitting a token to defeat literal matching.',
    }
  }

  return null
}
