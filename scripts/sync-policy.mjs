/**
 * Regenerate the machine-readable part of interp_policy from measured
 * behaviour.
 *
 * interp_policy used to be prose that nothing read - a claim in a JSON file
 * presented as a specification. It now carries `codes`, the exact set of
 * INTERP_* codes the parser emits for the ask-marked cases in the corpus, and
 * guard.test.ts fails if that set drifts from the code. Run this after adding
 * or renaming an interpreter rule:
 *
 *   npm run build && node scripts/sync-policy.mjs
 */
import { readFileSync, writeFileSync, readdirSync } from 'node:fs'
import { verify } from '../lib/src/guard/verify.js'

const DIR = 'test/'
const WORKSPACE = 'D:/AI_Assistant'

const files = readdirSync(DIR)
  .filter((f) => /^attacks.*\.json$/.test(f))
  .sort()

const cases = files.flatMap((f) => JSON.parse(readFileSync(DIR + f, 'utf8')).cases)

const codes = new Set()
for (const c of cases) {
  if (c.layer !== 'interp' || c.expect !== 'ask') continue
  const state = {
    workspaceRoot: WORKSPACE,
    ...(c.requires_state === 'recent_write' ? { recentWrites: ['scripts/fresh.py'] } : {}),
  }
  const result = verify(
    { cmd: c.cmd, why: c.why, tool: c.tool, commandSource: c.command_source },
    state,
  )
  codes.add(result.code)
}

const path = DIR + 'attacks.json'
const doc = JSON.parse(readFileSync(path, 'utf8'))

doc.interp_policy.codes = [...codes].sort()

const additions = [
  'bundled short flags that carry a program body: -uc / -pe / -ep',
  'interpreter named by path or version: C:\\Python39\\python.exe / python3.11 / node18',
]
for (const line of additions) {
  if (!doc.interp_policy.ask.includes(line)) doc.interp_policy.ask.push(line)
}

writeFileSync(path, JSON.stringify(doc, null, 2) + '\n')

console.log(JSON.stringify(doc.interp_policy.codes, null, 2))
