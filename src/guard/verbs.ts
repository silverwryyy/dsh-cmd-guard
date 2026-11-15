/**
 * Verb vocabularies.
 *
 * Split out of rules.ts because normalization needs the same lists: the head
 * of a command is only knowable once you know which words do destructive work.
 * Keeping two copies would let them drift, and a drifted copy is a bypass.
 */

/**
 * Registry hive names, in both the short and the long spelling.
 *
 * `reg` accepts `HKLM` and `HKEY_LOCAL_MACHINE` as the same hive, so a layer
 * that knows one and not the other has a spelling bypass. Kept here because
 * two layers need it and two copies drift.
 */
export const REGISTRY_HIVE =
  /^(?:hk(?:lm|cr|cu|u|cc|pd)|hkey_(?:local_machine|current_user|classes_root|users|current_config|performance_data|dynamic_data))(?=[\\/]|$)/i

/** Verbs that remove files. */
export const DELETE_VERBS: ReadonlySet<string> = new Set([
  'del',
  'erase',
  'rd',
  'rmdir',
  'rm',
  'remove-item',
  'ri',
  'clear-content',
  'clc',
]);

/** Verbs that write to an existing path. */
export const MUTATION_VERBS: ReadonlySet<string> = new Set([
  ...DELETE_VERBS,
  'sed',
  'truncate',
  'tee',
  'cp',
  'mv',
  'copy',
  'move',
  'xcopy',
  'robocopy',
  'chmod',
  'chown',
  'attrib',
  'dd',
  'shred',
  'ddrescue',
]);

/**
 * Words worth hunting for when the head is not one of them.
 *
 * Measured evasions that motivated this: `busybox rm -rf /`, `strace -f rm -rf /`,
 * `setsid rm -rf /`, `chroot / rm -rf /`, `watch -n1 rm -rf /`,
 * `systemd-run rm -rf /`, `flock /tmp/l rm -rf /`, `ionice -c3 rm -rf /` and
 * `timeout -s KILL 5 rm -rf /` all reached the end of the pipeline untouched,
 * because the head was an interpreter nobody had listed.
 *
 * The set is deliberately narrow: only verbs that can produce a deny, plus the
 * ones whose arguments decide it. Hunting for `net`, `sc` and friends would
 * turn ordinary argument text into asks.
 */
export const HUNT_VERBS: ReadonlySet<string> = new Set([
  ...DELETE_VERBS,
  'find',
  'vssadmin',
  'icacls',
  'dd',
  'format',
  'reg',
  'takeown',
  'cipher',
]);

/**
 * Heads whose remaining tokens are arguments, never a command.
 *
 * The hunt is an inversion of the wrapper list: instead of enumerating every
 * program that runs the rest of the line, it assumes an unrecognised head may
 * be one of them. That is right for `strace`, and wrong for `man` or `echo`,
 * whose tail is data. These are the measured cases where the tail is data.
 */
export const HUNT_STOP: ReadonlySet<string> = new Set([
  'echo',
  'printf',
  'man',
  'which',
  'where',
  'type',
  'help',
  'git',
  'npm',
  'npx',
  'pnpm',
  'yarn',
  'node',
  'python',
  'python3',
  'py',
  'cargo',
  'go',
  'docker',
  'kubectl',
  'grep',
  'rg',
  'ag',
  'cat',
  'ls',
  'dir',
  'type',
  'head',
  'tail',
  'more',
  'less',
  'curl',
  'wget',
  'tar',
  'unzip',
  'make',
  'gradle',
  'mvn',
  'dotnet',
  'code',
  'sed',
  'awk',
  'sort',
  'uniq',
  'wc',
  'diff',
  'tsc',
  'eslint',
  'prettier',
]);

/** Shell keywords that sit in head position inside a compound statement. */
export const SHELL_KEYWORDS: ReadonlySet<string> = new Set([
  'then',
  'do',
  'else',
  'elif',
  'if',
  'while',
  'until',
  'for',
  '!',
]);
