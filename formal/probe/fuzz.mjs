import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const probe = dirname(fileURLToPath(import.meta.url));
const output = resolve(probe, '..', '..', '.abc', 'probe-fuzz');
const native = process.argv[2] === '--native' && process.argv.length === 3;
if (!native && process.argv.length !== 2) throw new Error('Usage: node formal/probe/fuzz.mjs [--native]');
mkdirSync(output, { recursive: true });
const work = mkdtempSync(join(output, 'run-'));
const root = join(probe, 'rust');
const cases = [[0, 1], [0, 0], [2147483648, 2147483647], [4294967295, 0]];
const corpus = join(work, 'corpus');
mkdirSync(corpus);
const corpusFiles = cases.map(([left, right], index) => {
  const bytes = Buffer.alloc(8);
  bytes.writeUInt32LE(left, 0);
  bytes.writeUInt32LE(right, 4);
  const path = join(corpus, `seed-${index}`);
  writeFileSync(path, bytes);
  return { path, sha256: createHash('sha256').update(bytes).digest('hex') };
});

function logRun(program, args, cwd, log) {
  const start = performance.now();
  const run = spawnSync(program, args, { cwd, encoding: 'utf8', timeout: 300_000 });
  const output = `${run.stdout ?? ''}${run.stderr ?? ''}${run.error?.message ?? ''}`;
  writeFileSync(join(work, `${log}.log`), `${JSON.stringify([program, ...args])}\n${output}`);
  if (run.error || run.signal) throw new Error(`${log} failed to execute: ${run.error?.message ?? run.signal}`);
  return { status: run.status, output, elapsedMs: Math.round(performance.now() - start) };
}

function execute(crate, label, numberOfRuns, inputs) {
  const artifacts = join(work, `${label}-artifacts`);
  mkdirSync(artifacts);
  const args = [...inputs, `-runs=${numberOfRuns}`, '-seed=77', '-max_len=8', '-keep_seed=1', '-timeout=5',
    '-rss_limit_mb=1024', '-print_final_stats=1', `-artifact_prefix=${artifacts}${sep}`];
  const target = join(work, `${label}-target`);
  if (!native) {
    return logRun('cargo', ['+nightly-2026-03-30', 'fuzz', 'run', '--sanitizer', 'none', '--target-dir', target,
      'bounded_add', ...inputs, '--', ...args.slice(inputs.length)], crate, label);
  }
  const windows = process.platform === 'win32';
  const linkOptions = windows ? ['--', '-Clink-arg=/include:main'] : [];
  const build = logRun('cargo', ['+1.92.0', 'rustc', '--locked', '--release', '--manifest-path',
    'fuzz/Cargo.toml', '--target-dir', target, '--bin', 'bounded_add', ...linkOptions], crate, `${label}-build`);
  if (build.status !== 0) throw new Error(`${label} binary failed to build; see ${label}-build.log`);
  const executable = join(target, 'release', windows ? 'bounded_add.exe' : 'bounded_add');
  return logRun(executable, args, crate, label);
}

try {
  const normal = execute(root, 'positive', 10_000, [corpus]);
  if (normal.status !== 0 || !/Done 10000 runs\b/.test(normal.output)) throw new Error('The expected positive fuzz budget did not finish');
  if (!native && !/Loaded \d+ modules?\s*\(\d+ inline 8-bit counters\)/.test(normal.output)) {
    throw new Error('The coverage run did not report instrumented modules');
  }

  const mutant = join(work, 'mutant');
  for (const directory of ['src', 'fuzz/fuzz_targets']) mkdirSync(join(mutant, directory), { recursive: true });
  for (const file of ['Cargo.toml', 'Cargo.lock', 'fuzz/Cargo.toml', 'fuzz/Cargo.lock', 'fuzz/fuzz_targets/bounded_add.rs']) {
    copyFileSync(join(root, file), join(mutant, file));
  }
  const source = readFileSync(join(root, 'src', 'lib.rs'), 'utf8');
  const changed = source.replace('    left + right', '    left');
  if (changed === source) throw new Error('The mutation did not change the implementation');
  writeFileSync(join(mutant, 'src', 'lib.rs'), changed);
  const wrong = execute(mutant, 'mutant', 1, [corpusFiles[0].path]);
  if (wrong.status === 0 || !wrong.output.includes('bounded-add differential mismatch')) {
    throw new Error('The fuzzer did not reject the mutant with the expected differential failure');
  }
  const report = {
    scope: 'bounded u32 addition on valid input pairs',
    coverage: native ? 'uninstrumented' : 'edge-counters',
    sanitizer: 'none',
    oracle: 'widened u64 integer addition',
    corpus: corpusFiles.map(({ sha256 }) => sha256),
    implementation: createHash('sha256').update(source).digest('hex'),
    seed: 77,
    inputs: 10_000,
    elapsedMs: normal.elapsedMs,
    mutantExit: wrong.status,
  };
  writeFileSync(join(work, 'result.json'), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ ...report, path: work }));
} catch (error) {
  console.error(JSON.stringify({ status: 'not_passed', error: error.message, path: work }));
  process.exitCode = 1;
}
