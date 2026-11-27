import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const algorithm = dirname(here);
const build = join(algorithm, 'implementations', 'abc-rust-portable');
const implementationSource = join(build, 'src', 'lib.rs');
const output = resolve(algorithm, '..', '..', '..', '..', '.abc', 'sha256-fuzz');
const args = process.argv.slice(2);
const sourceCoverage = args[0] === '--source-coverage';
const native = args[0] === '--native' || sourceCoverage;
if (native) args.shift();
const budget = args.length === 0 ? 5 : Number(args[0]);
if (args.length > 1 || !Number.isInteger(budget) || budget < 1 || budget > 600) {
  console.error('Usage: node algorithms/hash/sha2/sha256/fuzz/run.mjs [--native|--source-coverage] [seconds (1–600)]');
  process.exit(2);
}
mkdirSync(output, { recursive: true });
const work = mkdtempSync(join(output, 'run-'));
const corpus = join(work, 'corpus');
mkdirSync(corpus);
const boundaries = [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 1024, 4096];
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const seeds = boundaries.map((length) => {
  const input = Buffer.alloc(16 + length);
  input.set([0x80, 0x81, 0xb6, 0, 1, 0x86, 0xc0, 1, 0xbf, 0x80, 127, 0, 0, 0, 0, 0x80]);
  for (let index = 0; index < length; index++) input[16 + index] = (index * 73 + length) % 256;
  const path = join(corpus, `length-${length}`);
  writeFileSync(path, input);
  return { bytes: length, digest: hash(input) };
});

function run(program, processArgs, cwd, label, timeout, environment) {
  const start = performance.now();
  const child = spawnSync(program, processArgs, {
    cwd, encoding: 'utf8', timeout, maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, ...environment },
  });
  const log = `${child.stdout ?? ''}${child.stderr ?? ''}${child.error?.message ?? ''}`;
  writeFileSync(join(work, `${label}.log`), `${JSON.stringify([program, ...processArgs])}\n${log}`);
  if (child.error || child.signal) throw new Error(`${label}: ${child.error?.message ?? child.signal}`);
  return { status: child.status, log, elapsedMs: Math.round(performance.now() - start) };
}

function execute(fuzz, label, inputs, limits) {
  const target = join(work, `${label}-build`);
  const artifacts = join(work, `${label}-artifacts`);
  mkdirSync(artifacts);
  const engineArgs = ['-seed=95', '-max_len=4112', '-keep_seed=1', '-timeout=5', '-rss_limit_mb=1024', '-print_final_stats=1',
    `-artifact_prefix=${artifacts}${sep}`, ...limits];
  if (!native) {
    return run('cargo', ['+nightly-2026-03-30', 'fuzz', 'run', '--fuzz-dir', fuzz, '--sanitizer', 'none',
      '--target-dir', target, 'differential', ...inputs, '--', ...engineArgs], algorithm, label, (budget + 180) * 1000);
  }
  const windows = process.platform === 'win32';
  const linker = windows ? ['--', '-Clink-arg=/include:main'] : [];
  const compilerOptions = sourceCoverage && label === 'positive'
    ? ['--config', 'build.rustflags=["-Cinstrument-coverage"]'] : [];
  const compiled = run('cargo', ['+1.92.0', 'rustc', '--locked', '--release', ...compilerOptions, '--manifest-path',
    join(fuzz, 'Cargo.toml'), '--target-dir', target, '--bin', 'differential', ...linker], algorithm, `${label}-build`, 180_000);
  if (compiled.status !== 0) throw new Error(`${label} binary failed to build`);
  const executable = join(target, 'release', windows ? 'differential.exe' : 'differential');
  const profile = join(work, `${label}.profraw`);
  const result = run(executable, [...inputs, ...engineArgs], algorithm, label, (budget + 15) * 1000,
    { LLVM_PROFILE_FILE: profile });
  return { ...result, executable, profile };
}

function summarizeCoverage(executable, rawProfile) {
  const merged = join(work, 'sha256.profdata');
  const merge = run('llvm-profdata', ['merge', '-sparse', rawProfile, '-o', merged], algorithm, 'coverage-merge', 10_000);
  if (merge.status !== 0) throw new Error('LLVM could not merge the runtime profile');
  const exported = run('llvm-cov', ['export', '--summary-only', '--instr-profile', merged, executable, implementationSource],
    algorithm, 'coverage', 10_000);
  if (exported.status !== 0) throw new Error('LLVM could not export source coverage');
  const report = JSON.parse(exported.log).data[0]?.files;
  if (report?.length !== 1 || !report[0].summary?.regions?.count || !report[0].summary?.lines?.count) {
    throw new Error('LLVM exported no coverage for the exact SHA-256 source');
  }
  return report[0].summary;
}

try {
  const correct = execute(here, 'positive', [corpus], [`-max_total_time=${budget}`]);
  const ran = /^Done (\d+) runs in (\d+) second\(s\)/m.exec(correct.log);
  if (correct.status !== 0 || !ran) throw new Error('Positive fuzz run did not finish successfully');
  if (!native && !/Loaded \d+ modules?\s*\(\d+ inline 8-bit counters\)/.test(correct.log)) {
    throw new Error('Instrumented coverage was requested and the engine reported no counters');
  }
  const mutant = join(work, 'mutant');
  const mutantFuzz = join(mutant, 'fuzz');
  const mutantCore = join(mutant, 'implementations', 'abc-rust-portable');
  mkdirSync(join(mutantFuzz, 'fuzz_targets'), { recursive: true });
  mkdirSync(join(mutantCore, 'src'), { recursive: true });
  for (const file of ['Cargo.toml', 'Cargo.lock', 'fuzz_targets/differential.rs']) {
    copyFileSync(join(here, file), join(mutantFuzz, file));
  }
  copyFileSync(join(build, 'README.md'), join(mutantCore, 'README.md'));
  const manifest = readFileSync(join(build, 'Cargo.toml'), 'utf8').replace(/^workspace\s*=\s*"[^"]*"\r?\n/m, '');
  writeFileSync(join(mutantCore, 'Cargo.toml'), `${manifest}\n[workspace]\n`);
  const source = readFileSync(implementationSource, 'utf8');
  const changed = source.replace(/^( {8}digest)\r?$/m, '        digest[0] ^= 1;\n$1');
  if (changed === source) throw new Error('Could not locate the output of Sha256::finalize for fault injection');
  writeFileSync(join(mutantCore, 'src', 'lib.rs'), changed);
  const wrong = execute(mutantFuzz, 'mutant', [join(corpus, 'length-56')], ['-runs=1']);
  if (wrong.status === 0 || !wrong.log.includes('SHA-256 one-shot mismatch')) {
    throw new Error('Fuzz harness did not report the expected fault-injection mismatch');
  }

  const result = {
    status: 'passed', implementation: 'sha256-abc-rust-portable', oracle: 'RustCrypto sha2 0.10.9',
    coverage: sourceCoverage ? 'llvm-source' : native ? 'uninstrumented' : 'edge-counters', sanitizer: 'none',
    sourceCoverage: sourceCoverage ? summarizeCoverage(correct.executable, correct.profile) : undefined,
    inputBudgetSeconds: budget,
    engineSeconds: Number(ran[2]), elapsedMs: correct.elapsedMs, inputs: Number(ran[1]), seed: 95,
    sourceSha256: hash(source), harnessSha256: hash(readFileSync(join(here, 'fuzz_targets', 'differential.rs'))),
    mutantExit: wrong.status, corpus: seeds,
  };
  writeFileSync(join(work, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify({ ...result, path: work }));
} catch (error) {
  const result = { status: 'not_passed', error: error.message, path: work };
  writeFileSync(join(work, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
  console.error(JSON.stringify(result));
  process.exitCode = 1;
}
