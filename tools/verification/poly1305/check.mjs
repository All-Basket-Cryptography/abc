import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const scope = 'src/crypto/mac/poly1305';
const crate = join(repo, scope, 'impl/rust');
const pinPath = 'tools/verification/probe/toolchain-candidate.json';
const pins = JSON.parse(readFileSync(join(repo, pinPath), 'utf8'));
const target = 'x86_64-unknown-linux-gnu';
const namespace = 'Abc.Poly1305.Extracted';
const subdir = namespace.replaceAll('.', '/');
const modelFiles = [`${subdir}/Funs.lean`, `${subdir}/Types.lean`];
const cargo = ['--locked', '--offline', '--lib', '--no-default-features', '--target', target];
const charonArgs = ['--preset=aeneas', '--start-from', 'crate::absorb_bytes',
  '--start-from', 'crate::clamped_key', '--start-from', 'crate::key_multiples', '--start-from', 'crate::finish_tag'];
const aeneasArgs = ['-backend', 'lean', '-split-files', '-no-progress-bar', '-subdir', subdir,
  '-namespace', namespace];
const officialBinaries = {
  aeneas: '22b326476f854e19b52ca5a2acfd953fd186da7694cd10d8d008ed5502f7c46a',
  charon: '2603f720f0d26a4c77ae215485e2457029d69504dbd9d318a497ed866f21d4fd',
};
const sourceFiles = [
  pinPath, 'tools/build/rust/Cargo.toml', 'tools/build/rust/Cargo.lock',
  `${scope}/impl/rust/src/lib.rs`, `${scope}/impl/rust/Cargo.toml`,
  'tools/verification/poly1305/check.mjs',
];
const digest = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const hashes = (root, files) => Object.fromEntries(files.map((path) => [path, digest(join(root, path))]));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function check(toolRoot) {
  if (!toolRoot) throw new Error('Set ABC_AENEAS_ROOT to the pinned Aeneas checkout');
  const tools = resolve(toolRoot);
  const charon = join(tools, 'charon/bin/charon');
  const aeneas = join(tools, 'bin/aeneas');
  const output = join(repo, '.abc/poly1305-extraction');
  mkdirSync(output, { recursive: true });
  const work = mkdtempSync(join(output, 'run-'));
  const report = { status: 'failed', scope: 'poly1305_block_and_tag_arithmetic', pins, target, features: [],
    cargo, charonArgs, aeneasArgs };

  function run(label, program, args, cwd, env = {}) {
    const result = spawnSync(program, args, { cwd, env: { ...process.env, ...env },
      encoding: 'utf8', timeout: 900_000, maxBuffer: 16 * 1024 * 1024 });
    const log = join(work, `${label}.log`);
    writeFileSync(log, `${JSON.stringify([program, ...args])}\n${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`);
    if (result.status !== 0) throw new Error(`${label} failed. See ${log}`);
    return result.stdout.trim();
  }

  function requireCleanPin(label, path, revision) {
    if (run(`${label}-revision`, 'git', ['rev-parse', 'HEAD'], path) !== revision ||
        run(`${label}-status`, 'git', ['status', '--porcelain', '--untracked-files=no'], path)) {
      throw new Error(`${label} tracked sources do not match the repository pin`);
    }
  }

  function translate(label) {
    const llbc = join(work, `${label}.llbc`);
    const generated = join(work, label);
    mkdirSync(generated);
    run(`${label}-charon`, charon, ['cargo', ...charonArgs, '--dest-file', llbc, '--', ...cargo], crate,
      { RUSTUP_TOOLCHAIN: pins.rust, CARGO_TARGET_DIR: join(work, `${label}-cargo`), CARGO_NET_OFFLINE: 'true' });
    run(`${label}-aeneas`, aeneas, [...aeneasArgs, '-dest', generated, llbc], crate);
    const files = readdirSync(generated, { recursive: true, withFileTypes: true })
      .filter((item) => item.isFile())
      .map((item) => relative(generated, join(item.parentPath, item.name)).replaceAll('\\', '/')).sort();
    if (!same(files, modelFiles)) throw new Error('Expected only generated Types and Funs modules');
    return { llbc: digest(llbc), files: hashes(generated, modelFiles) };
  }

  try {
    report.revision = run('repository-revision', 'git', ['rev-parse', 'HEAD'], repo);
    report.sources = hashes(repo, sourceFiles);
    requireCleanPin('aeneas', tools, pins.aeneas);
    requireCleanPin('charon', join(tools, 'charon'), pins.charon);
    report.binaries = { aeneas: digest(aeneas), charon: digest(charon) };
    if (!same(report.binaries, officialBinaries)) throw new Error('Expected pinned Linux x86-64 release binaries');
    if (run('charon-toolchain', charon, ['toolchain-version'], crate) !== pins.rust) {
      throw new Error('Charon requested a different Rust toolchain');
    }
    report.rust = run('rustc-version', 'rustup', ['run', pins.rust, 'rustc', '-Vv'], crate);
    if (!report.rust.includes(`host: ${target}`)) throw new Error(`Expected a ${target} Rust host`);
    report.first = translate('first');
    report.second = translate('second');
    if (!same(report.first.files, report.second.files)) throw new Error('Independent translations disagree');
    if (!same(report.sources, hashes(repo, sourceFiles))) throw new Error('Extraction sources changed during replay');
    report.status = 'poly1305_model_extracted';
  } catch (error) {
    report.error = error.message;
    process.exitCode = 1;
  }
  writeFileSync(join(work, 'result.json'), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ ...report, path: work }));
}

try {
  check(process.env.ABC_AENEAS_ROOT);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
