import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const scope = 'src/crypto/cipher/chacha20';
const crate = join(repo, scope, 'impl/rust');
const pinPath = 'tools/verification/probe/toolchain-candidate.json';
const pins = JSON.parse(readFileSync(join(repo, pinPath), 'utf8'));
const namespace = 'Abc.ChaCha20.Extracted';
const subdir = namespace.replaceAll('.', '/');
const modelFiles = [`${subdir}/Funs.lean`, `${subdir}/Types.lean`];
const specFile = 'ChaCha20QuarterRound.lean';
const counterSpecFile = 'ChaCha20Counter.lean';
const streamSpecFile = 'ChaCha20Stream.lean';
const proofFile = 'ChaCha20QuarterRoundRefinement.lean';
const streamProofFile = 'ChaCha20StreamRefinement.lean';
const theorems = ['quarter_round_refines', 'double_round_refines', 'rounds_20_refines',
  'block_words_refines', 'load_word_refines', 'initial_state_refines', 'serialize_refines',
  'block_refines', 'block_from_bytes_refines'].map((name) => `Abc.Refine.ChaCha20.${name}`);
const streamSpecTheorems = ['stream_position_exact', 'stream_counter_in_range', 'stream_count_exact',
  'stream_write_prefix', 'stream_guard_exact', 'chunked_stream_refines', 'stream_rejection_preserves',
  'stream_involution'].map((name) => `Abc.Spec.ChaCha20.${name}`);
const streamRefinementTheorems = ['extracted_block_provider_observes_result',
  'extracted_block_provider_refines', 'extracted_chunked_stream_refines']
  .map((name) => `Abc.Refine.ChaCha20.${name}`);
const allowedAxioms = new Set(['propext', 'Classical.choice', 'Quot.sound']);
const target = 'x86_64-unknown-linux-gnu';
const cargo = ['--locked', '--offline', '--lib', '--no-default-features', '--target', target];
const charonArgs = ['--preset=aeneas', '--start-from', 'crate::initial_state', '--start-from', 'crate::block'];
const aeneasArgs = ['-backend', 'lean', '-split-files', '-no-progress-bar', '-subdir', subdir,
  '-namespace', namespace];
const officialBinaries = {
  aeneas: '22b326476f854e19b52ca5a2acfd953fd186da7694cd10d8d008ed5502f7c46a',
  charon: '2603f720f0d26a4c77ae215485e2457029d69504dbd9d318a497ed866f21d4fd',
};
const sourceFiles = [
  pinPath, 'tools/build/rust/Cargo.toml', 'tools/build/rust/Cargo.lock',
  `${scope}/impl/rust/src/lib.rs`, `${scope}/impl/rust/Cargo.toml`,
  `${scope}/spec/${specFile}`, `${scope}/spec/${counterSpecFile}`, `${scope}/spec/${streamSpecFile}`,
  `${scope}/impl/rust/formal/${proofFile}`, 'tools/verification/chacha20/check.mjs',
  `tools/verification/chacha20/${streamProofFile}`,
];
const hash = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const hashes = (root, files) => Object.fromEntries(files.map((file) => [file, hash(join(root, file))]));
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

function auditTheorems(output, expected) {
  const reports = [...output.matchAll(/^'([^']+)' (?:depends on axioms:\s*\[([^\]]+)\]|does not depend on any axioms)\r?$/gm)];
  const audit = {};
  for (const theorem of expected) {
    const entry = reports.filter((match) => match[1] === theorem);
    if (entry.length !== 1) throw new Error(`Missing or ambiguous axiom report for ${theorem}`);
    const axioms = entry[0][2]?.split(',').map((name) => name.trim()) ?? [];
    if (axioms.some((name) => !allowedAxioms.has(name))) throw new Error(`Unapproved axiom in ${theorem}`);
    audit[theorem] = axioms;
  }
  return audit;
}

function check(toolRoot) {
  if (!toolRoot) throw new Error('Set ABC_AENEAS_ROOT to the pinned Aeneas checkout');
  const tools = resolve(toolRoot);
  const backend = join(tools, 'backends/lean');
  const charon = join(tools, 'charon/bin/charon');
  const aeneas = join(tools, 'bin/aeneas');
  const output = join(repo, '.abc/chacha20-extraction');
  mkdirSync(output, { recursive: true });
  const work = mkdtempSync(join(output, 'run-'));
  const report = { status: 'failed', scope: 'block_from_bytes', pins, target, features: [], cargo,
    charonArgs, aeneasArgs };

  function run(label, program, args, cwd, env = {}) {
    const result = spawnSync(program, args, { cwd, env: { ...process.env, ...env },
      encoding: 'utf8', timeout: 900_000, maxBuffer: 16 * 1024 * 1024 });
    const log = join(work, `${label}.log`);
    writeFileSync(log, `${JSON.stringify([program, ...args])}\n${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`);
    if (result.status !== 0) throw new Error(`${label} failed. See ${log}`);
    return result.stdout.trim();
  }

  function requireCleanPin(label, root, revision) {
    if (run(`${label}-revision`, 'git', ['rev-parse', 'HEAD'], root) !== revision ||
        run(`${label}-status`, 'git', ['status', '--porcelain', '--untracked-files=no'], root)) {
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
      .filter((entry) => entry.isFile())
      .map((entry) => relative(generated, join(entry.parentPath, entry.name)).replaceAll('\\', '/')).sort();
    if (!same(files, modelFiles)) throw new Error('Expected only generated Types and Funs modules');
    return { llbc: hash(llbc), files: hashes(generated, modelFiles) };
  }

  try {
    report.sources = hashes(repo, sourceFiles);
    report.revision = run('repository-revision', 'git', ['rev-parse', 'HEAD'], repo);
    requireCleanPin('aeneas', tools, pins.aeneas);
    requireCleanPin('charon', join(tools, 'charon'), pins.charon);
    report.binaries = { aeneas: hash(aeneas), charon: hash(charon) };
    if (!same(report.binaries, officialBinaries)) throw new Error('Expected the pinned Linux x86-64 release binaries');
    if (run('charon-toolchain', charon, ['toolchain-version'], crate) !== pins.rust) {
      throw new Error('Charon requested a different Rust toolchain');
    }
    report.rust = run('rustc-version', 'rustup', ['run', pins.rust, 'rustc', '-Vv'], crate);
    if (!report.rust.includes(`host: ${target}`)) throw new Error(`Expected a ${target} Rust host`);
    report.first = translate('first');
    report.second = translate('second');
    if (!same(report.first.files, report.second.files)) throw new Error('Independent translations disagree');

    report.lean = run('lean-version', 'lean', ['--version'], backend);
    if (!report.lean.includes(`version ${pins.lean.split(':v').at(-1)},`)) {
      throw new Error('Lean version mismatch');
    }
    const manifest = JSON.parse(readFileSync(join(backend, 'lake-manifest.json'), 'utf8'));
    if (manifest.packages.find((entry) => entry.name === 'mathlib')?.rev !== pins.mathlibRevision) {
      throw new Error('Mathlib manifest does not match the repository pin');
    }
    if (process.env.ABC_FORMAL_USE_MATHLIB_CACHE === '1') run('mathlib-cache', 'lake', ['exe', 'cache', 'get'], backend);
    run('aeneas-build', 'lake', ['build', '+Aeneas:olean'], backend);
    requireCleanPin('mathlib', join(backend, '.lake/packages/mathlib'), pins.mathlibRevision);
    const leanPath = run('lean-path', 'lake', ['env', 'node', '-p', 'process.env.LEAN_PATH'], backend);
    const objects = join(work, 'objects');
    const leanEnv = { LEAN_PATH: [objects, leanPath].join(delimiter) };
    function compile(root, file) {
      const object = join(objects, file.replace(/\.lean$/, '.olean'));
      mkdirSync(dirname(object), { recursive: true });
      return run(file.replaceAll('/', '-'), 'lean', [`--root=${root}`, '-DwarningAsError=true',
        '-o', object, join(root, file)], root, leanEnv);
    }
    const model = join(work, 'first');
    compile(model, `${subdir}/Types.lean`);
    compile(model, `${subdir}/Funs.lean`);
    const spec = join(repo, scope, 'spec');
    compile(spec, specFile);
    compile(spec, counterSpecFile);
    const blockAudit = auditTheorems(compile(join(crate, 'formal'), proofFile), theorems);
    const streamSpecAudit = auditTheorems(compile(spec, streamSpecFile), streamSpecTheorems);
    const streamRefinementAudit = auditTheorems(
      compile(dirname(fileURLToPath(import.meta.url)), streamProofFile), streamRefinementTheorems);
    if (!same(hashes(repo, sourceFiles), report.sources) || !same(hashes(model, modelFiles), report.first.files)) {
      throw new Error('Source or generated model changed during verification');
    }
    report.theorems = blockAudit;
    report.streamModel = { scope: 'logical_mutations_with_extracted_block',
      theorems: { ...streamSpecAudit, ...streamRefinementAudit } };
    report.status = 'block_from_bytes_refinement_checked';
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
