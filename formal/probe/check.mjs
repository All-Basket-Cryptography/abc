import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const probe = dirname(fileURLToPath(import.meta.url));
const pins = JSON.parse(readFileSync(join(probe, 'toolchain-candidate.json'), 'utf8'));
const allowedAxioms = new Set(['propext', 'Classical.choice', 'Quot.sound']);
const theorem = 'Abc.Probe.boundedAddRefines';

function run(program, args, cwd, label, work, environment = {}) {
  const result = spawnSync(program, args, {
    cwd,
    env: { ...process.env, ...environment },
    encoding: 'utf8',
    timeout: 1_800_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`;
  writeFileSync(join(work, `${label}.log`), `${JSON.stringify([program, ...args])}\n${output}`);
  if (result.error || result.signal) {
    throw new Error(`${label} could not run (${result.error?.message ?? result.signal})`);
  }
  return { ...result, output };
}

function requireSuccess(result, label) {
  if (result.status !== 0) throw new Error(`${label} failed with exit code ${result.status}`);
  return result.output.trim();
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function modelDigests(path) {
  const files = readdirSync(path).filter((file) => file.endsWith('.lean')).sort();
  if (!files.includes('Funs.lean')) throw new Error('Aeneas did not generate Funs.lean');
  return Object.fromEntries(files.map((file) => [file, sha256(join(path, file))]));
}

function parseAxioms(output, declaration) {
  const lines = output.split(/\r?\n/).filter((line) => line.startsWith(`'${declaration}' `));
  if (lines.length !== 1) throw new Error(`Missing or ambiguous axiom report for ${declaration}`);
  if (lines[0] === `'${declaration}' does not depend on any axioms`) return [];
  const report = /^'[^']+' depends on axioms: \[([^\]]+)\]$/.exec(lines[0]);
  if (!report) throw new Error(`Unrecognized axiom report for ${declaration}`);
  return report[1].split(',').map((name) => name.trim());
}

function assertPinnedCheckout(path, revision, label, work) {
  const actual = requireSuccess(run('git', ['rev-parse', 'HEAD'], path, `${label}-revision`, work), label);
  const status = requireSuccess(run('git', ['status', '--porcelain', '--untracked-files=no'], path, `${label}-status`, work), label);
  if (actual !== revision || status) throw new Error(`${label} must use its clean pinned checkout`);
}

function extract(label, source, output, work, aeneasRoot) {
  const crate = join(work, `rust-${label}`);
  mkdirSync(join(crate, 'src'), { recursive: true });
  copyFileSync(join(probe, 'rust', 'Cargo.toml'), join(crate, 'Cargo.toml'));
  copyFileSync(join(probe, 'rust', 'Cargo.lock'), join(crate, 'Cargo.lock'));
  writeFileSync(join(crate, 'src', 'lib.rs'), source);
  const model = join(work, `${label}.llbc`);
  const environment = { RUSTUP_TOOLCHAIN: pins.rust, CARGO_TARGET_DIR: join(crate, 'target') };
  const charon = join(aeneasRoot, 'charon', 'bin', 'charon');
  const aeneas = join(aeneasRoot, 'bin', 'aeneas');
  requireSuccess(run(charon, ['cargo', '--preset=aeneas', '--dest-file', model], crate, `${label}-charon`, work, environment), 'Charon extraction');
  mkdirSync(output, { recursive: true });
  requireSuccess(run(aeneas, ['-backend', 'lean', '-split-files', '-dest', output, '-subdir', 'Generated', '-namespace', 'Generated', model], crate, `${label}-aeneas`, work), 'Aeneas translation');
  return { rust: sha256(join(crate, 'src', 'lib.rs')), llbc: sha256(model), lean: modelDigests(join(output, 'Generated')) };
}

function main(work) {
  const tools = ['rustup', 'git', 'lake', 'lean'];
  const missing = tools.filter((tool) => spawnSync(tool, ['--version'], { encoding: 'utf8', timeout: 5000 }).error?.code === 'ENOENT');
  if (missing.length || !process.env.ABC_AENEAS_ROOT) {
    const reason = [missing.length && `missing commands: ${missing.join(', ')}`, !process.env.ABC_AENEAS_ROOT && 'ABC_AENEAS_ROOT is unset'].filter(Boolean).join('; ');
    throw new Error(reason);
  }
  const aeneasRoot = resolve(process.env.ABC_AENEAS_ROOT);
  assertPinnedCheckout(aeneasRoot, pins.aeneas, 'aeneas', work);
  assertPinnedCheckout(join(aeneasRoot, 'charon'), pins.charon, 'charon', work);
  const rustVersion = requireSuccess(run('rustup', ['run', pins.rust, 'rustc', '-Vv'], probe, 'rustc-version', work), 'Pinned rustc');
  const leanRoot = join(work, 'lean');
  mkdirSync(leanRoot);
  writeFileSync(join(leanRoot, 'lean-toolchain'), `${pins.lean}\n`);
  const leanVersion = requireSuccess(run('lean', ['--version'], leanRoot, 'lean-version', work), 'Pinned Lean');
  const expectedLeanVersion = pins.lean.split(':v').at(-1);
  if (!leanVersion.includes(`version ${expectedLeanVersion},`)) throw new Error('Lean does not match its pinned release');
  writeFileSync(join(leanRoot, 'lakefile.toml'), [
    'name = "abc_probe"', 'defaultTargets = ["Generated"]', '[[require]]', 'name = "aeneas"',
    `path = ${JSON.stringify(join(aeneasRoot, 'backends', 'lean'))}`, '[[lean_lib]]', 'name = "Generated"',
    'globs = ["Generated.+"]', '',
  ].join('\n'));
  const rustSource = readFileSync(join(probe, 'rust', 'src', 'lib.rs'), 'utf8');
  const positive = extract('positive', rustSource, leanRoot, work, aeneasRoot);
  const repeated = extract('repeat', rustSource, join(work, 'repeat'), work, aeneasRoot);
  if (JSON.stringify(positive.lean) !== JSON.stringify(repeated.lean)) {
    throw new Error('Independent extraction produced different Lean bytes');
  }
  requireSuccess(run('lake', ['update'], leanRoot, 'dependency-resolution', work), 'Lake dependency resolution');
  const manifest = JSON.parse(readFileSync(join(leanRoot, 'lake-manifest.json'), 'utf8'));
  const mathlib = manifest.packages.find((pkg) => pkg.name === 'mathlib');
  if (mathlib?.inputRev !== pins.mathlib || mathlib?.rev !== pins.mathlibRevision) {
    throw new Error('Lake did not resolve the pinned Mathlib release');
  }
  if (process.env.ABC_FORMAL_USE_MATHLIB_CACHE === '1') {
    requireSuccess(run('lake', ['exe', 'cache', 'get'], leanRoot, 'mathlib-cache', work), 'Pinned Mathlib cache');
  }
  requireSuccess(run('lake', ['build'], leanRoot, 'positive-model', work), 'Lean model build');
  copyFileSync(join(probe, 'Proof.lean'), join(leanRoot, 'Proof.lean'));
  const proofOutput = requireSuccess(run('lake', ['env', 'lean', 'Proof.lean'], leanRoot, 'positive-proof', work), 'Lean proof');
  const axioms = parseAxioms(proofOutput, theorem);
  if (axioms.some((axiom) => !allowedAxioms.has(axiom))) throw new Error('Probe theorem uses an unapproved axiom');
  copyFileSync(join(probe, 'RejectedProof.lean'), join(leanRoot, 'RejectedProof.lean'));
  const rejectedOutput = requireSuccess(run('lake', ['env', 'lean', 'RejectedProof.lean'], leanRoot, 'negative-axioms', work), 'Lean axiom fixtures');
  for (const fixture of ['transitiveSorry', 'customAxiom', 'nativeEvaluation']) {
    const fixtureAxioms = parseAxioms(rejectedOutput, `Abc.Probe.Fixtures.${fixture}`);
    if (!fixtureAxioms.some((axiom) => !allowedAxioms.has(axiom))) {
      throw new Error(`Axiom fixture ${fixture} escaped the allowlist`);
    }
  }
  const mutantSource = rustSource.replace('    left + right', '    left');
  if (mutantSource === rustSource) throw new Error('The mutation did not change the Rust program');
  renameSync(join(leanRoot, 'Generated'), join(work, 'positive-generated'));
  const mutant = extract('mutant', mutantSource, leanRoot, work, aeneasRoot);
  requireSuccess(run('lake', ['build'], leanRoot, 'negative-model', work), 'Mutant Lean model build');
  const negative = run('lake', ['env', 'lean', 'Proof.lean'], leanRoot, 'negative-proof', work);
  if (negative.status === 0 || !/Proof\.lean:\d+:\d+: error:/.test(negative.output)) {
    throw new Error('The checker did not report a proof error for the mutant model');
  }
  const binaries = {
    charon: sha256(join(aeneasRoot, 'charon', 'bin', 'charon')),
    aeneas: sha256(join(aeneasRoot, 'bin', 'aeneas')),
  };
  return { positive, repeated, mutant, theorem, axioms, rustVersion, leanVersion, binaries,
    mathlibRevision: mathlib.rev, proofSource: sha256(join(probe, 'Proof.lean')) };
}

const outputRoot = resolve(probe, '..', '..', '.abc', 'formal-probe');
mkdirSync(outputRoot, { recursive: true });
const work = mkdtempSync(join(outputRoot, 'run-'));
let report;
try {
  report = { status: 'passed', pins, ...main(work) };
} catch (error) {
  report = { status: 'not_passed', pins, error: error.message };
  process.exitCode = 1;
}
writeFileSync(join(work, 'result.json'), `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify({ ...report, path: work }));
