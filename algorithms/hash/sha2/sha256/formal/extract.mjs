import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../../../../..');
const crate = resolve(here, '../implementations/abc-rust-portable');
const workspace = join(repo, 'build/rust');
const pins = JSON.parse(readFileSync(join(repo, 'formal/probe/toolchain-candidate.json'), 'utf8'));
const argumentsGiven = process.argv.slice(2);
const llbcOnly = argumentsGiven[0] === '--llbc-only';
if (llbcOnly) argumentsGiven.shift();
const item = argumentsGiven[0] === '--item' ? argumentsGiven[1] : undefined;
if (argumentsGiven.length && !(argumentsGiven.length === 2 && /^crate(?:::[A-Za-z_][A-Za-z_0-9]*)+$/.test(item ?? ''))) {
  console.error('Usage: node algorithms/hash/sha2/sha256/formal/extract.mjs [--llbc-only] [--item crate::name]');
  process.exit(2);
}

const directory = join(repo, '.abc/sha256-extraction');
mkdirSync(directory, { recursive: true });
const output = mkdtempSync(join(directory, 'run-'));
const subjectFiles = [join(crate, 'src/lib.rs'), join(crate, 'Cargo.toml'), join(workspace, 'Cargo.toml'), join(workspace, 'Cargo.lock')];
const digest = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const subject = () => Object.fromEntries(subjectFiles.map((file) => [relative(repo, file).replaceAll('\\', '/'), digest(file)]));
const result = { status: 'failed', scope: item ?? 'entire crate', pins, subject: subject() };

function run(label, program, args, cwd, environment = {}) {
  console.log(`${label}: ${basename(program)}`);
  const execution = spawnSync(program, args, {
    cwd, env: { ...process.env, ...environment }, encoding: 'utf8', timeout: 600_000, maxBuffer: 32 * 1024 * 1024,
  });
  writeFileSync(join(output, `${label}.log`), `${JSON.stringify([program, ...args])}\n${execution.stdout ?? ''}${execution.stderr ?? ''}${execution.error?.message ?? ''}`);
  if (execution.error || execution.signal || execution.status !== 0) {
    throw new Error(`${label} failed: ${execution.error?.message ?? execution.signal ?? `exit ${execution.status}`}`);
  }
  return execution.stdout.trim();
}

function checkout(root, revision, label) {
  const actual = run(`${label}-revision`, 'git', ['rev-parse', 'HEAD'], root);
  const modifications = run(`${label}-status`, 'git', ['status', '--porcelain', '--untracked-files=no'], root);
  if (actual !== revision || modifications) throw new Error(`${label} checkout does not match its clean pin`);
}

function leanFiles(folder) {
  if (!existsSync(folder)) return {};
  const files = readdirSync(folder, { recursive: true, withFileTypes: true })
    .filter((path) => path.isFile() && path.name.endsWith('.lean'))
    .map((entry) => join(entry.parentPath, entry.name)).sort();
  return Object.fromEntries(files.map((file) => [relative(folder, file).replaceAll('\\', '/'), digest(file)]));
}

function extract(charon, aeneas, label) {
  const llbc = join(output, `${label}.llbc`);
  const selector = item ? ['--start-from', item] : [];
  const env = { RUSTUP_TOOLCHAIN: pins.rust, CARGO_NET_OFFLINE: 'true', CARGO_TARGET_DIR: join(output, `cargo-${label}`) };
  run(`${label}-charon`, charon, ['cargo', '--preset=aeneas', '--dest-file', llbc, ...selector,
    '--', '--locked', '--offline', '--lib'], crate, env);
  const readable = run(`${label}-pretty`, charon, ['pretty-print', llbc], crate);
  writeFileSync(join(output, `${label}.txt`), `${readable}\n`);
  const extraction = { llbc: digest(llbc) };
  result[label] = extraction;
  if (aeneas) {
    const out = join(output, `lean-${label}`);
    mkdirSync(out);
    try {
      run(`${label}-aeneas`, aeneas, ['-backend', 'lean', '-split-files', '-dest', out,
        '-subdir', 'Abc/Sha256/Extracted', '-namespace', 'Abc.Sha256.Extracted', llbc], crate);
    } finally {
      extraction.lean = leanFiles(out);
    }
    if (!extraction.lean['Abc/Sha256/Extracted/Funs.lean']) throw new Error(`${label} is missing its generated function model`);
    extraction.unresolvedTemplates = Object.keys(extraction.lean).filter((file) => file.includes('External_Template'));
  }
}

try {
  const toolRoot = process.env.ABC_AENEAS_ROOT;
  if (!toolRoot && !llbcOnly) throw new Error('ABC_AENEAS_ROOT must point to the pinned Aeneas checkout');
  const charon = llbcOnly ? process.env.ABC_CHARON : join(toolRoot, 'charon/bin/charon');
  if (!charon) throw new Error('ABC_CHARON must point to the pinned Charon binary for --llbc-only');
  const aeneas = llbcOnly ? undefined : join(toolRoot, 'bin/aeneas');
  if (aeneas) {
    checkout(toolRoot, pins.aeneas, 'aeneas');
    checkout(join(toolRoot, 'charon'), pins.charon, 'charon');
  }
  const rust = run('rustc-version', 'rustup', ['run', pins.rust, 'rustc', '-Vv'], repo);
  const charonToolchain = run('charon-toolchain', charon, ['toolchain-version'], repo);
  if (charonToolchain !== pins.rust) throw new Error('Charon embeds a different Rust toolchain');
  const charonVersion = run('charon-version', charon, ['version'], repo);
  if (llbcOnly && !charonVersion.includes(pins.charon)) throw new Error('Standalone Charon does not report the pinned revision');
  const aeneasVersion = aeneas && run('aeneas-version', aeneas, ['-version'], repo);
  result.toolchain = { rust, charonVersion, charonBinary: digest(charon), aeneasVersion, aeneasBinary: aeneas && digest(aeneas) };
  extract(charon, aeneas, 'first');
  if (aeneas) {
    extract(charon, aeneas, 'second');
    if (JSON.stringify(result.first.lean) !== JSON.stringify(result.second.lean)) {
      throw new Error('Independent extraction did not reproduce the Lean model bytes');
    }
  }
  if (JSON.stringify(subject()) !== JSON.stringify(result.subject)) throw new Error('The Rust subject changed during extraction');
  result.status = aeneas ? 'model_generated' : 'llbc_generated';
} catch (error) {
  result.error = error.message;
  process.exitCode = 1;
}
writeFileSync(join(output, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify({ ...result, path: output }));
