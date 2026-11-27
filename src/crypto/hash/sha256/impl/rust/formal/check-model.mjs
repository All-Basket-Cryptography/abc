import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../../../../../..');
const pins = JSON.parse(readFileSync(join(repo, 'tools/verification/probe/toolchain-candidate.json'), 'utf8'));
const modules = ['Abc/Sha256/Extracted/Types.lean', 'Abc/Sha256/Extracted/Funs.lean'];
const proofModules = [
  'Sha256Spec.lean', 'CompressionRefinement.lean', 'StreamingRefinement.lean', 'ModelView.lean',
  'CounterRefinement.lean', 'WordRefinement.lean', 'CoreRefinement.lean', 'ExtractedCompression.lean',
  'UpdateRefinement.lean', 'FinalizeRefinement.lean',
];
const declarations = [
  'new_refines', 'compress_refines', 'update_refines', 'finalize_refines', 'digest_refines',
  'finalize_trace_refines', 'finalize_trace_refines_concat',
].map((name) => `Abc.Refine.Sha256.Implementation.${name}`);
const permittedAxioms = new Set(['propext', 'Classical.choice', 'Quot.sound']);
const target = 'x86_64-unknown-linux-gnu';
const hash = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

function main(reportPath, toolRoot) {
  if (!reportPath || !toolRoot) throw new Error('Pass the extraction result.json and set ABC_AENEAS_ROOT');
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  const cleanRoot = resolve(toolRoot);
  const backend = join(cleanRoot, 'backends', 'lean');
  const work = mkdtempSync(join(dirname(resolve(reportPath)), 'proof-'));

  function run(label, program, args, cwd, env = {}) {
    const result = spawnSync(program, args, {
      cwd, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 900_000, maxBuffer: 16 * 1024 * 1024,
    });
    const output = `${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`;
    writeFileSync(join(work, `${label}.log`), `${JSON.stringify([program, ...args])}\n${output}`);
    if (result.status !== 0) throw new Error(`${label} failed, see ${join(work, `${label}.log`)}`);
    return result.stdout.trim();
  }

  if (report.status !== 'model_generated' || report.scope !== 'entire crate' ||
      JSON.stringify(report.pins) !== JSON.stringify(pins) ||
      !report.toolchain?.rust.includes(`host: ${target}`)) {
    throw new Error('A successful full-crate extraction at the repository toolchain pins is required');
  }
  const extraction = report.extraction;
  if (extraction?.target !== target || JSON.stringify(extraction.features) !== '[]' ||
      JSON.stringify(extraction.cargo) !== JSON.stringify(
        ['--locked', '--offline', '--lib', '--no-default-features', '--target', target])) {
    throw new Error('The extraction must select the pinned Cargo target without features');
  }
  const subject = [
    'src/crypto/hash/sha256/impl/rust/src/lib.rs',
    'src/crypto/hash/sha256/impl/rust/Cargo.toml',
    'tools/build/rust/Cargo.toml',
    'tools/build/rust/Cargo.lock',
  ];
  for (const file of subject) {
    if (hash(join(repo, file)) !== report.subject?.[file]) throw new Error(`Extraction source mismatch: ${file}`);
  }
  for (const pass of ['first', 'second']) {
    const model = report[pass];
    if (hash(join(dirname(reportPath), `${pass}.llbc`)) !== model.llbc) {
      throw new Error(`Extraction LLBC mismatch: ${pass}`);
    }
    if (model.unresolvedTemplates.length || Object.keys(model.lean).length !== modules.length) {
      throw new Error(`The ${pass} extraction has unexpected Lean modules`);
    }
    for (const file of modules) {
      if (hash(join(dirname(reportPath), `lean-${pass}`, file)) !== model.lean[file] ||
          model.lean[file] !== report.first.lean[file]) {
        throw new Error(`Extraction model mismatch: ${file}`);
      }
    }
  }
  const revision = run('aeneas-revision', 'git', ['rev-parse', 'HEAD'], cleanRoot);
  const status = run('aeneas-status', 'git', ['status', '--porcelain', '--untracked-files=no'], cleanRoot);
  if (revision !== pins.aeneas || status) throw new Error('Aeneas source does not match the clean pin');
  const mathlib = JSON.parse(readFileSync(join(backend, 'lake-manifest.json'), 'utf8'))
    .packages.find((entry) => entry.name === 'mathlib');
  if (mathlib?.rev !== pins.mathlibRevision) throw new Error('Mathlib revision mismatch');
  const version = run('lean-version', 'lean', ['--version'], backend);
  if (!version.includes(`version ${pins.lean.split(':v').at(-1)},`)) throw new Error('Lean version mismatch');
  if (process.env.ABC_FORMAL_USE_MATHLIB_CACHE === '1') {
    run('mathlib-cache', 'lake', ['exe', 'cache', 'get'], backend);
  }
  run('aeneas-build', 'lake', ['build', '+Aeneas:olean'], backend);
  const resolvedMathlib = join(backend, '.lake/packages/mathlib');
  if (run('mathlib-revision', 'git', ['rev-parse', 'HEAD'], resolvedMathlib) !== pins.mathlibRevision ||
      run('mathlib-status', 'git', ['status', '--porcelain', '--untracked-files=no'], resolvedMathlib)) {
    throw new Error('Mathlib source does not match the clean pin');
  }
  const dependencyPath = run('lean-path', 'lake', ['env', 'node', '-p', 'process.env.LEAN_PATH'], backend);
  const env = { LEAN_PATH: `${work}${delimiter}${dependencyPath}` };
  const generated = join(dirname(resolve(reportPath)), 'lean-first');

  function compile(root, file) {
    const output = join(work, file.replace(/\.lean$/, '.olean'));
    mkdirSync(dirname(output), { recursive: true });
    return run(file.replaceAll('/', '-'), 'lean',
      [`--root=${root}`, '-o', output, join(root, file)], root, env);
  }

  const proofSources = {};
  function compileProof(root, file) {
    proofSources[file] = hash(join(root, file));
    return compile(root, file);
  }
  compileProof(join(repo, 'src/lean'), 'Abc/Foundation/Encoding.lean');
  for (const file of modules) compile(generated, file);
  const spec = join(repo, 'src/crypto/hash/sha256/spec');
  for (const file of proofModules) {
    const root = ['Sha256Spec.lean', 'CompressionRefinement.lean', 'StreamingRefinement.lean'].includes(file)
      ? spec : here;
    compileProof(root, file);
  }
  const output = compileProof(here, 'Refinement.lean');
  compileProof(here, 'TrustedClaims.lean');
  const reports = [...output.matchAll(/^'([^']+)' (?:depends on axioms:\s*\[([^\]]+)\]|does not depend on any axioms)\r?$/gm)];
  const axioms = {};
  for (const declaration of declarations) {
    const entries = reports.filter((report) => report[1] === declaration);
    if (entries.length !== 1) throw new Error(`Missing or ambiguous axiom report: ${declaration}`);
    const dependencies = entries[0][2];
    axioms[declaration] = dependencies ? dependencies.split(',').map((axiom) => axiom.trim()) : [];
    if (axioms[declaration].some((axiom) => !permittedAxioms.has(axiom))) {
      throw new Error(`Unapproved axiom in ${declaration}`);
    }
  }
  const summary = {
    status: 'implementation_refinement_checked', axioms, lean: version, mathlib: mathlib.rev,
    extraction, extractionToolchain: report.toolchain, subject: report.subject,
    llbc: { first: report.first.llbc, second: report.second.llbc }, model: report.first.lean, proofSources,
  };
  writeFileSync(join(work, 'result.json'), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(JSON.stringify({ ...summary, path: work }));
}

try {
  main(process.argv[2], process.env.ABC_AENEAS_ROOT);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
