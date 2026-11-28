import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../../..');
const pinPath = 'tools/verification/probe/toolchain-candidate.json';
const scope = 'src/crypto/mac/poly1305';
const sources = [pinPath, 'tools/build/rust/Cargo.toml', 'tools/build/rust/Cargo.lock',
  `${scope}/impl/rust/src/lib.rs`, `${scope}/impl/rust/Cargo.toml`, 'tools/verification/poly1305/check.mjs'];
const generated = ['Abc/Poly1305/Extracted/Funs.lean', 'Abc/Poly1305/Extracted/Types.lean'];
const audits = {
  Poly1305EncodingRefinement: ['Abc.Refine.Poly1305.Encoding.source_limbs_refines'],
  Poly1305SourceRefinement: ['source_carry_pair_refines', 'source_carry_upper_refines',
    'source_carry_refines', 'source_key_multiples_refines', 'source_multiply_refines',
    'source_absorb_limbs_refines', 'source_absorb_polynomial_step'].map((name) => `Abc.Refine.Poly1305.${name}`),
};
const permittedAxioms = new Set(['propext', 'Classical.choice', 'Quot.sound']);
const digest = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

function runReplay(artifactPath) {
  if (!artifactPath) throw new Error('Usage: node tools/verification/poly1305/replay.mjs <extraction-run-directory>');
  if (!process.env.LEAN_PATH) throw new Error('Set LEAN_PATH to the built pinned Aeneas backend and package libraries');
  const artifact = resolve(artifactPath);
  const receipt = JSON.parse(readFileSync(join(artifact, 'result.json'), 'utf8'));
  if (receipt.status !== 'poly1305_model_extracted' || receipt.scope !== 'poly1305_block_absorption' ||
      receipt.target !== 'x86_64-unknown-linux-gnu' || receipt.features?.length !== 0) {
    throw new Error('Expected a successful Poly1305 Linux extraction receipt');
  }
  for (const source of sources) {
    if (digest(join(repo, source)) !== receipt.sources?.[source]) {
      throw new Error(`Extraction input differs from the current checkout: ${source}`);
    }
  }
  for (const file of generated) {
    const expected = receipt.first?.files?.[file];
    if (expected !== receipt.second?.files?.[file] ||
        ['first', 'second'].some((run) => digest(join(artifact, run, file)) !== expected)) {
      throw new Error(`The independently generated models disagree: ${file}`);
    }
  }

  const output = join(repo, '.abc/poly1305-replay');
  mkdirSync(output, { recursive: true });
  const work = mkdtempSync(join(output, 'run-'));
  const lean = process.env.ABC_LEAN_BIN || 'lean';
  const env = { ...process.env, LEAN_PATH: `${work}${delimiter}${process.env.LEAN_PATH}` };

  function run(label, args, cwd) {
    const result = spawnSync(lean, args, { cwd, env, encoding: 'utf8', timeout: 900_000,
      maxBuffer: 16 * 1024 * 1024 });
    const log = join(work, `${label}.log`);
    writeFileSync(log, `${JSON.stringify([lean, ...args])}\n${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`);
    if (result.status !== 0) throw new Error(`${label} failed. See ${log}`);
    return result.stdout;
  }

  function compile(cwd, file, module) {
    const compiled = join(work, `${module}.olean`);
    mkdirSync(dirname(compiled), { recursive: true });
    return run(module.replaceAll('/', '-'), ['-j2', '-DwarningAsError=true', '-o', compiled, file], cwd);
  }

  const pins = JSON.parse(readFileSync(join(repo, pinPath), 'utf8'));
  const version = run('lean-version', ['--version'], repo);
  if (!version.includes(`version ${pins.lean.split(':v')[1]},`)) throw new Error('Lean version differs from the pin');
  for (const file of generated.toReversed()) compile(join(artifact, 'first'), file, file.slice(0, -5));
  compile(join(repo, scope, 'impl/go'), 'Poly1305GoModel.lean', 'Poly1305GoModel');
  for (const [module, theorems] of Object.entries(audits)) {
    const checked = compile(here, `${module}.lean`, module);
    const dependencies = new Map([...checked.matchAll(/^'([^']+)' depends on axioms: \[([^\]]*)\]/gm)]
      .map((match) => [match[1], match[2].split(', ').filter(Boolean)]));
    for (const theorem of theorems) {
      if (!dependencies.has(theorem) || dependencies.get(theorem).some((axiom) => !permittedAxioms.has(axiom))) {
        throw new Error(`Missing or unexpected axiom audit for ${theorem}. See ${join(work, `${module}.log`)}`);
      }
    }
  }
  const report = { status: 'poly1305_source_refinement_checked', extractionRevision: receipt.revision,
    target: receipt.target, model: receipt.first.files, theorems: Object.values(audits).flat(),
    proofFiles: Object.fromEntries(Object.keys(audits).map((module) => [module, digest(join(here, `${module}.lean`))])),
  };
  writeFileSync(join(work, 'result.json'), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ ...report, path: work }));
}

try {
  runReplay(process.argv[2]);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
