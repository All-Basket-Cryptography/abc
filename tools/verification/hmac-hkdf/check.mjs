import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { delimiter, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../../..');
const sha256 = 'src/crypto/hash/sha256/impl/rust/formal';
const target = 'x86_64-unknown-linux-gnu';
const cargo = ['--locked', '--offline', '--lib', '--no-default-features', '--target', target];
const pins = JSON.parse(readFileSync(join(repo, 'tools/verification/probe/toolchain-candidate.json'), 'utf8'));
const constructions = [
  {
    name: 'hmac',
    crate: 'src/crypto/mac/hmac-sha256/impl/rust',
    spec: 'src/crypto/mac/hmac-sha256/spec',
    namespace: 'Abc.HmacSha256.Extracted',
    externalType: 'abc_sha256.Sha256',
    externalFunctions: [
      'abc_sha256.DIGEST_BYTES', 'abc_sha256.MAX_MESSAGE_BYTES',
      'abc_sha256.Sha256.new', 'abc_sha256.Sha256.update', 'abc_sha256.Sha256.finalize', 'abc_sha256.digest',
    ],
    proofs: ['HmacSpec', 'HmacPadRefinement', 'HmacRefinement', 'HmacTrustedClaims'],
  },
  {
    name: 'hkdf',
    crate: 'src/crypto/kdf/hkdf-sha256/impl/rust',
    spec: 'src/crypto/kdf/hkdf-sha256/spec',
    namespace: 'Abc.HkdfSha256.Extracted',
    externalType: 'abc_hmac_sha256.HmacSha256',
    externalFunctions: [
      'abc_hmac_sha256.TAG_BYTES', 'abc_hmac_sha256.MAX_KEY_BYTES', 'abc_hmac_sha256.MAX_INPUT_BYTES',
      'abc_hmac_sha256.HmacSha256.new', 'abc_hmac_sha256.HmacSha256.update',
      'abc_hmac_sha256.HmacSha256.finalize', 'abc_hmac_sha256.authenticate',
    ],
    proofs: ['HkdfSpec', 'HkdfLengthRefinement', 'ExpandInvariant', 'ExpandBlockRefinement',
      'ExpandRefinement', 'HkdfRefinement', 'HkdfApi', 'HkdfClaims'],
  },
];
const claims = {
  HmacRefinement: [
    'new_refines', 'new_rejects', 'update_refines', 'finalize_refines', 'authenticate_refines',
    'finalize_trace_refines', 'finalize_trace_refines_concat',
  ].map((name) => `Abc.Refine.HmacSha256.Implementation.${name}`),
  ExpandRefinement: ['copy_block_refines', 'expand_block_refines', 'expand_loop_refines']
    .map((name) => `Abc.Refine.HkdfSha256.Implementation.${name}`),
  HkdfRefinement: ['Abc.Refine.HkdfSha256.validate_expansion_refines'],
  HkdfApi: ['extract_refines', 'expand_refines', 'prk_as_bytes_refines', 'prk_expand_refines', 'derive_refines']
    .map((name) => `Abc.Refine.HkdfSha256.Implementation.${name}`),
};
const permittedAxioms = new Set(['propext', 'Classical.choice', 'Quot.sound']);
const hash = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const readJson = (file) => JSON.parse(readFileSync(file, 'utf8'));
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function generatedFiles(folder) {
  return readdirSync(folder, { withFileTypes: true, recursive: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.lean'))
    .map((entry) => relative(folder, join(entry.parentPath, entry.name)).replaceAll('\\', '/'))
    .sort();
}

function validateTemplate(folder, file, names) {
  const declared = [...readFileSync(join(folder, file), 'utf8')
    .matchAll(/^axiom ([A-Za-z_][A-Za-z_0-9.]*)\b/gm)].map((declaration) => declaration[1]).sort();
  if (!same(declared, [...names].sort())) throw new Error(`Unexpected external declarations in ${file}`);
}

function check(reportPath, aeneasRoot) {
  if (!aeneasRoot) throw new Error('Set ABC_AENEAS_ROOT to the pinned Aeneas checkout');
  const runRoot = join(repo, '.abc/hmac-hkdf-extraction');
  mkdirSync(runRoot, { recursive: true });
  const work = mkdtempSync(join(runRoot, 'run-'));
  const result = { status: 'failed', pins, target, features: [], cargo, model: {}, axioms: {} };

  function run(label, program, args, cwd, env = {}) {
    const execution = spawnSync(program, args, {
      cwd, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 900_000, maxBuffer: 32 * 1024 * 1024,
    });
    const output = `${execution.stdout ?? ''}${execution.stderr ?? ''}${execution.error?.message ?? ''}`;
    writeFileSync(join(work, `${label}.log`), `${JSON.stringify([program, ...args])}\n${output}`);
    if (execution.status !== 0) throw new Error(`${label} failed, see ${join(work, `${label}.log`)}`);
    return execution.stdout.trim();
  }

  const linkRoot = join(here, 'links');
  const sourceFiles = [
    'tools/build/rust/Cargo.toml', 'tools/build/rust/Cargo.lock', 'tools/verification/probe/toolchain-candidate.json',
    'src/crypto/hash/sha256/impl/rust/Cargo.toml',
    'src/crypto/hash/sha256/impl/rust/src/lib.rs',
  ].concat(constructions.flatMap(({ crate, spec, namespace, proofs }) => [
    `${crate}/src/lib.rs`, `${crate}/Cargo.toml`,
    ...proofs.map((name) => `${name.endsWith('Spec') ? spec : `${crate}/formal`}/${name}.lean`),
    ...['TypesExternal', 'FunsExternal'].map((name) =>
      `tools/verification/hmac-hkdf/links/${namespace.replaceAll('.', '/')}/${name}.lean`),
  ]));
  const sourceHashes = () => Object.fromEntries(sourceFiles.map((file) => [file, hash(join(repo, file))]));
  try {
    result.sources = sourceHashes();
    const toolRoot = resolve(aeneasRoot);
    const charon = join(toolRoot, 'charon/bin/charon');
    const aeneas = join(toolRoot, 'bin/aeneas');
    if (!reportPath) {
      const extraction = run('sha256-extraction', process.execPath, [join(repo, sha256, 'extract.mjs')], repo);
      reportPath = join(JSON.parse(extraction.split(/\r?\n/).at(-1)).path, 'result.json');
    }
    const shaReport = resolve(reportPath);
    const shaLog = run('sha256-proof', process.execPath, [join(repo, sha256, 'check-model.mjs'), shaReport], repo);
    const shaProof = JSON.parse(shaLog.split(/\r?\n/).at(-1));
    if (shaProof.status !== 'implementation_refinement_checked') throw new Error('SHA-256 refinement did not pass');
    result.sha256 = { extraction: hash(shaReport), proof: hash(join(shaProof.path, 'result.json')) };
    const toolchain = readJson(shaReport).toolchain;
    if (hash(charon) !== toolchain.charonBinary || hash(aeneas) !== toolchain.aeneasBinary) {
      throw new Error('Construction extraction binaries do not match the SHA-256 extraction');
    }
    result.extractionToolchain = toolchain;

    const backend = join(toolRoot, 'backends/lean');
    const dependencyPath = run('lean-path', 'lake', ['env', 'node', '-p', 'process.env.LEAN_PATH'], backend);
    // Lean resolves a module's top-level namespace in one search root.
    const objectRoot = shaProof.path;
    const leanEnvironment = { LEAN_PATH: [objectRoot, dependencyPath].join(delimiter) };
    function compile(root, file) {
      const object = join(objectRoot, file.replace(/\.lean$/, '.olean'));
      mkdirSync(dirname(object), { recursive: true });
      return run(file.replaceAll('/', '-'), 'lean', [`--root=${root}`, '-o', object, join(root, file)], root, leanEnvironment);
    }

    for (const construction of constructions) {
      const { name, crate, spec, namespace, externalType, externalFunctions, proofs } = construction;
      const crateRoot = join(repo, crate);
      const subdir = namespace.replaceAll('.', '/');
      const expectedModules = ['Types', 'Funs', 'TypesExternal_Template', 'FunsExternal_Template']
        .map((module) => `${subdir}/${module}.lean`).sort();
      const aeneasArgs = ['-backend', 'lean', '-split-files', '-no-progress-bar', '-subdir', subdir,
        '-namespace', namespace];
      const passes = result.model[name] = { aeneasArgs };
      for (const pass of ['first', 'second']) {
        const label = `${name}-${pass}`;
        const llbc = join(work, `${label}.llbc`);
        const out = join(work, label);
        mkdirSync(out);
        const env = {
          RUSTUP_TOOLCHAIN: pins.rust, CARGO_NET_OFFLINE: 'true', CARGO_TARGET_DIR: join(work, `cargo-${label}`),
        };
        run(`${label}-charon`, charon, ['cargo', '--preset=aeneas', '--dest-file', llbc, '--', ...cargo], crateRoot, env);
        run(`${label}-aeneas`, aeneas, [...aeneasArgs, '-dest', out, llbc], crateRoot);
        const files = generatedFiles(out);
        if (!same(files, expectedModules)) throw new Error(`Unexpected generated modules in ${label}`);
        validateTemplate(out, `${subdir}/TypesExternal_Template.lean`, [externalType]);
        validateTemplate(out, `${subdir}/FunsExternal_Template.lean`, externalFunctions);
        passes[pass] = { llbc: hash(llbc), files: Object.fromEntries(files.map((file) => [file, hash(join(out, file))])) };
      }
      if (!same(passes.first.files, passes.second.files)) throw new Error(`Independent ${name} extraction disagrees`);

      const generated = join(work, `${name}-first`);
      compile(linkRoot, `${subdir}/TypesExternal.lean`);
      compile(generated, `${subdir}/Types.lean`);
      compile(linkRoot, `${subdir}/FunsExternal.lean`);
      compile(generated, `${subdir}/Funs.lean`);
      for (const proof of proofs) compile(proof.endsWith('Spec') ? join(repo, spec) : join(crateRoot, 'formal'), `${proof}.lean`);
    }

    const declarations = Object.values(claims).flat();
    const audit = [
      ...Object.keys(claims).map((name) => `import ${name}`),
      ...declarations.map((name) => `#print axioms ${name}`), '',
    ];
    writeFileSync(join(work, 'ConstructionClaimAudit.lean'), audit.join('\n'));
    const printed = compile(work, 'ConstructionClaimAudit.lean');
    const reports = [...printed.matchAll(/^'([^']+)' (?:depends on axioms:\s*\[([^\]]+)\]|does not depend on any axioms)\r?$/gm)];
    for (const name of declarations) {
      const entries = reports.filter((report) => report[1] === name);
      if (entries.length !== 1) throw new Error(`Missing or ambiguous axiom report: ${name}`);
      const axioms = entries[0][2]?.split(',').map((axiom) => axiom.trim()) ?? [];
      if (axioms.some((axiom) => !permittedAxioms.has(axiom))) throw new Error(`Unapproved axiom in ${name}`);
      result.axioms[name] = axioms;
    }
    if (!same(sourceHashes(), result.sources)) throw new Error('Construction sources changed during the check');
    result.status = 'implementation_refinement_checked';
  } catch (error) {
    result.error = error.message;
    process.exitCode = 1;
  }
  writeJson(join(work, 'result.json'), result);
  console.log(JSON.stringify({ ...result, path: work }));
}

try {
  check(process.argv[2], process.env.ABC_AENEAS_ROOT);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
