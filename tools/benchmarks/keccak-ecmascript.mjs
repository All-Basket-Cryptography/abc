import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';

const index = process.argv[2];
if (!index) throw new Error('Pass a checkout containing the baseline src/crypto tree');
const baseline = resolve(index);
const candidate = fileURLToPath(new URL('../../', import.meta.url));
const rows = [
  { profile: 'sha3-256', exported: 'sha3_256', output: 32 },
  { profile: 'shake256', exported: 'shake256', output: 32 },
  { profile: 'shake256', exported: 'shake256', output: 1536 },
];
const repetitions = 11;
const warmupCalls = 128;
let checksum = 0;

function time(hash, count) {
  const start = performance.now();
  for (let i = 0; i < count; ++i) checksum = (checksum * 31 + hash()[0]) | 0;
  return (performance.now() - start) * 1000 / count;
}

function statistics(values) {
  const sorted = values.slice().sort((a, b) => a - b);
  return { median: sorted[repetitions >>> 1], min: sorted[0], max: sorted.at(-1) };
}

function open(root, profile, name, language, extension) {
  return import(pathToFileURL(join(root, 'src/crypto/hash', profile, 'impl', language, name + '.' + extension)));
}

const results = [];
for (const [language, extension] of [['javascript', 'mjs'], ['typescript', 'mts']]) {
  for (const { profile, exported, output } of rows) {
    const before = (await open(baseline, profile, exported, language, extension))[exported];
    const after = (await open(candidate, profile, exported, language, extension))[exported];
    for (const size of [64, 1024, 16384]) {
      const input = Uint8Array.from({ length: size }, (_, i) => (i * 137) ^ (i >>> 5));
      const options = profile === 'shake256' ? { outputLength: output } : undefined;
      const expected = createHash(profile, options).update(input).digest();
      const methods = [() => before(input, output), () => after(input, output)];
      for (const method of methods) assert.deepEqual(Buffer.from(method()), expected);
      const count = size === 16384 ? 48 : 192;
      for (const method of methods) time(method, warmupCalls);
      const readings = [[], []];
      for (let sample = 0; sample < repetitions; ++sample) {
        const first = sample & 1;
        readings[first].push(time(methods[first], count));
        readings[1 - first].push(time(methods[1 - first], count));
      }
      results.push({ language, profile, inputBytes: size, outputBytes: output, callsPerSample: count,
        baseline: statistics(readings[0]), candidate: statistics(readings[1]) });
    }
  }
}
function treeHashes(root) {
  const result = {};
  for (const [language, extension] of [['javascript', 'mjs'], ['typescript', 'mts']]) {
    for (const [profile, filename] of [['keccak-p1600', 'keccak'], ['sha3-256', 'sha3_256'], ['shake256', 'shake256']]) {
      const path = `src/crypto/hash/${profile}/impl/${language}/${filename}.${extension}`;
      result[path] = createHash('sha256').update(readFileSync(join(root, path))).digest('hex');
    }
  }
  return result;
}
console.log(JSON.stringify({
  node: process.version, openssl: process.versions.openssl, cpu: cpus()[0].model,
  platform: process.platform, arch: process.arch, units: 'microseconds per operation',
  repetitions, warmupCalls, checksum, baselineSources: treeHashes(baseline), candidateSources: treeHashes(candidate),
  byteViewSources: Object.fromEntries(['mjs', 'mts'].map((ext) => {
    const path = `src/crypto/inputs/bytes.${ext}`;
    return [path, createHash('sha256').update(readFileSync(join(candidate, path))).digest('hex')];
  })),
  results,
}, null, 2));
