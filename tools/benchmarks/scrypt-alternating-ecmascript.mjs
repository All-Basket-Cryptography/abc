import assert from 'node:assert/strict';
import { createHash, scryptSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { cpus, release } from 'node:os';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';

if (process.argv.length !== 3) throw new Error('Pass an archived baseline root or checkout');
const roots = [resolve(process.argv[2]), fileURLToPath(new URL('../../', import.meta.url))];
const password = Uint8Array.from({ length: 76 }, (_, i) => (41 + 131 * i) & 255).subarray(1, 74);
const salt = Uint8Array.from({ length: 27 }, (_, i) => (71 + 11 * i) & 255).subarray(2, 25);
const samples = 11;
const length = 64;
const maxmem = 64 * 1024 * 1024;
let checksum = 0;

const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');

function time(run, calls) {
  const start = performance.now();
  for (let i = 0; i < calls; i += 1) {
    checksum = (Math.imul(checksum, 31) + run()[0]) | 0;
  }
  return (performance.now() - start) * 1000 / calls;
}

function statistics(values) {
  const sorted = values.toSorted((a, b) => a - b);
  return { median: sorted[samples >>> 1], min: sorted[0], max: sorted.at(-1), samples: values };
}

const sources = roots.map(() => ({}));
const results = [];
for (const [language, extension] of [['javascript', 'mjs'], ['typescript', 'mts']]) {
  const entry = `src/crypto/kdf/scrypt/impl/${language}/scrypt.${extension}`;
  const paths = [entry, `src/crypto/kdf/pbkdf2-hmac-sha256/impl/${language}/pbkdf2.${extension}`,
    `src/crypto/mac/hmac-sha256/impl/${language}/hmac.${extension}`,
    `src/crypto/hash/sha256/impl/${language}/sha256.${extension}`, `src/crypto/inputs/bytes.${extension}`];
  for (const [index, root] of roots.entries()) {
    for (const path of paths) sources[index][path] = digest(resolve(root, path));
  }
  const modules = await Promise.all(roots.map(root => import(pathToFileURL(resolve(root, entry)).href)));
  for (const [cost, blockSize, parallel, calls] of [[16, 2, 3, 128], [1024, 8, 1, 16], [512, 32, 2, 4]]) {
    const memoryLimit = modules[0].workspaceSize(cost, blockSize, parallel) + length;
    assert.equal(modules[1].workspaceSize(cost, blockSize, parallel) + length, memoryLimit);
    const settings = { cost, blockSize, parallel, length, memoryLimit };
    const oracle = () => scryptSync(password, salt, length, { N: cost, r: blockSize, p: parallel, maxmem });
    const expected = oracle();
    const methods = modules.map(sdk => () => sdk.derive(password, salt, settings));
    for (const method of methods) assert.deepEqual(Buffer.from(method()), expected);
    methods.push(oracle);
    for (const method of methods) time(method, 3 * calls);
    const timings = methods.map(() => []);
    for (let sample = 0; sample < samples; sample += 1) {
      const first = sample & 1;
      const pair = [first, 1 - first];
      const order = sample % 3 === 0 ? [2, ...pair] : [...pair, 2];
      for (const index of order) timings[index].push(time(methods[index], calls));
    }
    const [baseline, candidate, nodeOpenSSL] = timings.map(statistics);
    results.push({ language, ...settings, calls, baseline, candidate, nodeOpenSSL });
  }
}

console.log(JSON.stringify({
  node: process.version, openssl: process.versions.openssl, cpu: cpus()[0].model,
  platform: process.platform, release: release(), arch: process.arch, units: 'microseconds per operation',
  runnerSha256: digest(fileURLToPath(import.meta.url)), samples, checksum,
  baselineSources: sources[0], candidateSources: sources[1], results,
}, null, 2));
