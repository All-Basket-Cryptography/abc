import assert from 'node:assert/strict';
import { createHash, createHmac, hkdfSync, pbkdf2Sync, scryptSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { cpus, release } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';

const baselinePath = process.argv[2];
if (!baselinePath) throw new Error('Pass a checkout containing the baseline src/crypto tree');
const roots = [resolve(baselinePath), fileURLToPath(new URL('../../', import.meta.url))];
const implementations = {
  hash: 'hash/sha256/impl/*/sha256', hmac: 'mac/hmac-sha256/impl/*/hmac',
  hkdf: 'kdf/hkdf-sha256/impl/*/hkdf', pbkdf2: 'kdf/pbkdf2-hmac-sha256/impl/*/pbkdf2',
  scrypt: 'kdf/scrypt/impl/*/scrypt',
};

const bytes = (length, seed) => Uint8Array.from({ length }, (_, i) => (i * 137 + seed) ^ (i >>> 5));
const input = bytes(1024, 43);
const key = bytes(32, 79);
const salt = bytes(16, 107);
const info = bytes(24, 139);
const messages = [bytes(0, 0), bytes(32, 37), bytes(55, 67), bytes(120, 97)];
const hmac = (message) => createHmac('sha256', key).update(message).digest();
const scrypt = { cost: 1024, blockSize: 1, parallel: 1, length: 32, memoryLimit: 256 * 1024 };
const workloads = [
  { profile: 'sha256', shape: 'one-shot, 1024 B', calls: 768,
    setup: ({ hash }) => () => hash.sha256(input), oracle: () => createHash('sha256').update(input).digest() },
  { profile: 'hmac-sha256', shape: 'one-shot, 32 B key, 32 B message', calls: 768,
    setup: ({ hmac }) => () => hmac.authenticate(key, messages[1]), oracle: () => hmac(messages[1]) },
  { profile: 'hmac-sha256', shape: 'same 32 B key, reset, cycle message sizes 0/32/55/120 B', calls: 768,
    setup: ({ hmac }) => {
      const state = new hmac.HmacSha256(key);
      return (i) => state.reset().update(messages[i % messages.length]).digest();
    }, oracle: (i) => hmac(messages[i % messages.length]) },
  { profile: 'hkdf-sha256', shape: 'extract and expand, 128 B output (four blocks)', calls: 768,
    setup: ({ hkdf }) => () => hkdf.derive(salt, key, info, 128),
    oracle: () => new Uint8Array(hkdfSync('sha256', key, salt, info, 128)) },
  { profile: 'pbkdf2-hmac-sha256', shape: '2048 iterations, 32 B output', calls: 24,
    setup: ({ pbkdf2 }) => () => pbkdf2.derive(key, salt, 2048, 32),
    oracle: () => pbkdf2Sync(key, salt, 2048, 32, 'sha256') },
  { profile: 'scrypt', shape: 'N=1024, r=1, p=1, 32 B output', calls: 24,
    setup: ({ scrypt: module }) => () => module.derive(key, salt, scrypt),
    oracle: () => scryptSync(key, salt, 32, { N: 1024, r: 1, p: 1 }) },
];
const samples = 11;
let checksum = 0;

function time(run, calls) {
  const started = performance.now();
  for (let i = 0; i < calls; i += 1) checksum = (Math.imul(checksum, 31) + run(i)[0]) | 0;
  return (performance.now() - started) * 1000 / calls;
}

function stats(result) {
  const sorted = result.toSorted((a, b) => a - b);
  return { median: sorted[samples >>> 1], min: sorted[0], max: sorted.at(-1), samples: result };
}

function digest(root, path) {
  return createHash('sha256').update(readFileSync(join(root, path))).digest('hex');
}

const results = [];
const fingerprints = roots.map(() => ({}));
for (const [language, extension] of [['javascript', 'mjs'], ['typescript', 'mts']]) {
  const paths = Object.entries(implementations).map(([name, path]) =>
    [name, `src/crypto/${path.replace('*', language)}.${extension}`]);
  const variants = await Promise.all(roots.map(async (root, version) => {
    const owned = [...paths.map(([, path]) => path), `src/crypto/inputs/bytes.${extension}`];
    for (const path of owned) fingerprints[version][path] = digest(root, path);
    return Object.fromEntries(await Promise.all(paths.map(async ([name, path]) =>
      [name, await import(pathToFileURL(join(root, path)).href)])));
  }));

  for (const { profile, shape, calls, setup, oracle } of workloads) {
    const implementations = variants.map(setup);
    for (let i = 0; i < messages.length; i += 1) {
      for (const method of implementations) assert.deepEqual(Buffer.from(method(i)), Buffer.from(oracle(i)));
    }
    const methods = [...implementations, oracle];
    const warmupCalls = 3 * calls;
    for (const method of methods) time(method, warmupCalls);
    const timings = methods.map(() => []);
    for (let sample = 0; sample < samples; sample += 1) {
      const first = sample & 1;
      const order = sample % 3 === 0 ? [2, first, 1 - first] : [first, 1 - first, 2];
      for (const index of order) timings[index].push(time(methods[index], calls));
    }
    results.push({ language, profile, shape, calls, warmupCalls,
      baseline: stats(timings[0]), candidate: stats(timings[1]), nodeOpenSSL: stats(timings[2]) });
  }
}

console.log(JSON.stringify({
  node: process.version, openssl: process.versions.openssl, cpu: cpus()[0].model,
  platform: process.platform, osRelease: release(), arch: process.arch, units: 'microseconds per operation',
  baselineSources: fingerprints[0], candidateSources: fingerprints[1], samples, checksum, results,
}, null, 2));
