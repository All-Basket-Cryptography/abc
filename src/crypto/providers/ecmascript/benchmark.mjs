import assert from 'node:assert/strict';
import { arch, platform, cpus } from 'node:os';
import { performance } from 'node:perf_hooks';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import * as abcX25519 from '../../agreement/x25519/impl/javascript/x25519.mjs';
import * as abcEd25519 from '../../signature/ed25519/impl/javascript/ed25519.mjs';

const seed = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const peer = x25519.getPublicKey(Uint8Array.from(seed, value => value + 2));
const message = new Uint8Array(1024).fill(0x42);
const publicKey = ed25519.getPublicKey(seed);
const signature = ed25519.sign(message, seed);
const workloads = [
  ['X25519 shared secret', () => abcX25519.sharedSecret(seed, peer), () => x25519.getSharedSecret(seed, peer)],
  ['Ed25519 sign 1024 bytes', () => abcEd25519.sign(seed, message), () => ed25519.sign(message, seed)],
  ['Ed25519 verify 1024 bytes', () => abcEd25519.verify(publicKey, message, signature),
    () => ed25519.verify(signature, message, publicKey, { zip215: false })],
];

function sample(operation, count) {
  const start = performance.now();
  for (let i = 0; i < count; i += 1) operation();
  return (performance.now() - start) * 1000 / count;
}

function summarize(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const round = value => Math.round(value * 10) / 10;
  return { median: round(sorted[2]), min: round(sorted[0]), max: round(sorted[4]) };
}

const warmup = 100;
const count = 300;
const results = workloads.map(([name, sdk, noble]) => {
  const actual = sdk(), expected = noble();
  if (typeof actual === 'boolean') assert.equal(actual, expected, name);
  else assert.deepEqual(Buffer.from(actual), Buffer.from(expected), name);
  sample(sdk, warmup);
  sample(noble, warmup);
  const times = [[], []];
  const operations = [sdk, noble];
  for (let round = 0; round < 5; round += 1) {
    for (const index of round % 2 ? [1, 0] : [0, 1]) {
      times[index].push(sample(operations[index], count));
    }
  }
  return { name, sdk: summarize(times[0]), noble: summarize(times[1]) };
});
console.log(JSON.stringify({
  platform: platform(), architecture: arch(), cpu: cpus()[0]?.model,
  node: process.version, openssl: process.versions.openssl,
  unit: 'microseconds per operation', warmup, sampleSize: count, samples: 5, results,
}, null, 2));
