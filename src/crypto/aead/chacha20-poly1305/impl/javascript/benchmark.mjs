import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import { cpus } from 'node:os';
import { seal as sealJs } from './chacha20poly1305.mjs';
import { seal as sealTs } from '../typescript/chacha20poly1305.mts';

const key = new Uint8Array(32);
const nonce = new Uint8Array(12);
const aad = new Uint8Array(16);
const input = new Uint8Array(4096);

function openssl() {
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
  return { ciphertext, tag: cipher.getAuthTag() };
}

const expected = openssl();
const implementations = [
  ['JavaScript', () => sealJs(key, nonce, aad, input)],
  ['TypeScript', () => sealTs(key, nonce, aad, input)],
  ['Node/OpenSSL', openssl],
];
const iterations = 1000;
const runs = 7;
const results = [];
for (const [name, seal] of implementations) {
  const initial = seal();
  assert.deepEqual(Buffer.from(initial.ciphertext), expected.ciphertext);
  assert.deepEqual(Buffer.from(initial.tag), expected.tag);
  for (let i = 0; i < iterations; i += 1) seal();
  const samples = [];
  for (let trial = 0; trial < runs; trial += 1) {
    const start = process.hrtime.bigint();
    for (let i = 0; i < iterations; i += 1) seal();
    samples.push(Number(process.hrtime.bigint() - start) / iterations / 1000);
  }
  samples.sort((a, b) => a - b);
  results.push({ implementation: name, medianMicroseconds: samples[(runs - 1) / 2] });
}

console.log(JSON.stringify({
  cpu: cpus()[0]?.model, platform: process.platform, arch: process.arch,
  node: process.versions.node, openssl: process.versions.openssl,
  bytes: input.length, aadBytes: aad.length, iterations, runs, results,
}, null, 2));
