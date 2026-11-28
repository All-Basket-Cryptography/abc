import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import { cpus } from 'node:os';
import { seal as sealJs } from './aes256gcm.mjs';
import { seal as sealTs } from '../typescript/aes256gcm.mts';

const key = new Uint8Array(32);
const nonce = new Uint8Array(12);
const aad = new Uint8Array(16);
const data = new Uint8Array(4096);

function openssl() {
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  return { ciphertext, tag: cipher.getAuthTag() };
}

const expected = openssl();
const samples = [];
const warmup = 50;
const calls = 100;
const repeats = 5;
for (const [implementation, seal] of [
  ['JavaScript', () => sealJs(key, nonce, aad, data)],
  ['TypeScript', () => sealTs(key, nonce, aad, data)],
  ['Node/OpenSSL', openssl],
]) {
  const known = seal();
  assert.deepEqual(Buffer.from(known.ciphertext), expected.ciphertext);
  assert.deepEqual(Buffer.from(known.tag), expected.tag);
  for (let i = 0; i < warmup; i += 1) seal();
  const durations = [];
  for (let trial = 0; trial < repeats; trial += 1) {
    const start = process.hrtime.bigint();
    for (let i = 0; i < calls; i += 1) seal();
    durations.push(Number(process.hrtime.bigint() - start) / (1000 * calls));
  }
  durations.sort((a, b) => a - b);
  samples.push({ implementation, medianMicroseconds: durations[2] });
}

console.log(JSON.stringify({
  cpu: cpus()[0]?.model, platform: process.platform, arch: process.arch,
  node: process.versions.node, openssl: process.versions.openssl,
  messageBytes: data.length, aadBytes: aad.length, warmup, calls, repeats, samples,
}, null, 2));
