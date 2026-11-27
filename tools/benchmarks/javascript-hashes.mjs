import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cpus } from 'node:os';
import { sha512 as jsSha512 } from '../../src/crypto/hash/sha512/impl/javascript/sha512.mjs';
import { sha512 as tsSha512 } from '../../src/crypto/hash/sha512/impl/typescript/sha512.mts';
import { sha3_256 as jsSha3 } from '../../src/crypto/hash/sha3-256/impl/javascript/sha3_256.mjs';
import { sha3_256 as tsSha3 } from '../../src/crypto/hash/sha3-256/impl/typescript/sha3_256.mts';
import { shake256 as jsShake } from '../../src/crypto/hash/shake256/impl/javascript/shake256.mjs';
import { shake256 as tsShake } from '../../src/crypto/hash/shake256/impl/typescript/shake256.mts';

const methods = [
  ['sha512', jsSha512, tsSha512],
  ['sha3-256', jsSha3, tsSha3],
  ['shake256', input => jsShake(input, 32), input => tsShake(input, 32)],
];
let checksum = 0;

function medianNs(hash, input) {
  const batches = 9;
  const iterations = 96;
  for (let i = 0; i < 384; i += 1) checksum ^= hash(input)[0];
  const samples = [];
  for (let batch = 0; batch < batches; batch += 1) {
    const start = process.hrtime.bigint();
    for (let i = 0; i < iterations; i += 1) checksum ^= hash(input)[0];
    samples.push(Number(process.hrtime.bigint() - start) / iterations);
  }
  samples.sort((a, b) => a - b);
  return Math.round(samples[batches >>> 1]);
}

const results = [];
for (const [name, js, ts] of methods) {
  const reference = input => createHash(name, name === 'shake256' ? { outputLength: 32 } : {})
    .update(input).digest();
  for (const size of [64, 4096]) {
    const input = Uint8Array.from({ length: size }, (_, index) => (index * 137) ^ (index >>> 5));
    const expected = reference(input);
    assert.deepEqual(Buffer.from(js(input)), expected);
    assert.deepEqual(Buffer.from(ts(input)), expected);
    results.push({ hash: name, bytes: size, jsNs: medianNs(js, input), tsNs: medianNs(ts, input),
      opensslNs: medianNs(reference, input) });
  }
}
console.log(JSON.stringify({
  node: process.version, openssl: process.versions.openssl,
  cpu: cpus()[0].model, platform: process.platform, arch: process.arch,
  results, checksum,
}, null, 2));
