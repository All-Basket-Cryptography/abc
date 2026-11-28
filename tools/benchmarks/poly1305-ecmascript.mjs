import assert from 'node:assert/strict';
import { createCipheriv, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { cpus, release } from 'node:os';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';

if (process.argv.length !== 3) throw new Error('Pass an archived baseline root or checkout');
const roots = [resolve(process.argv[2]), fileURLToPath(new URL('../../', import.meta.url))];
const key = Uint8Array.from({ length: 32 }, (_, i) => (41 + 131 * i) & 255);
const nonce = Uint8Array.of(7, 22, 32, 15, 99, 10, 135, 250, 241, 5, 7, 207);
const aad = Uint8Array.from({ length: 27 }, (_, i) => (71 + 11 * i) & 255);
const samples = 11;
let checksum = 0;

const digest = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

function littleEndian(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) + BigInt(bytes[i]);
  return value;
}

function poly1305(message) {
  const r = littleEndian(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const p = (1n << 130n) - 5n;
  let h = 0n;
  for (let offset = 0; offset < message.length; offset += 16) {
    const block = message.subarray(offset, offset + 16);
    h = ((h + littleEndian(block) + (1n << BigInt(8 * block.length))) * r) % p;
  }
  const tag = h + littleEndian(key.subarray(16));
  return Buffer.from(Array.from({ length: 16 }, (_, i) => Number((tag >> BigInt(8 * i)) & 255n)));
}

function openSsl(message) {
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: message.length });
  const ciphertext = Buffer.concat([cipher.update(message), cipher.final()]);
  return { ciphertext, tag: cipher.getAuthTag() };
}

function time(run, calls) {
  const start = performance.now();
  for (let i = 0; i < calls; i += 1) {
    const out = run();
    checksum = (Math.imul(checksum, 31) + (out instanceof Uint8Array ? out[0] : out.tag[0])) | 0;
  }
  return (performance.now() - start) * 1000 / calls;
}

function statistics(values) {
  const sorted = values.toSorted((x, y) => x - y);
  return { median: sorted[samples >>> 1], min: sorted[0], max: sorted.at(-1), samples: values };
}

const sources = roots.map(() => ({}));
const results = [];
for (const [language, extension] of [['javascript', 'mjs'], ['typescript', 'mts']]) {
  const mac = `src/crypto/mac/poly1305/impl/${language}/poly1305.${extension}`;
  const aead = `src/crypto/aead/chacha20-poly1305/impl/${language}/chacha20poly1305.${extension}`;
  for (const [index, root] of roots.entries()) {
    for (const path of [mac, aead, `src/crypto/cipher/chacha20/impl/${language}/chacha20.${extension}`,
      `src/crypto/inputs/bytes.${extension}`]) sources[index][path] = digest(resolve(root, path));
  }
  for (const [profile, path] of [['poly1305', mac], ['chacha20-poly1305', aead]]) {
    const modules = await Promise.all(roots.map(root => import(pathToFileURL(resolve(root, path)).href)));
    for (const [size, calls] of [[0, 2048], [17, 2048], [1024, 768], [16387, 64]]) {
      const message = new Uint8Array(size + 2).subarray(1, size + 1);
      for (let i = 0; i < message.length; i += 1) message[i] = (137 * i) ^ (i >>> 5);
      const seal = profile === 'chacha20-poly1305';
      const methods = seal ? modules.map(sdk => () => sdk.seal(key, nonce, aad, message))
        : modules.map(sdk => () => sdk.authenticate(key, message));
      if (seal) {
        const oracle = () => openSsl(message);
        const expected = oracle();
        for (const method of methods) {
          const { ciphertext, tag } = method();
          assert.deepEqual(Buffer.from(ciphertext), expected.ciphertext);
          assert.deepEqual(Buffer.from(tag), expected.tag);
        }
        methods.push(oracle);
      } else {
        const expected = poly1305(message);
        for (const method of methods) assert.deepEqual(Buffer.from(method()), expected);
      }
      for (const method of methods) time(method, 3 * calls);
      const timings = methods.map(() => []);
      for (let sample = 0; sample < samples; sample += 1) {
        const first = sample & 1;
        const pair = [first, 1 - first];
        const order = seal ? (sample % 3 === 0 ? [2, ...pair] : [...pair, 2]) : pair;
        for (const index of order) timings[index].push(time(methods[index], calls));
      }
      const [baseline, candidate, nodeOpenSSL] = timings.map(statistics);
      results.push({ profile, language, size, calls, baseline, candidate, nodeOpenSSL });
    }
  }
}

console.log(JSON.stringify({
  node: process.version, openssl: process.versions.openssl, cpu: cpus()[0].model,
  platform: process.platform, release: release(), arch: process.arch, units: 'microseconds per operation',
  runnerSha256: digest(fileURLToPath(import.meta.url)), samples, checksum,
  baselineSources: sources[0], candidateSources: sources[1], results,
}, null, 2));
