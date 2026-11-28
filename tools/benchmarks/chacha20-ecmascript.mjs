import assert from 'node:assert/strict';
import { createCipheriv, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { cpus, release } from 'node:os';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';

if (process.argv.length !== 3) throw new Error('Pass an archived baseline root or checkout');
const roots = [resolve(process.argv[2]), fileURLToPath(new URL('../../', import.meta.url))];
const languages = [['javascript', 'mjs'], ['typescript', 'mts']];
const streamPath = 'src/crypto/cipher/chacha20/impl';
const aeadPath = 'src/crypto/aead/chacha20-poly1305/impl';
const macPath = 'src/crypto/mac/poly1305/impl';
const inputsPath = 'src/crypto/inputs';
const fixtures = [[67, 1024], [1024, 768], [16387, 64]];
const samples = 11;
const key = Uint8Array.from({ length: 32 }, (_, i) => (19 + 7 * i) & 255);
const nonce = Uint8Array.of(7, 22, 32, 15, 99, 10, 135, 250, 241, 5, 7, 207);
const aad = Uint8Array.from({ length: 27 }, (_, i) => (71 + 11 * i) & 255);
const counter = 1;
const iv = Buffer.alloc(16);
iv.writeUInt32LE(counter);
iv.set(nonce, 4);
let checksum = 0;

function hashSources(root, files) {
  return Object.fromEntries(files.map((path) => [path,
    createHash('sha256').update(readFileSync(resolve(root, path))).digest('hex')]));
}

function oracle(profile, message) {
  if (profile === 'chacha20') {
    const cipher = createCipheriv('chacha20', key, iv);
    return Buffer.concat([cipher.update(message), cipher.final()]);
  }
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: message.length });
  const ciphertext = Buffer.concat([cipher.update(message), cipher.final()]);
  return { ciphertext, tag: cipher.getAuthTag() };
}

function normalize(result) {
  return result instanceof Uint8Array ? Buffer.from(result) : Buffer.concat([result.ciphertext, result.tag]);
}

function time(run, calls) {
  const start = performance.now();
  for (let index = 0; index < calls; index += 1) {
    const output = run();
    const first = output instanceof Uint8Array ? output[0] : output.ciphertext[0] ^ output.tag[0];
    checksum = (Math.imul(checksum, 31) + first) | 0;
  }
  return (performance.now() - start) * 1000 / calls;
}

function statistics(values) {
  const sorted = values.toSorted((left, right) => left - right);
  return { median: sorted[samples >>> 1], min: sorted[0], max: sorted.at(-1), samples: values };
}

const results = [];
const sources = roots.map(() => ({}));
for (const [language, extension] of languages) {
  const stream = `${streamPath}/${language}/chacha20.${extension}`;
  const aead = `${aeadPath}/${language}/chacha20poly1305.${extension}`;
  for (const [index, root] of roots.entries()) {
    Object.assign(sources[index], hashSources(root, [stream, aead, `${macPath}/${language}/poly1305.${extension}`,
      `${inputsPath}/bytes.${extension}`]));
  }
  for (const [profile, path] of [['chacha20', stream], ['chacha20-poly1305', aead]]) {
    const implementations = await Promise.all(roots.map((root) => import(pathToFileURL(resolve(root, path)).href)));
    for (const [size, calls] of fixtures) {
      const message = new Uint8Array(size + 2).subarray(1, size + 1);
      for (let i = 0; i < message.length; ++i) message[i] = (i * 137) ^ (i >>> 5);
      const methods = implementations.map((implementation) => {
        if (profile === 'chacha20-poly1305') return () => implementation.seal(key, nonce, aad, message);
        const out = new Uint8Array(size + 2).subarray(1, size + 1);
        return () => {
          out.set(message);
          return implementation.applyKeystream(key, nonce, counter, out);
        };
      });
      const provider = () => oracle(profile, message);
      const expected = normalize(provider());
      for (const method of methods) assert.deepEqual(normalize(method()), expected);
      const runs = [...methods, provider];
      for (const run of runs) time(run, 3 * calls);
      const readings = runs.map(() => []);
      for (let sample = 0; sample < samples; ++sample) {
        const first = sample & 1;
        const order = sample % 3 === 0 ? [2, first, 1 - first] : [first, 1 - first, 2];
        for (const index of order) readings[index].push(time(runs[index], calls));
      }
      const [baseline, candidate, nodeOpenSSL] = readings.map(statistics);
      results.push({ profile, language, size, calls, baseline, candidate, nodeOpenSSL });
    }
  }
}

console.log(JSON.stringify({
  node: process.version, openssl: process.versions.openssl, cpu: cpus()[0].model,
  platform: process.platform, release: release(), arch: process.arch, units: 'microseconds per operation',
  runnerSha256: createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex'),
  samples, checksum, baselineSources: sources[0], candidateSources: sources[1], results,
}, null, 2));
