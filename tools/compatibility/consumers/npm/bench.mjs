import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { createSha256Provider } from 'abc-cryptography-research';

const started = performance.now();
const provider = await createSha256Provider();
const initializationMs = performance.now() - started;
const engines = {
  wasm: bytes => provider.digest(bytes),
  openssl: bytes => createHash('sha256').update(bytes).digest(),
};

function sample(digest, input, iterations) {
  let checksum = 0;
  const start = performance.now();
  for (let index = 0; index < iterations; index++) checksum ^= digest(input)[0];
  return { ms: +(performance.now() - start).toFixed(3), checksum };
}

const workloads = [];
for (const [size, iterations] of [[32, 5000], [4096, 2000], [1048576, 12]]) {
  const input = Uint8Array.from({ length: size }, (_, index) => index % 251);
  const samples = {};
  for (const [name, digest] of Object.entries(engines)) {
    sample(digest, input, Math.min(iterations, 500));
    samples[name] = Array.from({ length: 5 }, () => sample(digest, input, iterations).ms);
  }
  workloads.push({ size, iterations, samples });
}

console.log(JSON.stringify({ node: process.version, openssl: process.versions.openssl, platform: process.platform,
  architecture: process.arch, initialization_ms: +initializationMs.toFixed(3), workloads }));
