import { spawnSync } from 'node:child_process';
import { createCipheriv } from 'node:crypto';
import { cpus, arch, platform } from 'node:os';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const methods = ['aes-256-gcm', 'chacha20-poly1305'];
const cargo = ['+1.92.0', 'run', '--release', '--quiet', '--offline', '--locked',
  '--manifest-path', 'tools/compatibility/portable-aead/Cargo.toml'];

function run(input = '', args = []) {
  const child = spawnSync('cargo', [...cargo, ...args], {
    cwd: root, encoding: 'utf8', input, timeout: 110000, maxBuffer: 4 * 1024 * 1024,
  });
  if (child.status !== 0) throw new Error(child.error?.message || child.stderr || 'Rust test program failed');
  return child.stdout.trim().split(/\r?\n/);
}

function seal(name, key, nonce, aad, message) {
  const cipher = createCipheriv(name, key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(message), cipher.final(), cipher.getAuthTag()]);
}

let seed = 0x8439197;
function bytes(size) {
  return Buffer.from(Array.from({ length: size }, () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) | 0;
    return seed >>> 24;
  }));
}

const cases = [];
for (const name of methods) {
  for (const message of [0, 1, 15, 16, 17, 63, 64, 65, 129]) {
    for (const aad of [0, 1, 15, 16, 17, 65]) {
      cases.push([name, bytes(32), bytes(12), bytes(aad), bytes(message)]);
    }
  }
  for (let i = 0; i < 120; i += 1) {
    cases.push([name, bytes(32), bytes(12), bytes(i % 39), bytes((i * 169) % 257)]);
  }
}
const encoded = cases.map(([name, ...values]) => [name, ...values.map(value => value.toString('hex'))].join(':'));
const candidate = run(encoded.join('\n') + '\n');
if (candidate.length !== cases.length) throw new Error('Incorrect case count from Rust');
for (let i = 0; i < cases.length; i += 1) {
  if (seal(...cases[i]).toString('hex') !== candidate[i]) throw new Error(`Mismatch in ${cases[i][0]} case ${i}`);
}
console.log(`Rust AES-256-GCM and ChaCha20-Poly1305 matched Node/OpenSSL for ${cases.length} cases`);

if (process.argv.includes('--benchmark')) {
  const [cpu] = cpus();
  console.log(JSON.stringify({ platform: platform(), arch: arch(), cpu: cpu.model,
    node: process.version, openssl: process.versions.openssl }));
  for (const row of run('', ['--', '--benchmark'])) console.log(`Rust ns/op: ${row}`);
  let lastOutput;
  let counter = 0;
  const key = Buffer.alloc(32);
  const nonce = Buffer.alloc(12);
  const aad = Buffer.alloc(16);
  for (const name of methods) {
    for (const length of [64, 4096]) {
      const input = Buffer.alloc(length, 0x43);
      const samples = [];
      for (let trial = 0; trial < 10; trial += 1) {
        const start = process.hrtime.bigint();
        for (let i = 0; i < 64; i += 1) {
          counter += 1;
          nonce.writeUInt32BE(counter, 8);
          lastOutput = seal(name, key, nonce, aad, input);
        }
        if (trial > 0) samples.push(Number((process.hrtime.bigint() - start) / 64n));
      }
      samples.sort((a, b) => a - b);
      console.log(`Node/OpenSSL ns/op: ${name} ${length} ${samples[4]} [${samples}]`);
    }
  }
  if (lastOutput.length !== 4112) throw new Error('Incorrect benchmark output size');
}
