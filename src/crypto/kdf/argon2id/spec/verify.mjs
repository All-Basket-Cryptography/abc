import { spawnSync } from 'node:child_process';
import { argon2Sync } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../../../../', import.meta.url));
let seed = 0x09106013;

function bytes(size) {
  return Buffer.from(Array.from({ length: size }, () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed >>> 24;
  }));
}

const cases = [];

function add(parallelism, memory, passes, tagLength, index) {
  const message = bytes([0, 1, 31, 32, 129][index % 5]);
  const nonce = bytes([8, 16, 32][index % 3]);
  const secret = bytes([0, 1, 8, 65][index % 4]);
  const associatedData = bytes([12, 0, 1, 129][index % 4]);
  cases.push({ memory, passes, parallelism, tagLength, message, nonce, secret, associatedData });
}

for (const parallelism of [1, 2, 3, 4]) {
  for (const segmentBlocks of [2, 3, 4, 7, 11]) {
    for (const tagLength of [4, 16, 32, 64, 65]) {
      const index = cases.length;
      // Odd requested memory exercises rounding; H0 still receives the original value.
      add(parallelism, 4 * parallelism * segmentBlocks + index % (4 * parallelism),
        1 + index % 4, tagLength, index);
    }
  }
}

for (const [index, tagLength] of [33, 63, 64, 65, 96, 97, 128, 129, 257].entries()) {
  const parallelism = 1 + index % 3;
  // Cross the 128-word batch boundary in Argon2i-style indexing.
  const segmentBlocks = [127, 128, 129][Math.floor(index / 3)];
  add(parallelism, 4 * parallelism * segmentBlocks, 1 + index % 3, tagLength, index);
}

const rfc = {
  memory: 32, passes: 3, parallelism: 4, tagLength: 32,
  message: Buffer.alloc(32, 1), nonce: Buffer.alloc(16, 2),
  secret: Buffer.alloc(8, 3), associatedData: Buffer.alloc(12, 4),
};
cases.push(rfc);
const rfcTag = '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659';

function oracle(test) {
  const { secret, associatedData, ...inputs } = test;
  if (secret.length !== 0) inputs.secret = secret;
  if (associatedData.length !== 0) inputs.associatedData = associatedData;
  return argon2Sync('argon2id', inputs).toString('hex');
}

if (oracle(rfc) !== rfcTag) {
  throw new Error('Node/OpenSSL disagree with RFC 9106 §5.3');
}

function encode({ memory, passes, parallelism, tagLength, message, nonce, secret, associatedData }) {
  return [memory, passes, parallelism, tagLength, message.toString('hex'), nonce.toString('hex'),
    secret.toString('hex'), associatedData.toString('hex')].join(':');
}

const child = spawnSync('cargo', [
  '+1.92.0', 'run', '--manifest-path', 'tools/build/rust/Cargo.toml', '--release', '--locked', '--offline',
  '--quiet', '-p', 'abc-argon2id', '--example', 'differential',
], { cwd: root, encoding: 'utf8', input: cases.map(encode).join('\n') + '\n',
  timeout: 120_000, maxBuffer: 4 * 1024 * 1024 });
if (child.status !== 0) {
  throw new Error(child.error?.message || child.stderr || 'Rust test program failed');
}
const actual = child.stdout.trim().split(/\r?\n/);
if (actual.length !== cases.length) throw new Error('Incorrect result count from Rust');
for (const [index, test] of cases.entries()) {
  if (actual[index] !== oracle(test)) {
    const { memory, passes, parallelism, tagLength } = test;
    throw new Error('Argon2id disagreement: ' + JSON.stringify({ index, memory, passes, parallelism, tagLength }));
  }
}
console.log(JSON.stringify({
  status: 'passed', cases: cases.length, rfc_9106_5_3: 'passed',
  node: process.version, openssl: process.versions.openssl, platform: process.platform, arch: process.arch,
}));
