import { spawnSync } from 'node:child_process';
import { argon2Sync } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const work = fileURLToPath(new URL('.', import.meta.url));
const cases = [];
let seed = 0x09106013;

function data(length) {
  const output = Buffer.alloc(length);
  for (let i = 0; i < length; i += 1) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    output[i] = seed >>> 24;
  }
  return output;
}

function add(memory, passes, parallelism, tagLength) {
  const i = cases.length;
  const test = { memory, passes, parallelism, tagLength,
    message: data([0, 1, 31, 32, 129][i % 5]),
    nonce: data([8, 16, 32][i % 3]),
  };
  if (i % 4 !== 0) test.secret = data([0, 1, 8, 65][i % 4]);
  if (i % 4 !== 0) test.associatedData = data([0, 1, 12, 129][i % 4]);
  cases.push(test);
}

for (const lanes of [1, 2, 3, 4]) {
  for (const segment of [2, 3, 4, 7, 11]) {
    for (const tag of [4, 16, 32, 64, 65]) {
      add(4 * lanes * segment + (cases.length % (4 * lanes)), 1 + (cases.length % 4), lanes, tag);
    }
  }
}

for (let i = 0; i < 9; i += 1) {
  const lanes = 1 + (i % 3);
  add(4 * lanes * (127 + Math.floor(i / 3)), 1 + (i % 3), lanes,
    [33, 63, 64, 65, 96, 97, 128, 129, 257][i]);
}

const rfc = {
  memory: 32, passes: 3, parallelism: 4, tagLength: 32,
  message: Buffer.alloc(32, 1), nonce: Buffer.alloc(16, 2),
  secret: Buffer.alloc(8, 3), associatedData: Buffer.alloc(12, 4),
};
cases.push(rfc);
const want = cases.map(test => argon2Sync('argon2id', test).toString('hex'));
if (want.at(-1) !== '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659') {
  throw new Error('reference disagrees with RFC 9106 §5.3');
}

function encode(test) {
  return [test.memory, test.passes, test.parallelism, test.tagLength, test.message.toString('hex'),
    test.nonce.toString('hex'), test.secret?.toString('hex') ?? '',
    test.associatedData?.toString('hex') ?? ''].join(':');
}

const child = spawnSync('go', ['run', './internal/differential'], {
  cwd: work, encoding: 'utf8', input: cases.map(encode).join('\n') + '\n',
  env: { ...process.env, GOPROXY: 'off', CGO_ENABLED: '0' }, timeout: 120_000,
});
if (child.status !== 0) throw new Error(child.error?.message || child.stderr || 'Go differential runner failed');
const got = child.stdout.trim().split(/\r?\n/);
if (got.length !== want.length) throw new Error('Go differential runner returned the wrong number of cases');
for (const [i, value] of want.entries()) {
  if (got[i] !== value) throw new Error(`Go disagrees with Node/OpenSSL at case ${i}`);
}
console.log(JSON.stringify({
  status: 'passed', cases: cases.length, node: process.version,
  openssl: process.versions.openssl, platform: process.platform, arch: process.arch,
}));
