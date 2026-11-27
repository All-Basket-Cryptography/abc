import { spawnSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const work = fileURLToPath(new URL('.', import.meta.url));
const privatePrefix = Buffer.from('302e020100300506032b657004220420', 'hex');
const publicPrefix = Buffer.from('302a300506032b6570032100', 'hex');
let state = 0x80320017;

function data(length) {
  const bytes = Buffer.alloc(length);
  for (let i = 0; i < length; i += 1) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    bytes[i] = state >>> 24;
  }
  return bytes;
}

const tests = Array.from({ length: 96 }, (_, index) => {
  const seed = data(32);
  const message = data([0, 1, 31, 63, 64, 127, 128, 255, 256, 4096][index % 10]);
  const privateKey = createPrivateKey({
    key: Buffer.concat([privatePrefix, seed]), format: 'der', type: 'pkcs8',
  });
  const publicDER = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const publicRaw = publicDER.subarray(publicPrefix.length);
  if (publicRaw.length !== 32 || !publicDER.subarray(0, publicPrefix.length).equals(publicPrefix)) {
    throw new Error('unexpected OpenSSL Ed25519 public-key encoding');
  }
  return { seed, message, publicRaw, signature: sign(null, message, privateKey) };
});

const lines = tests.map(test => [test.seed, test.message, test.signature].map(x => x.toString('hex')).join(':'));
const child = spawnSync('go', ['run', './internal/differential'], {
  cwd: work, encoding: 'utf8', input: lines.join('\n') + '\n',
  env: { ...process.env, CGO_ENABLED: '0' }, timeout: 100_000,
});
if (child.status !== 0) throw new Error(child.error?.message || child.stderr || 'Go runner failed');
const outputs = child.stdout.trim().split(/\r?\n/);
if (outputs.length !== tests.length) throw new Error('unexpected Ed25519 case count');

for (const [i, test] of tests.entries()) {
  const [publicHex, signatureHex] = outputs[i].split(':');
  const publicRaw = Buffer.from(publicHex, 'hex');
  const signature = Buffer.from(signatureHex, 'hex');
  if (!publicRaw.equals(test.publicRaw) || !signature.equals(test.signature)) {
    throw new Error(`Go/OpenSSL Ed25519 mismatch at case ${i}`);
  }
  const publicKey = createPublicKey({
    key: Buffer.concat([publicPrefix, publicRaw]), format: 'der', type: 'spki',
  });
  if (!verify(null, test.message, publicKey, signature)) {
    throw new Error(`OpenSSL rejected Go's Ed25519 signature at case ${i}`);
  }
}
console.log(JSON.stringify({
  status: 'passed', cases: tests.length, node: process.version, openssl: process.versions.openssl,
}));
