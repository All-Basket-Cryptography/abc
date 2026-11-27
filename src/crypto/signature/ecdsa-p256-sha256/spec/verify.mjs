import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createECDH, createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const manifest = fileURLToPath(new URL('../impl/rust/Cargo.toml', import.meta.url));
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const encode = scalar => Buffer.from(scalar.toString(16).padStart(64, '0'), 'hex');
const cases = [];
for (const length of [0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 128, 1024]) {
  for (let variant = 0; variant < 4; variant += 1) {
    const seed = createHash('sha256').update(`ABC P-256 interop ${length} ${variant}`).digest('hex');
    const scalar = encode(1n + BigInt('0x' + seed) % (order - 1n));
    const curve = createECDH('prime256v1');
    curve.setPrivateKey(scalar);
    const point = curve.getPublicKey();
    const key = createPrivateKey({ format: 'jwk', key: {
      kty: 'EC', crv: 'P-256', d: scalar.toString('base64url'),
      x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url'),
    } });
    const publicKey = createPublicKey(key);
    const message = Buffer.from(Array.from({ length }, (_, i) => (i * 29 + variant) & 255));
    const signature = sign('sha256', message, { key, dsaEncoding: 'ieee-p1363' });
    cases.push({ scalar, point, message, signature, publicKey });
  }
}

const input = cases.map(({ scalar, message, signature }) =>
  [scalar, message, signature].map(value => value.toString('hex')).join(':'));
const run = spawnSync('cargo', ['+1.92.0', 'run', '--release', '--offline', '--locked', '--quiet',
  '--manifest-path', manifest, '--example', 'ecdsa_p256_interop'], {
  input: input.join('\n') + '\n', encoding: 'utf8', timeout: 150000,
});
if (run.status !== 0) throw new Error(run.error?.message || run.stderr || `Exit ${run.status}`);

const output = run.stdout.trim().split(/\r?\n/);
assert.equal(output.length, cases.length);
for (let i = 0; i < cases.length; i += 1) {
  const { point, message, publicKey } = cases[i];
  const [candidatePoint, candidateSignature] = output[i].split(':').map(hex => Buffer.from(hex, 'hex'));
  assert.deepEqual(candidatePoint, point);
  assert.equal(candidateSignature.length, 64);
  const options = { key: publicKey, dsaEncoding: 'ieee-p1363' };
  assert(verify('sha256', message, options, candidateSignature), `signature ${i}`);
  assert(!verify('sha256', Buffer.concat([message, Buffer.from([0])]), options, candidateSignature));
}
console.log(`${cases.length} bidirectional ECDSA P-256 comparisons passed with OpenSSL ${process.versions.openssl}`);
