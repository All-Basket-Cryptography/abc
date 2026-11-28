import assert from 'node:assert/strict';
import { createECDH, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const samples = JSON.parse(readFileSync(0, 'utf8'));
const cases = [];
for (const item of samples) {
  const scalar = Buffer.from(item.scalar, 'hex');
  const message = Buffer.from(item.message, 'hex');
  const candidate = Buffer.from(item.signature, 'hex');
  const curve = createECDH('prime256v1');
  curve.setPrivateKey(scalar);
  const point = curve.getPublicKey();
  const compressed = curve.getPublicKey('hex', 'compressed');
  const key = createPrivateKey({ format: 'jwk', key: {
    kty: 'EC', crv: 'P-256', d: scalar.toString('base64url'),
    x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url'),
  } });
  const signature = sign('sha256', message, { key, dsaEncoding: 'ieee-p1363' });
  const options = { key: createPublicKey(key), dsaEncoding: 'ieee-p1363' };
  assert.equal(candidate.length, 64);
  assert(verify('sha256', message, options, candidate));
  assert(!verify('sha256', Buffer.concat([message, Buffer.from([0])]), options, candidate));
  cases.push({ uncompressed: point.toString('hex'), compressed, signature: signature.toString('hex') });
}
console.log(JSON.stringify({ node: process.version, openssl: process.versions.openssl, cases }));
