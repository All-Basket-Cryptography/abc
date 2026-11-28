import assert from 'node:assert/strict';
import { createHmac, hkdfSync } from 'node:crypto';
import test from 'node:test';
import { derive, expand, extract } from './hkdf.mjs';

const hex = (bytes) => Buffer.from(bytes).toString('hex');

test('RFC 5869 extraction, expansion and omitted salt', () => {
  const ikm = new Uint8Array(22).fill(0x0b);
  const salt = Uint8Array.from({ length: 13 }, (_, i) => i);
  const info = Uint8Array.from({ length: 10 }, (_, i) => 0xf0 + i);
  const prk = extract(salt, ikm);
  assert.equal(hex(prk), '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
  const wanted = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';
  assert.equal(hex(expand(prk, info, 42)), wanted);
  assert.equal(hex(derive(salt, ikm, info, 42)), wanted);
  assert.equal(hex(derive(null, ikm, new Uint8Array(0), 42)),
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8');
  assert.deepEqual(extract(null, ikm), extract(new Uint8Array(0), ikm));
});

test('independent OpenSSL oracle across output lengths including block 255', () => {
  const ikm = Uint8Array.from({ length: 133 }, (_, i) => i * 7);
  const salt = Uint8Array.from({ length: 130 }, (_, i) => i * 31);
  const info = Uint8Array.from({ length: 80 }, (_, i) => i + 0x99);
  const prk = createHmac('sha256', salt).update(ikm).digest('hex');
  assert.equal(hex(extract(salt, ikm)), prk);
  assert.deepEqual(derive(salt, ikm, info, 0), new Uint8Array(0));
  for (const length of [1, 31, 32, 33, 64, 97, 8159, 8160]) {
    const expected = Buffer.from(hkdfSync('sha256', ikm, salt, info, length)).toString('hex');
    assert.equal(hex(derive(salt, ikm, info, length)), expected);
  }
  for (const size of [64, 65, 137]) {
    const key = Uint8Array.from({ length: size }, (_, i) => i);
    const wanted = createHmac('sha256', key).update(info).update(Uint8Array.of(1)).digest('hex');
    assert.equal(hex(expand(key, info, 32)), wanted);
  }
});

test('reject invalid input types, PRK and output lengths', () => {
  for (const length of [-1, 8161, 2.5, NaN]) {
    assert.throws(() => expand(new Uint8Array(32), new Uint8Array(0), length), RangeError);
  }
  assert.throws(() => expand(new Uint8Array(31), new Uint8Array(0), 0), RangeError);
  assert.throws(() => expand(new Uint8Array(32), new Uint16Array(2), 0), TypeError);
});
