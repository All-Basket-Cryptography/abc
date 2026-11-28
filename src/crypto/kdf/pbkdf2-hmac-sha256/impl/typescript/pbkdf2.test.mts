import assert from 'node:assert/strict';
import { pbkdf2Sync } from 'node:crypto';
import test from 'node:test';
import { MAX_ITERATIONS, MAX_OUTPUT_BYTES, derive } from './pbkdf2.mts';

const encoder = new TextEncoder();
const bytes = (value: string) => encoder.encode(value);

test('RFC 7914 section 11 vector', () => {
  const expected = '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc' +
    '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783';
  assert.equal(Buffer.from(derive(bytes('passwd'), bytes('salt'), 1, 64)).toString('hex'), expected);
});

test('native oracle for iterations, output lengths and long passwords', () => {
  const prefix = (length: number) => Uint8Array.from({ length }, (_, i) => i);
  const cases = [
    [bytes(''), bytes('')],
    [bytes('pass\x00word'), bytes('sa\x00lt')],
    [prefix(65), bytes('salt')],
    [prefix(137), prefix(60)],
  ];
  for (const [key, salt] of cases) {
    for (const count of [1, 2, 7]) {
      for (const length of [1, 31, 32, 33, 64, 65]) {
        const expected = pbkdf2Sync(key, salt, count, length, 'sha256');
        assert.deepEqual(Buffer.from(derive(key, salt, count, length)), expected);
      }
    }
  }
  // Blocks 255, 256 and 257 exercise the carry in the big-endian index.
  const data = [bytes('k'), bytes('s')];
  assert.deepEqual(Buffer.from(derive(data[0], data[1], 1, 8193)), pbkdf2Sync(data[0], data[1], 1, 8193, 'sha256'));
});

test('reject invalid types, iteration counts and output lengths', () => {
  const key = bytes('p');
  const salt = bytes('s');
  for (const count of [0, -1, 1.5, NaN, MAX_ITERATIONS + 1]) {
    assert.throws(() => derive(key, salt, count, 1), RangeError);
  }
  for (const length of [0, -1, 1.5, NaN, MAX_OUTPUT_BYTES + 1]) {
    assert.throws(() => derive(key, salt, 1, length), RangeError);
  }
  assert.throws(() => derive(key, new Uint16Array(1) as unknown as Uint8Array, 1, 1), TypeError);
});
