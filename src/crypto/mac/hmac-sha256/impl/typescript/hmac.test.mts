import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';
import { HmacSha256, authenticate } from './hmac.mts';

const encoder = new TextEncoder();
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

test('RFC 4231 short and long keys', () => {
  const short = new Uint8Array(20).fill(0x0b);
  const long = new Uint8Array(131).fill(0xaa);
  assert.equal(hex(authenticate(short, encoder.encode('Hi There'))),
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  assert.equal(hex(authenticate(long, encoder.encode('Test Using Larger Than Block-Size Key - Hash Key First'))),
    '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');
});

test('independent oracle across key lengths and message splits', () => {
  for (const klen of [0, 1, 31, 63, 64, 65, 131]) {
    const key = Uint8Array.from({ length: klen }, (_, i) => 11 * i + 7);
    const stream = new HmacSha256(key);
    for (const length of [0, 1, 55, 64, 130]) {
      const input = Uint8Array.from({ length }, (_, i) => 29 * i + 13);
      const digest = createHmac('sha256', key).update(input).digest('hex');
      assert.equal(hex(authenticate(key, input)), digest);
      const split = Math.floor(length / 2);
      stream.reset().update(input.subarray(0, split)).update(new Uint8Array()).update(input.subarray(split));
      assert.equal(hex(stream.digest()), digest);
    }
  }
});

test('bad inputs and mutable caller buffers', () => {
  const key = encoder.encode('key');
  const stream = new HmacSha256(key).update(encoder.encode('abc'));
  const expected = createHmac('sha256', key).update('abc').digest('hex');
  key.fill(0);
  stream.digest().fill(0);
  assert.throws(() => stream.update(new Uint16Array(4) as unknown as Uint8Array), TypeError);
  assert.equal(hex(stream.digest()), expected);
});

test('prepared state survives repeated snapshots, resets and independent keys', () => {
  const keyA = new Uint8Array(131).fill(13);
  const keyB = new Uint8Array(64).fill(29);
  const first = new HmacSha256(keyA);
  const second = new HmacSha256(keyB);
  for (const size of [127, 0, 56, 1, 55, 256, 64]) {
    const part = Uint8Array.from({ length: size }, (_, i) => 17 * i + size);
    const suffix = Uint8Array.of(2, 3, 5, 7);
    first.reset().update(part);
    second.reset().update(suffix);
    const expectedA = createHmac('sha256', keyA).update(part).digest('hex');
    assert.equal(hex(first.digest()), expectedA);
    first.digest().fill(0);
    assert.equal(hex(first.digest()), expectedA);
    assert.equal(hex(second.digest()), createHmac('sha256', keyB).update(suffix).digest('hex'));
    first.update(suffix);
    second.update(part);
    assert.equal(hex(first.digest()), createHmac('sha256', keyA).update(part).update(suffix).digest('hex'));
    assert.equal(hex(second.digest()), createHmac('sha256', keyB).update(suffix).update(part).digest('hex'));
  }
});
