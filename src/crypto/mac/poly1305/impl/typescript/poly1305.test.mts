import assert from 'node:assert/strict';
import { test } from 'node:test';
import { authenticate, Poly1305 } from './poly1305.mts';

let state = 0x8439;
function fixture(size: number) {
  return Uint8Array.from({ length: size }, () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state >>> 24;
  });
}
function littleEndian(bytes) {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) result = (result << 8n) + BigInt(bytes[i]);
  return result;
}

function reference(key, input) {
  const r = littleEndian(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const p = (1n << 130n) - 5n;
  let h = 0n;
  for (let offset = 0; offset < input.length; offset += 16) {
    const block = input.subarray(offset, offset + 16);
    h = ((h + littleEndian(block) + (1n << BigInt(8 * block.length))) * r) % p;
  }
  h += littleEndian(key.subarray(16));
  return Uint8Array.from({ length: 16 }, (_, i) => Number((h >> BigInt(8 * i)) & 255n));
}

test('RFC 8439 §2.5.2', () => {
  const key = Buffer.from('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b', 'hex');
  const input = Buffer.from('Cryptographic Forum Research Group');
  assert.equal(Buffer.from(authenticate(key, input)).toString('hex'), 'a8061dc1305136c6c22b8baf0c0127a9');
});

test('2,126 independent integer comparisons with split and snapshot', () => {
  for (let i = 0; i < 2126; i += 1) {
    const key = fixture(32);
    if (i % 7 === 0) key.fill(255, 0, 16);
    const input = fixture(i < 260 ? i : (31 * i) % 529);
    if (i % 13 === 0) input.fill(255);
    const split = (i * 137) % (input.length + 1);
    const mac = new Poly1305(key).update(input.subarray(0, split));
    assert.deepEqual(mac.digest(), reference(key, input.subarray(0, split)));
    mac.update(input.subarray(split));
    const expected = reference(key, input);
    assert.deepEqual(mac.digest(), expected);
    assert.deepEqual(mac.digest(), expected);
    assert.deepEqual(authenticate(key, input), expected);
  }
});

test('owns key bytes and rejects a detached update before changing its state', () => {
  const key = Buffer.from(fixture(32));
  const input = fixture(17);
  const expected = reference(key, input);
  const mac = new Poly1305(key).update(input);
  key.fill(0);
  const detached = new Uint8Array(1);
  structuredClone(detached, { transfer: [detached.buffer] });
  assert.throws(() => mac.update(detached), TypeError);
  assert.throws(() => mac.update(new Uint8Array(new SharedArrayBuffer(1))), TypeError);
  assert.deepEqual(mac.digest(), expected);
  assert.throws(() => new Poly1305(key.subarray(1)), RangeError);
});
