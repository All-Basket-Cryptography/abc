import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { Shake256, shake256 } from './shake256.mts';

const hex = (value: Uint8Array) => Buffer.from(value).toString('hex');
const reference = (input: Uint8Array, size: number) => createHash('shake256', { outputLength: size }).update(input).digest('hex');

test('known answer and zero-length output', () => {
  assert.equal(hex(shake256(new Uint8Array(), 32)),
    '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f');
  assert.equal(shake256(Uint8Array.of(1, 2, 3), 0).length, 0);
});

test('input splits and 409 output bytes across rate boundaries', () => {
  const fixture = Uint8Array.from({ length: 560 }, (_, i) => (i * i + 19 * i + 7) >>> 2);
  for (const size of [0, 1, 134, 135, 136, 137, 271, 272, 273, 545]) {
    const input = fixture.subarray(7, 7 + size);
    const expected = reference(input, 409);
    assert.equal(hex(shake256(input, 409)), expected);
    for (let split = 0; split <= size; split += 1) {
      const source = input.slice(0, split);
      const absorber = new Shake256().update(source);
      source.fill(0);
      const snapshot = absorber.finalize();
      absorber.update(input.subarray(split));
      const reader = absorber.finalize();
      const output = new Uint8Array(409);
      let offset = 0;
      for (const part of [0, 1, 134, 1, 136, 137]) {
        assert.equal(reader.readInto(output.subarray(offset, offset + part)), part);
        offset += part;
      }
      assert.equal(hex(output), expected);
      assert.equal(hex(snapshot.read(31)), reference(input.subarray(0, split), 31));
    }
  }
});

test('rejected reads preserve the output cursor', () => {
  const reader = new Shake256().update(Uint8Array.of(9)).finalize();
  for (const invalid of [-1, 0.5, Infinity, NaN]) assert.throws(() => reader.read(invalid), RangeError);
  const detached = Uint8Array.of(99);
  structuredClone(detached, { transfer: [detached.buffer] });
  assert.throws(() => reader.readInto(detached), TypeError);
  assert.equal(hex(reader.read(273)), reference(Uint8Array.of(9), 273));
});
