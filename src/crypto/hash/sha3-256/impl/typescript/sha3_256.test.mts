import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { Sha3_256, sha3_256 } from './sha3_256.mts';

const hex = (value: Uint8Array) => Buffer.from(value).toString('hex');
const reference = (input: Uint8Array) => createHash('sha3-256').update(input).digest('hex');

test('known answers', () => {
  assert.equal(hex(sha3_256(new Uint8Array())),
    'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
  assert.equal(hex(sha3_256(Uint8Array.of(97, 98, 99))),
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
});

test('same digest for every split around the padding and rate boundary', () => {
  const fixture = Uint8Array.from({ length: 560 }, (_, i) => (i * i + 19 * i + 33) >>> 2);
  for (const size of [0, 1, 134, 135, 136, 137, 271, 272, 273, 545]) {
    const input = fixture.subarray(7, size + 7);
    const expected = reference(input);
    assert.equal(hex(sha3_256(input)), expected);
    for (let split = 0; split <= size; split += 1) {
      const prefix = input.slice(0, split);
      const stream = new Sha3_256().update(prefix);
      prefix.fill(0);
      const first = stream.digest();
      assert.equal(hex(first), reference(input.subarray(0, split)));
      first.fill(0);
      assert.equal(hex(stream.update(input.subarray(split)).digest()), expected);
    }
  }
});

test('detached input is rejected before state changes', () => {
  const input = Uint8Array.of(99);
  structuredClone(input, { transfer: [input.buffer] });
  const stream = new Sha3_256().update(Uint8Array.of(97, 98));
  assert.throws(() => stream.update(input), TypeError);
  assert.equal(hex(stream.update(Uint8Array.of(99)).digest()), reference(Uint8Array.of(97, 98, 99)));
});
