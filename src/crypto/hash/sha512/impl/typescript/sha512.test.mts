import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { MAX_MESSAGE_BYTES, Sha512, sha512 } from './sha512.mts';

const reference = (bytes: Uint8Array) => createHash('sha512').update(bytes).digest('hex');
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

test('known answers', () => {
  const encoder = new TextEncoder();
  assert.equal(hex(sha512(encoder.encode(''))),
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce' +
    '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
  assert.equal(hex(sha512(encoder.encode('abc'))),
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
    '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
  assert.equal(hex(sha512(new Uint8Array(1_000_000).fill(97))),
    'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb' +
    'de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b');
  assert.equal(MAX_MESSAGE_BYTES * 8n + 8n, 1n << 128n);
});

test('offset, padding, multi-block and all boundary splits', () => {
  const fixture = Uint8Array.from({ length: 1041 }, (_, i) => (i * i + 31 * i + 9) >>> 2);
  for (const size of [0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 257, 1025]) {
    const input = fixture.subarray(13, 13 + size);
    const expected = reference(input);
    assert.equal(hex(sha512(input)), expected);
    for (let split = 0; split <= size; split += 1) {
      const stream = new Sha512();
      const borrowed = input.slice(0, split);
      stream.update(borrowed);
      borrowed.fill(0);
      assert.equal(hex(stream.digest()), reference(input.subarray(0, split)));
      stream.update(input.subarray(split));
      assert.equal(hex(stream.digest()), expected);
    }
  }
});

test('mixed full blocks, repeated snapshots and reset', () => {
  let state = 0x30cf418a;
  for (let n = 0; n < 100; n += 1) {
    const input = Uint8Array.from({ length: (n * 521) % 4031 }, () => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state >>> 24;
    });
    const stream = new Sha512();
    for (let position = 0; position < input.length; position += 137) {
      stream.update(input.subarray(position, position + 137));
    }
    assert.equal(hex(stream.digest()), reference(input));
    stream.digest().fill(1);
    assert.equal(hex(stream.digest()), reference(input));
    stream.reset();
    assert.equal(hex(stream.digest()), reference(new Uint8Array()));
  }
});

test('rejected inputs preserve the partial stream', () => {
  const stream = new Sha512().update(Uint8Array.of(97, 98));
  assert.throws(() => stream.update([] as unknown as Uint8Array), TypeError);
  const detached = Uint8Array.of(99);
  structuredClone(detached, { transfer: [detached.buffer] });
  assert.throws(() => stream.update(detached), TypeError);
  assert.equal(hex(stream.update(Uint8Array.of(99)).digest()), reference(Uint8Array.of(97, 98, 99)));
});
