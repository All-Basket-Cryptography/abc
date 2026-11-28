import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { Sha256, sha256 } from './sha256.mjs';

const bytes = (text) => new TextEncoder().encode(text);
const hex = (data) => Buffer.from(data).toString('hex');
const reference = (input) => createHash('sha256').update(input).digest('hex');

test('known answers', () => {
  for (const [input, expected] of [
    ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
  ]) {
    assert.equal(hex(sha256(bytes(input))), expected);
  }
  assert.equal(hex(sha256(new Uint8Array(1_000_000).fill(0x61))), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
});

test('all chunk splits around padding and block boundaries', () => {
  for (const size of [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129]) {
    const input = Uint8Array.from({ length: size }, (_, i) => 31 * i + 17);
    const expected = reference(input);
    for (let split = 0; split <= size; split += 1) {
      const hash = new Sha256().update(input.subarray(0, split)).update(new Uint8Array()).update(input.subarray(split));
      assert.equal(hex(hash.digest()), expected, `length ${size}, split ${split}`);
    }
  }
});

test('deterministic differential binary inputs', () => {
  let generator = 0xc001ca71;
  const next = () => (generator = (Math.imul(generator, 1664525) + 1013904223) >>> 0);
  for (let trial = 0; trial < 256; trial += 1) {
    const input = Uint8Array.from({ length: next() % 8193 }, () => next() >>> 24);
    const expected = reference(input);
    assert.equal(hex(sha256(input)), expected);
    const stream = new Sha256();
    for (let start = 0; start < input.length;) {
      const end = start + 1 + (next() % 193);
      stream.update(input.subarray(start, end));
      start = end;
    }
    assert.equal(hex(stream.digest()), expected);
  }
});

test('snapshot, rejected types, caller-buffer ownership and reset', () => {
  const input = bytes('_abc_');
  const context = new Sha256().update(input.subarray(1, 4));
  input.fill(0);
  const first = reference(bytes('abc'));
  const digest = context.digest();
  assert.equal(hex(digest), first);
  digest.fill(0);
  assert.throws(() => context.update(new Uint16Array(4)), TypeError);
  assert.equal(hex(context.digest()), first);
  context.update(bytes('def'));
  assert.equal(hex(context.digest()), reference(bytes('abcdef')));
  context.reset();
  assert.equal(hex(context.digest()), reference(new Uint8Array()));
});

test('copied prefix state owns its pending bytes, chaining words and length', () => {
  const referenceHash = reference;
  for (const size of [0, 1, 55, 56, 63, 64, 65, 120, 128, 129]) {
    const prefix = Uint8Array.from({ length: size }, (_, i) => 67 * i + 11);
    const left = Uint8Array.of(3, 5, 7);
    const right = new Uint8Array(69).fill(23);
    const source = new Sha256().update(prefix);
    const copy = new Sha256().update(new Uint8Array(127).fill(19));
    assert.equal(copy.copyFrom(source), copy);
    assert.equal(hex(copy.digest()), referenceHash(prefix));
    assert.throws(() => copy.copyFrom({}), TypeError);
    source.update(left);
    copy.copyFrom(copy).update(right);
    assert.equal(hex(source.digest()), referenceHash(Uint8Array.of(...prefix, ...left)));
    assert.equal(hex(copy.digest()), referenceHash(Uint8Array.of(...prefix, ...right)));
    source.reset();
    copy.copyFrom(source);
    assert.equal(hex(copy.digest()), referenceHash(new Uint8Array()));
  }
});
