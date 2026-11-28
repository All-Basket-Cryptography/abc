import assert from 'node:assert/strict';
import crypto, { createCipheriv, createDecipheriv } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { test } from 'node:test';
import { open, seal } from './aes256gcm.mjs';
import { open as nodeOpen, seal as nodeSeal } from './node.mjs';

let seed = 0x1970038d;
function fixture(length) {
  return Uint8Array.from({ length }, () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed >>> 24;
  });
}
const hex = text => Buffer.from(text, 'hex');

test('NIST known answers with empty and partial blocks', () => {
  const empty = new Uint8Array();
  const zeros = seal(new Uint8Array(32), new Uint8Array(12), empty, empty);
  assert.deepEqual(zeros.ciphertext, empty);
  assert.deepEqual(Buffer.from(zeros.tag), hex('530f8afbc74536b9a963b4f1c4cb738b'));
  assert.deepEqual(nodeSeal(new Uint8Array(32), new Uint8Array(12), empty, empty), zeros);
  const key = hex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
  const nonce = hex('cafebabefacedbaddecaf888');
  const aad = hex('3ad77bb40d7a3660a89ecaf32466ef97f5d3d585');
  const plaintext = hex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
  const target = hex('522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
    '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662');
  const { ciphertext, tag } = seal(key, nonce, aad, plaintext);
  assert.deepEqual(Buffer.from(ciphertext), target);
  assert.deepEqual(Buffer.from(tag), hex('e097195f4532da895fb917a5a55c6aa0'));
  assert.deepEqual(open(key, nonce, aad, ciphertext, tag), new Uint8Array(plaintext));
  assert.deepEqual(nodeSeal(key, nonce, aad, plaintext), { ciphertext, tag });
  assert.deepEqual(nodeOpen(key, nonce, aad, ciphertext, tag), new Uint8Array(plaintext));
});

test('216 interoperability cases across the portable and Node entries', () => {
  const cases = [0, 1, 15, 16, 17, 31, 32, 33, 129, 4097]
    .flatMap(size => [0, 1, 15, 16, 17, 65].map(aad => [size, aad]));
  for (let i = 0; i < 156; i += 1) cases.push([(169 * i) % 521, (53 * i) % 89]);
  for (const [size, headerSize] of cases) {
    const key = fixture(32), nonce = fixture(12), aad = fixture(headerSize), input = fixture(size);
    const reference = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    reference.setAAD(aad);
    const expected = Buffer.concat([reference.update(input), reference.final()]);
    const expectedTag = reference.getAuthTag();
    const { ciphertext, tag } = seal(key, nonce, aad, input);
    assert.deepEqual(Buffer.from(ciphertext), expected);
    assert.deepEqual(Buffer.from(tag), expectedTag);
    assert.deepEqual(open(key, nonce, aad, expected, expectedTag), input);
    assert.deepEqual(nodeSeal(key, nonce, aad, input), { ciphertext, tag });
    assert.deepEqual(nodeOpen(key, nonce, aad, ciphertext, tag), input);
    const reverse = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    reverse.setAAD(aad);
    reverse.setAuthTag(tag);
    assert.deepEqual(Buffer.concat([reverse.update(ciphertext), reverse.final()]), Buffer.from(input));
  }
});

test('authentication failure returns no plaintext and preserves caller views', () => {
  const key = fixture(32), nonce = fixture(12), aad = fixture(19), data = fixture(65);
  const { ciphertext, tag } = seal(key, nonce, aad, data);
  const preserved = ciphertext.slice();
  for (let i = 0; i < tag.length; i += 1) {
    const invalid = tag.slice();
    invalid[i] ^= 1;
    assert.equal(open(key, nonce, aad, ciphertext, invalid), null);
    assert.equal(nodeOpen(key, nonce, aad, ciphertext, invalid), null);
  }
  assert.equal(open(key, nonce, aad.subarray(1), ciphertext, tag), null);
  assert.equal(open(key, nonce, aad, ciphertext.subarray(1), tag), null);
  assert.equal(open(key, nonce, aad, ciphertext, tag.subarray(1)), null);
  assert.equal(nodeOpen(key, nonce, aad.subarray(1), ciphertext, tag), null);
  assert.equal(nodeOpen(key, nonce, aad, ciphertext.subarray(1), tag), null);
  assert.equal(nodeOpen(key, nonce, aad, ciphertext, tag.subarray(1)), null);
  assert.deepEqual(ciphertext, preserved);
  assert.throws(() => seal(key, nonce.subarray(1), aad, data), RangeError);
  assert.throws(() => nodeSeal(key, nonce.subarray(1), aad, data), RangeError);
  assert.throws(() => nodeSeal(key.subarray(1), nonce, aad, data), RangeError);
  class CallerView extends Uint8Array {
    get buffer() { throw new Error('Uses native byte view accessors'); }
    [Symbol.iterator]() { throw new Error('Uses native byte reads'); }
  }
  const source = new CallerView(preserved.buffer, preserved.byteOffset, preserved.byteLength);
  assert.deepEqual(open(key, nonce, aad, source, tag), data);
  assert.deepEqual(nodeOpen(key, nonce, aad, source, tag), data);
  const shared = new Uint8Array(new SharedArrayBuffer(1));
  assert.throws(() => nodeSeal(key, nonce, shared, data), TypeError);
  const detached = new Uint8Array(1);
  structuredClone(detached, { transfer: [detached.buffer] });
  assert.throws(() => nodeOpen(key, nonce, aad, detached, tag), TypeError);
});

test('Node open wipes temporary plaintext and propagates a distinct provider error', (t) => {
  const message = 'Unsupported state or unable to authenticate data';
  const providerError = Object.assign(new Error(message), { code: 'ERR_TEST_PROVIDER_FAILURE' });
  let failure = providerError;
  const scratch = new Uint8Array([1, 2]);
  const tail = new Uint8Array([3]);
  const mocked = t.mock.method(crypto, 'createDecipheriv', () => ({
    setAAD() {},
    setAuthTag() {},
    update() { return scratch; },
    final() {
      if (failure) throw failure;
      return tail;
    },
  }));
  syncBuiltinESMExports();
  const invoke = () => nodeOpen(new Uint8Array(32), new Uint8Array(12), new Uint8Array(),
    new Uint8Array(3), new Uint8Array(16));
  try {
    assert.throws(invoke, error => error === providerError);
    assert.deepEqual(scratch, new Uint8Array(2));

    scratch.set([1, 2]);
    failure = new Error(message);
    assert.equal(invoke(), null);
    assert.deepEqual(scratch, new Uint8Array(2));

    scratch.set([1, 2]);
    failure = undefined;
    assert.deepEqual(invoke(), new Uint8Array([1, 2, 3]));
    assert.deepEqual(scratch, new Uint8Array(2));
    assert.deepEqual(tail, new Uint8Array(1));
  } finally {
    mocked.mock.restore();
    syncBuiltinESMExports();
  }
});
