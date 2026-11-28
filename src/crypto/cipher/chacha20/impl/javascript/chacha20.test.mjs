import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import { test } from 'node:test';
import { applyKeystream, block } from './chacha20.mjs';

let state = 0x8439;
function fixture(size) {
  return Uint8Array.from({ length: size }, () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state >>> 24;
  });
}

test('RFC 8439 §2.3.2 block', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => i);
  const nonce = Buffer.from('000000090000004a00000000', 'hex');
  assert.equal(Buffer.from(block(key, nonce, 1)).toString('hex'),
    '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e' +
    'd2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e');
});

test('144 OpenSSL comparisons and reciprocal XOR', () => {
  for (const size of [0, 1, 15, 16, 63, 64, 65, 129, 4097]) {
    for (let i = 0; i < 16; i += 1) {
      const key = fixture(32), nonce = fixture(12), clear = fixture(size);
      const counter = Math.imul(i, 0x50739b71) >>> 0;
      const iv = Buffer.alloc(16);
      iv.writeUInt32LE(counter);
      iv.set(nonce, 4);
      const cipher = createCipheriv('chacha20', key, iv);
      const expected = Buffer.concat([cipher.update(clear), cipher.final()]);
      const input = Buffer.concat([Buffer.of(0xa5), clear, Buffer.of(0xc7)]);
      applyKeystream(key, nonce, counter, input.subarray(1, size + 1));
      assert.deepEqual(input.subarray(1, size + 1), expected);
      assert.equal(input[0], 0xa5);
      assert.equal(input[size + 1], 0xc7);
      applyKeystream(key, nonce, counter, input.subarray(1, size + 1));
      assert.deepEqual(input.subarray(1, size + 1), Buffer.from(clear));
    }
  }
});

test('rejection before mutation and final counter', () => {
  const key = fixture(32), nonce = fixture(12);
  const largest = fixture(65);
  const saved = largest.slice();
  assert.throws(() => applyKeystream(key, nonce, 0xffffffff, largest), RangeError);
  assert.throws(() => applyKeystream(key, nonce, 0x100000000, largest), RangeError);
  assert.throws(() => applyKeystream(key.subarray(1), nonce, 0, largest), RangeError);
  assert.throws(() => applyKeystream(key, nonce.subarray(1), 0, largest), RangeError);
  assert.deepEqual(largest, saved);
  const last = new Uint8Array(64);
  applyKeystream(key, nonce, 0xffffffff, last);
  assert.deepEqual(last, block(key, nonce, 0xffffffff));
  const detached = new Uint8Array(1);
  structuredClone(detached, { transfer: [detached.buffer] });
  assert.throws(() => applyKeystream(key, nonce, 0, detached), TypeError);
  assert.throws(() => applyKeystream(key, nonce, 0, new Uint8Array(new SharedArrayBuffer(1))), TypeError);
});

test('word XOR preserves bytes outside unaligned views and supports aliased key and nonce', () => {
  for (const offset of [1, 2, 3, 4]) {
    for (const size of [2, 3, 4, 5, 6, 7, 62, 63, 64, 65, 66, 67]) {
      const buffer = fixture(80);
      const key = buffer.subarray(0, 32);
      const nonce = buffer.subarray(19, 31);
      const input = buffer.subarray(offset, offset + size);
      const saved = Buffer.from(buffer);
      const iv = Buffer.alloc(16);
      iv.writeUInt32LE(0xfffffffe);
      iv.set(nonce, 4);
      const cipher = createCipheriv('chacha20', key, iv);
      const expected = Buffer.concat([cipher.update(input), cipher.final()]);
      saved.set(expected, offset);
      assert.equal(applyKeystream(key, nonce, 0xfffffffe, input), input);
      assert.deepEqual(Buffer.from(buffer), saved);
    }
  }
});
