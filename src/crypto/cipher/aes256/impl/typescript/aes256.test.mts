import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { test } from 'node:test';
import { Aes256 } from './aes256.mts';

let seed = 0x1970038d;
function fixture(length) {
  return Uint8Array.from({ length }, () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed >>> 24;
  });
}
const hex = text => Buffer.from(text, 'hex');

test('FIPS 197 AES-256 and SP 800-38A block answers', () => {
  const examples = [
    ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      '00112233445566778899aabbccddeeff', '8ea2b7ca516745bfeafc49904b496089'],
    ['603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
      '6bc1bee22e409f96e93d7e117393172a', 'f3eed1bdb5d2a03c064b5a7e3db181f8'],
  ];
  for (const [key, data, encrypted] of examples) {
    const aes = new Aes256(hex(key));
    assert.deepEqual(Buffer.from(aes.encrypt(hex(data))), hex(encrypted));
    assert.deepEqual(Buffer.from(aes.decrypt(hex(encrypted))), hex(data));
  }
});

test('256 matches with OpenSSL in both directions', () => {
  for (let i = 0; i < 256; i += 1) {
    const key = fixture(32), input = fixture(16);
    if (i === 0) key.fill(0);
    if (i === 1) key.fill(255);
    const aes = new Aes256(key);
    const reference = createCipheriv('aes-256-ecb', key, null).setAutoPadding(false);
    const expected = Buffer.concat([reference.update(input), reference.final()]);
    assert.deepEqual(Buffer.from(aes.encrypt(input)), expected);
    assert.deepEqual(aes.decrypt(expected), input);
    const reverse = createDecipheriv('aes-256-ecb', key, null).setAutoPadding(false);
    const ciphertext = fixture(16);
    assert.deepEqual(Buffer.from(aes.decrypt(ciphertext)),
      Buffer.concat([reverse.update(ciphertext), reverse.final()]));
  }
});

test('rejects wrong sizes and maintains byte ownership', () => {
  const key = fixture(32), block = fixture(16);
  const copy = block.slice();
  const aes = new Aes256(key);
  const expected = aes.encrypt(block);
  key.fill(0);
  const released = aes.encrypt(block);
  released.fill(0);
  assert.deepEqual(aes.encrypt(block), expected);
  assert.deepEqual(block, copy);
  assert.throws(() => new Aes256(new Uint8Array(31)), RangeError);
  assert.throws(() => aes.encrypt(new Uint8Array(15)), RangeError);
  assert.throws(() => aes.decrypt(new Uint8Array(17)), RangeError);
  assert.throws(() => aes.encrypt(new Uint8Array(new SharedArrayBuffer(16))), TypeError);
});
