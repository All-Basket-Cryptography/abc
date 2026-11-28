import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { test } from 'node:test';
import { open, seal } from './chacha20poly1305.mjs';

let state = 0x8439;
function fixture(size) {
  return Uint8Array.from({ length: size }, () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state >>> 24;
  });
}
test('RFC 8439 §2.8.2 AEAD', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => 128 + i);
  const nonce = Buffer.from('070000004041424344454647', 'hex');
  const aad = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
  const plaintext = Buffer.from("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e", 'hex');
  const expected = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
  const { ciphertext, tag } = seal(key, nonce, aad, plaintext);
  assert.equal(Buffer.from(ciphertext).toString('hex'), expected);
  assert.equal(Buffer.from(tag).toString('hex'), '1ae10b594f09e26a7e902ecbd0600691');
  assert.deepEqual(open(key, nonce, aad, ciphertext, tag), Uint8Array.from(plaintext));
});

test('174 OpenSSL comparisons across payload and AAD boundaries', () => {
  const sizes = [0, 1, 15, 16, 17, 63, 64, 65, 129];
  const cases = sizes.flatMap(size => [0, 1, 15, 16, 17, 65].map(aad => [size, aad]));
  for (let i = 0; i < 120; i += 1) cases.push([(i * 169) % 257, i % 39]);
  for (const [size, aadSize] of cases) {
    const key = fixture(32), nonce = fixture(12), aad = fixture(aadSize), input = fixture(size);
    const oracle = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    oracle.setAAD(aad);
    const expected = Buffer.concat([oracle.update(input), oracle.final()]);
    const { ciphertext, tag } = seal(key, nonce, aad, input);
    assert.deepEqual(Buffer.from(ciphertext), expected);
    assert.deepEqual(Buffer.from(tag), oracle.getAuthTag());
    assert.deepEqual(open(key, nonce, aad, ciphertext, tag), input);
    const oracleOpen = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    oracleOpen.setAAD(aad);
    oracleOpen.setAuthTag(tag);
    assert.deepEqual(Buffer.concat([oracleOpen.update(ciphertext), oracleOpen.final()]), Buffer.from(input));
  }
});

test('bad tag, AAD, and ciphertext expose no plaintext and preserve input views', () => {
  const key = fixture(32), nonce = fixture(12), aad = fixture(17), input = Buffer.from(fixture(65));
  const saved = Buffer.from(input);
  const { ciphertext, tag } = seal(key, nonce, aad, input);
  const savedCiphertext = ciphertext.slice();
  for (let i = 0; i < 16; i += 1) {
    const corrupt = tag.slice();
    corrupt[i] ^= 1;
    assert.equal(open(key, nonce, aad, ciphertext, corrupt), null);
  }
  const corrupt = ciphertext.slice();
  corrupt[0] ^= 1;
  assert.equal(open(key, nonce, aad, corrupt, tag), null);
  assert.equal(open(key, nonce, aad.subarray(1), ciphertext, tag), null);
  assert.equal(open(key, nonce, aad, ciphertext, tag.subarray(1)), null);
  assert.throws(() => open(key, nonce, aad, new Uint8Array(new SharedArrayBuffer(65)), tag), TypeError);
  assert.deepEqual(input, saved);
  assert.deepEqual(ciphertext, savedCiphertext);
});

test('caller view methods and getters are unused during seal and open', () => {
  const key = fixture(32), nonce = fixture(12), aad = fixture(17), plaintext = fixture(65);
  const expected = seal(key, nonce, aad, plaintext);

  for (const property of ['buffer', 'byteOffset', 'byteLength', 'length', 'subarray', Symbol.iterator]) {
    function viewWithUnusedProperty(bytes) {
      const storage = new Uint8Array(bytes.length + 6);
      const view = storage.subarray(3, 3 + bytes.length);
      view.set(bytes);
      Object.defineProperty(view, property, {
        get() { assert.fail(`AEAD read a caller property: ${String(property)}`); },
      });
      return view;
    }

    const keyView = viewWithUnusedProperty(key);
    const nonceView = viewWithUnusedProperty(nonce);
    const aadView = viewWithUnusedProperty(aad);
    assert.deepEqual(seal(keyView, nonceView, aadView, viewWithUnusedProperty(plaintext)), expected);
    assert.deepEqual(open(keyView, nonceView, aadView,
      viewWithUnusedProperty(expected.ciphertext), viewWithUnusedProperty(expected.tag)), plaintext);
  }
});
