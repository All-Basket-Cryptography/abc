import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { Blake2b, blake2b } from './blake2b.mts';

const hex = bytes => Buffer.from(bytes).toString('hex');

test('RFC 7693 Appendix A, empty input, and digest-length parameter binding', () => {
  assert.equal(hex(blake2b(Buffer.from('abc'))),
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1' +
    '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923');
  assert.equal(hex(blake2b(new Uint8Array())),
    '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419' +
    'd25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce');
  assert.notEqual(hex(blake2b(Buffer.from('abc'), 17)), hex(blake2b(Buffer.from('abc')).subarray(0, 17)));
});

test('576 CPython oracle cases, 9 OpenSSL checks and 2,304 incremental splits', () => {
  const messages = [0, 1, 2, 31, 127, 128, 129, 255, 258].map(size =>
    Buffer.from(Uint8Array.from({ length: size }, (_, i) => (i * 67 + size) & 255)));
  const command = process.env.ABC_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
  const python = 'import hashlib,json,sys; print(json.dumps([[hashlib.blake2b(bytes.fromhex(m), digest_size=n).hexdigest() for n in range(1, 65)] for m in json.load(sys.stdin)]))';
  const expected = JSON.parse(execFileSync(command, ['-B', '-c', python], { input: JSON.stringify(messages.map(hex)) }));
  for (const [i, message] of messages.entries()) {
    assert.equal(hex(blake2b(message)), createHash('blake2b512').update(message).digest('hex'));
    for (let length = 1; length <= 64; length += 1) {
      const result = expected[i][length - 1];
      assert.equal(hex(blake2b(message, length)), result);
      for (const split of [0, message.length >>> 1, Math.max(0, message.length - 1), message.length]) {
        const hasher = new Blake2b(length).update(message.subarray(0, split));
        if (length === 64) {
          assert.equal(hex(hasher.digest()), createHash('blake2b512').update(message.subarray(0, split)).digest('hex'));
        }
        hasher.update(new Uint8Array()).update(message.subarray(split));
        assert.equal(hex(hasher.digest()), result);
        assert.equal(hex(hasher.digest()), result);
      }
    }
  }
});

test('rejects invalid parameters and changes no state on detached or shared input', () => {
  for (const length of [0, 65, NaN, 1.5]) assert.throws(() => new Blake2b(length), RangeError);
  const hasher = new Blake2b(20).update(Buffer.from('abc'));
  const saved = hasher.digest();
  const detached = new Uint8Array(1);
  structuredClone(detached, { transfer: [detached.buffer] });
  assert.throws(() => hasher.update(detached), TypeError);
  assert.throws(() => hasher.update(new Uint8Array(new SharedArrayBuffer(1))), TypeError);
  const released = hasher.digest();
  released.fill(0);
  assert.deepEqual(hasher.digest(), saved);
});
