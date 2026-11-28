import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { Sha256, sha256 } from './sha256.mts';

const encoder = new TextEncoder();

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function expected(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

test('one-shot fixed digests and million-byte split update', () => {
  assert.equal(hex(sha256(new Uint8Array())), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(hex(sha256(encoder.encode('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  const twoBlocks = encoder.encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
  assert.equal(hex(sha256(twoBlocks)), '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  const chunk = new Uint8Array(1000).fill(97);
  const stream = new Sha256();
  for (let i = 0; i < 1000; ++i) stream.update(chunk);
  assert.equal(hex(stream.digest()), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
});

test('digest is independent of splits and view offsets', () => {
  for (const length of [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 257]) {
    const outer = Uint8Array.from({ length: length + 4 }, (_, i) => 79 * i);
    const data = outer.subarray(2, 2 + length);
    const digest = expected(data);
    for (let i = 0; i <= length; ++i) {
      const stream = new Sha256();
      stream.update(data.subarray(0, i)).update(new Uint8Array()).update(data.subarray(i));
      assert.equal(hex(stream.digest()), digest, `length ${length}, split ${i}`);
    }
  }
});

test('deterministic differential inputs and intermediate snapshots', () => {
  let seed = 0x8a6329d7;
  const next = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
  for (let run = 0; run < 256; ++run) {
    const data = Uint8Array.from({ length: next() % 4097 }, () => next() >>> 24);
    const digest = expected(data);
    const limit = next() % (data.length + 1);
    const stream = new Sha256().update(data.subarray(0, limit));
    const earlyDigest = stream.digest();
    assert.equal(hex(earlyDigest), expected(data.subarray(0, limit)));
    earlyDigest.fill(0);
    const chunk = 1 + (next() % 137);
    for (let start = limit; start < data.length; start += chunk) stream.update(data.subarray(start, start + chunk));
    assert.equal(hex(stream.digest()), digest);
    assert.equal(hex(sha256(data)), digest);
  }
});

test('caller buffers can change, bad input leaves state intact, reset clears it', () => {
  const original = encoder.encode('abc');
  const stream = new Sha256().update(original);
  original.fill(0);
  assert.throws(() => stream.update(new DataView(new ArrayBuffer(1)) as unknown as Uint8Array), TypeError);
  assert.equal(hex(stream.digest()), expected(encoder.encode('abc')));
  stream.reset();
  assert.equal(hex(stream.digest()), expected(new Uint8Array()));
});

test('copied prefix state owns its pending bytes, chaining words and length', () => {
  const referenceHash = expected;
  for (const size of [0, 1, 55, 56, 63, 64, 65, 120, 128, 129]) {
    const prefix = Uint8Array.from({ length: size }, (_, i) => 67 * i + 11);
    const left = Uint8Array.of(3, 5, 7);
    const right = new Uint8Array(69).fill(23);
    const source = new Sha256().update(prefix);
    const copy = new Sha256().update(new Uint8Array(127).fill(19));
    assert.equal(copy.copyFrom(source), copy);
    assert.equal(hex(copy.digest()), referenceHash(prefix));
    assert.throws(() => copy.copyFrom({} as Sha256), TypeError);
    source.update(left);
    copy.copyFrom(copy).update(right);
    assert.equal(hex(source.digest()), referenceHash(Uint8Array.of(...prefix, ...left)));
    assert.equal(hex(copy.digest()), referenceHash(Uint8Array.of(...prefix, ...right)));
    source.reset();
    copy.copyFrom(source);
    assert.equal(hex(copy.digest()), referenceHash(new Uint8Array()));
  }
});
