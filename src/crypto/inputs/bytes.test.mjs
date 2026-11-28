import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import * as js from './bytes.mjs';
import * as ts from './bytes.mts';

for (const [name, { asUint8Array: normalize, asUint32Array: normalizeWords }] of [['JavaScript', js], ['TypeScript', ts]]) {
  test(`${name} uses intrinsic view properties and preserves its byte range`, () => {
    class ByteView extends Uint8Array {
      get buffer() { throw new Error('Own getter must stay untouched'); }
      get byteOffset() { throw new Error('Own getter must stay untouched'); }
      get byteLength() { throw new Error('Own getter must stay untouched'); }
      get length() { throw new Error('Own getter must stay untouched'); }
    }
    const storage = new Uint8Array([10, 20, 30, 40]);
    const normalized = normalize(new ByteView(storage.buffer, 1, 2));
    assert.equal(Object.getPrototypeOf(normalized), Uint8Array.prototype);
    assert.deepEqual(normalized, Uint8Array.of(20, 30));
    normalized[0] = 90;
    assert.deepEqual(storage, Uint8Array.of(10, 90, 30, 40));
    assert.deepEqual(normalize(runInNewContext('Uint8Array.of(17, 49)')), Uint8Array.of(17, 49));
  });

  test(`${name} rejects shared, detached, and out-of-bounds backing views`, () => {
    assert.throws(() => normalize(new Uint8Array(new SharedArrayBuffer(4))), TypeError);
    assert.throws(() => normalize(new Uint16Array(1)), TypeError);
    assert.throws(() => normalize(Object.create(Uint8Array.prototype)), TypeError);
    const detached = new Uint8Array(1);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    assert.throws(() => normalize(detached), TypeError);
    const resizable = new ArrayBuffer(8, { maxByteLength: 16 });
    const view = new Uint8Array(resizable, 4, 4);
    resizable.resize(2);
    assert.throws(() => normalize(view), TypeError);
    assert.deepEqual(normalize(new Uint8Array(0)), Uint8Array.of());
  });

  test(`${name} uses element lengths and preserves a fixed word range in resizable storage`, () => {
    const resizable = new ArrayBuffer(16, { maxByteLength: 36 });
    const tracking = new Uint32Array(resizable, 4);
    tracking.set([17, 49, 81]);
    Object.defineProperty(tracking, 'length', { get() { throw new Error('Own length'); } });
    const fixed = normalizeWords(tracking);
    resizable.resize(24);
    assert.deepEqual(fixed, Uint32Array.of(17, 49, 81));
    assert.equal(fixed.byteOffset, 4);
    assert.throws(() => normalizeWords(new Uint32Array(new SharedArrayBuffer(4))), TypeError);
    resizable.resize(4);
    assert.deepEqual(normalizeWords(tracking), Uint32Array.of());
    assert.throws(() => normalizeWords(fixed), TypeError);
    resizable.resize(0);
    assert.throws(() => normalizeWords(tracking), TypeError);
  });
}
