import { derive, workspaceSize } from './scrypt.mjs';
import assert from 'node:assert/strict';
import { scryptSync } from 'node:crypto';
import { test } from 'node:test';

const maxmem = 128 * 1024 * 1024;
const expectedEmpty = '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fc' +
  'd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906';
const expectedLanes = 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622' +
  'eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640';

test('RFC 7914 empty and sixteen-lane vectors', () => {
  const empty = new Uint8Array();
  assert.equal(Buffer.from(derive(empty, empty,
    { cost: 16, blockSize: 1, parallel: 1, length: 64, memoryLimit: maxmem })).toString('hex'),
  expectedEmpty);
  assert.equal(Buffer.from(derive(Buffer.from('password'), Buffer.from('NaCl'),
    { cost: 1024, blockSize: 8, parallel: 16, length: 64, memoryLimit: maxmem })).toString('hex'),
  expectedLanes);
});

test('144 independent OpenSSL cases across parameter and length boundaries', () => {
  let trial = 0;
  for (const cost of [2, 4, 16, 32]) {
    for (const blockSize of [1, 2, 4]) {
      for (const parallel of [1, 2, 3]) {
        for (const length of [1, 32, 33, 71]) {
          const password = Uint8Array.from({ length: trial % 75 }, (_, i) => (trial * 47 + i * 91) & 255);
          const salt = Uint8Array.from({ length: (trial * 13) % 68 }, (_, i) => (trial * 81 + i * 71) & 255);
          const needed = workspaceSize(cost, blockSize, parallel);
          const actual = derive(password, salt, { cost, blockSize, parallel, length, memoryLimit: needed + length });
          assert.deepEqual(Buffer.from(actual), scryptSync(password, salt, length,
            { N: cost, r: blockSize, p: parallel, maxmem }));
          trial += 1;
        }
      }
    }
  }
  assert.equal(trial, 144);
});

test('workspace limits and RFC parameters reject before derivation', () => {
  const blank = new Uint8Array();
  assert.throws(() => workspaceSize(65536, 1, 1), RangeError);
  assert.throws(() => workspaceSize(3, 1, 1), RangeError);
  assert.throws(() => workspaceSize(32, 0, 1), RangeError);
  assert.throws(() => workspaceSize(16, 8, Number.MAX_SAFE_INTEGER), RangeError);
  assert.throws(() => workspaceSize(2 ** 30, 8, 1), RangeError);
  const required = workspaceSize(2, 1, 1);
  assert.equal(required, 768);
  assert.throws(() => derive(blank, blank,
    { cost: 2, blockSize: 1, parallel: 1, length: 32, memoryLimit: required + 31 }), RangeError);
  assert.throws(() => derive(new Uint8Array(new SharedArrayBuffer(4)), blank,
    { cost: 2, blockSize: 1, parallel: 1, length: 32, memoryLimit: required + 32 }), TypeError);
});
