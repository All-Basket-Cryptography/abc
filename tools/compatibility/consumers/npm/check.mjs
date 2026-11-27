import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createSha256Provider } from 'abc-cryptography-research';

const provider = await createSha256Provider();
assert.equal(provider.identity.implementation, 'sha256-abc-rust-portable');
const abc = new TextEncoder().encode('abc');
const hex = bytes => Buffer.from(bytes).toString('hex');
assert.equal(hex(provider.digest(abc)), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

const streaming = provider.create();
const another = provider.create();
const large = Uint8Array.from({ length: 14000 }, (_, index) => index % 251);
streaming.update(large.subarray(0, 64));
another.update(abc);
streaming.update(large.subarray(64));
assert.equal(hex(streaming.finalize()), createHash('sha256').update(large).digest('hex'));
assert.equal(hex(another.finalize()), hex(provider.digest(abc)));
assert.throws(() => streaming.finalize(), /closed/);
assert.throws(() => another.update(abc), /closed/);
assert.throws(() => provider.digest('abc'), TypeError);
const abandoned = provider.create();
abandoned.dispose();
abandoned.dispose();
assert.throws(() => abandoned.update(abc), /closed/);
console.log('External Node SHA-256 consumer passed');
