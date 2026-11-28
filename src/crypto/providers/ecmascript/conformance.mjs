import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, decapsulate, encapsulate, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const hex = text => new Uint8Array(Buffer.from(text, 'hex'));
const encode = bytes => Buffer.from(bytes).toString('hex');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const json = path => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const data = (size, seed) => Uint8Array.from({ length: size }, (_, i) => (i * 93 + seed * 157 + i * seed) & 255);

export function testArgon2id(api) {
  test('RFC 9106 with secret and AAD and 24 portable Rust comparisons', () => {
    const rfc = [32, 3, 4, 32, new Uint8Array(32).fill(1), new Uint8Array(16).fill(2),
      new Uint8Array(8).fill(3), new Uint8Array(12).fill(4)];
    const cases = Array.from({ length: 24 }, (_, i) => {
      const lanes = 1 + i % 4;
      return [8 * lanes + i % (4 * lanes), 1 + i % 3, lanes, [4, 32, 65][i % 3],
        data(i % 17, i), data(8 + i % 16, i + 1), data(i % 5, i + 2), data(i % 11, i + 3)];
    });
    const result = spawnSync('cargo', [
      '+1.92.0', 'run', '--manifest-path', 'tools/build/rust/Cargo.toml', '--release', '--locked', '--offline',
      '--quiet', '-p', 'abc-argon2id', '--example', 'differential',
    ], { cwd: root, input: cases.map(row => row.map(v => typeof v === 'number' ? v : encode(v)).join(':')).join('\n') + '\n',
      encoding: 'utf8', timeout: 120000 });
    assert.equal(result.status, 0, result.error?.message ?? result.stderr);
    const expected = result.stdout.trim().split(/\r?\n/);
    assert.equal(expected.length, cases.length);
    expected.push('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
    cases.push(rfc);
    for (let i = 0; i < cases.length; i += 1) {
      const [memoryKiB, passes, lanes, length, password, salt, secret, associatedData] = cases[i];
      const memoryLimit = api.workspaceBytes(memoryKiB, lanes) + length;
      const options = { memoryKiB, passes, lanes, length, secret, associatedData, memoryLimit };
      assert.equal(encode(api.derive(password, salt, options)), expected[i]);
      assert.throws(() => api.derive(password, salt, { ...options, memoryLimit: memoryLimit - 1 }), RangeError);
    }
    assert.equal(api.workspaceBytes(49, 3), 48 * 1024);
    assert.throws(() => api.workspaceBytes(23, 3), RangeError);
  });
}

export function testX25519(api) {
  test('RFC 7748 agreement, coordinate aliases and 32 independent public keys', () => {
    const alice = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const bob = hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    const a = api.publicKey(alice), b = api.publicKey(bob);
    assert.equal(encode(a), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    assert.equal(encode(b), 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    assert.equal(encode(api.sharedSecret(alice, b)), '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
    const alias = hex('f6' + 'ff'.repeat(30) + 'ff');
    assert.deepEqual(api.sharedSecret(alice, alias), a);
    assert.equal(api.sharedSecret(alice, new Uint8Array(32)), null);
    assert.equal(api.sharedSecret(alice, hex('ed' + 'ff'.repeat(30) + '7f')), null);
    assert.throws(() => api.sharedSecret(alice, new Uint8Array(31)), RangeError);
    for (let i = 0; i < 32; i += 1) {
      const seed = data(32, i);
      const other = x25519.getPublicKey(data(32, 32 + i));
      assert.deepEqual(api.publicKey(seed), x25519.getPublicKey(seed));
      assert.deepEqual(api.sharedSecret(seed, other), x25519.getSharedSecret(seed, other));
    }
  });
}

export function testEd25519(api) {
  test('RFC 8032 exact signature, strict points and 32 independent signatures', () => {
    const seed = hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    const key = api.publicKey(seed);
    const empty = new Uint8Array();
    assert.equal(encode(key), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    const signature = api.sign(seed, empty);
    assert.equal(encode(signature), 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
      + '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
    assert.equal(api.verify(key, empty, signature), true);
    const low = new Uint8Array(32);
    low[0] = 1;
    assert.equal(api.verify(low, empty, signature), false);
    const bad = new Uint8Array(signature);
    bad.set(low, 0);
    assert.equal(api.verify(key, empty, bad), false);
    bad.set(signature);
    bad.fill(255, 32);
    assert.equal(api.verify(key, empty, bad), false);
    for (let i = 0; i < 32; i += 1) {
      const secret = data(32, i), message = data(i * 7, i + 1);
      const expected = ed25519.sign(message, secret);
      assert.deepEqual(api.publicKey(secret), ed25519.getPublicKey(secret));
      assert.deepEqual(api.sign(secret, message), expected);
      assert.equal(api.verify(api.publicKey(secret), message, expected), true);
      assert.equal(api.verify(api.publicKey(secret), data(message.length + 1, i), expected), false);
    }
  });
}

export function testEcdsaP256(api) {
  test('RFC 6979 SHA-256 deterministic signatures and independent OpenSSL verification', () => {
    const secret = hex('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721');
    const publicBytes = api.publicKey(secret);
    assert.equal(encode(publicBytes), '0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6'
      + '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299');
    for (const [message, expected] of [
      ['sample', 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716'
        + 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8'],
      ['test', 'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367'
        + '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083'],
    ]) {
      const input = Buffer.from(message);
      assert.equal(encode(api.sign(secret, input)), expected);
      const compressed = Uint8Array.of(3, ...publicBytes.subarray(1, 33));
      assert.equal(api.verify(compressed, input, hex(expected)), true);
    }
    const encodeJwk = bytes => Buffer.from(bytes).toString('base64url');
    const native = createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: encodeJwk(secret),
      x: encodeJwk(publicBytes.subarray(1, 33)), y: encodeJwk(publicBytes.subarray(33)) }, format: 'jwk' });
    for (let i = 0; i < 24; i += 1) {
      const input = data(i * 9, i + 1);
      assert.equal(verify('sha256', input, { key: createPublicKey(native), dsaEncoding: 'ieee-p1363' }, api.sign(secret, input)), true);
      assert.equal(api.verify(publicBytes, input, sign('sha256', input, { key: native, dsaEncoding: 'ieee-p1363' })), true);
    }
    assert.equal(api.verify(Uint8Array.of(0), Buffer.from('sample'), new Uint8Array(64)), false);
    assert.throws(() => api.publicKey(new Uint8Array(32)), RangeError);
  });
}

export function testMlKem(api) {
  test('NIST ACVP public key vectors and two-way OpenSSL interoperability', () => {
    const fixture = json('../../agreement/ml-kem-768/spec/acvp.json');
    const prefix = Buffer.from('3054020100300b060960864801650304040204428040', 'hex');
    for (const row of fixture.cases.filter(row => row.d && row.z)) {
      const seed = hex(row.d + row.z);
      const pub = api.publicKey(seed);
      assert.equal(encode(pub), row.ek.toLowerCase());
      const key = createPrivateKey({ key: Buffer.concat([prefix, seed]), format: 'der', type: 'pkcs8' });
      const ours = api.encapsulate(pub);
      const upstream = encapsulate(createPublicKey(key));
      assert.equal(encode(decapsulate(key, ours.ciphertext)), encode(ours.sharedSecret));
      assert.equal(encode(api.decapsulate(seed, upstream.ciphertext)), encode(upstream.sharedKey));
      const changed = new Uint8Array(upstream.ciphertext);
      changed[0] ^= 1;
      assert.equal(encode(api.decapsulate(seed, changed)), encode(decapsulate(key, changed)));
      assert.throws(() => api.decapsulate(seed, changed.subarray(1)), RangeError);
    }
    const malformedKey = new Uint8Array(1184).fill(255);
    assert.throws(() => api.encapsulate(malformedKey));
  });
}

export function testMlDsa(api) {
  test('NIST ACVP key derivation and signature verdicts', () => {
    const fixture = json('../../signature/ml-dsa-65/spec/acvp-fips204-sample.json');
    const seed = hex(fixture.keyGen.seed);
    const pub = api.publicKey(seed);
    assert.equal(hash(pub), fixture.keyGen.public_key_sha256);
    for (const row of fixture.sigGen.cases) {
      assert.equal(api.verify(hex(row.pk), hex(row.message), hex(row.signature), hex(row.context)), true);
    }
    for (const row of fixture.sigVer.cases) {
      assert.equal(api.verify(hex(row.pk), hex(row.message), hex(row.signature), hex(row.context)), row.testPassed);
    }
    for (const context of [new Uint8Array(), Uint8Array.of(0, 255), data(255, 67)]) {
      const msg = data(73, 11);
      const signature = api.sign(seed, msg, context);
      assert.deepEqual(signature, api.sign(seed, msg, context));
      assert.equal(api.verify(pub, msg, signature, context), true);
      assert.equal(api.verify(pub, msg, signature, Uint8Array.of(7)), false);
      assert.equal(api.verify(pub, msg, signature.subarray(0, -1), context), false);
    }
    assert.throws(() => api.sign(seed, new Uint8Array(), new Uint8Array(256)), RangeError);
  });
}
