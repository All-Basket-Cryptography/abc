import assert from 'node:assert/strict';
import test from 'node:test';
import { ml_kem768 } from '../../../src/crypto/providers/ecmascript/noble.mjs';

const variants = { javascript: 'mjs', typescript: 'mts' };
const key = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const nonce = new Uint8Array(12);
const message = Uint8Array.from({ length: 277 }, (_, i) => (i * 37) & 255);
const salt = new TextEncoder().encode('public fixture salt');
const aad = Uint8Array.of(3, 17, 93);
const context = Uint8Array.of(7, 9);
const seed = Uint8Array.from({ length: 64 }, (_, i) => 255 - i);
const scrypt = { cost: 16, blockSize: 1, parallel: 1, length: 32, memoryLimit: 4096 };
const argon = { memoryKiB: 32, lanes: 1, passes: 1, length: 32, memoryLimit: 32768 + 32 };

function apiRun(args, call) {
  return { args, call };
}

function aead(sdk) {
  const { ciphertext, tag } = sdk.seal(key, nonce, aad, message);
  return [
    apiRun([key, nonce, aad, message], (a) => sdk.seal(...a)),
    apiRun([key, nonce, aad, ciphertext, tag], (a) => sdk.open(...a)),
  ];
}

function signatures(sdk, extra = []) {
  const encoded = sdk.publicKey(key);
  const signature = sdk.sign(key, message, ...extra);
  return [
    apiRun([key, message, ...extra], (a) => sdk.sign(...a)),
    apiRun([encoded, message, signature, ...extra], (a) => sdk.verify(...a)),
  ];
}

const profiles = [
  ['hash/sha256', 'sha256', (s) => [apiRun([message], (a) => s.sha256(...a))]],
  ['hash/sha512', 'sha512', (s) => [apiRun([message], (a) => s.sha512(...a))]],
  ['hash/sha3-256', 'sha3_256', (s) => [apiRun([message], (a) => s.sha3_256(...a))]],
  ['hash/shake256', 'shake256', (s) => [
    apiRun([message], ([bytes]) => s.shake256(bytes, 321)),
    apiRun([message, new Uint8Array(321)], ([bytes, output], visible) => {
      const reader = new s.Shake256().update(bytes).finalize();
      assert.equal(reader.readInto(output), 321);
      return visible[1];
    }),
  ]],
  ['hash/blake2b', 'blake2b', (s) => [apiRun([message], ([bytes]) => s.blake2b(bytes, 32))]],
  ['mac/hmac-sha256', 'hmac', (s) => [apiRun([key, message], (a) => s.authenticate(...a))]],
  ['kdf/hkdf-sha256', 'hkdf', (s) => [
    apiRun([salt, key, aad], ([salt, input, info]) => s.derive(salt, input, info, 65)),
    apiRun([key, aad], ([prk, info]) => s.expand(prk, info, 0)),
  ]],
  ['kdf/pbkdf2-hmac-sha256', 'pbkdf2', (s) => [
    apiRun([key, salt], ([password, salt]) => s.derive(password, salt, 3, 65)),
  ]],
  ['kdf/scrypt', 'scrypt', (s) => [
    apiRun([key, salt], ([password, salt]) => s.derive(password, salt, scrypt)),
  ]],
  ['kdf/argon2id', 'argon2id', (s) => [
    apiRun([key, salt, aad, context], ([password, salt, secret, associatedData]) =>
      s.derive(password, salt, { ...argon, secret, associatedData })),
  ]],
  ['cipher/aes256', 'aes256', (s) => [
    apiRun([key, message.subarray(0, 16)], ([key, block]) => new s.Aes256(key).encrypt(block)),
  ]],
  ['aead/aes256-gcm', 'aes256gcm', aead],
  ['cipher/chacha20', 'chacha20', (s) => [
    apiRun([key, nonce, message], ([key, nonce, out], visible) => {
      s.applyKeystream(key, nonce, 1, out);
      return visible[2];
    }),
  ]],
  ['mac/poly1305', 'poly1305', (s) => [apiRun([key, message], (a) => s.authenticate(...a))]],
  ['aead/chacha20-poly1305', 'chacha20poly1305', aead],
  ['agreement/x25519', 'x25519', (s) => [
    apiRun([key, s.publicKey(seed.subarray(0, 32))], (a) => s.sharedSecret(...a)),
  ]],
  ['signature/ed25519', 'ed25519', (s) => signatures(s)],
  ['signature/ecdsa-p256-sha256', 'ecdsa_p256', (s) => signatures(s)],
  ['agreement/ml-kem-768', 'ml_kem_768', (s) => {
    const encoded = s.publicKey(seed);
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(encoded, new Uint8Array(32).fill(0x58));
    assert.deepEqual(s.decapsulate(seed, cipherText), sharedSecret);
    return [
      apiRun([seed], (a) => s.publicKey(...a)),
      apiRun([seed, cipherText], (a) => s.decapsulate(...a)),
    ];
  }],
  ['signature/ml-dsa-65', 'ml_dsa_65', (s) => signatures(s, [context])],
];

function ordinary(bytes) {
  return { argument: bytes, visible: bytes };
}

function viewAtOffset(bytes) {
  const buffer = new ArrayBuffer(bytes.length + 9, { maxByteLength: bytes.length + 16 });
  const visible = new Uint8Array(buffer, 3, bytes.length);
  visible.set(bytes);
  const argument = new Uint8Array(buffer, 3, bytes.length);
  for (const property of ['buffer', 'byteOffset', 'byteLength', 'length', 'subarray', 'slice', 'set', 'constructor']) {
    Object.defineProperty(argument, property, {
      get() { throw new Error(`Cryptographic API accessed caller property ${property}`); },
    });
  }
  return { argument, visible };
}

function shared(bytes) {
  const argument = new Uint8Array(new SharedArrayBuffer(bytes.length));
  argument.set(bytes);
  return { argument, visible: argument };
}

function detached(bytes) {
  const argument = Uint8Array.from(bytes);
  structuredClone(argument.buffer, { transfer: [argument.buffer] });
  return { argument, visible: argument };
}

function run({ args, call }, slot = -1, variant = ordinary) {
  const supplied = args.map((bytes, i) => (i === slot ? variant : ordinary)(Uint8Array.from(bytes)));
  return call(supplied.map(({ argument }) => argument), supplied.map(({ visible }) => visible));
}

assert.equal(profiles.length, 20);
for (const [language, extension] of Object.entries(variants)) {
  for (const [profile, file, cases] of profiles) {
    test(`${language} ${profile} byte-view inputs`, async () => {
      const sdk = await import(new URL(`../../../src/crypto/${profile}/impl/${language}/${file}.${extension}`, import.meta.url));
      for (const item of cases(sdk)) {
        const expected = run(item);
        for (let slot = 0; slot < item.args.length; slot += 1) {
          assert.deepEqual(run(item, slot, viewAtOffset), expected);
          assert.throws(() => run(item, slot, shared), TypeError);
          assert.throws(() => run(item, slot, detached), TypeError);
        }
      }
    });
  }

  test(`${language} rejected updates and squeeze outputs preserve state`, async () => {
    for (const [profile, file, className] of [
      ['sha256', 'sha256', 'Sha256'], ['sha512', 'sha512', 'Sha512'], ['sha3-256', 'sha3_256', 'Sha3_256'],
    ]) {
      const sdk = await import(new URL(`../../../src/crypto/hash/${profile}/impl/${language}/${file}.${extension}`, import.meta.url));
      const state = new sdk[className]().update(message.subarray(0, 129));
      const expected = state.digest();
      for (const variant of [shared, detached]) assert.throws(() => state.update(variant(aad).argument), TypeError);
      assert.deepEqual(state.digest(), expected);
      assert.deepEqual(state.update(message).digest(),
        new sdk[className]().update(message.subarray(0, 129)).update(message).digest());
    }
    const sdk = await import(new URL(`../../../src/crypto/hash/shake256/impl/${language}/shake256.${extension}`, import.meta.url));
    const reader = new sdk.Shake256().update(message).finalize();
    reader.read(135);
    for (const variant of [shared, detached]) assert.throws(() => reader.readInto(variant(aad).argument), TypeError);
    assert.deepEqual(reader.read(251), sdk.shake256(message, 386).subarray(135));
  });

  test(`${language} Keccak writes only the supplied word view`, async () => {
    const sdk = await import(new URL(`../../../src/crypto/hash/keccak-p1600/impl/${language}/keccak.${extension}`, import.meta.url));
    const full = new Uint32Array(52).fill(0x76543210);
    const expected = new Uint32Array(50).fill(0x76543210);
    const view = new Uint32Array(full.buffer, 4, 50);
    Object.defineProperty(view, 'length', { get() { throw new Error('Caller length was accessed'); } });
    sdk.permute(expected);
    sdk.permute(view);
    assert.deepEqual(full.subarray(1, 51), expected);
    assert.equal(full[0], 0x76543210);
    assert.equal(full[51], 0x76543210);
    assert.throws(() => sdk.permute(new Uint32Array(new SharedArrayBuffer(200))), TypeError);
    assert.throws(() => sdk.permute(new Uint32Array(49)), TypeError);
  });
}
