import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { performance } from 'node:perf_hooks';
import { ml_kem768 } from '../../src/crypto/providers/ecmascript/noble.mjs';

const inputs = {
  message: Buffer.from(Array.from({ length: 1024 }, (_, i) => (i * 137) ^ (i >>> 5))),
  key: Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1)),
  nonce: Buffer.from('000000000000000000000002', 'hex'),
  salt: Buffer.from('public benchmark salt'),
  aad: Buffer.from('ABC public timing fixture'),
};
const { message, key, nonce, salt, aad } = inputs;
const seed = Buffer.concat([key, Buffer.alloc(32, 0x9b)]);
const hashes = [
  ['sha256', 'sha256', 'sha256', 32],
  ['sha512', 'sha512', 'sha512', 64],
  ['sha3-256', 'sha3_256', 'sha3-256', 32],
  ['shake256', 'shake256', 'shake256', 32],
  ['blake2b', 'blake2b', 'blake2b512', 64],
];

const cipherOutput = (cipher, bytes) => Buffer.concat([cipher.update(bytes), cipher.final()]);
const privateKey = (prefix, bytes) => crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from(prefix, 'hex'), bytes]), format: 'der', type: 'pkcs8',
});
const publicKey = (prefix, bytes) => crypto.createPublicKey({
  key: Buffer.concat([Buffer.from(prefix, 'hex'), bytes]), format: 'der', type: 'spki',
});
const packAead = ({ ciphertext, tag }) => Buffer.concat([ciphertext, tag]);

async function loadPair(path, source) {
  const leaf = new URL(`../../src/crypto/${path}/impl/`, import.meta.url);
  return Promise.all([
    import(new URL(`javascript/${source}.mjs`, leaf)),
    import(new URL(`typescript/${source}.mts`, leaf)),
  ]);
}

const workloads = [];

function record(path, description, pair, call, provider) {
  workloads.push({ profile: path.split('/')[1], description, pair, call, provider });
}

async function setup(path, source, description, call, provider) {
  record(path, description, await loadPair(path, source), call, provider);
}

for (const [slug, source, providerName, size] of hashes) {
  const args = slug === 'shake256' ? [message, size] : [message];
  const options = slug === 'shake256' ? { outputLength: size } : undefined;
  await setup(`hash/${slug}`, source, `1024 input bytes, ${size} output bytes`,
    sdk => sdk[source](...args), () => crypto.createHash(providerName, options).update(message).digest());
}

await setup('mac/hmac-sha256', 'hmac', '32-byte key, 1024-byte message',
  sdk => sdk.authenticate(key, message), () => crypto.createHmac('sha256', key).update(message).digest());

await setup('kdf/hkdf-sha256', 'hkdf', '32-byte input key, 64-byte output',
  sdk => sdk.derive(salt, key, aad, 64), () => Buffer.from(crypto.hkdfSync('sha256', key, salt, aad, 64)));

await setup('kdf/pbkdf2-hmac-sha256', 'pbkdf2', '256 iterations, 32-byte output',
  sdk => sdk.derive(key, salt, 256, 32), () => crypto.pbkdf2Sync(key, salt, 256, 32, 'sha256'));

const scrypt = { cost: 1024, blockSize: 8, parallel: 1, length: 32, memoryLimit: 4 * 1024 ** 2 };
await setup('kdf/scrypt', 'scrypt', 'N=1024, r=8, p=1, 32-byte output',
  sdk => sdk.derive(key, salt, scrypt), () => crypto.scryptSync(key, salt, scrypt.length, {
    N: scrypt.cost, r: scrypt.blockSize, p: scrypt.parallel, maxmem: scrypt.memoryLimit,
  }));

const argon = { memoryKiB: 1024, lanes: 1, passes: 2, length: 32, memoryLimit: 1024 ** 2 + 32 };
await setup('kdf/argon2id', 'argon2id', '1024 KiB, two passes, one lane, 32-byte output',
  sdk => sdk.derive(key, salt, argon), () => crypto.argon2Sync('argon2id', {
    message: key, nonce: salt, memory: argon.memoryKiB, passes: argon.passes,
    parallelism: argon.lanes, tagLength: argon.length,
  }));

await setup('cipher/aes256', 'aes256', 'one 16-byte block including key schedule',
  sdk => new sdk.Aes256(key).encrypt(message.subarray(0, 16)), () => {
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    cipher.setAutoPadding(false);
    return cipherOutput(cipher, message.subarray(0, 16));
  });

for (const [profile, source] of [['aes256-gcm', 'aes256gcm'], ['chacha20-poly1305', 'chacha20poly1305']]) {
  const algorithm = profile === 'aes256-gcm' ? 'aes-256-gcm' : profile;
  await setup(`aead/${profile}`, source, 'seal 1024 bytes, 25-byte AAD, 16-byte tag',
    sdk => packAead(sdk.seal(key, nonce, aad, message)), () => {
      const cipher = crypto.createCipheriv(algorithm, key, nonce, { authTagLength: 16 });
      cipher.setAAD(aad);
      return Buffer.concat([cipherOutput(cipher, message), cipher.getAuthTag()]);
    });
}
const nativeAesGcm = await loadPair('aead/aes256-gcm', 'node');
workloads.find(({ profile }) => profile === 'aes256-gcm').native = nativeAesGcm;

const chachaIv = Buffer.concat([Buffer.from([1, 0, 0, 0]), nonce]);
await setup('cipher/chacha20', 'chacha20', 'XOR 1024 bytes, IETF counter starts at 1',
  sdk => {
    const output = Uint8Array.from(message);
    sdk.applyKeystream(key, nonce, 1, output);
    return output;
  }, () => cipherOutput(crypto.createCipheriv('chacha20', key, chachaIv), message));

await setup('mac/poly1305', 'poly1305', 'one-time MAC on 1024 bytes',
  sdk => sdk.authenticate(key, message));

const xPath = 'agreement/x25519';
const x = await loadPair(xPath, 'x25519');
const peer = x[0].publicKey(seed.subarray(32));
record(xPath, 'shared secret including key import', x, sdk => sdk.sharedSecret(key, peer),
  () => crypto.diffieHellman({
    privateKey: privateKey('302e020100300506032b656e04220420', key),
    publicKey: publicKey('302a300506032b656e032100', peer),
  }));

for (const [profile, source, algorithm, prefix] of [
  ['ed25519', 'ed25519', null, '302a300506032b6570032100'],
  ['ecdsa-p256-sha256', 'ecdsa_p256', 'sha256', '3059301306072a8648ce3d020106082a8648ce3d030107034200'],
]) {
  const path = `signature/${profile}`;
  const pair = await loadPair(path, source);
  const encoded = pair[0].publicKey(key);
  const signature = pair[0].sign(key, message);
  record(path, 'verify 1024-byte message including key import', pair,
    sdk => sdk.verify(encoded, message, signature),
    () => crypto.verify(algorithm, message, { key: publicKey(prefix, encoded), dsaEncoding: 'ieee-p1363' }, signature));
}

const kemPath = 'agreement/ml-kem-768';
const kem = await loadPair(kemPath, 'ml_kem_768');
const { cipherText: kemCiphertext, sharedSecret } =
  ml_kem768.encapsulate(kem[0].publicKey(seed), Buffer.alloc(32, 0xa7));
const decap = sdk => sdk.decapsulate(seed, kemCiphertext);
assert.deepEqual(Buffer.from(decap(kem[0])), Buffer.from(sharedSecret));
record(kemPath, 'decapsulate 1088-byte ciphertext from 64-byte seed', kem, decap,
  () => crypto.decapsulate(privateKey('3054020100300b060960864801650304040204428040', seed), kemCiphertext));

const dsaPath = 'signature/ml-dsa-65';
const dsa = await loadPair(dsaPath, 'ml_dsa_65');
const dsaKey = dsa[0].publicKey(key);
const dsaSig = dsa[0].sign(key, message);
const dsaPrefix = '308207b2300b0609608648016503040312038207a100';
record(dsaPath, 'verify 1024-byte message, empty context, including key import', dsa,
  sdk => sdk.verify(dsaKey, message, dsaSig),
  () => crypto.verify(null, message, publicKey(dsaPrefix, dsaKey), dsaSig));

const samples = 7;
let checksum = 0;
function countFor(operation) {
  const start = performance.now();
  for (let i = 0; i < 8; i += 1) operation();
  return Math.max(1, Math.min(2048, Math.round(64 / Math.max(0.01, performance.now() - start))));
}
function measure(operation, count) {
  const start = performance.now();
  for (let i = 0; i < count; i += 1) {
    const value = operation();
    checksum = (Math.imul(checksum, 16777619) ^ (typeof value === 'boolean' ? Number(value) : value[0])) >>> 0;
  }
  return Math.round((performance.now() - start) * 1000 / count * 100) / 100;
}
function describe(observations, count) {
  const sorted = [...observations].sort((a, b) => a - b);
  return { count, median: sorted[samples >> 1], min: sorted[0], max: sorted.at(-1) };
}
const normalized = value => typeof value === 'boolean' ? value : Buffer.from(value);

const results = workloads.map(({ profile, description, pair, call, provider, native }) => {
  const methods = [['javascript', () => call(pair[0])], ['typescript', () => call(pair[1])]];
  if (provider) methods.push(['node_openssl', provider]);
  if (native) methods.push(['javascript_node', () => call(native[0])], ['typescript_node', () => call(native[1])]);
  const expected = normalized(methods[0][1]());
  if (typeof expected === 'boolean') assert.equal(expected, true, profile);
  for (const [name, operation] of methods) assert.deepEqual(normalized(operation()), expected, `${profile}: ${name}`);
  const counts = methods.map(([, fn]) => countFor(fn));
  const observations = methods.map(() => []);
  for (let trial = 0; trial < samples; trial += 1) {
    for (let offset = 0; offset < methods.length; offset += 1) {
      const i = (offset + trial) % methods.length;
      observations[i].push(measure(methods[i][1], counts[i]));
    }
  }
  return { profile, workload: description, results: Object.fromEntries(methods.map(([name], i) =>
    [name, describe(observations[i], counts[i])])) };
});
assert.equal(new Set(results.map(({ profile }) => profile)).size, 20);
console.log(JSON.stringify({
  node: process.version, openssl: process.versions.openssl, cpu: cpus()[0].model,
  platform: process.platform, arch: process.arch, units: 'microseconds per operation',
  runnerSha256: crypto.createHash('sha256').update(readFileSync(new URL(import.meta.url))).digest('hex'),
  warmupCalls: 8, samples, checksum, results,
}, null, 2));
