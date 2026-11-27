import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, diffieHellman } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const privatePrefix = Buffer.from('302e020100300506032b656e04220420', 'hex');
const publicPrefix = Buffer.from('302a300506032b656e032100', 'hex');
const root = fileURLToPath(new URL('../../../../../', import.meta.url));
const cases = [];

function bytes(label, index) {
  return createHash('sha256').update(`abc/x25519/${label}/${index}`).digest();
}

function privateKey(raw) {
  return createPrivateKey({ key: Buffer.concat([privatePrefix, raw]), format: 'der', type: 'pkcs8' });
}

function publicKey(raw) {
  return createPublicKey({ key: Buffer.concat([publicPrefix, raw]), format: 'der', type: 'spki' });
}

for (let index = 0; index < 128; index += 1) {
  const scalar = bytes('private', index);
  const privateObject = privateKey(scalar);
  const otherPublic = createPublicKey(privateKey(bytes('other-private', index)))
    .export({ type: 'spki', format: 'der' }).subarray(-32);
  const arbitraryPeer = bytes('arbitrary-peer', index);
  const expectedPublic = createPublicKey(privateObject).export({ type: 'spki', format: 'der' })
    .subarray(-32).toString('hex');
  cases.push({ input: scalar.toString('hex'), expected: expectedPublic });
  for (const peer of [otherPublic, arbitraryPeer]) {
    const expected = diffieHellman({ privateKey: privateObject, publicKey: publicKey(peer) });
    cases.push({
      input: `${scalar.toString('hex')} ${peer.toString('hex')}`,
      expected: expected.toString('hex'),
    });
  }
}

const child = spawnSync('cargo', ['+1.92.0', 'run', '--release', '--quiet', '--offline', '--locked',
  '--manifest-path', 'tools/build/rust/Cargo.toml', '-p', 'abc-x25519', '--example', 'x25519_differential'], {
  cwd: root, input: `${cases.map(test => test.input).join('\n')}\n`, encoding: 'utf8', timeout: 110000,
});
if (child.status !== 0) throw new Error(child.error?.message || child.stderr || 'Rust test program failed');
const results = child.stdout.trim().split(/\r?\n/);
assert.equal(results.length, cases.length);
for (const [index, test] of cases.entries()) {
  assert.equal(results[index], test.expected, `X25519 comparison ${index}`);
}
console.log(`${cases.length} X25519 comparisons passed (OpenSSL ${process.versions.openssl})`);
