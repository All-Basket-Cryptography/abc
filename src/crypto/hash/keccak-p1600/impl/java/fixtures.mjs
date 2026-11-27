import { createHash } from 'node:crypto';

const inputs = [0, 1, 135, 136, 137, 271, 272, 273, 1000].map(length =>
  Buffer.from(Array.from({ length }, (_, i) => (131 * i) & 255)));
inputs.push(Buffer.from('abc'), Buffer.alloc(200, 0xa3));

for (const [i, message] of inputs.entries()) {
  const sha3 = createHash('sha3-256').update(message).digest('hex');
  const shake = createHash('shake256', { outputLength: 409 }).update(message).digest('hex');
  if (i === 0 && (sha3 !== 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a' ||
      shake.slice(0, 64) !== '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f')) {
    throw new Error('provider disagrees with the empty input vectors');
  }
  if (i === 9 && (sha3 !== '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532' ||
      shake.slice(0, 64) !== '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739')) {
    throw new Error('provider disagrees with the abc vectors');
  }
  if (i === 10 && sha3 !== '79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787') {
    throw new Error('provider disagrees with the NIST 1600-bit SHA3-256 vector');
  }
  console.log([message.toString('hex'), sha3, shake].join(':'));
}
