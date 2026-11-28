import { argon2Sync, createPrivateKey, createPublicKey, diffieHellman, sign, verify } from 'node:crypto';

const PRIVATE = {
  x25519: Buffer.from('302e020100300506032b656e04220420', 'hex'),
  ed25519: Buffer.from('302e020100300506032b657004220420', 'hex'),
};
const PUBLIC = {
  x25519: Buffer.from('302a300506032b656e032100', 'hex'),
  ed25519: Buffer.from('302a300506032b6570032100', 'hex'),
};

function privateKey(algorithm, seed) {
  const der = Buffer.concat([PRIVATE[algorithm], seed]);
  try {
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } finally {
    der.fill(0);
  }
}

function publicKey(algorithm, encoded) {
  return createPublicKey({ key: Buffer.concat([PUBLIC[algorithm], encoded]), format: 'der', type: 'spki' });
}

export function nativePublicKey(algorithm, seed) {
  const der = createPublicKey(privateKey(algorithm, seed)).export({ format: 'der', type: 'spki' });
  const prefix = PUBLIC[algorithm];
  if (der.length !== prefix.length + 32 || !der.subarray(0, prefix.length).equals(prefix)) {
    throw new Error('The provider returned an unexpected public key format');
  }
  return new Uint8Array(der.subarray(prefix.length));
}

export function nativeX25519(seed, peer) {
  try {
    const shared = diffieHellman({
      privateKey: privateKey('x25519', seed), publicKey: publicKey('x25519', peer),
    });
    let nonzero = 0;
    for (const byte of shared) nonzero |= byte;
    const result = nonzero === 0 ? null : new Uint8Array(shared);
    shared.fill(0);
    return result;
  } catch (error) {
    if (error?.code === 'ERR_OSSL_FAILED_DURING_DERIVATION') return null;
    throw error;
  }
}

export function nativeEd25519Sign(seed, message) {
  return new Uint8Array(sign(null, message, privateKey('ed25519', seed)));
}

export function nativeEd25519Verify(key, message, signature) {
  return verify(null, message, publicKey('ed25519', key), signature);
}

export function nativeArgon2id(parameters) {
  const output = argon2Sync('argon2id', parameters);
  const result = new Uint8Array(output);
  output.fill(0);
  return result;
}
