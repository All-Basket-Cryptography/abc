type Curve = 'x25519' | 'ed25519';
export function nativePublicKey(algorithm: Curve, seed: Uint8Array): Uint8Array;
export function nativeX25519(seed: Uint8Array, peer: Uint8Array): Uint8Array | null;
export function nativeEd25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array;
export function nativeEd25519Verify(key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
export function nativeArgon2id(parameters: {
  message: Uint8Array;
  nonce: Uint8Array;
  secret: Uint8Array;
  associatedData: Uint8Array;
  parallelism: number;
  tagLength: number;
  memory: number;
  passes: number;
}): Uint8Array;
