// The narrow built-in Node API used by the synchronous AES-GCM wrapper.
declare module 'node:crypto' {
  interface AbcGcmCipher {
    setAAD(bytes: Uint8Array): void;
    update(bytes: Uint8Array): Uint8Array;
    final(): Uint8Array;
    getAuthTag(): Uint8Array;
  }

  interface AbcGcmDecipher {
    setAAD(bytes: Uint8Array): void;
    setAuthTag(bytes: Uint8Array): void;
    update(bytes: Uint8Array): Uint8Array;
    final(): Uint8Array;
  }

  function createCipheriv(algorithm: 'aes-256-gcm', key: Uint8Array, iv: Uint8Array,
    options: { authTagLength: 16 }): AbcGcmCipher;
  function createDecipheriv(algorithm: 'aes-256-gcm', key: Uint8Array, iv: Uint8Array,
    options: { authTagLength: 16 }): AbcGcmDecipher;
}
