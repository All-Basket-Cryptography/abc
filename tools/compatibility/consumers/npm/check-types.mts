import { createSha256Provider, type Sha256Context, type Sha256Provider } from 'abc-cryptography-research';

const provider: Sha256Provider = await createSha256Provider();
const context: Sha256Context = provider.create();
context.update(new Uint8Array([0x61]));
context.update(new Uint8Array([0x62, 0x63]));

const bytes: Uint8Array = context.finalize();
const digest = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
if (digest !== 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') {
  throw new Error('TypeScript consumer digest mismatch');
}
console.log('External TypeScript SHA-256 consumer passed');
