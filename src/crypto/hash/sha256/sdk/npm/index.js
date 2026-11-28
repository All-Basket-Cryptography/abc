const maxBytes = (1n << 61n) - 1n;
const identity = Object.freeze({ implementation: 'sha256-abc-rust-portable', target: 'wasm32-unknown-unknown', status: 'research' });

async function loadDefaultBinary() {
  const url = new URL('./abc_sha256.wasm', import.meta.url);
  if (url.protocol === 'file:' && typeof process !== 'undefined' && process.versions?.node) {
    const { readFile } = await import('node:fs/promises');
    return readFile(url);
  }
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Could not load SHA-256 WASM (${response.status})`);
  return response.arrayBuffer();
}

export async function createSha256Provider() {
  const { instance } = await WebAssembly.instantiate(await loadDefaultBinary());
  const abi = instance.exports;
  if (abi.abc_abi_version() !== 1) throw new Error('Unsupported SHA-256 WASM ABI');
  const capacity = abi.abc_buffer_size();
  const address = abi.abc_buffer_address() >>> 0;
  const buffer = () => new Uint8Array(abi.memory.buffer, address, capacity);

  const create = () => {
    let handle = abi.abc_new();
    let length = 0n;
    if (!handle) throw new Error('SHA-256 context capacity exhausted');

    const requireActive = () => {
      if (!handle) throw new Error('SHA-256 context is closed');
    };
    const dispose = () => {
      if (handle) abi.abc_drop(handle);
      handle = 0;
    };
    return Object.freeze({
      update(bytes) {
        requireActive();
        if (!(bytes instanceof Uint8Array)) throw new TypeError('SHA-256 input must be a Uint8Array');
        const nextLength = length + BigInt(bytes.byteLength);
        if (nextLength > maxBytes) throw new RangeError('SHA-256 message exceeds the maximum byte length');
        for (let offset = 0; offset < bytes.byteLength; offset += capacity) {
          const chunk = Uint8Array.prototype.subarray.call(bytes, offset, offset + capacity);
          buffer().set(chunk);
          if (abi.abc_update(handle, chunk.byteLength) !== 0) {
            dispose();
            throw new Error('SHA-256 WASM update failed');
          }
        }
        length = nextLength;
      },
      finalize() {
        requireActive();
        const result = abi.abc_finish(handle);
        handle = 0;
        if (result !== 0) throw new Error('SHA-256 WASM finalize failed');
        return buffer().slice(0, 32);
      },
      dispose,
    });
  };
  return Object.freeze({
    identity,
    create,
    digest(bytes) {
      const context = create();
      try {
        context.update(bytes);
        return context.finalize();
      } finally {
        context.dispose();
      }
    },
  });
}
