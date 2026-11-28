export interface Sha256Context {
  update(bytes: Uint8Array): void;
  finalize(): Uint8Array;
  dispose(): void;
}

export interface Sha256Provider {
  readonly identity: Readonly<{
    implementation: 'sha256-abc-rust-portable';
    target: 'wasm32-unknown-unknown';
    status: 'research';
  }>;
  create(): Sha256Context;
  digest(bytes: Uint8Array): Uint8Array;
}

export function createSha256Provider(): Promise<Sha256Provider>;
