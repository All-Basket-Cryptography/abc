# ChaCha20 in Go

The standalone Go module implements the IETF ChaCha20 block and stream
functions. `Block` produces a 64-byte keystream block from a 32-byte key,
12-byte nonce, and 32-bit counter. `XOR` reads source bytes and writes the
equally long destination prefix. It supports overlapping buffers and
checks the block counter before writing. Aligned independent calls must
advance the counter by the number of blocks already processed. The
caller supplies a unique nonce for each message under a key. Use the
separate authenticated-encryption module when authenticity is required.
[RFC 8439 §§2.1–2.4 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.1) · [ChaCha, a variant of Salsa20](https://cr.yp.to/chacha/chacha-20080128.pdf)

The RFC block and multiblock encryption answers, counter limits, write
preservation on errors, and aliasing checks pass with Go 1.24.9 on
Windows amd64 and 386. Node 24.12 and OpenSSL 3.5.4 match 144 ciphertexts,
including the final counter. The ChaCha20 specification has verified
counter and quarter-round properties. Complete correspondence with the
Go source and compiled leakage testing are open.
[Lean counter model](../../spec/ChaCha20Counter.lean)

```sh
go test -C src/crypto/cipher/chacha20/impl/go -count=1 -v ./...
```

Node is required for the provider comparison. The RFC and buffer tests
run with Go alone.
