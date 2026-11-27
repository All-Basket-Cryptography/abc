# ChaCha20-Poly1305 in C

Compile `abc_chacha20_poly1305_c.c` and the C11 ChaCha20 and Poly1305
cores. Add their include directories and include
`abc_chacha20_poly1305_c.h` in the consumer. `abc_chacha20_poly1305_c_seal`
outputs ciphertext and a detached 16-byte tag. An open call accepts the
exact tag length.

Supply a unique 96-bit nonce for each seal under the same key. Input,
output and associated data may overlap. The seal's detached tag has
separate storage from the ciphertext prefix. Opening authenticates the
full ciphertext and associated data before releasing plaintext.
Rejection preserves destination bytes.

The RFC example and 174 bidirectional OpenSSL 3.5.4 cases pass. Tests
exercise tagging, tampered data, output capacity and aliases. The
benchmark includes 16 bytes of associated data and changes its public
key and nonce inputs for each call in a sample.

The Windows x64 Clang 21.1.8 release and UBSan runs passed. Source
refinement and compiled-target leakage evidence remain open.
[RFC 8439 §§2.6–2.8 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.6) · [Lean AEAD lengths](../../spec/ChaCha20Poly1305Lengths.lean)

On the Intel Core i7-12700K test host, the medians were
288 ns for 64 bytes and 6793 ns for 4 KiB.
The native harness measures five batches of 1,024 calls with the
test bridge inside the timer.

In a Visual Studio developer shell on Windows, run from the
repository root with Python and Clang. Node provides the independent OpenSSL comparisons.

```sh
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language c --profile aead
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language c --profile aead --ubsan
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language c --profile aead --benchmark
```
