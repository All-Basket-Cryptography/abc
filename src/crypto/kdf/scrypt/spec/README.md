# scrypt

The portable Rust implementation composes RFC 7914's PBKDF2-HMAC-SHA-256,
Salsa20/8, BlockMix and ROMix. The caller supplies the memory for the
initial parallel lanes, one reusable ROMix table and temporary BlockMix
storage. Parameter and workspace sizing use checked arithmetic and reject
totals larger than the maximum representable Rust slice.
[RFC 7914 §§ 2–6](https://www.rfc-editor.org/rfc/rfc7914.html#section-2)

The tested profile includes admissible positive `r` and `p`, a power-of-two
`N > 1`, and the RFC's output and parallelization bounds. Target integer
size and supplied workspace can further restrict admissible inputs.
ROMix uses data-dependent memory accesses. Callers own workspace erasure,
resource limits and password policy. This core remains a research
implementation with no production approval.

Rust reproduces two RFC known-answer vectors, including sixteen parallel
lanes, and checks invalid sizes and workspace preservation. The
`python -B src/crypto/kdf/scrypt/spec/verify.py` command compares 144 cases
with Python's OpenSSL implementation, covering cost, block size, parallel
lane count and output boundaries. Lean checks the BlockMix permutation and
table bounds. [Bounds](ScryptBounds.lean) · [RFC 7914 § 12](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)

## ROMix and construction model

The Lean model checks both ROMix passes. Row `j` in the filled table
equals the input after `j` BlockMix applications. The corresponding
fixed-width slice in a byte workspace selects that same row. The
second pass uses a lower-64-bit little-endian load, a pointer-width
cast and a mask. Lean proves that the resulting index is the RFC
Integerify value modulo `N` for every power-of-two cost covered by
both widths. The construction theorem applies this equality to each
lane between the two PBKDF2 calls.
[Functional model](ScryptFunctional.lean) · [RFC 7914 §§ 4–6](https://www.rfc-editor.org/rfc/rfc7914.html#section-4)

The construction theorem takes a Salsa20/8 block contract and the
PBKDF2-HMAC-SHA-256 output contract for one iteration. It checks
functional composition for successful primitive calls. Source-level
correspondence, failed calls, workspace erasure and target leakage
remain separate obligations.

```sh
lean -DwarningAsError=true src/crypto/kdf/scrypt/spec/ScryptFunctional.lean
```

Lean 4.31.0 audits the seven theorem statements with standard Lean axioms.
