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
python -B src/lean/check.py scrypt
```

Lean 4.31.0 audits the seven theorem statements with standard Lean axioms.

## Alternating ROMix buffers

Each BlockMix reads one lane and writes the reordered blocks to the other
buffer. ROMix exchanges the roles after each BlockMix. There are `N` steps
in the table-fill pass and `N` steps in the lookup pass. For each admissible
cost, both passes end with the current value in the original lane. The
Lean model proves the correspondence of the stored rows, the lookup pass,
and the result in that original lane. The construction theorem composes
this result with the existing Salsa20/8 and PBKDF2 contracts.
[Alternating-buffer model](ScryptAlternating.lean)

C, C++, Go, JavaScript, Python, Rust and TypeScript now use this pattern.
C#, Java, Kotlin and Swift already used it. The change in the seven
implementations removes `2*N*p` full-lane copies per derivation, equivalent
to `256*N*r*p` bytes of explicit copy destinations. The ROMix table still
uses the same space and data-dependent lookups. The proof covers the model
and the portable implementations are checked by vectors and differential
tests. Traffic and elapsed time depend on the target and workload.
[RFC 7914 § 5](https://www.rfc-editor.org/rfc/rfc7914.html#section-5)

Colin Percival, *Stronger Key Derivation via Sequential Memory-Hard
Functions*, 2009, gives the motivation and formal cost model for ROMix.
[Original paper](https://www.tarsnap.com/scrypt/scrypt.pdf)
