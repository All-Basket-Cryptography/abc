# scrypt

The portable Rust implementation composes RFC 7914's PBKDF2-HMAC-SHA-256,
Salsa20/8, BlockMix and ROMix. The caller supplies the memory for the
initial parallel lanes, one reusable ROMix table and temporary BlockMix
storage. Parameter and workspace sizing use checked arithmetic.
[RFC 7914 §§ 2–6](https://www.rfc-editor.org/rfc/rfc7914.html#section-2)

The tested profile includes admissible positive `r` and `p`, a power-of-two
`N > 1`, and the RFC's output and parallelization bounds. Target integer
size and supplied workspace can further restrict admissible inputs.
ROMix uses data-dependent memory accesses. Callers own workspace erasure,
resource limits and password policy. This core remains a research
implementation with no production approval.

Rust reproduces two RFC known-answer vectors, including sixteen parallel
lanes, and checks invalid sizes and workspace preservation. Lean checks
the BlockMix destination bound and table lookup bounds. Full source
refinement and independent platform security and performance assessment
remain open.
[RFC 7914 § 12](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)
