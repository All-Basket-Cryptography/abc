# ABC SHA-256

Research implementation of byte-oriented, portable SHA-256. `digest` computes a 32-byte digest. `Sha256::update` accepts sequential chunks and `Sha256::finalize` consumes the state.

The core uses safe Rust and has no runtime dependencies. The functional refinement of this implementation against an independent Lean specification is pending. This package has research status.
