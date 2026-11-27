# HMAC and HKDF model checking

The checker extracts the portable Rust SHA-256, HMAC-SHA-256, and HKDF-SHA-256 crate models and checks their correspondence to the Lean specifications. The HMAC external modules bind the imported SHA-256 state and operations directly to the checked SHA-256 model. The HKDF external modules bind the HMAC state and operations to the checked HMAC model and map the two HMAC error constructors into HKDF's generated enum.

## Running the check

Set `ABC_AENEAS_ROOT` to the pinned Aeneas checkout and use the `x86_64-unknown-linux-gnu` toolchain from the SHA-256 setup. Run the command from the repository root. [SHA-256 setup](../../algorithms/hash/sha2/sha256/formal/README.md)

```sh
node formal/hmac-hkdf/check.mjs
```

The command accepts an optional path to a SHA-256 extraction `result.json` and reruns the SHA-256 proof checker against it. It extracts both construction crates twice in fresh Cargo target directories, compares the generated Lean files, and validates the external declaration names. It then compiles the original generated modules, the tracked bindings, and the proof modules. The transcript, source digests, and axiom audits appear under `.abc/hmac-hkdf-extraction/`. [Advisory workflow](../../.github/workflows/sha256-model.yml)

## Local extraction evidence

Two independent extractions used pinned Charon on `x86_64-pc-windows-msvc` and the checksum-verified Linux Aeneas release under WSL. The two passes matched all four output files per crate, including the templates used to inventory the required imports. Lean 4.31.0 compiled the original `Types` and `Funs` files with the tracked bindings.

In a fresh Lean object directory, the Windows-target SHA-256 provider, both
construction models, their bindings, and all three proof suites passed
together. Lean audited seven SHA-256, seven HMAC and nine HKDF declarations.
Each used only `propext`, `Classical.choice`, and `Quot.sound`. The local
transcript is `.abc/hmac-hkdf-extraction/windows-proof-audit.log`.

The pinned Rust toolchain passed both HMAC tests and all five HKDF tests, including RFC 4231 and RFC 5869 vectors, boundary lengths, and preservation of the output buffer on a length error.

A fresh Lean 4.31.0 build checked the generated SHA-256, HMAC, and HKDF models and their full proof chain on the same Windows target. It compiled the independent claim files and audited seven SHA-256, seven HMAC, and nine HKDF declarations. Each audited declaration depends only on `propext`, `Classical.choice`, and `Quot.sound`. The transcript is `.abc/hmac-hkdf-extraction/windows-proof-audit.log`.

| Model | Rust source SHA-256 | `Types.lean` SHA-256 | `Funs.lean` SHA-256 |
|---|---|---|---|
| HMAC-SHA-256 | `b9be56d2cc809e6b3998e76ec53edcaf4ccb98f19e3c2f643678f224a9f09425` | `b5032253263920856001d66032212539fa890010b34af03490160da5f0c0ac48` | `1f11cef6d06576dd35715a2a8e6d6108d6562c7da4bb1437bf25b33c85102143` |
| HKDF-SHA-256 | `635284ceccfc1065a6b9b069aa104f5e407f8511c86349bcfa67fd41b380015e` | `cb3fba041473d5ee999e3944ad945e577a575c3ff1ec6cd9eaad99b1d9f6eb3f` | `ca0e216cf02715c386d32f866c470127408e9715d4c955daadc926045faf88cc` |
