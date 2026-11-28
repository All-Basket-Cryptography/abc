# C# Argon2id

The byte API fixes Argon2id version 1.3. It accepts password, salt,
optional secret and associated-data spans. The SDK returns an owned tag.
`WorkspaceBytes` reports the rounded primary matrix bytes. `Derive`
checks that amount plus the tag bytes before invoking the provider.
Managed object
headers, provider scratch buffers, and available heap are outside
the budget. The adapter clears temporary password and secret copies.
[RFC 9106 §§3–5](https://www.rfc-editor.org/rfc/rfc9106.html#section-3)

The NuGet SDK package is `Abc.Cryptography.Argon2id` 0.1.0.
It depends on the locked Bouncy Castle 2.7.0 archive.
[Provider lock and checks](../../../../providers/csharp/README.md)

```sh
python -B src/crypto/providers/csharp/check.py --profile argon2id
```

The isolated consumer matched 101 OpenSSL outputs including the RFC
vector with secret and associated data. Each case accepted its exact
rounded matrix-plus-tag budget and rejected a budget one byte lower.
Invalid lanes, salt, pass count and tag length were also checked.

The package follows the repository's research profile. Exact source
refinement, compiled leakage and comparative performance remain open.
