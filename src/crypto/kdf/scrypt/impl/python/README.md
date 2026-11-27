# Python scrypt

`derive` implements RFC 7914 scrypt in Python with the ABC Python
PBKDF2-HMAC-SHA-256 core. It accepts the password and salt as byte buffers.
The caller names `cost` (N), `block_size` (r), `parallel` (p), the
output `length`, and an explicit `memory_limit`. The limits cover the
documented algorithm buffers plus output. Python and PBKDF2 temporaries
also use runtime memory. Bound the permitted work independently when
admitting external parameters. [RFC 7914 §§ 2–7](https://www.rfc-editor.org/rfc/rfc7914.html#section-2)

```sh
python -B -m unittest discover -s src/crypto/kdf/scrypt/impl/python -p test_scrypt.py -v
```

The tests reproduce a published answer, compare 81 cases with OpenSSL
through CPython `hashlib.scrypt`, and check parameter and budget
rejection. ROMix accesses the table using data-dependent indexes.
The explicit byte buffers are cleared on return. Python temporary
objects, compiled timing and source refinement still require evidence.
[RFC 7914 § 12](https://www.rfc-editor.org/rfc/rfc7914.html#section-12) · [Lean arithmetic model](../../spec/ScryptBounds.lean)
