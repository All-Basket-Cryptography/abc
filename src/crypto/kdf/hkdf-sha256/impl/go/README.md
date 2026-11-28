# Portable Go HKDF-SHA-256

This research core implements [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)
using the [native Go HMAC](../../../../mac/hmac-sha256/impl/go). The API has
extract, expand, and derive operations. Expand returns a fresh byte slice,
checks the 255-block limit, and requires a PRK of at least 32 bytes. Nil salt
uses 32 zero bytes. Callers own the returned key material.

Run `go test -C src/crypto/kdf/hkdf-sha256/impl/go -count=1 ./...` from the
repository root with Go 1.24.9. The tests use RFC 5869 cases A.1 and A.3 and
compare against Go's `crypto/hkdf` across salt, block, and output boundaries.
The Windows amd64 run passed 10,000 generated differential inputs with
`go test -run '^$' -fuzz '^FuzzDifferential$' -fuzztime 10000x -parallel 2`
from this module directory with cgo disabled.

The [shared specification](../../spec/HkdfSpec.lean) defines the extract and
expand functions. This core still needs Go source-to-spec refinement, target
timing evidence, and review of key material lifetime and production use.
