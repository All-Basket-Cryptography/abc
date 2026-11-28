# ABC SHA-256 for Go

The research SDK uses the ABC C ABI on Windows amd64. `Open` takes an absolute path to the packaged `abc_crypto.dll`. The Go 1.24 module uses the Windows syscall API with `CGO_ENABLED=0`. No C compiler is required for the consumer. The binding provides `Digest` and an owned streaming context. Finalization closes the hash operation, `Reset` starts an empty message, and `Close` releases the native context. One provider can create independent contexts. Other platforms are planned.
