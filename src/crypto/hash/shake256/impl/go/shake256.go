// Package abcshake256 implements the byte-oriented SHAKE256 output stream.
package abcshake256

import (
	"io"

	abckeccak "github.com/All-Basket-Cryptography/abc/src/crypto/hash/keccak-p1600/impl/go"
)

const BlockSize = abckeccak.Rate

// Absorber accepts arbitrary message chunks. The zero value is ready to use.
type Absorber struct{ sponge abckeccak.Sponge }

func New() *Absorber { return &Absorber{} }

func (a *Absorber) Write(input []byte) (int, error) { return a.sponge.Write(input) }
func (a *Absorber) Reset()                          { *a = Absorber{} }

// Finalize returns a separate reader at offset zero. The absorber remains usable.
func (a *Absorber) Finalize() *Reader {
	return &Reader{stream: a.sponge.SHAKEReader()}
}

// Reader is a SHAKE256 output stream created by Absorber.Finalize.
type Reader struct{ stream abckeccak.Reader }

var _ io.Reader = (*Reader)(nil)

// Read fills output and advances this reader by its byte length.
func (r *Reader) Read(output []byte) (int, error) { return r.stream.Read(output) }

// XOF computes the requested SHAKE256 output. Input and output slices may overlap.
func XOF(input, output []byte) {
	var absorber Absorber
	absorber.Write(input)
	absorber.Finalize().Read(output)
}
