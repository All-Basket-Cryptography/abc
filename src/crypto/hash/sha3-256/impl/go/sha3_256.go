// Package abcsha3 implements byte-oriented SHA3-256.
package abcsha3

import (
	"hash"

	abckeccak "github.com/All-Basket-Cryptography/abc/src/crypto/hash/keccak-p1600/impl/go"
)

const (
	Size      = 32
	BlockSize = abckeccak.Rate
)

// Hasher is a SHA3-256 absorber. The zero value is ready to use.
type Hasher struct{ sponge abckeccak.Sponge }

var _ hash.Hash = (*Hasher)(nil)

func New() *Hasher { return &Hasher{} }

func (h *Hasher) Write(input []byte) (int, error) { return h.sponge.Write(input) }
func (h *Hasher) Reset()                          { *h = Hasher{} }
func (h *Hasher) Size() int                       { return Size }
func (h *Hasher) BlockSize() int                  { return BlockSize }

// Digest returns a non-destructive digest snapshot.
func (h *Hasher) Digest() [Size]byte { return h.sponge.SHA3Digest() }

func (h *Hasher) Sum(prefix []byte) []byte {
	digest := h.Digest()
	return append(prefix, digest[:]...)
}

// Sum256 hashes a single slice.
func Sum256(input []byte) [Size]byte {
	var hasher Hasher
	hasher.Write(input)
	return hasher.Digest()
}
