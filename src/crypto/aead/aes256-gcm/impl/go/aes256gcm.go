// Package aes256gcm implements the SP 800-38D AES-256-GCM fixed profile.
package aes256gcm

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"

	aes "github.com/All-Basket-Cryptography/abc/src/crypto/cipher/aes256/impl/go"
)

const (
	KeyBytes   = aes.KeyBytes
	NonceBytes = 12
	TagBytes   = 16
	blockBytes = aes.BlockBytes

	maxPayloadBytes = ((1 << 32) - 2) * blockBytes
	maxAADBytes     = math.MaxUint64 / 8
)

var (
	ErrUninitialized    = errors.New("aes256-gcm: use New to initialize the key")
	ErrShortDestination = errors.New("aes256-gcm: destination is shorter than the input")
	ErrLength           = errors.New("aes256-gcm: message or associated data exceeds the profile")
	ErrAuthentication   = errors.New("aes256-gcm: authentication failed")
)

// GCM holds an expanded key and its GHASH subkey. Initialize with New.
// The methods are read-only after creation. Callers own nonce uniqueness.
type GCM struct {
	block aes.Cipher
	h     field
	ready bool
}

// New creates a GCM context for a 32-byte key.
func New(key [KeyBytes]byte) GCM {
	c := aes.New(key)
	h := c.EncryptBlock([blockBytes]byte{})
	return GCM{block: c, h: fieldFrom(h[:]), ready: true}
}

// SealDetached writes ciphertext to the equally long prefix of dst and
// returns the full tag. The destination may overlap plaintext or associated
// data. An error preserves dst. Use a distinct nonce on each call under a key.
func (g *GCM) SealDetached(dst, plaintext, associatedData []byte, nonce [NonceBytes]byte) ([TagBytes]byte, error) {
	if err := g.validate(dst, plaintext, associatedData); err != nil {
		return [TagBytes]byte{}, err
	}
	accumulator := authenticate(field{}, associatedData, g.h)
	copy(dst, plaintext)
	output := dst[:len(plaintext)]
	g.counterXOR(output, nonce)
	return g.tag(accumulator, output, len(associatedData), nonce), nil
}

// OpenDetached authenticates the ciphertext and associated data, then writes
// the equally long prefix of dst. It admits overlapping buffers, and errors
// preserve all destination bytes. The tag is compared in constant time by
// the Go standard library helper.
func (g *GCM) OpenDetached(dst, ciphertext, associatedData []byte, tag [TagBytes]byte, nonce [NonceBytes]byte) error {
	if err := g.validate(dst, ciphertext, associatedData); err != nil {
		return err
	}
	accumulator := authenticate(field{}, associatedData, g.h)
	expected := g.tag(accumulator, ciphertext, len(associatedData), nonce)
	if subtle.ConstantTimeCompare(expected[:], tag[:]) != 1 {
		return ErrAuthentication
	}
	copy(dst, ciphertext)
	g.counterXOR(dst[:len(ciphertext)], nonce)
	return nil
}

func lengthsFit(payload, aad uint64) bool {
	return payload <= maxPayloadBytes && aad <= maxAADBytes
}

func (g *GCM) validate(dst, input, associatedData []byte) error {
	if !g.ready {
		return ErrUninitialized
	}
	if len(dst) < len(input) {
		return ErrShortDestination
	}
	if !lengthsFit(uint64(len(input)), uint64(len(associatedData))) {
		return ErrLength
	}
	return nil
}

func (g *GCM) counterXOR(buffer []byte, nonce [NonceBytes]byte) {
	var input [blockBytes]byte
	copy(input[:NonceBytes], nonce[:])
	counter := uint32(2)
	for len(buffer) != 0 {
		binary.BigEndian.PutUint32(input[NonceBytes:], counter)
		stream := g.block.EncryptBlock(input)
		width := min(len(buffer), blockBytes)
		subtle.XORBytes(buffer[:width], buffer[:width], stream[:width])
		buffer = buffer[width:]
		counter++
	}
}

type field struct{ high, low uint64 }

func fieldFrom(input []byte) field {
	return field{binary.BigEndian.Uint64(input[:8]), binary.BigEndian.Uint64(input[8:16])}
}

func product(x, h field) field {
	var z field
	for _, word := range [2]uint64{x.high, x.low} {
		for range 64 {
			mask := uint64(0) - (word >> 63)
			z.high ^= h.high & mask
			z.low ^= h.low & mask
			reduction := uint64(0) - (h.low & 1)
			h.low = h.low>>1 | h.high<<63
			h.high = h.high>>1 ^ (reduction & 0xe100000000000000)
			word <<= 1
		}
	}
	return z
}

func absorb(accumulator field, input []byte, key field) field {
	x := fieldFrom(input)
	return product(field{accumulator.high ^ x.high, accumulator.low ^ x.low}, key)
}

func authenticate(accumulator field, input []byte, key field) field {
	for len(input) >= blockBytes {
		accumulator = absorb(accumulator, input[:blockBytes], key)
		input = input[blockBytes:]
	}
	if len(input) != 0 {
		var tail [blockBytes]byte
		copy(tail[:], input)
		accumulator = absorb(accumulator, tail[:], key)
	}
	return accumulator
}

func (g *GCM) tag(accumulator field, ciphertext []byte, aadBytes int, nonce [NonceBytes]byte) [TagBytes]byte {
	accumulator = authenticate(accumulator, ciphertext, g.h)
	lengths := field{8 * uint64(aadBytes), 8 * uint64(len(ciphertext))}
	accumulator = product(field{accumulator.high ^ lengths.high, accumulator.low ^ lengths.low}, g.h)

	var initial [blockBytes]byte
	copy(initial[:NonceBytes], nonce[:])
	initial[blockBytes-1] = 1
	mask := g.block.EncryptBlock(initial)
	binary.BigEndian.PutUint64(mask[:8], binary.BigEndian.Uint64(mask[:8])^accumulator.high)
	binary.BigEndian.PutUint64(mask[8:], binary.BigEndian.Uint64(mask[8:])^accumulator.low)
	return mask
}
