// Package sha256 implements byte-oriented SHA-256 in portable Go for ABC research.
package sha256

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	// Size is the digest size in bytes.
	Size = 32
	// BlockSize is the compression block size in bytes.
	BlockSize = 64
	// MaxMessageBytes is the largest byte-aligned input admitted by FIPS 180-4.
	MaxMessageBytes = 1<<61 - 1
)

// ErrMessageTooLong reports that an update would exceed MaxMessageBytes.
var ErrMessageTooLong = errors.New("sha256: message length exceeds the 64-bit bit-length limit")

// Hasher holds the chaining state and the uncompressed suffix of a message.
// Its zero value is ready to use. Calls on one Hasher must be serialized.
type Hasher struct {
	state  [8]uint32
	tail   [BlockSize]byte
	used   int
	length uint64
}

// New returns a hasher for an empty message.
func New() *Hasher { return &Hasher{} }

// Reset starts a new empty message.
func (h *Hasher) Reset() { *h = Hasher{} }

// Update appends bytes and leaves the state unchanged if the length limit would
// be exceeded. It retains no references to data after the call returns.
func (h *Hasher) Update(data []byte) error {
	incoming := uint64(len(data))
	if incoming > MaxMessageBytes-h.length {
		return ErrMessageTooLong
	}
	if incoming == 0 {
		return nil
	}
	if h.length == 0 {
		h.state = initialState
	}
	h.length += incoming

	if h.used != 0 {
		copied := copy(h.tail[h.used:], data)
		h.used += copied
		if h.used < BlockSize {
			return nil
		}
		compress(&h.state, &h.tail)
		data = data[copied:]
	}
	for len(data) >= BlockSize {
		compress(&h.state, (*[BlockSize]byte)(data))
		data = data[BlockSize:]
	}
	h.used = copy(h.tail[:], data)
	return nil
}

// Digest returns the hash of the current message without closing or modifying
// the context. Later updates can extend the message.
func (h *Hasher) Digest() [Size]byte {
	state := h.state
	if h.length == 0 {
		state = initialState
	}
	var padded [2 * BlockSize]byte
	copy(padded[:], h.tail[:h.used])
	padded[h.used] = 0x80
	end := BlockSize
	if h.used >= BlockSize-8 {
		end = 2 * BlockSize
	}
	binary.BigEndian.PutUint64(padded[end-8:end], h.length*8)
	for offset := 0; offset < end; offset += BlockSize {
		compress(&state, (*[BlockSize]byte)(padded[offset:]))
	}
	var digest [Size]byte
	for i, word := range state {
		binary.BigEndian.PutUint32(digest[4*i:4*i+4], word)
	}
	return digest
}

// Sum256 computes the digest of data in one call.
func Sum256(data []byte) ([Size]byte, error) {
	var h Hasher
	if err := h.Update(data); err != nil {
		return [Size]byte{}, err
	}
	return h.Digest(), nil
}

// FIPS 180-4 §§ 4.2.2 and 5.3.3.
var initialState = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

var roundConstants = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// compress applies the message schedule, rounds, and feed-forward of § 6.2.2.
// All additions are modulo 2^32 by construction of uint32 arithmetic.
func compress(state *[8]uint32, block *[BlockSize]byte) {
	var schedule [64]uint32
	for i := 0; i < 16; i++ {
		schedule[i] = binary.BigEndian.Uint32(block[4*i : 4*i+4])
	}
	for i := 16; i < len(schedule); i++ {
		x, y := schedule[i-15], schedule[i-2]
		small0 := bits.RotateLeft32(x, -7) ^ bits.RotateLeft32(x, -18) ^ (x >> 3)
		small1 := bits.RotateLeft32(y, -17) ^ bits.RotateLeft32(y, -19) ^ (y >> 10)
		schedule[i] = schedule[i-16] + small0 + schedule[i-7] + small1
	}

	a, b, c, d := state[0], state[1], state[2], state[3]
	e, f, g, h := state[4], state[5], state[6], state[7]
	for i, constant := range roundConstants {
		large1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
		choose := (e & f) ^ (^e & g)
		first := h + large1 + choose + constant + schedule[i]
		large0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
		majority := (a & b) ^ (a & c) ^ (b & c)
		second := large0 + majority
		a, b, c, d, e, f, g, h = first+second, a, b, c, d+first, e, f, g
	}
	for i, word := range [8]uint32{a, b, c, d, e, f, g, h} {
		state[i] += word
	}
}
