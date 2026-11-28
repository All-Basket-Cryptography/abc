// Package abcblake2b implements unkeyed sequential BLAKE2b.
package abcblake2b

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	BlockSize     = 128
	MaxDigestSize = 64
)

var (
	ErrDigestSize   = errors.New("BLAKE2b digest size must be between 1 and 64 bytes")
	ErrOutputSize   = errors.New("BLAKE2b output size must equal the configured digest size")
	ErrMessageLimit = errors.New("BLAKE2b message exceeds its 128-bit byte counter")
)

var initial = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

var sigma = [10][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

// Hasher is a streaming unkeyed BLAKE2b context.
// Its zero value uses the 64-byte digest.
type Hasher struct {
	state                 [8]uint64
	tail                  [BlockSize]byte
	size, used            int
	lengthLow, lengthHigh uint64
}

func withSize(size int) Hasher {
	context := Hasher{state: initial, size: size}
	context.state[0] ^= 0x01010000 | uint64(size)
	return context
}

// New chooses a fixed digest size in bytes.
func New(size int) (*Hasher, error) {
	if size < 1 || size > MaxDigestSize {
		return nil, ErrDigestSize
	}
	context := withSize(size)
	return &context, nil
}

// Size returns the chosen digest size.
func (h *Hasher) Size() int {
	if h.size == 0 {
		return MaxDigestSize
	}
	return h.size
}

// Reset starts an empty message at the same digest size.
func (h *Hasher) Reset() { *h = withSize(h.Size()) }

// Update absorbs bytes and leaves the state unchanged on counter overflow.
func (h *Hasher) Update(input []byte) error {
	nextLow, carry := bits.Add64(h.lengthLow, uint64(len(input)), 0)
	nextHigh, overflow := bits.Add64(h.lengthHigh, 0, carry)
	if overflow != 0 {
		return ErrMessageLimit
	}
	if len(input) == 0 {
		return nil
	}
	if h.size == 0 {
		h.Reset()
	}
	compressedLow, borrow := bits.Sub64(h.lengthLow, uint64(h.used), 0)
	compressedHigh, _ := bits.Sub64(h.lengthHigh, 0, borrow)
	h.lengthLow, h.lengthHigh = nextLow, nextHigh

	if h.used != 0 {
		copied := copy(h.tail[h.used:], input)
		h.used += copied
		input = input[copied:]
		if len(input) == 0 {
			return nil
		}
		compressedLow, carry = bits.Add64(compressedLow, BlockSize, 0)
		compressedHigh += carry
		compress(&h.state, h.tail[:], compressedLow, compressedHigh, false)
	}
	// Even an exact final block must be held for the last-block flag.
	for len(input) > BlockSize {
		compressedLow, carry = bits.Add64(compressedLow, BlockSize, 0)
		compressedHigh += carry
		compress(&h.state, input[:BlockSize], compressedLow, compressedHigh, false)
		input = input[BlockSize:]
	}
	h.used = copy(h.tail[:], input)
	return nil
}

// Finalize writes a digest snapshot and leaves the absorber available for updates.
func (h Hasher) Finalize(output []byte) error {
	if len(output) != h.Size() {
		return ErrOutputSize
	}
	if h.size == 0 {
		h.Reset()
	}
	clear(h.tail[h.used:])
	compress(&h.state, h.tail[:], h.lengthLow, h.lengthHigh, true)

	for _, word := range h.state {
		if len(output) < 8 {
			var last [8]byte
			binary.LittleEndian.PutUint64(last[:], word)
			copy(output, last[:])
			break
		}
		binary.LittleEndian.PutUint64(output, word)
		output = output[8:]
	}
	return nil
}

// Sum computes a digest sized by output. Input and output slices can overlap.
func Sum(input, output []byte) error {
	if len(output) < 1 || len(output) > MaxDigestSize {
		return ErrDigestSize
	}
	hasher := withSize(len(output))
	if err := hasher.Update(input); err != nil {
		return err
	}
	return hasher.Finalize(output)
}

func mix(v *[16]uint64, a, b, c, d int, x, y uint64) {
	v[a] += v[b] + x
	v[d] = bits.RotateLeft64(v[d]^v[a], -32)
	v[c] += v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -24)
	v[a] += v[b] + y
	v[d] = bits.RotateLeft64(v[d]^v[a], -16)
	v[c] += v[d]
	v[b] = bits.RotateLeft64(v[b]^v[c], -63)
}

func compress(state *[8]uint64, block []byte, low, high uint64, final bool) {
	var m, v [16]uint64
	for i := range m {
		m[i] = binary.LittleEndian.Uint64(block[8*i:])
	}
	copy(v[:8], state[:])
	copy(v[8:], initial[:])
	v[12] ^= low
	v[13] ^= high
	if final {
		v[14] = ^v[14]
	}
	for round := 0; round < 12; round++ {
		s := &sigma[round%10]
		mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := range state {
		state[i] ^= v[i] ^ v[i+8]
	}
}
