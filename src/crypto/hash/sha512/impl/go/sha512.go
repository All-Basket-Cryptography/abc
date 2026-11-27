// Package abcsha512 implements the byte-oriented FIPS 180-4 SHA-512 hash.
package abcsha512

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	// Size is the digest size in bytes.
	Size = 64
	// BlockSize is the compression block size in bytes.
	BlockSize = 128
	lengthPos = BlockSize - 16
)

// ErrMessageTooLong reports that an update would reach the 2^128-bit limit.
var ErrMessageTooLong = errors.New("SHA-512 message exceeds the 128-bit bit-length domain")

var initial = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

var constants = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

// Hasher holds a streaming hash. Its zero value is ready to use.
type Hasher struct {
	state     [8]uint64
	block     [BlockSize]byte
	buffered  int
	bytesLow  uint64
	bytesHigh uint64
}

// New constructs an empty SHA-512 stream.
func New() *Hasher { return &Hasher{} }

// Sum512 returns the SHA-512 digest of a single slice.
func Sum512(input []byte) [Size]byte {
	var hasher Hasher
	_ = hasher.Update(input) // A single Go slice fits in the 125-bit byte count.
	return hasher.Digest()
}

// Reset starts a new empty message.
func (d *Hasher) Reset() {
	*d = Hasher{}
}

// Update appends bytes and leaves the stream unchanged if the length is rejected.
func (d *Hasher) Update(input []byte) error {
	length := len(input)
	low, carry := bits.Add64(d.bytesLow, uint64(length), 0)
	high := d.bytesHigh + carry
	if high>>61 != 0 {
		return ErrMessageTooLong
	}
	if length == 0 {
		return nil
	}
	if d.bytesLow == 0 && d.bytesHigh == 0 {
		d.state = initial
	}
	d.bytesLow, d.bytesHigh = low, high

	if d.buffered != 0 {
		used := copy(d.block[d.buffered:], input)
		d.buffered += used
		if d.buffered < BlockSize {
			return nil
		}
		compress(&d.state, d.block[:])
		input = input[used:]
	}
	for len(input) >= BlockSize {
		compress(&d.state, input[:BlockSize])
		input = input[BlockSize:]
	}
	d.buffered = copy(d.block[:], input)
	return nil
}

// Digest returns the current digest without modifying the stream.
func (d Hasher) Digest() [Size]byte {
	if d.bytesLow == 0 && d.bytesHigh == 0 {
		d.state = initial
	}
	d.block[d.buffered] = 0x80
	clear(d.block[d.buffered+1:])
	if d.buffered >= lengthPos {
		compress(&d.state, d.block[:])
		clear(d.block[:])
	}
	binary.BigEndian.PutUint64(d.block[lengthPos:], d.bytesHigh<<3|d.bytesLow>>61)
	binary.BigEndian.PutUint64(d.block[lengthPos+8:], d.bytesLow<<3)
	compress(&d.state, d.block[:])

	var result [Size]byte
	for i, word := range d.state {
		binary.BigEndian.PutUint64(result[8*i:], word)
	}
	return result
}

func compress(state *[8]uint64, block []byte) {
	// The longest-lived schedule word is reused after sixteen rounds.
	var words [16]uint64
	for i := range words {
		words[i] = binary.BigEndian.Uint64(block[8*i:])
	}
	a, b, c, d, e, f, g, h := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
	for i, k := range constants {
		slot := i & 15
		if i >= len(words) {
			x, y := words[(i-15)&15], words[(i-2)&15]
			s0 := bits.RotateLeft64(x, -1) ^ bits.RotateLeft64(x, -8) ^ (x >> 7)
			s1 := bits.RotateLeft64(y, -19) ^ bits.RotateLeft64(y, -61) ^ (y >> 6)
			words[slot] += s0 + words[(i-7)&15] + s1
		}
		s1 := bits.RotateLeft64(e, -14) ^ bits.RotateLeft64(e, -18) ^ bits.RotateLeft64(e, -41)
		t1 := h + s1 + ((e & f) ^ (^e & g)) + k + words[slot]
		s0 := bits.RotateLeft64(a, -28) ^ bits.RotateLeft64(a, -34) ^ bits.RotateLeft64(a, -39)
		t2 := s0 + ((a & b) ^ (a & c) ^ (b & c))
		a, b, c, d, e, f, g, h = t1+t2, a, b, c, d+t1, e, f, g
	}
	for i, word := range [8]uint64{a, b, c, d, e, f, g, h} {
		state[i] += word
	}
}
