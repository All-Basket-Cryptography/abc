// Package abckeccakp1600 provides the FIPS 202 permutation and 1088-bit-rate sponge.
package abckeccakp1600

import (
	"encoding/binary"
	"math/bits"
)

const Rate = 136

// Lane indices are x + 5*y. The pi table maps (x,y) to (y,2*x+3*y mod 5).
var rotation = [25]int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

var pi = [25]int{
	0, 10, 20, 5, 15,
	16, 1, 11, 21, 6,
	7, 17, 2, 12, 22,
	23, 8, 18, 3, 13,
	14, 24, 9, 19, 4,
}

var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// Permute applies Keccak-p[1600,24] to a state in lane order x + 5*y.
func Permute(state *[25]uint64) {
	var moved [25]uint64
	for _, round := range roundConstants {
		var parity [5]uint64
		for x := range parity {
			parity[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
		}
		theta := [5]uint64{
			parity[4] ^ bits.RotateLeft64(parity[1], 1),
			parity[0] ^ bits.RotateLeft64(parity[2], 1),
			parity[1] ^ bits.RotateLeft64(parity[3], 1),
			parity[2] ^ bits.RotateLeft64(parity[4], 1),
			parity[3] ^ bits.RotateLeft64(parity[0], 1),
		}
		for row := 0; row < 25; row += 5 {
			for column, delta := range theta {
				lane := row + column
				moved[pi[lane]] = bits.RotateLeft64(state[lane]^delta, rotation[lane])
			}
		}
		for row := 0; row < 25; row += 5 {
			a, b, c, d, e := moved[row], moved[row+1], moved[row+2], moved[row+3], moved[row+4]
			state[row] = a ^ (c &^ b)
			state[row+1] = b ^ (d &^ c)
			state[row+2] = c ^ (e &^ d)
			state[row+3] = d ^ (a &^ e)
			state[row+4] = e ^ (b &^ a)
		}
		state[0] ^= round
	}
}

// Sponge absorbs byte-aligned input. The zero value is the empty sponge.
type Sponge struct {
	lanes [25]uint64
	block [Rate]byte
	used  int
}

func (s *Sponge) absorb(block []byte) {
	for lane := 0; lane < Rate/8; lane++ {
		s.lanes[lane] ^= binary.LittleEndian.Uint64(block[8*lane:])
	}
	Permute(&s.lanes)
}

// Write absorbs the entire input and keeps no reference to the caller's slice.
func (s *Sponge) Write(input []byte) (int, error) {
	written := len(input)
	if s.used != 0 {
		copied := copy(s.block[s.used:], input)
		s.used += copied
		if s.used < Rate {
			return written, nil
		}
		s.absorb(s.block[:])
		input = input[copied:]
	}
	for len(input) >= Rate {
		s.absorb(input[:Rate])
		input = input[Rate:]
	}
	s.used = copy(s.block[:], input)
	return written, nil
}

// SHA3Digest returns a SHA3-256 digest without modifying the absorber.
func (s Sponge) SHA3Digest() (output [32]byte) {
	s.finalize(0x06)
	for lane := 0; lane < len(output)/8; lane++ {
		binary.LittleEndian.PutUint64(output[8*lane:], s.lanes[lane])
	}
	return output
}

// SHAKEReader returns an independent SHAKE256 output stream starting at offset zero.
func (s Sponge) SHAKEReader() Reader {
	s.finalize(0x1f)
	reader := Reader{lanes: s.lanes}
	reader.encode()
	return reader
}

func (s *Sponge) finalize(suffix byte) {
	s.block[s.used] = suffix
	clear(s.block[s.used+1:])
	s.block[Rate-1] |= 0x80
	s.absorb(s.block[:])
}

// Reader is an extendable output stream initialized by Sponge.SHAKEReader.
type Reader struct {
	lanes  [25]uint64
	block  [Rate]byte
	offset int
}

func (r *Reader) encode() {
	for lane := 0; lane < Rate/8; lane++ {
		binary.LittleEndian.PutUint64(r.block[8*lane:], r.lanes[lane])
	}
}

// Read fills the destination and advances this reader. The stream has no EOF.
func (r *Reader) Read(output []byte) (int, error) {
	written := len(output)
	for len(output) != 0 {
		if r.offset == Rate {
			Permute(&r.lanes)
			r.encode()
			r.offset = 0
		}
		length := copy(output, r.block[r.offset:])
		r.offset += length
		output = output[length:]
	}
	return written, nil
}
