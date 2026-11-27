// Package chacha20 implements the IETF ChaCha20 stream and block functions.
package chacha20

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	KeyBytes   = 32
	NonceBytes = 12
	BlockBytes = 64
)

var (
	ErrShortDestination = errors.New("chacha20: destination is shorter than the input")
	ErrCounterRange     = errors.New("chacha20: input exhausts the 32-bit block counter")
)

// FitsCounter reports whether byteCount bytes fit at the given initial counter.
func FitsCounter(byteCount uint64, counter uint32) bool {
	return byteCount == 0 || (byteCount-1)/BlockBytes < (1<<32)-uint64(counter)
}

// Block returns one 64-byte keystream block. The caller owns key and nonce
// uniqueness and must assign disjoint counters when processing separate chunks.
func Block(key [KeyBytes]byte, nonce [NonceBytes]byte, counter uint32) [BlockBytes]byte {
	return block(&key, &nonce, counter)
}

// XOR reads src and writes one equally long prefix of dst. It permits exact or
// partial overlap between src and dst. Validation errors leave dst unchanged.
func XOR(dst, src []byte, key [KeyBytes]byte, nonce [NonceBytes]byte, counter uint32) error {
	if len(dst) < len(src) {
		return ErrShortDestination
	}
	if !FitsCounter(uint64(len(src)), counter) {
		return ErrCounterRange
	}

	data := dst[:len(src)]
	copy(data, src)
	for len(data) != 0 {
		keystream := block(&key, &nonce, counter)
		width := min(len(data), BlockBytes)
		subtle.XORBytes(data[:width], data[:width], keystream[:width])
		data = data[width:]
		counter++
	}
	return nil
}

func block(key *[KeyBytes]byte, nonce *[NonceBytes]byte, counter uint32) [BlockBytes]byte {
	state := [16]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
	for lane := range 8 {
		state[4+lane] = binary.LittleEndian.Uint32(key[4*lane : 4*lane+4])
	}
	state[12] = counter
	for lane := range 3 {
		state[13+lane] = binary.LittleEndian.Uint32(nonce[4*lane : 4*lane+4])
	}

	work := state
	for range 10 {
		quarter(&work[0], &work[4], &work[8], &work[12])
		quarter(&work[1], &work[5], &work[9], &work[13])
		quarter(&work[2], &work[6], &work[10], &work[14])
		quarter(&work[3], &work[7], &work[11], &work[15])
		quarter(&work[0], &work[5], &work[10], &work[15])
		quarter(&work[1], &work[6], &work[11], &work[12])
		quarter(&work[2], &work[7], &work[8], &work[13])
		quarter(&work[3], &work[4], &work[9], &work[14])
	}

	output := [BlockBytes]byte{}
	for lane, word := range work {
		binary.LittleEndian.PutUint32(output[4*lane:4*lane+4], word+state[lane])
	}
	return output
}

func quarter(a, b, c, d *uint32) {
	*a += *b
	*d = bits.RotateLeft32(*d^*a, 16)
	*c += *d
	*b = bits.RotateLeft32(*b^*c, 12)
	*a += *b
	*d = bits.RotateLeft32(*d^*a, 8)
	*c += *d
	*b = bits.RotateLeft32(*b^*c, 7)
}
