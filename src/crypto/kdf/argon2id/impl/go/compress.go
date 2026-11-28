package abcargon2id

import "math/bits"

func compress(left, right *Block) Block {
	var mixed Block
	for i := range mixed {
		mixed[i] = left[i] ^ right[i]
	}
	state := mixed
	for row := 0; row < 8; row++ {
		permute((*[16]uint64)(state[row*16:]))
	}
	for column := 0; column < 8; column++ {
		var stripe [16]uint64
		for row := 0; row < 8; row++ {
			offset := 16*row + 2*column
			stripe[2*row], stripe[2*row+1] = state[offset], state[offset+1]
		}
		permute(&stripe)
		for row := 0; row < 8; row++ {
			offset := 16*row + 2*column
			state[offset], state[offset+1] = stripe[2*row], stripe[2*row+1]
		}
	}
	for i := range state {
		state[i] ^= mixed[i]
	}
	return state
}

func permute(words *[16]uint64) {
	quarter(words, 0, 4, 8, 12)
	quarter(words, 1, 5, 9, 13)
	quarter(words, 2, 6, 10, 14)
	quarter(words, 3, 7, 11, 15)
	quarter(words, 0, 5, 10, 15)
	quarter(words, 1, 6, 11, 12)
	quarter(words, 2, 7, 8, 13)
	quarter(words, 3, 4, 9, 14)
}

func quarter(words *[16]uint64, ai, bi, ci, di int) {
	a, b, c, d := words[ai], words[bi], words[ci], words[di]
	a = blamka(a, b)
	d = bits.RotateLeft64(d^a, -32)
	c = blamka(c, d)
	b = bits.RotateLeft64(b^c, -24)
	a = blamka(a, b)
	d = bits.RotateLeft64(d^a, -16)
	c = blamka(c, d)
	b = bits.RotateLeft64(b^c, -63)
	words[ai], words[bi], words[ci], words[di] = a, b, c, d
}

func blamka(left, right uint64) uint64 {
	product := uint64(uint32(left)) * uint64(uint32(right))
	return left + right + (product << 1)
}
