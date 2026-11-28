// Package aes256 implements the FIPS 197 AES-256 block cipher.
package aes256

import (
	"encoding/binary"
	"math/bits"
)

const (
	KeyBytes   = 32
	BlockBytes = 16
	rounds     = 14

	ones     = 0x0101010101010101
	lowSeven = 0x7f7f7f7f7f7f7f7f
)

// Cipher holds the expanded key. Its methods are read-only after New.
// The zero value is uninitialized.
type Cipher struct {
	keys  [rounds + 1][2]uint64
	ready bool
}

// New expands one 32-byte AES-256 key. The cipher can process multiple blocks.
func New(key [KeyBytes]byte) Cipher {
	var words [4 * (rounds + 1)]uint32
	for i := range 8 {
		words[i] = binary.LittleEndian.Uint32(key[4*i : 4*i+4])
	}
	var rcon byte = 1
	for i := 8; i < len(words); i++ {
		word := words[i-1]
		switch i & 7 {
		case 0:
			word = uint32(substitute(uint64(bits.RotateLeft32(word, -8)))) ^ uint32(rcon)
			rcon = byte(double(uint64(rcon)))
		case 4:
			word = uint32(substitute(uint64(word)))
		}
		words[i] = words[i-8] ^ word
	}
	c := Cipher{ready: true}
	for i := range c.keys {
		c.keys[i][0] = uint64(words[4*i]) | uint64(words[4*i+1])<<32
		c.keys[i][1] = uint64(words[4*i+2]) | uint64(words[4*i+3])<<32
	}
	return c
}

// EncryptBlock encrypts one block. It panics on an uninitialized Cipher.
func (c *Cipher) EncryptBlock(input [BlockBytes]byte) [BlockBytes]byte {
	if !c.ready {
		panic("aes256: use New before EncryptBlock")
	}
	low := binary.LittleEndian.Uint64(input[:8]) ^ c.keys[0][0]
	high := binary.LittleEndian.Uint64(input[8:]) ^ c.keys[0][1]
	for i := 1; i < rounds; i++ {
		low, high = shiftRows(substitute(low), substitute(high))
		low = mixColumns(low) ^ c.keys[i][0]
		high = mixColumns(high) ^ c.keys[i][1]
	}
	low, high = shiftRows(substitute(low), substitute(high))
	binary.LittleEndian.PutUint64(input[:8], low^c.keys[rounds][0])
	binary.LittleEndian.PutUint64(input[8:], high^c.keys[rounds][1])
	return input
}

// DecryptBlock decrypts one block. It panics on an uninitialized Cipher.
func (c *Cipher) DecryptBlock(input [BlockBytes]byte) [BlockBytes]byte {
	if !c.ready {
		panic("aes256: use New before DecryptBlock")
	}
	low := binary.LittleEndian.Uint64(input[:8]) ^ c.keys[rounds][0]
	high := binary.LittleEndian.Uint64(input[8:]) ^ c.keys[rounds][1]
	for i := rounds - 1; i > 0; i-- {
		low, high = inverseShiftRows(low, high)
		low = inverseMixColumns(inverseSubstitute(low) ^ c.keys[i][0])
		high = inverseMixColumns(inverseSubstitute(high) ^ c.keys[i][1])
	}
	low, high = inverseShiftRows(low, high)
	binary.LittleEndian.PutUint64(input[:8], inverseSubstitute(low)^c.keys[0][0])
	binary.LittleEndian.PutUint64(input[8:], inverseSubstitute(high)^c.keys[0][1])
	return input
}

// Each byte of x is a separate element of GF(2^8).
func double(x uint64) uint64 {
	return (x&lowSeven)<<1 ^ ((x>>7)&ones)*0x1b
}

func multiply(x, y uint64) uint64 {
	var sum uint64
	for range 8 {
		sum ^= x & ((y & ones) * 0xff)
		x = double(x)
		y = (y >> 1) & lowSeven
	}
	return sum
}

func square(x uint64) uint64 {
	// Squaring is linear in characteristic two. The constants are the
	// field squares of 1, x, ..., x^7 in the AES polynomial basis.
	return (x & ones) ^
		((x>>1)&ones)*0x04 ^
		((x>>2)&ones)*0x10 ^
		((x>>3)&ones)*0x40 ^
		((x>>4)&ones)*0x1b ^
		((x>>5)&ones)*0x6c ^
		((x>>6)&ones)*0xab ^
		((x>>7)&ones)*0x9a
}

func inverse(x uint64) uint64 {
	x2 := square(x)
	x3 := multiply(x2, x)
	x6 := square(x3)
	x7 := multiply(x6, x)
	x14 := square(x7)
	x15 := multiply(x14, x)
	x30 := square(x15)
	x60 := square(x30)
	x120 := square(x60)
	x127 := multiply(x120, x7)
	return square(x127)
}

func rotateBytes(x uint64, n uint) uint64 {
	low := (1 << n) - 1
	return (x<<n)&(uint64(0xff^low)*ones) | (x>>(8-n))&(uint64(low)*ones)
}

func substitute(x uint64) uint64 {
	y := inverse(x)
	return y ^ rotateBytes(y, 1) ^ rotateBytes(y, 2) ^ rotateBytes(y, 3) ^
		rotateBytes(y, 4) ^ 0x63*ones
}

func inverseSubstitute(y uint64) uint64 {
	return inverse(rotateBytes(y, 1) ^ rotateBytes(y, 3) ^ rotateBytes(y, 6) ^ 0x05*ones)
}

const (
	row0 = 0x000000ff000000ff
	row1 = 0x000000000000ff00
	row2 = 0x00ff000000ff0000
	row3 = 0x00000000ff000000
)

func shiftHalf(current, other, forward, backward uint64) uint64 {
	return current&row0 | other&row2 |
		(current>>32)&forward | (other&forward)<<32 |
		(other>>32)&backward | (current&backward)<<32
}

func shiftRows(low, high uint64) (uint64, uint64) {
	return shiftHalf(low, high, row1, row3), shiftHalf(high, low, row1, row3)
}

func inverseShiftRows(low, high uint64) (uint64, uint64) {
	return shiftHalf(low, high, row3, row1), shiftHalf(high, low, row3, row1)
}

func rotateColumns(x uint64, amount int) uint64 {
	return uint64(bits.RotateLeft32(uint32(x), amount)) |
		uint64(bits.RotateLeft32(uint32(x>>32), amount))<<32
}

func mixColumns(x uint64) uint64 {
	next := rotateColumns(x, -8)
	parity := x ^ next ^ rotateColumns(x, -16) ^ rotateColumns(x, -24)
	return x ^ parity ^ double(x^next)
}

func inverseMixColumns(x uint64) uint64 {
	return mixColumns(x ^ double(double(x^rotateColumns(x, -16))))
}
