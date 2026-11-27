package aes256

import (
	"crypto/aes"
	"encoding/hex"
	"math/bits"
	"math/rand/v2"
	"testing"
)

func TestKnownAnswers(t *testing.T) {
	cases := []struct {
		key, plaintext, ciphertext string
	}{
		{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"},
		{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
			"6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"},
	}
	for _, test := range cases {
		key := [KeyBytes]byte(decoded(t, test.key))
		plain := [BlockBytes]byte(decoded(t, test.plaintext))
		want := [BlockBytes]byte(decoded(t, test.ciphertext))
		c := New(key)
		if got := c.EncryptBlock(plain); got != want {
			t.Fatalf("encryption: %x != %x", got, want)
		}
		if got := c.DecryptBlock(want); got != plain {
			t.Fatalf("decryption: %x != %x", got, plain)
		}
	}
}

func TestIndependentGoProvider(t *testing.T) {
	rng := rand.New(rand.NewPCG(197, 256))
	for i := range 512 {
		var key [KeyBytes]byte
		var plain, other [BlockBytes]byte
		for _, buf := range [][]byte{key[:], plain[:], other[:]} {
			for j := range buf {
				buf[j] = byte(rng.Uint32())
			}
		}
		ref, err := aes.NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}
		c := New(key)
		var want [BlockBytes]byte
		ref.Encrypt(want[:], plain[:])
		if got := c.EncryptBlock(plain); got != want {
			t.Fatalf("encryption case %d: %x != %x", i, got, want)
		}
		ref.Decrypt(want[:], other[:])
		if got := c.DecryptBlock(other); got != want {
			t.Fatalf("decryption case %d: %x != %x", i, got, want)
		}
	}
	t.Log("512 encryption and 512 independent decryption comparisons")
}

func TestPackedFieldOperations(t *testing.T) {
	for x := range 256 {
		var lanes uint64
		for lane := range 8 {
			lanes |= uint64(byte(x+37*lane)) << (8 * lane)
		}
		squared := square(lanes)
		substituted := substitute(lanes)
		if inverseSubstitute(substituted) != lanes {
			t.Fatalf("inverse substitution of %016x", lanes)
		}
		for lane := range 8 {
			shift := 8 * lane
			input := byte(lanes >> shift)
			if byte(squared>>shift) != scalarProduct(input, input) {
				t.Fatalf("square of %02x in lane %d", input, lane)
			}
			if byte(substituted>>shift) != referenceSbox(input) {
				t.Fatalf("substitution of %02x in lane %d", input, lane)
			}
		}
		for y := range 256 {
			var factors uint64
			for lane := range 8 {
				factors |= uint64(byte(y+71*lane)) << (8 * lane)
			}
			got := multiply(lanes, factors)
			for lane := range 8 {
				shift := 8 * lane
				if byte(got>>shift) != scalarProduct(byte(lanes>>shift), byte(factors>>shift)) {
					t.Fatalf("product %016x * %016x in lane %d", lanes, factors, lane)
				}
			}
		}
	}
}

func scalarProduct(a, b byte) byte {
	var polynomial uint16
	for i := range 8 {
		if a&(1<<i) != 0 {
			polynomial ^= uint16(b) << i
		}
	}
	for degree := 14; degree >= 8; degree-- {
		if polynomial&(1<<degree) != 0 {
			polynomial ^= 0x11b << (degree - 8)
		}
	}
	return byte(polynomial)
}

func referenceSbox(x byte) byte {
	var reciprocal byte
	if x != 0 {
		for i := 1; i < 256; i++ {
			if scalarProduct(x, byte(i)) == 1 {
				reciprocal = byte(i)
				break
			}
		}
	}
	return reciprocal ^ bits.RotateLeft8(reciprocal, 1) ^ bits.RotateLeft8(reciprocal, 2) ^
		bits.RotateLeft8(reciprocal, 3) ^ bits.RotateLeft8(reciprocal, 4) ^ 0x63
}

func TestUninitialized(t *testing.T) {
	for _, use := range []func(*Cipher){func(c *Cipher) { c.EncryptBlock([BlockBytes]byte{}) }, func(c *Cipher) {
		c.DecryptBlock([BlockBytes]byte{})
	}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("uninitialized key was accepted")
				}
			}()
			var c Cipher
			use(&c)
		}()
	}
}

func BenchmarkEncryptBlock(b *testing.B) {
	var key [KeyBytes]byte
	c := New(key)
	reference, err := aes.NewCipher(key[:])
	if err != nil {
		b.Fatal(err)
	}
	b.Run("packed-Go", func(b *testing.B) {
		var input [BlockBytes]byte
		b.SetBytes(BlockBytes)
		b.ReportAllocs()
		for b.Loop() {
			input = c.EncryptBlock(input)
		}
	})
	b.Run("standard", func(b *testing.B) {
		var block [BlockBytes]byte
		b.SetBytes(BlockBytes)
		b.ReportAllocs()
		for b.Loop() {
			reference.Encrypt(block[:], block[:])
		}
	})
}

func decoded(t *testing.T, wire string) []byte {
	t.Helper()
	value, err := hex.DecodeString(wire)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
