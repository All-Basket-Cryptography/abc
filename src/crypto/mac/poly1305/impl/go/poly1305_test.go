package poly1305

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"math/rand/v2"
	"slices"
	"testing"
)

func TestRFC8439(t *testing.T) {
	key := [KeyBytes]byte(decoded(t, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"))
	msg := []byte("Cryptographic Forum Research Group")
	tag := [TagBytes]byte(decoded(t, "a8061dc1305136c6c22b8baf0c0127a9"))
	checkSplits(t, key, msg, tag)

	fillBlock := func(first, following byte) [16]byte {
		value := [16]byte(bytes.Repeat([]byte{following}, 16))
		value[0] = first
		return value
	}
	var zero [16]byte
	ones := fillBlock(255, 255)
	first, second := fillBlock(1, 0), fillBlock(2, 0)
	vectors := []struct {
		r, s [16]byte
		msg  [][16]byte
		tag  [TagBytes]byte
	}{
		{second, zero, [][16]byte{ones}, fillBlock(3, 0)},
		{second, ones, [][16]byte{second}, fillBlock(3, 0)},
		{first, zero, [][16]byte{ones, fillBlock(0xf0, 0xff), fillBlock(17, 0)}, fillBlock(5, 0)},
		{first, zero, [][16]byte{ones, fillBlock(0xfb, 0xfe), fillBlock(1, 1)}, zero},
		{second, zero, [][16]byte{fillBlock(0xfd, 0xff)}, fillBlock(0xfa, 0xff)},
		{
			[16]byte{0: 1, 8: 4}, zero,
			[][16]byte{
				[16]byte(decoded(t, "e33594d7505e43b90000000000000000")),
				[16]byte(decoded(t, "3394d7505e4379cd0100000000000000")),
				zero, first,
			},
			[16]byte{0: 0x14, 8: 0x55},
		},
		{
			[16]byte{0: 1, 8: 4}, zero,
			[][16]byte{
				[16]byte(decoded(t, "e33594d7505e43b90000000000000000")),
				[16]byte(decoded(t, "3394d7505e4379cd0100000000000000")),
				zero,
			},
			[16]byte{0x13},
		},
	}
	for _, vector := range vectors {
		var key [KeyBytes]byte
		copy(key[:16], vector.r[:])
		copy(key[16:], vector.s[:])
		var message []byte
		for _, block := range vector.msg {
			message = append(message, block[:]...)
		}
		checkSplits(t, key, message, vector.tag)
	}
}

func TestIndependentIntegerOracle(t *testing.T) {
	rng := rand.New(rand.NewPCG(8439, 1305))
	for i := range 2126 {
		var key [KeyBytes]byte
		width := rng.IntN(515)
		if i < 126 {
			width = i
		}
		message := make([]byte, width)
		for _, buf := range [][]byte{key[:], message} {
			for j := range buf {
				buf[j] = byte(rng.Uint32())
			}
		}
		want := integerOracle(key, message)
		if got := Sum(key, message); got != want {
			t.Fatalf("oracle case %d: %x != %x", i, got, want)
		}
		m := New(key)
		for offset := 0; offset < len(message); {
			end := min(offset+1+rng.IntN(37), len(message))
			chunk := bytes.Clone(message[offset:end])
			if err := m.Update(chunk); err != nil {
				t.Fatal(err)
			}
			clear(chunk)
			offset = end
		}
		if got, err := m.Finalize(); err != nil || got != want {
			t.Fatalf("streaming oracle case %d: %x != %x, %v", i, got, want, err)
		}
	}
	t.Log("2,126 independent integer comparisons and streaming traces")
}

func TestStateAndEmptyMessage(t *testing.T) {
	var m MAC
	if err := m.Update([]byte{1}); err != ErrState {
		t.Fatal("uninitialized Update accepted")
	}
	if _, err := m.Finalize(); err != ErrState {
		t.Fatal("uninitialized Finalize accepted")
	}
	key := [KeyBytes]byte{16: 0xa9, 31: 0x72}
	want := [TagBytes]byte(key[16:])
	if got := Sum(key, nil); got != want {
		t.Fatalf("empty input: %x != %x", got, want)
	}
	if got := Sum(key, make([]byte, 73)); got != want {
		t.Fatalf("zero multiplier: %x != %x", got, want)
	}
	fresh := New(key)
	if got, err := fresh.Finalize(); err != nil || got != want {
		t.Fatal("empty Finalize mismatch")
	}
	if err := fresh.Update(nil); err != ErrState {
		t.Fatal("Update after Finalize accepted")
	}
	if got, err := fresh.Finalize(); err != nil || got != want {
		t.Fatal("repeated Finalize mismatch")
	}
	if fresh.r != [5]uint64{} || fresh.pad != [4]uint32{} || fresh.residue != [5]uint64{} {
		t.Fatal("key-derived state retained in the object")
	}
}

func checkSplits(t *testing.T, key [KeyBytes]byte, message []byte, expected [TagBytes]byte) {
	t.Helper()
	if got := Sum(key, message); got != expected {
		t.Fatalf("one-shot: %x != %x", got, expected)
	}
	for split := 0; split <= len(message); split++ {
		m := New(key)
		for _, chunk := range [][]byte{message[:split], nil, message[split:]} {
			if err := m.Update(chunk); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := m.Finalize(); err != nil || got != expected {
			t.Fatalf("split %d: %x != %x, %v", split, got, expected, err)
		}
	}
}

func integerOracle(key [KeyBytes]byte, message []byte) [TagBytes]byte {
	little := func(b []byte) *big.Int {
		order := bytes.Clone(b)
		slices.Reverse(order)
		return new(big.Int).SetBytes(order)
	}
	mask, _ := new(big.Int).SetString("0ffffffc0ffffffc0ffffffc0fffffff", 16)
	r := new(big.Int).And(little(key[:16]), mask)
	s := little(key[16:])
	modulus := new(big.Int).Lsh(big.NewInt(1), 130)
	modulus.Sub(modulus, big.NewInt(5))
	h := new(big.Int)
	for len(message) != 0 {
		width := min(len(message), 16)
		block := new(big.Int).Lsh(big.NewInt(1), uint(8*width))
		block.Add(block, little(message[:width]))
		h.Add(h, block).Mul(h, r).Mod(h, modulus)
		message = message[width:]
	}
	h.Add(h, s).Mod(h, new(big.Int).Lsh(big.NewInt(1), 128))
	var output [TagBytes]byte
	h.FillBytes(output[:])
	slices.Reverse(output[:])
	return output
}

func decoded(t *testing.T, encoded string) []byte {
	t.Helper()
	wire, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
