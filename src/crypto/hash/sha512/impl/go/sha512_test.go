package abcsha512

import (
	"bytes"
	standard "crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestKnownAnswers(t *testing.T) {
	for message, expected := range map[string]string{
		"": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
			"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"abc": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
			"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	} {
		actual := Sum512([]byte(message))
		if hex.EncodeToString(actual[:]) != expected {
			t.Fatalf("SHA-512(%q) = %x", message, actual)
		}
	}
}

func TestProviderAndAllBoundarySplits(t *testing.T) {
	data := make([]byte, 2049)
	for i := range data {
		data[i] = byte(i*i + 17)
	}
	for _, size := range []int{0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 257, 2049} {
		expected := standard.Sum512(data[:size])
		if actual := Sum512(data[:size]); actual != expected {
			t.Fatalf("one-shot size %d", size)
		}
		for split := 0; split <= size; split++ {
			var state Hasher
			transient := bytes.Clone(data[:split])
			if err := state.Update(transient); err != nil {
				t.Fatalf("update size %d: %v", split, err)
			}
			clear(transient)
			first := standard.Sum512(data[:split])
			if state.Digest() != first {
				t.Fatalf("snapshot size %d", split)
			}
			if err := state.Update(data[split:size]); err != nil || state.Digest() != expected {
				t.Fatalf("stream size %d split %d", size, split)
			}
			state.Reset()
			empty := standard.Sum512(nil)
			if state.Digest() != empty {
				t.Fatalf("reset size %d split %d", size, split)
			}
		}
	}
}

func TestOverflowPreservesState(t *testing.T) {
	state := Hasher{state: initial, bytesHigh: (1 << 61) - 1, bytesLow: ^uint64(0) - 1, buffered: 126}
	if err := state.Update([]byte{0x88}); err != nil {
		t.Fatalf("last accepted byte: %v", err)
	}
	expected := state
	if err := state.Update([]byte{0x99}); err != ErrMessageTooLong || state != expected {
		t.Fatalf("overflow changed state: %v", err)
	}
	if err := state.Update(nil); err != nil || state != expected {
		t.Fatalf("empty update changed state: %v", err)
	}
	carry := Hasher{state: initial, bytesLow: ^uint64(0), buffered: 127}
	if err := carry.Update([]byte{0x11}); err != nil || carry.bytesHigh != 1 || carry.bytesLow != 0 {
		t.Fatalf("carry did not reach high word: %v", err)
	}
}

func BenchmarkSum512(b *testing.B) {
	for _, length := range []int{32, 4096} {
		message := make([]byte, length)
		for name, sum := range map[string]func([]byte) [Size]byte{"abc": Sum512, "stdlib": standard.Sum512} {
			b.Run(fmt.Sprintf("%s/%d", name, length), func(b *testing.B) {
				b.SetBytes(int64(length))
				b.ReportAllocs()
				for b.Loop() {
					sum(message)
				}
			})
		}
	}
}
