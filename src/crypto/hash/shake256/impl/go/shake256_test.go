package abcshake256

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"io"
	"testing"
)

func TestKnownAnswers(t *testing.T) {
	for _, vector := range []struct{ input, hex string }{
		{"", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"},
		{"abc", "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"},
	} {
		var output [32]byte
		XOF([]byte(vector.input), output[:])
		if hex.EncodeToString(output[:]) != vector.hex {
			t.Fatalf("known-answer mismatch for %q", vector.input)
		}
	}
}

func TestAllRateBoundarySplits(t *testing.T) {
	lengths := []int{0, 1, 135, 136, 137, 271, 272, 273, 1000}
	for _, length := range lengths {
		message := make([]byte, length)
		for index := range message {
			message[index] = byte(index * 131)
		}
		reference := sha3.NewSHAKE256()
		reference.Write(message)
		var expected, output [409]byte
		io.ReadFull(reference, expected[:])
		XOF(message, output[:])
		if output != expected {
			t.Fatalf("one-shot mismatch at length %d", length)
		}
		for split := 0; split <= length; split++ {
			var absorber Absorber
			absorber.Write(message[:split])
			absorber.Write(nil)
			absorber.Write(message[split:])
			reader := absorber.Finalize()
			offset := 0
			for _, count := range []int{1, 134, 1, 136, 137} {
				if n, err := reader.Read(nil); n != 0 || err != nil {
					t.Fatalf("empty read returned (%d, %v)", n, err)
				}
				if n, err := reader.Read(output[offset : offset+count]); n != count || err != nil {
					t.Fatalf("read returned (%d, %v)", n, err)
				}
				offset += count
			}
			if output != expected {
				t.Fatalf("split mismatch at length %d split %d", length, split)
			}
		}
	}
}

func TestIndependentReadersAndOverlap(t *testing.T) {
	absorber := New()
	message := bytes.Repeat([]byte{7}, 137)
	original := bytes.Clone(message)
	absorber.Write(message)
	first, second := absorber.Finalize(), absorber.Finalize()
	clear(message)
	absorber.Reset()
	absorber.Write([]byte("different message"))
	var read, expected [409]byte
	reference := sha3.NewSHAKE256()
	reference.Write(original)
	io.ReadFull(reference, expected[:])
	first.Read(read[:BlockSize])
	first.Read(read[BlockSize:])
	if read != expected {
		t.Fatal("reader changed when absorber was reset")
	}
	second.Read(read[:])
	if read != expected {
		t.Fatal("separate readers shared state")
	}
	overlap := make([]byte, len(expected)+5)
	copy(overlap, original)
	XOF(overlap[:len(original)], overlap[5:])
	if !bytes.Equal(overlap[5:], expected[:]) {
		t.Fatal("in-place output changed the input before absorption")
	}
}

func BenchmarkXOF32(b *testing.B) {
	for _, length := range []int{32, 4096} {
		message := make([]byte, length)
		b.Run(fmt.Sprintf("native/%d", length), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(length))
			var output [32]byte
			for b.Loop() {
				XOF(message, output[:])
			}
		})
		b.Run(fmt.Sprintf("standard/%d", length), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(length))
			var output [32]byte
			var hasher = sha3.NewSHAKE256()
			for b.Loop() {
				hasher.Reset()
				hasher.Write(message)
				hasher.Read(output[:])
			}
		})
	}
}
