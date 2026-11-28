package abcsha3

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestKnownAnswers(t *testing.T) {
	vectors := []struct {
		input []byte
		hex   string
	}{
		{nil, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
		{[]byte("abc"), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
		{bytes.Repeat([]byte{0xa3}, 200), "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"},
	}
	for _, vector := range vectors {
		digest := Sum256(vector.input)
		if hex.EncodeToString(digest[:]) != vector.hex {
			t.Fatalf("known-answer mismatch at length %d", len(vector.input))
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
		expected := sha3.Sum256(message)
		if actual := Sum256(message); actual != expected {
			t.Fatalf("single update mismatch at length %d", length)
		}
		for split := 0; split <= length; split++ {
			var hasher Hasher
			hasher.Write(message[:split])
			if hasher.Digest() != sha3.Sum256(message[:split]) {
				t.Fatalf("snapshot mismatch at length %d split %d", length, split)
			}
			hasher.Write(nil)
			hasher.Write(message[split:])
			if actual := hasher.Digest(); actual != expected {
				t.Fatalf("digest mismatch at length %d split %d", length, split)
			}
			prefix := []byte{0x5a, 0xa5}
			if actual := hasher.Sum(prefix); !bytes.Equal(actual[:2], prefix) || !bytes.Equal(actual[2:], expected[:]) {
				t.Fatalf("hash.Hash Sum mismatch at length %d split %d", length, split)
			}
		}
	}
}

func TestWriteOwnershipAndReset(t *testing.T) {
	hasher := New()
	message := bytes.Repeat([]byte{7}, 137)
	expected := sha3.Sum256(message)
	if n, err := hasher.Write(message); n != len(message) || err != nil {
		t.Fatalf("Write returned (%d, %v)", n, err)
	}
	clear(message)
	if hasher.Digest() != expected {
		t.Fatal("absorber retained caller data")
	}
	hasher.Reset()
	if hasher.Digest() != sha3.Sum256(nil) || hasher.Size() != Size || hasher.BlockSize() != BlockSize {
		t.Fatal("reset or size metadata mismatch")
	}
}

func BenchmarkSum256(b *testing.B) {
	for _, length := range []int{32, 4096} {
		message := make([]byte, length)
		b.Run(fmt.Sprintf("native/%d", length), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(length))
			for b.Loop() {
				Sum256(message)
			}
		})
		b.Run(fmt.Sprintf("standard/%d", length), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(length))
			for b.Loop() {
				sha3.Sum256(message)
			}
		})
	}
}
