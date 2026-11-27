package abcblake2b

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"testing"
)

func pattern(length int) []byte {
	input := make([]byte, length)
	for i := range input {
		input[i] = byte(37*i + 11)
	}
	return input
}

func TestRFC7693(t *testing.T) {
	var digest [64]byte
	if err := Sum([]byte("abc"), digest[:]); err != nil {
		t.Fatal(err)
	}
	expected := "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d" +
		"87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
	if hex.EncodeToString(digest[:]) != expected {
		t.Fatal("RFC 7693 Appendix A digest mismatch")
	}
	var short [32]byte
	if err := Sum([]byte("abc"), short[:]); err != nil || bytes.Equal(digest[:32], short[:]) {
		t.Fatal("digest length is not bound to the initial state")
	}
}

func TestEverySizeAndFinalBlockSplit(t *testing.T) {
	fingerprint := sha256.New()
	var digest, snapshot [64]byte
	for _, length := range []int{0, 1, 127, 128, 129, 255, 256, 257, 1000} {
		message := pattern(length)
		for size := 1; size <= MaxDigestSize; size++ {
			if err := Sum(message, digest[:size]); err != nil {
				t.Fatal(err)
			}
			fingerprint.Write(digest[:size])
			if size != 1 && size != 31 && size != 64 {
				continue
			}
			for split := 0; split <= length; split++ {
				h, err := New(size)
				if err != nil {
					t.Fatal(err)
				}
				if err := h.Update(message[:split]); err != nil {
					t.Fatal(err)
				}
				if err := h.Update(nil); err != nil {
					t.Fatal(err)
				}
				if err := h.Update(message[split:]); err != nil {
					t.Fatal(err)
				}
				if err := h.Finalize(snapshot[:size]); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(snapshot[:size], digest[:size]) {
					t.Fatalf("digest mismatch at length %d size %d split %d", length, size, split)
				}
			}
		}
	}
	// SHA-256 of the 576 independent Python hashlib.blake2b results.
	if got := hex.EncodeToString(fingerprint.Sum(nil)); got != "7722eb20825ceb22cb3f50eeefe50421c921908ef28f006d6750bc9389542bb9" {
		t.Fatalf("reference digest aggregate mismatch: %s", got)
	}
}

func TestSnapshotsOwnershipAndErrors(t *testing.T) {
	for _, invalid := range []int{-1, 0, 65} {
		if _, err := New(invalid); err != ErrDigestSize {
			t.Fatalf("accepted digest size %d", invalid)
		}
	}
	var h Hasher
	message := pattern(129)
	if err := h.Update(message[:128]); err != nil {
		t.Fatal(err)
	}
	first, second, expected := make([]byte, 64), make([]byte, 64), make([]byte, 64)
	invalid := bytes.Repeat([]byte{0xa5}, 63)
	if err := h.Finalize(invalid); err != ErrOutputSize || !bytes.Equal(invalid, bytes.Repeat([]byte{0xa5}, 63)) {
		t.Fatal("invalid output buffer was modified")
	}
	if err := Sum(message[:128], expected); err != nil {
		t.Fatal(err)
	}
	clear(message[:128])
	if err := h.Finalize(first); err != nil || !bytes.Equal(first, expected) {
		t.Fatal("snapshot changed after caller reused input")
	}
	if err := h.Update(message[128:]); err != nil {
		t.Fatal(err)
	}
	if err := h.Finalize(second); err != nil {
		t.Fatal(err)
	}
	message = pattern(129)
	if err := Sum(message, message[9:73]); err != nil || !bytes.Equal(message[9:73], second) {
		t.Fatal("overlapping one-shot output mismatch")
	}
	h.Reset()
	if err := h.Finalize(first); err != nil {
		t.Fatal(err)
	}
	if err := Sum(nil, expected); err != nil || h.Size() != 64 || !bytes.Equal(first, expected) {
		t.Fatal("reset state mismatch")
	}
}

func TestCounterOverflow(t *testing.T) {
	h := withSize(1)
	h.lengthLow, h.lengthHigh, h.used = math.MaxUint64-1, math.MaxUint64, 126
	if err := h.Update([]byte{11}); err != nil || h.lengthLow != math.MaxUint64 {
		t.Fatal("should accept the largest representable byte count")
	}
	snapshot := h
	if err := h.Update([]byte{77}); err != ErrMessageLimit || h != snapshot {
		t.Fatal("counter overflow changed the context")
	}
	if err := h.Update(nil); err != nil || h != snapshot {
		t.Fatal("zero-byte update changed a full context")
	}
}

func BenchmarkSum4096(b *testing.B) {
	var input [4096]byte
	var output [64]byte
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		Sum(input[:], output[:])
	}
}
