package sha256

import (
	"bytes"
	standard "crypto/sha256"
	"encoding/hex"
	"math/rand"
	"strconv"
	"testing"
)

func BenchmarkSHA256(b *testing.B) {
	for _, size := range []int{64, 4096} {
		message := make([]byte, size)
		b.Run("abc/"+strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				if _, err := Sum256(message); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("stdlib/"+strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				standard.Sum256(message)
			}
		})
	}
}

func TestKnownAnswers(t *testing.T) {
	vectors := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", nil, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", []byte("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"two-padding-blocks", []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
			"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
		{"million-a", bytes.Repeat([]byte{'a'}, 1_000_000),
			"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			got, err := Sum256(vector.data)
			if err != nil || hex.EncodeToString(got[:]) != vector.want {
				t.Fatalf("Sum256 = %x, %v, want %s", got, err, vector.want)
			}
			var h Hasher
			for start := 0; start < len(vector.data); start += 4093 {
				if err := h.Update(vector.data[start:min(start+4093, len(vector.data))]); err != nil {
					t.Fatal(err)
				}
			}
			got = h.Digest()
			if hex.EncodeToString(got[:]) != vector.want {
				t.Fatalf("streaming digest = %x, want %s", got, vector.want)
			}
		})
	}
}

func TestEveryTwoChunkSplitAtBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 255, 256, 257} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(31*i + 17)
		}
		want := standard.Sum256(data)
		for split := 0; split <= size; split++ {
			var h Hasher
			if err := h.Update(data[:split]); err != nil {
				t.Fatal(err)
			}
			if err := h.Update(nil); err != nil {
				t.Fatal(err)
			}
			if err := h.Update(data[split:]); err != nil {
				t.Fatal(err)
			}
			if got := h.Digest(); got != want {
				t.Fatalf("length %d, split %d: %x, want %x", size, split, got, want)
			}
		}
	}
}

func TestSnapshotResetAndInputOwnership(t *testing.T) {
	h := New()
	input := []byte("abc")
	if err := h.Update(input); err != nil {
		t.Fatal(err)
	}
	input[0] = 'x'
	before := *h
	want := standard.Sum256([]byte("abc"))
	if got := h.Digest(); got != want || *h != before || h.Digest() != want {
		t.Fatalf("digest snapshot = %x, want %x without modifying the state", got, want)
	}
	if err := h.Update([]byte("def")); err != nil {
		t.Fatal(err)
	}
	if got, want := h.Digest(), standard.Sum256([]byte("abcdef")); got != want {
		t.Fatalf("extended digest = %x, want %x", got, want)
	}
	h.Reset()
	if got, want := h.Digest(), standard.Sum256(nil); got != want {
		t.Fatalf("reset digest = %x, want %x", got, want)
	}
}

func TestLengthLimitRejectsBeforeMutation(t *testing.T) {
	// Set the metadata directly to exercise the domain edge without a giant input.
	h := Hasher{state: initialState, used: 62, length: MaxMessageBytes - 1}
	if err := h.Update([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if h.length != MaxMessageBytes || h.used != 63 {
		t.Fatalf("maximal accepted state has length %d and tail %d", h.length, h.used)
	}
	before := h
	if err := h.Update([]byte{2}); err != ErrMessageTooLong || h != before {
		t.Fatalf("overflow update = %v; the entire state must be preserved", err)
	}
	if err := h.Update(nil); err != nil || h != before {
		t.Fatalf("empty update at the limit = %v; the state must be preserved", err)
	}
}

func TestDeterministicDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(42026))
	for i := 0; i < 512; i++ {
		data := make([]byte, rng.Intn(8193))
		_, _ = rng.Read(data)
		compareWithStandard(t, data, 1+rng.Intn(257))
	}
}

func FuzzDifferential(f *testing.F) {
	for _, size := range []int{0, 1, 55, 56, 63, 64, 65, 129} {
		f.Add(bytes.Repeat([]byte{0x9b}, size), uint8(size))
	}
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		compareWithStandard(t, data, int(chunk)+1)
	})
}

func compareWithStandard(t testing.TB, data []byte, chunk int) {
	t.Helper()
	want := standard.Sum256(data)
	got, err := Sum256(data)
	if err != nil || got != want {
		t.Fatalf("length %d: Sum256 = %x, %v, want %x", len(data), got, err, want)
	}
	var h Hasher
	for start := 0; start < len(data); start += chunk {
		if err := h.Update(data[start:min(start+chunk, len(data))]); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.Digest(); got != want {
		t.Fatalf("length %d, chunk %d: streaming digest = %x, want %x", len(data), chunk, got, want)
	}
}
