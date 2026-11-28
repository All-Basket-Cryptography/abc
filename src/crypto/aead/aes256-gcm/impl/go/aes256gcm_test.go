package aes256gcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand/v2"
	"testing"
)

func TestNISTExamples(t *testing.T) {
	cases := []struct {
		key, nonce, plaintext, associated, ciphertext, tag string
	}{
		{"0000000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000", "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"},
		{"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			"cafebabefacedbaddecaf888",
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
				"1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			"3ad77bb40d7a3660a89ecaf32466ef97f5d3d585",
			"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
				"8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
			"e097195f4532da895fb917a5a55c6aa0"},
	}
	for _, test := range cases {
		key := [KeyBytes]byte(decoded(t, test.key))
		nonce := [NonceBytes]byte(decoded(t, test.nonce))
		plaintext, aad := decoded(t, test.plaintext), decoded(t, test.associated)
		want := decoded(t, test.ciphertext)
		wantTag := [TagBytes]byte(decoded(t, test.tag))
		var ciphertext = make([]byte, len(plaintext))
		g := New(key)
		tag, err := g.SealDetached(ciphertext, plaintext, aad, nonce)
		if err != nil || tag != wantTag || !bytes.Equal(ciphertext, want) {
			t.Fatalf("NIST seal: %v, ciphertext %x, tag %x", err, ciphertext, tag)
		}
		if err := g.OpenDetached(ciphertext, ciphertext, aad, tag, nonce); err != nil || !bytes.Equal(ciphertext, plaintext) {
			t.Fatalf("NIST open: %v", err)
		}
	}
}

func TestIndependentGoProvider(t *testing.T) {
	rng := rand.New(rand.NewPCG(38, 256))
	sizes := []int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65}
	for i := range 400 {
		var key [KeyBytes]byte
		var nonce [NonceBytes]byte
		payloadLen, aadLen := rng.IntN(1280), rng.IntN(512)
		if i < len(sizes)*len(sizes) {
			payloadLen, aadLen = sizes[i/len(sizes)], sizes[i%len(sizes)]
		}
		plaintext, aad := make([]byte, payloadLen), make([]byte, aadLen)
		for _, data := range [][]byte{key[:], nonce[:], plaintext, aad} {
			for j := range data {
				data[j] = byte(rng.Uint32())
			}
		}
		provider := standardGCM(t, key)
		want := provider.Seal(nil, nonce[:], plaintext, aad)
		g := New(key)
		ciphertext := make([]byte, payloadLen)
		tag, err := g.SealDetached(ciphertext, plaintext, aad, nonce)
		if err != nil || !bytes.Equal(ciphertext, want[:payloadLen]) || tag != [TagBytes]byte(want[payloadLen:]) {
			t.Fatalf("independent seal case %d: %v", i, err)
		}
		plain, err := provider.Open(nil, nonce[:], append(ciphertext, tag[:]...), aad)
		if err != nil || !bytes.Equal(plain, plaintext) {
			t.Fatalf("standard provider opening case %d: %v", i, err)
		}
		if err := g.OpenDetached(ciphertext, want[:payloadLen], aad, [TagBytes]byte(want[payloadLen:]), nonce); err != nil ||
			!bytes.Equal(ciphertext, plaintext) {
			t.Fatalf("opening standard provider case %d: %v", i, err)
		}
	}
	t.Log("400 bidirectional crypto/aes and crypto/cipher comparisons")
}

func TestRejectionPreservesOutput(t *testing.T) {
	g := New([KeyBytes]byte{9: 0x42})
	aad := []byte("associated data")
	for _, size := range []int{0, 1, 15, 16, 17, 33, 73, 257} {
		nonce := [NonceBytes]byte{0: byte(size)}
		plaintext := bytes.Repeat([]byte{0xc4}, size)
		ciphertext := make([]byte, size)
		tag, err := g.SealDetached(ciphertext, plaintext, aad, nonce)
		if err != nil {
			t.Fatal(err)
		}
		for j := range tag {
			tampered := tag
			tampered[j] ^= 1
			inPlace := bytes.Clone(ciphertext)
			if err := g.OpenDetached(inPlace, inPlace, aad, tampered, nonce); err != ErrAuthentication ||
				!bytes.Equal(inPlace, ciphertext) {
				t.Fatalf("tampered tag byte %d at length %d wrote destination", j, size)
			}
		}
		canary := bytes.Repeat([]byte{0xf3}, size+4)
		out := bytes.Clone(canary)
		if err := g.OpenDetached(out, ciphertext, []byte("wrong"), tag, nonce); err != ErrAuthentication ||
			!bytes.Equal(out, canary) {
			t.Fatalf("tampered AAD at length %d wrote destination", size)
		}
		if size != 0 {
			tampered := bytes.Clone(ciphertext)
			tampered[len(tampered)-1] ^= 1
			if err := g.OpenDetached(out, tampered, aad, tag, nonce); err != ErrAuthentication ||
				!bytes.Equal(out, canary) {
				t.Fatalf("tampered ciphertext at length %d wrote destination", size)
			}
			if _, err := g.SealDetached(out[:size-1], plaintext, aad, nonce); err != ErrShortDestination ||
				!bytes.Equal(out, canary) {
				t.Fatalf("short seal buffer at length %d wrote destination", size)
			}
			if err := g.OpenDetached(out[:size-1], ciphertext, aad, tag, nonce); err != ErrShortDestination ||
				!bytes.Equal(out, canary) {
				t.Fatalf("short open buffer at length %d wrote destination", size)
			}
		}
	}
	var uninitialized GCM
	var destination = []byte{0xab}
	if _, err := uninitialized.SealDetached(destination, destination, nil, [NonceBytes]byte{}); err != ErrUninitialized ||
		destination[0] != 0xab {
		t.Fatal("an uninitialized key was accepted")
	}
}

func TestLimits(t *testing.T) {
	for _, test := range []struct {
		payload, aad uint64
		fits         bool
	}{
		{0, 0, true},
		{maxPayloadBytes, maxAADBytes, true},
		{maxPayloadBytes + 1, 0, false},
		{0, maxAADBytes + 1, false},
		{math.MaxUint64, math.MaxUint64, false},
	} {
		if got := lengthsFit(test.payload, test.aad); got != test.fits {
			t.Fatalf("lengthsFit(%d, %d) = %v", test.payload, test.aad, got)
		}
	}
}

func TestOverlap(t *testing.T) {
	g := New([KeyBytes]byte{3: 37, 27: 4})
	nonce := [NonceBytes]byte{2: 84}
	buffer := make([]byte, 160)
	for i := range buffer {
		buffer[i] = byte(81 * i)
	}
	input, aad := buffer[:74], buffer[14:33]
	plaintext := bytes.Clone(input)
	associated := bytes.Clone(aad)
	expected := make([]byte, len(plaintext))
	wantTag, err := g.SealDetached(expected, plaintext, associated, nonce)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := buffer[9 : 9+len(input)]
	suffix := bytes.Clone(buffer[9+len(input):])
	tag, err := g.SealDetached(buffer[9:], input, aad, nonce)
	if err != nil || tag != wantTag || !bytes.Equal(ciphertext, expected) ||
		!bytes.Equal(buffer[9+len(input):], suffix) {
		t.Fatalf("overlapping seal: %v", err)
	}
	copy(buffer[:len(associated)], associated)
	copy(buffer[31:], expected)
	if err := g.OpenDetached(buffer[3:], buffer[31:31+len(expected)], buffer[:len(associated)], tag, nonce); err != nil ||
		!bytes.Equal(buffer[3:3+len(plaintext)], plaintext) {
		t.Fatalf("overlapping open: %v", err)
	}
}

func BenchmarkSeal(b *testing.B) {
	var key [KeyBytes]byte
	g := New(key)
	provider := standardGCM(b, key)
	for _, length := range []int{64, 4096} {
		input := make([]byte, length)
		aad := make([]byte, 16)
		b.Run(fmt.Sprintf("packed-Go-%d", length), func(b *testing.B) {
			var nonce [NonceBytes]byte
			var counter uint64
			dst := make([]byte, length)
			b.SetBytes(int64(length))
			b.ReportAllocs()
			for b.Loop() {
				binary.BigEndian.PutUint64(nonce[4:], counter)
				counter++
				if _, err := g.SealDetached(dst, input, aad, nonce); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("standard-%d", length), func(b *testing.B) {
			var nonce [NonceBytes]byte
			var counter uint64
			dst := make([]byte, 0, length+TagBytes)
			b.SetBytes(int64(length))
			b.ReportAllocs()
			for b.Loop() {
				binary.BigEndian.PutUint64(nonce[4:], counter)
				counter++
				provider.Seal(dst, nonce[:], input, aad)
			}
		})
	}
}

func standardGCM(t testing.TB, key [KeyBytes]byte) cipher.AEAD {
	t.Helper()
	ref, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(ref)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func decoded(t *testing.T, wire string) []byte {
	t.Helper()
	data, err := hex.DecodeString(wire)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
