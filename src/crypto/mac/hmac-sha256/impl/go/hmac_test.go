package hmacsha256

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func repeatByte(value byte, count int) []byte { return bytes.Repeat([]byte{value}, count) }

func decodeHex(t *testing.T, input string) []byte {
	t.Helper()
	result, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRFC4231(t *testing.T) {
	vectors := []struct {
		name         string
		key, message []byte
		expected     string
	}{
		{"1", repeatByte(0x0b, 20), []byte("Hi There"), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
		{"2", []byte("Jefe"), []byte("what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
		{"3", repeatByte(0xaa, 20), repeatByte(0xdd, 50), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"},
		{"4", decodeHex(t, "0102030405060708090a0b0c0d0e0f10111213141516171819"), repeatByte(0xcd, 50),
			"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"},
		{"5", repeatByte(0x0c, 20), []byte("Test With Truncation"), "a3b6167473100ee06e0c796c2955552b"},
		{"6", repeatByte(0xaa, 131), []byte("Test Using Larger Than Block-Size Key - Hash Key First"),
			"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
		{"7", repeatByte(0xaa, 131), decodeHex(t, "5468697320697320612074657374207573696e672061206c6172676572207468"+
			"616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a652064"+
			"6174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365"+
			"642062792074686520484d414320616c676f726974686d2e"), "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			tag, err := Authenticate(vector.key, vector.message)
			if err != nil {
				t.Fatal(err)
			}
			// Case 5 publishes the first 16 bytes of the full tag.
			expected := decodeHex(t, vector.expected)
			if !bytes.Equal(tag[:len(expected)], expected) {
				t.Fatalf("tag = %x, want prefix %x", tag, expected)
			}
		})
	}
}

func oracleTag(key, message []byte) [Size]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return [Size]byte(mac.Sum(nil))
}

func checkTrace(t *testing.T, key, data []byte, split int) {
	t.Helper()
	m, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Update(data[:split]); err != nil {
		t.Fatal(err)
	}
	if tag, err := m.Digest(); err != nil || tag != oracleTag(key, data[:split]) {
		t.Fatalf("prefix tag = %x, error = %v", tag, err)
	}
	if err := m.Update(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Update(data[split:]); err != nil {
		t.Fatal(err)
	}
	want := oracleTag(key, data)
	for range 2 {
		if tag, err := m.Digest(); err != nil || tag != want {
			t.Fatalf("streaming tag = %x, want %x, error = %v", tag, want, err)
		}
	}
	if tag, err := Authenticate(key, data); err != nil || tag != want {
		t.Fatalf("one-shot tag = %x, want %x, error = %v", tag, want, err)
	}
}

func sequence(length int) []byte {
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(i*193 + length*17)
	}
	return data
}

func TestDifferentialBoundaries(t *testing.T) {
	for _, keyLength := range []int{0, 1, 32, 63, 64, 65, 131} {
		for _, dataLength := range []int{0, 1, 55, 56, 63, 64, 65, 119, 120, 257} {
			t.Run(fmt.Sprintf("key-%d/data-%d", keyLength, dataLength), func(t *testing.T) {
				key, data := sequence(keyLength), sequence(dataLength)
				for split := 0; split <= len(data); split++ {
					checkTrace(t, key, data, split)
				}
			})
		}
	}
}

func TestCallerBuffersAndErrors(t *testing.T) {
	key := sequence(65)
	data := sequence(37)
	want := oracleTag(key, data)
	m, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	if err := m.Update(data); err != nil {
		t.Fatal(err)
	}
	clear(data)
	if tag, err := m.Digest(); err != nil || tag != want {
		t.Fatalf("tag after changing caller buffers = %x, want %x, error = %v", tag, want, err)
	}
	// Exercise admission at its limit without allocating an enormous message.
	m.messageBytes = MaxInputBytes
	before := *m
	if err := m.Update([]byte{7}); err != ErrMessageTooLong || *m != before {
		t.Fatalf("over-limit update changed the context or returned %v", err)
	}
	if err := m.Update(nil); err != nil || *m != before {
		t.Fatalf("empty update at the limit changed the context or returned %v", err)
	}
	for _, invalid := range []*Hasher{nil, {}} {
		if err := invalid.Update(nil); err != ErrUninitialized {
			t.Fatalf("uninitialized update error = %v", err)
		}
		if tag, err := invalid.Digest(); err != ErrUninitialized || tag != ([Size]byte{}) {
			t.Fatalf("uninitialized digest = %x, error = %v", tag, err)
		}
	}
}

func FuzzDifferential(f *testing.F) {
	for _, size := range []int{0, 1, 63, 64, 65, 131} {
		f.Add(sequence(size), sequence(size+7), uint16(size/2))
	}
	f.Fuzz(func(t *testing.T, key, data []byte, split uint16) {
		checkTrace(t, key, data, int(split)%(len(data)+1))
	})
}
