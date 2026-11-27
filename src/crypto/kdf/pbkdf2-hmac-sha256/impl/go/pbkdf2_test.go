package pbkdf2

import (
	"bytes"
	ref "crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestRFC7914(t *testing.T) {
	want, err := hex.DecodeString("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Derive([]byte("passwd"), []byte("salt"), 1, len(want))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("derive = %x, %v", got, err)
	}
}

func TestDifferential(t *testing.T) {
	for _, plen := range []int{0, 63, 64, 65, 4096} {
		password := bytes.Repeat([]byte{0x4f}, plen)
		for _, slen := range []int{0, 59, 60, 61, 133} {
			salt := bytes.Repeat([]byte{0x85}, slen)
			for _, rounds := range []uint32{1, 2, 17} {
				for _, length := range []int{1, 31, 32, 33, 65, 8193} {
					want, err := ref.Key(sha256.New, string(password), salt, int(rounds), length)
					if err != nil {
						t.Fatal(err)
					}
					got, err := Derive(password, salt, rounds, length)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("mismatch with p=%d, salt=%d, rounds=%d, size=%d, err=%v", plen, slen, rounds, length, err)
					}
				}
			}
		}
	}
}

func TestInvalidLengths(t *testing.T) {
	if out, err := Derive(nil, nil, 0, 32); out != nil || !errors.Is(err, ErrIterations) {
		t.Fatalf("zero rounds: %v, %v", out, err)
	}
	for _, length := range []int{-1, 0} {
		if out, err := Derive(nil, nil, 1, length); out != nil || !errors.Is(err, ErrOutput) {
			t.Fatalf("length %d: %v, %v", length, out, err)
		}
	}
}
