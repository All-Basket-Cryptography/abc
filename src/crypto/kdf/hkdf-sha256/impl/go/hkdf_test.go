package hkdf

import (
	"bytes"
	refhkdf "crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func decode(t *testing.T, value string) []byte {
	t.Helper()
	bytes, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

func TestRFC5869(t *testing.T) {
	input := bytes.Repeat([]byte{0x0b}, 22)
	for _, test := range []struct {
		name, salt, info, prk, okm string
	}{
		{"A.1", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
			"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
		{"A.3", "", "",
			"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var salt []byte
			if test.salt != "" {
				salt = decode(t, test.salt)
			}
			info := decode(t, test.info)
			prk, err := Extract(salt, input)
			if err != nil || !bytes.Equal(prk[:], decode(t, test.prk)) {
				t.Fatalf("Extract = %x, %v", prk, err)
			}
			output, err := Derive(salt, input, info, 42)
			if err != nil || !bytes.Equal(output, decode(t, test.okm)) {
				t.Fatalf("Derive = %x, %v", output, err)
			}
		})
	}
}

func TestDifferentialAndOutputBounds(t *testing.T) {
	input := bytes.Repeat([]byte{0x42}, 128)
	info := []byte{0, 0xff, 0x70, 0x71, 0x80}
	for _, saltLength := range []int{0, 32, 63, 64, 65, 128} {
		salt := bytes.Repeat([]byte{0x20}, saltLength)
		for _, length := range []int{0, 1, 31, 32, 33, 64, 65, MaxOutputBytes - 1, MaxOutputBytes} {
			want, err := refhkdf.Key(sha256.New, input, salt, string(info), length)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Derive(salt, input, info, length)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("mismatch at salt=%d, output=%d: %v", saltLength, length, err)
			}
		}
	}
	for _, length := range []int{-1, MaxOutputBytes + 1} {
		if got, err := Derive(nil, input, info, length); got != nil || !errors.Is(err, ErrOutputLength) {
			t.Fatalf("unexpected output length result: %x, %v", got, err)
		}
	}
	if got, err := Expand(make([]byte, PRKSize-1), info, 1); got != nil || !errors.Is(err, ErrPRKTooShort) {
		t.Fatalf("unexpected PRK length result: %x, %v", got, err)
	}
}

func FuzzDifferential(f *testing.F) {
	f.Add([]byte{1}, []byte{2}, []byte{3}, uint16(42))
	f.Add(make([]byte, 65), make([]byte, 64), make([]byte, 63), uint16(0))
	f.Fuzz(func(t *testing.T, salt, input, info []byte, requested uint16) {
		if len(salt) > 1024 || len(input) > 1024 || len(info) > 1024 {
			t.Skip()
		}
		length := int(requested) % 257
		want, err := refhkdf.Key(sha256.New, input, salt, string(info), length)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Derive(salt, input, info, length)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("HKDF differential mismatch for salt=%d input=%d info=%d output=%d: %v",
				len(salt), len(input), len(info), length, err)
		}
	})
}
