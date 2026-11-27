package ecdsap256_test

import (
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	p256 "github.com/All-Basket-Cryptography/abc/src/crypto/signature/ecdsa-p256-sha256/impl/go"
)

const orderHex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"

func unhex(t testing.TB, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func rfcKey(t testing.TB) [p256.PrivateKeySize]byte {
	t.Helper()
	return [p256.PrivateKeySize]byte(unhex(t, "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"))
}

func TestRFC6979(t *testing.T) {
	key := rfcKey(t)
	public, err := p256.PublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(public[:]) != "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"+
		"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299" {
		t.Fatalf("RFC 6979 public key mismatch: %x", public)
	}
	compressed := append([]byte{3}, public[1:33]...)
	for _, pair := range []struct{ message, signature string }{
		{"sample", "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" +
			"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"},
		{"test", "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" +
			"019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"},
	} {
		message := []byte(pair.message)
		for i := 0; i < 2; i++ {
			signature, err := p256.Sign(key, message)
			if err != nil || hex.EncodeToString(signature[:]) != pair.signature {
				t.Fatalf("RFC 6979 %q signature mismatch: %x (%v)", message, signature, err)
			}
			for _, encoding := range [][]byte{public[:], compressed} {
				if err := p256.Verify(encoding, message, signature[:]); err != nil {
					t.Fatalf("RFC 6979 %q verify failed: %v", message, err)
				}
			}
			otherS := new(big.Int).Sub(new(big.Int).SetBytes(unhex(t, orderHex)), new(big.Int).SetBytes(signature[32:]))
			otherS.FillBytes(signature[32:])
			if err := p256.Verify(public[:], message, signature[:]); err != nil {
				t.Fatalf("alternate S representative rejected: %v", err)
			}
		}
	}
}

func TestRejectInvalidEncodings(t *testing.T) {
	key := rfcKey(t)
	message := []byte("sample")
	public, err := p256.PublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := p256.Sign(key, message)
	if err != nil {
		t.Fatal(err)
	}
	order := [p256.PrivateKeySize]byte(unhex(t, orderHex))
	allOnes := [p256.PrivateKeySize]byte(unhex(t, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
	for _, invalid := range [][p256.PrivateKeySize]byte{{}, order, allOnes} {
		if result, err := p256.PublicKey(invalid); !errors.Is(err, p256.ErrInvalidPrivateKey) || result != [p256.PublicKeySize]byte{} {
			t.Fatalf("invalid private scalar accepted: %x (%v)", invalid, err)
		}
		if result, err := p256.Sign(invalid, message); !errors.Is(err, p256.ErrInvalidPrivateKey) || result != [p256.SignatureSize]byte{} {
			t.Fatalf("invalid private scalar signed: %x (%v)", invalid, err)
		}
	}

	// Adjacent valid private scalars bound the accepted interval.
	var first [p256.PrivateKeySize]byte
	first[len(first)-1] = 1
	last := order
	last[len(last)-1]--
	for _, valid := range [][p256.PrivateKeySize]byte{first, last} {
		point, err := p256.PublicKey(valid)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := p256.Sign(valid, message)
		if err != nil {
			t.Fatal(err)
		}
		if err := p256.Verify(point[:], message, sig[:]); err != nil {
			t.Fatal(err)
		}
	}

	hybrid := public
	hybrid[0] = 7
	offCurve := [p256.PublicKeySize]byte{4}
	badCompressed := append([]byte{2}, allOnes[:]...)
	for _, bad := range [][]byte{nil, {0}, public[:64], hybrid[:], offCurve[:], badCompressed} {
		if err := p256.Verify(bad, message, signature[:]); !errors.Is(err, p256.ErrInvalidPublicKey) {
			t.Fatalf("invalid public key accepted: %x (%v)", bad, err)
		}
	}
	if err := p256.Verify(public[:], message, signature[:63]); !errors.Is(err, p256.ErrInvalidSignature) {
		t.Fatalf("truncated signature accepted: %v", err)
	}
	if err := p256.Verify(public[:], message, append(append([]byte{}, signature[:]...), 0)); !errors.Is(err, p256.ErrInvalidSignature) {
		t.Fatalf("extended signature accepted: %v", err)
	}
	for _, offset := range []int{0, 32} {
		for _, bad := range [][32]byte{{}, order} {
			changed := signature
			copy(changed[offset:], bad[:])
			if err := p256.Verify(public[:], message, changed[:]); !errors.Is(err, p256.ErrInvalidSignature) {
				t.Fatalf("invalid signature scalar accepted: %v", err)
			}
		}
	}
	changed := signature
	changed[0] ^= 1
	if err := p256.Verify(public[:], message, changed[:]); !errors.Is(err, p256.ErrVerificationFailed) {
		t.Fatalf("changed signature accepted: %v", err)
	}
	if err := p256.Verify(public[:], []byte("test"), signature[:]); !errors.Is(err, p256.ErrVerificationFailed) {
		t.Fatalf("wrong message accepted: %v", err)
	}
	other, err := p256.PublicKey(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := p256.Verify(other[:], message, signature[:]); !errors.Is(err, p256.ErrVerificationFailed) {
		t.Fatalf("wrong public key accepted: %v", err)
	}
}

func BenchmarkSDK(b *testing.B) {
	key := rfcKey(b)
	message := make([]byte, 128)
	public, err := p256.PublicKey(key)
	if err != nil {
		b.Fatal(err)
	}
	signature, err := p256.Sign(key, message)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("PublicKey", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := p256.PublicKey(key); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Sign128", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := p256.Sign(key, message); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Verify128", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := p256.Verify(public[:], message, signature[:]); err != nil {
				b.Fatal(err)
			}
		}
	})
}
