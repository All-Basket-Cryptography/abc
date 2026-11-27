package abced25519

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, text string) []byte {
	t.Helper()
	result, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRFC8032(t *testing.T) {
	for _, test := range []struct {
		seed, public, message, signature string
	}{
		{
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			"",
			"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
				"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
		},
		{
			"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			"72",
			"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
				"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
		},
		{
			"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
			"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
			"af82",
			"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
				"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
		},
	} {
		seed := [SeedSize]byte(unhex(t, test.seed))
		public := [PublicKeySize]byte(unhex(t, test.public))
		message := unhex(t, test.message)
		signature := [SignatureSize]byte(unhex(t, test.signature))
		if PublicKey(seed) != public || Sign(seed, message) != signature {
			t.Fatal("RFC 8032 public key or signature mismatch")
		}
		if err := VerifyStrict(public, message, signature); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStrictPolicy(t *testing.T) {
	seed := [SeedSize]byte{1, 2, 3}
	public := PublicKey(seed)
	message := []byte("binary\x00message")
	signature := Sign(seed, message)
	if VerifyStrict(public, message, signature) != nil {
		t.Fatal("rejected a valid seed-derived signature")
	}
	if VerifyStrict(public, []byte("different"), signature) != ErrSignature ||
		VerifyStrict(PublicKey([SeedSize]byte{9}), message, signature) != ErrSignature {
		t.Fatal("accepted the wrong message or public key")
	}

	identity := [PublicKeySize]byte{1}
	zeroXWithSign := identity
	zeroXWithSign[31] = 0x80
	noncanonicalY := [PublicKeySize]byte(bytes.Repeat([]byte{0xff}, PublicKeySize))
	noncanonicalY[0], noncanonicalY[31] = 0xf0, 0x7f // p + 3
	if canonical := [PublicKeySize]byte{3}; !validPoint(canonical[:]) {
		t.Fatal("canonical fixture should be valid and have nontrivial cofactor multiple")
	}
	for _, test := range []struct {
		name  string
		point [PublicKeySize]byte
	}{
		{"identity", identity},
		{"order-four point", [PublicKeySize]byte{}},
		{"zero x with sign bit", zeroXWithSign},
		{"noncanonical y with a nontrivial cofactor multiple", noncanonicalY},
	} {
		if VerifyStrict(test.point, message, signature) != ErrPublicKey {
			t.Fatalf("accepted a %s public key", test.name)
		}
		changed := signature
		copy(changed[:PublicKeySize], test.point[:])
		if VerifyStrict(public, message, changed) != ErrSignature {
			t.Fatalf("accepted a %s signature commitment", test.name)
		}
	}

	changed := signature
	order := unhex(t, "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	copy(changed[PublicKeySize:], order)
	if VerifyStrict(public, message, changed) != ErrSignature {
		t.Fatal("accepted scalar S equal to the group order")
	}
	changed = signature
	var carry uint16
	for i, value := range order {
		s := uint16(changed[PublicKeySize+i]) + uint16(value) + carry
		changed[PublicKeySize+i], carry = byte(s), s>>8
	}
	if VerifyStrict(public, message, changed) != ErrSignature {
		t.Fatal("accepted scalar S plus the group order")
	}
}

func BenchmarkProviderVerify(b *testing.B) {
	var seed [SeedSize]byte
	message := make([]byte, 4096)
	public, signature := PublicKey(seed), Sign(seed, message)
	b.ReportAllocs()
	for b.Loop() {
		if !ed25519.Verify(public[:], message, signature[:]) {
			b.Fatal("provider rejected generated signature")
		}
	}
}

func BenchmarkVerifyStrict(b *testing.B) {
	var seed [SeedSize]byte
	message := make([]byte, 4096)
	public, signature := PublicKey(seed), Sign(seed, message)
	b.ReportAllocs()
	for b.Loop() {
		if err := VerifyStrict(public, message, signature); err != nil {
			b.Fatal(err)
		}
	}
}
