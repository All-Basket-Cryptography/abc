package mldsa65_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	mldsa65 "github.com/All-Basket-Cryptography/abc/src/crypto/signature/ml-dsa-65/impl/go"
)

type signatureCase struct {
	ID        int    `json:"tcId"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	PublicKey string `json:"pk"`
	Signature string `json:"signature"`
	Passed    bool   `json:"testPassed"`
}

type acvpFixture struct {
	Revision      string `json:"acvp_revision"`
	KeyGeneration struct {
		GroupID   int    `json:"tgId"`
		ID        int    `json:"tcId"`
		Seed      string `json:"seed"`
		PublicSHA string `json:"public_key_sha256"`
	} `json:"keyGen"`
	SignatureGeneration struct {
		GroupID int             `json:"tgId"`
		Cases   []signatureCase `json:"cases"`
	} `json:"sigGen"`
	SignatureVerification struct {
		GroupID int             `json:"tgId"`
		Cases   []signatureCase `json:"cases"`
	} `json:"sigVer"`
}

func decode(t testing.TB, value string) []byte {
	t.Helper()
	result, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func loadFixtures(t testing.TB) acvpFixture {
	t.Helper()
	raw, err := os.ReadFile("../../spec/acvp-fips204-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture acvpFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Revision != "975de31eb83d87039ec88934fdc47d8c312b892d" ||
		fixture.KeyGeneration.GroupID != 2 || fixture.KeyGeneration.ID != 26 ||
		fixture.SignatureGeneration.GroupID != 3 || len(fixture.SignatureGeneration.Cases) != 1 ||
		fixture.SignatureGeneration.Cases[0].ID != 41 ||
		fixture.SignatureVerification.GroupID != 3 || len(fixture.SignatureVerification.Cases) != 2 {
		t.Fatal("unexpected pinned ACVP fixture selection")
	}
	return fixture
}

func TestNISTACVP(t *testing.T) {
	data := loadFixtures(t)
	seed := [mldsa65.SeedSize]byte(decode(t, data.KeyGeneration.Seed))
	public, err := mldsa65.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(public[:])
	if hex.EncodeToString(digest[:]) != data.KeyGeneration.PublicSHA {
		t.Fatal("NIST ACVP key generation mismatch")
	}

	for _, item := range append(data.SignatureGeneration.Cases, data.SignatureVerification.Cases...) {
		want := item.ID == 41 || item.ID == 43
		if (item.ID != 38 && item.ID != 41 && item.ID != 43) || (item.ID != 41 && item.Passed != want) {
			t.Fatalf("unexpected ACVP verification case %d", item.ID)
		}
		err := mldsa65.Verify(decode(t, item.PublicKey), decode(t, item.Message),
			decode(t, item.Context), decode(t, item.Signature))
		if want && err != nil || !want && !errors.Is(err, mldsa65.ErrVerificationFailed) {
			t.Fatalf("NIST ACVP verification case %d mismatch: %v", item.ID, err)
		}
	}
	t.Log("NIST ACVP keyGen tc26, sigGen signature verification tc41, sigVer tc38 and tc43 matched")
}

func TestDeterminismAndRejection(t *testing.T) {
	fixture := loadFixtures(t)
	seed := [mldsa65.SeedSize]byte(decode(t, fixture.KeyGeneration.Seed))
	public, err := mldsa65.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, context := range [][]byte{nil, {0, 255}, make([]byte, 255)} {
		const message = "ML-DSA-65 demo"
		first, err := mldsa65.Sign(seed, []byte(message), context)
		if err != nil {
			t.Fatal(err)
		}
		second, err := mldsa65.Sign(seed, []byte(message), context)
		if err != nil || first != second {
			t.Fatalf("deterministic signing mismatch at context length %d: %v", len(context), err)
		}
		if err := mldsa65.Verify(public[:], []byte(message), context, first[:]); err != nil {
			t.Fatal(err)
		}
		if err := mldsa65.Verify(public[:], []byte(message+"!"), context, first[:]); !errors.Is(err, mldsa65.ErrVerificationFailed) {
			t.Fatalf("changed message accepted: %v", err)
		}
		if err := mldsa65.Verify(public[:], []byte(message), []byte{0x5a}, first[:]); !errors.Is(err, mldsa65.ErrVerificationFailed) {
			t.Fatalf("changed context accepted: %v", err)
		}
		truncated := first[:len(first)-1]
		extended := append(append([]byte(nil), first[:]...), 0)
		for _, invalid := range [][]byte{truncated, extended} {
			if err := mldsa65.Verify(public[:], []byte(message), context, invalid); !errors.Is(err, mldsa65.ErrInvalidSignature) {
				t.Fatalf("invalid signature length accepted: %v", err)
			}
		}
	}
	empty, err := mldsa65.Sign(seed, nil, nil)
	if err != nil || mldsa65.Verify(public[:], nil, nil, empty[:]) != nil {
		t.Fatalf("empty input failed: %v", err)
	}
	if sig, err := mldsa65.Sign(seed, nil, make([]byte, 256)); !errors.Is(err, mldsa65.ErrContextTooLong) || sig != [mldsa65.SignatureSize]byte{} {
		t.Fatalf("oversize context signing mismatch: %v", err)
	}
	if err := mldsa65.Verify(public[:], nil, make([]byte, 256), empty[:]); !errors.Is(err, mldsa65.ErrContextTooLong) {
		t.Fatalf("oversize context accepted: %v", err)
	}
	if err := mldsa65.Verify(public[:len(public)-1], nil, nil, empty[:]); !errors.Is(err, mldsa65.ErrInvalidPublicKey) {
		t.Fatalf("truncated key accepted: %v", err)
	}
}

func BenchmarkSDK(b *testing.B) {
	fixture := loadFixtures(b)
	seed := [mldsa65.SeedSize]byte(decode(b, fixture.KeyGeneration.Seed))
	message := make([]byte, 128)
	context := []byte{0, 0xff}
	public, err := mldsa65.PublicKey(seed)
	if err != nil {
		b.Fatal(err)
	}
	signature, err := mldsa65.Sign(seed, message, context)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("PublicKey", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := mldsa65.PublicKey(seed); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Sign128", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := mldsa65.Sign(seed, message, context); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Verify128", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := mldsa65.Verify(public[:], message, context, signature[:]); err != nil {
				b.Fatal(err)
			}
		}
	})
}
