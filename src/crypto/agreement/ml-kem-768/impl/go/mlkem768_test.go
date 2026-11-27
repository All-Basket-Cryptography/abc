package mlkem768

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func decode(t *testing.T, data string) []byte {
	t.Helper()
	result, err := hex.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestACVPKeyGenerationAndPublicKeyValidation(t *testing.T) {
	var inputs struct {
		Cases []struct {
			TcID int    `json:"tcId"`
			D    string `json:"d"`
			Z    string `json:"z"`
			EK   string `json:"ek"`
		}
	}
	source, err := os.ReadFile("../../spec/acvp.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(source, &inputs); err != nil {
		t.Fatal(err)
	}
	verified := 0
	var rejected bool
	for _, tc := range inputs.Cases {
		switch {
		case tc.D != "" && tc.Z != "":
			seed := append(decode(t, tc.D), decode(t, tc.Z)...)
			private, err := NewDecapsulationKey(seed)
			if err != nil {
				t.Fatalf("ACVP %d: %v", tc.TcID, err)
			}
			public, err := private.PublicKey()
			if err != nil || !bytes.Equal(public[:], decode(t, tc.EK)) {
				t.Fatalf("ACVP %d: public key mismatch: %v", tc.TcID, err)
			}
			verified++
		case tc.TcID == 137:
			if _, _, err := Encapsulate(decode(t, tc.EK)); err == nil {
				t.Fatal("ACVP 137 noncanonical key accepted")
			}
			rejected = true
		}
	}
	if verified != 2 || !rejected {
		t.Fatalf("unexpected fixture coverage: %d keyGen cases, rejection = %t", verified, rejected)
	}
}

func TestProductionAPI(t *testing.T) {
	var empty DecapsulationKey
	if _, err := empty.PublicKey(); err == nil {
		t.Fatal("uninitialized key accepted")
	}
	if _, err := empty.Decapsulate(make([]byte, CiphertextSize)); err == nil {
		t.Fatal("uninitialized decapsulation accepted")
	}
	if _, err := NewDecapsulationKey(make([]byte, SeedSize-1)); err == nil {
		t.Fatal("short seed accepted")
	}
	if _, _, err := Encapsulate(make([]byte, PublicKeySize-1)); err == nil {
		t.Fatal("short public key accepted")
	}
	for i := 0; i < 4; i++ {
		key, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		public, err := key.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		ct, expected, err := Encapsulate(public[:])
		if err != nil {
			t.Fatal(err)
		}
		secret, err := key.Decapsulate(ct[:])
		if err != nil || secret != expected {
			t.Fatalf("round trip %d failed: %v", i, err)
		}
		if _, err := key.Decapsulate(ct[1:]); err == nil {
			t.Fatal("short ciphertext accepted")
		}
	}
}

func TestOpenSSL(t *testing.T) {
	type request struct {
		Seed       string `json:"seed"`
		Ciphertext string `json:"ciphertext"`
		Damaged    string `json:"damaged"`
	}
	type response struct {
		Public       string
		Decapsulated string
		Ciphertext   string
		Shared       string
		Rejected     string
	}
	const count = 12
	var tests []request
	var expected [count][SharedSecretSize]byte
	var public [count][PublicKeySize]byte
	var fallback [count][SharedSecretSize]byte
	var keys [count]*DecapsulationKey
	for i := range keys {
		seed := make([]byte, SeedSize)
		for j := range seed {
			seed[j] = byte((j*179 + i*53 + 31) ^ (i * j))
		}
		var err error
		keys[i], err = NewDecapsulationKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		public[i], err = keys[i].PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		ct, shared, err := Encapsulate(public[i][:])
		if err != nil {
			t.Fatal(err)
		}
		expected[i] = shared
		damaged := ct
		damaged[(i*73)%len(damaged)] ^= 0x80
		fallback[i], err = keys[i].Decapsulate(damaged[:])
		preimage := append(append([]byte{}, seed[32:]...), damaged[:]...)
		if err != nil || !bytes.Equal(fallback[i][:], sha3.SumSHAKE256(preimage, SharedSecretSize)) {
			t.Fatalf("implicit rejection case %d: %v", i, err)
		}
		tests = append(tests, request{hex.EncodeToString(seed), hex.EncodeToString(ct[:]), hex.EncodeToString(damaged[:])})
	}
	input, err := json.Marshal(tests)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("node", "oracle.mjs")
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	if err != nil {
		if failure, ok := err.(*exec.ExitError); ok {
			t.Fatalf("OpenSSL oracle: %v: %s", err, failure.Stderr)
		}
		t.Fatal(err)
	}
	var results []response
	if err := json.Unmarshal(output, &results); err != nil || len(results) != count {
		t.Fatalf("invalid oracle output: %d results, %v", len(results), err)
	}
	for i, result := range results {
		shared, err := keys[i].Decapsulate(decode(t, result.Ciphertext))
		if err != nil || !bytes.Equal(shared[:], decode(t, result.Shared)) ||
			!bytes.Equal(public[i][:], decode(t, result.Public)) ||
			!bytes.Equal(expected[i][:], decode(t, result.Decapsulated)) ||
			!bytes.Equal(fallback[i][:], decode(t, result.Rejected)) {
			t.Fatalf("OpenSSL interoperability failed in case %d: %v", i, err)
		}
	}
	t.Logf("%d OpenSSL cases cover key expansion, reciprocal encapsulation, and implicit rejection", count)
}
