//go:build interop

package ecdsap256_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os/exec"
	"testing"

	p256 "github.com/All-Basket-Cryptography/abc/src/crypto/signature/ecdsa-p256-sha256/impl/go"
)

func TestOpenSSLInterop(t *testing.T) {
	type sample struct {
		Scalar    string `json:"scalar"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}
	var cases []sample
	order := new(big.Int).SetBytes(unhex(t, orderHex))
	maximum := new(big.Int).Sub(order, big.NewInt(1))
	for _, length := range []int{0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 128, 1024} {
		for variant := 0; variant < 4; variant++ {
			seed := sha256.Sum256([]byte(fmt.Sprintf("ABC Go ECDSA P-256 %d %d", length, variant)))
			value := new(big.Int).SetBytes(seed[:])
			value.Mod(value, maximum).Add(value, big.NewInt(1))
			var scalar [p256.PrivateKeySize]byte
			value.FillBytes(scalar[:])
			message := make([]byte, length)
			for i := range message {
				message[i] = byte(i*29 + variant)
			}
			signature, err := p256.Sign(scalar, message)
			if err != nil {
				t.Fatal(err)
			}
			cases = append(cases, sample{hex.EncodeToString(scalar[:]), hex.EncodeToString(message), hex.EncodeToString(signature[:])})
		}
	}

	input, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("node", "tests/interop.mjs")
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Node/OpenSSL oracle failed: %v\n%s", err, output)
	}
	var report struct {
		Node    string
		OpenSSL string
		Cases   []struct {
			Uncompressed string
			Compressed   string
			Signature    string
		}
	}
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Cases) != len(cases) || report.Node == "" || report.OpenSSL == "" {
		t.Fatalf("incomplete reference results: %d", len(report.Cases))
	}
	for index, result := range report.Cases {
		item := cases[index]
		public, err := p256.PublicKey([p256.PrivateKeySize]byte(unhex(t, item.Scalar)))
		if err != nil || hex.EncodeToString(public[:]) != result.Uncompressed {
			t.Fatalf("public key comparison %d: %v", index, err)
		}
		sig := unhex(t, result.Signature)
		msg := unhex(t, item.Message)
		for _, encoded := range [][]byte{public[:], unhex(t, result.Compressed)} {
			if err := p256.Verify(encoded, msg, sig); err != nil {
				t.Fatalf("OpenSSL to Go %d: %v", index, err)
			}
		}
	}
	t.Logf("%d bidirectional comparisons passed through Node %s and OpenSSL %s", len(cases), report.Node, report.OpenSSL)
}
