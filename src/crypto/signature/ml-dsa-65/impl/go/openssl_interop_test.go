//go:build interop

package mldsa65_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	mldsa65 "github.com/All-Basket-Cryptography/abc/src/crypto/signature/ml-dsa-65/impl/go"
)

func TestOpenSSLInterop(t *testing.T) {
	fixture := loadFixtures(t)
	seed := [mldsa65.SeedSize]byte(decode(t, fixture.KeyGeneration.Seed))
	goPublic, err := mldsa65.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	openssl := os.Getenv("ABC_MLDSA_OPENSSL")
	if openssl == "" {
		openssl = "openssl"
	}
	work := t.TempDir()
	run := func(args ...string) []byte {
		t.Helper()
		command := exec.Command(openssl, args...)
		command.Dir = work
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("OpenSSL %s: %v\n%s", args[0], err, output)
		}
		return output
	}
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name string) []byte {
		t.Helper()
		result, err := os.ReadFile(filepath.Join(work, name))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	// RFC 9881 PKCS#8 containing the ML-DSA-65 seed form.
	write("seed.der", append(decode(t, "3034020100300b060960864801650304031204228020"), seed[:]...))
	run("pkey", "-inform", "DER", "-in", "seed.der", "-pubout", "-out", "pub.pem")
	run("pkey", "-pubin", "-in", "pub.pem", "-pubout", "-outform", "DER", "-out", "pub.der")
	publicDER := read("pub.der")
	if len(publicDER) < len(goPublic) || !bytes.Equal(publicDER[len(publicDER)-len(goPublic):], goPublic[:]) {
		t.Fatal("Go and OpenSSL public keys differ")
	}

	count := 0
	for _, messageLength := range []int{1, 64, 1024} {
		message := make([]byte, messageLength)
		for i := range message {
			message[i] = byte(i*33 + 5)
		}
		write("message", message)
		for _, contextLength := range []int{0, 2, 128, 255} {
			context := make([]byte, contextLength)
			for i := range context {
				context[i] = byte(i*17 + 0xff)
			}
			options := []string{"-pkeyopt", "message-encoding:1"}
			if len(context) != 0 {
				options = append(options, "-pkeyopt", "hexcontext-string:"+hex.EncodeToString(context))
			}
			signArgs := []string{"pkeyutl", "-sign", "-rawin", "-inkey", "seed.der", "-keyform", "DER",
				"-in", "message", "-out", "openssl.sig", "-pkeyopt", "deterministic:1"}
			run(append(signArgs, options...)...)
			actual, err := mldsa65.Sign(seed, message, context)
			if err != nil {
				t.Fatal(err)
			}
			expected := read("openssl.sig")
			if !bytes.Equal(actual[:], expected) {
				t.Fatalf("Go and OpenSSL deterministic signatures differ at %d/%d", messageLength, contextLength)
			}
			if err := mldsa65.Verify(goPublic[:], message, context, expected); err != nil {
				t.Fatal(err)
			}
			write("go.sig", actual[:])
			verifyArgs := []string{"pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", "pub.pem",
				"-in", "message", "-sigfile", "go.sig"}
			run(append(verifyArgs, options...)...)
			count++
		}
	}
	t.Logf("%d deterministic signatures matched and were verified in both directions by %s", count,
		bytes.TrimSpace(run("version")))
}
