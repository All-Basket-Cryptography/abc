package x25519

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"os/exec"
	"testing"
)

func TestRFC7748AliceBob(t *testing.T) {
	aliceScalar := decode(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePublic := decode(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobScalar := decode(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPublic := decode(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	wantSecret := decode(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
	for _, participant := range []struct{ scalar, public, remote [KeyBytes]byte }{
		{aliceScalar, alicePublic, bobPublic}, {bobScalar, bobPublic, alicePublic},
	} {
		key := newKey(t, participant.scalar)
		if got, err := key.PublicKey(); err != nil || got != participant.public {
			t.Fatalf("RFC public key: %x, %v", got, err)
		}
		if got, err := key.SharedSecret(participant.remote); err != nil || got != wantSecret {
			t.Fatalf("RFC shared secret: %x, %v", got, err)
		}
	}
}

func TestRFC7748Iterations(t *testing.T) {
	scalar := [KeyBytes]byte{9}
	point := scalar
	for i := 1; i <= 1000; i++ {
		key := newKey(t, scalar)
		got, err := key.SharedSecret(point)
		if err != nil {
			t.Fatal(err)
		}
		scalar, point = got, scalar
		if i == 1 && scalar != decode(t, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079") {
			t.Fatalf("RFC single iteration: %x", scalar)
		}
	}
	if scalar != decode(t, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51") {
		t.Fatalf("RFC 1000 iterations: %x", scalar)
	}
}

func TestNoncanonicalPeersAndLowOrderRejection(t *testing.T) {
	scalar := [KeyBytes]byte{0: 128, 11: 0x11, 31: 0x73}
	key := newKey(t, scalar)
	want, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range equivalentBasePoints(t) {
		if got, err := key.SharedSecret(point); err != nil || got != want {
			t.Fatalf("equivalent basepoint %x: %x, %v", point, got, err)
		}
	}
	for variant := range 32 {
		clampedAlias := scalar
		clampedAlias[0] = scalar[0]&0xf8 | byte(variant&7)
		clampedAlias[31] = scalar[31]&0x3f | byte(variant>>3)<<6
		if got, err := newKey(t, clampedAlias).PublicKey(); err != nil || got != want {
			t.Fatalf("scalar clamping variant %d: %x, %v", variant, got, err)
		}
	}
	for _, point := range lowOrderPeers(t) {
		if got, err := key.SharedSecret(point); err != ErrInvalidPeer || got != [KeyBytes]byte{} {
			t.Fatalf("low-order peer %x: %x, %v", point, got, err)
		}
	}
	var empty PrivateKey
	if k, err := empty.PublicKey(); k != [KeyBytes]byte{} || err != ErrUninitialized {
		t.Fatal("uninitialized public key returned a result")
	}
	if s, err := empty.SharedSecret([KeyBytes]byte{9}); s != [KeyBytes]byte{} || err != ErrUninitialized {
		t.Fatal("uninitialized key exchange returned a result")
	}
}

func TestOpenSSL(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js OpenSSL oracle is unavailable")
	}
	type fixture struct {
		Scalar, Point string
	}
	type answer struct {
		Public, Shared string
	}
	var questions []fixture
	var expected []answer
	add := func(scalar, point [KeyBytes]byte) {
		key := newKey(t, scalar)
		public, err := key.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		shared, err := key.SharedSecret(point)
		want := answer{Public: hex.EncodeToString(public[:])}
		if err == nil {
			want.Shared = hex.EncodeToString(shared[:])
		} else if err != ErrInvalidPeer {
			t.Fatal(err)
		}
		questions = append(questions, fixture{hex.EncodeToString(scalar[:]), hex.EncodeToString(point[:])})
		expected = append(expected, want)
	}
	rng := rand.New(rand.NewPCG(7748, 25519))
	for range 128 {
		var scalar, point [KeyBytes]byte
		for _, b := range [][]byte{scalar[:], point[:]} {
			for i := range b {
				b[i] = byte(rng.Uint32())
			}
		}
		add(scalar, point)
	}
	for _, point := range equivalentBasePoints(t) {
		add([KeyBytes]byte{17: 0x25}, point)
	}
	for _, point := range lowOrderPeers(t) {
		add([KeyBytes]byte{27: 0x42}, point)
	}
	wire, err := json.Marshal(questions)
	if err != nil {
		t.Fatal(err)
	}
	const oracle = `
const crypto = require("node:crypto");
const fs = require("node:fs");
const hex = s => Buffer.from(s, "hex");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const pkcs8 = hex("302e020100300506032b656e04220420");
const spki = hex("302a300506032b656e032100");
const output = input.map(({Scalar, Point}) => {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([pkcs8, hex(Scalar)]), format: "der", type: "pkcs8"
  });
  const local = crypto.createPublicKey(privateKey).export({format: "der", type: "spki"});
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([spki, hex(Point)]), format: "der", type: "spki"
  });
  let shared = "";
  try {
    shared = crypto.diffieHellman({privateKey, publicKey}).toString("hex");
  } catch (error) {
    if (error.code !== "ERR_OSSL_FAILED_DURING_DERIVATION") throw error;
  }
  return {Public: local.subarray(-32).toString("hex"), Shared: shared};
});
process.stdout.write(JSON.stringify({version: process.versions.openssl, output}));
`
	cmd := exec.Command(node, "-e", oracle)
	cmd.Stdin = bytes.NewReader(wire)
	result, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenSSL oracle: %v\n%s", err, result)
	}
	var report struct {
		Version string
		Output  []answer
	}
	if err := json.Unmarshal(result, &report); err != nil || len(report.Output) != len(expected) {
		t.Fatalf("invalid oracle output (%d values): %v", len(report.Output), err)
	}
	for i, want := range expected {
		if report.Output[i] != want {
			t.Fatalf("OpenSSL case %d differs", i)
		}
	}
	t.Logf("%d independent OpenSSL %s public and shared-secret comparisons", len(expected), report.Version)
}

func equivalentBasePoints(t *testing.T) [][KeyBytes]byte {
	t.Helper()
	atLeastP := decode(t, "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	topBit := atLeastP
	topBit[31] |= 128
	return [][KeyBytes]byte{{9}, {0: 9, 31: 128}, atLeastP, topBit}
}

func lowOrderPeers(t *testing.T) [][KeyBytes]byte {
	t.Helper()
	var values [][KeyBytes]byte
	for _, encoded := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	} {
		peer := decode(t, encoded)
		values = append(values, peer)
		peer[31] |= 128
		values = append(values, peer)
	}
	return values
}

func newKey(t testing.TB, bytes [KeyBytes]byte) PrivateKey {
	t.Helper()
	key, err := NewPrivateKey(bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func decode(t testing.TB, input string) [KeyBytes]byte {
	t.Helper()
	decoded, err := hex.DecodeString(input)
	if err != nil || len(decoded) != KeyBytes {
		t.Fatalf("invalid vector: %s, %v", input, err)
	}
	return [KeyBytes]byte(decoded)
}

func BenchmarkSharedSecret(b *testing.B) {
	key := newKey(b, [KeyBytes]byte{28: 0x47})
	peer := decode(b, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := key.SharedSecret(peer); err != nil {
			b.Fatal(err)
		}
	}
}
