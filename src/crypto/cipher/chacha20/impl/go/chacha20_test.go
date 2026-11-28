package chacha20

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/rand/v2"
	"os/exec"
	"testing"
)

const plaintextHex = "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
	"73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
	"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
	"637265656e20776f756c642062652069742e"

func TestRFC8439(t *testing.T) {
	var key [KeyBytes]byte
	for i := range key {
		key[i] = byte(i)
	}
	nonce := [NonceBytes]byte{3: 9, 7: 0x4a}
	block := Block(key, nonce, 1)
	const wantBlock = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
		"d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
	if hex.EncodeToString(block[:]) != wantBlock {
		t.Fatalf("RFC block: %x", block)
	}
	nonce[3] = 0
	plaintext := decoded(t, plaintextHex)
	ciphertext := make([]byte, len(plaintext))
	if err := XOR(ciphertext, plaintext, key, nonce, 1); err != nil {
		t.Fatal(err)
	}
	const wantCipher = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
		"f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
		"07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
		"5af90bbf74a35be6b40b8eedf2785e42874d"
	if hex.EncodeToString(ciphertext) != wantCipher {
		t.Fatalf("RFC cipher: %x", ciphertext)
	}
}

func TestCounterAndDestination(t *testing.T) {
	var key [KeyBytes]byte
	var nonce [NonceBytes]byte
	var buffer [65]byte
	cases := []struct {
		length  uint64
		counter uint32
		fits    bool
	}{
		{0, math.MaxUint32, true},
		{64, math.MaxUint32, true},
		{65, math.MaxUint32, false},
		{128, math.MaxUint32 - 1, true},
		{129, math.MaxUint32 - 1, false},
		{1 << 38, 0, true},
		{1<<38 + 1, 0, false},
		{math.MaxUint64, 0, false},
	}
	for _, c := range cases {
		if got := FitsCounter(c.length, c.counter); got != c.fits {
			t.Fatalf("FitsCounter(%d, %d) = %v", c.length, c.counter, got)
		}
	}
	if err := XOR(buffer[:], buffer[:], key, nonce, math.MaxUint32); err != ErrCounterRange || buffer != [65]byte{} {
		t.Fatal("counter error wrote output")
	}
	if err := XOR(buffer[:64], buffer[:], key, nonce, 0); err != ErrShortDestination || buffer != [65]byte{} {
		t.Fatal("short-destination error wrote output")
	}
	if err := XOR(buffer[:], buffer[:64], key, nonce, math.MaxUint32); err != nil || buffer[64] != 0 {
		t.Fatal("the final block or destination suffix was mishandled")
	}
	block := Block(key, nonce, math.MaxUint32)
	if !bytes.Equal(buffer[:64], block[:]) {
		t.Fatal("final counter block mismatch")
	}
}

func TestOverlappingSlicesAndBlockSplit(t *testing.T) {
	var key [KeyBytes]byte
	var nonce [NonceBytes]byte
	key[17] = 37
	nonce[2] = 91
	message := make([]byte, 213)
	for i := range message {
		message[i] = byte(i * 19)
	}
	want := make([]byte, len(message))
	if err := XOR(want, message, key, nonce, 31); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{-9, 0, 9} {
		buffer := bytes.Repeat([]byte{0xa7}, len(message)+32)
		dstAt, srcAt := 12+offset, 12
		source := buffer[srcAt : srcAt+len(message)]
		copy(source, message)
		suffix := bytes.Clone(buffer[dstAt+len(message):])
		if err := XOR(buffer[dstAt:], source, key, nonce, 31); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, buffer[dstAt:dstAt+len(message)]) ||
			!bytes.Equal(suffix, buffer[dstAt+len(message):]) {
			t.Fatalf("overlap at offset %d", offset)
		}
	}
	split := bytes.Clone(message)
	if err := XOR(split[:128], split[:128], key, nonce, 31); err != nil {
		t.Fatal(err)
	}
	if err := XOR(split[128:], split[128:], key, nonce, 33); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, split) {
		t.Fatal("aligned split mismatch")
	}
}

func TestOpenSSL(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js OpenSSL oracle is unavailable")
	}
	type fixture struct {
		Key, Nonce, Message string
		Counter             uint32
	}
	rng := rand.New(rand.NewPCG(8439, 20))
	var vectors []fixture
	var expected []string
	for i := range 144 {
		var key [KeyBytes]byte
		var nonce [NonceBytes]byte
		n := rng.IntN(513)
		counter := uint32(rng.IntN(65536))
		boundaries := []int{0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257}
		if i < len(boundaries) {
			n = boundaries[i]
			counter = math.MaxUint32 - 4
		} else if i == len(boundaries) {
			n, counter = 64, math.MaxUint32
		}
		data := make([]byte, n)
		for _, b := range [][]byte{key[:], nonce[:], data} {
			for j := range b {
				b[j] = byte(rng.Uint32())
			}
		}
		vectors = append(vectors, fixture{hex.EncodeToString(key[:]), hex.EncodeToString(nonce[:]), hex.EncodeToString(data), counter})
		if err := XOR(data, data, key, nonce, counter); err != nil {
			t.Fatal(err)
		}
		expected = append(expected, hex.EncodeToString(data))
	}
	input, err := json.Marshal(vectors)
	if err != nil {
		t.Fatal(err)
	}
	const oracle = `
const crypto = require("node:crypto");
const fs = require("node:fs");
const hex = x => Buffer.from(x, "hex");
const output = JSON.parse(fs.readFileSync(0, "utf8")).map(x => {
  const iv = Buffer.alloc(16);
  iv.writeUInt32LE(x.Counter);
  hex(x.Nonce).copy(iv, 4);
  const cipher = crypto.createCipheriv("chacha20", hex(x.Key), iv);
  return Buffer.concat([cipher.update(hex(x.Message)), cipher.final()]).toString("hex");
});
process.stdout.write(JSON.stringify({version: process.versions.openssl, output}));
`
	cmd := exec.Command(node, "-e", oracle)
	cmd.Stdin = bytes.NewReader(input)
	result, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenSSL oracle: %v\n%s", err, result)
	}
	var report struct {
		Version string
		Output  []string
	}
	if err := json.Unmarshal(result, &report); err != nil || len(report.Output) != len(expected) {
		t.Fatalf("invalid oracle output (%d values): %v", len(report.Output), err)
	}
	for i, want := range expected {
		if report.Output[i] != want {
			t.Fatalf("OpenSSL case %d differs", i)
		}
	}
	t.Logf("%d independent OpenSSL %s comparisons", len(expected), report.Version)
}

func decoded(t *testing.T, encoded string) []byte {
	t.Helper()
	data, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
