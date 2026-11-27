package chacha20poly1305

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"os/exec"
	"testing"
)

func TestRFC8439(t *testing.T) {
	var key [KeyBytes]byte
	for i := range key {
		key[i] = byte(0x80 + i)
	}
	nonce := [NonceBytes]byte(decode(t, "070000004041424344454647"))
	aad := decode(t, "50515253c0c1c2c3c4c5c6c7")
	plaintext := decode(t, "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"+
		"73206f66202739393a204966204920636f756c64206f6666657220796f75206f"+
		"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"+
		"637265656e20776f756c642062652069742e")
	want := decode(t, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"+
		"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"+
		"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"+
		"3ff4def08e4b7a9de576d26586cec64b6116")
	wantTag := [TagBytes]byte(decode(t, "1ae10b594f09e26a7e902ecbd0600691"))
	ciphertext := make([]byte, len(plaintext))
	tag, err := SealDetached(ciphertext, plaintext, aad, key, nonce)
	if err != nil || tag != wantTag || !bytes.Equal(ciphertext, want) {
		t.Fatalf("RFC seal: %v, %x, %x", err, tag, ciphertext)
	}
	if err := OpenDetached(ciphertext, ciphertext, aad, tag, key, nonce); err != nil || !bytes.Equal(ciphertext, plaintext) {
		t.Fatalf("RFC open: %v", err)
	}
}

func TestAuthenticationErrorsPreserveDestination(t *testing.T) {
	key := [KeyBytes]byte{7: 39, 22: 53}
	aad := []byte("associated data")
	for i, size := range []int{0, 1, 15, 16, 17, 63, 64, 65, 273} {
		nonce := [NonceBytes]byte{byte(i)}
		plaintext := bytes.Repeat([]byte{0x88}, size)
		ciphertext := make([]byte, size)
		tag, err := SealDetached(ciphertext, plaintext, aad, key, nonce)
		if err != nil {
			t.Fatal(err)
		}
		for index := range tag {
			wrong := tag
			wrong[index] ^= 1
			inPlace := bytes.Clone(ciphertext)
			if err := OpenDetached(inPlace, inPlace, aad, wrong, key, nonce); err != ErrAuthentication ||
				!bytes.Equal(inPlace, ciphertext) {
				t.Fatalf("tampered tag byte %d of length %d wrote output", index, size)
			}
		}
		canary := bytes.Repeat([]byte{0x7b}, size+4)
		output := bytes.Clone(canary)
		if err := OpenDetached(output, ciphertext, []byte("invalid"), tag, key, nonce); err != ErrAuthentication ||
			!bytes.Equal(output, canary) {
			t.Fatalf("tampered associated data of length %d wrote output", size)
		}
		if size != 0 {
			wrong := bytes.Clone(ciphertext)
			wrong[0] ^= 1
			if err := OpenDetached(output, wrong, aad, tag, key, nonce); err != ErrAuthentication ||
				!bytes.Equal(output, canary) {
				t.Fatalf("tampered ciphertext of length %d wrote output", size)
			}
			short := output[:size-1]
			zero, err := SealDetached(short, plaintext, aad, key, nonce)
			if err != ErrShortDestination || zero != [TagBytes]byte{} || !bytes.Equal(output, canary) {
				t.Fatalf("short seal destination at length %d wrote output", size)
			}
			if err := OpenDetached(short, ciphertext, aad, tag, key, nonce); err != ErrShortDestination ||
				!bytes.Equal(output, canary) {
				t.Fatalf("short open destination at length %d wrote output", size)
			}
		}
	}
}

func TestOverlappingBuffersAndAAD(t *testing.T) {
	key := [KeyBytes]byte{22: 57}
	nonce := [NonceBytes]byte{9: 12}
	buffer := make([]byte, 150)
	for i := range buffer {
		buffer[i] = byte(i*71 + 15)
	}
	input := buffer[:75]
	aad := buffer[15:38]
	plaintext, associatedData := bytes.Clone(input), bytes.Clone(aad)
	want := make([]byte, len(input))
	wantTag, err := SealDetached(want, plaintext, associatedData, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := buffer[9 : 9+len(input)]
	suffix := bytes.Clone(buffer[9+len(input):])
	tag, err := SealDetached(buffer[9:], input, aad, key, nonce)
	if err != nil || tag != wantTag || !bytes.Equal(ciphertext, want) ||
		!bytes.Equal(buffer[9+len(input):], suffix) {
		t.Fatalf("overlapping SealDetached: %v", err)
	}

	copy(buffer[:23], associatedData)
	copy(buffer[31:], want)
	if err := OpenDetached(buffer[3:], buffer[31:31+len(want)], buffer[:23], tag, key, nonce); err != nil ||
		!bytes.Equal(buffer[3:3+len(plaintext)], plaintext) {
		t.Fatalf("overlapping OpenDetached: %v", err)
	}
}

func TestOpenSSL(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js OpenSSL oracle is unavailable")
	}
	type fixture struct {
		Key, Nonce, Message, AAD, Ciphertext, Tag string
	}
	rng := rand.New(rand.NewPCG(8439, 2026))
	boundaries := []int{0, 1, 15, 16, 17, 63, 64, 65}
	var vectors []fixture
	for i := range 174 {
		var key [KeyBytes]byte
		var nonce [NonceBytes]byte
		width, aadWidth := rng.IntN(513), rng.IntN(137)
		if i < len(boundaries)*len(boundaries) {
			width, aadWidth = boundaries[i/len(boundaries)], boundaries[i%len(boundaries)]
		}
		plain, aad := make([]byte, width), make([]byte, aadWidth)
		for _, b := range [][]byte{key[:], nonce[:], plain, aad} {
			for j := range b {
				b[j] = byte(rng.Uint32())
			}
		}
		cipher := make([]byte, width)
		tag, err := SealDetached(cipher, plain, aad, key, nonce)
		if err != nil {
			t.Fatal(err)
		}
		vectors = append(vectors, fixture{
			hex.EncodeToString(key[:]), hex.EncodeToString(nonce[:]), hex.EncodeToString(plain),
			hex.EncodeToString(aad), hex.EncodeToString(cipher), hex.EncodeToString(tag[:]),
		})
	}
	input, err := json.Marshal(vectors)
	if err != nil {
		t.Fatal(err)
	}
	const oracle = `
const crypto = require("node:crypto");
const fs = require("node:fs");
const hex = x => Buffer.from(x, "hex");
const data = JSON.parse(fs.readFileSync(0, "utf8"));
const output = data.map(x => {
  const key = hex(x.Key), nonce = hex(x.Nonce), aad = hex(x.AAD);
  const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, {authTagLength: 16});
  cipher.setAAD(aad);
  const c = Buffer.concat([cipher.update(hex(x.Message)), cipher.final()]);
  const tag = cipher.getAuthTag();
  const decipher = crypto.createDecipheriv("chacha20-poly1305", key, nonce, {authTagLength: 16});
  decipher.setAAD(aad);
  decipher.setAuthTag(hex(x.Tag));
  const m = Buffer.concat([decipher.update(hex(x.Ciphertext)), decipher.final()]);
  return {Ciphertext: c.toString("hex"), Tag: tag.toString("hex"), Message: m.toString("hex")};
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
		Output  []fixture
	}
	if err := json.Unmarshal(result, &report); err != nil || len(report.Output) != len(vectors) {
		t.Fatalf("invalid oracle output (%d values): %v", len(report.Output), err)
	}
	for i, orig := range vectors {
		ref := report.Output[i]
		if ref.Ciphertext != orig.Ciphertext || ref.Tag != orig.Tag || ref.Message != orig.Message {
			t.Fatalf("OpenSSL case %d differs", i)
		}
		key := [KeyBytes]byte(decode(t, orig.Key))
		nonce := [NonceBytes]byte(decode(t, orig.Nonce))
		tag := [TagBytes]byte(decode(t, ref.Tag))
		target := decode(t, ref.Ciphertext)
		if err := OpenDetached(target, target, decode(t, orig.AAD), tag, key, nonce); err != nil ||
			hex.EncodeToString(target) != orig.Message {
			t.Fatalf("opening OpenSSL case %d: %v", i, err)
		}
	}
	t.Logf("%d bidirectional independent OpenSSL %s comparisons", len(vectors), report.Version)
}

func BenchmarkSeal4096(b *testing.B) {
	var key [KeyBytes]byte
	var nonce [NonceBytes]byte
	input, output := make([]byte, 4096), make([]byte, 4096)
	aad := make([]byte, 16)
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		binaryCounter := uint64(i)
		for index := range 8 {
			nonce[index] = byte(binaryCounter >> (8 * index))
		}
		if _, err := SealDetached(output, input, aad, key, nonce); err != nil {
			b.Fatal(err)
		}
	}
}

func decode(t *testing.T, wire string) []byte {
	t.Helper()
	out, err := hex.DecodeString(wire)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
