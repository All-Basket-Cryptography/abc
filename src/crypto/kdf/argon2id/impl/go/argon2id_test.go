package abcargon2id

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"
)

func TestRFC9106(t *testing.T) {
	inputs := [4][]byte{
		bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 16),
		bytes.Repeat([]byte{3}, 8), bytes.Repeat([]byte{4}, 12),
	}
	p, err := NewParameters(32, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	h0 := prehash(p, 32, inputs)
	wantH0 := "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b854" +
		"6a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997"
	if hex.EncodeToString(h0[:]) != wantH0 {
		t.Fatal("initial hash mismatch")
	}
	want := [3][2][4]uint64{
		{
			{0x6b2e09f10671bd43, 0xf69f5c27918a21be, 0xdea7810ea41290e1, 0x6787f7171870f893},
			{0x377fa81666dc7f2b, 0x50e586398a9c39c8, 0x6f732732a550924a, 0x81f88b28683ea8e5},
		},
		{
			{0x3653ec9d01583df9, 0x69ef53a72d1e1fd3, 0x35635631744ab54f, 0x599512e96a37ab6e},
			{0x4d4b435cea35caa6, 0xc582210d99ad1359, 0xd087971b36fd6d77, 0xa55222a93754c692},
		},
		{
			{0x942363968ce597a4, 0xa22448c0bdad5760, 0xa5f80662b6fa8748, 0xa0f9b9ce392f719f},
			{0xd723359b485f509b, 0xcb78824f42375111, 0x35bc8cc6e83b1875, 0x0b012846a40f346a},
		},
	}
	var workspace [33]Block
	for i := range workspace {
		workspace[i][0] = 0xaabb
	}
	extra := workspace[32]
	active := workspace[:p.WorkspaceBlocks()]
	initialize(active, p, &h0)
	for pass, expected := range want {
		fillPass(active, p, uint32(pass))
		if [4]uint64(active[0][:4]) != expected[0] || [4]uint64(active[31][124:]) != expected[1] {
			t.Fatalf("RFC 9106 pass %d checkpoint mismatch", pass)
		}
	}
	var tag [32]byte
	if err := Derive(inputs[0], inputs[1], inputs[2], inputs[3], p, tag[:], workspace[:]); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(tag[:]) != "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659" ||
		workspace[32] != extra {
		t.Fatal("RFC 9106 tag or extra workspace mismatch")
	}
}

func TestParameterBounds(t *testing.T) {
	for _, values := range [][3]uint32{
		{8, 1, 0}, {8, 0, 1}, {15, 1, 2}, {math.MaxUint32, 1, maxLanes + 1},
	} {
		if _, err := NewParameters(values[0], values[1], values[2]); err != ErrParameters {
			t.Fatalf("accepted invalid parameters %v: %v", values, err)
		}
	}
	p, err := NewParameters(31, 2, 3)
	if err != nil || p.WorkspaceBlocks() != 24 {
		t.Fatalf("memory rounding returned %v, %v", p, err)
	}
	p, err = NewParameters(math.MaxUint32, 1, 1)
	if uint64(math.MaxInt) <= math.MaxUint32 {
		if err != ErrWorkspaceSize {
			t.Fatal("accepted a workspace too large for this platform")
		}
	} else if err != nil || uint64(p.WorkspaceBlocks()) != math.MaxUint32-3 {
		t.Fatal("failed to represent the largest rounded 64-bit-platform workspace")
	}

	valid := [4]uint64{math.MaxUint32, 8, math.MaxUint32, math.MaxUint32}
	if err := validateLengths(valid, math.MaxUint32); err != nil {
		t.Fatal(err)
	}
	if err := validateLengths(valid, uint64(math.MaxUint32)+1); err != ErrTagLength {
		t.Fatal("accepted an overlong tag")
	}
	for i := range valid {
		bad := valid
		bad[i] = uint64(math.MaxUint32) + 1
		if err := validateLengths(bad, 4); err != ErrInputLength {
			t.Fatal("accepted an overlong input")
		}
	}
}

func TestValidationPreservesBuffers(t *testing.T) {
	p, err := NewParameters(8, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("12345678")
	workspace := make([]Block, p.WorkspaceBlocks())
	for i := range workspace {
		workspace[i][i] = 0x1234
	}
	expected := append([]Block(nil), workspace...)
	out := [4]byte{0xa5, 0xa5, 0xa5, 0xa5}
	for _, test := range []struct {
		params Parameters
		blocks int
		salt   []byte
		size   int
		err    error
	}{
		{Parameters{}, 8, salt, 4, ErrParameters},
		{p, 7, salt, 4, ErrWorkspace},
		{p, 8, salt[:7], 4, ErrSaltLength},
		{p, 8, salt, 3, ErrTagLength},
	} {
		if err := Derive(nil, test.salt, nil, nil, test.params, out[:test.size], workspace[:test.blocks]); err != test.err {
			t.Fatalf("expected %v, received %v", test.err, err)
		}
		if out != [4]byte{0xa5, 0xa5, 0xa5, 0xa5} {
			t.Fatal("reject changed output")
		}
		for i := range workspace {
			if workspace[i] != expected[i] {
				t.Fatal("reject changed workspace")
			}
		}
	}
}

func TestOverlap(t *testing.T) {
	p, err := NewParameters(8, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	workspace := make([]Block, p.WorkspaceBlocks())
	message := bytes.Repeat([]byte("pass"), 10)
	var expected [32]byte
	if err := Derive(message, []byte("test-salt"), nil, nil, p, expected[:], workspace); err != nil {
		t.Fatal(err)
	}
	if err := Derive(message, []byte("test-salt"), nil, nil, p, message[4:36], workspace); err != nil ||
		!bytes.Equal(expected[:], message[4:36]) {
		t.Fatal("overlapping output produced a different tag", err)
	}
}

func BenchmarkDerive64KiB(b *testing.B) {
	p, err := NewParameters(64, 2, 1)
	if err != nil {
		b.Fatal(err)
	}
	workspace := make([]Block, p.WorkspaceBlocks())
	var password [32]byte
	var salt [16]byte
	var output [32]byte
	b.ReportAllocs()
	for b.Loop() {
		if err := Derive(password[:], salt[:], nil, nil, p, output[:], workspace); err != nil {
			b.Fatal(err)
		}
	}
}
