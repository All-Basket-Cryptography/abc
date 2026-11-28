package scrypt

import (
	"encoding/hex"
	"errors"
	"math/bits"
	"testing"
)

func TestRFC7914(t *testing.T) {
	for _, tc := range []struct {
		password, salt    string
		cost, r, parallel int
		want              string
	}{
		{"", "", 16, 1, 1,
			"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442" +
				"fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"},
		{"password", "NaCl", 1024, 8, 16,
			"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162" +
				"2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"},
	} {
		p, err := NewParameters(tc.cost, tc.r, tc.parallel)
		if err != nil {
			t.Fatal(err)
		}
		key, err := Derive([]byte(tc.password), []byte(tc.salt), p, 64, p.WorkspaceBytes()+64)
		if err != nil || hex.EncodeToString(key) != tc.want {
			t.Fatalf("N=%d r=%d p=%d: %x, %v", tc.cost, tc.r, tc.parallel, key, err)
		}
	}
}

func TestBudgetsAndParameters(t *testing.T) {
	for _, invalid := range [][3]int{{1, 1, 1}, {3, 1, 1}, {16, 0, 1}, {16, 1, -2}, {1 << 16, 1, 1}} {
		if _, err := NewParameters(invalid[0], invalid[1], invalid[2]); !errors.Is(err, ErrParameters) {
			t.Fatalf("%v: %v", invalid, err)
		}
	}
	for _, huge := range [][3]int{{16, maxInt, 1}, {16, 1, maxInt}, {1 << (bits.UintSize - 9), 4, 1}} {
		if _, err := NewParameters(huge[0], huge[1], huge[2]); !errors.Is(err, ErrMemory) {
			t.Fatalf("%v: %v", huge, err)
		}
	}
	p, err := NewParameters(16, 2, 3)
	if err != nil || p.WorkspaceBytes() != (16+3+1)*2*128 {
		t.Fatalf("wrong workspace: %d, %v", p.WorkspaceBytes(), err)
	}
	if key, err := Derive(nil, nil, p, 32, p.WorkspaceBytes()+31); key != nil || !errors.Is(err, ErrMemory) {
		t.Fatalf("admitted short memory budget: %x, %v", key, err)
	}
	if key, err := Derive(nil, nil, Parameters{}, 32, maxInt); key != nil || !errors.Is(err, ErrParameters) {
		t.Fatalf("admitted zero parameters: %x, %v", key, err)
	}
}
