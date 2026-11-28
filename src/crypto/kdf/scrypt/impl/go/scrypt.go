// Package scrypt implements RFC 7914 using ABC's native Go PBKDF2 core.
package scrypt

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"

	pbkdf2 "github.com/All-Basket-Cryptography/abc/src/crypto/kdf/pbkdf2-hmac-sha256/impl/go"
)

const maxInt = int(^uint(0) >> 1)

var (
	ErrParameters = errors.New("scrypt: invalid RFC 7914 parameters")
	ErrMemory     = errors.New("scrypt: workspace exceeds the memory budget or addressable size")
)

// Parameters is a validated RFC 7914 choice of cost, block size, and parallelization.
type Parameters struct {
	cost, stride, lanes, table, workspace int
}

// NewParameters computes the exact byte workspace size using checked arithmetic.
func NewParameters(cost, blockSize, parallel int) (Parameters, error) {
	if cost <= 1 || cost&(cost-1) != 0 || blockSize <= 0 || parallel <= 0 ||
		blockSize <= bits.TrailingZeros(uint(cost))/16 {
		return Parameters{}, ErrParameters
	}
	if blockSize > maxInt/128 {
		return Parameters{}, ErrMemory
	}
	stride := 128 * blockSize
	if parallel > maxInt/stride || cost > maxInt/stride {
		return Parameters{}, ErrMemory
	}
	lanes := stride * parallel
	table := stride * cost
	if uint64(lanes) > pbkdf2.MaxOutputBytes {
		return Parameters{}, ErrParameters
	}
	if table > maxInt-lanes || stride > maxInt-lanes-table {
		return Parameters{}, ErrMemory
	}
	return Parameters{cost: cost, stride: stride, lanes: lanes, table: table,
		workspace: lanes + table + stride}, nil
}

// WorkspaceBytes returns the space for input lanes, the ROMix table and BlockMix scratch.
func (p Parameters) WorkspaceBytes() int { return p.workspace }

// Derive returns a fresh key. memoryLimit must cover the working buffers and
// output. Apply a separate bound on the work when accepting untrusted parameters.
func Derive(password, salt []byte, p Parameters, length, memoryLimit int) ([]byte, error) {
	if p.workspace == 0 {
		return nil, ErrParameters
	}
	if length <= 0 || uint64(length) > pbkdf2.MaxOutputBytes {
		return nil, pbkdf2.ErrOutput
	}
	if memoryLimit < p.workspace || length > memoryLimit-p.workspace {
		return nil, ErrMemory
	}
	input, err := pbkdf2.Derive(password, salt, 1, p.lanes)
	if err != nil {
		return nil, err
	}
	defer clear(input)
	scratch := make([]byte, p.table+p.stride)
	defer clear(scratch)
	table, temporary := scratch[:p.table], scratch[p.table:]
	for offset := 0; offset < len(input); offset += p.stride {
		romix(input[offset:offset+p.stride], table, temporary, p.cost)
	}
	return pbkdf2.Derive(password, input, 1, length)
}

func romix(lane, table, temporary []byte, cost int) {
	stride := len(lane)
	for i := 0; i < cost; i++ {
		copy(table[i*stride:(i+1)*stride], lane)
		blockMix(lane, temporary)
		lane, temporary = temporary, lane
	}
	for i := 0; i < cost; i++ {
		index := int(binary.LittleEndian.Uint64(lane[stride-64:]) & uint64(cost-1))
		subtle.XORBytes(lane, lane, table[index*stride:(index+1)*stride])
		blockMix(lane, temporary)
		lane, temporary = temporary, lane
	}
	// The two passes perform 2*N swaps, returning the result to the caller's lane.
}

func blockMix(lane, temporary []byte) {
	blocks := len(lane) / 64
	var state [16]uint32
	for i := range state {
		state[i] = binary.LittleEndian.Uint32(lane[len(lane)-64+4*i:])
	}
	for block := 0; block < blocks; block++ {
		for i := range state {
			state[i] ^= binary.LittleEndian.Uint32(lane[block*64+4*i:])
		}
		salsa8(&state)
		dst := 64 * (block/2 + (block%2)*(blocks/2))
		for i, word := range state {
			binary.LittleEndian.PutUint32(temporary[dst+4*i:], word)
		}
	}
}

func quarter(s *[16]uint32, a, b, c, d int) {
	s[b] ^= bits.RotateLeft32(s[a]+s[d], 7)
	s[c] ^= bits.RotateLeft32(s[b]+s[a], 9)
	s[d] ^= bits.RotateLeft32(s[c]+s[b], 13)
	s[a] ^= bits.RotateLeft32(s[d]+s[c], 18)
}

func salsa8(state *[16]uint32) {
	work := *state
	for i := 0; i < 4; i++ {
		quarter(&work, 0, 4, 8, 12)
		quarter(&work, 5, 9, 13, 1)
		quarter(&work, 10, 14, 2, 6)
		quarter(&work, 15, 3, 7, 11)
		quarter(&work, 0, 1, 2, 3)
		quarter(&work, 5, 6, 7, 4)
		quarter(&work, 10, 11, 8, 9)
		quarter(&work, 15, 12, 13, 14)
	}
	for i, word := range work {
		state[i] += word
	}
}
