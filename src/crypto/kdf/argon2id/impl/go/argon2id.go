// Package abcargon2id implements RFC 9106 Argon2id v1.3 with caller-owned memory.
package abcargon2id

import (
	"encoding/binary"
	"errors"
	"math"

	abcblake2b "github.com/All-Basket-Cryptography/abc/src/crypto/hash/blake2b/impl/go"
)

const (
	BlockSize = 1024
	words     = BlockSize / 8
	slices    = 4
	version   = 0x13
	variant   = 2
	maxLanes  = (1 << 24) - 1
)

var (
	ErrParameters    = errors.New("invalid Argon2id cost parameters")
	ErrWorkspaceSize = errors.New("Argon2id workspace cannot fit in a block slice")
	ErrWorkspace     = errors.New("Argon2id workspace is smaller than the rounded memory cost")
	ErrInputLength   = errors.New("Argon2id input length exceeds 32 bits")
	ErrSaltLength    = errors.New("Argon2id requires at least eight salt bytes")
	ErrTagLength     = errors.New("Argon2id output length must be between four and 2^32 - 1 bytes")
)

// Block represents one KiB of workspace as native unsigned words.
type Block [words]uint64

// Parameters represent validated cost and rounded workspace dimensions.
type Parameters struct {
	memoryKiB  uint32
	passes     uint32
	lanes      int
	segment    int
	blockCount int
}

// NewParameters validates the costs and computes the required block count.
func NewParameters(memoryKiB, passes, lanes uint32) (Parameters, error) {
	if lanes == 0 || lanes > maxLanes || passes == 0 || memoryKiB < 8*lanes {
		return Parameters{}, ErrParameters
	}
	segment := memoryKiB / (slices * lanes)
	blocks := segment * slices * lanes
	if uint64(blocks)*BlockSize > uint64(math.MaxInt) {
		return Parameters{}, ErrWorkspaceSize
	}
	return Parameters{memoryKiB, passes, int(lanes), int(segment), int(blocks)}, nil
}

// WorkspaceBlocks returns the required number of 1 KiB blocks.
func (p Parameters) WorkspaceBlocks() int { return p.blockCount }

func (p Parameters) laneBlocks() int { return p.segment * slices }

// Derive writes the tag into output using caller-owned workspace.
// Validation errors preserve both buffers. Extra workspace is untouched.
// The caller owns cost selection and any cleanup of workspace.
func Derive(password, salt, secret, associatedData []byte, p Parameters, output []byte, workspace []Block) error {
	if p.blockCount == 0 {
		return ErrParameters
	}
	inputs := [4][]byte{password, salt, secret, associatedData}
	var lengths [4]uint64
	for i, input := range inputs {
		lengths[i] = uint64(len(input))
	}
	if err := validateLengths(lengths, uint64(len(output))); err != nil {
		return err
	}
	if len(workspace) < p.blockCount {
		return ErrWorkspace
	}
	matrix := workspace[:p.blockCount]
	initial := prehash(p, uint32(len(output)), inputs)
	initialize(matrix, p, &initial)
	for pass := uint32(0); pass < p.passes; pass++ {
		fillPass(matrix, p, pass)
	}
	var encoded [BlockSize]byte
	combineFinal(matrix, p, &encoded)
	longHash(encoded[:], output)
	return nil
}

func validateLengths(inputs [4]uint64, output uint64) error {
	for _, length := range inputs {
		if length > math.MaxUint32 {
			return ErrInputLength
		}
	}
	if inputs[1] < 8 {
		return ErrSaltLength
	}
	if output < 4 || output > math.MaxUint32 {
		return ErrTagLength
	}
	return nil
}

func prehash(p Parameters, tagLength uint32, inputs [4][]byte) (h0 [64]byte) {
	// The zero value selects BLAKE2b-512. All input lengths fit in u32.
	var hash abcblake2b.Hasher
	var word [4]byte
	for _, value := range []uint32{uint32(p.lanes), tagLength, p.memoryKiB, p.passes, version, variant} {
		binary.LittleEndian.PutUint32(word[:], value)
		_ = hash.Update(word[:])
	}
	for _, input := range inputs {
		binary.LittleEndian.PutUint32(word[:], uint32(len(input)))
		_ = hash.Update(word[:])
		_ = hash.Update(input)
	}
	_ = hash.Finalize(h0[:])
	return h0
}

func prefixedHash(input []byte, length uint32, output []byte) {
	// The caller supplies 4–64 output bytes and at most one block of input.
	hash, _ := abcblake2b.New(len(output))
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], length)
	_ = hash.Update(prefix[:])
	_ = hash.Update(input)
	_ = hash.Finalize(output)
}

func longHash(input, output []byte) {
	total := uint32(len(output))
	if len(output) <= abcblake2b.MaxDigestSize {
		prefixedHash(input, total, output)
		return
	}
	var previous [64]byte
	prefixedHash(input, total, previous[:])
	for len(output) > abcblake2b.MaxDigestSize {
		copy(output, previous[:32])
		output = output[32:]
		if len(output) > abcblake2b.MaxDigestSize {
			_ = abcblake2b.Sum(previous[:], previous[:])
		}
	}
	_ = abcblake2b.Sum(previous[:], output)
}

func combineFinal(memory []Block, p Parameters, output *[BlockSize]byte) {
	var final Block
	for lane := 0; lane < p.lanes; lane++ {
		last := &memory[(lane+1)*p.laneBlocks()-1]
		for i := range final {
			final[i] ^= last[i]
		}
	}
	for i, word := range final {
		binary.LittleEndian.PutUint64(output[8*i:], word)
	}
}
