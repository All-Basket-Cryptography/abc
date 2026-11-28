// Package poly1305 implements the RFC 8439 one-time message authenticator.
package poly1305

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	KeyBytes = 32
	TagBytes = 16

	blockBytes = 16
	limbBits   = 26
	limbMask   = (1 << limbBits) - 1
)

var ErrState = errors.New("poly1305: authenticator is uninitialized or finished")

// MAC authenticates a single message. Construct it with New and keep its
// state under one caller's control. Each new message needs a distinct key.
type MAC struct {
	residue [5]uint64
	r       [5]uint64
	fold    [5]uint64
	pad     [4]uint32
	tail    [blockBytes]byte
	used    int
	state   macState
	tag     [TagBytes]byte
}

type macState uint8

const (
	active macState = iota + 1
	finished
)

// New constructs a streaming authenticator for a fresh, one-time 32-byte key.
func New(key [KeyBytes]byte) MAC {
	m := MAC{state: active}
	for i := range 4 {
		m.pad[i] = binary.LittleEndian.Uint32(key[blockBytes+4*i : blockBytes+4*i+4])
		key[4*i+3] &= 15
	}
	for i := 4; i <= 12; i += 4 {
		key[i] &= 252
	}
	m.r = limbs(key[:blockBytes])
	for i := 1; i < len(m.r); i++ {
		m.fold[i] = 5 * m.r[i]
	}
	return m
}

// Sum returns the tag for one message and one fresh, one-time key.
func Sum(key [KeyBytes]byte, message []byte) [TagBytes]byte {
	m := New(key)
	m.update(message)
	return m.finish()
}

// Update consumes message bytes. Calls on an inactive MAC return ErrState.
func (m *MAC) Update(message []byte) error {
	if m.state != active {
		return ErrState
	}
	m.update(message)
	return nil
}

func (m *MAC) update(message []byte) {
	if m.used != 0 {
		copied := copy(m.tail[m.used:], message)
		m.used += copied
		message = message[copied:]
		if m.used < blockBytes {
			return
		}
		m.block(m.tail[:], 1<<24)
		m.used = 0
	}
	for len(message) >= blockBytes {
		m.block(message[:blockBytes], 1<<24)
		message = message[blockBytes:]
	}
	m.used = copy(m.tail[:], message)
}

// Finalize computes the tag and closes the message. Repeated calls return the
// same value. An uninitialized MAC returns ErrState.
func (m *MAC) Finalize() ([TagBytes]byte, error) {
	switch m.state {
	case active:
		return m.finish(), nil
	case finished:
		return m.tag, nil
	default:
		return [TagBytes]byte{}, ErrState
	}
}

func limbs(block []byte) [5]uint64 {
	t0 := uint64(binary.LittleEndian.Uint32(block[0:4]))
	t1 := uint64(binary.LittleEndian.Uint32(block[4:8]))
	t2 := uint64(binary.LittleEndian.Uint32(block[8:12]))
	t3 := uint64(binary.LittleEndian.Uint32(block[12:16]))
	return [5]uint64{
		t0 & limbMask,
		(t0>>26 | t1<<6) & limbMask,
		(t1>>20 | t2<<12) & limbMask,
		(t2>>14 | t3<<18) & limbMask,
		t3 >> 8,
	}
}

func (m *MAC) block(block []byte, highBit uint64) {
	h := limbs(block)
	for i, old := range m.residue {
		h[i] += old
	}
	h[4] += highBit
	r := &m.r
	f := &m.fold

	// Fold terms of degree five or higher using (2^26)^5 = 5 modulo p.
	d := [5]uint64{
		h[0]*r[0] + h[1]*f[4] + h[2]*f[3] + h[3]*f[2] + h[4]*f[1],
		h[0]*r[1] + h[1]*r[0] + h[2]*f[4] + h[3]*f[3] + h[4]*f[2],
		h[0]*r[2] + h[1]*r[1] + h[2]*r[0] + h[3]*f[4] + h[4]*f[3],
		h[0]*r[3] + h[1]*r[2] + h[2]*r[1] + h[3]*r[0] + h[4]*f[4],
		h[0]*r[4] + h[1]*r[3] + h[2]*r[2] + h[3]*r[1] + h[4]*r[0],
	}
	m.residue = carry(d)
}

func carry(h [5]uint64) [5]uint64 {
	for i := 0; i < 4; i++ {
		h[i+1] += h[i] >> limbBits
		h[i] &= limbMask
	}
	h[0] += (h[4] >> limbBits) * 5
	h[4] &= limbMask
	h[1] += h[0] >> limbBits
	h[0] &= limbMask
	return h
}

func (m *MAC) finish() [TagBytes]byte {
	if m.used != 0 {
		clear(m.tail[m.used:])
		m.tail[m.used] = 1
		m.block(m.tail[:], 0)
	}

	h := carry(m.residue)
	reduced := h
	reduced[0] += 5
	for i := 0; i < 4; i++ {
		reduced[i+1] += reduced[i] >> limbBits
		reduced[i] &= limbMask
	}
	mask := uint64(0) - (reduced[4] >> limbBits)
	reduced[4] &= limbMask
	for i := range h {
		h[i] = (h[i] &^ mask) | (reduced[i] & mask)
	}

	words := [4]uint32{
		uint32(h[0] | h[1]<<26),
		uint32(h[1]>>6 | h[2]<<20),
		uint32(h[2]>>12 | h[3]<<14),
		uint32(h[3]>>18 | h[4]<<8),
	}
	var tag [TagBytes]byte
	var bit uint32
	for i, word := range words {
		words[i], bit = bits.Add32(word, m.pad[i], bit)
		binary.LittleEndian.PutUint32(tag[4*i:4*i+4], words[i])
	}
	*m = MAC{state: finished, tag: tag}
	return tag
}
