// Package hmacsha256 implements full HMAC-SHA-256 tags in portable Go for ABC research.
package hmacsha256

import (
	"errors"

	"github.com/All-Basket-Cryptography/abc/src/crypto/hash/sha256/impl/go"
)

const (
	// Size is the full tag size in bytes.
	Size = sha256.Size
	// BlockSize is the underlying SHA-256 block size in bytes.
	BlockSize = sha256.BlockSize
	// MaxKeyBytes is the largest key supported by the underlying hash.
	MaxKeyBytes = sha256.MaxMessageBytes
	// MaxInputBytes leaves space for the inner key block in SHA-256's input domain.
	MaxInputBytes = sha256.MaxMessageBytes - BlockSize
)

var (
	// ErrKeyTooLong reports a key outside the underlying hash's byte-length domain.
	ErrKeyTooLong = errors.New("hmacsha256: key exceeds the SHA-256 message length limit")
	// ErrMessageTooLong reports an update outside the remaining inner hash capacity.
	ErrMessageTooLong = errors.New("hmacsha256: message exceeds the HMAC-SHA-256 length limit")
	// ErrUninitialized reports use of a context that was never initialized with New.
	ErrUninitialized = errors.New("hmacsha256: initialize the context with New")
)

// Hasher holds the inner and outer SHA-256 states for a key. Initialize a
// Hasher with New. A value copy snapshots the current state independently.
// Calls and value copies of one Hasher must be serialized.
type Hasher struct {
	inner        sha256.Hasher
	outer        sha256.Hasher
	messageBytes uint64
	initialized  bool
}

// New initializes HMAC as specified in RFC 2104 section 2. The returned
// context retains no reference to the caller's key bytes.
func New(key []byte) (*Hasher, error) {
	if uint64(len(key)) > MaxKeyBytes {
		return nil, ErrKeyTooLong
	}
	var keyBlock [BlockSize]byte
	if len(key) > BlockSize {
		digest, err := sha256.Sum256(key)
		if err != nil {
			return nil, ErrKeyTooLong
		}
		copy(keyBlock[:], digest[:])
	} else {
		copy(keyBlock[:], key)
	}

	var innerPad, outerPad [BlockSize]byte
	for i, b := range keyBlock {
		innerPad[i] = b ^ 0x36
		outerPad[i] = b ^ 0x5c
	}
	var h Hasher
	if err := h.inner.Update(innerPad[:]); err != nil {
		return nil, ErrMessageTooLong
	}
	if err := h.outer.Update(outerPad[:]); err != nil {
		return nil, ErrMessageTooLong
	}
	h.initialized = true
	return &h, nil
}

// Update appends a message chunk. Rejection preserves the prior context.
func (h *Hasher) Update(data []byte) error {
	if h == nil || !h.initialized {
		return ErrUninitialized
	}
	incoming := uint64(len(data))
	if incoming > MaxInputBytes-h.messageBytes {
		return ErrMessageTooLong
	}
	if err := h.inner.Update(data); err != nil {
		return ErrMessageTooLong
	}
	h.messageBytes += incoming
	return nil
}

// Digest returns the full tag of the accepted bytes. It leaves the context
// open and unchanged, so later updates can extend the authenticated message.
func (h *Hasher) Digest() ([Size]byte, error) {
	if h == nil || !h.initialized {
		return [Size]byte{}, ErrUninitialized
	}
	innerDigest := h.inner.Digest()
	outer := h.outer
	if err := outer.Update(innerDigest[:]); err != nil {
		return [Size]byte{}, ErrMessageTooLong
	}
	return outer.Digest(), nil
}

// Authenticate computes one full HMAC-SHA-256 tag.
func Authenticate(key, message []byte) ([Size]byte, error) {
	h, err := New(key)
	if err != nil {
		return [Size]byte{}, err
	}
	if err := h.Update(message); err != nil {
		return [Size]byte{}, err
	}
	return h.Digest()
}
