// Package x25519 supplies fixed-width raw keys over Go's native RFC 7748 provider.
package x25519

import (
	"crypto/ecdh"
	"errors"
)

const KeyBytes = 32

var (
	ErrUninitialized = errors.New("x25519: use NewPrivateKey to initialize the scalar")
	ErrInvalidPeer   = errors.New("x25519: peer produced the all-zero shared secret")
)

// PrivateKey holds a read-only Go X25519 key and its derived public key.
// The zero value is uninitialized.
type PrivateKey struct {
	provider *ecdh.PrivateKey
}

// NewPrivateKey loads a raw 32-byte scalar. Go's X25519 implementation
// clamps the scalar at multiplication. The caller supplies key entropy.
func NewPrivateKey(scalar [KeyBytes]byte) (PrivateKey, error) {
	key, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		return PrivateKey{}, err
	}
	return PrivateKey{provider: key}, nil
}

// PublicKey returns the local RFC 7748 public-coordinate encoding.
func (k PrivateKey) PublicKey() ([KeyBytes]byte, error) {
	if k.provider == nil {
		return [KeyBytes]byte{}, ErrUninitialized
	}
	return [KeyBytes]byte(k.provider.PublicKey().Bytes()), nil
}

// SharedSecret returns a raw 32-byte secret or an error with a zero result.
// The protocol using the secret must authenticate its keys and context and
// use a suitable key derivation function.
func (k PrivateKey) SharedSecret(peer [KeyBytes]byte) ([KeyBytes]byte, error) {
	if k.provider == nil {
		return [KeyBytes]byte{}, ErrUninitialized
	}
	remote, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return [KeyBytes]byte{}, err
	}
	secret, err := k.provider.ECDH(remote)
	if err != nil {
		return [KeyBytes]byte{}, ErrInvalidPeer
	}
	return [KeyBytes]byte(secret), nil
}
