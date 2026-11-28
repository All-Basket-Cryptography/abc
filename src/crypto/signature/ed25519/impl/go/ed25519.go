// Package abced25519 exposes seed-only pure Ed25519 with explicit point checks.
package abced25519

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"filippo.io/edwards25519"
)

const (
	SeedSize      = ed25519.SeedSize
	PublicKeySize = ed25519.PublicKeySize
	SignatureSize = ed25519.SignatureSize
)

var (
	ErrPublicKey = errors.New("invalid Ed25519 public key")
	ErrSignature = errors.New("invalid Ed25519 signature")
	identity     = edwards25519.NewIdentityPoint()
)

// PublicKey derives the raw public key from a 32-byte Ed25519 seed.
func PublicKey(seed [SeedSize]byte) (public [PublicKeySize]byte) {
	private := ed25519.NewKeyFromSeed(seed[:])
	defer clear(private)
	copy(public[:], private[SeedSize:])
	return public
}

// Sign signs the exact message bytes in pure RFC 8032 Ed25519 mode.
func Sign(seed [SeedSize]byte, message []byte) (signature [SignatureSize]byte) {
	private := ed25519.NewKeyFromSeed(seed[:])
	defer clear(private)
	copy(signature[:], ed25519.Sign(private, message))
	return signature
}

// VerifyStrict checks canonical encodings and rejects small-order A and R.
// The Go provider checks the canonical scalar S and the pure Ed25519 equation.
func VerifyStrict(public [PublicKeySize]byte, message []byte, signature [SignatureSize]byte) error {
	if !validPoint(public[:]) {
		return ErrPublicKey
	}
	if !validPoint(signature[:PublicKeySize]) ||
		!ed25519.Verify(ed25519.PublicKey(public[:]), message, signature[:]) {
		return ErrSignature
	}
	return nil
}

func validPoint(encoded []byte) bool {
	var point, multiplied edwards25519.Point
	if _, err := point.SetBytes(encoded); err != nil || !bytes.Equal(point.Bytes(), encoded) {
		return false
	}
	return multiplied.MultByCofactor(&point).Equal(identity) == 0
}
