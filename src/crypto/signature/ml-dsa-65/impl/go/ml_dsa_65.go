// Package mldsa65 supplies ABC's byte protocol for Pure deterministic ML-DSA-65.
package mldsa65

import (
	"crypto/mldsa"
	"errors"
)

const (
	SeedSize        = mldsa.PrivateKeySize
	PublicKeySize   = mldsa.MLDSA65PublicKeySize
	SignatureSize   = mldsa.MLDSA65SignatureSize
	MaxContextBytes = 255
)

var (
	ErrInvalidPublicKey   = errors.New("ml-dsa-65: invalid public key")
	ErrInvalidSignature   = errors.New("ml-dsa-65: invalid signature length")
	ErrContextTooLong     = errors.New("ml-dsa-65: context exceeds 255 bytes")
	ErrVerificationFailed = errors.New("ml-dsa-65: signature verification failed")
	ErrKeyDerivation      = errors.New("ml-dsa-65: key derivation failed")
	ErrSigningFailed      = errors.New("ml-dsa-65: signing failed")
)

// PublicKey derives the canonical public key from a caller-owned 32-byte seed.
func PublicKey(seed [SeedSize]byte) ([PublicKeySize]byte, error) {
	var output [PublicKeySize]byte
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[:])
	if err != nil {
		return output, ErrKeyDerivation
	}
	encoded := key.PublicKey().Bytes()
	if len(encoded) != PublicKeySize {
		return output, ErrKeyDerivation
	}
	copy(output[:], encoded)
	return output, nil
}

// Sign signs the message using the Pure ML-DSA domain and FIPS 204 deterministic randomness.
func Sign(seed [SeedSize]byte, message, context []byte) ([SignatureSize]byte, error) {
	var output [SignatureSize]byte
	if len(context) > MaxContextBytes {
		return output, ErrContextTooLong
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed[:])
	if err != nil {
		return output, ErrKeyDerivation
	}
	signature, err := key.SignDeterministic(message, &mldsa.Options{Context: string(context)})
	if err != nil || len(signature) != SignatureSize {
		return output, ErrSigningFailed
	}
	copy(output[:], signature)
	return output, nil
}

// Verify verifies an exact-length signature with the given public key and context.
func Verify(publicKey, message, context, signature []byte) error {
	if len(context) > MaxContextBytes {
		return ErrContextTooLong
	}
	if len(publicKey) != PublicKeySize {
		return ErrInvalidPublicKey
	}
	if len(signature) != SignatureSize {
		return ErrInvalidSignature
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), publicKey)
	if err != nil {
		return ErrInvalidPublicKey
	}
	if err := mldsa.Verify(key, message, signature, &mldsa.Options{Context: string(context)}); err != nil {
		return ErrVerificationFailed
	}
	return nil
}
