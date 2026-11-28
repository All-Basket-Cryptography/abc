// Package ecdsap256 implements ABC's byte format for deterministic P-256 ECDSA with SHA-256.
package ecdsap256

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
)

const (
	PrivateKeySize          = 32
	PublicKeySize           = 65
	CompressedPublicKeySize = 33
	SignatureSize           = 64
)

var (
	ErrInvalidPrivateKey  = errors.New("ecdsa-p256: private scalar must be in 1..n-1")
	ErrInvalidPublicKey   = errors.New("ecdsa-p256: invalid SEC 1 point")
	ErrInvalidSignature   = errors.New("ecdsa-p256: invalid P1363 signature")
	ErrVerificationFailed = errors.New("ecdsa-p256: signature verification failed")
	ErrSigningFailed      = errors.New("ecdsa-p256: signing failed")
)

// PublicKey derives an uncompressed SEC 1 point from a 32-byte big-endian scalar.
func PublicKey(scalar [PrivateKeySize]byte) ([PublicKeySize]byte, error) {
	var result [PublicKeySize]byte
	key, err := importPrivateKey(scalar)
	if err != nil {
		return result, err
	}
	copy(result[:], elliptic.Marshal(elliptic.P256(), key.X, key.Y))
	return result, nil
}

// Sign returns the RFC 6979 signature of SHA-256(message) as fixed-width r || s.
// It preserves the provider's S representative.
func Sign(scalar [PrivateKeySize]byte, message []byte) ([SignatureSize]byte, error) {
	var result [SignatureSize]byte
	key, err := importPrivateKey(scalar)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(message)
	der, err := key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return result, ErrSigningFailed
	}
	var integers struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &integers)
	if err != nil || len(rest) != 0 || !validInteger(integers.R) || !validInteger(integers.S) {
		return result, ErrSigningFailed
	}
	integers.R.FillBytes(result[:SignatureSize/2])
	integers.S.FillBytes(result[SignatureSize/2:])
	return result, nil
}

// Verify admits uncompressed or compressed SEC 1 keys and exact-length P1363
// signatures. Both representatives of S are accepted.
func Verify(publicKey, message, signature []byte) error {
	key, err := importPublicKey(publicKey)
	if err != nil {
		return err
	}
	if len(signature) != SignatureSize {
		return ErrInvalidSignature
	}
	r := new(big.Int).SetBytes(signature[:SignatureSize/2])
	s := new(big.Int).SetBytes(signature[SignatureSize/2:])
	if !validInteger(r) || !validInteger(s) {
		return ErrInvalidSignature
	}
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(key, digest[:], r, s) {
		return ErrVerificationFailed
	}
	return nil
}

func validInteger(scalar *big.Int) bool {
	return scalar != nil && scalar.Sign() > 0 && scalar.Cmp(elliptic.P256().Params().N) < 0
}

func importPrivateKey(scalar [PrivateKeySize]byte) (*ecdsa.PrivateKey, error) {
	var zero [PrivateKeySize]byte
	if subtle.ConstantTimeCompare(scalar[:], zero[:]) == 1 {
		return nil, ErrInvalidPrivateKey
	}
	// Version 1, the 32-byte scalar, and the explicit prime256v1 named-curve OID.
	var der [51]byte
	copy(der[:7], []byte{0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20})
	copy(der[7:39], scalar[:])
	copy(der[39:], []byte{0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07})
	key, err := x509.ParseECPrivateKey(der[:])
	clear(der[:])
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	return key, nil
}

func importPublicKey(encoded []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	var x, y *big.Int
	switch len(encoded) {
	case PublicKeySize:
		x, y = elliptic.Unmarshal(curve, encoded)
	case CompressedPublicKeySize:
		x, y = elliptic.UnmarshalCompressed(curve, encoded)
	default:
		return nil, ErrInvalidPublicKey
	}
	if x == nil || y == nil {
		return nil, ErrInvalidPublicKey
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
