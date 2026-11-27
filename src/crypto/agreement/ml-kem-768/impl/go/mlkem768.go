// Package mlkem768 exposes the fixed-size FIPS 203 profile of Go crypto/mlkem.
package mlkem768

import (
	"crypto/mlkem"
	"errors"
)

const (
	SeedSize         = mlkem.SeedSize
	PublicKeySize    = mlkem.EncapsulationKeySize768
	CiphertextSize   = mlkem.CiphertextSize768
	SharedSecretSize = mlkem.SharedKeySize
)

var errUninitialized = errors.New("ml-kem-768: uninitialized decapsulation key")

// DecapsulationKey holds a provider key. Construct it with GenerateKey or
// NewDecapsulationKey. Keep the seed and all copies of the key private.
type DecapsulationKey struct {
	key *mlkem.DecapsulationKey768
}

// GenerateKey creates a key using the Go runtime's cryptographic RNG.
func GenerateKey() (*DecapsulationKey, error) {
	key, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey{key}, nil
}

// NewDecapsulationKey derives a key from the private 64-byte d || z seed.
func NewDecapsulationKey(seed []byte) (*DecapsulationKey, error) {
	key, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey{key}, nil
}

// PublicKey returns the owned fixed-size encapsulation key.
func (key *DecapsulationKey) PublicKey() ([PublicKeySize]byte, error) {
	var result [PublicKeySize]byte
	if key == nil || key.key == nil {
		return result, errUninitialized
	}
	copy(result[:], key.key.EncapsulationKey().Bytes())
	return result, nil
}

// Decapsulate returns the shared secret. Correctly sized invalid ciphertexts
// return the FIPS 203 implicit-rejection secret instead of a validity signal.
func (key *DecapsulationKey) Decapsulate(ciphertext []byte) ([SharedSecretSize]byte, error) {
	var result [SharedSecretSize]byte
	if key == nil || key.key == nil {
		return result, errUninitialized
	}
	secret, err := key.key.Decapsulate(ciphertext)
	if err != nil {
		return result, err
	}
	copy(result[:], secret)
	return result, nil
}

// Encapsulate checks an encoded public key and returns the new ciphertext and shared secret.
func Encapsulate(public []byte) ([CiphertextSize]byte, [SharedSecretSize]byte, error) {
	var ciphertext [CiphertextSize]byte
	var secret [SharedSecretSize]byte
	key, err := mlkem.NewEncapsulationKey768(public)
	if err != nil {
		return ciphertext, secret, err
	}
	s, c := key.Encapsulate()
	copy(ciphertext[:], c)
	copy(secret[:], s)
	return ciphertext, secret, nil
}
