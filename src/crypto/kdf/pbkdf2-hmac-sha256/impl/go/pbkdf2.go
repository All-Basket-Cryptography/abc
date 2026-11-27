// Package pbkdf2 implements portable Go PBKDF2-HMAC-SHA-256 for ABC research.
package pbkdf2

import (
	"encoding/binary"
	"errors"

	hmac "github.com/All-Basket-Cryptography/abc/src/crypto/mac/hmac-sha256/impl/go"
)

const MaxOutputBytes uint64 = (1<<32 - 1) * hmac.Size

var (
	ErrIterations = errors.New("pbkdf2: iterations must be positive")
	ErrOutput     = errors.New("pbkdf2: output length is outside the RFC domain")
	ErrSalt       = errors.New("pbkdf2: salt and block index exceed the HMAC message limit")
)

// Derive returns a fresh output slice. Callers set resource-policy limits
// before accepting iterations and output length from untrusted input.
func Derive(password, salt []byte, iterations uint32, length int) ([]byte, error) {
	if iterations == 0 {
		return nil, ErrIterations
	}
	if length <= 0 || uint64(length) > MaxOutputBytes {
		return nil, ErrOutput
	}
	if uint64(len(salt)) > hmac.MaxInputBytes-4 {
		return nil, ErrSalt
	}
	keyed, err := hmac.New(password)
	if err != nil {
		return nil, err
	}
	salted := *keyed
	if err := salted.Update(salt); err != nil {
		return nil, err
	}

	output := make([]byte, length)
	for offset, index := 0, uint64(1); offset < length; index++ {
		block, err := deriveBlock(*keyed, salted, uint32(index), iterations)
		if err != nil {
			return nil, err
		}
		offset += copy(output[offset:], block[:])
	}
	return output, nil
}

func deriveBlock(keyed, salted hmac.Hasher, index, iterations uint32) ([hmac.Size]byte, error) {
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], index)
	if err := salted.Update(counter[:]); err != nil {
		return [hmac.Size]byte{}, err
	}
	previous, err := salted.Digest()
	if err != nil {
		return [hmac.Size]byte{}, err
	}
	full := previous
	for round := uint32(1); round < iterations; round++ {
		mac := keyed
		if err := mac.Update(previous[:]); err != nil {
			return [hmac.Size]byte{}, err
		}
		previous, err = mac.Digest()
		if err != nil {
			return [hmac.Size]byte{}, err
		}
		for i, term := range previous {
			full[i] ^= term
		}
	}
	return full, nil
}
