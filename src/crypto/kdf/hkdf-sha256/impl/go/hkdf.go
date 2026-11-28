// Package hkdf implements research HKDF-SHA-256 in portable Go.
package hkdf

import (
	"errors"

	hmac "github.com/All-Basket-Cryptography/abc/src/crypto/mac/hmac-sha256/impl/go"
)

const (
	// PRKSize is the size of an extracted key in bytes.
	PRKSize = hmac.Size
	// MaxOutputBytes is the RFC 5869 limit of 255 digest blocks.
	MaxOutputBytes = 255 * PRKSize
)

var (
	ErrPRKTooShort  = errors.New("hkdf: pseudorandom key must contain at least 32 bytes")
	ErrInfoTooLong  = errors.New("hkdf: context exceeds the HMAC message limit")
	ErrOutputLength = errors.New("hkdf: output length must be between 0 and 8160 bytes")
)

// Extract derives a fixed-size pseudorandom key. A nil salt uses the RFC's
// default of PRKSize zero bytes.
func Extract(salt, input []byte) ([PRKSize]byte, error) {
	if salt == nil {
		var defaultSalt [PRKSize]byte
		return hmac.Authenticate(defaultSalt[:], input)
	}
	return hmac.Authenticate(salt, input)
}

// Expand returns independent storage and leaves the input slices unchanged.
func Expand(prk, info []byte, length int) ([]byte, error) {
	if len(prk) < PRKSize {
		return nil, ErrPRKTooShort
	}
	if uint64(len(prk)) > hmac.MaxKeyBytes {
		return nil, hmac.ErrKeyTooLong
	}
	if length < 0 || length > MaxOutputBytes {
		return nil, ErrOutputLength
	}
	if length == 0 {
		return []byte{}, nil
	}
	overhead := uint64(1)
	if length > PRKSize {
		overhead += PRKSize
	}
	if uint64(len(info)) > hmac.MaxInputBytes-overhead {
		return nil, ErrInfoTooLong
	}
	output := make([]byte, length)
	var previous [PRKSize]byte
	for offset, counter := 0, 1; offset < length; counter++ {
		mac, err := hmac.New(prk)
		if err != nil {
			return nil, err
		}
		if counter > 1 {
			if err := mac.Update(previous[:]); err != nil {
				return nil, err
			}
		}
		if err := mac.Update(info); err != nil {
			return nil, err
		}
		if err := mac.Update([]byte{byte(counter)}); err != nil {
			return nil, err
		}
		previous, err = mac.Digest()
		if err != nil {
			return nil, err
		}
		offset += copy(output[offset:], previous[:])
	}
	return output, nil
}

// Derive performs RFC 5869 extract and expand without exporting the
// intermediate pseudorandom key.
func Derive(salt, input, info []byte, length int) ([]byte, error) {
	if length < 0 || length > MaxOutputBytes {
		return nil, ErrOutputLength
	}
	prk, err := Extract(salt, input)
	if err != nil {
		return nil, err
	}
	return Expand(prk[:], info, length)
}
