// Package chacha20poly1305 implements RFC 8439 detached authenticated encryption.
package chacha20poly1305

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	chacha "github.com/All-Basket-Cryptography/abc/src/crypto/cipher/chacha20/impl/go"
	poly "github.com/All-Basket-Cryptography/abc/src/crypto/mac/poly1305/impl/go"
)

const (
	KeyBytes   = chacha.KeyBytes
	NonceBytes = chacha.NonceBytes
	TagBytes   = poly.TagBytes
)

var (
	ErrShortDestination = chacha.ErrShortDestination
	ErrCounterRange     = chacha.ErrCounterRange
	ErrAuthentication   = errors.New("chacha20-poly1305: authentication failed")
)

// SealDetached encrypts plaintext into the equally long prefix of dst and
// returns a separate tag. Use a fresh nonce for each call under a key.
// It admits overlapping plaintext, associatedData, and dst.
func SealDetached(dst, plaintext, associatedData []byte, key [KeyBytes]byte, nonce [NonceBytes]byte) ([TagBytes]byte, error) {
	if err := validate(dst, plaintext); err != nil {
		return [TagBytes]byte{}, err
	}
	mac := startMAC(key, nonce, associatedData)
	if err := chacha.XOR(dst, plaintext, key, nonce, 1); err != nil {
		return [TagBytes]byte{}, err
	}
	return finishMAC(&mac, dst[:len(plaintext)], len(associatedData)), nil
}

// OpenDetached verifies the tag before writing plaintext. It admits overlapping
// ciphertext, associatedData, and dst. Errors preserve the destination.
func OpenDetached(dst, ciphertext, associatedData []byte, tag [TagBytes]byte, key [KeyBytes]byte, nonce [NonceBytes]byte) error {
	if err := validate(dst, ciphertext); err != nil {
		return err
	}
	mac := startMAC(key, nonce, associatedData)
	expected := finishMAC(&mac, ciphertext, len(associatedData))
	if subtle.ConstantTimeCompare(expected[:], tag[:]) != 1 {
		return ErrAuthentication
	}
	return chacha.XOR(dst, ciphertext, key, nonce, 1)
}

func validate(dst, src []byte) error {
	if len(dst) < len(src) {
		return ErrShortDestination
	}
	if !chacha.FitsCounter(uint64(len(src)), 1) {
		return ErrCounterRange
	}
	return nil
}

func startMAC(key [KeyBytes]byte, nonce [NonceBytes]byte, associatedData []byte) poly.MAC {
	keystream := chacha.Block(key, nonce, 0)
	mac := poly.New([poly.KeyBytes]byte(keystream[:poly.KeyBytes]))
	writePadded(&mac, associatedData)
	return mac
}

func writePadded(mac *poly.MAC, message []byte) {
	var zeros [16]byte
	padding := (0 - len(message)) & 15
	// The freshly constructed MAC stays active until the length field is written.
	_ = mac.Update(message)
	_ = mac.Update(zeros[:padding])
}

func finishMAC(mac *poly.MAC, ciphertext []byte, associatedBytes int) [TagBytes]byte {
	writePadded(mac, ciphertext)
	var lengths [16]byte
	binary.LittleEndian.PutUint64(lengths[:8], uint64(associatedBytes))
	binary.LittleEndian.PutUint64(lengths[8:], uint64(len(ciphertext)))
	_ = mac.Update(lengths[:])
	tag, _ := mac.Finalize()
	return tag
}
