// Package keywrap implements the AES Key Wrap algorithm of RFC 3394
// (NIST SP 800-38F KW), used by CMS KeyAgreeRecipientInfo to wrap the
// content-encryption key under the pairwise key-encryption key.
package keywrap

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// Errors returned by Wrap and Unwrap.
var (
	// ErrKeyLength reports plaintext that is not a multiple of 8 octets of
	// at least 16, or wrapped data that is not a multiple of 8 of at least 24.
	ErrKeyLength = errors.New("keywrap: invalid key length")
	// ErrIntegrity reports a failed integrity check on unwrap.
	ErrIntegrity = errors.New("keywrap: integrity check failed")
)

// defaultIV is the RFC 3394 §2.2.3.1 initial value.
var defaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// Wrap wraps plaintext (n ≥ 2 blocks of 64 bits) under kek, an AES block
// cipher, returning n+1 blocks.
func Wrap(kek cipher.Block, plaintext []byte) ([]byte, error) {
	if kek.BlockSize() != 16 {
		return nil, ErrKeyLength
	}
	n := len(plaintext) / 8
	if n < 2 || len(plaintext)%8 != 0 {
		return nil, ErrKeyLength
	}
	// RFC 3394 §2.2.1, index-based variant.
	a := defaultIV
	r := make([]byte, len(plaintext))
	copy(r, plaintext)
	var b [16]byte
	var t uint64 // n*j + i, which the loops visit in increasing order
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(b[:8], a[:])
			copy(b[8:], r[(i-1)*8:i*8])
			kek.Encrypt(b[:], b[:])
			t++
			copy(a[:], b[:8])
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(a[:])^t)
			copy(r[(i-1)*8:i*8], b[8:])
		}
	}
	out := make([]byte, 0, len(plaintext)+8)
	out = append(out, a[:]...)
	return append(out, r...), nil
}

// Unwrap reverses Wrap and checks the integrity value. It returns
// ErrIntegrity, and no key material, when the check fails.
func Unwrap(kek cipher.Block, wrapped []byte) ([]byte, error) {
	if kek.BlockSize() != 16 {
		return nil, ErrKeyLength
	}
	n := len(wrapped)/8 - 1
	if n < 2 || len(wrapped)%8 != 0 {
		return nil, ErrKeyLength
	}
	// RFC 3394 §2.2.2, index-based variant.
	var a [8]byte
	copy(a[:], wrapped[:8])
	r := make([]byte, len(wrapped)-8)
	copy(r, wrapped[8:])
	var b [16]byte
	t := 6 * uint64(len(r)/8) // n*j + i, visited in decreasing order
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a[:])^t)
			t--
			copy(b[8:], r[(i-1)*8:i*8])
			kek.Decrypt(b[:], b[:])
			copy(a[:], b[:8])
			copy(r[(i-1)*8:i*8], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(a[:], defaultIV[:]) != 1 {
		clear(r)
		return nil, ErrIntegrity
	}
	return r, nil
}
