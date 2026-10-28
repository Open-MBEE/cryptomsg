// Package kdf implements the ANSI X9.63 key derivation function (also
// SEC 1 §3.6.1 and NIST SP 800-56A §5.8.1 "concatenation KDF"), used by CMS
// ephemeral-static ECDH (RFC 5753 §7.1.8) to derive the key-encryption key
// from the shared secret and the DER-encoded ECC-CMS-SharedInfo.
package kdf

import (
	"encoding/binary"
	"errors"
	"hash"
)

// ErrLength reports a request for more than hashLen · (2^32 − 1) octets.
var ErrLength = errors.New("kdf: requested length too large")

// X963 derives length octets from secret and sharedInfo with the hash
// function h: K = Hash(Z || counter || SharedInfo) for counter = 1, 2, …
func X963(h func() hash.Hash, secret, sharedInfo []byte, length int) ([]byte, error) {
	hh := h()
	size := hh.Size()
	// ceil(length/size) counter blocks must fit the 32-bit counter.
	if length < 0 || (length > 0 && (length-1)/size >= 0xffffffff) {
		return nil, ErrLength
	}
	out := make([]byte, 0, length+size)
	var counter [4]byte
	for c := uint32(1); len(out) < length; c++ {
		binary.BigEndian.PutUint32(counter[:], c)
		hh.Reset()
		hh.Write(secret)
		hh.Write(counter[:])
		hh.Write(sharedInfo)
		out = hh.Sum(out)
	}
	return out[:length], nil
}
