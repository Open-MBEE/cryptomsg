package cryptomsg

import (
	"errors"

	"github.com/Open-MBEE/cryptomsg/internal/ber"
)

var (
	errConstructed  = errors.New("constructed encoding where a primitive is required")
	errTrailingData = errors.New("trailing data")
	errAbsent       = errors.New("required field absent")
)

// malformed wraps a decoding failure of the named structure.
func malformed(structure string, err error) error {
	if err == nil {
		err = errors.New("invalid encoding")
	}
	return &MalformedError{Structure: structure, Err: err}
}

// normalizeInput turns BER or DER input into DER, or a MalformedError.
func normalizeInput(in []byte) ([]byte, error) {
	der, err := ber.Normalize(in)
	if err != nil {
		return nil, malformed("ContentInfo", err)
	}
	return der, nil
}
