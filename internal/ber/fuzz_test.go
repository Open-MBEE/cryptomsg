package ber

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"os"
	"testing"
)

func FuzzNormalize(f *testing.F) {
	seeds := []string{
		"3000", "3080" + "0000", "3080020101020102" + "0000",
		"24800403616263040264650000", "2380" + "03020040" + "0302" + "0680" + "0000",
		"a080" + "3080" + "0603" + "2a0304" + "0000" + "0000",
		"3082000402010502", "1f8100" + "0100", "30800000ff", "0480",
	}
	for _, s := range seeds {
		b, err := hexDecode(s)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	for _, name := range []string{"openssl-stream-envelopeddata.ber", "openssl-stream-authenvelopeddata.ber"} {
		if fx, err := os.ReadFile("testdata/" + name); err == nil {
			f.Add(fx)
		}
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := Normalize(in)
		if err != nil {
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("untyped error %T: %v", err, err)
			}
			if se.Offset < 0 || se.Offset > len(in) {
				t.Fatalf("offset %d outside input of %d", se.Offset, len(in))
			}
			return
		}
		// Output is DER: a fixed point of Normalize and acceptable to the
		// strict decoder.
		again, err := Normalize(out)
		if err != nil {
			t.Fatalf("output rejected: %v", err)
		}
		if !bytes.Equal(again, out) {
			t.Fatalf("not idempotent")
		}
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(out, &raw)
		if err != nil || len(rest) != 0 {
			t.Fatalf("encoding/asn1: %v rest=%d", err, len(rest))
		}
	})
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		var b byte
		for _, c := range s[i : i+2] {
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = byte(c - '0')
			case c >= 'a' && c <= 'f':
				v = byte(c-'a') + 10
			default:
				return nil, errors.New("bad hex")
			}
			b = b<<4 | v
		}
		out = append(out, b)
	}
	return out, nil
}
