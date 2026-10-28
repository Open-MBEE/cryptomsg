package ber

import (
	"bytes"
	"sort"
)

// SortSetOf orders DER-encoded elements as X.690 §11.6 requires for a SET OF:
// ascending by encoding, comparing octet by octet with the shorter encoding
// padded by zero octets at the end. It sorts in place and returns the slice.
func SortSetOf(elements [][]byte) [][]byte {
	sort.SliceStable(elements, func(i, j int) bool {
		return compareSetOf(elements[i], elements[j]) < 0
	})
	return elements
}

func compareSetOf(a, b []byte) int {
	n := min(len(a), len(b))
	if c := bytes.Compare(a[:n], b[:n]); c != 0 {
		return c
	}
	// Equal prefix: the longer one is greater unless its tail is all zeros.
	for _, x := range a[n:] {
		if x != 0 {
			return 1
		}
	}
	for _, x := range b[n:] {
		if x != 0 {
			return -1
		}
	}
	return 0
}

// CanonicalSetOf returns the contents of a SET OF, given as concatenated DER
// elements, with the elements in DER order.
func CanonicalSetOf(content []byte) ([]byte, error) {
	var elements [][]byte
	for off := 0; off < len(content); {
		h, err := readHeader(content[off:], off)
		if err != nil {
			return nil, err
		}
		if h.indefinite || h.length > len(content)-off-h.size {
			return nil, &SyntaxError{Offset: off, Err: ErrTruncated}
		}
		end := off + h.size + h.length
		elements = append(elements, content[off:end])
		off = end
	}
	SortSetOf(elements)
	out := make([]byte, 0, len(content))
	for _, e := range elements {
		out = append(out, e...)
	}
	return out, nil
}
