// Package ber normalises BER-encoded ASN.1 to DER.
//
// CMS producers such as a streaming `openssl cms` emit the Basic Encoding
// Rules: indefinite-length constructed elements terminated by end-of-contents
// octets, and string types split into constructed chunks. The strict DER
// decoders of encoding/asn1 and cryptobyte reject both. Normalize rewrites such
// input into the Distinguished Encoding Rules form — definite minimal lengths,
// primitive strings — without knowing the schema, so the result can be decoded
// strictly afterwards.
//
// The normaliser is bounded: nesting is limited by MaxDepth, lengths must fit
// in 32 bits and within the input, and every malformation is reported as a
// *SyntaxError that wraps one of the sentinel errors of this package. It never
// panics on any input.
package ber

import (
	"errors"
	"fmt"
	"math"
)

// MaxDepth is the deepest nesting of constructed elements Normalize accepts.
// CMS structures nest about a dozen levels; the bound guards the recursion.
const MaxDepth = 64

// maxLengthOctets bounds the long-form length encoding: four octets allow
// lengths up to 4 GiB, more than any in-memory message.
const maxLengthOctets = 4

// Sentinel errors wrapped by *SyntaxError. Match with errors.Is.
var (
	// ErrTruncated reports an element extending past the end of its enclosure.
	ErrTruncated = errors.New("truncated element")
	// ErrLength reports a length encoding that is reserved, oversized or
	// otherwise not representable.
	ErrLength = errors.New("invalid length encoding")
	// ErrTag reports an identifier octet sequence that is malformed or whose
	// tag number exceeds what encoding/asn1 accepts (2^31-1).
	ErrTag = errors.New("invalid identifier octets")
	// ErrIndefinitePrimitive reports a primitive element with indefinite
	// length, which neither BER nor DER allows.
	ErrIndefinitePrimitive = errors.New("indefinite length on primitive element")
	// ErrMissingEOC reports an indefinite-length element without its
	// end-of-contents octets.
	ErrMissingEOC = errors.New("missing end-of-contents octets")
	// ErrUnexpectedEOC reports end-of-contents octets inside a definite-length
	// element, where they are not a valid element.
	ErrUnexpectedEOC = errors.New("unexpected end-of-contents octets")
	// ErrDepth reports nesting deeper than MaxDepth.
	ErrDepth = errors.New("nesting too deep")
	// ErrConstructedString reports a constructed string whose segments are
	// not primitive strings of the same type, or a constructed BIT STRING whose
	// non-final segments have unused bits.
	ErrConstructedString = errors.New("malformed constructed string")
	// ErrTrailingData reports octets after the single top-level element.
	ErrTrailingData = errors.New("trailing data after element")
)

// SyntaxError describes where in the input the normaliser stopped and why.
// Err is one of the sentinel errors of this package.
type SyntaxError struct {
	Offset int
	Err    error
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("ber: offset %d: %v", e.Offset, e.Err)
}

// Unwrap returns the sentinel error.
func (e *SyntaxError) Unwrap() error { return e.Err }

// Universal tag numbers whose primitive contents DER canonicalises.
const (
	tagBoolean    = 1
	tagInteger    = 2
	tagEnumerated = 10
)

// Universal tag numbers whose constructed form DER forbids and whose segments
// Normalize concatenates.
const (
	tagBitString       = 3
	tagOctetString     = 4
	tagUTF8String      = 12
	tagNumericString   = 18
	tagPrintableString = 19
	tagT61String       = 20
	tagVideotexString  = 21
	tagIA5String       = 22
	tagGraphicString   = 25
	tagVisibleString   = 26
	tagGeneralString   = 27
	tagUniversalString = 28
	tagBMPString       = 30
)

const classUniversal = 0

// Normalize converts a single BER-encoded element to its DER encoding. Input
// that is already DER comes back byte-identical. Every element must lie
// within the input and nothing may follow the top-level element.
func Normalize(in []byte) ([]byte, error) {
	out := make([]byte, 0, len(in))
	out, rest, err := normalize(out, in, 0, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, &SyntaxError{Offset: len(in) - len(rest), Err: ErrTrailingData}
	}
	return out, nil
}

// header is the decoded identifier and length octets of one element.
type header struct {
	class       byte
	constructed bool
	tag         uint32
	indefinite  bool
	length      int // valid when !indefinite
	size        int // number of header octets
}

// normalize appends the DER encoding of the first element of in to out and
// returns the remainder of in. base is the offset of in within the original
// input, for error reporting.
func normalize(out, in []byte, base, depth int) ([]byte, []byte, error) {
	if depth > MaxDepth {
		return nil, nil, &SyntaxError{Offset: base, Err: ErrDepth}
	}
	h, err := readHeader(in, base)
	if err != nil {
		return nil, nil, err
	}
	body := in[h.size:]
	if h.class == classUniversal && h.tag == 0 {
		// End-of-contents octets are only consumed by normalizeIndefinite.
		return nil, nil, &SyntaxError{Offset: base, Err: ErrUnexpectedEOC}
	}

	if !h.constructed {
		if h.indefinite {
			return nil, nil, &SyntaxError{Offset: base, Err: ErrIndefinitePrimitive}
		}
		if h.length > len(body) {
			return nil, nil, &SyntaxError{Offset: base, Err: ErrTruncated}
		}
		content := canonicalPrimitive(h, body[:h.length])
		out = appendHeader(out, h, len(content))
		out = append(out, content...)
		return out, body[h.length:], nil
	}

	// Constructed: normalise the children into a scratch buffer, then emit a
	// definite-length header for them.
	var children []byte
	var rest []byte
	childBase := base + h.size
	if h.indefinite {
		children, rest, err = normalizeIndefinite(body, childBase, depth)
	} else {
		if h.length > len(body) {
			return nil, nil, &SyntaxError{Offset: base, Err: ErrTruncated}
		}
		children, err = normalizeChildren(body[:h.length], childBase, depth)
		rest = body[h.length:]
	}
	if err != nil {
		return nil, nil, err
	}

	if h.class == classUniversal && isStringTag(h.tag) {
		content, err := joinSegments(children, h.tag, base, true)
		if err != nil {
			return nil, nil, err
		}
		h.constructed = false
		out = appendHeader(out, h, len(content))
		out = append(out, content...)
		return out, rest, nil
	}

	out = appendHeader(out, h, len(children))
	out = append(out, children...)
	return out, rest, nil
}

// normalizeChildren normalises every element of a definite-length body.
func normalizeChildren(body []byte, base, depth int) ([]byte, error) {
	var out []byte
	for len(body) > 0 {
		if body[0] == 0 {
			return nil, &SyntaxError{Offset: base, Err: ErrUnexpectedEOC}
		}
		var err error
		before := len(body)
		out, body, err = normalize(out, body, base, depth+1)
		if err != nil {
			return nil, err
		}
		base += before - len(body)
	}
	return out, nil
}

// normalizeIndefinite normalises elements until the end-of-contents octets
// and returns what follows them.
func normalizeIndefinite(body []byte, base, depth int) ([]byte, []byte, error) {
	var out []byte
	for {
		if len(body) < 2 {
			return nil, nil, &SyntaxError{Offset: base, Err: ErrMissingEOC}
		}
		if body[0] == 0 {
			if body[1] != 0 {
				return nil, nil, &SyntaxError{Offset: base, Err: ErrLength}
			}
			return out, body[2:], nil
		}
		var err error
		before := len(body)
		out, body, err = normalize(out, body, base, depth+1)
		if err != nil {
			return nil, nil, err
		}
		base += before - len(body)
	}
}

// JoinOctetStrings concatenates the OCTET STRING segments that make up the
// content of a constructed, implicitly tagged OCTET STRING already normalised
// by Normalize. Normalize cannot know that an element such as the
// `encryptedContent [0] IMPLICIT OCTET STRING` of CMS is a string under its
// context-specific tag, so it leaves such an element constructed; the decoder
// that knows the schema calls this on the element's content. Segments may be
// primitive OCTET STRINGs or constructed ones that nest primitive segments.
func JoinOctetStrings(content []byte) ([]byte, error) {
	return joinSegments(content, tagOctetString, 0, false)
}

// canonicalPrimitive returns the DER contents of a primitive element whose BER
// contents may differ: BOOLEAN TRUE is always 0xff and INTEGER/ENUMERATED carry
// no redundant sign octets. Every other value is returned as is.
func canonicalPrimitive(h header, content []byte) []byte {
	if h.class != classUniversal {
		return content
	}
	switch h.tag {
	case tagBoolean:
		if len(content) == 1 && content[0] != 0 {
			return []byte{0xff}
		}
	case tagInteger, tagEnumerated:
		for len(content) >= 2 && ((content[0] == 0 && content[1]&0x80 == 0) ||
			(content[0] == 0xff && content[1]&0x80 != 0)) {
			content = content[1:]
		}
	}
	return content
}

// joinSegments concatenates the contents of a constructed string's segments,
// which after normalisation are primitive elements of the same universal tag.
// For BIT STRING every segment but the last must have zero unused bits; the
// result carries the last segment's unused-bits octet. With flat set, the
// segments must all be primitive, as Normalize leaves them. segments are
// already normalised bytes, whose offsets no longer map onto the input, so an
// error is reported at base, the offset of the enclosing constructed string.
func joinSegments(segments []byte, tag uint32, base int, flat bool) ([]byte, error) {
	var content []byte
	if tag == tagBitString {
		content = append(content, 0)
	}
	for len(segments) > 0 {
		h, err := readHeader(segments, base)
		if err != nil {
			return nil, err
		}
		if h.class != classUniversal || h.tag != tag || h.indefinite || h.length > len(segments)-h.size {
			return nil, &SyntaxError{Offset: base, Err: ErrConstructedString}
		}
		seg := segments[h.size : h.size+h.length]
		if h.constructed {
			if flat {
				return nil, &SyntaxError{Offset: base, Err: ErrConstructedString}
			}
			inner, err := joinSegments(seg, tag, base, false)
			if err != nil {
				return nil, err
			}
			seg = inner
		}
		if tag == tagBitString {
			if len(seg) == 0 {
				return nil, &SyntaxError{Offset: base, Err: ErrConstructedString}
			}
			last := h.size+h.length == len(segments)
			if seg[0] > 7 || (!last && seg[0] != 0) {
				return nil, &SyntaxError{Offset: base, Err: ErrConstructedString}
			}
			content[0] = seg[0]
			seg = seg[1:]
		}
		content = append(content, seg...)
		segments = segments[h.size+h.length:]
	}
	return content, nil
}

func isStringTag(tag uint32) bool {
	switch tag {
	case tagBitString, tagOctetString, tagUTF8String, tagNumericString,
		tagPrintableString, tagT61String, tagVideotexString, tagIA5String,
		tagGraphicString, tagVisibleString, tagGeneralString,
		tagUniversalString, tagBMPString:
		return true
	}
	return false
}

// readHeader decodes the identifier and length octets at the start of in.
func readHeader(in []byte, base int) (header, error) {
	var h header
	if len(in) == 0 {
		return h, &SyntaxError{Offset: base, Err: ErrTruncated}
	}
	b := in[0]
	h.class = b >> 6
	h.constructed = b&0x20 != 0
	i := 1
	if b&0x1f != 0x1f {
		h.tag = uint32(b & 0x1f)
	} else {
		// High-tag-number form: base-128 digits, high bit set on all but the
		// last. The first digit must not be zero, the value ≥ 31 and ≤ 2^31-1.
		var tag uint64
		for n := 0; ; n++ {
			if i >= len(in) {
				return h, &SyntaxError{Offset: base, Err: ErrTruncated}
			}
			d := in[i]
			i++
			if n == 0 && d&0x7f == 0 {
				return h, &SyntaxError{Offset: base, Err: ErrTag}
			}
			if n >= 5 {
				return h, &SyntaxError{Offset: base, Err: ErrTag}
			}
			tag = tag<<7 | uint64(d&0x7f)
			if d&0x80 == 0 {
				break
			}
		}
		if tag < 0x1f || tag > math.MaxInt32 {
			return h, &SyntaxError{Offset: base, Err: ErrTag}
		}
		h.tag = uint32(tag)
	}

	if i >= len(in) {
		return h, &SyntaxError{Offset: base, Err: ErrTruncated}
	}
	l := in[i]
	i++
	switch {
	case l < 0x80:
		h.length = int(l)
	case l == 0x80:
		h.indefinite = true
	case l == 0xff:
		return h, &SyntaxError{Offset: base, Err: ErrLength}
	default:
		n := int(l & 0x7f)
		if n > maxLengthOctets {
			return h, &SyntaxError{Offset: base, Err: ErrLength}
		}
		if i+n > len(in) {
			return h, &SyntaxError{Offset: base, Err: ErrTruncated}
		}
		var length uint64
		for _, d := range in[i : i+n] {
			length = length<<8 | uint64(d)
		}
		i += n
		if length > uint64(len(in)) {
			// Cannot possibly fit; report before any conversion.
			return h, &SyntaxError{Offset: base, Err: ErrTruncated}
		}
		h.length = int(length)
	}
	h.size = i
	return h, nil
}

// appendHeader appends the DER identifier and definite minimal length octets.
func appendHeader(out []byte, h header, length int) []byte {
	b := h.class << 6
	if h.constructed {
		b |= 0x20
	}
	if h.tag < 0x1f {
		out = append(out, b|byte(h.tag))
	} else {
		out = append(out, b|0x1f)
		var digits [5]byte
		n := 0
		for t := h.tag; ; t >>= 7 {
			digits[n] = byte(t & 0x7f)
			n++
			if t < 0x80 {
				break
			}
		}
		for n > 0 {
			n--
			d := digits[n]
			if n > 0 {
				d |= 0x80
			}
			out = append(out, d)
		}
	}
	if length < 0 {
		// Unreachable: lengths are byte-slice lengths. Keep the conversion
		// below total anyway.
		length = 0
	}
	l := uint64(length)
	if l < 0x80 {
		return append(out, byte(l))
	}
	var lenOctets [8]byte
	n := 0
	for ; l > 0; l >>= 8 {
		lenOctets[n] = byte(l)
		n++
	}
	out = append(out, 0x80|byte(n))
	for n > 0 {
		n--
		out = append(out, lenOctets[n])
	}
	return out
}
