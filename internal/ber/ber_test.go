package ber

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNormalizeDERUnchanged(t *testing.T) {
	type inner struct {
		A int
		B []byte
		C string `asn1:"utf8"`
	}
	der, err := asn1.Marshal(struct {
		X     inner
		Flag  bool
		OID   asn1.ObjectIdentifier
		Bits  asn1.BitString
		Items []int `asn1:"set"`
	}{inner{42, bytes.Repeat([]byte{7}, 300), "héllo"}, true,
		asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}, asn1.BitString{Bytes: []byte{0xa0}, BitLength: 3}, []int{3, 1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Normalize(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, der) {
		t.Fatalf("DER changed:\n in %x\nout %x", der, got)
	}
}

func TestNormalizeIndefinite(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty sequence", "30800000", "3000"},
		{"sequence with two ints", "3080020101020102" + "0000", "3006020101020102"},
		{"nested indefinite", "30803080020105" + "0000" + "0000", "30053003020105"},
		{"constructed octet string", "24800403616263040264650000", "04056162636465"},
		{"constructed octet string definite", "2409" + "0403616263" + "04026465", "04056162636465"},
		{"nested constructed octet string", "2480" + "2480" + "040161" + "0000" + "040162" + "0000", "04026162"},
		{"constructed octet string definite inside indefinite sequence",
			"3080" + "2480" + "040161" + "0000" + "0000", "3003040161"},
		{"constructed bit string", "2380" + "03020040" + "0302" + "0680" + "0000", "03030640c0"[0:0] + "0303064080"},
		{"constructed utf8", "2c80" + "0c0161" + "0c0162" + "0000", "0c026162"},
		{"long form length normalised", "30820006020105020101", "3006020105020101"},
		{"context tag constructed indefinite", "a080" + "020100" + "0000", "a003020100"},
		{"high tag number", "bf8100" + "80" + "0000", "bf810000"},
		{"long form content > 127", "3080" + "0481" + "80" + hex.EncodeToString(bytes.Repeat([]byte{1}, 128)) + "0000",
			"3081830481" + "80" + hex.EncodeToString(bytes.Repeat([]byte{1}, 128))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Normalize(mustHex(t, c.in))
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if want := mustHex(t, c.want); !bytes.Equal(got, want) {
				t.Fatalf("got %x want %x", got, want)
			}
			// DER is a fixed point.
			again, err := Normalize(got)
			if err != nil || !bytes.Equal(again, got) {
				t.Fatalf("not idempotent: %x -> %x (%v)", got, again, err)
			}
			var raw asn1.RawValue
			rest, err := asn1.Unmarshal(got, &raw)
			if err != nil || len(rest) != 0 {
				t.Fatalf("encoding/asn1 rejects output: %v (rest %d)", err, len(rest))
			}
		})
	}
}

func TestNormalizeRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrTruncated},
		{"truncated header", "30", ErrTruncated},
		{"truncated content", "3004020105", ErrTruncated},
		{"content beyond length", "02050102", ErrTruncated},
		{"indefinite primitive", "0480616200" + "00", ErrIndefinitePrimitive},
		{"missing EOC", "3080020105", ErrMissingEOC},
		{"half EOC", "308002010500", ErrMissingEOC},
		{"bad EOC length", "3080020105" + "0001", ErrLength},
		{"EOC in definite", "30020000", ErrUnexpectedEOC},
		{"reserved length 0xff", "30ff", ErrLength},
		{"five length octets", "3085000000000130", ErrLength},
		{"oversized long length", "3084ffffffff", ErrTruncated},
		{"trailing data", "300000", ErrTrailingData},
		{"tag number zero in high form", "1f00" + "00", ErrTag},
		{"low tag in high form", "1f1e00", ErrTag},
		{"tag number over 32 bits", "1fffffffff7f00", ErrTag},
		{"tag number over 2^31-1", "ff8beec3d63000", ErrTag},
		{"six tag digits", "1f8080808080" + "0000", ErrTag},
		{"constructed octet string with foreign segment", "2480" + "020105" + "0000", ErrConstructedString},
		{"constructed bit string unused bits in non-final", "2380" + "03020140" + "03020080" + "0000", ErrConstructedString},
		{"constructed bit string empty segment", "2380" + "0300" + "0000", ErrConstructedString},
		{"constructed bit string unused > 7", "2380" + "03020840" + "0000", ErrConstructedString},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Normalize(mustHex(t, c.in))
			if err == nil {
				t.Fatalf("accepted %x as %x", mustHex(t, c.in), got)
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v want %v", err, c.want)
			}
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("not a *SyntaxError: %T", err)
			}
		})
	}
}

func TestNormalizeDepth(t *testing.T) {
	// MaxDepth nested indefinite SEQUENCEs are accepted, one more is not.
	build := func(n int) []byte {
		var b []byte
		for i := 0; i < n; i++ {
			b = append(b, 0x30, 0x80)
		}
		b = append(b, 0x05, 0x00)
		for i := 0; i < n; i++ {
			b = append(b, 0, 0)
		}
		return b
	}
	if _, err := Normalize(build(MaxDepth)); err != nil {
		t.Fatalf("depth %d rejected: %v", MaxDepth, err)
	}
	_, err := Normalize(build(MaxDepth + 1))
	if !errors.Is(err, ErrDepth) {
		t.Fatalf("depth %d: got %v want ErrDepth", MaxDepth+1, err)
	}
}

func TestNormalizeOpenSSLStream(t *testing.T) {
	// Written by `openssl cms -encrypt -stream -outform DER`: indefinite-length
	// wrappers and a constructed OCTET STRING for the encrypted content.
	cases := []struct {
		file        string
		contentType asn1.ObjectIdentifier
	}{
		{"openssl-stream-envelopeddata.ber", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}},
		{"openssl-stream-authenvelopeddata.ber", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			in, err := os.ReadFile("testdata/" + c.file)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(in, []byte{0x30, 0x80}) {
				t.Fatalf("fixture is not indefinite-length BER: % x", in[:4])
			}
			der, err := Normalize(in)
			if err != nil {
				t.Fatal(err)
			}
			var ci struct {
				ContentType asn1.ObjectIdentifier
				Content     asn1.RawValue `asn1:"explicit,tag:0"`
			}
			rest, err := asn1.Unmarshal(der, &ci)
			if err != nil || len(rest) != 0 {
				t.Fatalf("ContentInfo: %v (rest %d)", err, len(rest))
			}
			if !ci.ContentType.Equal(c.contentType) {
				t.Fatalf("content type %v", ci.ContentType)
			}
			// EnvelopedData and AuthEnvelopedData share this prefix.
			var ed struct {
				Version        int
				RecipientInfos asn1.RawValue `asn1:"set"`
				Eci            struct {
					ContentType asn1.ObjectIdentifier
					Alg         asn1.RawValue
					Encrypted   asn1.RawValue `asn1:"optional,tag:0"`
				}
				Rest asn1.RawValue `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
				t.Fatalf("EnvelopedData: %v", err)
			}
			// encryptedContent is [0] IMPLICIT OCTET STRING; the streaming
			// writer leaves it constructed and the schema-aware caller joins it.
			if !ed.Eci.Encrypted.IsCompound {
				t.Fatalf("expected a constructed encryptedContent from the streaming writer")
			}
			joined, err := JoinOctetStrings(ed.Eci.Encrypted.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if len(joined) < 8000 {
				t.Fatalf("encrypted content %d bytes; expected the whole joined stream", len(joined))
			}
		})
	}
}

func TestJoinOctetStrings(t *testing.T) {
	good := []struct{ in, want string }{
		{"", ""},
		{"040161", "61"},
		{"040161" + "04026263", "616263"},
		{"2403040161" + "040162", "6162"},
		{"0400", ""},
	}
	for _, c := range good {
		got, err := JoinOctetStrings(mustHex(t, c.in))
		if err != nil || !bytes.Equal(got, mustHex(t, c.want)) {
			t.Errorf("%s: got %x, %v; want %s", c.in, got, err, c.want)
		}
	}
	bad := []string{"020105", "0c0161", "2480040161" + "0000", "0405aa", "04", "2402" + "020100"}
	for _, in := range bad {
		if got, err := JoinOctetStrings(mustHex(t, in)); err == nil {
			t.Errorf("%s accepted as %x", in, got)
		} else if !errors.Is(err, ErrConstructedString) && !errors.Is(err, ErrTruncated) {
			t.Errorf("%s: unexpected error %v", in, err)
		}
	}
}

func TestSortSetOf(t *testing.T) {
	in := [][]byte{{0x04, 0x01, 0x02}, {0x02, 0x01, 0x05}, {0x04, 0x01, 0x01}, {0x04, 0x01, 0x01, 0x00}, {0x04, 0x01}}
	got := SortSetOf(in)
	want := [][]byte{{0x02, 0x01, 0x05}, {0x04, 0x01}, {0x04, 0x01, 0x01}, {0x04, 0x01, 0x01, 0x00}, {0x04, 0x01, 0x02}}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("position %d: got %x want %x", i, got[i], want[i])
		}
	}
	if compareSetOf([]byte{1, 0, 0}, []byte{1}) != 0 {
		t.Fatal("zero padding must compare equal")
	}
}
