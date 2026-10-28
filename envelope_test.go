package cryptomsg

import (
	"io"
	"math"
	"strings"

	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"github.com/Open-MBEE/cryptomsg/internal/ber"
	"testing"
)

func encryptBytes(t *testing.T, plaintext []byte, opts *EncryptOptions, recipients ...*x509.Certificate) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Encrypt(&out, bytes.NewReader(plaintext), recipients, opts); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return out.Bytes()
}

func decryptBytes(t *testing.T, envelope []byte, id *testIdentity, opts *DecryptOptions) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := Decrypt(&out, bytes.NewReader(envelope), id.Cert, id.Key, opts)
	return out.Bytes(), err
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	rsaID := sharedRSAIdentity(t, "rsa recipient")
	p256 := newECIdentity(t, "p256 recipient", elliptic.P256())
	p384 := newECIdentity(t, "p384 recipient", elliptic.P384())
	plaintext := bytes.Repeat([]byte("multi-megabyte archives are the use case; "), 50000) // ~2 MiB

	for _, c := range []struct {
		name string
		opts EncryptOptions
	}{
		{"AES-256-GCM IssuerAndSerial", EncryptOptions{}},
		{"AES-128-GCM IssuerAndSerial", EncryptOptions{Cipher: AES128GCM}},
		{"AES-256-GCM SubjectKeyID", EncryptOptions{RecipientIdentifier: SubjectKeyID}},
		{"AES-128-GCM SubjectKeyID", EncryptOptions{Cipher: AES128GCM, RecipientIdentifier: SubjectKeyID}},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := encryptBytes(t, plaintext, &c.opts, rsaID.Cert, p256.Cert, p384.Cert)
			if !bytes.HasPrefix(env, []byte{0x30, 0x82}) && !bytes.HasPrefix(env, []byte{0x30, 0x83}) {
				t.Fatalf("output is not a definite-length DER SEQUENCE")
			}
			for _, id := range []*testIdentity{rsaID, p256, p384} {
				got, err := decryptBytes(t, env, id, nil)
				if err != nil {
					t.Fatalf("%s: Decrypt: %v", id.Cert.Subject.CommonName, err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("%s: plaintext differs", id.Cert.Subject.CommonName)
				}
			}
			// The EC recipient also decrypts with the crypto/ecdh form of its key.
			ecdhKey, err := p256.Key.(*ecdsa.PrivateKey).ECDH()
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := Decrypt(&out, bytes.NewReader(env), p256.Cert, ecdhKey, nil); err != nil || !bytes.Equal(out.Bytes(), plaintext) {
				t.Fatalf("ecdh.PrivateKey: %v", err)
			}
			// Structure: AuthEnvelopedData with three RecipientInfos.
			parsed, err := parseEnvelope(env)
			if err != nil {
				t.Fatal(err)
			}
			if !parsed.Authenticated || len(parsed.Recipients) != 3 || len(parsed.MAC) != gcmTagSize {
				t.Fatalf("auth=%v recipients=%d mac=%d", parsed.Authenticated, len(parsed.Recipients), len(parsed.MAC))
			}
			wantOID := oidAES256GCM
			if c.opts.Cipher == AES128GCM {
				wantOID = oidAES128GCM
			}
			if !parsed.Cipher.Algorithm.Equal(wantOID) {
				t.Fatalf("cipher %v", parsed.Cipher.Algorithm)
			}
			for _, r := range parsed.Recipients {
				if r.ID.Kind != c.opts.RecipientIdentifier {
					t.Fatalf("recipient identifier %v, want %v", r.ID.Kind, c.opts.RecipientIdentifier)
				}
			}
		})
	}
}

func TestEncryptEmptyAndSmall(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	for _, pt := range [][]byte{{}, {0x00}, []byte("x")} {
		env := encryptBytes(t, pt, nil, id.Cert)
		got, err := decryptBytes(t, env, id, nil)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("len %d: %q, %v", len(pt), got, err)
		}
	}
}

func TestEncryptRefusals(t *testing.T) {
	var out bytes.Buffer
	if err := Encrypt(&out, bytes.NewReader(nil), nil, nil); err == nil {
		t.Fatal("no recipients accepted")
	}
	weak := newRSAIdentity(t, "rsa-1024", 1024)
	if err := Encrypt(&out, bytes.NewReader(nil), []*x509.Certificate{weak.Cert}, nil); !errors.Is(err, ErrKeyTooWeak) {
		t.Fatalf("RSA-1024: %v", err)
	}
	ed := newEd25519Identity(t, "ed25519")
	err := Encrypt(&out, bytes.NewReader(nil), []*x509.Certificate{ed.Cert}, nil)
	var ua *UnsupportedAlgorithmError
	if !errors.As(err, &ua) || !ua.OID.Equal(oidEd25519) {
		t.Fatalf("Ed25519 recipient: %v", err)
	}
	p521 := newECIdentity(t, "p521", elliptic.P521())
	if err := Encrypt(&out, bytes.NewReader(nil), []*x509.Certificate{p521.Cert}, nil); !errors.As(err, &ua) {
		t.Fatalf("P-521 recipient: %v", err)
	}
	noSKI := sharedRSAIdentity(t, "no ski")
	noSKI.Cert.SubjectKeyId = nil
	if err := Encrypt(&out, bytes.NewReader(nil), []*x509.Certificate{noSKI.Cert}, &EncryptOptions{RecipientIdentifier: SubjectKeyID}); err == nil {
		t.Fatal("SubjectKeyID without the extension accepted")
	}
	if out.Len() != 0 {
		t.Fatal("refusals must write nothing")
	}
}

func TestDecryptDuplicateRecipientAndMaxSize(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	plaintext := []byte("payload")
	// The same certificate twice: the first entry is spoiled (unknown KDF
	// scheme), the second must still decrypt.
	env := encryptBytes(t, plaintext, nil, id.Cert, id.Cert)
	from, _ := asn1.Marshal(oidDHSinglePassStdDHSHA256KDF)
	to, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 1, 11, 9})
	bad := bytes.Replace(env, from, to, 1)
	if got, err := decryptBytes(t, bad, id, nil); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("second RecipientInfo not used: %v", err)
	}
	both := bytes.ReplaceAll(env, from, to)
	if _, err := decryptBytes(t, both, id, nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("both spoiled: %v", err)
	}
	if _, err := decryptBytes(t, env, id, &DecryptOptions{MaxSize: int64(len(env)) - 1}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("MaxSize: %v", err)
	}
	if got, err := decryptBytes(t, env, id, &DecryptOptions{MaxSize: int64(len(env))}); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("MaxSize exact: %v", err)
	}
}

func TestDecryptWrongRecipient(t *testing.T) {
	a := newECIdentity(t, "a", elliptic.P256())
	b := newECIdentity(t, "b", elliptic.P256())
	r := sharedRSAIdentity(t, "r")
	env := encryptBytes(t, []byte("secret"), nil, a.Cert)
	for _, id := range []*testIdentity{b, r} {
		out, err := decryptBytes(t, env, id, nil)
		if !errors.Is(err, ErrNoMatchingRecipient) || len(out) != 0 {
			t.Fatalf("%s: %q, %v", id.Cert.Subject.CommonName, out, err)
		}
	}
	// Right certificate, wrong key: the mismatch is detected before any
	// cryptography.
	var out bytes.Buffer
	if err := Decrypt(&out, bytes.NewReader(env), a.Cert, b.Key, nil); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("mismatched key: %v", err)
	}
	envR := encryptBytes(t, []byte("secret"), nil, r.Cert)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := Decrypt(&out, bytes.NewReader(envR), r.Cert, other, nil); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("mismatched RSA key: %v", err)
	}
	if err := Decrypt(&out, bytes.NewReader(envR), r.Cert, a.Key, nil); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("EC key for RSA recipient: %v", err)
	}
}

func TestDecryptTampered(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	rsaID := sharedRSAIdentity(t, "rsa")
	plaintext := bytes.Repeat([]byte("payload "), 512)
	env := encryptBytes(t, plaintext, nil, id.Cert, rsaID.Cert)
	parsed, err := parseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one bit in the ciphertext body and in the tag (every recipient
	// fails) and in each recipient's encrypted key (that recipient fails, the
	// other is unaffected).
	flipAt := func(name string, needle []byte, affected ...*testIdentity) {
		t.Helper()
		i := bytes.Index(env, needle)
		if i < 0 {
			t.Fatalf("%s not found in envelope", name)
		}
		bad := bytes.Clone(env)
		bad[i+len(needle)/2] ^= 0x01
		for _, who := range []*testIdentity{id, rsaID} {
			out, err := decryptBytes(t, bad, who, nil)
			isAffected := false
			for _, a := range affected {
				isAffected = isAffected || a == who
			}
			if !isAffected {
				if err != nil || !bytes.Equal(out, plaintext) {
					t.Fatalf("%s tampered, %s unaffected but got %v", name, who.Cert.Subject.CommonName, err)
				}
				continue
			}
			if err == nil || len(out) != 0 {
				t.Fatalf("%s tampered, %s: %v (%d bytes written)", name, who.Cert.Subject.CommonName, err, len(out))
			}
			if !errors.Is(err, ErrAuthenticationFailed) && !errors.Is(err, ErrMalformed) {
				t.Fatalf("%s tampered, %s: unexpected error %v", name, who.Cert.Subject.CommonName, err)
			}
		}
	}
	flipAt("ciphertext", parsed.Ciphertext, id, rsaID)
	flipAt("tag", parsed.MAC, id, rsaID)
	for _, r := range parsed.Recipients {
		if r.ktri != nil {
			flipAt("RSA encrypted key", r.ktri.EncryptedKey, rsaID)
		} else {
			flipAt("wrapped key", r.rek.EncryptedKey, id)
		}
	}
}

func TestDecryptAlgorithmSubstitution(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	rsaID := sharedRSAIdentity(t, "rsa")
	plaintext := []byte("payload")
	env := encryptBytes(t, plaintext, nil, id.Cert, rsaID.Cert)
	// substitute swaps one OID for an equal-length one and checks that every
	// affected recipient is refused with wantErr while the others still
	// decrypt.
	substitute := func(from, to asn1.ObjectIdentifier, wantErr error, affected ...*testIdentity) {
		t.Helper()
		fromDER, _ := asn1.Marshal(from)
		toDER, _ := asn1.Marshal(to)
		if len(fromDER) != len(toDER) {
			t.Fatalf("test needs equal-length OIDs: %v %v", from, to)
		}
		if !bytes.Contains(env, fromDER) {
			t.Fatalf("%v not in envelope", from)
		}
		bad := bytes.Replace(env, fromDER, toDER, 1)
		for _, who := range []*testIdentity{id, rsaID} {
			out, err := decryptBytes(t, bad, who, nil)
			isAffected := false
			for _, a := range affected {
				isAffected = isAffected || a == who
			}
			switch {
			case !isAffected && (err != nil || !bytes.Equal(out, plaintext)):
				t.Fatalf("%v→%v, %s unaffected but got %v", from, to, who.Cert.Subject.CommonName, err)
			case isAffected && (err == nil || len(out) != 0):
				t.Fatalf("%v→%v, %s: accepted", from, to, who.Cert.Subject.CommonName)
			case isAffected && !errors.Is(err, wantErr):
				t.Fatalf("%v→%v, %s: %v, want %v", from, to, who.Cert.Subject.CommonName, err, wantErr)
			}
		}
	}
	// Content cipher AES-256-GCM → AES-128-GCM: the 32-byte key no longer fits.
	substitute(oidAES256GCM, oidAES128GCM, ErrMalformed, id, rsaID)
	// Content cipher → AES-256-CBC: refused (and CBC is never authenticated).
	substitute(oidAES256GCM, oidAES256CBC, ErrUnsupportedAlgorithm, id, rsaID)
	// Key wrap AES-256 → AES-128: the KEK length changes and the unwrap fails.
	substitute(oidAES256Wrap, oidAES128Wrap, ErrAuthenticationFailed, id)
	// Key agreement scheme SHA-256 → SHA-384: not the curve's suite.
	substitute(oidDHSinglePassStdDHSHA256KDF, oidDHSinglePassStdDHSHA384KDF, ErrUnsupportedAlgorithm, id)
	// OAEP hash SHA-256 → SHA-384 (first occurrence is in the RSA recipient).
	substitute(oidSHA256, oidSHA384, ErrUnsupportedAlgorithm, rsaID)
}

func TestDecryptMalformed(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	env := encryptBytes(t, []byte("payload"), nil, id.Cert)
	cases := map[string][]byte{
		"empty":            {},
		"truncated":        env[:len(env)/2],
		"trailing":         append(bytes.Clone(env), 0),
		"not CMS":          {0x30, 0x03, 0x02, 0x01, 0x05},
		"deep nesting":     bytes.Repeat([]byte{0x30, 0x80}, 100),
		"oversized length": {0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := decryptBytes(t, in, id, nil)
			if !errors.Is(err, ErrMalformed) || len(out) != 0 {
				t.Fatalf("%v (%d bytes written)", err, len(out))
			}
		})
	}
	// SignedData ContentInfo handed to Decrypt.
	sd, _ := encodeContentInfo(oidSignedData, []byte{0x30, 0x00})
	if _, err := decryptBytes(t, sd, id, nil); !errors.Is(err, ErrUnsupportedStructure) {
		t.Fatalf("SignedData: %v", err)
	}
}

func TestDecryptStreamedBERFixtures(t *testing.T) {
	// The committed OpenSSL fixtures were made for a throwaway key, so they
	// cannot be decrypted; they must still parse into the key-free view.
	for _, f := range []string{"internal/ber/testdata/openssl-stream-envelopeddata.ber", "internal/ber/testdata/openssl-stream-authenvelopeddata.ber"} {
		raw := readFile(t, f)
		der, err := normalizeInput(raw)
		if err != nil {
			t.Fatal(err)
		}
		env, err := parseEnvelope(der)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(env.Recipients) != 1 || env.Recipients[0].ktri == nil || !env.Recipients[0].Alg.Equal(oidRSAESOAEP) {
			t.Fatalf("%s: recipients %+v", f, env.Recipients)
		}
		if len(env.Ciphertext) < 8000 {
			t.Fatalf("%s: ciphertext %d bytes", f, len(env.Ciphertext))
		}
		id := newECIdentity(t, "stranger", elliptic.P256())
		if _, err := decryptBytes(t, raw, id, nil); !errors.Is(err, ErrNoMatchingRecipient) {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func TestUnpadPKCS7(t *testing.T) {
	good := [][]byte{append(bytes.Repeat([]byte{1}, 15), 1), bytes.Repeat([]byte{16}, 16), append([]byte("abc"), bytes.Repeat([]byte{13}, 13)...)}
	for _, b := range good {
		if _, err := unpadPKCS7(b); err != nil {
			t.Errorf("%x: %v", b, err)
		}
	}
	bad := [][]byte{{}, {0}, {17}, append(bytes.Repeat([]byte{2}, 14), 1, 2), bytes.Repeat([]byte{3}, 2)}
	for _, b := range bad {
		if _, err := unpadPKCS7(b); err == nil {
			t.Errorf("%x accepted", b)
		}
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	n, _ := w.Buffer.Write(p[:len(p)/2])
	return n, nil
}

func TestShortWritesAreErrors(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	var sw shortWriter
	if err := Encrypt(&sw, bytes.NewReader([]byte("payload")), []*x509.Certificate{id.Cert}, nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Encrypt: %v", err)
	}
	env := encryptBytes(t, []byte("payload"), nil, id.Cert)
	sw.Reset()
	if err := Decrypt(&sw, bytes.NewReader(env), id.Cert, id.Key, nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Decrypt: %v", err)
	}
}

func TestDecryptMaxSizeAtMaxInt64(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	plaintext := []byte("payload")
	env := encryptBytes(t, plaintext, nil, id.Cert)
	if got, err := decryptBytes(t, env, id, &DecryptOptions{MaxSize: math.MaxInt64}); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("MaxSize MaxInt64: %v", err)
	}
}

func TestDecryptRefusesNonDataContentType(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	env := encryptBytes(t, []byte("payload"), nil, id.Cert)
	from, _ := asn1.Marshal(oidData)
	to, _ := asn1.Marshal(oidSignedData)
	bad := bytes.Replace(env, from, to, 1)
	if bytes.Equal(bad, env) {
		t.Fatal("id-data not found in envelope")
	}
	if _, err := decryptBytes(t, bad, id, nil); !errors.Is(err, ErrUnsupportedStructure) {
		t.Fatalf("got %v, want ErrUnsupportedStructure", err)
	}
}

// withAuthAttrs re-encodes an AuthEnvelopedData with the given authAttrs
// members (concatenated DER Attribute values).
func withAuthAttrs(t *testing.T, env, members []byte) []byte {
	t.Helper()
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(env, &ci); err != nil {
		t.Fatal(err)
	}
	var aed authEnvelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &aed); err != nil {
		t.Fatal(err)
	}
	aed.AuthAttrs = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: members}
	body, err := asn1.Marshal(aed)
	if err != nil {
		t.Fatal(err)
	}
	out, err := encodeContentInfo(oidAuthEnvelopedData, body)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func attributeDER(t *testing.T, typ asn1.ObjectIdentifier, value any) []byte {
	t.Helper()
	v, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	b, err := asn1.Marshal(struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}{typ, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: v}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecryptAuthAttrsContentType(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	env := encryptBytes(t, []byte("payload"), nil, id.Cert)
	other := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	cases := []struct {
		name    string
		members []byte
		want    string
	}{
		{"wrong content type", attributeDER(t, oidAttrContentType, oidSignedData), "does not name"},
		{"no content type", attributeDER(t, other, []byte{1}), "0 content-type attributes"},
		{"two content types", append(attributeDER(t, oidAttrContentType, oidData), attributeDER(t, oidAttrContentType, oidData)...), "2 content-type attributes"},
		// Well-formed attributes pass the check; the tag then fails because
		// the message was not sealed over them.
		{"unauthenticated attributes", attributeDER(t, oidAttrContentType, oidData), "cryptomsg: authentication failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decryptBytes(t, withAuthAttrs(t, env, c.members), id, nil)
			if !errors.Is(err, ErrAuthenticationFailed) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want ErrAuthenticationFailed mentioning %q", err, c.want)
			}
		})
	}
}

func TestAuthAttrsAADIsSorted(t *testing.T) {
	a := attributeDER(t, oidAttrContentType, oidData)
	b := attributeDER(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}, []byte{1})
	sorted := make([]byte, 0, len(a)+len(b))
	for _, e := range ber.SortSetOf([][]byte{a, b}) {
		sorted = append(sorted, e...)
	}
	want, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: sorted})
	for _, members := range [][]byte{append(append([]byte{}, a...), b...), append(append([]byte{}, b...), a...)} {
		got, err := authAttrsAAD(asn1.RawValue{FullBytes: []byte{0xa1}, Bytes: members})
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("AAD not in SET OF order: %x %v", got, err)
		}
	}
}
