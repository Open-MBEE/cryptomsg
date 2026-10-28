package cryptomsg

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"github.com/Open-MBEE/cryptomsg/internal/ber"
	"io"
	"testing"
	"time"
)

func signBytesHelper(t *testing.T, content []byte, id *testIdentity, opts *SignOptions) []byte {
	t.Helper()
	sig, err := Sign(bytes.NewReader(content), id.Key, []*x509.Certificate{id.Cert}, opts)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sig
}

func verifyHelper(t *testing.T, sig []byte, content io.Reader, extra ...*x509.Certificate) ([]*VerifiedSignature, error) {
	t.Helper()
	der, err := normalizeInput(sig)
	if err != nil {
		return nil, err
	}
	msg, err := parseSignedData(der)
	if err != nil {
		return nil, err
	}
	return verifySigners(msg, content, extra)
}

func signerIdentities(t *testing.T) []*testIdentity {
	return []*testIdentity{
		newECIdentity(t, "p256 signer", elliptic.P256()),
		newECIdentity(t, "p384 signer", elliptic.P384()),
		sharedRSAIdentity(t, "rsa signer"),
		newEd25519Identity(t, "ed25519 signer"),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	content := bytes.Repeat([]byte("signed content\n"), 10000)
	when := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	for _, id := range signerIdentities(t) {
		for _, detached := range []bool{true, false} {
			for _, sid := range []RecipientIdentifierKind{IssuerAndSerial, SubjectKeyID} {
				name := id.Cert.Subject.CommonName
				if detached {
					name += " detached"
				}
				t.Run(name+" "+sid.String(), func(t *testing.T) {
					sig := signBytesHelper(t, content, id, &SignOptions{Detached: detached, SigningTime: when, SignerIdentifier: sid})
					var reader io.Reader
					if detached {
						reader = bytes.NewReader(content)
					}
					got, err := verifyHelper(t, sig, reader)
					if err != nil {
						t.Fatalf("verify: %v", err)
					}
					if len(got) != 1 || !got[0].Signer.Equal(id.Cert) || !got[0].SigningTime.Equal(when) || !got[0].ContentType.Equal(oidData) {
						t.Fatalf("verified %+v", got)
					}
					msg, _ := parseSignedData(mustNormalize(t, sig))
					if msg.Attached != !detached {
						t.Fatalf("attached=%v", msg.Attached)
					}
					if detached {
						if _, err := verifyHelper(t, sig, nil); !errors.Is(err, ErrDetachedContentRequired) {
							t.Fatalf("detached without content: %v", err)
						}
					} else {
						if _, err := verifyHelper(t, sig, bytes.NewReader(content)); !errors.Is(err, ErrContentMismatch) {
							t.Fatalf("attached with content: %v", err)
						}
						if !bytes.Equal(msg.Content, content) {
							t.Fatal("embedded content differs")
						}
					}
					// Determinism of the structure: a second signature at the
					// same time differs only in the signature value for the
					// randomised schemes, never in the attributes.
					sig2 := signBytesHelper(t, content, id, &SignOptions{Detached: detached, SigningTime: when, SignerIdentifier: sid})
					m1, _ := parseSignedData(mustNormalize(t, sig))
					m2, _ := parseSignedData(mustNormalize(t, sig2))
					if !bytes.Equal(m1.Signers[0].SignedAttrs.FullBytes, m2.Signers[0].SignedAttrs.FullBytes) {
						t.Fatal("signed attributes differ between runs")
					}
				})
			}
		}
	}
}

func TestSignRefusals(t *testing.T) {
	content := []byte("c")
	weak := newRSAIdentity(t, "rsa-1024", 1024)
	if _, err := Sign(bytes.NewReader(content), weak.Key, []*x509.Certificate{weak.Cert}, nil); !errors.Is(err, ErrKeyTooWeak) {
		t.Fatalf("RSA-1024: %v", err)
	}
	p521 := newECIdentity(t, "p521", elliptic.P521())
	var ua *UnsupportedAlgorithmError
	if _, err := Sign(bytes.NewReader(content), p521.Key, []*x509.Certificate{p521.Cert}, nil); !errors.As(err, &ua) {
		t.Fatalf("P-521: %v", err)
	}
	a := newECIdentity(t, "a", elliptic.P256())
	b := newECIdentity(t, "b", elliptic.P256())
	if _, err := Sign(bytes.NewReader(content), a.Key, []*x509.Certificate{b.Cert}, nil); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("key/cert mismatch: %v", err)
	}
	if _, err := Sign(bytes.NewReader(content), a.Key, nil, nil); err == nil {
		t.Fatal("no chain accepted")
	}
}

func TestVerifyTamperedContentAndSignature(t *testing.T) {
	content := []byte("the quick brown fox")
	for _, id := range signerIdentities(t) {
		t.Run(id.Cert.Subject.CommonName, func(t *testing.T) {
			sig := signBytesHelper(t, content, id, &SignOptions{Detached: true})
			// Content altered.
			if _, err := verifyHelper(t, sig, bytes.NewReader([]byte("the quick brown fix"))); !errors.Is(err, ErrSignatureInvalid) {
				t.Fatalf("altered content: %v", err)
			}
			// Signature value altered.
			msg, _ := parseSignedData(mustNormalize(t, sig))
			i := bytes.Index(sig, msg.Signers[0].Signature)
			bad := bytes.Clone(sig)
			bad[i+len(msg.Signers[0].Signature)/2] ^= 0x40
			if _, err := verifyHelper(t, bad, bytes.NewReader(content)); !errors.Is(err, ErrSignatureInvalid) {
				t.Fatalf("altered signature: %v", err)
			}
			// Signing time altered inside the signed attributes.
			j := bytes.Index(sig, []byte{0x17, 0x0d}) // UTCTime
			if j < 0 {
				t.Fatal("UTCTime not found")
			}
			bad = bytes.Clone(sig)
			bad[j+2] ^= 0x01
			if _, err := verifyHelper(t, bad, bytes.NewReader(content)); !errors.Is(err, ErrSignatureInvalid) {
				t.Fatalf("altered signing time: %v", err)
			}
			// Attached content altered.
			att := signBytesHelper(t, content, id, nil)
			k := bytes.Index(att, content)
			bad = bytes.Clone(att)
			bad[k] ^= 0x01
			if _, err := verifyHelper(t, bad, nil); !errors.Is(err, ErrSignatureInvalid) {
				t.Fatalf("altered attached content: %v", err)
			}
		})
	}
}

// TestVerifyStrippedAttribute removes each mandatory attribute (re-signing
// the rest, as an attacker with the key could not, but a buggy producer
// would) and expects the typed refusal.
func TestVerifyStrippedAttribute(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	content := []byte("content")
	sig := signBytesHelper(t, content, id, &SignOptions{Detached: true})
	msg, _ := parseSignedData(mustNormalize(t, sig))
	attrsRaw := msg.Signers[0].SignedAttrs
	var attrs []attribute
	setDER, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: attrsRaw.Bytes})
	if _, err := asn1.UnmarshalWithParams(setDER, &attrs, "set"); err != nil {
		t.Fatal(err)
	}
	if len(attrs) != 4 {
		t.Fatalf("%d signed attributes", len(attrs))
	}
	for drop := range attrs {
		var keep []byte
		for i, a := range attrs {
			if i == drop {
				continue
			}
			b, _ := asn1.Marshal(a)
			keep = append(keep, b...)
		}
		newSet := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: keep}
		bad := rebuildWithSignedAttrs(t, sig, newSet)
		_, err := verifyHelper(t, bad, bytes.NewReader(content))
		if !errors.Is(err, ErrMissingSignedAttribute) {
			t.Fatalf("dropped %v: %v", attrs[drop].Type, err)
		}
	}
	// No signed attributes at all.
	bad := rebuildWithSignedAttrs(t, sig, asn1.RawValue{})
	if _, err := verifyHelper(t, bad, bytes.NewReader(content)); !errors.Is(err, ErrMissingSignedAttribute) {
		t.Fatalf("no signedAttrs: %v", err)
	}
}

// rebuildWithSignedAttrs re-encodes a single-signer SignedData with the given
// signedAttrs element (signature left as is).
func rebuildWithSignedAttrs(t *testing.T, sig []byte, attrs asn1.RawValue) []byte {
	t.Helper()
	var ci contentInfo
	if _, err := asn1.Unmarshal(sig, &ci); err != nil {
		t.Fatal(err)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	sd.SignerInfos[0].SignedAttrs = attrs
	body, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	out, err := encodeContentInfo(oidSignedData, body)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifySignerCertificateSubstitution(t *testing.T) {
	// The ESSCertIDv2 binds the signer certificate: a SignedData whose
	// certificate set carries a different certificate with the same key is
	// refused even though the signature itself verifies under that key.
	id := newECIdentity(t, "p256", elliptic.P256())
	twin := newIdentity(t, "twin with same key", id.Key)
	content := []byte("content")
	sig, err := Sign(bytes.NewReader(content), id.Key, []*x509.Certificate{id.Cert}, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	// Replace the certificate; the sid (issuer+serial) must also point at the
	// twin for it to be found.
	var ci contentInfo
	if _, err := asn1.Unmarshal(sig, &ci); err != nil {
		t.Fatal(err)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: twin.Cert.Raw}
	sd.SignerInfos[0].Sid, _ = encodeRecipientID(twin.Cert, IssuerAndSerial, false)
	body, _ := asn1.Marshal(sd)
	bad, _ := encodeContentInfo(oidSignedData, body)
	_, err = verifyHelper(t, bad, bytes.NewReader(content))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("substituted certificate: %v", err)
	}
	// Certificate absent from the message and not supplied: typed refusal;
	// supplied through extra: verifies.
	sd.Certificates = asn1.RawValue{}
	sd.SignerInfos[0].Sid, _ = encodeRecipientID(id.Cert, IssuerAndSerial, false)
	body, _ = asn1.Marshal(sd)
	stripped, _ := encodeContentInfo(oidSignedData, body)
	if _, err := verifyHelper(t, stripped, bytes.NewReader(content)); !errors.Is(err, ErrSignerCertificateMissing) {
		t.Fatalf("no certificate: %v", err)
	}
	if _, err := verifyHelper(t, stripped, bytes.NewReader(content), id.Cert); err != nil {
		t.Fatalf("certificate supplied: %v", err)
	}
}

func TestVerifyAlgorithmSubstitution(t *testing.T) {
	content := []byte("content")
	p256 := newECIdentity(t, "p256", elliptic.P256())
	sig := signBytesHelper(t, content, p256, &SignOptions{Detached: true})
	// Swap the last occurrence only: that is the SignerInfo's, the earlier
	// ones sit inside the certificate, whose hash ESSCertIDv2 pins.
	swap := func(from, to asn1.ObjectIdentifier) []byte {
		f, _ := asn1.Marshal(from)
		d, _ := asn1.Marshal(to)
		i := bytes.LastIndex(sig, f)
		if len(f) != len(d) || i < 0 {
			t.Fatalf("cannot swap %v for %v", from, to)
		}
		out := append([]byte{}, sig...)
		copy(out[i:], d)
		return out
	}
	var ua *UnsupportedAlgorithmError
	if _, err := verifyHelper(t, swap(oidECDSAWithSHA256, oidECDSAWithSHA384), bytes.NewReader(content)); !errors.As(err, &ua) {
		t.Fatalf("signature algorithm swapped: %v", err)
	}
	if _, err := verifyHelper(t, swap(oidSHA256, oidSHA384), bytes.NewReader(content)); !errors.As(err, &ua) && !errors.Is(err, ErrMalformed) {
		t.Fatalf("digest algorithm swapped: %v", err)
	}
	rsaID := sharedRSAIdentity(t, "rsa")
	sig = signBytesHelper(t, content, rsaID, &SignOptions{Detached: true})
	if _, err := verifyHelper(t, swap(oidRSASSAPSS, oidRSAEncryption), bytes.NewReader(content)); !errors.As(err, &ua) || !ua.OID.Equal(oidRSAEncryption) {
		t.Fatalf("PKCS#1 v1.5 claimed: %v", err)
	}
	// Not a SignedData.
	env := encryptBytes(t, content, nil, p256.Cert)
	if _, err := verifyHelper(t, env, nil); !errors.Is(err, ErrUnsupportedStructure) {
		t.Fatalf("envelope as signature: %v", err)
	}
}

func TestSignCertificateSetInDEROrder(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	a := sharedRSAIdentity(t, "rsa")
	b := newECIdentity(t, "p384", elliptic.P384())
	content := []byte("content")
	var sets [][]byte
	for _, chain := range [][]*x509.Certificate{{id.Cert, a.Cert, b.Cert}, {id.Cert, b.Cert, a.Cert}} {
		sig, err := Sign(bytes.NewReader(content), id.Key, chain, &SignOptions{Detached: true})
		if err != nil {
			t.Fatal(err)
		}
		var ci contentInfo
		if _, err := asn1.Unmarshal(sig, &ci); err != nil {
			t.Fatal(err)
		}
		var sd signedData
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
			t.Fatal(err)
		}
		sets = append(sets, sd.Certificates.Bytes)
		if _, err := verifyHelper(t, sig, bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
	}
	var want []byte
	for _, r := range ber.SortSetOf([][]byte{id.Cert.Raw, a.Cert.Raw, b.Cert.Raw}) {
		want = append(want, r...)
	}
	for i, got := range sets {
		if !bytes.Equal(got, want) {
			t.Fatalf("chain order %d: CertificateSet not in DER order", i)
		}
	}
}

func TestVerifyRenewedCertificateSharingKeyIdentifier(t *testing.T) {
	// Two certificates with the same key share a SubjectKeyIdentifier; the
	// signed ESSCertIDv2 picks the signer among them whichever comes first.
	id := newECIdentity(t, "p256", elliptic.P256())
	renewed := newIdentity(t, "renewed", id.Key)
	if !bytes.Equal(id.Cert.SubjectKeyId, renewed.Cert.SubjectKeyId) {
		t.Fatal("test setup: key identifiers differ")
	}
	content := []byte("content")
	for _, pair := range [][2]*testIdentity{{id, renewed}, {renewed, id}} {
		signer, other := pair[0], pair[1]
		sig, err := Sign(bytes.NewReader(content), signer.Key, []*x509.Certificate{signer.Cert, other.Cert}, &SignOptions{Detached: true, SignerIdentifier: SubjectKeyID})
		if err != nil {
			t.Fatal(err)
		}
		got, err := verifyHelper(t, sig, bytes.NewReader(content))
		if err != nil {
			t.Fatalf("%s: %v", signer.Cert.Subject.CommonName, err)
		}
		if !got[0].Signer.Equal(signer.Cert) {
			t.Fatalf("%s: verified against %q", signer.Cert.Subject.CommonName, got[0].Signer.Subject.CommonName)
		}
	}
}

func TestCheckSigningCertificateUsesFirstEntry(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	twin := newIdentity(t, "twin", id.Key)
	hashOf := func(c *x509.Certificate) []byte {
		h := sha256.Sum256(c.Raw)
		return h[:]
	}
	attrs := &signedAttributes{signingCert: signingCertificateV2{Certs: []essCertIDv2{{CertHash: hashOf(twin.Cert)}, {CertHash: hashOf(id.Cert)}}}}
	if err := checkSigningCertificate(attrs, id.Cert); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("signer named second: %v", err)
	}
	attrs.signingCert.Certs[0], attrs.signingCert.Certs[1] = attrs.signingCert.Certs[1], attrs.signingCert.Certs[0]
	if err := checkSigningCertificate(attrs, id.Cert); err != nil {
		t.Fatalf("signer named first: %v", err)
	}
}
