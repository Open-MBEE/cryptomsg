package cryptomsg

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"
)

func mustMarshalOID(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	b, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse(t *testing.T) {
	rsaID := sharedRSAIdentity(t, "rsa")
	p256 := newECIdentity(t, "p256", elliptic.P256())
	content := []byte("payload")

	env := encryptBytes(t, content, &EncryptOptions{RecipientIdentifier: SubjectKeyID}, rsaID.Cert, p256.Cert)
	info, err := Parse(bytes.NewReader(env))
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != KindAuthEnvelopedData || len(info.Recipients) != 2 || !info.ContentEncryption.Equal(oidAES256GCM) || info.EncryptedSize != len(content) {
		t.Fatalf("%+v", info)
	}
	for _, r := range info.Recipients {
		if r.Identifier != SubjectKeyID || !r.Supported || r.Description == "" {
			t.Fatalf("%+v", r)
		}
	}
	if !info.Recipients[0].KeyAlgorithm.Equal(oidRSAESOAEP) || !info.Recipients[1].KeyAlgorithm.Equal(oidDHSinglePassStdDHSHA256KDF) {
		t.Fatalf("%+v", info.Recipients)
	}

	sig, err := Sign(bytes.NewReader(content), p256.Key, []*x509.Certificate{p256.Cert}, nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err = Parse(bytes.NewReader(sig))
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != KindSignedData || !info.Attached || len(info.Signers) != 1 || len(info.Certificates) != 1 {
		t.Fatalf("%+v", info)
	}
	s := info.Signers[0]
	if s.Certificate == nil || s.Certificate.Subject.CommonName != "p256" || !s.HasSignedAttributes || !s.SignatureAlgorithm.Equal(oidECDSAWithSHA256) || !s.DigestAlgorithm.Equal(oidSHA256) {
		t.Fatalf("%+v", s)
	}

	// Recipients whose parameters Decrypt would refuse are reported unsupported.
	sha1OAEP := bytes.Replace(env, mustMarshalOID(t, oidSHA256), mustMarshalOID(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}), 1)
	info, err = Parse(bytes.NewReader(sha1OAEP))
	if err != nil {
		t.Fatalf("OAEP SHA-384 recipient: %v", err)
	}
	if info.Recipients[0].Supported || !info.Recipients[1].Supported {
		t.Fatalf("OAEP SHA-384 recipient: %+v", info.Recipients)
	}
	badKDF := bytes.Replace(env, mustMarshalOID(t, oidDHSinglePassStdDHSHA256KDF), mustMarshalOID(t, asn1.ObjectIdentifier{1, 3, 132, 1, 11, 9}), 1)
	info, err = Parse(bytes.NewReader(badKDF))
	if err != nil {
		t.Fatalf("unknown KDF scheme recipient: %v", err)
	}
	if !info.Recipients[0].Supported || info.Recipients[1].Supported {
		t.Fatalf("unknown KDF scheme recipient: %+v", info.Recipients)
	}

	// OpenSSL streamed BER fixture, and a non-CMS object.
	info, err = Parse(bytes.NewReader(readFile(t, "internal/ber/testdata/openssl-stream-envelopeddata.ber")))
	if err != nil || info.Kind != KindEnvelopedData || !info.ContentEncryption.Equal(oidAES256CBC) || len(info.Recipients) != 1 {
		t.Fatalf("%+v, %v", info, err)
	}
	if _, err := Parse(bytes.NewReader([]byte{0x30, 0x00})); !errors.Is(err, ErrMalformed) {
		t.Fatalf("%v", err)
	}
	other, _ := encodeContentInfo(oidData, []byte{0x04, 0x00})
	if _, err := Parse(bytes.NewReader(other)); !errors.Is(err, ErrUnsupportedStructure) {
		t.Fatalf("%v", err)
	}
}

func TestParseNamesSignerAmongSameKeyCertificates(t *testing.T) {
	id := newECIdentity(t, "p256", elliptic.P256())
	renewed := newIdentity(t, "renewed", id.Key)
	content := []byte("content")
	for _, pair := range [][2]*testIdentity{{id, renewed}, {renewed, id}} {
		signer, other := pair[0], pair[1]
		sig, err := Sign(bytes.NewReader(content), signer.Key, []*x509.Certificate{signer.Cert, other.Cert}, &SignOptions{Detached: true, SignerIdentifier: SubjectKeyID})
		if err != nil {
			t.Fatal(err)
		}
		info, err := Parse(bytes.NewReader(sig))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Signers[0].Certificate; got == nil || !got.Equal(signer.Cert) {
			t.Fatalf("%s: inspection named %v", signer.Cert.Subject.CommonName, got)
		}
	}
}
