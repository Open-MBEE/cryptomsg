package cryptomsg

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"
)

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
