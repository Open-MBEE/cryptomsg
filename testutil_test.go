package cryptomsg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testIdentity is a self-signed certificate with its key, for tests.
type testIdentity struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

var testSerial int64 = 1000

func newIdentity(t *testing.T, cn string, key crypto.Signer) *testIdentity {
	t.Helper()
	testSerial++
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	ski := sha1.Sum(pubDER)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(testSerial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"cryptomsg tests"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
		SubjectKeyId:          ski[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testIdentity{Cert: cert, Key: key}
}

func newRSAIdentity(t *testing.T, cn string, bits int) *testIdentity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return newIdentity(t, cn, key)
}

func newECIdentity(t *testing.T, cn string, curve elliptic.Curve) *testIdentity {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newIdentity(t, cn, key)
}

func newEd25519Identity(t *testing.T, cn string) *testIdentity {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newIdentity(t, cn, key)
}

// writePEM writes the identity's certificate and key to dir for OpenSSL.
func (id *testIdentity) writePEM(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.Cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(id.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// rsa2048 is shared across tests because key generation is slow.
var rsa2048 *rsa.PrivateKey

func sharedRSAIdentity(t *testing.T, cn string) *testIdentity {
	t.Helper()
	if rsa2048 == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rsa2048 = key
	}
	return newIdentity(t, cn, rsa2048)
}
