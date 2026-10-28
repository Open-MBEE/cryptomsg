package cryptomsg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// testPKI is a root → intermediate → leaf hierarchy with a CRL per issuer.
type testPKI struct {
	Root, Intermediate, Leaf *testIdentity
	now                      time.Time
}

func issueCert(t *testing.T, tmpl *x509.Certificate, parent *testIdentity, key *ecdsa.PrivateKey) *testIdentity {
	t.Helper()
	testSerial++
	tmpl.SerialNumber = big.NewInt(testSerial)
	tmpl.SubjectKeyId = []byte{byte(testSerial >> 8), byte(testSerial)}
	parentCert, signerKey := tmpl, key
	if parent != nil {
		parentCert, signerKey = parent.Cert, parent.Key.(*ecdsa.PrivateKey)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testIdentity{Cert: cert, Key: key}
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	root := issueCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, key())
	inter := issueCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test Intermediate"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, root, key())
	leaf := issueCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test Signer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}, inter, key())
	return &testPKI{Root: root, Intermediate: inter, Leaf: leaf, now: now}
}

// crl issues a CRL from issuer listing the given serials, valid for a week.
func (p *testPKI) crl(t *testing.T, issuer *testIdentity, thisUpdate time.Time, revoked ...*x509.Certificate) *x509.RevocationList {
	t.Helper()
	tmpl := &x509.RevocationList{Number: big.NewInt(thisUpdate.Unix()), ThisUpdate: thisUpdate, NextUpdate: thisUpdate.Add(7 * 24 * time.Hour)}
	for _, c := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: thisUpdate})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer.Cert, issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

func (p *testPKI) policy() *Policy {
	roots := x509.NewCertPool()
	roots.AddCert(p.Root.Cert)
	return &Policy{Roots: roots, Time: p.now}
}

func TestVerifyPolicy(t *testing.T) {
	pki := newPKI(t)
	content := []byte("policy content")
	// Chain carried in the message.
	sig, err := Sign(bytes.NewReader(content), pki.Leaf.Key, []*x509.Certificate{pki.Leaf.Cert, pki.Intermediate.Cert}, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	// Leaf only in the message; intermediate from the policy.
	sigLeafOnly, err := Sign(bytes.NewReader(content), pki.Leaf.Key, []*x509.Certificate{pki.Leaf.Cert}, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	goodCRLs := []*x509.RevocationList{pki.crl(t, pki.Root, pki.now.Add(-time.Hour)), pki.crl(t, pki.Intermediate, pki.now.Add(-time.Hour))}

	t.Run("trusted", func(t *testing.T) {
		v, err := Verify(sig, bytes.NewReader(content), pki.policy())
		if err != nil {
			t.Fatal(err)
		}
		if len(v.Chain) != 3 || !v.Chain[0].Equal(pki.Leaf.Cert) || !v.Chain[2].Equal(pki.Root.Cert) {
			t.Fatalf("chain %v", v.Chain)
		}
	})
	t.Run("intermediate from policy", func(t *testing.T) {
		pol := pki.policy()
		if _, err := Verify(sigLeafOnly, bytes.NewReader(content), pol); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("without intermediate: %v", err)
		}
		pol.Intermediates = x509.NewCertPool()
		pol.Intermediates.AddCert(pki.Intermediate.Cert)
		if _, err := Verify(sigLeafOnly, bytes.NewReader(content), pol); err != nil {
			t.Fatalf("with intermediate: %v", err)
		}
	})
	t.Run("signer outside the trust store", func(t *testing.T) {
		other := newPKI(t)
		if _, err := Verify(sig, bytes.NewReader(content), other.policy()); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("%v", err)
		}
		self := newECIdentity(t, "self-signed", elliptic.P256())
		selfSig := signBytesHelper(t, content, self, &SignOptions{Detached: true})
		if _, err := Verify(selfSig, bytes.NewReader(content), pki.policy()); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("self-signed: %v", err)
		}
	})
	t.Run("no policy", func(t *testing.T) {
		for _, pol := range []*Policy{nil, {}} {
			if _, err := Verify(sig, bytes.NewReader(content), pol); !errors.Is(err, ErrUntrustedSigner) {
				t.Fatalf("%v", err)
			}
		}
	})
	t.Run("expired at evaluation time", func(t *testing.T) {
		pol := pki.policy()
		pol.Time = pki.Leaf.Cert.NotAfter.Add(time.Hour)
		if _, err := Verify(sig, bytes.NewReader(content), pol); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("after NotAfter: %v", err)
		}
		pol.Time = pki.Leaf.Cert.NotBefore.Add(-time.Hour)
		if _, err := Verify(sig, bytes.NewReader(content), pol); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("before NotBefore: %v", err)
		}
	})
	t.Run("EKU", func(t *testing.T) {
		pol := pki.policy()
		pol.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		if _, err := Verify(sig, bytes.NewReader(content), pol); err != nil {
			t.Fatalf("emailProtection: %v", err)
		}
		pol.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		if _, err := Verify(sig, bytes.NewReader(content), pol); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("codeSigning: %v", err)
		}
	})
	t.Run("CRL", func(t *testing.T) {
		pol := pki.policy()
		pol.CRLs = goodCRLs
		if _, err := Verify(sig, bytes.NewReader(content), pol); err != nil {
			t.Fatalf("clean CRLs: %v", err)
		}
		pol.RequireCRL = true
		if _, err := Verify(sig, bytes.NewReader(content), pol); err != nil {
			t.Fatalf("clean CRLs required: %v", err)
		}
		// Leaf revoked.
		pol.CRLs = []*x509.RevocationList{goodCRLs[0], pki.crl(t, pki.Intermediate, pki.now.Add(-time.Hour), pki.Leaf.Cert)}
		if _, err := Verify(sig, bytes.NewReader(content), pol); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("revoked leaf: %v", err)
		}
		// Intermediate revoked by the root.
		pol.CRLs = []*x509.RevocationList{pki.crl(t, pki.Root, pki.now.Add(-time.Hour), pki.Intermediate.Cert), goodCRLs[1]}
		if _, err := Verify(sig, bytes.NewReader(content), pol); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("revoked intermediate: %v", err)
		}
		// A CRL from a stranger naming the leaf is ignored (its signature
		// does not verify under the issuer).
		stranger := newPKI(t)
		fake := stranger.crl(t, stranger.Intermediate, pki.now.Add(-time.Hour), pki.Leaf.Cert)
		pol.CRLs = append([]*x509.RevocationList{fake}, goodCRLs...)
		if _, err := Verify(sig, bytes.NewReader(content), pol); err != nil {
			t.Fatalf("forged CRL: %v", err)
		}
		// Stale CRL.
		pol.CRLs = []*x509.RevocationList{goodCRLs[0], pki.crl(t, pki.Intermediate, pki.now.Add(-30*24*time.Hour))}
		if _, err := Verify(sig, bytes.NewReader(content), pol); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("stale CRL: %v", err)
		}
		pol.AllowStaleCRLs = true
		if _, err := Verify(sig, bytes.NewReader(content), pol); err != nil {
			t.Fatalf("stale CRL allowed: %v", err)
		}
		// A stale CRL listed before a current one does not block it, and a
		// current one revoking the leaf still wins over a stale clean one.
		pol.AllowStaleCRLs = false
		pol.CRLs = []*x509.RevocationList{pki.crl(t, pki.Intermediate, pki.now.Add(-30*24*time.Hour)), goodCRLs[0], goodCRLs[1]}
		if _, err := Verify(sig, bytes.NewReader(content), pol); err != nil {
			t.Fatalf("stale then current CRL: %v", err)
		}
		pol.CRLs = []*x509.RevocationList{pki.crl(t, pki.Intermediate, pki.now.Add(-30*24*time.Hour)), goodCRLs[0], pki.crl(t, pki.Intermediate, pki.now.Add(-time.Hour), pki.Leaf.Cert)}
		if _, err := Verify(sig, bytes.NewReader(content), pol); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("stale clean then current revoking CRL: %v", err)
		}
		// RequireCRL with no CRL for the leaf.
		pol.AllowStaleCRLs = false
		pol.CRLs = goodCRLs[:1]
		if _, err := Verify(sig, bytes.NewReader(content), pol); !errors.Is(err, ErrUntrustedSigner) {
			t.Fatalf("missing CRL required: %v", err)
		}
		pol.RequireCRL = false
		if _, err := Verify(sig, bytes.NewReader(content), pol); err != nil {
			t.Fatalf("missing CRL not required: %v", err)
		}
	})
	t.Run("signature failure beats policy", func(t *testing.T) {
		bad := bytes.Clone(sig)
		bad[len(bad)-5] ^= 0x01
		if _, err := Verify(bad, bytes.NewReader(content), pki.policy()); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("%v", err)
		}
	})
}

func TestVerifyEnvelopeSignedWorkflow(t *testing.T) {
	// The container use case: encrypt, sign the ciphertext detached, verify
	// against the trust store, then decrypt.
	pki := newPKI(t)
	recipient := newECIdentity(t, "recipient", elliptic.P384())
	payload := bytes.Repeat([]byte("zip bytes "), 100000)
	env := encryptBytes(t, payload, nil, recipient.Cert)
	sig, err := Sign(bytes.NewReader(env), pki.Leaf.Key, []*x509.Certificate{pki.Leaf.Cert, pki.Intermediate.Cert}, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(sig, bytes.NewReader(env), pki.policy())
	if err != nil {
		t.Fatal(err)
	}
	if v.Signer.Subject.CommonName != "Test Signer" {
		t.Fatalf("signer %s", v.Signer.Subject)
	}
	got, err := decryptBytes(t, env, recipient, nil)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("decrypt: %v", err)
	}
}

func TestVerifyIgnoresNilPolicyEntries(t *testing.T) {
	pki := newPKI(t)
	content := []byte("policy content")
	sig, err := Sign(bytes.NewReader(content), pki.Leaf.Key, []*x509.Certificate{pki.Leaf.Cert, pki.Intermediate.Cert}, &SignOptions{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	pol := pki.policy()
	pol.CRLs = []*x509.RevocationList{nil, pki.crl(t, pki.Root, pki.now.Add(-time.Hour)), nil, pki.crl(t, pki.Intermediate, pki.now.Add(-time.Hour))}
	pol.Certificates = []*x509.Certificate{nil}
	if _, err := Verify(sig, bytes.NewReader(content), pol); err != nil {
		t.Fatalf("nil CRL entries: %v", err)
	}
	revoking := pki.policy()
	revoking.CRLs = []*x509.RevocationList{nil, pki.crl(t, pki.Intermediate, pki.now.Add(-time.Hour), pki.Leaf.Cert)}
	if _, err := Verify(sig, bytes.NewReader(content), revoking); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("revocation behind a nil entry: %v", err)
	}
}
