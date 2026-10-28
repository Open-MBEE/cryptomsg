package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type identity struct {
	cert, key string
	c         *x509.Certificate
}

var serial int64 = 100

func makeIdentity(t *testing.T, dir, name string, key any, pub any, parent *identity, parentKey any, isCA bool) *identity {
	t.Helper()
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, SubjectKeyId: []byte{byte(serial)},
		BasicConstraintsValid: true, IsCA: isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	parentCert, signer := tmpl, key
	if parent != nil {
		parentCert, signer = parent.c, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	id := &identity{cert: filepath.Join(dir, name+".crt"), key: filepath.Join(dir, name+".key"), c: cert}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(id.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(id.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return id
}

func TestCLI(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := makeIdentity(t, dir, "ca", caKey, &caKey.PublicKey, nil, nil, true)
	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := makeIdentity(t, dir, "signer", signerKey, &signerKey.PublicKey, ca, caKey, false)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaID := makeIdentity(t, dir, "rsa", rsaKey, &rsaKey.PublicKey, nil, nil, false)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecID := makeIdentity(t, dir, "ec", ecKey, &ecKey.PublicKey, nil, nil, false)

	plain := filepath.Join(dir, "plain.bin")
	payload := bytes.Repeat([]byte("cli payload "), 5000)
	os.WriteFile(plain, payload, 0o600)
	envelope := filepath.Join(dir, "env.der")
	sig := filepath.Join(dir, "sig.der")

	exec := func(want int, args ...string) (string, string) {
		t.Helper()
		var out, errb bytes.Buffer
		code := run(args, strings.NewReader(""), &out, &errb)
		if code != want {
			t.Fatalf("%v: exit %d, want %d\nstdout: %s\nstderr: %s", args, code, want, out.String(), errb.String())
		}
		return out.String(), errb.String()
	}

	exec(0, "encrypt", "-recipient", rsaID.cert, "-recipient", ecID.cert, "-keyid", "-in", plain, "-out", envelope)
	for _, id := range []*identity{rsaID, ecID} {
		out := filepath.Join(dir, "out.bin")
		exec(0, "decrypt", "-cert", id.cert, "-key", id.key, "-in", envelope, "-out", out)
		got, _ := os.ReadFile(out)
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s: plaintext differs", id.cert)
		}
	}
	// Stranger: refused with exit 2 and nothing written.
	_, stderr := exec(2, "decrypt", "-cert", signer.cert, "-key", signer.key, "-in", envelope, "-out", filepath.Join(dir, "none.bin"))
	if !strings.Contains(stderr, "no RecipientInfo") {
		t.Fatalf("stderr %q", stderr)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "none.bin")); len(b) != 0 {
		t.Fatal("plaintext written on refusal")
	}

	stdout, _ := exec(0, "inspect", "-in", envelope)
	if !strings.Contains(stdout, "type: AuthEnvelopedData") || !strings.Contains(stdout, "recipients: 2") || !strings.Contains(stdout, "ski=") {
		t.Fatalf("inspect:\n%s", stdout)
	}

	exec(0, "sign", "-cert", signer.cert, "-key", signer.key, "-in", envelope, "-out", sig)
	stdout, _ = exec(0, "verify", "-root", ca.cert, "-content", envelope, "-in", sig, "-eku", "emailProtection")
	if !strings.Contains(stdout, "verified: CN=signer") || !strings.Contains(stdout, "chain[1]: CN=ca") {
		t.Fatalf("verify:\n%s", stdout)
	}
	// Wrong root, wrong EKU, altered content, future time: all exit 2.
	exec(2, "verify", "-root", rsaID.cert, "-content", envelope, "-in", sig)
	exec(2, "verify", "-root", ca.cert, "-content", envelope, "-in", sig, "-eku", "codeSigning")
	exec(2, "verify", "-root", ca.cert, "-content", plain, "-in", sig)
	exec(2, "verify", "-root", ca.cert, "-content", envelope, "-in", sig, "-time", time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339))
	// Detached signature without content.
	exec(2, "verify", "-root", ca.cert, "-in", sig)

	stdout, _ = exec(0, "inspect", "-in", sig)
	if !strings.Contains(stdout, "type: SignedData") || !strings.Contains(stdout, "content: detached") || !strings.Contains(stdout, "CN=signer") {
		t.Fatalf("inspect:\n%s", stdout)
	}

	// Attached signature verifies without -content.
	exec(0, "sign", "-cert", signer.cert, "-key", signer.key, "-attached", "-in", plain, "-out", sig)
	exec(0, "verify", "-root", ca.cert, "-in", sig)

	// Usage errors exit 1.
	exec(1, "encrypt", "-in", plain)
	exec(1, "decrypt", "-in", envelope)
	exec(1, "verify", "-in", sig)
	exec(1, "verify", "-root", ca.cert, "-in", sig, "-eku", "bogus")
	exec(1, "encrypt", "-recipient")
	exec(1, "verify", "-no-such-flag")
	exec(1, "bogus")
	exec(1)
}
