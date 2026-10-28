package cryptomsg

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type interopSigner struct {
	name    string
	id      *testIdentity
	keyopts []string
	md      string
}

func interopSigners(t *testing.T) []interopSigner {
	return []interopSigner{
		{"p256", newECIdentity(t, "p256 signer", elliptic.P256()), nil, "sha256"},
		{"p384", newECIdentity(t, "p384 signer", elliptic.P384()), nil, "sha384"},
		{"rsa-pss", sharedRSAIdentity(t, "rsa signer"), []string{"rsa_padding_mode:pss", "rsa_pss_saltlen:32"}, "sha256"},
		{"ed25519", newEd25519Identity(t, "ed25519 signer"), nil, "sha512"},
	}
}

// opensslSignsEd25519 reports whether this OpenSSL can produce (and so
// verify) Ed25519 CMS signatures: 3.0 refuses ("no default digest" / "invalid
// digest"), 3.5 signs with -md sha512 as RFC 8419 requires.
func opensslSignsEd25519(t *testing.T, bin string) bool {
	t.Helper()
	dir := t.TempDir()
	id := newEd25519Identity(t, "ed25519 probe")
	certPath, keyPath := id.writePEM(t, dir, "probe")
	in := filepath.Join(dir, "in")
	if err := os.WriteFile(in, []byte("probe"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "cms", "-sign", "-binary", "-md", "sha512", "-outform", "DER", "-in", in, "-signer", certPath, "-inkey", keyPath)
	out, err := cmd.Output()
	return err == nil && len(out) > 0
}

// TestOpenSSLVerifiesOurSignatures: every signing row, attached and detached,
// verifies with `openssl cms -verify`.
func TestOpenSSLVerifiesOurSignatures(t *testing.T) {
	bin := opensslBin(t)
	dir := t.TempDir()
	content := bytes.Repeat([]byte("signed interop line\n"), 2000)
	contentPath := filepath.Join(dir, "content.bin")
	if err := os.WriteFile(contentPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	ed25519OK := opensslSignsEd25519(t, bin)
	for _, s := range interopSigners(t) {
		for _, detached := range []bool{true, false} {
			name := s.name
			if detached {
				name += "/detached"
			}
			t.Run(name, func(t *testing.T) {
				if s.name == "ed25519" && !ed25519OK {
					t.Skip("this OpenSSL has no Ed25519 CMS support")
				}
				certPath, _ := s.id.writePEM(t, dir, s.name)
				sig := signBytesHelper(t, content, s.id, &SignOptions{Detached: detached})
				sigPath := filepath.Join(dir, "sig.der")
				if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
					t.Fatal(err)
				}
				args := []string{"cms", "-verify", "-binary", "-inform", "DER", "-in", sigPath, "-CAfile", certPath, "-purpose", "any"}
				if detached {
					args = append(args, "-content", contentPath)
				}
				got := openssl(t, bin, args...)
				if !bytes.Equal(got, content) {
					t.Fatalf("openssl returned %d bytes, want %d", len(got), len(content))
				}
			})
		}
	}
}

// TestVerifyOpenSSLSignatures: `openssl cms -sign -cades` output (CAdES adds
// the ESS signingCertificateV2 the profile requires) verifies here, DER and
// streamed BER, attached and detached; output without -cades is refused for
// the missing attribute. OpenSSL quirks the cases work around: -stream always
// embeds the content (its "detached" streaming output is attached), and
// RSA-PSS cannot be streamed at all ("illegal zero content").
func TestVerifyOpenSSLSignatures(t *testing.T) {
	bin := opensslBin(t)
	dir := t.TempDir()
	content := bytes.Repeat([]byte("openssl signed line\n"), 2000)
	contentPath := filepath.Join(dir, "content.bin")
	if err := os.WriteFile(contentPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	ed25519OK := opensslSignsEd25519(t, bin)
	for _, s := range interopSigners(t) {
		if s.name == "ed25519" && !ed25519OK {
			t.Logf("%s: this OpenSSL has no Ed25519 CMS support, skipped", s.name)
			continue
		}
		certPath, keyPath := s.id.writePEM(t, dir, s.name)
		for _, c := range []struct {
			name string
			args []string
		}{
			{"detached DER", []string{"-noindef"}},
			{"attached DER", []string{"-nodetach", "-noindef"}},
			{"attached BER", []string{"-stream"}},
			{"attached BER nodetach", []string{"-nodetach", "-stream"}},
		} {
			if s.name == "rsa-pss" && strings.Contains(c.name, "BER") {
				continue
			}
			t.Run(s.name+"/"+c.name, func(t *testing.T) {
				args := []string{"cms", "-sign", "-binary", "-cades", "-outform", "DER", "-in", contentPath, "-signer", certPath, "-inkey", keyPath}
				if s.md != "" {
					args = append(args, "-md", s.md)
				}
				for _, ko := range s.keyopts {
					args = append(args, "-keyopt", ko)
				}
				args = append(args, c.args...)
				sig := openssl(t, bin, args...)
				if strings.Contains(c.name, "BER") && !bytes.HasPrefix(sig, []byte{0x30, 0x80}) {
					t.Fatal("expected indefinite-length BER")
				}
				var reader = bytes.NewReader(content)
				if strings.HasPrefix(c.name, "attached") {
					reader = nil
				}
				var in io.Reader
				if reader != nil {
					in = reader
				}
				got, err := verifyHelper(t, sig, in)
				if err != nil {
					t.Fatalf("verify: %v", err)
				}
				if len(got) != 1 || !got[0].Signer.Equal(s.id.Cert) {
					t.Fatalf("verified %+v", got)
				}
			})
		}
		t.Run(s.name+"/without -cades", func(t *testing.T) {
			args := []string{"cms", "-sign", "-binary", "-outform", "DER", "-in", contentPath, "-signer", certPath, "-inkey", keyPath}
			if s.md != "" {
				args = append(args, "-md", s.md)
			}
			for _, ko := range s.keyopts {
				args = append(args, "-keyopt", ko)
			}
			sig := openssl(t, bin, args...)
			if _, err := verifyHelper(t, sig, bytes.NewReader(content)); !errors.Is(err, ErrMissingSignedAttribute) {
				t.Fatalf("plain OpenSSL signature: %v", err)
			}
		})
	}
}
