package cryptomsg

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// opensslBin returns the OpenSSL binary for interoperability tests:
// $CRYPTOMSG_OPENSSL, else the first `openssl` on PATH. With
// CRYPTOMSG_REQUIRE_OPENSSL set an absent binary fails instead of skipping.
func opensslBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("CRYPTOMSG_OPENSSL")
	if bin == "" {
		bin, _ = exec.LookPath("openssl")
	}
	if bin == "" {
		if os.Getenv("CRYPTOMSG_REQUIRE_OPENSSL") != "" {
			t.Fatal("CRYPTOMSG_REQUIRE_OPENSSL set but no openssl found")
		}
		t.Skip("no openssl binary; set CRYPTOMSG_OPENSSL")
	}
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatalf("%s version: %v", bin, err)
	}
	version := strings.TrimSpace(string(out))
	if !strings.HasPrefix(version, "OpenSSL 3.") {
		if os.Getenv("CRYPTOMSG_REQUIRE_OPENSSL") != "" {
			t.Fatalf("need OpenSSL 3.x, found %q", version)
		}
		t.Skipf("need OpenSSL 3.x, found %q", version)
	}
	t.Logf("interop against %s", version)
	return bin
}

func openssl(t *testing.T, bin string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}

type interopRecipient struct {
	name    string
	id      *testIdentity
	keyopts []string // openssl -keyopt values for -encrypt
}

func interopRecipients(t *testing.T) []interopRecipient {
	return []interopRecipient{
		{"rsa-2048", sharedRSAIdentity(t, "rsa interop"), []string{"rsa_padding_mode:oaep", "rsa_oaep_md:sha256"}},
		{"p256", newECIdentity(t, "p256 interop", elliptic.P256()), []string{"ecdh_kdf_md:sha256"}},
		{"p384", newECIdentity(t, "p384 interop", elliptic.P384()), []string{"ecdh_kdf_md:sha384"}},
	}
}

// TestOpenSSLDecryptsOurOutput: every recipient kind, both ciphers and both
// recipient identifiers open with `openssl cms -decrypt`.
func TestOpenSSLDecryptsOurOutput(t *testing.T) {
	bin := opensslBin(t)
	dir := t.TempDir()
	plaintext := bytes.Repeat([]byte("interop payload line\n"), 3000)
	recipients := interopRecipients(t)
	var certs []*x509.Certificate
	for _, r := range recipients {
		certs = append(certs, r.id.Cert)
	}
	for _, cipher := range []ContentCipher{AES256GCM, AES128GCM} {
		for _, rid := range []RecipientIdentifierKind{IssuerAndSerial, SubjectKeyID} {
			env := encryptBytes(t, plaintext, &EncryptOptions{Cipher: cipher, RecipientIdentifier: rid}, certs...)
			envPath := filepath.Join(dir, "ours.der")
			if err := os.WriteFile(envPath, env, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, r := range recipients {
				t.Run(cipher.String()+"/"+rid.String()+"/"+r.name, func(t *testing.T) {
					certPath, keyPath := r.id.writePEM(t, dir, r.name)
					got := openssl(t, bin, "cms", "-decrypt", "-binary", "-inform", "DER", "-in", envPath, "-recip", certPath, "-inkey", keyPath)
					if !bytes.Equal(got, plaintext) {
						t.Fatalf("openssl recovered %d bytes, want %d", len(got), len(plaintext))
					}
				})
			}
		}
	}
}

// TestDecryptOpenSSLOutput: `openssl cms -encrypt` output — DER and streamed
// BER, GCM for every recipient kind, CBC under the option — decrypts here.
func TestDecryptOpenSSLOutput(t *testing.T) {
	bin := opensslBin(t)
	dir := t.TempDir()
	plaintext := bytes.Repeat([]byte("openssl payload line\n"), 3000)
	ptPath := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(ptPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	recipients := interopRecipients(t)
	var recipArgs []string
	for _, r := range recipients {
		certPath, _ := r.id.writePEM(t, dir, r.name)
		recipArgs = append(recipArgs, "-recip", certPath)
		for _, ko := range r.keyopts {
			recipArgs = append(recipArgs, "-keyopt", ko)
		}
	}
	for _, c := range []struct {
		name   string
		cipher string
		stream []string
		keyid  bool
	}{
		{"aes-256-gcm DER", "-aes-256-gcm", []string{"-noindef"}, false},
		{"aes-256-gcm BER", "-aes-256-gcm", []string{"-stream"}, false},
		{"aes-128-gcm DER", "-aes-128-gcm", []string{"-noindef"}, false},
		{"aes-128-gcm BER keyid", "-aes-128-gcm", []string{"-stream"}, true},
		{"aes-256-gcm DER keyid", "-aes-256-gcm", []string{"-noindef"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := []string{"cms", "-encrypt", "-binary", "-outform", "DER", "-in", ptPath, c.cipher}
			args = append(args, c.stream...)
			if c.keyid {
				args = append(args, "-keyid")
			}
			args = append(args, recipArgs...)
			env := openssl(t, bin, args...)
			if len(c.stream) > 0 && c.stream[0] == "-stream" && !bytes.HasPrefix(env, []byte{0x30, 0x80}) {
				t.Fatalf("expected indefinite-length BER from -stream")
			}
			parsed, err := parseEnvelope(mustNormalize(t, env))
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Recipients) != len(recipients) {
				t.Fatalf("%d recipients parsed", len(parsed.Recipients))
			}
			for _, r := range parsed.Recipients {
				if want := SubjectKeyID; c.keyid && r.ID.Kind != want {
					t.Fatalf("recipient %v with -keyid", r.ID.Kind)
				}
			}
			for _, r := range recipients {
				got, err := decryptBytes(t, env, r.id, nil)
				if err != nil {
					t.Fatalf("%s: %v", r.name, err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("%s: plaintext differs", r.name)
				}
			}
		})
	}

	t.Run("aes-256-cbc needs AllowCBC", func(t *testing.T) {
		args := append([]string{"cms", "-encrypt", "-binary", "-outform", "DER", "-stream", "-in", ptPath, "-aes-256-cbc"}, recipArgs...)
		env := openssl(t, bin, args...)
		for _, r := range recipients {
			out, err := decryptBytes(t, env, r.id, nil)
			var ua *UnsupportedAlgorithmError
			if !errors.As(err, &ua) || !ua.OID.Equal(oidAES256CBC) || len(out) != 0 {
				t.Fatalf("%s without AllowCBC: %v", r.name, err)
			}
			got, err := decryptBytes(t, env, r.id, &DecryptOptions{AllowCBC: true})
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("%s with AllowCBC: %v", r.name, err)
			}
		}
	})

	t.Run("sha1 KDF and OAEP defaults are refused", func(t *testing.T) {
		var args []string
		args = append(args, "cms", "-encrypt", "-binary", "-outform", "DER", "-in", ptPath, "-aes-256-gcm")
		for _, r := range recipients {
			certPath, _ := r.id.writePEM(t, dir, r.name)
			args = append(args, "-recip", certPath)
			if r.name == "rsa-2048" {
				args = append(args, "-keyopt", "rsa_padding_mode:oaep") // SHA-1 OAEP
			}
		}
		env := openssl(t, bin, args...)
		for _, r := range recipients {
			out, err := decryptBytes(t, env, r.id, nil)
			var ua *UnsupportedAlgorithmError
			if !errors.As(err, &ua) || len(out) != 0 {
				t.Fatalf("%s with SHA-1 defaults: %v", r.name, err)
			}
			t.Logf("%s refused: %v", r.name, err)
		}
	})
}

func mustNormalize(t *testing.T, in []byte) []byte {
	t.Helper()
	der, err := normalizeInput(in)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
