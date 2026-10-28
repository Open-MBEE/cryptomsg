package cryptomsg

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var writeBCInput = flag.String("write-bc-input", "", "directory to write cryptomsg output for interop/bouncycastle/generate.sh verify")

const bcDir = "testdata/bouncycastle"

// bcFixtureTime is inside the fixture certificates' validity (2026–2036).
var bcFixtureTime = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

func loadBCIdentity(t *testing.T, name string) *testIdentity {
	t.Helper()
	certPEM, _ := pem.Decode(readFile(t, filepath.Join(bcDir, name+".crt")))
	keyPEM, _ := pem.Decode(readFile(t, filepath.Join(bcDir, name+".key")))
	if certPEM == nil || keyPEM == nil {
		t.Fatalf("%s: bad PEM", name)
	}
	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyPEM.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return &testIdentity{Cert: cert, Key: key.(crypto.Signer)}
}

// TestBouncyCastleEnvelopes: Bouncy Castle 1.80 output decrypts here for every
// recipient kind, both identifiers, DER and BER; CBC only under the option.
func TestBouncyCastleEnvelopes(t *testing.T) {
	content := readFile(t, filepath.Join(bcDir, "content.bin"))
	recipients := []*testIdentity{loadBCIdentity(t, "rsa2048"), loadBCIdentity(t, "p256"), loadBCIdentity(t, "p384")}
	for _, c := range []struct {
		file   string
		kind   Kind
		cipher string
		rid    RecipientIdentifierKind
		cbc    bool
	}{
		{"authenv-aes256gcm-ias.der", KindAuthEnvelopedData, oidAES256GCM.String(), IssuerAndSerial, false},
		{"authenv-aes128gcm-ski.der", KindAuthEnvelopedData, oidAES128GCM.String(), SubjectKeyID, false},
		{"authenv-aes256gcm-ski.ber", KindAuthEnvelopedData, oidAES256GCM.String(), SubjectKeyID, false},
		{"env-aes256cbc-ias.der", KindEnvelopedData, oidAES256CBC.String(), IssuerAndSerial, true},
	} {
		t.Run(c.file, func(t *testing.T) {
			env := readFile(t, filepath.Join(bcDir, c.file))
			info, err := Parse(bytes.NewReader(env))
			if err != nil {
				t.Fatal(err)
			}
			if info.Kind != c.kind || info.ContentEncryption.String() != c.cipher || len(info.Recipients) != 3 {
				t.Fatalf("%+v", info)
			}
			for _, r := range info.Recipients {
				if r.Identifier != c.rid || !r.Supported {
					t.Fatalf("%+v", r)
				}
			}
			for _, id := range recipients {
				got, err := decryptBytes(t, env, id, &DecryptOptions{AllowCBC: c.cbc})
				if err != nil || !bytes.Equal(got, content) {
					t.Fatalf("%s: %v", id.Cert.Subject.CommonName, err)
				}
				if c.cbc {
					if _, err := decryptBytes(t, env, id, nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
						t.Fatalf("CBC without the option: %v", err)
					}
				}
			}
		})
	}
}

// TestBouncyCastleSignatures: Bouncy Castle SignedData for every signing row
// (with signingCertificateV2) verifies here against the fixture certificate
// as trust anchor.
func TestBouncyCastleSignatures(t *testing.T) {
	content := readFile(t, filepath.Join(bcDir, "content.bin"))
	for _, name := range []string{"p256", "p384", "rsa2048", "ed25519"} {
		id := loadBCIdentity(t, name)
		roots := x509.NewCertPool()
		roots.AddCert(id.Cert)
		policy := &Policy{Roots: roots, Time: bcFixtureTime}
		for _, variant := range []string{"detached.der", "attached.der", "attached.ber"} {
			path := filepath.Join(bcDir, "signed-"+name+"-"+variant)
			if _, err := os.Stat(path); err != nil {
				continue
			}
			t.Run(name+"-"+variant, func(t *testing.T) {
				sig := readFile(t, path)
				var reader *bytes.Reader
				if variant == "detached.der" {
					reader = bytes.NewReader(content)
				}
				var v *VerifiedSignature
				var err error
				if reader != nil {
					v, err = Verify(sig, reader, policy)
				} else {
					v, err = Verify(sig, nil, policy)
				}
				if err != nil {
					t.Fatalf("verify: %v", err)
				}
				if !v.Signer.Equal(id.Cert) || len(v.Chain) != 1 {
					t.Fatalf("%+v", v)
				}
				// Wrong content and a stranger's trust store are refused.
				if variant == "detached.der" {
					if _, err := Verify(sig, bytes.NewReader(content[1:]), policy); !errors.Is(err, ErrSignatureInvalid) {
						t.Fatalf("wrong content: %v", err)
					}
				}
				other := x509.NewCertPool()
				other.AddCert(loadBCIdentity(t, "rsa2048").Cert)
				if name != "rsa2048" {
					var rerr error
					if reader != nil {
						_, rerr = Verify(sig, bytes.NewReader(content), &Policy{Roots: other, Time: bcFixtureTime})
					} else {
						_, rerr = Verify(sig, nil, &Policy{Roots: other, Time: bcFixtureTime})
					}
					if !errors.Is(rerr, ErrUntrustedSigner) {
						t.Fatalf("stranger's roots: %v", rerr)
					}
				}
			})
		}
	}
}

// TestWriteBouncyCastleInput writes cryptomsg output under the fixture keys
// for `interop/bouncycastle/generate.sh verify <dir>`; a no-op without the flag.
func TestWriteBouncyCastleInput(t *testing.T) {
	if *writeBCInput == "" {
		t.Skip("set -write-bc-input=<dir>")
	}
	dir := *writeBCInput
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := readFile(t, filepath.Join(bcDir, "content.bin"))
	for _, name := range []string{"rsa2048", "p256", "p384", "ed25519", "content.bin"} {
		src := name + ".crt"
		if name == "content.bin" {
			src = name
		}
		copyFile(t, filepath.Join(bcDir, src), filepath.Join(dir, src))
		if name != "content.bin" {
			copyFile(t, filepath.Join(bcDir, name+".key"), filepath.Join(dir, name+".key"))
		}
	}
	recipients := []*x509.Certificate{loadBCIdentity(t, "rsa2048").Cert, loadBCIdentity(t, "p256").Cert, loadBCIdentity(t, "p384").Cert}
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go-authenv-aes256gcm-ias.der", encryptBytes(t, content, nil, recipients...))
	write("go-authenv-aes128gcm-ski.der", encryptBytes(t, content, &EncryptOptions{Cipher: AES128GCM, RecipientIdentifier: SubjectKeyID}, recipients...))
	for _, name := range []string{"p256", "p384", "rsa2048", "ed25519"} {
		id := loadBCIdentity(t, name)
		write("go-signed-"+name+"-detached.der", signBytesHelper(t, content, id, &SignOptions{Detached: true}))
		write("go-signed-"+name+"-attached.der", signBytesHelper(t, content, id, nil))
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.WriteFile(dst, readFile(t, src), 0o644); err != nil {
		t.Fatal(err)
	}
}
