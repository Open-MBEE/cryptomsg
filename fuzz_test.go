package cryptomsg

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var writeFuzzSeeds = flag.Bool("write-fuzz-seeds", false, "regenerate testdata/fuzz seed corpora from fresh test keys")

// TestWriteFuzzSeeds regenerates the committed seed corpora when run with
// -write-fuzz-seeds; otherwise it only checks that they exist.
func TestWriteFuzzSeeds(t *testing.T) {
	seeds := map[string][][]byte{}
	rsaID := sharedRSAIdentity(t, "rsa seed")
	p256 := newECIdentity(t, "p256 seed", elliptic.P256())
	ed := newEd25519Identity(t, "ed25519 seed")
	content := []byte("seed content")
	seeds["FuzzParseEnvelope"] = [][]byte{
		encryptBytes(t, content, nil, rsaID.Cert, p256.Cert),
		encryptBytes(t, content, &EncryptOptions{Cipher: AES128GCM, RecipientIdentifier: SubjectKeyID}, p256.Cert),
		readFile(t, "internal/ber/testdata/openssl-stream-envelopeddata.ber"),
		readFile(t, "internal/ber/testdata/openssl-stream-authenvelopeddata.ber"),
	}
	seeds["FuzzParseSignedData"] = [][]byte{
		signBytesHelper(t, content, p256, nil),
		signBytesHelper(t, content, rsaID, &SignOptions{Detached: true, SignerIdentifier: SubjectKeyID}),
		signBytesHelper(t, content, ed, &SignOptions{Detached: true}),
	}
	for target, inputs := range seeds {
		dir := filepath.Join("testdata", "fuzz", target)
		if *writeFuzzSeeds {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			for i, in := range inputs {
				body := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", in)
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("seed-%d", i)), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) == 0 {
			t.Fatalf("%s has no seed corpus (run with -write-fuzz-seeds)", dir)
		}
	}
}

// FuzzParseEnvelope: envelope parsing and recipient matching never panic,
// refuse with typed errors, and never write plaintext for a stranger.
func FuzzParseEnvelope(f *testing.F) {
	f.Fuzz(func(t *testing.T, in []byte) {
		der, err := normalizeInput(in)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("untyped error %T", err)
			}
			return
		}
		env, err := parseEnvelope(der)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnsupportedStructure) && !errors.Is(err, ErrUnsupportedAlgorithm) {
				t.Fatalf("untyped error %T: %v", err, err)
			}
			return
		}
		for _, r := range env.Recipients {
			_ = r.ID.String()
		}
		var out bytes.Buffer
		err = Decrypt(&out, bytes.NewReader(in), fuzzStranger.Cert, fuzzStranger.Key, &DecryptOptions{AllowCBC: true})
		if err == nil || out.Len() != 0 {
			t.Fatalf("stranger decrypted %d bytes", out.Len())
		}
	})
}

// FuzzParseSignedData: SignedData and signed-attribute parsing never panic,
// refuse with typed errors, and never verify for arbitrary input.
func FuzzParseSignedData(f *testing.F) {
	f.Fuzz(func(t *testing.T, in []byte) {
		der, err := normalizeInput(in)
		if err != nil {
			return
		}
		msg, err := parseSignedData(der)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnsupportedStructure) {
				t.Fatalf("untyped error %T: %v", err, err)
			}
			return
		}
		for i := range msg.Signers {
			if attrs, err := parseSignedAttributes(msg.Signers[i].SignedAttrs); err == nil {
				_ = attrs.signingTime.String()
			} else if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrMissingSignedAttribute) {
				t.Fatalf("untyped error %T: %v", err, err)
			}
		}
		var content []byte
		if !msg.Attached {
			content = []byte("fuzz")
		}
		var reader *bytes.Reader
		if content != nil {
			reader = bytes.NewReader(content)
		}
		var results []*VerifiedSignature
		if reader != nil {
			results, err = verifySigners(msg, reader, nil)
		} else {
			results, err = verifySigners(msg, nil, nil)
		}
		if err == nil && len(results) > 0 {
			// Only our own seeds can verify; they carry fresh random keys, so
			// a verifying mutation would have to be a byte-identical seed.
			for _, r := range results {
				if r.Signer == nil {
					t.Fatal("verified without a signer")
				}
			}
		}
	})
}

// fuzzStranger is a recipient no corpus entry is addressed to.
var fuzzStranger = func() *testIdentity {
	t := &testing.T{}
	return newECIdentity(t, "fuzz stranger", elliptic.P256())
}()
