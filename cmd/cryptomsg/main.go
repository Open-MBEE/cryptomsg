// Command cryptomsg encrypts, decrypts, signs, verifies and inspects CMS
// (RFC 5652) objects with the cryptomsg library. It is a thin wrapper: every
// decision about algorithms and trust is the library's.
//
//	cryptomsg encrypt -recipient a.crt [-recipient b.crt ...] [-aes128] [-keyid] -in plain -out envelope.der
//	cryptomsg decrypt -cert me.crt -key me.key [-allow-cbc] -in envelope.der -out plain
//	cryptomsg sign    -cert signer.crt -key signer.key [-chain inter.pem] [-attached] -in content -out sig.der
//	cryptomsg verify  -root ca.pem [-intermediate inter.pem] [-crl list.crl] [-time RFC3339] [-content content] -in sig.der
//	cryptomsg inspect -in object.der
//
// Certificates and keys are PEM or DER files; keys are PKCS#8 (also PKCS#1 RSA
// and SEC 1 EC). Exit status is 0 on success, 1 on a usage error, 2 when the
// library refuses the object or the signature does not verify.
package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Open-MBEE/cryptomsg"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: cryptomsg encrypt|decrypt|sign|verify|inspect [flags]")
		return 1
	}
	var err error
	switch args[0] {
	case "encrypt":
		err = cmdEncrypt(args[1:], stdin, stdout, stderr)
	case "decrypt":
		err = cmdDecrypt(args[1:], stdin, stdout, stderr)
	case "sign":
		err = cmdSign(args[1:], stdin, stdout, stderr)
	case "verify":
		err = cmdVerify(args[1:], stdin, stdout, stderr)
	case "inspect":
		err = cmdInspect(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "cryptomsg: unknown command %q\n", args[0])
		return 1
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 1
	case isUsage(err):
		fmt.Fprintln(stderr, "cryptomsg:", err)
		return 1
	}
	fmt.Fprintln(stderr, "cryptomsg:", err)
	return 2
}

type usageError struct{ error }

func isUsage(err error) bool {
	var u usageError
	return errors.As(err, &u)
}

func usagef(format string, a ...any) error {
	return usageError{fmt.Errorf(format, a...)}
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("cryptomsg "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func openIn(path string, stdin io.Reader) (io.ReadCloser, error) {
	if path == "" || path == "-" {
		return io.NopCloser(stdin), nil
	}
	return os.Open(path) // #nosec G304 -- the path is the operator's own command-line argument
}

func openOut(path string, stdout io.Writer) (io.WriteCloser, error) {
	if path == "" || path == "-" {
		return nopWriteCloser{stdout}, nil
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- operator's argument
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func cmdEncrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("encrypt", stderr)
	var recipients multiFlag
	fs.Var(&recipients, "recipient", "recipient certificate file (repeatable)")
	aes128 := fs.Bool("aes128", false, "use AES-128-GCM instead of AES-256-GCM")
	keyid := fs.Bool("keyid", false, "name recipients by SubjectKeyIdentifier instead of issuer and serial")
	in := fs.String("in", "-", "plaintext file ('-' for stdin)")
	out := fs.String("out", "-", "envelope output file ('-' for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(recipients) == 0 {
		return usagef("encrypt: at least one -recipient is required")
	}
	var certs []*x509.Certificate
	for _, path := range recipients {
		cs, err := loadCertificates(path)
		if err != nil {
			return err
		}
		certs = append(certs, cs...)
	}
	opts := &cryptomsg.EncryptOptions{}
	if *aes128 {
		opts.Cipher = cryptomsg.AES128GCM
	}
	if *keyid {
		opts.RecipientIdentifier = cryptomsg.SubjectKeyID
	}
	r, err := openIn(*in, stdin)
	if err != nil {
		return err
	}
	defer r.Close()
	var buf bytes.Buffer
	if err := cryptomsg.Encrypt(&buf, r, certs, opts); err != nil {
		return err
	}
	return writeOut(*out, stdout, buf.Bytes())
}

func cmdDecrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("decrypt", stderr)
	certPath := fs.String("cert", "", "recipient certificate file")
	keyPath := fs.String("key", "", "recipient private key file (PKCS#8, PKCS#1 or SEC 1 PEM/DER)")
	allowCBC := fs.Bool("allow-cbc", false, "accept legacy AES-CBC EnvelopedData (no integrity protection)")
	in := fs.String("in", "-", "envelope file ('-' for stdin)")
	out := fs.String("out", "-", "plaintext output file ('-' for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certPath == "" || *keyPath == "" {
		return usagef("decrypt: -cert and -key are required")
	}
	cert, err := loadCertificate(*certPath)
	if err != nil {
		return err
	}
	key, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	r, err := openIn(*in, stdin)
	if err != nil {
		return err
	}
	defer r.Close()
	var buf bytes.Buffer
	if err := cryptomsg.Decrypt(&buf, r, cert, key, &cryptomsg.DecryptOptions{AllowCBC: *allowCBC}); err != nil {
		return err
	}
	return writeOut(*out, stdout, buf.Bytes())
}

func cmdSign(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("sign", stderr)
	certPath := fs.String("cert", "", "signer certificate file")
	keyPath := fs.String("key", "", "signer private key file")
	var chain multiFlag
	fs.Var(&chain, "chain", "additional certificate file to include for the verifier (repeatable)")
	attached := fs.Bool("attached", false, "embed the content in the signature (default: detached)")
	keyid := fs.Bool("keyid", false, "name the signer by SubjectKeyIdentifier instead of issuer and serial")
	in := fs.String("in", "-", "content file ('-' for stdin)")
	out := fs.String("out", "-", "signature output file ('-' for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certPath == "" || *keyPath == "" {
		return usagef("sign: -cert and -key are required")
	}
	cert, err := loadCertificate(*certPath)
	if err != nil {
		return err
	}
	key, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return usagef("sign: key in %s cannot sign", *keyPath)
	}
	certs := []*x509.Certificate{cert}
	for _, path := range chain {
		cs, err := loadCertificates(path)
		if err != nil {
			return err
		}
		certs = append(certs, cs...)
	}
	r, err := openIn(*in, stdin)
	if err != nil {
		return err
	}
	defer r.Close()
	opts := &cryptomsg.SignOptions{Detached: !*attached}
	if *keyid {
		opts.SignerIdentifier = cryptomsg.SubjectKeyID
	}
	sig, err := cryptomsg.Sign(r, signer, certs, opts)
	if err != nil {
		return err
	}
	return writeOut(*out, stdout, sig)
}

func cmdVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("verify", stderr)
	var roots, intermediates, crls, ekus multiFlag
	fs.Var(&roots, "root", "trust anchor certificate file (repeatable)")
	fs.Var(&intermediates, "intermediate", "intermediate CA certificate file (repeatable)")
	fs.Var(&crls, "crl", "CRL file, PEM or DER (repeatable)")
	fs.Var(&ekus, "eku", "required extended key usage: emailProtection, codeSigning, clientAuth, serverAuth, timeStamping, any (repeatable)")
	requireCRL := fs.Bool("require-crl", false, "refuse chains with a certificate no CRL covers")
	allowStale := fs.Bool("allow-stale-crl", false, "accept CRLs past their NextUpdate")
	at := fs.String("time", "", "evaluation time, RFC 3339 (default: now)")
	contentPath := fs.String("content", "", "detached content file")
	in := fs.String("in", "-", "signature file ('-' for stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(roots) == 0 {
		return usagef("verify: at least one -root is required")
	}
	policy := &cryptomsg.Policy{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool(), RequireCRL: *requireCRL, AllowStaleCRLs: *allowStale}
	for _, path := range roots {
		cs, err := loadCertificates(path)
		if err != nil {
			return err
		}
		for _, c := range cs {
			policy.Roots.AddCert(c)
		}
	}
	for _, path := range intermediates {
		cs, err := loadCertificates(path)
		if err != nil {
			return err
		}
		for _, c := range cs {
			policy.Intermediates.AddCert(c)
		}
	}
	for _, path := range crls {
		crl, err := loadCRL(path)
		if err != nil {
			return err
		}
		policy.CRLs = append(policy.CRLs, crl)
	}
	for _, name := range ekus {
		eku, err := parseEKU(name)
		if err != nil {
			return err
		}
		policy.KeyUsages = append(policy.KeyUsages, eku)
	}
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return usagef("verify: -time: %v", err)
		}
		policy.Time = t
	}
	r, err := openIn(*in, stdin)
	if err != nil {
		return err
	}
	defer r.Close()
	sig, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	var content io.Reader
	if *contentPath != "" {
		f, err := os.Open(*contentPath)
		if err != nil {
			return err
		}
		defer f.Close()
		content = f
	}
	v, err := cryptomsg.Verify(sig, content, policy)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "verified: %s\n", v.Signer.Subject)
	fmt.Fprintf(stdout, "algorithm: %s\n", v.Algorithm)
	fmt.Fprintf(stdout, "signing time: %s\n", v.SigningTime.UTC().Format(time.RFC3339))
	for i, c := range v.Chain {
		fmt.Fprintf(stdout, "chain[%d]: %s\n", i, c.Subject)
	}
	return nil
}

func cmdInspect(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := newFlagSet("inspect", stderr)
	in := fs.String("in", "-", "CMS object file ('-' for stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := openIn(*in, stdin)
	if err != nil {
		return err
	}
	defer r.Close()
	info, err := cryptomsg.Parse(r)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "type: %s\n", info.Kind)
	fmt.Fprintf(stdout, "content type: %s\n", info.ContentType)
	switch info.Kind {
	case cryptomsg.KindEnvelopedData, cryptomsg.KindAuthEnvelopedData:
		fmt.Fprintf(stdout, "content encryption: %s\n", info.ContentEncryption)
		fmt.Fprintf(stdout, "encrypted size: %d bytes\n", info.EncryptedSize)
		fmt.Fprintf(stdout, "recipients: %d\n", len(info.Recipients))
		for i, rcpt := range info.Recipients {
			status := "supported"
			if !rcpt.Supported {
				status = "unsupported"
			}
			fmt.Fprintf(stdout, "  [%d] %s key algorithm %s (%s)\n", i, rcpt.Description, rcpt.KeyAlgorithm, status)
		}
	case cryptomsg.KindSignedData:
		fmt.Fprintf(stdout, "content: %s\n", map[bool]string{true: "attached", false: "detached"}[info.Attached])
		fmt.Fprintf(stdout, "signers: %d\n", len(info.Signers))
		for i, s := range info.Signers {
			who := s.Description
			if s.Certificate != nil {
				who = s.Certificate.Subject.String()
			}
			fmt.Fprintf(stdout, "  [%d] %s digest %s signature %s\n", i, who, s.DigestAlgorithm, s.SignatureAlgorithm)
		}
		fmt.Fprintf(stdout, "certificates: %d\n", len(info.Certificates))
		for i, c := range info.Certificates {
			fmt.Fprintf(stdout, "  [%d] %s (issuer %s, serial %s)\n", i, c.Subject, c.Issuer, c.SerialNumber)
		}
	}
	return nil
}

func writeOut(path string, stdout io.Writer, data []byte) error {
	w, err := openOut(path, stdout)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

// pemOrDER returns every PEM block of the named type, or the whole file as
// one DER blob when it is not PEM.
func pemOrDER(path string, types ...string) ([][]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the path is the operator's own command-line argument
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		return [][]byte{data}, nil
	}
	var out [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		for _, t := range types {
			if block.Type == t {
				out = append(out, block.Bytes)
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, usagef("%s: no %s PEM block", path, strings.Join(types, "/"))
	}
	return out, nil
}

func loadCertificates(path string) ([]*x509.Certificate, error) {
	blobs, err := pemOrDER(path, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, b := range blobs {
		cs, err := x509.ParseCertificates(b)
		if err != nil {
			return nil, usagef("%s: %v", path, err)
		}
		certs = append(certs, cs...)
	}
	return certs, nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	certs, err := loadCertificates(path)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

func loadPrivateKey(path string) (crypto.PrivateKey, error) {
	blobs, err := pemOrDER(path, "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	der := blobs[0]
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, usagef("%s: not a PKCS#8, PKCS#1 or SEC 1 private key", path)
}

func loadCRL(path string) (*x509.RevocationList, error) {
	blobs, err := pemOrDER(path, "X509 CRL")
	if err != nil {
		return nil, err
	}
	crl, err := x509.ParseRevocationList(blobs[0])
	if err != nil {
		return nil, usagef("%s: %v", path, err)
	}
	return crl, nil
}

func parseEKU(name string) (x509.ExtKeyUsage, error) {
	switch strings.ToLower(name) {
	case "any":
		return x509.ExtKeyUsageAny, nil
	case "emailprotection":
		return x509.ExtKeyUsageEmailProtection, nil
	case "codesigning":
		return x509.ExtKeyUsageCodeSigning, nil
	case "clientauth":
		return x509.ExtKeyUsageClientAuth, nil
	case "serverauth":
		return x509.ExtKeyUsageServerAuth, nil
	case "timestamping":
		return x509.ExtKeyUsageTimeStamping, nil
	}
	return 0, usagef("unknown extended key usage %q", name)
}
