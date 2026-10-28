package cryptomsg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/Open-MBEE/cryptomsg/internal/ber"
)

// SignOptions tunes Sign. The zero value signs detached with the current time.
type SignOptions struct {
	// Detached omits the content from the SignedData; the verifier supplies
	// it. When false the content is embedded (attached).
	Detached bool
	// SigningTime is the signing-time attribute; time.Now() when zero. It is
	// stored at second precision in UTC.
	SigningTime time.Time
	// SignerIdentifier selects IssuerAndSerialNumber (default) or
	// SubjectKeyIdentifier for the SignerInfo.
	SignerIdentifier RecipientIdentifierKind
	// ContentType is the eContentType; id-data when nil.
	ContentType asn1.ObjectIdentifier
	// Rand is the entropy source for randomised signatures (ECDSA, RSA-PSS);
	// crypto/rand.Reader when nil.
	Rand io.Reader
}

// signatureSuite is one row of the signing profile.
type signatureSuite struct {
	name         string
	digestOID    asn1.ObjectIdentifier
	hash         crypto.Hash
	signatureOID asn1.ObjectIdentifier
}

var (
	suiteECDSAP256 = signatureSuite{"ECDSA P-256 with SHA-256", oidSHA256, crypto.SHA256, oidECDSAWithSHA256}
	suiteECDSAP384 = signatureSuite{"ECDSA P-384 with SHA-384", oidSHA384, crypto.SHA384, oidECDSAWithSHA384}
	suiteRSAPSS    = signatureSuite{"RSASSA-PSS with SHA-256", oidSHA256, crypto.SHA256, oidRSASSAPSS}
	suiteEd25519   = signatureSuite{"Ed25519", oidSHA512, crypto.SHA512, oidEd25519}
)

// suiteForPublicKey picks the profile row for a signer's key, or refuses it.
func suiteForPublicKey(pub crypto.PublicKey) (*signatureSuite, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return &suiteECDSAP256, nil
		case elliptic.P384():
			return &suiteECDSAP384, nil
		}
		return nil, &UnsupportedAlgorithmError{OID: oidECPublicKey, Use: "signature curve"}
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return nil, fmt.Errorf("%w: RSA-%d signer, minimum %d", ErrKeyTooWeak, k.N.BitLen(), MinRSABits)
		}
		return &suiteRSAPSS, nil
	case ed25519.PublicKey:
		return &suiteEd25519, nil
	}
	return nil, &UnsupportedAlgorithmError{OID: asn1.ObjectIdentifier{0}, Use: fmt.Sprintf("signer key of type %T", pub)}
}

// hashFor returns the constructor for a digest algorithm of the profile.
func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, func() hash.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, sha256.New, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, sha512.New384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, sha512.New, nil
	}
	return 0, nil, &UnsupportedAlgorithmError{OID: oid, Use: "digest"}
}

// pssSHA256Params is RSASSA-PSS-params for SHA-256, MGF1-SHA-256, a 32-byte
// salt and the default trailer.
func pssSHA256Params() (asn1.RawValue, error) {
	sha := algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1Null}
	shaDER, err := asn1.Marshal(sha)
	if err != nil {
		return asn1.RawValue{}, err
	}
	b, err := asn1.Marshal(rsassaPSSParams{
		HashAlgorithm:    sha,
		MaskGenAlgorithm: algorithmIdentifier{Algorithm: oidMGF1, Parameters: asn1.RawValue{FullBytes: shaDER}},
		SaltLength:       sha256.Size,
		TrailerField:     1,
	})
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: b}, nil
}

// Sign produces a CMS SignedData over content with signer, whose certificate
// is chain[0]; the remaining chain certificates are included for the verifier.
// The signature algorithm follows the key: ECDSA P-256/SHA-256, ECDSA
// P-384/SHA-384, RSASSA-PSS/SHA-256 (keys ≥ MinRSABits) or Ed25519 (RFC 8419).
// Signed attributes always carry content-type, message-digest, signing-time
// and signingCertificateV2 (ESSCertIDv2 with SHA-256 over chain[0]).
//
// Content is hashed as it is read; with opts.Detached false it is also
// buffered to be embedded in the result.
func Sign(content io.Reader, signer crypto.Signer, chain []*x509.Certificate, opts *SignOptions) ([]byte, error) {
	if opts == nil {
		opts = &SignOptions{}
	}
	if signer == nil || len(chain) == 0 || chain[0] == nil {
		return nil, errors.New("cryptomsg: Sign needs a signer and its certificate as chain[0]")
	}
	cert := chain[0]
	if !publicKeysEqual(cert.PublicKey, signer.Public()) {
		return nil, fmt.Errorf("%w: signer key does not match chain[0]", ErrKeyMismatch)
	}
	suite, err := suiteForPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	random := opts.Rand
	if random == nil {
		random = rand.Reader
	}
	contentType := opts.ContentType
	if contentType == nil {
		contentType = oidData
	}
	signingTime := opts.SigningTime
	if signingTime.IsZero() {
		signingTime = time.Now()
	}
	signingTime = signingTime.UTC().Truncate(time.Second)

	// Digest the content, keeping it only for the attached form.
	h := suite.hash.New()
	var buffered bytes.Buffer
	var sink io.Writer = h
	if !opts.Detached {
		sink = io.MultiWriter(h, &buffered)
	}
	if _, err := io.Copy(sink, content); err != nil {
		return nil, err
	}
	messageDigest := h.Sum(nil)

	signedAttrsDER, err := buildSignedAttributes(contentType, messageDigest, signingTime, cert)
	if err != nil {
		return nil, err
	}
	signature, err := signBytes(random, signer, suite, signedAttrsDER)
	if err != nil {
		return nil, err
	}

	sid, err := encodeRecipientID(cert, opts.SignerIdentifier, false)
	if err != nil {
		return nil, err
	}
	sigAlg := algorithmIdentifier{Algorithm: suite.signatureOID}
	if suite == &suiteRSAPSS {
		if sigAlg.Parameters, err = pssSHA256Params(); err != nil {
			return nil, err
		}
	}
	si := signerInfo{
		Version:            1,
		Sid:                sid,
		DigestAlgorithm:    algorithmIdentifier{Algorithm: suite.digestOID},
		SignedAttrs:        asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: contentOf(signedAttrsDER)},
		SignatureAlgorithm: sigAlg,
		Signature:          signature,
	}
	version := 1
	if opts.SignerIdentifier == SubjectKeyID {
		si.Version = 3
		version = 3
	}
	if !contentType.Equal(oidData) {
		version = 3
	}

	// CertificateSet is a SET OF: DER orders its members by encoding, not by
	// the chain order the caller gave.
	raws := make([][]byte, 0, len(chain))
	for _, c := range chain {
		if c == nil {
			return nil, errors.New("cryptomsg: nil certificate in chain")
		}
		raws = append(raws, c.Raw)
	}
	var certSet []byte
	for _, r := range ber.SortSetOf(raws) {
		certSet = append(certSet, r...)
	}
	eci := encapsulatedContentInfo{EContentType: contentType}
	if !opts.Detached {
		octets, err := asn1.Marshal(buffered.Bytes())
		if err != nil {
			return nil, err
		}
		eci.EContent = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: octets}
	}
	sd := signedData{
		Version:          version,
		DigestAlgorithms: []algorithmIdentifier{{Algorithm: suite.digestOID}},
		EncapContentInfo: eci,
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certSet},
		SignerInfos:      []signerInfo{si},
	}
	body, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	return encodeContentInfo(oidSignedData, body)
}

// buildSignedAttributes returns the DER of the SET OF Attribute (universal
// tag, X.690 ordering), which is what the signature covers.
func buildSignedAttributes(contentType asn1.ObjectIdentifier, messageDigest []byte, signingTime time.Time, cert *x509.Certificate) ([]byte, error) {
	certHash := sha256.Sum256(cert.Raw)
	issuerName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: cert.RawIssuer}
	ess := signingCertificateV2{Certs: []essCertIDv2{{
		CertHash:     certHash[:],
		IssuerSerial: issuerSerial{Issuer: []asn1.RawValue{issuerName}, SerialNumber: cert.SerialNumber},
	}}}
	attrs := []struct {
		oid   asn1.ObjectIdentifier
		value any
	}{
		{oidAttrContentType, contentType},
		{oidAttrMessageDigest, messageDigest},
		{oidAttrSigningTime, signingTime},
		{oidAttrSigningCertV2, ess},
	}
	elements := make([][]byte, 0, len(attrs))
	for _, a := range attrs {
		valueDER, err := asn1.Marshal(a.value)
		if err != nil {
			return nil, err
		}
		attrDER, err := asn1.Marshal(attribute{Type: a.oid, Values: []asn1.RawValue{{FullBytes: valueDER}}})
		if err != nil {
			return nil, err
		}
		elements = append(elements, attrDER)
	}
	var content []byte
	for _, e := range ber.SortSetOf(elements) {
		content = append(content, e...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: content})
}

// signBytes signs the DER signed attributes: Ed25519 signs them directly,
// the others sign their digest.
func signBytes(random io.Reader, signer crypto.Signer, suite *signatureSuite, signedAttrs []byte) ([]byte, error) {
	switch suite {
	case &suiteEd25519:
		return signer.Sign(random, signedAttrs, crypto.Hash(0))
	case &suiteRSAPSS:
		digest := sha256.Sum256(signedAttrs)
		return signer.Sign(random, digest[:], &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256})
	default:
		h := suite.hash.New()
		h.Write(signedAttrs)
		return signer.Sign(random, h.Sum(nil), suite.hash)
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}
