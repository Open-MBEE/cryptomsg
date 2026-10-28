package cryptomsg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/Open-MBEE/cryptomsg/internal/ber"
	"hash"
	"io"
	"time"
)

// ErrSignerCertificateMissing reports a SignerInfo whose certificate is
// neither in the SignedData nor supplied by the caller.
var ErrSignerCertificateMissing = errors.New("cryptomsg: signer certificate not found")

// VerifiedSignature describes one SignerInfo whose signature verified.
type VerifiedSignature struct {
	// Signer is the certificate that made the signature.
	Signer *x509.Certificate
	// SigningTime is the signer's claimed signing-time attribute. It is a
	// claim, not evidence; validity is judged at the policy's time.
	SigningTime time.Time
	// ContentType is the eContentType the signature covers.
	ContentType asn1.ObjectIdentifier
	// Algorithm names the profile row, e.g. "ECDSA P-256 with SHA-256".
	Algorithm string
	// Certificates are all certificates carried in the SignedData.
	Certificates []*x509.Certificate
}

// signedMessage is the decoded, key-free view of a SignedData.
type signedMessage struct {
	Version      int
	ContentType  asn1.ObjectIdentifier
	Content      []byte // attached content, when Attached
	Attached     bool
	Certificates []*x509.Certificate
	Signers      []signerInfo
	digestOIDs   []asn1.ObjectIdentifier
}

// parseSignedData decodes a DER ContentInfo holding SignedData.
func parseSignedData(der []byte) (*signedMessage, error) {
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) != 0 {
		if err == nil {
			err = errTrailingData
		}
		return nil, malformed("ContentInfo", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedStructure, ci.ContentType)
	}
	var sd signedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) != 0 {
		return nil, malformed("SignedData", err)
	}
	msg := &signedMessage{Version: sd.Version, ContentType: sd.EncapContentInfo.EContentType, Signers: sd.SignerInfos}
	for _, d := range sd.DigestAlgorithms {
		msg.digestOIDs = append(msg.digestOIDs, d.Algorithm)
	}
	if ec := sd.EncapContentInfo.EContent; len(ec.FullBytes) != 0 {
		var octets []byte
		if rest, err := asn1.Unmarshal(ec.Bytes, &octets); err != nil || len(rest) != 0 {
			return nil, malformed("eContent", err)
		}
		msg.Content = octets
		msg.Attached = true
	}
	if len(sd.Certificates.FullBytes) != 0 {
		rest := sd.Certificates.Bytes
		for len(rest) > 0 {
			var raw asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
				return nil, malformed("CertificateSet", err)
			}
			if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
				// extendedCertificate, v1AttrCert, v2AttrCert, other: skipped,
				// as RFC 5652 §10.2.3 allows.
				continue
			}
			cert, err := x509.ParseCertificate(raw.FullBytes)
			if err != nil {
				return nil, malformed("certificate", err)
			}
			msg.Certificates = append(msg.Certificates, cert)
		}
	}
	if len(msg.Signers) == 0 {
		return nil, malformed("SignerInfos", errors.New("empty"))
	}
	return msg, nil
}

// signerCertificates finds every certificate a SignerInfo's sid names: a
// SubjectKeyIdentifier identifies a key, which renewed certificates share,
// so the signed ESSCertIDv2 picks among them.
func (msg *signedMessage) signerCertificates(si *signerInfo, extra []*x509.Certificate) ([]*x509.Certificate, error) {
	id, err := parseRecipientID(si.Sid, false)
	if err != nil {
		return nil, err
	}
	if (id.Kind == SubjectKeyID) != (si.Version == 3) {
		return nil, malformed("SignerInfo", fmt.Errorf("version %d with %s", si.Version, id.Kind))
	}
	var found []*x509.Certificate
	for _, set := range [][]*x509.Certificate{msg.Certificates, extra} {
		for _, c := range set {
			if c != nil && id.matches(c) {
				found = append(found, c)
			}
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrSignerCertificateMissing, id)
	}
	return found, nil
}

// signedAttributes is the decoded mandatory attribute set.
type signedAttributes struct {
	der           []byte // DER of the SET OF Attribute, what the signature covers
	contentType   asn1.ObjectIdentifier
	messageDigest []byte
	signingTime   time.Time
	signingCert   signingCertificateV2
}

// parseSignedAttributes decodes the [0] IMPLICIT SignedAttributes, requiring
// each mandatory attribute exactly once with exactly one value.
func parseSignedAttributes(raw asn1.RawValue) (*signedAttributes, error) {
	if len(raw.FullBytes) == 0 {
		return nil, fmt.Errorf("%w: signedAttrs absent", ErrMissingSignedAttribute)
	}
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 || !raw.IsCompound {
		return nil, malformed("signedAttrs", errors.New("unexpected tag"))
	}
	// What was signed is the DER of the SET (RFC 5652 §5.4): members in SET OF
	// order, whatever order BER input carried them in.
	members, err := ber.CanonicalSetOf(raw.Bytes)
	if err != nil {
		return nil, malformed("signedAttrs", err)
	}
	setDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: members})
	if err != nil {
		return nil, malformed("signedAttrs", err)
	}
	var attrs []attribute
	if rest, err := asn1.UnmarshalWithParams(setDER, &attrs, "set"); err != nil || len(rest) != 0 {
		return nil, malformed("signedAttrs", err)
	}
	out := &signedAttributes{der: setDER}
	seen := map[string]bool{}
	for _, a := range attrs {
		key := a.Type.String()
		if seen[key] {
			return nil, malformed("signedAttrs", fmt.Errorf("attribute %v repeated", a.Type))
		}
		seen[key] = true
		single := func(dst any) error {
			if len(a.Values) != 1 {
				return malformed("signedAttrs", fmt.Errorf("attribute %v has %d values", a.Type, len(a.Values)))
			}
			if rest, err := asn1.Unmarshal(a.Values[0].FullBytes, dst); err != nil || len(rest) != 0 {
				return malformed(fmt.Sprintf("attribute %v", a.Type), err)
			}
			return nil
		}
		switch {
		case a.Type.Equal(oidAttrContentType):
			err = single(&out.contentType)
		case a.Type.Equal(oidAttrMessageDigest):
			err = single(&out.messageDigest)
		case a.Type.Equal(oidAttrSigningTime):
			err = single(&out.signingTime)
		case a.Type.Equal(oidAttrSigningCertV2):
			err = single(&out.signingCert)
		}
		if err != nil {
			return nil, err
		}
	}
	for _, m := range []struct {
		oid  asn1.ObjectIdentifier
		name string
	}{{oidAttrContentType, "content-type"}, {oidAttrMessageDigest, "message-digest"}, {oidAttrSigningTime, "signing-time"}, {oidAttrSigningCertV2, "signingCertificateV2"}} {
		if !seen[m.oid.String()] {
			return nil, fmt.Errorf("%w: %s", ErrMissingSignedAttribute, m.name)
		}
	}
	if len(out.signingCert.Certs) == 0 {
		return nil, malformed("signingCertificateV2", errors.New("no ESSCertIDv2"))
	}
	return out, nil
}

// checkSigningCertificate requires the first ESSCertIDv2 — RFC 5035 §4 makes
// it the signer's — to hash to the signer certificate (and, when present,
// name its issuer and serial).
func checkSigningCertificate(attrs *signedAttributes, cert *x509.Certificate) error {
	for _, id := range attrs.signingCert.Certs[:1] {
		hashOID := oidSHA256
		if id.HashAlgorithm.Algorithm != nil {
			hashOID = id.HashAlgorithm.Algorithm
		}
		_, newHash, err := hashFor(hashOID)
		if err != nil {
			return err
		}
		h := newHash()
		h.Write(cert.Raw)
		if subtle.ConstantTimeCompare(h.Sum(nil), id.CertHash) != 1 {
			continue
		}
		if id.IssuerSerial.SerialNumber != nil {
			if id.IssuerSerial.SerialNumber.Cmp(cert.SerialNumber) != 0 {
				continue
			}
			matched := false
			for _, gn := range id.IssuerSerial.Issuer {
				if gn.Class == asn1.ClassContextSpecific && gn.Tag == 4 && bytes.Equal(gn.Bytes, cert.RawIssuer) {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		return nil
	}
	return fmt.Errorf("%w: signingCertificateV2 does not name the signer certificate", ErrSignatureInvalid)
}

// verifySigners checks every SignerInfo of msg over the content (attached in
// msg, or supplied through content for a detached signature), using the
// certificates of the message plus extra to find signers. All must verify.
func verifySigners(msg *signedMessage, content io.Reader, extra []*x509.Certificate) ([]*VerifiedSignature, error) {
	switch {
	case msg.Attached && content != nil:
		return nil, ErrContentMismatch
	case !msg.Attached && content == nil:
		return nil, ErrDetachedContentRequired
	}

	// Resolve every signer's suite first so the content is read once, into
	// one hash per digest algorithm.
	type pending struct {
		si    *signerInfo
		cert  *x509.Certificate
		suite *signatureSuite
		attrs *signedAttributes
	}
	var work []pending
	hashes := map[string]hash.Hash{}
	for i := range msg.Signers {
		si := &msg.Signers[i]
		candidates, err := msg.signerCertificates(si, extra)
		if err != nil {
			return nil, err
		}
		attrs, err := parseSignedAttributes(si.SignedAttrs)
		if err != nil {
			return nil, err
		}
		var cert *x509.Certificate
		for _, c := range candidates {
			if err = checkSigningCertificate(attrs, c); err == nil {
				cert = c
				break
			}
		}
		if cert == nil {
			return nil, err
		}
		suite, err := suiteForPublicKey(cert.PublicKey)
		if err != nil {
			return nil, err
		}
		if !si.DigestAlgorithm.Algorithm.Equal(suite.digestOID) {
			return nil, &UnsupportedAlgorithmError{OID: si.DigestAlgorithm.Algorithm, Use: "digest for " + suite.name}
		}
		if !containsOID(msg.digestOIDs, suite.digestOID) {
			return nil, malformed("digestAlgorithms", fmt.Errorf("%v not listed", suite.digestOID))
		}
		if err := checkSignatureAlgorithm(si.SignatureAlgorithm, suite); err != nil {
			return nil, err
		}
		if !attrs.contentType.Equal(msg.ContentType) {
			return nil, fmt.Errorf("%w: content-type attribute %v, eContentType %v", ErrSignatureInvalid, attrs.contentType, msg.ContentType)
		}
		if _, ok := hashes[suite.digestOID.String()]; !ok {
			hashes[suite.digestOID.String()] = suite.hash.New()
		}
		work = append(work, pending{si, cert, suite, attrs})
	}

	var sinks []io.Writer
	for _, h := range hashes {
		sinks = append(sinks, h)
	}
	if msg.Attached {
		content = bytes.NewReader(msg.Content)
	}
	if _, err := io.Copy(io.MultiWriter(sinks...), content); err != nil {
		return nil, err
	}
	digests := map[string][]byte{}
	for k, h := range hashes {
		digests[k] = h.Sum(nil)
	}

	var out []*VerifiedSignature
	for _, p := range work {
		if subtle.ConstantTimeCompare(digests[p.suite.digestOID.String()], p.attrs.messageDigest) != 1 {
			return nil, fmt.Errorf("%w: message-digest mismatch", ErrSignatureInvalid)
		}
		if err := verifyBytes(p.cert.PublicKey, p.suite, p.si.SignatureAlgorithm, p.attrs.der, p.si.Signature); err != nil {
			return nil, err
		}
		out = append(out, &VerifiedSignature{
			Signer:       p.cert,
			SigningTime:  p.attrs.signingTime,
			ContentType:  msg.ContentType,
			Algorithm:    p.suite.name,
			Certificates: msg.Certificates,
		})
	}
	return out, nil
}

func containsOID(list []asn1.ObjectIdentifier, oid asn1.ObjectIdentifier) bool {
	for _, o := range list {
		if o.Equal(oid) {
			return true
		}
	}
	return false
}

// checkSignatureAlgorithm requires the SignerInfo's signatureAlgorithm to be
// the suite's, with PSS parameters of the profile.
func checkSignatureAlgorithm(alg algorithmIdentifier, suite *signatureSuite) error {
	if !alg.Algorithm.Equal(suite.signatureOID) {
		return &UnsupportedAlgorithmError{OID: alg.Algorithm, Use: "signature for " + suite.name}
	}
	if suite == &suiteRSAPSS {
		if _, err := pssSaltLength(alg); err != nil {
			return err
		}
	}
	return nil
}

// pssSaltLength checks RSASSA-PSS-params for SHA-256 / MGF1-SHA-256 / trailer
// 1 and returns the declared salt length.
func pssSaltLength(alg algorithmIdentifier) (int, error) {
	if len(alg.Parameters.FullBytes) == 0 {
		// All defaults: SHA-1.
		return 0, &UnsupportedAlgorithmError{OID: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, Use: "PSS hash"}
	}
	var p rsassaPSSParams
	if rest, err := asn1.Unmarshal(alg.Parameters.FullBytes, &p); err != nil || len(rest) != 0 {
		return 0, malformed("RSASSA-PSS-params", err)
	}
	if p.HashAlgorithm.Algorithm == nil || !p.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		oid := p.HashAlgorithm.Algorithm
		if oid == nil {
			oid = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
		}
		return 0, &UnsupportedAlgorithmError{OID: oid, Use: "PSS hash"}
	}
	if p.MaskGenAlgorithm.Algorithm == nil || !p.MaskGenAlgorithm.Algorithm.Equal(oidMGF1) {
		oid := p.MaskGenAlgorithm.Algorithm
		if oid == nil {
			oid = oidMGF1
		}
		return 0, &UnsupportedAlgorithmError{OID: oid, Use: "PSS mask generation"}
	}
	var mgfHash algorithmIdentifier
	if rest, err := asn1.Unmarshal(p.MaskGenAlgorithm.Parameters.FullBytes, &mgfHash); err != nil || len(rest) != 0 {
		return 0, malformed("MGF1 parameters", err)
	}
	if !mgfHash.Algorithm.Equal(oidSHA256) {
		return 0, &UnsupportedAlgorithmError{OID: mgfHash.Algorithm, Use: "PSS MGF1 hash"}
	}
	if p.TrailerField != 1 {
		return 0, malformed("RSASSA-PSS-params", fmt.Errorf("trailerField %d", p.TrailerField))
	}
	if p.SaltLength < 0 || p.SaltLength > 512 {
		return 0, malformed("RSASSA-PSS-params", fmt.Errorf("saltLength %d", p.SaltLength))
	}
	return p.SaltLength, nil
}

// verifyBytes checks signature over the DER signed attributes.
func verifyBytes(pub crypto.PublicKey, suite *signatureSuite, alg algorithmIdentifier, signedAttrs, signature []byte) error {
	ok := false
	switch suite {
	case &suiteEd25519:
		k, isEd := pub.(ed25519.PublicKey)
		ok = isEd && len(signature) == ed25519.SignatureSize && ed25519.Verify(k, signedAttrs, signature)
	case &suiteRSAPSS:
		k, isRSA := pub.(*rsa.PublicKey)
		salt, err := pssSaltLength(alg)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(signedAttrs)
		ok = isRSA && rsa.VerifyPSS(k, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: salt, Hash: crypto.SHA256}) == nil
	default:
		k, isEC := pub.(*ecdsa.PublicKey)
		h := suite.hash.New()
		h.Write(signedAttrs)
		ok = isEC && ecdsa.VerifyASN1(k, h.Sum(nil), signature)
	}
	if !ok {
		return ErrSignatureInvalid
	}
	return nil
}
