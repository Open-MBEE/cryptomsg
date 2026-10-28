package cryptomsg

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
)

// Kind is the CMS content type of a parsed object.
type Kind int

const (
	// KindEnvelopedData is RFC 5652 §6 EnvelopedData.
	KindEnvelopedData Kind = iota + 1
	// KindAuthEnvelopedData is RFC 5083 AuthEnvelopedData.
	KindAuthEnvelopedData
	// KindSignedData is RFC 5652 §5 SignedData.
	KindSignedData
)

func (k Kind) String() string {
	switch k {
	case KindEnvelopedData:
		return "EnvelopedData"
	case KindAuthEnvelopedData:
		return "AuthEnvelopedData"
	case KindSignedData:
		return "SignedData"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// Info is the key-free view of a CMS object returned by Parse: enough to
// report "encrypted for 3 recipients" or "signed by CN=…" before deciding to
// decrypt or verify. Nothing in it has been authenticated.
type Info struct {
	Kind Kind
	// ContentType is the inner content type (id-data for plain payloads).
	ContentType asn1.ObjectIdentifier

	// Recipients lists the RecipientInfos of an envelope.
	Recipients []RecipientInfo
	// ContentEncryption is the content-encryption algorithm of an envelope.
	ContentEncryption asn1.ObjectIdentifier
	// EncryptedSize is the ciphertext length in bytes.
	EncryptedSize int

	// Signers lists the SignerInfos of a SignedData.
	Signers []SignerInfo
	// Certificates are the certificates carried in a SignedData.
	Certificates []*x509.Certificate
	// Attached reports whether a SignedData carries its content.
	Attached bool
}

// RecipientInfo describes one RecipientInfo without any key material.
type RecipientInfo struct {
	// Identifier is how the recipient is named: IssuerAndSerial or
	// SubjectKeyID; -1 for a RecipientInfo alternative outside the profile.
	Identifier RecipientIdentifierKind
	// Description renders the identifier, e.g. "issuer=CN=CA serial=42".
	Description string
	// KeyAlgorithm is the key-transport or key-agreement algorithm OID.
	KeyAlgorithm asn1.ObjectIdentifier
	// Supported reports whether Decrypt could use this RecipientInfo.
	Supported bool
}

// SignerInfo describes one SignerInfo without verifying anything.
type SignerInfo struct {
	// Description renders the signer identifier.
	Description string
	// Certificate is the signer certificate when the SignedData carries it.
	Certificate *x509.Certificate
	// DigestAlgorithm and SignatureAlgorithm are as declared.
	DigestAlgorithm    asn1.ObjectIdentifier
	SignatureAlgorithm asn1.ObjectIdentifier
	// HasSignedAttributes reports whether signedAttrs is present.
	HasSignedAttributes bool
}

// recipientSupported reports whether Decrypt would accept the RecipientInfo's
// algorithms and parameters, judged without any key.
func recipientSupported(r *recipientInfo) bool {
	switch {
	case r.ktri != nil:
		return checkOAEPParams(r.ktri.KeyEncryptionAlgorithm) == nil
	case r.kari != nil:
		known := false
		for i := range ecdhSuites {
			known = known || r.kari.KeyEncryptionAlgorithm.Algorithm.Equal(ecdhSuites[i].schemeOID)
		}
		if !known {
			return false
		}
		var wrapAlg algorithmIdentifier
		if rest, err := asn1.Unmarshal(r.kari.KeyEncryptionAlgorithm.Parameters.FullBytes, &wrapAlg); err != nil || len(rest) != 0 {
			return false
		}
		_, err := kekLenForWrap(wrapAlg.Algorithm)
		return err == nil
	}
	return false
}

// Parse decodes a CMS object (DER or BER) into its key-free view. It refuses
// malformed input and content types outside the profile with typed errors
// and performs no cryptography.
//
// The whole object is read into memory; bound untrusted input by wrapping
// data in an io.LimitReader, a cut-off object is refused as malformed.
func Parse(data io.Reader) (*Info, error) {
	raw, err := io.ReadAll(data)
	if err != nil {
		return nil, err
	}
	der, err := normalizeInput(raw)
	if err != nil {
		return nil, err
	}
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) != 0 {
		if err == nil {
			err = errTrailingData
		}
		return nil, malformed("ContentInfo", err)
	}
	switch {
	case ci.ContentType.Equal(oidEnvelopedData), ci.ContentType.Equal(oidAuthEnvelopedData):
		env, err := parseEnvelope(der)
		if err != nil {
			return nil, err
		}
		info := &Info{Kind: KindEnvelopedData, ContentType: env.ContentType, ContentEncryption: env.Cipher.Algorithm, EncryptedSize: len(env.Ciphertext)}
		if env.Authenticated {
			info.Kind = KindAuthEnvelopedData
		}
		for _, r := range env.Recipients {
			info.Recipients = append(info.Recipients, RecipientInfo{
				Identifier:   r.ID.Kind,
				Description:  r.ID.String(),
				KeyAlgorithm: r.Alg,
				Supported:    recipientSupported(&r),
			})
		}
		return info, nil
	case ci.ContentType.Equal(oidSignedData):
		msg, err := parseSignedData(der)
		if err != nil {
			return nil, err
		}
		info := &Info{Kind: KindSignedData, ContentType: msg.ContentType, Certificates: msg.Certificates, Attached: msg.Attached}
		for i := range msg.Signers {
			si := &msg.Signers[i]
			id, err := parseRecipientID(si.Sid, false)
			if err != nil {
				return nil, err
			}
			s := SignerInfo{
				Description:         id.String(),
				DigestAlgorithm:     si.DigestAlgorithm.Algorithm,
				SignatureAlgorithm:  si.SignatureAlgorithm.Algorithm,
				HasSignedAttributes: len(si.SignedAttrs.FullBytes) != 0,
			}
			s.Certificate = inspectSignerCertificate(si, id, msg.Certificates)
			info.Signers = append(info.Signers, s)
		}
		return info, nil
	}
	return nil, fmt.Errorf("%w: %v", ErrUnsupportedStructure, ci.ContentType)
}

// inspectSignerCertificate names the carried certificate a SignerInfo is for,
// without verifying anything. Several certificates can share a key identifier;
// then the (unverified) first ESSCertIDv2 picks, as Verify does after checking
// the signature, and nothing is named when it picks none.
func inspectSignerCertificate(si *signerInfo, id recipientID, carried []*x509.Certificate) *x509.Certificate {
	var matches []*x509.Certificate
	for _, c := range carried {
		if c != nil && id.matches(c) {
			matches = append(matches, c)
		}
	}
	if len(matches) <= 1 {
		if len(matches) == 1 {
			return matches[0]
		}
		return nil
	}
	attrs, err := parseSignedAttributes(si.SignedAttrs)
	if err != nil {
		return nil
	}
	for _, c := range matches {
		if checkSigningCertificate(attrs, c) == nil {
			return c
		}
	}
	return nil
}
