package cryptomsg

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// RecipientIdentifierKind says how a RecipientInfo names its recipient.
type RecipientIdentifierKind int

const (
	// IssuerAndSerial identifies the recipient certificate by issuer name and
	// serial number (RFC 5652 §6.2.1 IssuerAndSerialNumber).
	IssuerAndSerial RecipientIdentifierKind = iota
	// SubjectKeyID identifies it by the SubjectKeyIdentifier extension.
	SubjectKeyID
)

func (k RecipientIdentifierKind) String() string {
	switch k {
	case IssuerAndSerial:
		return "IssuerAndSerialNumber"
	case SubjectKeyID:
		return "SubjectKeyIdentifier"
	}
	return fmt.Sprintf("RecipientIdentifierKind(%d)", int(k))
}

// recipientID is a decoded RecipientIdentifier / KeyAgreeRecipientIdentifier.
type recipientID struct {
	Kind         RecipientIdentifierKind
	Issuer       []byte // DER Name, when Kind == IssuerAndSerial
	SerialNumber *big.Int
	SubjectKeyID []byte
}

// matches reports whether the identifier names cert.
func (r recipientID) matches(cert *x509.Certificate) bool {
	switch r.Kind {
	case IssuerAndSerial:
		return r.SerialNumber != nil && cert.SerialNumber != nil &&
			r.SerialNumber.Cmp(cert.SerialNumber) == 0 && bytes.Equal(r.Issuer, cert.RawIssuer)
	case SubjectKeyID:
		return len(r.SubjectKeyID) > 0 && bytes.Equal(r.SubjectKeyID, cert.SubjectKeyId)
	}
	return false
}

// String renders the identifier for reports; it never contains key material.
func (r recipientID) String() string {
	switch r.Kind {
	case IssuerAndSerial:
		var rdn pkixName
		if _, err := asn1.Unmarshal(r.Issuer, &rdn); err == nil {
			return fmt.Sprintf("issuer=%s serial=%s", rdn, r.SerialNumber)
		}
		return fmt.Sprintf("serial=%s", r.SerialNumber)
	case SubjectKeyID:
		return fmt.Sprintf("ski=%x", r.SubjectKeyID)
	}
	return "unknown"
}

// parseRecipientID decodes the CHOICE: a SEQUENCE is IssuerAndSerialNumber,
// [0] is a SubjectKeyIdentifier (KeyTrans) or RecipientKeyIdentifier (KeyAgree).
func parseRecipientID(raw asn1.RawValue, keyAgree bool) (recipientID, error) {
	switch {
	case raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence:
		var ias issuerAndSerialNumber
		if rest, err := asn1.Unmarshal(raw.FullBytes, &ias); err != nil || len(rest) != 0 {
			return recipientID{}, malformed("IssuerAndSerialNumber", err)
		}
		return recipientID{Kind: IssuerAndSerial, Issuer: ias.Issuer.FullBytes, SerialNumber: ias.SerialNumber}, nil
	case raw.Class == asn1.ClassContextSpecific && raw.Tag == tagSubjectKeyIdentifier:
		if !keyAgree {
			if raw.IsCompound {
				return recipientID{}, malformed("SubjectKeyIdentifier", errConstructed)
			}
			return recipientID{Kind: SubjectKeyID, SubjectKeyID: raw.Bytes}, nil
		}
		var rki recipientKeyIdentifier
		seq := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: raw.Bytes}
		full, err := asn1.Marshal(seq)
		if err != nil {
			return recipientID{}, malformed("RecipientKeyIdentifier", err)
		}
		if rest, err := asn1.Unmarshal(full, &rki); err != nil || len(rest) != 0 {
			return recipientID{}, malformed("RecipientKeyIdentifier", err)
		}
		return recipientID{Kind: SubjectKeyID, SubjectKeyID: rki.SubjectKeyIdentifier}, nil
	}
	return recipientID{}, malformed("RecipientIdentifier", fmt.Errorf("unexpected tag class %d number %d", raw.Class, raw.Tag))
}

// encodeRecipientID encodes the identifier for cert in the requested form.
func encodeRecipientID(cert *x509.Certificate, kind RecipientIdentifierKind, keyAgree bool) (asn1.RawValue, error) {
	switch kind {
	case IssuerAndSerial:
		b, err := asn1.Marshal(issuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		})
		if err != nil {
			return asn1.RawValue{}, err
		}
		return asn1.RawValue{FullBytes: b}, nil
	case SubjectKeyID:
		if len(cert.SubjectKeyId) == 0 {
			return asn1.RawValue{}, fmt.Errorf("cryptomsg: certificate %q has no SubjectKeyIdentifier", cert.Subject)
		}
		if !keyAgree {
			return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tagSubjectKeyIdentifier, Bytes: cert.SubjectKeyId}, nil
		}
		inner, err := asn1.Marshal(cert.SubjectKeyId)
		if err != nil {
			return asn1.RawValue{}, err
		}
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tagSubjectKeyIdentifier, IsCompound: true, Bytes: inner}, nil
	}
	return asn1.RawValue{}, fmt.Errorf("cryptomsg: unknown recipient identifier kind %d", int(kind))
}

// pkixName is the minimal Name decoder used only for diagnostics.
type pkixName []asn1.RawValue

func (n pkixName) String() string {
	var buf bytes.Buffer
	for i, rdnSet := range n {
		var atv struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if _, err := asn1.Unmarshal(rdnSet.Bytes, &atv); err != nil {
			continue
		}
		if i > 0 {
			buf.WriteString(",")
		}
		var s string
		if _, err := asn1.Unmarshal(atv.Value.FullBytes, &s); err != nil {
			s = fmt.Sprintf("#%x", atv.Value.Bytes)
		}
		fmt.Fprintf(&buf, "%s=%s", attributeTypeName(atv.Type), s)
	}
	return buf.String()
}

func attributeTypeName(oid asn1.ObjectIdentifier) string {
	switch oid.String() {
	case "2.5.4.3":
		return "CN"
	case "2.5.4.6":
		return "C"
	case "2.5.4.7":
		return "L"
	case "2.5.4.8":
		return "ST"
	case "2.5.4.10":
		return "O"
	case "2.5.4.11":
		return "OU"
	}
	return oid.String()
}
