package cryptomsg

import (
	"encoding/asn1"
	"math/big"
	"time"
)

// ASN.1 structures of RFC 5652 §6, RFC 5083 and RFC 5753, as decoded by
// encoding/asn1 after BER normalisation. CHOICE members are kept as RawValue
// and dispatched on their tag.

// contentInfo's Content keeps the [0] EXPLICIT wrapper: encoding/asn1 does
// not unwrap an explicit tag into a RawValue, so the body is Content.Bytes.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type envelopedData struct {
	Version              int
	OriginatorInfo       asn1.RawValue   `asn1:"optional,tag:0"`
	RecipientInfos       []asn1.RawValue `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
	UnprotectedAttrs     asn1.RawValue `asn1:"optional,tag:1"`
}

type authEnvelopedData struct {
	Version                  int
	OriginatorInfo           asn1.RawValue   `asn1:"optional,tag:0"`
	RecipientInfos           []asn1.RawValue `asn1:"set"`
	AuthEncryptedContentInfo encryptedContentInfo
	AuthAttrs                asn1.RawValue `asn1:"optional,tag:1"`
	MAC                      []byte
	UnauthAttrs              asn1.RawValue `asn1:"optional,tag:2"`
}

// encryptedContentInfo's EncryptedContent is [0] IMPLICIT OCTET STRING; a
// streaming BER writer leaves it constructed, hence the RawValue.
type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"`
}

// gcmParameters is RFC 5084 §3.2 GCMParameters.
type gcmParameters struct {
	Nonce  []byte
	ICVLen int `asn1:"default:12"`
}

type keyTransRecipientInfo struct {
	Version                int
	Rid                    asn1.RawValue // IssuerAndSerialNumber or [0] SubjectKeyIdentifier
	KeyEncryptionAlgorithm algorithmIdentifier
	EncryptedKey           []byte
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// rsaesOAEPParams is RFC 8017 A.2.1 RSAES-OAEP-params.
type rsaesOAEPParams struct {
	HashAlgorithm    algorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGenAlgorithm algorithmIdentifier `asn1:"optional,explicit,tag:1"`
	PSourceAlgorithm algorithmIdentifier `asn1:"optional,explicit,tag:2"`
}

// keyAgreeRecipientInfo is the [1] IMPLICIT member of RecipientInfo.
type keyAgreeRecipientInfo struct {
	Version                int
	Originator             asn1.RawValue `asn1:"explicit,tag:0"` // OriginatorIdentifierOrKey
	UKM                    []byte        `asn1:"optional,explicit,tag:1"`
	KeyEncryptionAlgorithm algorithmIdentifier
	RecipientEncryptedKeys []recipientEncryptedKey
}

// originatorPublicKey is the [1] IMPLICIT member of OriginatorIdentifierOrKey.
type originatorPublicKey struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type recipientEncryptedKey struct {
	Rid          asn1.RawValue // IssuerAndSerialNumber or [0] RecipientKeyIdentifier
	EncryptedKey []byte
}

type recipientKeyIdentifier struct {
	SubjectKeyIdentifier []byte
	Date                 time.Time     `asn1:"optional,generalized"`
	Other                asn1.RawValue `asn1:"optional"`
}

// eccCMSSharedInfo is RFC 5753 §7.2 ECC-CMS-SharedInfo, the KDF SharedInfo.
type eccCMSSharedInfo struct {
	KeyInfo     algorithmIdentifier
	EntityUInfo []byte `asn1:"optional,explicit,tag:0"`
	SuppPubInfo []byte `asn1:"explicit,tag:2"`
}

// Tags of the CHOICE alternatives dispatched on above.
const (
	tagKeyTransRecipientInfo = 16 // universal SEQUENCE
	tagKeyAgreeRecipientInfo = 1  // [1] IMPLICIT
	tagSubjectKeyIdentifier  = 0  // [0] IMPLICIT in RecipientIdentifier and KeyAgreeRecipientIdentifier
	tagOriginatorKey         = 1  // [1] IMPLICIT OriginatorPublicKey
)

var asn1Null = asn1.RawValue{Tag: asn1.TagNull, FullBytes: []byte{0x05, 0x00}}
