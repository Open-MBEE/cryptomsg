package cryptomsg

import "encoding/asn1"

// Object identifiers of the profile. Everything the library emits is one of
// these; anything else on input is refused with *UnsupportedAlgorithmError.
var (
	// CMS content types (RFC 5652 §4–§6, RFC 5083).
	oidData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidAuthEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}

	// Content encryption (RFC 3565 CBC, RFC 5084 GCM).
	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}

	// Key wrap (RFC 3394 / RFC 3565).
	oidAES128Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 5}
	oidAES256Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}

	// Key transport (RFC 3560).
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidPSpecified    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 9}

	// Key agreement (RFC 5753): ephemeral-static ECDH, standard (X9.63) KDF.
	oidDHSinglePassStdDHSHA256KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 1}
	oidDHSinglePassStdDHSHA384KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 2}
	oidECPublicKey                = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP256             = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384             = asn1.ObjectIdentifier{1, 3, 132, 0, 34}

	// Digests.
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Signatures.
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	// Signed attributes (RFC 5652 §11, RFC 5035).
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttrSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)
