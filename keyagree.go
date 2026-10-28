package cryptomsg

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/Open-MBEE/cryptomsg/internal/kdf"
	"github.com/Open-MBEE/cryptomsg/internal/keywrap"
)

// ecdhSuite binds a curve to its RFC 5753 key-agreement algorithm and KDF hash.
type ecdhSuite struct {
	curve     ecdh.Curve
	curveOID  asn1.ObjectIdentifier
	schemeOID asn1.ObjectIdentifier
	hash      func() hash.Hash
}

var ecdhSuites = []ecdhSuite{
	{ecdh.P256(), oidNamedCurveP256, oidDHSinglePassStdDHSHA256KDF, sha256.New},
	{ecdh.P384(), oidNamedCurveP384, oidDHSinglePassStdDHSHA384KDF, sha512.New384},
}

// ecdhRecipientKey returns the certificate's EC key as a crypto/ecdh key and
// its suite, refusing curves outside the profile.
func ecdhRecipientKey(cert *x509.Certificate) (*ecdh.PublicKey, *ecdhSuite, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("cryptomsg: certificate %q does not carry an EC key", cert.Subject)
	}
	epub, err := pub.ECDH()
	if err != nil {
		return nil, nil, &UnsupportedAlgorithmError{OID: oidECPublicKey, Use: "key agreement curve"}
	}
	for i := range ecdhSuites {
		if ecdhSuites[i].curve == epub.Curve() {
			return epub, &ecdhSuites[i], nil
		}
	}
	return nil, nil, &UnsupportedAlgorithmError{OID: oidECPublicKey, Use: "key agreement curve"}
}

// wrapOID selects the AES key-wrap algorithm whose KEK is as long as the CEK.
func wrapOID(cekLen int) (asn1.ObjectIdentifier, error) {
	switch cekLen {
	case 16:
		return oidAES128Wrap, nil
	case 32:
		return oidAES256Wrap, nil
	}
	return nil, fmt.Errorf("cryptomsg: no key wrap for a %d-byte content-encryption key", cekLen)
}

func kekLenForWrap(oid asn1.ObjectIdentifier) (int, error) {
	switch {
	case oid.Equal(oidAES128Wrap):
		return 16, nil
	case oid.Equal(oidAES256Wrap):
		return 32, nil
	}
	return 0, &UnsupportedAlgorithmError{OID: oid, Use: "key wrap"}
}

// deriveKEK runs the X9.63 KDF over the ECDH shared secret with
// ECC-CMS-SharedInfo (RFC 5753 §7.2) naming the wrap algorithm and KEK length.
func deriveKEK(suite *ecdhSuite, shared []byte, wrap asn1.ObjectIdentifier, ukm []byte, kekLen int) ([]byte, error) {
	if kekLen != 16 && kekLen != 32 {
		return nil, fmt.Errorf("cryptomsg: unexpected KEK length %d", kekLen)
	}
	var supp [4]byte
	binary.BigEndian.PutUint32(supp[:], uint32(kekLen*8))
	info, err := asn1.Marshal(eccCMSSharedInfo{
		KeyInfo:     algorithmIdentifier{Algorithm: wrap},
		EntityUInfo: ukm,
		SuppPubInfo: supp[:],
	})
	if err != nil {
		return nil, err
	}
	return kdf.X963(suite.hash, shared, info, kekLen)
}

// encodeKeyAgree builds a KeyAgreeRecipientInfo for one recipient with a fresh
// ephemeral key: one RecipientEncryptedKey per structure, which is what
// OpenSSL and BouncyCastle also produce.
func encodeKeyAgree(random io.Reader, cert *x509.Certificate, kind RecipientIdentifierKind, cek []byte) (asn1.RawValue, error) {
	pub, suite, err := ecdhRecipientKey(cert)
	if err != nil {
		return asn1.RawValue{}, err
	}
	rid, err := encodeRecipientID(cert, kind, true)
	if err != nil {
		return asn1.RawValue{}, err
	}
	wrap, err := wrapOID(len(cek))
	if err != nil {
		return asn1.RawValue{}, err
	}
	eph, err := suite.curve.GenerateKey(random)
	if err != nil {
		return asn1.RawValue{}, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return asn1.RawValue{}, err
	}
	kek, err := deriveKEK(suite, shared, wrap, nil, len(cek))
	clear(shared)
	if err != nil {
		return asn1.RawValue{}, err
	}
	block, err := aes.NewCipher(kek)
	clear(kek)
	if err != nil {
		return asn1.RawValue{}, err
	}
	wrapped, err := keywrap.Wrap(block, cek)
	if err != nil {
		return asn1.RawValue{}, err
	}

	curveDER, err := asn1.Marshal(suite.curveOID)
	if err != nil {
		return asn1.RawValue{}, err
	}
	opk, err := asn1.Marshal(originatorPublicKey{
		Algorithm: algorithmIdentifier{Algorithm: oidECPublicKey, Parameters: asn1.RawValue{FullBytes: curveDER}},
		PublicKey: asn1.BitString{Bytes: eph.PublicKey().Bytes(), BitLength: 8 * len(eph.PublicKey().Bytes())},
	})
	if err != nil {
		return asn1.RawValue{}, err
	}
	wrapAlg, err := asn1.Marshal(algorithmIdentifier{Algorithm: wrap})
	if err != nil {
		return asn1.RawValue{}, err
	}
	// Originator is [0] EXPLICIT around the CHOICE; originatorKey is [1]
	// IMPLICIT. The explicit wrapper is built by hand (see encodeContentInfo).
	originatorKey, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tagOriginatorKey, IsCompound: true, Bytes: contentOf(opk)})
	if err != nil {
		return asn1.RawValue{}, err
	}
	originator := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: originatorKey}
	body, err := asn1.Marshal(keyAgreeRecipientInfo{
		Version:                3,
		Originator:             originator,
		KeyEncryptionAlgorithm: algorithmIdentifier{Algorithm: suite.schemeOID, Parameters: asn1.RawValue{FullBytes: wrapAlg}},
		RecipientEncryptedKeys: []recipientEncryptedKey{{Rid: rid, EncryptedKey: wrapped}},
	})
	if err != nil {
		return asn1.RawValue{}, err
	}
	// RecipientInfo's kari alternative is [1] IMPLICIT.
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tagKeyAgreeRecipientInfo, IsCompound: true, Bytes: contentOf(body)}, nil
}

// contentOf strips the outer tag and length of a DER element.
func contentOf(der []byte) []byte {
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		return nil
	}
	return rv.Bytes
}

// parseKeyAgree decodes the [1] IMPLICIT KeyAgreeRecipientInfo.
func parseKeyAgree(raw asn1.RawValue) (*keyAgreeRecipientInfo, error) {
	seq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: raw.Bytes})
	if err != nil {
		return nil, malformed("KeyAgreeRecipientInfo", err)
	}
	var kari keyAgreeRecipientInfo
	if rest, err := asn1.Unmarshal(seq, &kari); err != nil || len(rest) != 0 {
		return nil, malformed("KeyAgreeRecipientInfo", err)
	}
	if kari.Version != 3 {
		return nil, malformed("KeyAgreeRecipientInfo", fmt.Errorf("version %d", kari.Version))
	}
	return &kari, nil
}

// decryptKeyAgree recovers the CEK from the RecipientEncryptedKey addressed to
// cert, using the holder's static ECDH key.
func decryptKeyAgree(kari *keyAgreeRecipientInfo, rek *recipientEncryptedKey, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	pub, suite, err := ecdhRecipientKey(cert)
	if err != nil {
		return nil, err
	}
	if !kari.KeyEncryptionAlgorithm.Algorithm.Equal(suite.schemeOID) {
		return nil, &UnsupportedAlgorithmError{OID: kari.KeyEncryptionAlgorithm.Algorithm, Use: "key agreement"}
	}
	var wrapAlg algorithmIdentifier
	if rest, err := asn1.Unmarshal(kari.KeyEncryptionAlgorithm.Parameters.FullBytes, &wrapAlg); err != nil || len(rest) != 0 {
		return nil, malformed("KeyWrapAlgorithm", err)
	}
	kekLen, err := kekLenForWrap(wrapAlg.Algorithm)
	if err != nil {
		return nil, err
	}

	// Originator keeps its [0] EXPLICIT wrapper (encoding/asn1 does not unwrap
	// into a RawValue); inside, the CHOICE must be originatorKey [1] carrying
	// an id-ecPublicKey point on the recipient's curve.
	var choice asn1.RawValue
	if rest, err := asn1.Unmarshal(kari.Originator.Bytes, &choice); err != nil || len(rest) != 0 {
		return nil, malformed("OriginatorIdentifierOrKey", err)
	}
	if choice.Class != asn1.ClassContextSpecific || choice.Tag != tagOriginatorKey || !choice.IsCompound {
		return nil, malformed("OriginatorIdentifierOrKey", fmt.Errorf("originator is not originatorKey"))
	}
	opkDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: choice.Bytes})
	if err != nil {
		return nil, malformed("OriginatorPublicKey", err)
	}
	var opk originatorPublicKey
	if rest, err := asn1.Unmarshal(opkDER, &opk); err != nil || len(rest) != 0 {
		return nil, malformed("OriginatorPublicKey", err)
	}
	if !opk.Algorithm.Algorithm.Equal(oidECPublicKey) {
		return nil, &UnsupportedAlgorithmError{OID: opk.Algorithm.Algorithm, Use: "originator key"}
	}
	if p := opk.Algorithm.Parameters; len(p.FullBytes) != 0 && p.Tag != asn1.TagNull {
		var curve asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(p.FullBytes, &curve); err != nil || len(rest) != 0 {
			return nil, malformed("OriginatorPublicKey parameters", err)
		}
		if !curve.Equal(suite.curveOID) {
			return nil, &UnsupportedAlgorithmError{OID: curve, Use: "originator curve"}
		}
	}
	if opk.PublicKey.BitLength%8 != 0 {
		return nil, malformed("OriginatorPublicKey", fmt.Errorf("public key is not whole octets"))
	}
	ephPub, err := suite.curve.NewPublicKey(opk.PublicKey.Bytes)
	if err != nil {
		return nil, malformed("OriginatorPublicKey", err)
	}

	priv, err := ecdhPrivateKey(key, suite.curve)
	if err != nil {
		return nil, err
	}
	if !priv.PublicKey().Equal(pub) {
		return nil, ErrKeyMismatch
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("%w: key agreement", ErrAuthenticationFailed)
	}
	kek, err := deriveKEK(suite, shared, wrapAlg.Algorithm, kari.UKM, kekLen)
	clear(shared)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kek)
	clear(kek)
	if err != nil {
		return nil, err
	}
	cek, err := keywrap.Unwrap(block, rek.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: key unwrap", ErrAuthenticationFailed)
	}
	return cek, nil
}

// ecdhPrivateKey accepts *ecdh.PrivateKey or *ecdsa.PrivateKey on the curve.
func ecdhPrivateKey(key crypto.PrivateKey, curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdh.PrivateKey:
		if k.Curve() != curve {
			return nil, ErrKeyMismatch
		}
		return k, nil
	case *ecdsa.PrivateKey:
		ek, err := k.ECDH()
		if err != nil || ek.Curve() != curve {
			return nil, ErrKeyMismatch
		}
		return ek, nil
	}
	return nil, fmt.Errorf("%w: EC recipient needs an *ecdh.PrivateKey or *ecdsa.PrivateKey, got %T", ErrKeyMismatch, key)
}
