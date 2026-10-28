package cryptomsg

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
)

// MinRSABits is the smallest RSA modulus the profile accepts.
const MinRSABits = 2048

// oaepSHA256Params is RSAES-OAEP-params for SHA-256 / MGF1-SHA-256 with the
// default (empty) label, as RFC 3560 §3 and RFC 4055 §4.1 encode it.
func oaepSHA256Params() (asn1.RawValue, error) {
	sha := algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1Null}
	shaDER, err := asn1.Marshal(sha)
	if err != nil {
		return asn1.RawValue{}, err
	}
	p := rsaesOAEPParams{
		HashAlgorithm:    sha,
		MaskGenAlgorithm: algorithmIdentifier{Algorithm: oidMGF1, Parameters: asn1.RawValue{FullBytes: shaDER}},
	}
	b, err := asn1.Marshal(p)
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: b}, nil
}

// checkOAEPParams accepts exactly the SHA-256 / MGF1-SHA-256 / empty-label
// parameter set and refuses everything else with the offending OID.
func checkOAEPParams(alg algorithmIdentifier) error {
	if !alg.Algorithm.Equal(oidRSAESOAEP) {
		return &UnsupportedAlgorithmError{OID: alg.Algorithm, Use: "key transport"}
	}
	var p rsaesOAEPParams
	if len(alg.Parameters.FullBytes) == 0 {
		// All defaults: SHA-1, which the profile refuses.
		return &UnsupportedAlgorithmError{OID: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, Use: "OAEP hash"}
	}
	if rest, err := asn1.Unmarshal(alg.Parameters.FullBytes, &p); err != nil || len(rest) != 0 {
		return malformed("RSAES-OAEP-params", err)
	}
	if p.HashAlgorithm.Algorithm == nil || !p.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		oid := p.HashAlgorithm.Algorithm
		if oid == nil {
			oid = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
		}
		return &UnsupportedAlgorithmError{OID: oid, Use: "OAEP hash"}
	}
	if p.MaskGenAlgorithm.Algorithm == nil || !p.MaskGenAlgorithm.Algorithm.Equal(oidMGF1) {
		oid := p.MaskGenAlgorithm.Algorithm
		if oid == nil {
			oid = oidMGF1
		}
		return &UnsupportedAlgorithmError{OID: oid, Use: "OAEP mask generation"}
	}
	var mgfHash algorithmIdentifier
	if rest, err := asn1.Unmarshal(p.MaskGenAlgorithm.Parameters.FullBytes, &mgfHash); err != nil || len(rest) != 0 {
		return malformed("MGF1 parameters", err)
	}
	if !mgfHash.Algorithm.Equal(oidSHA256) {
		return &UnsupportedAlgorithmError{OID: mgfHash.Algorithm, Use: "OAEP MGF1 hash"}
	}
	if p.PSourceAlgorithm.Algorithm != nil {
		if !p.PSourceAlgorithm.Algorithm.Equal(oidPSpecified) {
			return &UnsupportedAlgorithmError{OID: p.PSourceAlgorithm.Algorithm, Use: "OAEP label source"}
		}
		var label []byte
		if rest, err := asn1.Unmarshal(p.PSourceAlgorithm.Parameters.FullBytes, &label); err != nil || len(rest) != 0 {
			return malformed("pSpecified label", err)
		}
		if len(label) != 0 {
			return &UnsupportedAlgorithmError{OID: oidPSpecified, Use: "OAEP non-empty label"}
		}
	}
	return nil
}

// rsaRecipientKey returns the certificate's RSA key, checking the size floor.
func rsaRecipientKey(cert *x509.Certificate) (*rsa.PublicKey, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cryptomsg: certificate %q does not carry an RSA key", cert.Subject)
	}
	if pub.N.BitLen() < MinRSABits {
		return nil, fmt.Errorf("%w: RSA-%d in certificate %q, minimum %d", ErrKeyTooWeak, pub.N.BitLen(), cert.Subject, MinRSABits)
	}
	return pub, nil
}

// encodeKeyTrans builds a KeyTransRecipientInfo wrapping cek for cert under
// RSA-OAEP SHA-256.
func encodeKeyTrans(random io.Reader, cert *x509.Certificate, kind RecipientIdentifierKind, cek []byte) (asn1.RawValue, error) {
	pub, err := rsaRecipientKey(cert)
	if err != nil {
		return asn1.RawValue{}, err
	}
	rid, err := encodeRecipientID(cert, kind, false)
	if err != nil {
		return asn1.RawValue{}, err
	}
	params, err := oaepSHA256Params()
	if err != nil {
		return asn1.RawValue{}, err
	}
	encKey, err := rsa.EncryptOAEP(crypto.SHA256.New(), random, pub, cek, nil)
	if err != nil {
		return asn1.RawValue{}, err
	}
	version := 0
	if kind == SubjectKeyID {
		version = 2
	}
	b, err := asn1.Marshal(keyTransRecipientInfo{
		Version:                version,
		Rid:                    rid,
		KeyEncryptionAlgorithm: algorithmIdentifier{Algorithm: oidRSAESOAEP, Parameters: params},
		EncryptedKey:           encKey,
	})
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: b}, nil
}

// decryptKeyTrans recovers the CEK from a KeyTransRecipientInfo addressed to
// cert, using the certificate holder's decrypter.
func decryptKeyTrans(ktri *keyTransRecipientInfo, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	if err := checkOAEPParams(ktri.KeyEncryptionAlgorithm); err != nil {
		return nil, err
	}
	pub, err := rsaRecipientKey(cert)
	if err != nil {
		return nil, err
	}
	dec, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("%w: RSA recipient needs a crypto.Decrypter, got %T", ErrKeyMismatch, key)
	}
	if kp, ok := dec.Public().(*rsa.PublicKey); !ok || !kp.Equal(pub) {
		return nil, ErrKeyMismatch
	}
	cek, err := dec.Decrypt(nil, ktri.EncryptedKey, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256})
	if err != nil {
		return nil, fmt.Errorf("%w: key transport", ErrAuthenticationFailed)
	}
	return cek, nil
}
