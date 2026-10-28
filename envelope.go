package cryptomsg

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"github.com/Open-MBEE/cryptomsg/internal/ber"
)

// ContentCipher selects the content-encryption algorithm of Encrypt.
type ContentCipher int

const (
	// AES256GCM is the default: AES-256 in GCM with a 96-bit nonce and a
	// 128-bit tag, carried in AuthEnvelopedData.
	AES256GCM ContentCipher = iota
	// AES128GCM is AES-128-GCM, same framing.
	AES128GCM
)

func (c ContentCipher) String() string {
	switch c {
	case AES256GCM:
		return "AES-256-GCM"
	case AES128GCM:
		return "AES-128-GCM"
	}
	return fmt.Sprintf("ContentCipher(%d)", int(c))
}

func (c ContentCipher) keyLen() (int, asn1.ObjectIdentifier, error) {
	switch c {
	case AES256GCM:
		return 32, oidAES256GCM, nil
	case AES128GCM:
		return 16, oidAES128GCM, nil
	}
	return 0, nil, fmt.Errorf("cryptomsg: unknown content cipher %d", int(c))
}

// EncryptOptions tunes Encrypt. The zero value is the default profile.
type EncryptOptions struct {
	// Cipher is the content-encryption algorithm; AES256GCM when zero.
	Cipher ContentCipher
	// RecipientIdentifier selects how each RecipientInfo names its
	// certificate; IssuerAndSerial when zero. SubjectKeyID requires every
	// recipient certificate to carry the SubjectKeyIdentifier extension.
	RecipientIdentifier RecipientIdentifierKind
	// Rand is the entropy source for keys, nonces and ephemeral keys;
	// crypto/rand.Reader when nil.
	Rand io.Reader
}

// DecryptOptions tunes Decrypt. The zero value is the default profile.
type DecryptOptions struct {
	// AllowCBC accepts EnvelopedData whose content is AES-CBC encrypted, for
	// interoperability with legacy producers. CBC carries no integrity
	// protection: callers that set this must authenticate the envelope by
	// other means (a signature over it) before trusting the plaintext.
	AllowCBC bool
}

// gcmNonceSize is the 96-bit nonce RFC 5084 §3.2 recommends.
const gcmNonceSize = 12

// gcmTagSize is the authentication tag length Encrypt uses; Decrypt accepts
// 12 to 16 as RFC 5084 allows.
const gcmTagSize = 16

// Encrypt writes an AuthEnvelopedData (RFC 5083) over plaintext for every
// recipient certificate: AES-GCM content encryption with one RecipientInfo
// per certificate — KeyTransRecipientInfo (RSA-OAEP SHA-256) for RSA keys,
// KeyAgreeRecipientInfo (ephemeral-static ECDH, X9.63 KDF, AES key wrap) for
// P-256/P-384 keys. Any other key type or an RSA key under MinRSABits refuses
// the whole message.
//
// GCM authenticates the content as a single unit, so plaintext is buffered in
// memory (about twice its size at peak) before the envelope is written to w.
func Encrypt(w io.Writer, plaintext io.Reader, recipients []*x509.Certificate, opts *EncryptOptions) error {
	if opts == nil {
		opts = &EncryptOptions{}
	}
	random := opts.Rand
	if random == nil {
		random = rand.Reader
	}
	if len(recipients) == 0 {
		return errors.New("cryptomsg: Encrypt needs at least one recipient")
	}
	keyLen, cipherOID, err := opts.Cipher.keyLen()
	if err != nil {
		return err
	}

	cek := make([]byte, keyLen)
	if _, err := io.ReadFull(random, cek); err != nil {
		return err
	}
	defer clear(cek)

	ris := make([]asn1.RawValue, 0, len(recipients))
	for _, cert := range recipients {
		if cert == nil {
			return errors.New("cryptomsg: nil recipient certificate")
		}
		var ri asn1.RawValue
		switch cert.PublicKey.(type) {
		case *rsa.PublicKey:
			ri, err = encodeKeyTrans(random, cert, opts.RecipientIdentifier, cek)
		case *ecdsa.PublicKey:
			ri, err = encodeKeyAgree(random, cert, opts.RecipientIdentifier, cek)
		default:
			err = &UnsupportedAlgorithmError{OID: publicKeyAlgorithm(cert.PublicKeyAlgorithm).oid(), Use: "recipient key"}
		}
		if err != nil {
			return err
		}
		ris = append(ris, ri)
	}

	content, err := io.ReadAll(plaintext)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCMWithTagSize(block, gcmTagSize)
	if err != nil {
		return err
	}
	sealed := aead.Seal(content[:0], nonce, content, nil)
	ciphertext, tag := sealed[:len(sealed)-gcmTagSize], sealed[len(sealed)-gcmTagSize:]

	params, err := asn1.Marshal(gcmParameters{Nonce: nonce, ICVLen: gcmTagSize})
	if err != nil {
		return err
	}
	aed := authEnvelopedData{
		Version:        0,
		RecipientInfos: ris,
		AuthEncryptedContentInfo: encryptedContentInfo{
			ContentType:                oidData,
			ContentEncryptionAlgorithm: algorithmIdentifier{Algorithm: cipherOID, Parameters: asn1.RawValue{FullBytes: params}},
			EncryptedContent:           asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: ciphertext},
		},
		MAC: tag,
	}
	body, err := asn1.Marshal(aed)
	if err != nil {
		return err
	}
	out, err := encodeContentInfo(oidAuthEnvelopedData, body)
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

// encodeContentInfo wraps a DER content in ContentInfo under its type. The
// [0] EXPLICIT wrapper is built by hand because encoding/asn1 emits a
// RawValue's FullBytes verbatim, ignoring an explicit tag on the field.
func encodeContentInfo(contentType asn1.ObjectIdentifier, content []byte) ([]byte, error) {
	return asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{contentType, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: content}})
}

// envelope is the decoded, key-free view shared by Decrypt and Parse.
type envelope struct {
	Authenticated bool // AuthEnvelopedData rather than EnvelopedData
	Version       int
	Recipients    []recipientInfo
	ContentType   asn1.ObjectIdentifier
	Cipher        algorithmIdentifier
	Ciphertext    []byte
	AuthAttrs     asn1.RawValue // raw [1] IMPLICIT SET, AuthEnvelopedData only
	MAC           []byte
}

// recipientInfo is one decoded RecipientInfo. For KeyAgree, one entry per
// RecipientEncryptedKey, all sharing kari.
type recipientInfo struct {
	ID   recipientID
	Alg  asn1.ObjectIdentifier
	ktri *keyTransRecipientInfo
	kari *keyAgreeRecipientInfo
	rek  *recipientEncryptedKey
}

// parseEnvelope decodes a DER ContentInfo holding EnvelopedData or
// AuthEnvelopedData.
func parseEnvelope(der []byte) (*envelope, error) {
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) != 0 {
		if err == nil {
			err = errTrailingData
		}
		return nil, malformed("ContentInfo", err)
	}
	env := &envelope{}
	var eci *encryptedContentInfo
	switch {
	case ci.ContentType.Equal(oidEnvelopedData):
		var ed envelopedData
		if rest, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil || len(rest) != 0 {
			return nil, malformed("EnvelopedData", err)
		}
		env.Version = ed.Version
		eci = &ed.EncryptedContentInfo
		if err := env.parseRecipients(ed.RecipientInfos); err != nil {
			return nil, err
		}
	case ci.ContentType.Equal(oidAuthEnvelopedData):
		var aed authEnvelopedData
		if rest, err := asn1.Unmarshal(ci.Content.Bytes, &aed); err != nil || len(rest) != 0 {
			return nil, malformed("AuthEnvelopedData", err)
		}
		env.Authenticated = true
		env.Version = aed.Version
		env.AuthAttrs = aed.AuthAttrs
		env.MAC = aed.MAC
		eci = &aed.AuthEncryptedContentInfo
		if err := env.parseRecipients(aed.RecipientInfos); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedStructure, ci.ContentType)
	}
	env.ContentType = eci.ContentType
	env.Cipher = eci.ContentEncryptionAlgorithm
	if len(eci.EncryptedContent.FullBytes) == 0 {
		return nil, malformed("EncryptedContentInfo", fmt.Errorf("encryptedContent %w", errAbsent))
	}
	if eci.EncryptedContent.IsCompound {
		joined, err := ber.JoinOctetStrings(eci.EncryptedContent.Bytes)
		if err != nil {
			return nil, malformed("encryptedContent", err)
		}
		env.Ciphertext = joined
	} else {
		env.Ciphertext = eci.EncryptedContent.Bytes
	}
	return env, nil
}

func (env *envelope) parseRecipients(raws []asn1.RawValue) error {
	if len(raws) == 0 {
		return malformed("RecipientInfos", errors.New("empty"))
	}
	for _, raw := range raws {
		switch {
		case raw.Class == asn1.ClassUniversal && raw.Tag == tagKeyTransRecipientInfo:
			var ktri keyTransRecipientInfo
			if rest, err := asn1.Unmarshal(raw.FullBytes, &ktri); err != nil || len(rest) != 0 {
				return malformed("KeyTransRecipientInfo", err)
			}
			if ktri.Version != 0 && ktri.Version != 2 {
				return malformed("KeyTransRecipientInfo", fmt.Errorf("version %d", ktri.Version))
			}
			id, err := parseRecipientID(ktri.Rid, false)
			if err != nil {
				return err
			}
			if (id.Kind == SubjectKeyID) != (ktri.Version == 2) {
				return malformed("KeyTransRecipientInfo", fmt.Errorf("version %d with %s", ktri.Version, id.Kind))
			}
			env.Recipients = append(env.Recipients, recipientInfo{ID: id, Alg: ktri.KeyEncryptionAlgorithm.Algorithm, ktri: &ktri})
		case raw.Class == asn1.ClassContextSpecific && raw.Tag == tagKeyAgreeRecipientInfo && raw.IsCompound:
			kari, err := parseKeyAgree(raw)
			if err != nil {
				return err
			}
			if len(kari.RecipientEncryptedKeys) == 0 {
				return malformed("KeyAgreeRecipientInfo", errors.New("no RecipientEncryptedKeys"))
			}
			for i := range kari.RecipientEncryptedKeys {
				rek := &kari.RecipientEncryptedKeys[i]
				id, err := parseRecipientID(rek.Rid, true)
				if err != nil {
					return err
				}
				env.Recipients = append(env.Recipients, recipientInfo{ID: id, Alg: kari.KeyEncryptionAlgorithm.Algorithm, kari: kari, rek: rek})
			}
		case raw.Class == asn1.ClassContextSpecific && raw.IsCompound && (raw.Tag == 2 || raw.Tag == 3 || raw.Tag == 4):
			// kekri, pwri and ori: outside the profile. The message may still
			// be decryptable by a key-transport or key-agreement recipient, so
			// record it as a refused alternative instead of failing here.
			env.Recipients = append(env.Recipients, recipientInfo{ID: recipientID{Kind: -1}, Alg: otherRecipientOID(raw.Tag)})
		default:
			return malformed("RecipientInfo", fmt.Errorf("unexpected tag class %d number %d", raw.Class, raw.Tag))
		}
	}
	return nil
}

// otherRecipientOID names the refused RecipientInfo alternatives, which carry
// no algorithm OID of their own, by a pseudo-OID of their tag for reporting.
func otherRecipientOID(tag int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 0, tag}
}

// Decrypt reads an EnvelopedData or AuthEnvelopedData, finds the RecipientInfo
// addressed to cert, recovers the content-encryption key with key
// (crypto.Decrypter for RSA-OAEP; *ecdh.PrivateKey or *ecdsa.PrivateKey for
// ECDH) and writes the plaintext to w. It fails closed: an unknown algorithm,
// a key that does not belong to cert, a missing RecipientInfo or a failed
// authentication tag yields a typed error and nothing is written to w.
//
// The whole envelope is read into memory, and for AES-GCM the plaintext is
// authenticated before any of it is written, so peak memory is about twice
// the content size.
func Decrypt(w io.Writer, envelope io.Reader, cert *x509.Certificate, key crypto.PrivateKey, opts *DecryptOptions) error {
	if opts == nil {
		opts = &DecryptOptions{}
	}
	if cert == nil || key == nil {
		return errors.New("cryptomsg: Decrypt needs the recipient certificate and private key")
	}
	raw, err := io.ReadAll(envelope)
	if err != nil {
		return err
	}
	der, err := normalizeInput(raw)
	if err != nil {
		return err
	}
	env, err := parseEnvelope(der)
	if err != nil {
		return err
	}

	var cek []byte
	found := false
	for i := range env.Recipients {
		ri := &env.Recipients[i]
		if !ri.ID.matches(cert) {
			continue
		}
		found = true
		switch {
		case ri.ktri != nil:
			cek, err = decryptKeyTrans(ri.ktri, cert, key)
		case ri.kari != nil:
			cek, err = decryptKeyAgree(ri.kari, ri.rek, cert, key)
		}
		if err != nil {
			return err
		}
		break
	}
	if !found {
		return ErrNoMatchingRecipient
	}
	defer clear(cek)

	plaintext, err := decryptContent(env, cek, opts)
	if err != nil {
		return err
	}
	_, err = w.Write(plaintext)
	return err
}

// decryptContent decrypts and, for GCM, authenticates the content with cek.
func decryptContent(env *envelope, cek []byte, opts *DecryptOptions) ([]byte, error) {
	alg := env.Cipher.Algorithm
	switch {
	case alg.Equal(oidAES128GCM), alg.Equal(oidAES256GCM):
		if !env.Authenticated {
			// RFC 5084 §1 binds AES-GCM to AuthEnvelopedData; an EnvelopedData
			// has no field for the tag.
			return nil, malformed("EnvelopedData", errors.New("AES-GCM outside AuthEnvelopedData"))
		}
		want := 16
		if alg.Equal(oidAES256GCM) {
			want = 32
		}
		if len(cek) != want {
			return nil, malformed("content-encryption key", fmt.Errorf("%d bytes for %v", len(cek), alg))
		}
		var params gcmParameters
		if rest, err := asn1.Unmarshal(env.Cipher.Parameters.FullBytes, &params); err != nil || len(rest) != 0 {
			return nil, malformed("GCMParameters", err)
		}
		if len(params.Nonce) < 7 || len(params.Nonce) > 128 || params.ICVLen < 12 || params.ICVLen > 16 {
			return nil, malformed("GCMParameters", fmt.Errorf("nonce %d bytes, ICV %d bytes", len(params.Nonce), params.ICVLen))
		}
		if len(env.MAC) != params.ICVLen {
			return nil, fmt.Errorf("%w: tag length", ErrAuthenticationFailed)
		}
		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, err
		}
		aead, err := newGCM(block, len(params.Nonce), params.ICVLen)
		if err != nil {
			return nil, err
		}
		aad, err := authAttrsAAD(env.AuthAttrs)
		if err != nil {
			return nil, err
		}
		sealed := make([]byte, 0, len(env.Ciphertext)+len(env.MAC))
		sealed = append(sealed, env.Ciphertext...)
		sealed = append(sealed, env.MAC...)
		plaintext, err := aead.Open(nil, params.Nonce, sealed, aad)
		if err != nil {
			return nil, ErrAuthenticationFailed
		}
		return plaintext, nil

	case alg.Equal(oidAES128CBC), alg.Equal(oidAES192CBC), alg.Equal(oidAES256CBC):
		if !opts.AllowCBC {
			return nil, &UnsupportedAlgorithmError{OID: alg, Use: "content encryption (AES-CBC needs DecryptOptions.AllowCBC)"}
		}
		if env.Authenticated {
			return nil, malformed("AuthEnvelopedData", errors.New("AES-CBC is not an authenticated cipher"))
		}
		want := 16
		switch {
		case alg.Equal(oidAES192CBC):
			want = 24
		case alg.Equal(oidAES256CBC):
			want = 32
		}
		if len(cek) != want {
			return nil, malformed("content-encryption key", fmt.Errorf("%d bytes for %v", len(cek), alg))
		}
		var iv []byte
		if rest, err := asn1.Unmarshal(env.Cipher.Parameters.FullBytes, &iv); err != nil || len(rest) != 0 || len(iv) != aes.BlockSize {
			return nil, malformed("AES-CBC parameters", err)
		}
		if len(env.Ciphertext) == 0 || len(env.Ciphertext)%aes.BlockSize != 0 {
			return nil, malformed("encryptedContent", errors.New("not a whole number of blocks"))
		}
		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, err
		}
		plaintext := make([]byte, len(env.Ciphertext))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, env.Ciphertext)
		return unpadPKCS7(plaintext)
	}
	return nil, &UnsupportedAlgorithmError{OID: alg, Use: "content encryption"}
}

// newGCM builds the AEAD for the nonce and tag lengths of the message. The
// standard library sets one of the two at a time, so either the nonce is the
// standard 96 bits or the tag is the full 128 bits.
func newGCM(block cipher.Block, nonceLen, tagLen int) (cipher.AEAD, error) {
	switch {
	case nonceLen == gcmNonceSize:
		return cipher.NewGCMWithTagSize(block, tagLen)
	case tagLen == gcmTagSize:
		return cipher.NewGCMWithNonceSize(block, nonceLen)
	}
	return nil, malformed("GCMParameters", fmt.Errorf("nonce of %d bytes with a %d-byte tag", nonceLen, tagLen))
}

// authAttrsAAD returns the additional authenticated data of RFC 5083 §2.2:
// the DER of the authAttrs as a SET (universal tag), or nil when absent.
func authAttrsAAD(attrs asn1.RawValue) ([]byte, error) {
	if len(attrs.FullBytes) == 0 {
		return nil, nil
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: attrs.Bytes})
}

// unpadPKCS7 removes the padding of RFC 5652 §6.3 after a CBC decryption.
func unpadPKCS7(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, malformed("padding", errors.New("empty"))
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, malformed("padding", errors.New("invalid length"))
	}
	for _, p := range b[len(b)-n:] {
		if int(p) != n {
			return nil, malformed("padding", errors.New("invalid bytes"))
		}
	}
	return b[:len(b)-n], nil
}

// oid maps an x509.PublicKeyAlgorithm to its OID for error reporting.
func (a publicKeyAlgorithm) oid() asn1.ObjectIdentifier {
	switch x509.PublicKeyAlgorithm(a) {
	case x509.RSA:
		return oidRSAEncryption
	case x509.ECDSA:
		return oidECPublicKey
	case x509.Ed25519:
		return oidEd25519
	case x509.DSA:
		return asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	}
	return asn1.ObjectIdentifier{0}
}

type publicKeyAlgorithm x509.PublicKeyAlgorithm
