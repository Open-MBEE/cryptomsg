package cryptomsg

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// Sentinel errors. Every refusal of this package wraps one of these or is one
// of the typed errors below; match with errors.Is and errors.As.
var (
	// ErrNoMatchingRecipient reports an envelope without a RecipientInfo for
	// the certificate given to Decrypt.
	ErrNoMatchingRecipient = errors.New("cryptomsg: no RecipientInfo matches the certificate")
	// ErrSignatureInvalid reports a signature that does not verify over the
	// content, or signed attributes inconsistent with it.
	ErrSignatureInvalid = errors.New("cryptomsg: signature invalid")
	// ErrAuthenticationFailed reports an AuthEnvelopedData whose tag does not
	// verify; no plaintext is released.
	ErrAuthenticationFailed = errors.New("cryptomsg: authentication failed")
	// ErrUntrustedSigner reports a signer certificate that does not chain to
	// the policy's trust anchors or fails its checks.
	ErrUntrustedSigner = errors.New("cryptomsg: signer not trusted by policy")
	// ErrMissingSignedAttribute reports a SignerInfo without one of the
	// mandatory signed attributes.
	ErrMissingSignedAttribute = errors.New("cryptomsg: mandatory signed attribute missing")
	// ErrUnsupportedStructure reports a ContentInfo whose content type is
	// outside the profile.
	ErrUnsupportedStructure = errors.New("cryptomsg: unsupported CMS content type")
	// ErrKeyTooWeak reports a public key below the profile's minimum size.
	ErrKeyTooWeak = errors.New("cryptomsg: key below the minimum size")
	// ErrKeyMismatch reports a private key that does not belong to the
	// certificate it was given with.
	ErrKeyMismatch = errors.New("cryptomsg: private key does not match the certificate")
	// ErrMalformed reports input that is not a well-formed CMS object.
	ErrMalformed = errors.New("cryptomsg: malformed CMS object")
	// ErrDetachedContentRequired reports verification of a detached signature
	// without the content it covers.
	ErrDetachedContentRequired = errors.New("cryptomsg: detached signature needs its content")
	// ErrContentMismatch reports attached content given to Verify when the
	// signature already carries content, or the reverse.
	ErrContentMismatch = errors.New("cryptomsg: content present both in the signature and as argument")
)

// UnsupportedAlgorithmError reports an algorithm outside the pinned profile.
// Nothing is negotiated: the object is refused as a whole.
type UnsupportedAlgorithmError struct {
	// OID identifies the algorithm.
	OID asn1.ObjectIdentifier
	// Use says where it appeared: "content encryption", "key transport",
	// "key agreement", "key wrap", "signature", "digest", "KDF".
	Use string
}

func (e *UnsupportedAlgorithmError) Error() string {
	return fmt.Sprintf("cryptomsg: unsupported %s algorithm %v", e.Use, e.OID)
}

// Is makes every UnsupportedAlgorithmError match ErrUnsupportedAlgorithm.
func (e *UnsupportedAlgorithmError) Is(target error) bool {
	return target == ErrUnsupportedAlgorithm
}

// ErrUnsupportedAlgorithm matches any *UnsupportedAlgorithmError.
var ErrUnsupportedAlgorithm = errors.New("cryptomsg: unsupported algorithm")

// MalformedError wraps ErrMalformed with the structure and reason, for
// diagnostics. It never carries key or content material.
type MalformedError struct {
	Structure string
	Err       error
}

func (e *MalformedError) Error() string {
	return fmt.Sprintf("cryptomsg: malformed %s: %v", e.Structure, e.Err)
}

// Unwrap returns the underlying error.
func (e *MalformedError) Unwrap() error { return e.Err }

// Is makes every MalformedError match ErrMalformed.
func (e *MalformedError) Is(target error) bool { return target == ErrMalformed }
