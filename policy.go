package cryptomsg

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"time"
)

// Policy is the offline trust model Verify evaluates a signer against. Every
// input is supplied by the caller; the library never fetches certificates,
// CRLs or time from anywhere.
type Policy struct {
	// Roots are the trust anchors. Required: an empty pool trusts nobody.
	Roots *x509.CertPool
	// Intermediates are extra CA certificates for chain building, in
	// addition to those carried in the SignedData.
	Intermediates *x509.CertPool
	// Certificates are extra end-entity certificates for locating a signer
	// whose certificate is not in the SignedData.
	Certificates []*x509.Certificate
	// CRLs are the revocation lists to consult. A CRL is used only when its
	// signature verifies under the issuer of the certificate it is checked
	// against and its validity window covers Time (see AllowStaleCRLs).
	CRLs []*x509.RevocationList
	// RequireCRL refuses a chain in which any non-root certificate is not
	// covered by a usable CRL. Without it, certificates with no applicable
	// CRL are simply not revocation-checked.
	RequireCRL bool
	// AllowStaleCRLs accepts a CRL whose NextUpdate is before Time.
	AllowStaleCRLs bool
	// Time is the evaluation time for validity periods and CRLs; time.Now()
	// when zero. Signing-time attributes play no part in it.
	Time time.Time
	// KeyUsages are the extended key usages a signer chain must allow;
	// x509.ExtKeyUsageAny when empty, which accepts any EKU extension and
	// its absence. The signer certificate must additionally allow
	// digitalSignature when it carries a KeyUsage extension.
	KeyUsages []x509.ExtKeyUsage
}

// Verify checks a SignedData: every signature must verify (see Sign for the
// profile) and every signer must chain to policy.Roots, be valid at
// policy.Time, carry the required key usages and not be revoked by the
// supplied CRLs. It returns the first signer with its validated chain; the
// signature is refused as a whole if any signer fails.
//
// content is the detached content, or nil when the SignedData carries it.
func Verify(signature []byte, content io.Reader, policy *Policy) (*VerifiedSignature, error) {
	if policy == nil || policy.Roots == nil {
		return nil, fmt.Errorf("%w: policy has no trust anchors", ErrUntrustedSigner)
	}
	der, err := normalizeInput(signature)
	if err != nil {
		return nil, err
	}
	msg, err := parseSignedData(der)
	if err != nil {
		return nil, err
	}
	verified, err := verifySigners(msg, content, policy.Certificates)
	if err != nil {
		return nil, err
	}
	for _, v := range verified {
		chain, err := policy.evaluate(v.Signer, msg.Certificates)
		if err != nil {
			return nil, err
		}
		v.Chain = chain
	}
	return verified[0], nil
}

// evaluate builds and checks the signer's chain under the policy.
func (p *Policy) evaluate(signer *x509.Certificate, carried []*x509.Certificate) ([]*x509.Certificate, error) {
	at := p.Time
	if at.IsZero() {
		at = time.Now()
	}
	intermediates := x509.NewCertPool()
	if p.Intermediates != nil {
		intermediates = p.Intermediates.Clone()
	}
	for _, c := range carried {
		if !c.Equal(signer) {
			intermediates.AddCert(c)
		}
	}
	usages := p.KeyUsages
	if len(usages) == 0 {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	chains, err := signer.Verify(x509.VerifyOptions{
		Roots:         p.Roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     usages,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUntrustedSigner, err)
	}
	if signer.KeyUsage != 0 && signer.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fmt.Errorf("%w: signer certificate does not allow digitalSignature", ErrUntrustedSigner)
	}
	// Take the first chain that passes revocation; report the first failure
	// when none does.
	var firstErr error
	for _, chain := range chains {
		if err := p.checkRevocation(chain, at); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return chain, nil
	}
	return nil, firstErr
}

// checkRevocation consults the CRLs for every certificate of the chain but
// the root. A certificate is revoked if any usable CRL from its issuer lists
// its serial number, whatever the revocation date. A CRL past its NextUpdate
// is not usable unless AllowStaleCRLs; it only matters when no current CRL
// from the same issuer exists.
func (p *Policy) checkRevocation(chain []*x509.Certificate, at time.Time) error {
	for i := 0; i+1 < len(chain); i++ {
		cert, issuer := chain[i], chain[i+1]
		covered := false
		var stale *x509.RevocationList
		for _, crl := range p.CRLs {
			if !bytes.Equal(crl.RawIssuer, cert.RawIssuer) || crl.CheckSignatureFrom(issuer) != nil || at.Before(crl.ThisUpdate) {
				continue
			}
			if !p.AllowStaleCRLs && !crl.NextUpdate.IsZero() && at.After(crl.NextUpdate) {
				stale = crl
				continue
			}
			covered = true
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return fmt.Errorf("%w: certificate %q revoked %s", ErrUntrustedSigner, cert.Subject, entry.RevocationTime.UTC().Format(time.RFC3339))
				}
			}
		}
		if !covered && stale != nil {
			return fmt.Errorf("%w: only CRL from %s expired %s", ErrUntrustedSigner, issuer.Subject, stale.NextUpdate.UTC().Format(time.RFC3339))
		}
		if p.RequireCRL && !covered {
			return fmt.Errorf("%w: no CRL covers %q", ErrUntrustedSigner, cert.Subject)
		}
	}
	return nil
}
