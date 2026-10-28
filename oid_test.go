package cryptomsg

import (
	"encoding/asn1"
	"errors"
	"testing"
)

func TestOIDsDistinct(t *testing.T) {
	all := []asn1.ObjectIdentifier{oidData, oidSignedData, oidEnvelopedData, oidAuthEnvelopedData,
		oidAES128CBC, oidAES192CBC, oidAES256CBC, oidAES128GCM, oidAES256GCM, oidAES128Wrap, oidAES256Wrap,
		oidRSAEncryption, oidRSAESOAEP, oidMGF1, oidPSpecified,
		oidDHSinglePassStdDHSHA256KDF, oidDHSinglePassStdDHSHA384KDF, oidECPublicKey, oidNamedCurveP256, oidNamedCurveP384,
		oidSHA256, oidSHA384, oidSHA512, oidECDSAWithSHA256, oidECDSAWithSHA384, oidRSASSAPSS, oidEd25519,
		oidAttrContentType, oidAttrMessageDigest, oidAttrSigningTime, oidAttrSigningCertV2}
	seen := map[string]bool{}
	for _, oid := range all {
		if seen[oid.String()] {
			t.Errorf("duplicate OID %v", oid)
		}
		seen[oid.String()] = true
		if _, err := asn1.Marshal(oid); err != nil {
			t.Errorf("%v does not encode: %v", oid, err)
		}
	}
}

func TestTypedErrors(t *testing.T) {
	var err error = &UnsupportedAlgorithmError{OID: oidAES192CBC, Use: "content encryption"}
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatal("UnsupportedAlgorithmError must match ErrUnsupportedAlgorithm")
	}
	var ua *UnsupportedAlgorithmError
	if !errors.As(err, &ua) || !ua.OID.Equal(oidAES192CBC) {
		t.Fatal("errors.As must recover the OID")
	}
	if got := err.Error(); got != "cryptomsg: unsupported content encryption algorithm 2.16.840.1.101.3.4.1.22" {
		t.Fatalf("message %q", got)
	}
	inner := errors.New("boom")
	err = &MalformedError{Structure: "EnvelopedData", Err: inner}
	if !errors.Is(err, ErrMalformed) || !errors.Is(err, inner) {
		t.Fatal("MalformedError must match ErrMalformed and its cause")
	}
}
