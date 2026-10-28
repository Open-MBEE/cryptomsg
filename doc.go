// Package cryptomsg implements the Cryptographic Message Syntax (CMS) of RFC 5652
// in pure Go: encryption to X.509 certificate holders (EnvelopedData and
// AuthEnvelopedData), decryption with the matching private key, signing
// (SignedData) and verification against an offline certificate policy.
//
// The library implements a fixed algorithm profile and refuses everything outside
// it with a typed error naming the offending OID; nothing is negotiated. See the
// README for the profile table.
package cryptomsg
