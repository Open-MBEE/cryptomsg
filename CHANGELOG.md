# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Verify` with an offline `Policy` (caller-supplied trust anchors, intermediates, CRLs,
  evaluation time, extended key usages; no network access) and `Parse`, the key-free view of
  a CMS object (recipients, algorithms, signer certificates).
- `Sign`: SignedData with ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, RSASSA-PSS/SHA-256 and
  Ed25519 (RFC 8419), attached or detached, with the mandatory content-type, message-digest,
  signing-time and signingCertificateV2 (ESSCertIDv2) attributes; signature verification
  that refuses missing attributes, substituted algorithms and certificates.
- `Encrypt` and `Decrypt`: AuthEnvelopedData with AES-128/256-GCM for RSA (RSA-OAEP SHA-256,
  ≥ 2048 bits) and EC (ephemeral-static ECDH on P-256/P-384, X9.63 KDF, RFC 3394 AES key
  wrap) recipients named by IssuerAndSerialNumber or SubjectKeyIdentifier; EnvelopedData with
  AES-CBC accepted on decrypt behind `DecryptOptions.AllowCBC`.
- BER→DER normaliser accepting the indefinite-length output of a streaming `openssl cms`.
- Repository scaffold: module `github.com/Open-MBEE/cryptomsg`, Apache-2.0 licence, CI
  (gofmt, go vet, staticcheck, gosec, `go test -race` on Linux/macOS/Windows, js/wasm and
  wasip1/wasm compile checks, `GOFIPS140=latest`), security policy and FIPS status note.

[Unreleased]: https://github.com/Open-MBEE/cryptomsg/compare/main...develop
