# Design

`cryptomsg` implements one fixed profile of the Cryptographic Message Syntax. This note records
the structural choices, the BER normaliser, the policy model, and what is deliberately left out.

## Principles

- **Nothing is negotiated.** Every algorithm identifier on input is compared against the
  profile and anything else is refused with `*UnsupportedAlgorithmError{OID, Use}`. Output
  never carries anything but profile OIDs (`oid.go` is the complete list).
- **Fail closed, typed.** Every refusal is a sentinel or typed error (`errors.go`), so callers
  can distinguish "not for me" (`ErrNoMatchingRecipient`), "tampered"
  (`ErrAuthenticationFailed`, `ErrSignatureInvalid`), "not trusted" (`ErrUntrustedSigner`) and
  "not CMS" (`ErrMalformed`). Nothing is written to an output writer on any error path, and no
  error message carries key or plaintext material.
- **Standard-library cryptography only.** `crypto/aes`+`cipher` GCM, `crypto/rsa` OAEP/PSS,
  `crypto/ecdh`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/x509`. The two primitives the
  standard library lacks are written here with their published vectors: RFC 3394 AES key wrap
  (`internal/keywrap`) and the ANSI X9.63 KDF (`internal/kdf`). No cgo anywhere; the library
  builds for `js/wasm` and `wasip1/wasm`.
- **Any `crypto.Signer` / `crypto.Decrypter`.** Keys are opaque interfaces so hardware-backed
  keys can be plugged in later without API change; ECDH recipients take `*ecdh.PrivateKey` (or
  `*ecdsa.PrivateKey`) because the standard library has no agreement interface.

## Structures

### Encryption: AuthEnvelopedData out, EnvelopedData in

`Encrypt` always writes **AuthEnvelopedData** (RFC 5083) with AES-128- or AES-256-GCM
(RFC 5084): a 96-bit random nonce, a 128-bit tag in `mac`, `authAttrs` absent. RFC 5084 ties
AES-GCM to AuthEnvelopedData — EnvelopedData has no field for the tag — and the profile has no
other output cipher, so there is no EnvelopedData output option. **EnvelopedData** is
decrypt-only: AES-GCM inside it is refused as malformed, AES-CBC with PKCS#7 padding is accepted
under `DecryptOptions.AllowCBC` for legacy producers and documented as unauthenticated (the
caller must verify a signature over the envelope before trusting the plaintext).

One `RecipientInfo` per recipient certificate, chosen by key type:

- RSA → `KeyTransRecipientInfo`, RSAES-OAEP with SHA-256 and MGF1-SHA-256, empty label, keys
  ≥ 2048 bits. SHA-1 defaults (absent parameters) are refused by OID.
- P-256 / P-384 → `KeyAgreeRecipientInfo` v3, ephemeral-static ECDH
  (`dhSinglePass-stdDH-sha256kdf` / `sha384kdf`), ECC-CMS-SharedInfo naming the wrap algorithm
  and KEK length, X9.63 KDF, AES key wrap sized like the content key. One structure (one
  ephemeral key) per recipient, which is also what OpenSSL and Bouncy Castle emit.
- Anything else (Ed25519, P-521, DSA) refuses the whole message.

Recipients are named by `IssuerAndSerialNumber` (default) or `SubjectKeyIdentifier`
(`EncryptOptions.RecipientIdentifier`); the structure versions follow RFC 5652 §6.1/§6.2.
`kekri`, `pwri` and `ori` alternatives are parsed as present-but-unsupported so a message that
also addresses a profile recipient still decrypts.

### Memory bound

GCM authenticates the content as a single unit and the standard library's AEAD is one-shot, so
both directions buffer: `Encrypt` reads the whole plaintext before sealing, `Decrypt` reads the
whole envelope and `Open`s it before writing a single byte. Peak memory is about twice the
content size. The `io.Reader`/`io.Writer` surfaces are kept so a future chunked profile
(e.g. a per-chunk AEAD with a committed chunk index) can be added without API change; it is
out of scope for v0.1 because no CMS content type standardises it.

### Signing

`Sign` produces `SignedData` with one `SignerInfo`; the suite follows the key: ECDSA
P-256/SHA-256, ECDSA P-384/SHA-384, RSASSA-PSS/SHA-256 (MGF1-SHA-256, 32-byte salt), Ed25519
per RFC 8419 (digest SHA-512, signature over the DER signed attributes). Signed attributes are
mandatory and always present: content-type, message-digest, signing-time and
signingCertificateV2 with one ESSCertIDv2 (SHA-256 of the signer certificate plus
IssuerSerial). The whole supplied chain is carried in `certificates`. Content is hashed as it
streams; attached content is buffered to be embedded.

Verification requires every signer of a message to verify (fail closed on any one), refuses a
`SignerInfo` without the four attributes (`ErrMissingSignedAttribute` — this is why OpenSSL
signers must use `-cades`), checks content-type against eContentType, message-digest against
the content in constant time, and the ESSCertIDv2 against the signer certificate, so swapping
the certificate under the same key is `ErrSignatureInvalid`. The signing-time attribute is
returned as a claim and plays no part in validity.

## The BER→DER normaliser

`openssl cms` streams by default and emits indefinite-length BER with the encrypted content
split into constructed OCTET STRING chunks; Bouncy Castle's `getEncoded()` is BER too. The
strict decoders of `encoding/asn1` reject both. `internal/ber.Normalize` rewrites one BER
element to DER without a schema:

- indefinite lengths → definite minimal lengths, end-of-contents checked;
- constructed universal strings → one primitive string (BIT STRING segments must have zero
  unused bits except the last);
- superfluous length octets and non-minimal high-tag-number forms → minimal.

It is bounded: 64 levels of nesting, at most four length octets, lengths must fit the input,
tag numbers ≤ 2³¹−1 (what `encoding/asn1` accepts). Every failure is a `*SyntaxError{Offset,
Err}` wrapping a sentinel; it never panics (fuzzed, seeds committed). DER input comes back
byte-identical.

What it cannot do, and why: an *implicitly* tagged string such as CMS's
`encryptedContent [0] IMPLICIT OCTET STRING` has lost its universal tag, and without the schema
a constructed `[0]` is indistinguishable from `[0] EXPLICIT OCTET STRING` or a
`SEQUENCE OF OCTET STRING`; joining it blindly would corrupt e.g. `ukm [1] EXPLICIT OCTET
STRING`. So `Normalize` leaves such elements constructed and the schema-aware decoder calls
`ber.JoinOctetStrings` on them. DER's other schema-dependent rules (DEFAULT value omission,
SET OF ordering) are likewise not applied blindly; signed attributes are DER-encoded by the
signer with `ber.SortSetOf` and verified over the bytes as received after normalisation.

Two `encoding/asn1` properties shape the code: `Marshal` emits a `RawValue`'s `FullBytes`
verbatim and ignores an `explicit` tag on the field, and `Unmarshal` leaves the explicit
wrapper on a `RawValue`. `ContentInfo.content [0]` and `KeyAgreeRecipientInfo.originator [0]`
are therefore wrapped and unwrapped by hand.

## Policy model

`Verify` evaluates every signer against a `Policy` that is **offline by construction**: the
caller supplies trust anchors, extra intermediates, extra end-entity certificates, parsed
CRLs, the evaluation time and the required extended key usages. Nothing is fetched; there is
no network code in the module.

Chain building is `crypto/x509`'s, from the roots through the policy's intermediates plus the
certificates carried in the message, at `policy.Time`, with the given EKUs (`ExtKeyUsageAny`
when none). The signer must also allow `digitalSignature` when it has a KeyUsage extension.
Revocation is checked for every non-root certificate of the chain against the CRLs whose
issuer matches *and* whose signature verifies under that issuer *and* whose `thisUpdate` is
not in the future; a CRL past `nextUpdate` is refused unless `AllowStaleCRLs`; a listed serial
is revoked regardless of the revocation date; `RequireCRL` refuses chains with an uncovered
certificate. Every policy failure is `ErrUntrustedSigner` with the reason, and a bad signature
is reported before any trust question.

`Parse` gives the key-free view of either structure for reporting; nothing in it has been
authenticated and its documentation says so.

## Deliberately out of scope for v0.1

- Negotiation of any kind, PKCS#1 v1.5, SHA-1, DES/3DES, RC2, AES-CCM, AES-CBC on output,
  ChaCha20-Poly1305, password (`pwri`) and pre-shared-key (`kekri`) recipients, static-static
  ECDH, DH, RSA-KEM, post-quantum KEMs.
- `DigestedData`, `EncryptedData`, `AuthenticatedData`, compressed data, counter-signatures,
  time-stamp tokens, CAdES beyond ESSCertIDv2, S/MIME wrapping.
- OCSP, CRL distribution points, any network fetch, system trust stores.
- Hardware keys (PKCS#11, PIV/CAC): the API accepts any `crypto.Signer`/`crypto.Decrypter`
  so they can be added behind a build tag later.
- Chunked/streaming AEAD for contents too large to buffer.
- Multiple `SignerInfo`s on output (verification handles them; signing adds one).
