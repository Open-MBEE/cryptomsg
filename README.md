# cryptomsg

A pure-Go implementation of the Cryptographic Message Syntax (CMS, [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652)):
encrypt to X.509 certificate holders, decrypt with the matching private key, sign, and
verify against an offline certificate policy. No cgo. Builds for `GOOS=js GOARCH=wasm` and
`GOOS=wasip1 GOARCH=wasm`.

The library implements one fixed algorithm profile. Everything outside it is refused with a
typed error naming the OID; nothing is negotiated.

## Profile (v0.1)

| Structure | Algorithms |
|---|---|
| `EnvelopedData` (RFC 5652 §6) and `AuthEnvelopedData` (RFC 5083) | content encryption AES-128-GCM and AES-256-GCM (RFC 5084); AES-CBC accepted on decrypt only, behind an option, for interop with legacy producers |
| `KeyTransRecipientInfo` | RSA-OAEP with SHA-256 and MGF1-SHA-256 (RFC 3560); RSA keys ≥ 2048 bits |
| `KeyAgreeRecipientInfo` | ephemeral-static ECDH on P-256 and P-384 (RFC 5753), ANSI X9.63 KDF with SHA-256/384, AES key wrap (RFC 3394) |
| `SignedData` (§5) | ECDSA P-256/SHA-256 and P-384/SHA-384; RSA-PSS with SHA-256; Ed25519 (RFC 8419). Signed attributes are mandatory: content-type, message-digest, signing-time, `ESSCertIDv2` (RFC 5035). Attached and detached content. |
| Encoding | strict DER on output; DER and the indefinite-length BER that `openssl cms` streams by default on input |
| Recipient selection | `IssuerAndSerialNumber` and `SubjectKeyIdentifier` |
| Certificate policy | offline only: caller-supplied trust anchors, intermediates and CRLs; no network access anywhere in the library; EKU and validity checked at a caller-supplied time |

## Example

```go
var envelope bytes.Buffer
if err := cryptomsg.Encrypt(&envelope, zipFile, recipientCerts, nil); err != nil { … }

sig, err := cryptomsg.Sign(bytes.NewReader(envelope.Bytes()), signerKey, signerChain,
    &cryptomsg.SignOptions{Detached: true})

policy := &cryptomsg.Policy{Roots: roots, Intermediates: intermediates, CRLs: crls, Time: time.Now()}
if _, err := cryptomsg.Verify(sig, bytes.NewReader(envelope.Bytes()), policy); err != nil { … }

var plaintext bytes.Buffer
err = cryptomsg.Decrypt(&plaintext, &envelope, myCert, myKey, nil)
```

`Parse` returns a typed view of a CMS object — recipients, algorithms, signer certificates —
without any key, so a caller can report "encrypted for 3 recipients, signed by CN=…" before
deciding to decrypt. The `cryptomsg` CLI (`encrypt`, `decrypt`, `sign`, `verify`, `inspect`) is
a thin wrapper over the library.

## Status

Pre-release; the API may change until `v0.1.0`. See [`CHANGELOG.md`](CHANGELOG.md),
[`docs/design.md`](docs/design.md) for the structure and policy choices, [`docs/fips.md`](docs/fips.md)
for the FIPS 140-3 position, and [`SECURITY.md`](SECURITY.md) for reporting vulnerabilities.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).
