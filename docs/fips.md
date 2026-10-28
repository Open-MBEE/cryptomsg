# FIPS 140-3 position

`cryptomsg` is **not** a validated cryptographic module and makes no FIPS claim of its own. It
is a protocol layer (ASN.1, CMS structures, certificate policy) over the cryptographic
primitives of the Go standard library, and the only FIPS-relevant statement that can be made
about it is which module performs the primitives when it is built in `GOFIPS140` mode.

## The Go Cryptographic Module — status as checked on 2026-10-28

Go 1.24 introduced the native FIPS 140-3 mode (`GOFIPS140=latest`, `GOFIPS140=v1.0.0`, …),
which routes `crypto/*` through the Go Cryptographic Module, a frozen snapshot of
`crypto/internal/fips140`. Sources: <https://go.dev/doc/security/fips140>, the NIST CMVP
certificate and the CMVP Modules In Process list, all read on the date above.

| Module version | Frozen from | Status (2026-10-28) |
|---|---|---|
| Go Cryptographic Module v1.0.0 | Go 1.24 | **CMVP Certificate #5247**, FIPS 140-3, Level 1, status *Active*, validated 2026-04-27 (Lightship Security), updated 2026-07-07, sunset 2031-04-26. CAVP certificates A6650 and A8668. Vendor: Geomys LLC. |
| Go Cryptographic Module v1.26.0 | Go 1.26 | **Not validated.** On the CMVP Modules In Process list (list last updated 2026-10-27) at "Comment Resolution – Lab (10/22/2026)". CAVP certificate A8028. |

Certificate #5247 carries the usual caveat: *"When operated in approved mode. No assurance of
the minimum strength of generated SSPs (e.g., keys). No assurance of minimum security of SSPs
that are externally loaded, or of SSPs established with externally loaded SSPs."*

What `GOFIPS140=latest` selects depends on the toolchain: with Go 1.24 and 1.25 it is
v1.0.0 (validated); with Go 1.26 it is v1.26.0 (in process). A deployment that needs the
validated module must therefore build with `GOFIPS140=v1.0.0` explicitly, with a Go 1.24+
toolchain that still ships that version, on an operating environment listed on the
certificate. Re-check the CMVP record before relying on any of this; validation status
changes and this page records only what was true on the date above.

## What the profile uses

All of the profile's primitives are FIPS-approved algorithms implemented inside the module:
AES-GCM and AES-CBC (SP 800-38A/D), AES key wrap (SP 800-38F), RSA-OAEP (SP 800-56B), RSA-PSS
and ECDSA (FIPS 186-5), Ed25519 (FIPS 186-5), ECDH on P-256/P-384 (SP 800-56A), SHA-2
(FIPS 180-4). The ANSI X9.63 KDF (SP 800-135, approved for CMS key agreement) is not exposed
by the standard library and is implemented in this repository over the module's SHA-2 — it is
therefore *outside* the module boundary, as is every ASN.1 and CMS structure here.

## How CI exercises it

The CI workflow runs the test suite once under `GOFIPS140=latest` so that no code path depends
on a primitive the module does not provide. That job checks compatibility with the FIPS build
mode; it does not and cannot confer validation on this library.
