# Security policy

## Reporting a vulnerability

Report vulnerabilities **privately**, through GitHub's private vulnerability reporting:
[Security → Report a vulnerability](https://github.com/Open-MBEE/cryptomsg/security/advisories/new)
on this repository. Do not open a public issue, pull request or discussion for anything you
believe is a security problem, and do not publish a working exploit before the advisory is
published.

A report is most useful when it has:

- the affected API or command (`Encrypt`, `Decrypt`, `Sign`, `Verify`, `Parse`, or a
  `cryptomsg` CLI subcommand) and the module version or commit;
- a minimal reproducer: the CMS object, certificates and the call or command line that
  trigger the problem (test keys only — never send a private key you use);
- the impact as you understand it: plaintext recovery, signature forgery, acceptance of an
  untrusted or revoked signer, denial of service, information leak.

The maintainers of Open-MBEE handle reports. If a report has gone a week without an
acknowledgement, say so (and only that a private report is waiting) on any issue of this
repository.

## What to expect

| Step | Deadline, from receipt |
|---|---|
| Acknowledgement | 3 business days |
| Triage: confirmed or not, severity (CVSS v3.1), affected versions | 7 calendar days |
| Fix released, **critical** severity | 14 calendar days |
| Fix released, **high** or **medium** severity | 60 calendar days |
| Fix released, **low** severity | next regular release |

Fixes are released as a new tagged version; the advisory is published with the release and
credits the reporter unless they ask otherwise. Please allow the fix to ship before
disclosing.

## Scope

In scope: anything that makes the library accept what the profile says it must refuse,
release plaintext before authentication, leak key or plaintext material, or misreport a
verification result. Out of scope: weaknesses of the algorithms the profile mandates (report
those to the standards bodies), and findings that require a compromised caller environment.
