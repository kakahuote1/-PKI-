# Security Policy

## Supported Versions

TinyPKI is still pre-release. Security fixes are accepted on `main` and will be
carried into the next release tag.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| `v0.1.x` | Yes, after the first release |
| Older commits | Best effort only |

## Reporting a Vulnerability

Please report security issues through a private GitHub security advisory when
available, or contact the repository maintainer directly.

Do not publish exploitable details before a fix or mitigation is available. A
useful report should include the affected commit, build platform, reproduction
steps, expected impact, and any proof-of-concept input needed to reproduce the
issue.

## Security Scope

TinyPKI handles lightweight PKI flows for constrained devices and edge nodes:

- ECQV implicit certificate issuance and reconstruction.
- Certificate authentication and key agreement.
- Sparse Merkle revocation proofs.
- MMR-style issuance transparency proofs.
- CA-signed epoch checkpoints and evidence bundles.
- Edge witness threshold verification.
- Device checkpoint persistence and rollback detection within software limits.

## Non-goals

TinyPKI is not an HSM, secure element, certified cryptographic module, or a
complete WebPKI CT ecosystem. Pure software cannot prove that local device state
was not rolled back if an attacker can restore the entire local storage snapshot
and the device has no non-rollback counter, trusted clock, secure element, or
other protected monotonic state.

## Release Security Checklist

Before a release baseline is used, maintainers should run:

```powershell
powershell -ExecutionPolicy Bypass -File tools\check_format.ps1
cmake -S . -B build
cmake --build build -j 1
ctest --test-dir build --output-on-failure
.\build\test_all.exe
```

Security-sensitive changes should also update the threat model or audit notes in
`docs/security/` when the trust boundary, proof format, or key lifecycle changes.
