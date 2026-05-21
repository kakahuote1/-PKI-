# TinyPKI v0.1.0 Security Audit

Date: 2026-05-21

## Scope

This audit covers the `v0.1.0` release baseline for the following areas:

- ECQV certificate request, issuance, reconstruction, and verification.
- Authentication, key agreement, and secure session establishment.
- Sparse Merkle revocation proof generation and verification.
- Issuance transparency proofs and append-only witness signing.
- Epoch evidence bundles and edge checkpoint quorum checks.
- Persisted device checkpoint storage.
- Benchmark and test entry points that may be used as release evidence.

## Summary

No release-blocking security issue remains open in the audited code baseline.
The code now has explicit hardening for fixed-length BIGNUM export, malformed
CBOR length fields, failed key-agreement output clearing, quorum input bounds,
and benchmark reproducibility.

The remaining risks are documented deployment limits: TinyPKI cannot provide HSM
memory isolation, and pure software cannot prove that a whole local storage
snapshot was not rolled back without a protected monotonic value.

## PR #11 / V-010 Review

PR #11 was opened by `orbisai0security` on 2026-05-14 and closed without merge
on 2026-05-21. It proposed changing `src/auth/auth.c` so that
`EC_POINT_free(point)` becomes `EC_POINT_clear_free(point)` and
`EC_GROUP_free(group)` becomes `EC_GROUP_clear_free(group)` in the public-key
validation helper.

Review result:

- The specific `EC_POINT` in that helper is reconstructed from a peer public
  key. It does not contain private scalar material.
- The `EC_GROUP` is public SM2 curve/domain metadata. Clearing it does not
  improve private-key protection and may reduce OpenSSL-version portability.
- The `BN_CTX` at that exact site is used for public-point validation.
- The broader concern was still useful: contexts that participate in private
  scalar operations were reviewed separately.

Action taken:

- The PR was not merged as-is.
- Sensitive fixed-length BIGNUM exports now use `BN_bn2binpad` instead of
  manual offset arithmetic.
- ECQV request/reconstruction failure paths clear private-key outputs.
- Session key derivation and mutual-handshake paths clear output buffers on
  failure.
- BN contexts used in private scalar multiplication and ECQV private-key
  reconstruction paths use secure BN contexts.

## Confirmed Fixes In Baseline

| Area | Risk | Resolution |
| --- | --- | --- |
| Fixed-length scalar export | Future oversized BIGNUM could overflow manual output offset. | Replaced manual export with `BN_bn2binpad` and checked return values. |
| ECQV decode | Malformed CBOR length fields could exercise unsafe offset arithmetic. | Reworked decode checks to compare remaining length before copying. |
| Revocation proof CBOR | Shared CBOR helpers used addition-style capacity checks. | Added centralized remaining-space checks for encode/decode helpers. |
| Key agreement outputs | Failed handshakes could leave caller buffers containing old bytes. | Clear output buffers before derivation and on failure. |
| Epoch quorum API | Empty or oversized vote arrays depended on lower-level behavior. | Public API now rejects empty and over-limit vote counts directly. |
| Benchmark evidence | Timing data lacked enough reproducibility metadata. | Added seed, commit, dirty flag, platform, compiler, warmup rounds, p95, mean, stddev, and stability flags. |

## Verification

The following checks are required for this audit baseline:

```powershell
powershell -ExecutionPolicy Bypass -File tools\check_format.ps1
cmake -S . -B build
cmake --build build -j 1
ctest --test-dir build --output-on-failure
.\build\test_all.exe
.\build\sm2_bench_capability_suite.exe tmp\bench_capability_suite_audit.json
```

At the time this document was added, the baseline passed local format checks,
build, `ctest`, `test_all`, and benchmark smoke execution. The release baseline
also passed GitHub Actions on Linux and Windows.

## Residual Risk

- Memory disclosure after full host compromise is outside TinyPKI's threat
  boundary.
- Long-term private key custody should use hardware-backed storage where the
  deployment needs physical attack resistance.
- Device rollback protection is strongest when paired with a secure counter,
  trusted clock, secure element, or equivalent non-rollback state.
- The benchmark suite is suitable for comparative release evidence, but
  deployment-specific latency should be measured on the target hardware.
