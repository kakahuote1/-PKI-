# Changelog

All notable changes to TinyPKI are recorded in this file.

The project is still pre-1.0. Entries describe the current release-candidate
baseline on `main`; version tags should be added here when a formal release is
cut.

## Unreleased

### Added

- ECQV implicit certificate lifecycle support, including request generation, CA
  issuance, endpoint key reconstruction, and certificate verification.
- Path-compressed sparse Merkle revocation proofs with member, absence, and
  multiproof verification paths.
- MMR-based issuance transparency with certificate commitments, issuance member
  proofs, CA-signed epoch roots, and append-only witness checks.
- Unified evidence bundles that bind revocation proofs, issuance proofs,
  witness signatures, CA identity, root versions, and freshness metadata.
- CRL-style revocation publication scheduling with `nextUpdate`, delta updates,
  heartbeat refresh, redirect hints, quorum checks, and rollback-aware device
  state persistence.
- Static and ephemeral authentication flows with handshake binding and
  SM4-GCM/CCM session protection.
- Capability and network benchmark programs that emit JSON and Markdown reports
  with reproducibility metadata.
- Standard project documentation: installation guide, security policy, threat
  model, and release-candidate security audit.

### Changed

- Public integration guidance now points callers to the high-level PKI service
  and client APIs instead of internal tree or authentication primitives.
- Revocation state is represented by a path-compressed sparse Merkle structure,
  reducing unnecessary empty-branch work while preserving offline proof
  verification.
- Issuance transparency uses an append-only MMR commitment flow, avoiding
  rebuild-heavy ordinary Merkle trees for sequential certificate issuance.
- Evidence verification caches only authenticated summaries and never treats
  cached data as an independent trust source.
- Documentation was reduced to the standard release-facing set required for
  build, security, contribution, and audit review.

### Security

- Hardened fixed-length BIGNUM export paths with checked `BN_bn2binpad`
  conversion.
- Cleared key-agreement outputs on failure to avoid stale caller-visible bytes.
- Added stricter CBOR and evidence-bundle length validation.
- Added explicit bounds checks for epoch quorum inputs.
- Reviewed PR #11 manually and documented why its exact public-key validation
  cleanup was not merged as-is.
- Switched BN contexts that participate in private scalar operations to secure
  BN contexts.

### Verification

- Current automated baseline: 6 `ctest` suites and 108 aggregated `test_all`
  cases.
- CI build coverage includes Linux and Windows workflows.
- Local release checks are expected to include format checking, build,
  `ctest`, `test_all`, and benchmark smoke execution.
