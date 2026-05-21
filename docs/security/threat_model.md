# TinyPKI Threat Model

Date: 2026-05-21

## Scope

This model covers TinyPKI as a C library and command-line benchmark/demo suite.
The primary deployment model has three roles:

- Lightweight device: stores its own certificate, private key, trusted CA
  material, recent CA-signed epoch checkpoints, and minimal verified state.
- Edge node: caches revocation and issuance state, builds evidence bundles, and
  can act as an epoch witness.
- CA: issues ECQV certificates, signs revocation roots, signs issuance roots,
  and publishes epoch checkpoints.

The model focuses on certificate issuance, revocation status, issuance
transparency, evidence verification, edge quorum checks, and local state
persistence.

## Assets

- Device private keys and ephemeral key material.
- CA private keys and witness private keys.
- ECQV private reconstruction values.
- CA-signed epoch root records.
- Sparse Merkle revocation roots and proofs.
- Issuance commitments, MMR roots, and member proofs.
- Witness threshold signatures over epoch roots.
- Persisted device checkpoint state and its authentication tag.
- Evidence bundles carried during authentication.

## Trust Boundaries

- Device to edge node: untrusted network. Evidence from the edge must verify
  against a CA-signed checkpoint already trusted by the device.
- Edge node to CA: edge nodes may be delayed, partitioned, or malicious. CA root
  signatures and witness append-only checks constrain what can be accepted.
- Device local storage: authenticated but not physically protected. HMAC detects
  tampering, while sequence floors detect rollback only when some non-rollback
  state survives.
- Benchmark and demo outputs: not security inputs. Generated files under `tmp/`
  are evidence artifacts, not trusted protocol state.

## Attacker Capabilities

The attacker may observe, replay, delay, drop, or modify network traffic. The
attacker may operate malicious edge nodes, provide stale evidence, attempt
rollback to older checkpoints, tamper with serialized proofs, or trigger decode
paths with malformed inputs.

The attacker is not assumed to break SM2, SM3, SM4, OpenSSL's primitive
implementations, or private keys that are not exposed by the host environment.
If the host process memory is fully compromised, TinyPKI cannot protect secrets
already present in memory.

## Main Abuse Paths And Mitigations

| Abuse path | Mitigation |
| --- | --- |
| Edge node returns a fabricated revocation proof | Device recomputes the Sparse Merkle root and compares it with the CA-signed epoch checkpoint. |
| Edge node returns a stale but valid old root | Client freshness policy, epoch version checks, checkpoint cache, and persisted sequence floor reject known rollback. |
| CA attempts hidden issuance | Issuance commitments are bound into an append-only MMR root, signed by the CA, and checked by edge witnesses before threshold acceptance. |
| CA or edge presents forked roots to different devices | Edge checkpoint quorum compares epoch digests and marks conflicts/forks. |
| Witness signs a non-append-only issuance history | Witness signing path verifies the previous frontier and candidate commitments before signing the new root. |
| Evidence bundle mixes roots from different authorities | Authority id, CA index, root versions, root hashes, and epoch digest are bound into verification and cache entries. |
| Serialized proof uses malicious length fields | CBOR and evidence bundle decoders validate lengths before copying and reject unsupported critical sections. |
| Failed key agreement leaves stale output bytes | Key derivation and handshake paths clear output buffers before and after failed operations. |
| Local persisted state is modified | Double-slot storage verifies HMAC-SM3 tags over domain, sequence, and state. |
| Full local storage snapshot is rolled back | Pure software cannot fully solve this without a protected monotonic value; TinyPKI documents this as a residual deployment requirement. |

## Residual Risks

- Host memory compromise, core dumps, swap, and debugger access are outside the
  protection offered by a software-only C library.
- Local rollback protection is bounded by whether the device can retain a
  monotonic value outside attacker-controlled storage.
- The project has a compact CT-style design for TinyPKI's own roles; it does not
  include the full WebPKI CT ecosystem of public logs, monitors, and browsers.
- Benchmarks are local comparative evidence, not a formal performance guarantee
  for every deployment platform.

## Release Baseline

The `v0.1.0` baseline is the release tag and the corresponding `main` history
that contain this document and the accompanying secure-context hardening
changes.
