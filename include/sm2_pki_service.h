/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_pki_service.h
 * @brief In-memory CA/RA service APIs for registration, issuance and
 * revocation.
 */

#ifndef SM2_PKI_SERVICE_H
#define SM2_PKI_SERVICE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "sm2_pki_types.h"
#include "sm2_revocation.h"
#include "sm2_implicit_cert.h"
#include "sm2_pki_transparency.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SM2_PKI_MAX_IDENTITIES 256
#define SM2_PKI_MAX_ID_LEN 64
#define SM2_PKI_MAX_ISSUER_LEN 64
#define SM2_PKI_BROADCAST_DEFAULT_ROOT_VALIDITY_SEC 300U

    typedef struct sm2_pki_service_ctx_st sm2_pki_service_ctx_t;

    /*
     * CA broadcast policy.
     * Root validity and sync cadence are
     * configured together.
     */
    typedef struct
    {
        uint64_t root_validity_sec;
        uint64_t t_base_sec;
        uint64_t fast_poll_sec;
        uint64_t max_backoff_sec;
        uint64_t propagation_delay_sec;
        uint64_t full_checkpoint_interval_sec;
        size_t max_delta_chain_len;
        uint64_t urgent_delta_grace_sec;
    } sm2_pki_broadcast_policy_t;

    sm2_pki_error_t sm2_pki_broadcast_policy_init(
        sm2_pki_broadcast_policy_t *policy);

    sm2_ic_error_t sm2_pki_broadcast_policy_to_rev_sync(
        const sm2_pki_broadcast_policy_t *policy,
        sm2_rev_sync_policy_t *sync_policy);

    sm2_ic_error_t sm2_pki_broadcast_policy_sync_digest(
        const sm2_pki_broadcast_policy_t *policy,
        uint8_t digest[SM2_PKI_POLICY_DIGEST_LEN]);

    sm2_pki_error_t sm2_pki_service_set_broadcast_policy(
        sm2_pki_service_ctx_t *ctx, const sm2_pki_broadcast_policy_t *policy,
        uint64_t now_ts);

    sm2_pki_error_t sm2_pki_service_get_broadcast_policy(
        const sm2_pki_service_ctx_t *ctx, sm2_pki_broadcast_policy_t *policy);

    /*
     * Opaque owning handle.
     * Instances must be created/destroyed via the API below.
     */
    sm2_pki_error_t sm2_pki_service_create(sm2_pki_service_ctx_t **ctx,
        const uint8_t *issuer_id, size_t issuer_id_len,
        size_t expected_revoked_items, uint64_t filter_ttl_sec,
        uint64_t now_ts);

    void sm2_pki_service_destroy(sm2_pki_service_ctx_t **ctx);

    sm2_pki_error_t sm2_pki_service_get_ca_public_key(
        const sm2_pki_service_ctx_t *ctx, sm2_ec_point_t *ca_public_key);

    /*
     * Startup/self-check helper. Validates that the internally managed CA
     * signing key remains within the expected SM2 private key range.
     */
    sm2_pki_error_t sm2_pki_service_validate_ca_key_material(
        const sm2_pki_service_ctx_t *ctx);

    /*
     * Returns the CA-signed epoch root that binds the current revocation root
     * and issuance transparency root into one verifier checkpoint.
     */
    sm2_pki_error_t sm2_pki_service_get_epoch_root_record(
        const sm2_pki_service_ctx_t *ctx,
        sm2_pki_epoch_root_record_t *root_record);

    sm2_pki_error_t sm2_pki_service_set_epoch_policy_binding(
        sm2_pki_service_ctx_t *ctx, uint64_t witness_policy_version,
        const uint8_t witness_policy_hash[SM2_PKI_POLICY_DIGEST_LEN],
        uint64_t sync_policy_version,
        const uint8_t sync_policy_hash[SM2_PKI_POLICY_DIGEST_LEN],
        uint64_t now_ts);

    sm2_pki_error_t sm2_pki_service_get_issuance_commitment_count(
        const sm2_pki_service_ctx_t *ctx, size_t *commitment_count);

    sm2_pki_error_t sm2_pki_service_export_issuance_commitments(
        const sm2_pki_service_ctx_t *ctx, size_t start_index,
        sm2_pki_issuance_commitment_t *commitments, size_t commitment_capacity,
        size_t *commitment_count);

    /*
     * Explicitly publishes a fresh CA-signed revocation root/heartbeat object.
     * Query handling must not mint new signed facts implicitly.
     */
    sm2_pki_error_t sm2_pki_service_refresh_root(
        sm2_pki_service_ctx_t *ctx, uint64_t now_ts);

    sm2_pki_error_t sm2_pki_identity_register(sm2_pki_service_ctx_t *ctx,
        const uint8_t *identity, size_t identity_len, uint8_t key_usage);

    /*
     * New deployments must generate ECQV requests on the end-entity side and
     * submit them for authorization before issuance.
     */
    sm2_pki_error_t sm2_pki_cert_authorize_request(
        sm2_pki_service_ctx_t *ctx, const sm2_ic_cert_request_t *request);

    sm2_pki_error_t sm2_pki_cert_issue(sm2_pki_service_ctx_t *ctx,
        const sm2_ic_cert_request_t *request, uint64_t now_ts,
        sm2_ic_cert_result_t *result);

    sm2_pki_error_t sm2_pki_service_revoke(
        sm2_pki_service_ctx_t *ctx, uint64_t serial_number, uint64_t now_ts);

    sm2_pki_error_t sm2_pki_service_prune_expired_revocations(
        sm2_pki_service_ctx_t *ctx, uint64_t now_ts, uint64_t grace_sec,
        size_t *pruned_count);

    sm2_pki_error_t sm2_pki_service_check_revocation(sm2_pki_service_ctx_t *ctx,
        uint64_t serial_number, uint64_t now_ts, sm2_rev_status_t *status,
        sm2_rev_source_t *source);

#ifdef __cplusplus
}
#endif

#endif /* SM2_PKI_SERVICE_H */
