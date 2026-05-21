/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/time.h>
#endif

#ifdef X509_NAME
#undef X509_NAME
#endif
#ifdef OCSP_REQUEST
#undef OCSP_REQUEST
#endif
#ifdef OCSP_RESPONSE
#undef OCSP_RESPONSE
#endif

#include "sm2_pki_client.h"
#include "sm2_pki_service.h"
#include "../revoke/revoke_internal.h"

#define BENCH_ROUNDS 21U
#define BENCH_WARMUP_ROUNDS 3U
#define BENCH_REPRO_SEED 20260520ULL
#define BENCH_STABLE_MAX_REL_STDDEV 0.50
#define BENCH_STABLE_MAX_P95_TO_MEDIAN 3.00
#define BENCH_BASELINE_X509_BITS 2048
#define BENCH_BASELINE_CRL_ENTRIES 2048U
#define BENCH_SCALE_TOTAL_CERTS 1048576U
#define BENCH_SCALE_REVOKED_CERTS 32768U
#define BENCH_SCALE_QUERY_COUNT 4096U
#define BENCH_SCALE_PROVE_ROUNDS 5U
#define BENCH_CRLITE_MAX_LEVELS 4U
#define BENCH_CRLITE_FP_RATE 0.01
#define BENCH_CRLITE_DELTA_FRACTION 0.05

#ifndef BENCH_GIT_COMMIT
#define BENCH_GIT_COMMIT "unknown"
#endif

#ifndef BENCH_GIT_DIRTY
#define BENCH_GIT_DIRTY 0
#endif

static int bench_output_path_is_safe(const char *path)
{
    if (!path || path[0] == '\0')
        return 0;
    if (path[0] == '/' || path[0] == '\\')
        return 0;
    if (((path[0] >= 'A' && path[0] <= 'Z')
            || (path[0] >= 'a' && path[0] <= 'z'))
        && path[1] == ':' && (path[2] == '/' || path[2] == '\\'))
    {
        return 0;
    }
    if (strstr(path, "..") != NULL)
        return 0;

    if (path[0] == '.' && (path[1] == '/' || path[1] == '\\'))
        path += 2;
    return strncmp(path, "tmp/", 4) == 0 || strncmp(path, "tmp\\", 4) == 0;
}

typedef struct
{
    size_t sample_count;
    double min_ms;
    double median_ms;
    double p95_ms;
    double max_ms;
    double mean_ms;
    double stddev_ms;
    double rel_stddev;
    double p95_to_median;
    int stable;
} bench_timing_stats_t;
typedef struct
{
    size_t cert_bytes;
    size_t signature_bytes;
    size_t epoch_root_bytes;
    size_t revocation_proof_bytes;
    size_t issuance_proof_bytes;
    size_t witness_signature_bytes;
    size_t evidence_bundle_bytes;
    size_t authentication_bundle_bytes;
} capability_size_metrics_t;

typedef struct
{
    double export_epoch_evidence_ms;
    double witness_sign_ms;
    double verify_epoch_bundle_ms;
    bench_timing_stats_t export_epoch_evidence_stats;
    bench_timing_stats_t witness_sign_stats;
    bench_timing_stats_t verify_epoch_bundle_stats;
} capability_timing_metrics_t;

typedef struct
{
    size_t x509_cert_bytes;
    size_t crl_entry_count;
    size_t crl_der_bytes;
    size_t scale_crl_entry_count;
    size_t scale_crl_der_bytes;
    size_t crl_delta_bytes;
    size_t ocsp_request_bytes;
    size_t ocsp_response_bytes;
    size_t ocsp_wire_bytes;
    double crl_verify_lookup_ms;
    double scale_crl_verify_lookup_ms;
    double ocsp_verify_ms;
    bench_timing_stats_t crl_verify_lookup_stats;
    bench_timing_stats_t scale_crl_verify_lookup_stats;
    bench_timing_stats_t ocsp_verify_stats;
} openssl_revocation_metrics_t;

typedef struct
{
    size_t total_certs;
    size_t revoked_certs;
    size_t query_count;
    size_t level_count;
    size_t filter_bytes;
    size_t delta_bytes;
    size_t repaired_false_positive_count;
    size_t query_error_count;
    double lookup_ms;
    double lookup_per_query_us;
    bench_timing_stats_t lookup_stats;
} crlite_metrics_t;

typedef struct
{
    size_t revoked_certs;
    size_t proof_bytes;
    size_t edge_tree_storage_estimate_bytes;
    size_t verifier_cache_bytes;
    double prove_absence_ms;
    double verify_absence_ms;
    bench_timing_stats_t prove_absence_stats;
    bench_timing_stats_t verify_absence_stats;
} tinypki_revocation_scale_metrics_t;

typedef struct
{
    openssl_revocation_metrics_t openssl;
    crlite_metrics_t crlite;
    tinypki_revocation_scale_metrics_t tinypki_revocation;
} comparison_metrics_t;

typedef struct
{
    sm2_pki_service_ctx_t *service;
    sm2_pki_client_ctx_t *signer;
    sm2_pki_client_ctx_t *verifier;
    sm2_ec_point_t ca_pub;
    sm2_ic_cert_result_t cert_result;
    sm2_private_key_t temp_private_key;
    sm2_private_key_t witness_private_key;
    sm2_ec_point_t witness_public_key;
    sm2_pki_transparency_witness_t witness;
    sm2_pki_transparency_policy_t policy;
    sm2_auth_signature_t signature;
    sm2_pki_evidence_bundle_t evidence;
    sm2_pki_epoch_checkpoint_t checkpoint;
    sm2_pki_verify_request_t request;
    uint8_t message[64];
    size_t message_len;
    uint64_t auth_now;
} capability_flow_ctx_t;

static double now_ms_highres(void)
{
#if defined(_WIN32)
    static LARGE_INTEGER freq;
    static int initialized = 0;
    LARGE_INTEGER counter;
    if (!initialized)
    {
        QueryPerformanceFrequency(&freq);
        initialized = 1;
    }
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
#endif
}

static int cmp_double_asc(const void *lhs, const void *rhs)
{
    double a = *(const double *)lhs;
    double b = *(const double *)rhs;
    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}

static int timing_stats_from_samples(
    double *samples, size_t count, bench_timing_stats_t *stats)
{
    double sum = 0.0;
    double variance = 0.0;
    size_t p95_index;

    if (!samples || count == 0U || !stats)
        return 0;

    memset(stats, 0, sizeof(*stats));
    for (size_t i = 0; i < count; i++)
    {
        if (samples[i] < 0.0)
            return 0;
        sum += samples[i];
    }

    qsort(samples, count, sizeof(samples[0]), cmp_double_asc);
    stats->sample_count = count;
    stats->min_ms = samples[0];
    stats->max_ms = samples[count - 1U];
    stats->mean_ms = sum / (double)count;
    if ((count & 1U) != 0U)
        stats->median_ms = samples[count / 2U];
    else
        stats->median_ms
            = (samples[(count / 2U) - 1U] + samples[count / 2U]) / 2.0;

    p95_index = (size_t)ceil((double)count * 0.95);
    if (p95_index == 0U)
        p95_index = 1U;
    if (p95_index > count)
        p95_index = count;
    stats->p95_ms = samples[p95_index - 1U];

    for (size_t i = 0; i < count; i++)
    {
        double delta = samples[i] - stats->mean_ms;
        variance += delta * delta;
    }
    stats->stddev_ms = sqrt(variance / (double)count);
    stats->rel_stddev
        = stats->mean_ms > 0.0 ? stats->stddev_ms / stats->mean_ms : 0.0;
    stats->p95_to_median
        = stats->median_ms > 0.0 ? stats->p95_ms / stats->median_ms : 0.0;
    stats->stable = count >= 5U
        && stats->rel_stddev <= BENCH_STABLE_MAX_REL_STDDEV
        && stats->p95_to_median <= BENCH_STABLE_MAX_P95_TO_MEDIAN;
    return 1;
}

static const char *bench_bool_json(int value)
{
    return value ? "true" : "false";
}

static const char *bench_os_name(void)
{
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

static const char *bench_compiler_name(void)
{
#if defined(__clang__)
    return "clang";
#elif defined(__GNUC__)
    return "gcc";
#elif defined(_MSC_VER)
    return "msvc";
#else
    return "unknown";
#endif
}

static const char *bench_build_mode(void)
{
#if defined(NDEBUG)
    return "release";
#else
    return "debug";
#endif
}

static uint64_t current_unix_ts(void)
{
    time_t now = time(NULL);
    return now < 0 ? 0U : (uint64_t)now;
}

static int create_rsa_pkey(EVP_PKEY **out_pkey, int bits)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    if (!out_pkey)
        return 0;
    *out_pkey = NULL;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx)
        goto cleanup;
    if (EVP_PKEY_keygen_init(kctx) != 1)
        goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, bits) != 1)
        goto cleanup;
    if (EVP_PKEY_keygen(kctx, &pkey) != 1)
        goto cleanup;

    *out_pkey = pkey;
    pkey = NULL;
    ok = 1;

cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return ok;
}

static int add_name_cn(X509_NAME *name, const char *cn)
{
    if (!name || !cn)
        return 0;
    return X509_NAME_add_entry_by_txt(
               name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0)
        == 1;
}

static int add_cert_ext(X509 *cert, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509_EXTENSION *ext = NULL;
    int ok = 0;

    if (!cert || !value)
        return 0;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
    if (!ext)
        goto cleanup;
    if (X509_add_ext(cert, ext, -1) != 1)
        goto cleanup;
    ok = 1;

cleanup:
    X509_EXTENSION_free(ext);
    return ok;
}

static int create_ca_cert(EVP_PKEY *ca_key, X509 **out_cert)
{
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    int ok = 0;

    if (!ca_key || !out_cert)
        return 0;
    *out_cert = NULL;

    cert = X509_new();
    if (!cert)
        goto cleanup;
    if (X509_set_version(cert, 2L) != 1)
        goto cleanup;
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert), 1L) != 1)
        goto cleanup;
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), -3600L)
        || !X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L))
    {
        goto cleanup;
    }
    if (X509_set_pubkey(cert, ca_key) != 1)
        goto cleanup;

    name = X509_get_subject_name(cert);
    if (!name || !add_name_cn(name, "TinyPKI Bench CA"))
        goto cleanup;
    if (X509_set_issuer_name(cert, name) != 1)
        goto cleanup;
    if (!add_cert_ext(cert, cert, NID_basic_constraints, "critical,CA:TRUE")
        || !add_cert_ext(cert, cert, NID_key_usage,
            "critical,keyCertSign,cRLSign,digitalSignature")
        || !add_cert_ext(cert, cert, NID_subject_key_identifier, "hash"))
    {
        goto cleanup;
    }
    if (X509_sign(cert, ca_key, EVP_sha256()) <= 0)
        goto cleanup;

    *out_cert = cert;
    cert = NULL;
    ok = 1;

cleanup:
    X509_free(cert);
    return ok;
}

static int create_leaf_cert(EVP_PKEY *leaf_key, X509 *ca_cert, EVP_PKEY *ca_key,
    long serial, X509 **out_cert)
{
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    int ok = 0;

    if (!leaf_key || !ca_cert || !ca_key || !out_cert)
        return 0;
    *out_cert = NULL;

    cert = X509_new();
    if (!cert)
        goto cleanup;
    if (X509_set_version(cert, 2L) != 1)
        goto cleanup;
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) != 1)
        goto cleanup;
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), -3600L)
        || !X509_gmtime_adj(X509_getm_notAfter(cert), 2592000L))
    {
        goto cleanup;
    }
    if (X509_set_pubkey(cert, leaf_key) != 1)
        goto cleanup;

    name = X509_get_subject_name(cert);
    if (!name || !add_name_cn(name, "TinyPKI Bench Leaf"))
        goto cleanup;
    if (X509_set_issuer_name(cert, X509_get_subject_name(ca_cert)) != 1)
        goto cleanup;
    if (!add_cert_ext(cert, ca_cert, NID_basic_constraints, "critical,CA:FALSE")
        || !add_cert_ext(cert, ca_cert, NID_key_usage,
            "critical,digitalSignature,keyEncipherment")
        || !add_cert_ext(
            cert, ca_cert, NID_ext_key_usage, "serverAuth,clientAuth"))
    {
        goto cleanup;
    }
    if (X509_sign(cert, ca_key, EVP_sha256()) <= 0)
        goto cleanup;

    *out_cert = cert;
    cert = NULL;
    ok = 1;

cleanup:
    X509_free(cert);
    return ok;
}

static int build_signed_crl(X509 *ca_cert, EVP_PKEY *ca_key, long leaf_serial,
    size_t entry_count, X509_CRL **out_crl, size_t *out_der_len)
{
    X509_CRL *crl = NULL;
    ASN1_TIME *last_update = NULL;
    ASN1_TIME *next_update = NULL;
    int der_len = 0;
    int ok = 0;

    if (!ca_cert || !ca_key || !out_crl || !out_der_len || entry_count == 0U)
        return 0;
    *out_crl = NULL;
    *out_der_len = 0U;

    crl = X509_CRL_new();
    if (!crl)
        goto cleanup;
    if (X509_CRL_set_version(crl, 1L) != 1)
        goto cleanup;
    if (X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca_cert)) != 1)
        goto cleanup;

    last_update = ASN1_TIME_new();
    next_update = ASN1_TIME_new();
    if (!last_update || !next_update)
        goto cleanup;
    if (!X509_gmtime_adj(last_update, 0L)
        || !X509_gmtime_adj(next_update, 7L * 24L * 3600L))
    {
        goto cleanup;
    }
    if (X509_CRL_set1_lastUpdate(crl, last_update) != 1
        || X509_CRL_set1_nextUpdate(crl, next_update) != 1)
    {
        goto cleanup;
    }

    for (size_t i = 0; i < entry_count; i++)
    {
        X509_REVOKED *revoked = NULL;
        ASN1_INTEGER *serial = NULL;
        ASN1_TIME *revocation_time = NULL;
        long serial_value = (i == 0U) ? leaf_serial : (long)(100000L + i);

        revoked = X509_REVOKED_new();
        serial = ASN1_INTEGER_new();
        revocation_time = ASN1_TIME_new();
        if (!revoked || !serial || !revocation_time)
        {
            X509_REVOKED_free(revoked);
            ASN1_INTEGER_free(serial);
            ASN1_TIME_free(revocation_time);
            goto cleanup;
        }
        if (ASN1_INTEGER_set(serial, serial_value) != 1
            || !X509_gmtime_adj(revocation_time, -(long)(i % 3600U))
            || X509_REVOKED_set_serialNumber(revoked, serial) != 1
            || X509_REVOKED_set_revocationDate(revoked, revocation_time) != 1
            || X509_CRL_add0_revoked(crl, revoked) != 1)
        {
            X509_REVOKED_free(revoked);
            ASN1_INTEGER_free(serial);
            ASN1_TIME_free(revocation_time);
            goto cleanup;
        }
        ASN1_INTEGER_free(serial);
        ASN1_TIME_free(revocation_time);
    }

    if (X509_CRL_sort(crl) != 1
        || X509_CRL_sign(crl, ca_key, EVP_sha256()) <= 0)
    {
        goto cleanup;
    }
    der_len = i2d_X509_CRL(crl, NULL);
    if (der_len <= 0)
        goto cleanup;

    *out_crl = crl;
    *out_der_len = (size_t)der_len;
    crl = NULL;
    ok = 1;

cleanup:
    ASN1_TIME_free(last_update);
    ASN1_TIME_free(next_update);
    X509_CRL_free(crl);
    return ok;
}

static int build_ocsp_artifacts(X509 *ca_cert, EVP_PKEY *ca_key,
    X509 *leaf_cert, OCSP_REQUEST **out_request, OCSP_RESPONSE **out_response,
    size_t *out_request_bytes, size_t *out_response_bytes)
{
    OCSP_CERTID *cid = NULL;
    OCSP_CERTID *status_id = NULL;
    OCSP_REQUEST *request = NULL;
    OCSP_BASICRESP *basic = NULL;
    OCSP_RESPONSE *response = NULL;
    ASN1_TIME *revtime = NULL;
    ASN1_TIME *thisupd = NULL;
    ASN1_TIME *nextupd = NULL;
    int req_len = 0;
    int resp_len = 0;

    if (!ca_cert || !ca_key || !leaf_cert || !out_request || !out_response
        || !out_request_bytes || !out_response_bytes)
    {
        return 0;
    }
    *out_request = NULL;
    *out_response = NULL;
    *out_request_bytes = 0U;
    *out_response_bytes = 0U;

    cid = OCSP_cert_to_id(EVP_sha1(), leaf_cert, ca_cert);
    request = OCSP_REQUEST_new();
    basic = OCSP_BASICRESP_new();
    revtime = ASN1_TIME_new();
    thisupd = ASN1_TIME_new();
    nextupd = ASN1_TIME_new();
    if (!cid || !request || !basic || !revtime || !thisupd || !nextupd)
        goto cleanup;
    if (OCSP_request_add0_id(request, cid) == NULL)
        goto cleanup;
    cid = NULL;

    if (!X509_gmtime_adj(revtime, -60L) || !X509_gmtime_adj(thisupd, 0L)
        || !X509_gmtime_adj(nextupd, 4L * 24L * 3600L))
    {
        goto cleanup;
    }
    status_id = OCSP_cert_to_id(EVP_sha1(), leaf_cert, ca_cert);
    if (!status_id
        || OCSP_basic_add1_status(basic, status_id, V_OCSP_CERTSTATUS_REVOKED,
               OCSP_REVOKED_STATUS_NOSTATUS, revtime, thisupd, nextupd)
            == NULL)
    {
        goto cleanup;
    }
    if (OCSP_basic_sign(basic, ca_cert, ca_key, EVP_sha256(), NULL, 0) != 1)
        goto cleanup;
    response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    if (!response)
        goto cleanup;
    basic = NULL;

    req_len = i2d_OCSP_REQUEST(request, NULL);
    resp_len = i2d_OCSP_RESPONSE(response, NULL);
    if (req_len <= 0 || resp_len <= 0)
        goto cleanup;

    *out_request = request;
    *out_response = response;
    *out_request_bytes = (size_t)req_len;
    *out_response_bytes = (size_t)resp_len;
    request = NULL;
    response = NULL;

cleanup:
    OCSP_CERTID_free(cid);
    OCSP_CERTID_free(status_id);
    OCSP_REQUEST_free(request);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(response);
    ASN1_TIME_free(revtime);
    ASN1_TIME_free(thisupd);
    ASN1_TIME_free(nextupd);
    return *out_request && *out_response;
}

static int measure_crl_verify_lookup(X509_CRL *crl, EVP_PKEY *ca_key,
    long lookup_serial, double *out_median_ms, bench_timing_stats_t *out_stats)
{
    double samples[BENCH_ROUNDS];
    ASN1_INTEGER *serial = NULL;

    if (!crl || !ca_key || !out_median_ms || !out_stats)
        return 0;
    memset(samples, 0, sizeof(samples));

    serial = ASN1_INTEGER_new();
    if (!serial || ASN1_INTEGER_set(serial, lookup_serial) != 1)
    {
        ASN1_INTEGER_free(serial);
        return 0;
    }

    for (size_t i = 0; i < BENCH_WARMUP_ROUNDS + BENCH_ROUNDS; i++)
    {
        X509_REVOKED *revoked = NULL;
        double t0 = now_ms_highres();
        if (X509_CRL_verify(crl, ca_key) != 1
            || X509_CRL_get0_by_serial(crl, &revoked, serial) != 1 || !revoked)
        {
            ASN1_INTEGER_free(serial);
            return 0;
        }
        if (i >= BENCH_WARMUP_ROUNDS)
            samples[i - BENCH_WARMUP_ROUNDS] = now_ms_highres() - t0;
    }

    ASN1_INTEGER_free(serial);
    if (!timing_stats_from_samples(samples, BENCH_ROUNDS, out_stats))
        return 0;
    *out_median_ms = out_stats->median_ms;
    return *out_median_ms > 0.0;
}

static int measure_ocsp_verify(OCSP_RESPONSE *response, X509 *ca_cert,
    X509 *leaf_cert, double *out_median_ms, bench_timing_stats_t *out_stats)
{
    X509_STORE *store = NULL;
    double samples[BENCH_ROUNDS];

    if (!response || !ca_cert || !leaf_cert || !out_median_ms || !out_stats)
        return 0;
    memset(samples, 0, sizeof(samples));

    store = X509_STORE_new();
    if (!store || X509_STORE_add_cert(store, ca_cert) != 1)
    {
        X509_STORE_free(store);
        return 0;
    }

    for (size_t i = 0; i < BENCH_WARMUP_ROUNDS + BENCH_ROUNDS; i++)
    {
        OCSP_BASICRESP *basic = NULL;
        OCSP_CERTID *cid = NULL;
        int status = -1;
        int reason = -1;
        ASN1_GENERALIZEDTIME *revtime = NULL;
        ASN1_GENERALIZEDTIME *thisupd = NULL;
        ASN1_GENERALIZEDTIME *nextupd = NULL;
        double t0 = now_ms_highres();

        if (OCSP_response_status(response) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
        {
            X509_STORE_free(store);
            return 0;
        }
        basic = OCSP_response_get1_basic(response);
        cid = OCSP_cert_to_id(EVP_sha1(), leaf_cert, ca_cert);
        if (!basic || !cid || OCSP_basic_verify(basic, NULL, store, 0) != 1
            || OCSP_resp_find_status(
                   basic, cid, &status, &reason, &revtime, &thisupd, &nextupd)
                != 1
            || status != V_OCSP_CERTSTATUS_REVOKED
            || OCSP_check_validity(thisupd, nextupd, 300L, -1L) != 1)
        {
            OCSP_BASICRESP_free(basic);
            OCSP_CERTID_free(cid);
            X509_STORE_free(store);
            return 0;
        }

        if (i >= BENCH_WARMUP_ROUNDS)
            samples[i - BENCH_WARMUP_ROUNDS] = now_ms_highres() - t0;
        OCSP_BASICRESP_free(basic);
        OCSP_CERTID_free(cid);
    }

    X509_STORE_free(store);
    if (!timing_stats_from_samples(samples, BENCH_ROUNDS, out_stats))
        return 0;
    *out_median_ms = out_stats->median_ms;
    return *out_median_ms > 0.0;
}

static int collect_openssl_revocation_metrics(
    openssl_revocation_metrics_t *metrics)
{
    EVP_PKEY *ca_key = NULL;
    EVP_PKEY *leaf_key = NULL;
    X509 *ca_cert = NULL;
    X509 *leaf_cert = NULL;
    X509_CRL *crl = NULL;
    X509_CRL *scale_crl = NULL;
    OCSP_REQUEST *ocsp_request = NULL;
    OCSP_RESPONSE *ocsp_response = NULL;
    const long leaf_serial = 2000L;
    int x509_der_len = 0;
    int ok = 0;

    if (!metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));

    if (!create_rsa_pkey(&ca_key, BENCH_BASELINE_X509_BITS)
        || !create_rsa_pkey(&leaf_key, BENCH_BASELINE_X509_BITS)
        || !create_ca_cert(ca_key, &ca_cert)
        || !create_leaf_cert(leaf_key, ca_cert, ca_key, leaf_serial, &leaf_cert)
        || !build_signed_crl(ca_cert, ca_key, leaf_serial,
            BENCH_BASELINE_CRL_ENTRIES, &crl, &metrics->crl_der_bytes)
        || !build_signed_crl(ca_cert, ca_key, leaf_serial,
            BENCH_SCALE_REVOKED_CERTS, &scale_crl,
            &metrics->scale_crl_der_bytes)
        || !build_ocsp_artifacts(ca_cert, ca_key, leaf_cert, &ocsp_request,
            &ocsp_response, &metrics->ocsp_request_bytes,
            &metrics->ocsp_response_bytes))
    {
        goto cleanup;
    }

    x509_der_len = i2d_X509(leaf_cert, NULL);
    if (x509_der_len <= 0)
        goto cleanup;
    metrics->x509_cert_bytes = (size_t)x509_der_len;
    metrics->crl_entry_count = BENCH_BASELINE_CRL_ENTRIES;
    metrics->scale_crl_entry_count = BENCH_SCALE_REVOKED_CERTS;
    metrics->crl_delta_bytes = (size_t)ceil(
        (double)metrics->scale_crl_der_bytes * BENCH_CRLITE_DELTA_FRACTION);
    metrics->ocsp_wire_bytes
        = metrics->ocsp_request_bytes + metrics->ocsp_response_bytes;

    if (!measure_crl_verify_lookup(crl, ca_key, leaf_serial,
            &metrics->crl_verify_lookup_ms, &metrics->crl_verify_lookup_stats)
        || !measure_crl_verify_lookup(scale_crl, ca_key, leaf_serial,
            &metrics->scale_crl_verify_lookup_ms,
            &metrics->scale_crl_verify_lookup_stats)
        || !measure_ocsp_verify(ocsp_response, ca_cert, leaf_cert,
            &metrics->ocsp_verify_ms, &metrics->ocsp_verify_stats))
    {
        goto cleanup;
    }

    ok = metrics->x509_cert_bytes > 0U && metrics->crl_der_bytes > 0U
        && metrics->scale_crl_der_bytes > 0U && metrics->ocsp_wire_bytes > 0U;

cleanup:
    X509_CRL_free(crl);
    X509_CRL_free(scale_crl);
    OCSP_REQUEST_free(ocsp_request);
    OCSP_RESPONSE_free(ocsp_response);
    X509_free(ca_cert);
    X509_free(leaf_cert);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(leaf_key);
    return ok;
}

static int issue_identity_cert(sm2_pki_service_ctx_t *service,
    const uint8_t *identity, size_t identity_len, uint8_t key_usage,
    sm2_ic_cert_result_t *cert_result, sm2_private_key_t *temp_private_key)
{
    sm2_ic_cert_request_t request;
    memset(&request, 0, sizeof(request));
    if (sm2_ic_create_cert_request(
            &request, identity, identity_len, key_usage, temp_private_key)
        != SM2_IC_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_cert_authorize_request(service, &request) != SM2_PKI_SUCCESS)
        return 0;
    return sm2_pki_cert_issue(service, &request, current_unix_ts(), cert_result)
        == SM2_PKI_SUCCESS;
}

static int get_identity_material(sm2_pki_client_ctx_t *client,
    const sm2_implicit_cert_t **cert, const sm2_ec_point_t **public_key)
{
    return sm2_pki_client_get_cert(client, cert) == SM2_PKI_SUCCESS
        && sm2_pki_client_get_public_key(client, public_key) == SM2_PKI_SUCCESS;
}

static int bind_epoch_policy(capability_flow_ctx_t *ctx)
{
    uint8_t witness_digest[SM2_PKI_POLICY_DIGEST_LEN];
    uint8_t sync_digest[SM2_PKI_POLICY_DIGEST_LEN];
    if (!ctx || !ctx->service)
        return 0;
    if (sm2_pki_transparency_policy_digest(&ctx->policy, witness_digest)
            != SM2_IC_SUCCESS
        || sm2_pki_default_sync_policy_digest(sync_digest) != SM2_IC_SUCCESS)
    {
        return 0;
    }
    return sm2_pki_service_set_epoch_policy_binding(ctx->service,
               SM2_PKI_DEFAULT_WITNESS_POLICY_VERSION, witness_digest,
               SM2_PKI_DEFAULT_SYNC_POLICY_VERSION, sync_digest, 0)
        == SM2_PKI_SUCCESS;
}

static int build_epoch_checkpoint(capability_flow_ctx_t *ctx)
{
    if (!ctx)
        return 0;
    if (!bind_epoch_policy(ctx))
        return 0;
    memset(&ctx->checkpoint, 0, sizeof(ctx->checkpoint));
    if (sm2_pki_service_get_epoch_root_record(
            ctx->service, &ctx->checkpoint.epoch_root_record)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    size_t commitment_count = 0;
    if (sm2_pki_service_get_issuance_commitment_count(
            ctx->service, &commitment_count)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    sm2_pki_issuance_commitment_t *commitments = NULL;
    if (commitment_count > 0)
    {
        commitments = (sm2_pki_issuance_commitment_t *)calloc(
            commitment_count, sizeof(*commitments));
        if (!commitments)
            return 0;
        size_t exported_count = 0;
        if (sm2_pki_service_export_issuance_commitments(
                ctx->service, 0, commitments, commitment_count, &exported_count)
                != SM2_PKI_SUCCESS
            || exported_count != commitment_count)
        {
            free(commitments);
            return 0;
        }
    }

    sm2_pki_epoch_witness_state_t witness_state;
    sm2_pki_epoch_witness_state_init(&witness_state);
    sm2_pki_error_t ret = sm2_pki_epoch_witness_sign_append_only(&witness_state,
        &ctx->checkpoint.epoch_root_record, &ctx->ca_pub,
        ctx->checkpoint.epoch_root_record.valid_from, commitments,
        commitment_count, ctx->witness.witness_id, ctx->witness.witness_id_len,
        &ctx->witness_private_key, &ctx->checkpoint.witness_signatures[0]);
    sm2_pki_epoch_witness_state_cleanup(&witness_state);
    free(commitments);
    if (ret != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    ctx->checkpoint.witness_signature_count = 1U;
    return 1;
}

static int import_evidence_checkpoint(
    capability_flow_ctx_t *ctx, sm2_pki_client_ctx_t *client)
{
    if (!ctx || !client)
        return 0;
    return sm2_pki_client_import_epoch_checkpoint(
               client, &ctx->checkpoint, ctx->auth_now)
        == SM2_PKI_SUCCESS;
}

static int build_flow(capability_flow_ctx_t *ctx)
{
    const uint8_t issuer[] = "CAPABILITY_CA";
    const uint8_t identity[] = "CAPABILITY_NODE";
    const uint8_t witness_id[] = "capability-witness-0";
    const uint8_t message[] = "TINYPKI_CAPABILITY_EPOCH_BUNDLE";
    const sm2_implicit_cert_t *cert = NULL;
    const sm2_ec_point_t *public_key = NULL;

    if (!ctx)
        return 0;
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->message, message, sizeof(message) - 1U);
    ctx->message_len = sizeof(message) - 1U;

    if (sm2_pki_service_create(&ctx->service, issuer, sizeof(issuer) - 1U, 64,
            300, current_unix_ts())
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_identity_register(ctx->service, identity, sizeof(identity) - 1U,
            SM2_KU_DIGITAL_SIGNATURE)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!issue_identity_cert(ctx->service, identity, sizeof(identity) - 1U,
            SM2_KU_DIGITAL_SIGNATURE, &ctx->cert_result,
            &ctx->temp_private_key))
    {
        return 0;
    }
    if (sm2_pki_service_get_ca_public_key(ctx->service, &ctx->ca_pub)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_create(&ctx->signer, &ctx->ca_pub, ctx->service)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_create(&ctx->verifier, &ctx->ca_pub, NULL)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_import_cert(ctx->signer, &ctx->cert_result,
            &ctx->temp_private_key, &ctx->ca_pub)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_generate_ephemeral_keypair(
            &ctx->witness_private_key, &ctx->witness_public_key)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    memcpy(ctx->witness.witness_id, witness_id, sizeof(witness_id) - 1U);
    ctx->witness.witness_id_len = sizeof(witness_id) - 1U;
    ctx->witness.key_version = SM2_PKI_WITNESS_KEY_DEFAULT_VERSION;
    ctx->witness.valid_from = 0;
    ctx->witness.valid_until = SM2_PKI_WITNESS_KEY_VALID_UNTIL_OPEN;
    ctx->witness.public_key = ctx->witness_public_key;
    ctx->policy.witnesses = &ctx->witness;
    ctx->policy.witness_count = 1U;
    ctx->policy.threshold = 1U;
    if (sm2_pki_client_set_transparency_policy(ctx->verifier, &ctx->policy)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!bind_epoch_policy(ctx))
        return 0;

    ctx->auth_now = ctx->cert_result.cert.valid_from != 0
        ? ctx->cert_result.cert.valid_from
        : current_unix_ts();
    if (sm2_pki_sign(
            ctx->signer, ctx->message, ctx->message_len, &ctx->signature)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!get_identity_material(ctx->signer, &cert, &public_key))
        return 0;
    if (sm2_pki_client_export_epoch_evidence(
            ctx->signer, ctx->auth_now, &ctx->evidence)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    ctx->request.cert = cert;
    ctx->request.public_key = public_key;
    ctx->request.message = ctx->message;
    ctx->request.message_len = ctx->message_len;
    ctx->request.signature = &ctx->signature;
    ctx->request.evidence_bundle = &ctx->evidence;
    return build_epoch_checkpoint(ctx)
        && import_evidence_checkpoint(ctx, ctx->verifier);
}

static void cleanup_flow(capability_flow_ctx_t *ctx)
{
    if (!ctx)
        return;
    sm2_pki_client_destroy(&ctx->verifier);
    sm2_pki_client_destroy(&ctx->signer);
    sm2_pki_service_destroy(&ctx->service);
    memset(ctx, 0, sizeof(*ctx));
}

static size_t epoch_root_bytes(const sm2_pki_epoch_root_record_t *root)
{
    if (!root)
        return 0U;
    return root->authority_id_len + (8U * sizeof(uint64_t))
        + (2U * SM2_REV_MERKLE_HASH_LEN) + (2U * SM2_PKI_POLICY_DIGEST_LEN)
        + root->signature_len;
}

static size_t issuance_proof_bytes(const sm2_pki_issuance_member_proof_t *proof)
{
    if (!proof)
        return 0U;
    return SM2_PKI_ISSUANCE_COMMITMENT_LEN + (3U * sizeof(size_t))
        + proof->sibling_count * (SM2_REV_MERKLE_HASH_LEN + 1U);
}

static size_t witness_bytes(const sm2_pki_epoch_checkpoint_t *checkpoint)
{
    size_t total = 0;
    if (!checkpoint)
        return 0U;
    for (size_t i = 0; i < checkpoint->witness_signature_count; i++)
    {
        total += checkpoint->witness_signatures[i].witness_id_len
            + checkpoint->witness_signatures[i].signature_len;
    }
    return total;
}

static int collect_size_metrics(
    capability_flow_ctx_t *ctx, capability_size_metrics_t *metrics)
{
    uint8_t cert_buf[1024];
    uint8_t absence_buf[16384];
    uint8_t evidence_buf[32768];
    size_t cert_len = sizeof(cert_buf);
    size_t absence_len = sizeof(absence_buf);
    size_t evidence_len = sizeof(evidence_buf);

    if (!ctx || !metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));

    if (sm2_ic_cbor_encode_cert(cert_buf, &cert_len, &ctx->cert_result.cert)
        != SM2_IC_SUCCESS)
    {
        return 0;
    }
    if (sm2_rev_absence_proof_encode(
            &ctx->evidence.revocation_proof.absence_proof, absence_buf,
            &absence_len)
        != SM2_IC_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_evidence_bundle_encode(
            &ctx->evidence, evidence_buf, &evidence_len)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    metrics->cert_bytes = cert_len;
    metrics->signature_bytes = ctx->signature.der_len;
    metrics->epoch_root_bytes
        = epoch_root_bytes(&ctx->checkpoint.epoch_root_record);
    metrics->revocation_proof_bytes = absence_len;
    metrics->issuance_proof_bytes
        = issuance_proof_bytes(&ctx->evidence.issuance_proof.member_proof);
    metrics->witness_signature_bytes = witness_bytes(&ctx->checkpoint);
    metrics->evidence_bundle_bytes = evidence_len;
    metrics->authentication_bundle_bytes = metrics->cert_bytes
        + metrics->signature_bytes + metrics->evidence_bundle_bytes;
    return 1;
}

static int collect_timing_metrics(
    capability_flow_ctx_t *ctx, capability_timing_metrics_t *metrics)
{
    double export_samples[BENCH_ROUNDS];
    double witness_samples[BENCH_ROUNDS];
    double verify_samples[BENCH_ROUNDS];

    if (!ctx || !metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));

    for (size_t i = 0; i < BENCH_WARMUP_ROUNDS + BENCH_ROUNDS; i++)
    {
        sm2_pki_evidence_bundle_t evidence;
        double t0 = now_ms_highres();
        if (sm2_pki_client_export_epoch_evidence(
                ctx->signer, ctx->auth_now, &evidence)
            != SM2_PKI_SUCCESS)
        {
            return 0;
        }
        if (i >= BENCH_WARMUP_ROUNDS)
            export_samples[i - BENCH_WARMUP_ROUNDS] = now_ms_highres() - t0;
    }

    for (size_t i = 0; i < BENCH_WARMUP_ROUNDS + BENCH_ROUNDS; i++)
    {
        double t0 = now_ms_highres();
        sm2_pki_epoch_checkpoint_t saved_checkpoint = ctx->checkpoint;
        if (!build_epoch_checkpoint(ctx))
        {
            return 0;
        }
        ctx->checkpoint = saved_checkpoint;
        if (i >= BENCH_WARMUP_ROUNDS)
            witness_samples[i - BENCH_WARMUP_ROUNDS] = now_ms_highres() - t0;
    }

    for (size_t i = 0; i < BENCH_WARMUP_ROUNDS + BENCH_ROUNDS; i++)
    {
        size_t matched = 0;
        double t0 = now_ms_highres();
        if (sm2_pki_verify(
                ctx->verifier, &ctx->request, ctx->auth_now, &matched)
            != SM2_PKI_SUCCESS)
        {
            return 0;
        }
        if (i >= BENCH_WARMUP_ROUNDS)
            verify_samples[i - BENCH_WARMUP_ROUNDS] = now_ms_highres() - t0;
    }

    if (!timing_stats_from_samples(
            export_samples, BENCH_ROUNDS, &metrics->export_epoch_evidence_stats)
        || !timing_stats_from_samples(
            witness_samples, BENCH_ROUNDS, &metrics->witness_sign_stats)
        || !timing_stats_from_samples(
            verify_samples, BENCH_ROUNDS, &metrics->verify_epoch_bundle_stats))
    {
        return 0;
    }
    metrics->export_epoch_evidence_ms
        = metrics->export_epoch_evidence_stats.median_ms;
    metrics->witness_sign_ms = metrics->witness_sign_stats.median_ms;
    metrics->verify_epoch_bundle_ms
        = metrics->verify_epoch_bundle_stats.median_ms;
    return 1;
}

typedef struct
{
    uint8_t *bits;
    size_t bit_count;
    size_t byte_count;
    size_t hash_count;
} bench_bloom_filter_t;

typedef struct
{
    bench_bloom_filter_t levels[BENCH_CRLITE_MAX_LEVELS];
    size_t level_count;
} bench_crlite_cascade_t;

static uint64_t bench_mix64(uint64_t x)
{
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30U)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27U)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31U);
}

static int bloom_init(
    bench_bloom_filter_t *filter, size_t item_count, double fp_rate)
{
    const double ln2 = 0.6931471805599453;
    double bit_count_d;
    size_t hash_count;

    if (!filter || item_count == 0U || fp_rate <= 0.0 || fp_rate >= 1.0)
        return 0;
    memset(filter, 0, sizeof(*filter));
    bit_count_d = -(double)item_count * log(fp_rate) / (ln2 * ln2);
    if (bit_count_d < 8.0)
        bit_count_d = 8.0;
    filter->bit_count = (size_t)ceil(bit_count_d);
    filter->byte_count = (filter->bit_count + 7U) / 8U;
    hash_count = (size_t)(((double)filter->bit_count / (double)item_count) * ln2
        + 0.5);
    if (hash_count == 0U)
        hash_count = 1U;
    filter->hash_count = hash_count;
    filter->bits = (uint8_t *)calloc(filter->byte_count, 1U);
    return filter->bits != NULL;
}

static void bloom_cleanup(bench_bloom_filter_t *filter)
{
    if (!filter)
        return;
    free(filter->bits);
    memset(filter, 0, sizeof(*filter));
}

static void bloom_add(bench_bloom_filter_t *filter, uint64_t value)
{
    if (!filter || !filter->bits || filter->bit_count == 0U)
        return;
    for (size_t i = 0; i < filter->hash_count; i++)
    {
        uint64_t h = bench_mix64(value ^ (0x9e3779b97f4a7c15ULL * (i + 1U)));
        size_t bit = (size_t)(h % filter->bit_count);
        filter->bits[bit >> 3U] |= (uint8_t)(1U << (bit & 7U));
    }
}

static int bloom_maybe_contains(
    const bench_bloom_filter_t *filter, uint64_t value)
{
    if (!filter || !filter->bits || filter->bit_count == 0U)
        return 0;
    for (size_t i = 0; i < filter->hash_count; i++)
    {
        uint64_t h = bench_mix64(value ^ (0x9e3779b97f4a7c15ULL * (i + 1U)));
        size_t bit = (size_t)(h % filter->bit_count);
        if ((filter->bits[bit >> 3U] & (uint8_t)(1U << (bit & 7U))) == 0U)
            return 0;
    }
    return 1;
}

static int crlite_true_revoked(uint64_t serial)
{
    return serial < (uint64_t)BENCH_SCALE_REVOKED_CERTS;
}

static int crlite_query_upto(
    const bench_crlite_cascade_t *cascade, uint64_t serial, size_t level_count)
{
    int status = 0;

    if (!cascade || level_count == 0U || level_count > cascade->level_count)
        return 0;
    for (size_t level = 0; level < level_count; level++)
    {
        if (!bloom_maybe_contains(&cascade->levels[level], serial))
            return status;
        status = (level & 1U) == 0U;
    }
    return status;
}

static void crlite_cleanup(bench_crlite_cascade_t *cascade)
{
    if (!cascade)
        return;
    for (size_t i = 0; i < cascade->level_count; i++)
        bloom_cleanup(&cascade->levels[i]);
    memset(cascade, 0, sizeof(*cascade));
}

static int crlite_build_cascade(
    bench_crlite_cascade_t *cascade, crlite_metrics_t *metrics)
{
    size_t repair_count = 0U;

    if (!cascade || !metrics)
        return 0;
    memset(cascade, 0, sizeof(*cascade));

    if (!bloom_init(&cascade->levels[0], BENCH_SCALE_REVOKED_CERTS,
            BENCH_CRLITE_FP_RATE))
    {
        return 0;
    }
    cascade->level_count = 1U;
    for (uint64_t serial = 0; serial < (uint64_t)BENCH_SCALE_REVOKED_CERTS;
         serial++)
    {
        bloom_add(&cascade->levels[0], serial);
    }

    for (size_t level = 1U; level < BENCH_CRLITE_MAX_LEVELS; level++)
    {
        size_t error_count = 0U;
        int expected_status = (level & 1U) == 0U;

        for (uint64_t serial = 0; serial < (uint64_t)BENCH_SCALE_TOTAL_CERTS;
             serial++)
        {
            int truth = crlite_true_revoked(serial);
            int predicted = crlite_query_upto(cascade, serial, level);
            if (predicted != truth && truth == expected_status)
                error_count++;
        }
        if (error_count == 0U)
            break;
        if (!bloom_init(
                &cascade->levels[level], error_count, BENCH_CRLITE_FP_RATE))
        {
            crlite_cleanup(cascade);
            return 0;
        }
        cascade->level_count++;
        for (uint64_t serial = 0; serial < (uint64_t)BENCH_SCALE_TOTAL_CERTS;
             serial++)
        {
            int truth = crlite_true_revoked(serial);
            int predicted = crlite_query_upto(cascade, serial, level);
            if (predicted != truth && truth == expected_status)
                bloom_add(&cascade->levels[level], serial);
        }
        repair_count += error_count;
    }

    metrics->level_count = cascade->level_count;
    metrics->filter_bytes = 0U;
    for (size_t i = 0; i < cascade->level_count; i++)
        metrics->filter_bytes += cascade->levels[i].byte_count;
    metrics->delta_bytes
        = (size_t)((double)metrics->filter_bytes * BENCH_CRLITE_DELTA_FRACTION
            + 0.5);
    metrics->repaired_false_positive_count = repair_count;
    return 1;
}

static int collect_crlite_metrics(crlite_metrics_t *metrics)
{
    bench_crlite_cascade_t cascade;
    double samples[BENCH_ROUNDS];
    size_t query_error_count = 0U;
    volatile size_t revoked_hits = 0U;

    if (!metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));
    memset(&cascade, 0, sizeof(cascade));
    metrics->total_certs = BENCH_SCALE_TOTAL_CERTS;
    metrics->revoked_certs = BENCH_SCALE_REVOKED_CERTS;
    metrics->query_count = BENCH_SCALE_QUERY_COUNT;

    if (!crlite_build_cascade(&cascade, metrics))
        return 0;

    for (size_t round = 0; round < BENCH_WARMUP_ROUNDS + BENCH_ROUNDS; round++)
    {
        double t0 = now_ms_highres();
        for (size_t i = 0; i < BENCH_SCALE_QUERY_COUNT; i++)
        {
            uint64_t serial = bench_mix64(BENCH_REPRO_SEED
                                  ^ ((uint64_t)round << 32U) ^ (uint64_t)i)
                % (uint64_t)BENCH_SCALE_TOTAL_CERTS;
            int predicted
                = crlite_query_upto(&cascade, serial, cascade.level_count);
            if (predicted)
                revoked_hits++;
        }
        if (round >= BENCH_WARMUP_ROUNDS)
            samples[round - BENCH_WARMUP_ROUNDS] = now_ms_highres() - t0;
    }

    for (size_t i = 0; i < BENCH_SCALE_QUERY_COUNT; i++)
    {
        uint64_t serial
            = bench_mix64(BENCH_REPRO_SEED ^ 0xabcddcbaULL ^ (uint64_t)i)
            % (uint64_t)BENCH_SCALE_TOTAL_CERTS;
        int predicted
            = crlite_query_upto(&cascade, serial, cascade.level_count);
        if (predicted != crlite_true_revoked(serial))
            query_error_count++;
    }
    (void)revoked_hits;
    if (!timing_stats_from_samples(
            samples, BENCH_ROUNDS, &metrics->lookup_stats))
    {
        crlite_cleanup(&cascade);
        return 0;
    }
    metrics->lookup_ms = metrics->lookup_stats.median_ms;
    metrics->lookup_per_query_us
        = (metrics->lookup_ms * 1000.0) / (double)BENCH_SCALE_QUERY_COUNT;
    metrics->query_error_count = query_error_count;
    crlite_cleanup(&cascade);
    return metrics->lookup_ms > 0.0;
}

static int collect_tinypki_revocation_scale_metrics(
    tinypki_revocation_scale_metrics_t *metrics)
{
    sm2_rev_tree_t *tree = NULL;
    uint64_t *revoked = NULL;
    sm2_rev_absence_proof_t proof;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
    uint8_t proof_buf[16384];
    double prove_samples[BENCH_SCALE_PROVE_ROUNDS];
    double verify_samples[BENCH_ROUNDS];
    size_t proof_len = sizeof(proof_buf);
    uint64_t good_serial
        = 900000000ULL + (bench_mix64(BENCH_REPRO_SEED) % 1000000ULL);
    int ok = 0;

    if (!metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));
    memset(&proof, 0, sizeof(proof));
    memset(root_hash, 0, sizeof(root_hash));

    revoked = (uint64_t *)calloc(BENCH_SCALE_REVOKED_CERTS, sizeof(*revoked));
    if (!revoked)
        goto cleanup;
    for (size_t i = 0; i < BENCH_SCALE_REVOKED_CERTS; i++)
        revoked[i] = 700000000ULL + (uint64_t)i;

    if (sm2_rev_tree_build(
            &tree, revoked, BENCH_SCALE_REVOKED_CERTS, 2026050501ULL)
            != SM2_IC_SUCCESS
        || sm2_rev_tree_get_root_hash(tree, root_hash) != SM2_IC_SUCCESS)
    {
        goto cleanup;
    }

    for (size_t i = 0; i < BENCH_WARMUP_ROUNDS + BENCH_SCALE_PROVE_ROUNDS; i++)
    {
        sm2_rev_absence_proof_t local_proof;
        double t0 = now_ms_highres();
        memset(&local_proof, 0, sizeof(local_proof));
        if (sm2_rev_tree_prove_absence(
                tree, good_serial + (uint64_t)i, &local_proof)
            != SM2_IC_SUCCESS)
        {
            goto cleanup;
        }
        if (i >= BENCH_WARMUP_ROUNDS)
            prove_samples[i - BENCH_WARMUP_ROUNDS] = now_ms_highres() - t0;
    }

    if (sm2_rev_tree_prove_absence(tree, good_serial, &proof) != SM2_IC_SUCCESS)
        goto cleanup;
    for (size_t i = 0; i < BENCH_WARMUP_ROUNDS + BENCH_ROUNDS; i++)
    {
        double t0 = now_ms_highres();
        if (sm2_rev_tree_verify_absence(root_hash, &proof) != SM2_IC_SUCCESS)
            goto cleanup;
        if (i >= BENCH_WARMUP_ROUNDS)
            verify_samples[i - BENCH_WARMUP_ROUNDS] = now_ms_highres() - t0;
    }
    if (sm2_rev_absence_proof_encode(&proof, proof_buf, &proof_len)
        != SM2_IC_SUCCESS)
    {
        goto cleanup;
    }

    metrics->revoked_certs = BENCH_SCALE_REVOKED_CERTS;
    metrics->proof_bytes = proof_len;
    if (!timing_stats_from_samples(prove_samples, BENCH_SCALE_PROVE_ROUNDS,
            &metrics->prove_absence_stats)
        || !timing_stats_from_samples(
            verify_samples, BENCH_ROUNDS, &metrics->verify_absence_stats))
    {
        goto cleanup;
    }
    metrics->prove_absence_ms = metrics->prove_absence_stats.median_ms;
    metrics->verify_absence_ms = metrics->verify_absence_stats.median_ms;
    metrics->verifier_cache_bytes
        = SM2_REV_MERKLE_HASH_LEN + sizeof(uint64_t) + sizeof(uint64_t);
    metrics->edge_tree_storage_estimate_bytes = BENCH_SCALE_REVOKED_CERTS
        * (sizeof(uint64_t) + SM2_REV_MERKLE_HASH_LEN + 2U * sizeof(void *));
    ok = metrics->proof_bytes > 0U && metrics->verify_absence_ms > 0.0;

cleanup:
    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    return ok;
}

static int collect_comparison_metrics(comparison_metrics_t *metrics)
{
    if (!metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));
    return collect_openssl_revocation_metrics(&metrics->openssl)
        && collect_crlite_metrics(&metrics->crlite)
        && collect_tinypki_revocation_scale_metrics(
            &metrics->tinypki_revocation);
}

static double pct_of(size_t part, size_t whole)
{
    if (whole == 0U)
        return 0.0;
    return ((double)part * 100.0) / (double)whole;
}

static void emit_json_timing_stats(FILE *out, const char *name,
    const bench_timing_stats_t *stats, int trailing_comma)
{
    if (!out || !name || !stats)
        return;
    fprintf(out, "      \"%s\": {", name);
    fprintf(out, "\"samples\": %zu, ", stats->sample_count);
    fprintf(out, "\"min\": %.6f, ", stats->min_ms);
    fprintf(out, "\"median\": %.6f, ", stats->median_ms);
    fprintf(out, "\"p95\": %.6f, ", stats->p95_ms);
    fprintf(out, "\"max\": %.6f, ", stats->max_ms);
    fprintf(out, "\"mean\": %.6f, ", stats->mean_ms);
    fprintf(out, "\"stddev\": %.6f, ", stats->stddev_ms);
    fprintf(out, "\"relative_stddev\": %.6f, ", stats->rel_stddev);
    fprintf(out, "\"p95_to_median\": %.6f, ", stats->p95_to_median);
    fprintf(out, "\"stable\": %s}", bench_bool_json(stats->stable));
    fprintf(out, "%s\n", trailing_comma ? "," : "");
}

static void emit_json_compiler(FILE *out)
{
    if (!out)
        return;
    fprintf(out, "      \"name\": \"%s\"", bench_compiler_name());
#if defined(__clang__)
    fprintf(out, ", \"major\": %d, \"minor\": %d, \"patch\": %d",
        __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    fprintf(out, ", \"major\": %d, \"minor\": %d, \"patch\": %d", __GNUC__,
        __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(_MSC_VER)
    fprintf(out, ", \"msvc_version\": %d", _MSC_VER);
#endif
    fprintf(out, "\n");
}

static void emit_json(FILE *out, const capability_size_metrics_t *sizes,
    const capability_timing_metrics_t *timings,
    const comparison_metrics_t *comparison)
{
    size_t tinypki_scale_auth_bytes = sizes->authentication_bundle_bytes
        - sizes->revocation_proof_bytes
        + comparison->tinypki_revocation.proof_bytes;

    fprintf(out, "{\n");
    fprintf(out, "  \"metadata\": {\n");
    fprintf(out, "    \"schema_version\": 2,\n");
    fprintf(out, "    \"benchmark\": \"tinypki-capability-suite\",\n");
    fprintf(out, "    \"evidence_model\": \"epoch_bundle\",\n");
    fprintf(out, "    \"dataset_model\": \"deterministic_serial_sets\",\n");
    fprintf(out, "    \"crypto_material\": \"generated_per_run\",\n");
    fprintf(out, "    \"timer\": \"platform_high_resolution_clock\",\n");
    fprintf(out, "    \"git_commit\": \"%s\",\n", BENCH_GIT_COMMIT);
    fprintf(out, "    \"git_dirty\": %s,\n", bench_bool_json(BENCH_GIT_DIRTY));
    fprintf(out, "    \"generated_at_unix\": %llu,\n",
        (unsigned long long)current_unix_ts());
    fprintf(out, "    \"os\": \"%s\",\n", bench_os_name());
    fprintf(out, "    \"build_mode\": \"%s\",\n", bench_build_mode());
    fprintf(out, "    \"compiler\": {\n");
    emit_json_compiler(out);
    fprintf(out, "    },\n");
    fprintf(out, "    \"deterministic_seed\": %llu,\n",
        (unsigned long long)BENCH_REPRO_SEED);
    fprintf(out, "    \"warmup_rounds\": %u,\n", (unsigned)BENCH_WARMUP_ROUNDS);
    fprintf(out, "    \"rounds\": %u,\n", (unsigned)BENCH_ROUNDS);
    fprintf(out, "    \"scale_total_certs\": %u,\n",
        (unsigned)BENCH_SCALE_TOTAL_CERTS);
    fprintf(out, "    \"scale_revoked_certs\": %u,\n",
        (unsigned)BENCH_SCALE_REVOKED_CERTS);
    fprintf(out, "    \"scale_query_count\": %u,\n",
        (unsigned)BENCH_SCALE_QUERY_COUNT);
    fprintf(out, "    \"scale_prove_rounds\": %u,\n",
        (unsigned)BENCH_SCALE_PROVE_ROUNDS);
    fprintf(out, "    \"stability_thresholds\": {\n");
    fprintf(out, "      \"max_relative_stddev\": %.2f,\n",
        BENCH_STABLE_MAX_REL_STDDEV);
    fprintf(out, "      \"max_p95_to_median\": %.2f\n",
        BENCH_STABLE_MAX_P95_TO_MEDIAN);
    fprintf(out, "    }\n");
    fprintf(out, "  },\n");
    fprintf(out, "  \"sizes\": {\n");
    fprintf(out, "    \"cert_bytes\": %zu,\n", sizes->cert_bytes);
    fprintf(out, "    \"signature_bytes\": %zu,\n", sizes->signature_bytes);
    fprintf(out, "    \"epoch_root_bytes\": %zu,\n", sizes->epoch_root_bytes);
    fprintf(out, "    \"revocation_proof_bytes\": %zu,\n",
        sizes->revocation_proof_bytes);
    fprintf(out, "    \"issuance_proof_bytes\": %zu,\n",
        sizes->issuance_proof_bytes);
    fprintf(out, "    \"witness_signature_bytes\": %zu,\n",
        sizes->witness_signature_bytes);
    fprintf(out, "    \"evidence_bundle_bytes\": %zu,\n",
        sizes->evidence_bundle_bytes);
    fprintf(out, "    \"authentication_bundle_bytes\": %zu\n",
        sizes->authentication_bundle_bytes);
    fprintf(out, "  },\n");
    fprintf(out, "  \"timings_ms\": {\n");
    fprintf(out, "    \"export_epoch_evidence_median\": %.3f,\n",
        timings->export_epoch_evidence_ms);
    fprintf(
        out, "    \"witness_sign_median\": %.3f,\n", timings->witness_sign_ms);
    fprintf(out, "    \"verify_epoch_bundle_median\": %.3f,\n",
        timings->verify_epoch_bundle_ms);
    fprintf(out, "    \"tinypki_sparse_prove_absence_median\": %.3f,\n",
        comparison->tinypki_revocation.prove_absence_ms);
    fprintf(out, "    \"tinypki_sparse_verify_absence_median\": %.3f,\n",
        comparison->tinypki_revocation.verify_absence_ms);
    fprintf(out, "    \"crlite_cascade_lookup_median\": %.3f,\n",
        comparison->crlite.lookup_ms);
    fprintf(out, "    \"crlite_cascade_lookup_per_query_us\": %.6f,\n",
        comparison->crlite.lookup_per_query_us);
    fprintf(out, "    \"crl_verify_lookup_median\": %.3f,\n",
        comparison->openssl.crl_verify_lookup_ms);
    fprintf(out, "    \"ocsp_verify_median\": %.3f\n",
        comparison->openssl.ocsp_verify_ms);
    fprintf(out, "  },\n");
    fprintf(out, "  \"timing_stats_ms\": {\n");
    emit_json_timing_stats(
        out, "export_epoch_evidence", &timings->export_epoch_evidence_stats, 1);
    emit_json_timing_stats(
        out, "witness_sign", &timings->witness_sign_stats, 1);
    emit_json_timing_stats(
        out, "verify_epoch_bundle", &timings->verify_epoch_bundle_stats, 1);
    emit_json_timing_stats(out, "tinypki_sparse_prove_absence",
        &comparison->tinypki_revocation.prove_absence_stats, 1);
    emit_json_timing_stats(out, "tinypki_sparse_verify_absence",
        &comparison->tinypki_revocation.verify_absence_stats, 1);
    emit_json_timing_stats(out, "crlite_cascade_lookup_batch",
        &comparison->crlite.lookup_stats, 1);
    emit_json_timing_stats(out, "crl_verify_lookup",
        &comparison->openssl.crl_verify_lookup_stats, 1);
    emit_json_timing_stats(out, "crl_scale_verify_lookup",
        &comparison->openssl.scale_crl_verify_lookup_stats, 1);
    emit_json_timing_stats(
        out, "ocsp_verify", &comparison->openssl.ocsp_verify_stats, 0);
    fprintf(out, "  },\n");
    fprintf(out, "  \"comparison\": {\n");
    fprintf(out, "    \"certificate_bytes\": {\n");
    fprintf(out, "      \"tinypki_ecqv\": %zu,\n", sizes->cert_bytes);
    fprintf(
        out, "      \"x509_der\": %zu,\n", comparison->openssl.x509_cert_bytes);
    fprintf(out, "      \"tinypki_vs_x509_pct\": %.2f\n",
        pct_of(sizes->cert_bytes, comparison->openssl.x509_cert_bytes));
    fprintf(out, "    },\n");
    fprintf(out, "    \"local_storage_bytes\": {\n");
    fprintf(out, "      \"tinypki_verifier_epoch_cache\": %zu,\n",
        comparison->tinypki_revocation.verifier_cache_bytes);
    fprintf(out, "      \"tinypki_edge_sparse_tree_estimate\": %zu,\n",
        comparison->tinypki_revocation.edge_tree_storage_estimate_bytes);
    fprintf(out, "      \"crlite_verifier_cascade_filters\": %zu,\n",
        comparison->crlite.filter_bytes);
    fprintf(out, "      \"crl_verifier_list\": %zu,\n",
        comparison->openssl.crl_der_bytes);
    fprintf(out, "      \"crl_scale_verifier_list\": %zu,\n",
        comparison->openssl.scale_crl_der_bytes);
    fprintf(out, "      \"ocsp_verifier_persistent\": %u\n", 0U);
    fprintf(out, "    },\n");
    fprintf(out, "    \"transmission_bytes\": {\n");
    fprintf(out, "      \"tinypki_authentication_bundle\": %zu,\n",
        sizes->authentication_bundle_bytes);
    fprintf(out,
        "      \"tinypki_scale_authentication_bundle_estimate\": %zu,\n",
        tinypki_scale_auth_bytes);
    fprintf(out, "      \"tinypki_epoch_root_background\": %zu,\n",
        sizes->epoch_root_bytes);
    fprintf(out, "      \"crlite_full_filter_background\": %zu,\n",
        comparison->crlite.filter_bytes);
    fprintf(out, "      \"crlite_delta_background_estimate\": %zu,\n",
        comparison->crlite.delta_bytes);
    fprintf(out, "      \"crlite_per_auth_revocation_bytes\": %u,\n", 0U);
    fprintf(out, "      \"ocsp_request_response\": %zu,\n",
        comparison->openssl.ocsp_wire_bytes);
    fprintf(out, "      \"crl_download\": %zu,\n",
        comparison->openssl.crl_der_bytes);
    fprintf(out, "      \"crl_scale_download\": %zu,\n",
        comparison->openssl.scale_crl_der_bytes);
    fprintf(out, "      \"crl_delta_background_estimate\": %zu\n",
        comparison->openssl.crl_delta_bytes);
    fprintf(out, "    },\n");
    fprintf(out, "    \"query_time_ms\": {\n");
    fprintf(out, "      \"tinypki_sparse_absence_verify\": %.3f,\n",
        comparison->tinypki_revocation.verify_absence_ms);
    fprintf(out, "      \"tinypki_sparse_absence_prove\": %.3f,\n",
        comparison->tinypki_revocation.prove_absence_ms);
    fprintf(out, "      \"crlite_cascade_bloom_lookup\": %.3f,\n",
        comparison->crlite.lookup_ms);
    fprintf(out, "      \"crlite_cascade_bloom_lookup_per_query_us\": %.6f,\n",
        comparison->crlite.lookup_per_query_us);
    fprintf(out, "      \"crl_verify_lookup\": %.3f,\n",
        comparison->openssl.crl_verify_lookup_ms);
    fprintf(out, "      \"crl_scale_verify_lookup\": %.3f,\n",
        comparison->openssl.scale_crl_verify_lookup_ms);
    fprintf(out, "      \"ocsp_verify\": %.3f\n",
        comparison->openssl.ocsp_verify_ms);
    fprintf(out, "    },\n");
    fprintf(out, "    \"scheme_comparison\": [\n");
    fprintf(out,
        "      {\"scheme\":\"TinyPKI\",\"certificate_bytes\":%zu,"
        "\"verifier_storage_bytes\":%zu,\"edge_or_server_storage_bytes\":%zu,"
        "\"foreground_bytes\":%zu,\"scale_foreground_bytes\":%zu,"
        "\"full_update_bytes\":%zu,\"delta_update_bytes\":%zu,"
        "\"scale_state_or_proof_bytes\":%zu,\"query_verify_ms\":%.6f,"
        "\"false_positive_repairs\":%u,\"online_required\":false},\n",
        sizes->cert_bytes, comparison->tinypki_revocation.verifier_cache_bytes,
        comparison->tinypki_revocation.edge_tree_storage_estimate_bytes,
        sizes->authentication_bundle_bytes, tinypki_scale_auth_bytes,
        sizes->epoch_root_bytes, sizes->epoch_root_bytes,
        comparison->tinypki_revocation.proof_bytes,
        comparison->tinypki_revocation.verify_absence_ms, 0U);
    fprintf(out,
        "      {\"scheme\":\"OCSP\",\"certificate_bytes\":%zu,"
        "\"verifier_storage_bytes\":%u,\"edge_or_server_storage_bytes\":%u,"
        "\"foreground_bytes\":%zu,\"scale_foreground_bytes\":%zu,"
        "\"full_update_bytes\":%u,\"delta_update_bytes\":%u,"
        "\"scale_state_or_proof_bytes\":%zu,\"query_verify_ms\":%.6f,"
        "\"false_positive_repairs\":%u,\"online_required\":true},\n",
        comparison->openssl.x509_cert_bytes, 0U, 0U,
        comparison->openssl.ocsp_wire_bytes,
        comparison->openssl.ocsp_wire_bytes, 0U, 0U,
        comparison->openssl.ocsp_wire_bytes, comparison->openssl.ocsp_verify_ms,
        0U);
    fprintf(out,
        "      {\"scheme\":\"CRL\",\"certificate_bytes\":%zu,"
        "\"verifier_storage_bytes\":%zu,\"edge_or_server_storage_bytes\":%u,"
        "\"foreground_bytes\":%zu,\"scale_foreground_bytes\":%zu,"
        "\"full_update_bytes\":%zu,\"delta_update_bytes\":%zu,"
        "\"scale_state_or_proof_bytes\":%zu,\"query_verify_ms\":%.6f,"
        "\"false_positive_repairs\":%u,\"online_required\":false},\n",
        comparison->openssl.x509_cert_bytes, comparison->openssl.crl_der_bytes,
        0U, comparison->openssl.crl_der_bytes,
        comparison->openssl.scale_crl_der_bytes,
        comparison->openssl.scale_crl_der_bytes,
        comparison->openssl.crl_delta_bytes,
        comparison->openssl.scale_crl_der_bytes,
        comparison->openssl.scale_crl_verify_lookup_ms, 0U);
    fprintf(out,
        "      {\"scheme\":\"CRLite\",\"certificate_bytes\":%zu,"
        "\"verifier_storage_bytes\":%zu,\"edge_or_server_storage_bytes\":%u,"
        "\"foreground_bytes\":%u,\"scale_foreground_bytes\":%u,"
        "\"full_update_bytes\":%zu,\"delta_update_bytes\":%zu,"
        "\"scale_state_or_proof_bytes\":%zu,\"query_verify_ms\":%.6f,"
        "\"false_positive_repairs\":%zu,\"online_required\":false}\n",
        comparison->openssl.x509_cert_bytes, comparison->crlite.filter_bytes,
        0U, 0U, 0U, comparison->crlite.filter_bytes,
        comparison->crlite.delta_bytes, comparison->crlite.filter_bytes,
        comparison->crlite.lookup_per_query_us / 1000.0,
        comparison->crlite.repaired_false_positive_count);
    fprintf(out, "    ],\n");
    fprintf(out, "    \"crlite_scale\": {\n");
    fprintf(
        out, "      \"total_certs\": %zu,\n", comparison->crlite.total_certs);
    fprintf(out, "      \"revoked_certs\": %zu,\n",
        comparison->crlite.revoked_certs);
    fprintf(out, "      \"cascade_levels\": %zu,\n",
        comparison->crlite.level_count);
    fprintf(
        out, "      \"filter_bytes\": %zu,\n", comparison->crlite.filter_bytes);
    fprintf(out, "      \"delta_bytes_estimate\": %zu,\n",
        comparison->crlite.delta_bytes);
    fprintf(out, "      \"repaired_false_positive_count\": %zu,\n",
        comparison->crlite.repaired_false_positive_count);
    fprintf(out, "      \"query_error_count\": %zu\n",
        comparison->crlite.query_error_count);
    fprintf(out, "    },\n");
    fprintf(out, "    \"tinypki_scale\": {\n");
    fprintf(out, "      \"revoked_certs\": %zu,\n",
        comparison->tinypki_revocation.revoked_certs);
    fprintf(out, "      \"absence_proof_bytes\": %zu,\n",
        comparison->tinypki_revocation.proof_bytes);
    fprintf(out, "      \"verifier_cache_bytes\": %zu,\n",
        comparison->tinypki_revocation.verifier_cache_bytes);
    fprintf(out, "      \"edge_sparse_tree_storage_estimate_bytes\": %zu\n",
        comparison->tinypki_revocation.edge_tree_storage_estimate_bytes);
    fprintf(out, "    }\n");
    fprintf(out, "  }\n");
    fprintf(out, "}\n");
}

static void build_markdown_report_path(
    const char *json_path, char *buf, size_t buf_len)
{
    const char *dot = NULL;
    size_t base_len;

    if (!buf || buf_len == 0U)
        return;
    buf[0] = '\0';
    if (!json_path)
        return;
    dot = strrchr(json_path, '.');
    base_len = dot ? (size_t)(dot - json_path) : strlen(json_path);
    if (base_len + 4U >= buf_len)
        return;
    memcpy(buf, json_path, base_len);
    memcpy(buf + base_len, ".md", 4U);
    buf[base_len + 3U] = '\0';
}

static void emit_markdown_timing_stats_row(FILE *out, const char *scheme,
    const char *operation, const bench_timing_stats_t *stats)
{
    if (!out || !scheme || !operation || !stats)
        return;
    fprintf(out, "| %s | %s | %.6f | %.6f | %.6f | %.2f | %s |\n", scheme,
        operation, stats->median_ms, stats->p95_ms, stats->mean_ms,
        stats->rel_stddev, stats->stable ? "yes" : "no");
}

static void emit_markdown_report(FILE *out,
    const capability_size_metrics_t *sizes,
    const capability_timing_metrics_t *timings,
    const comparison_metrics_t *comparison)
{
    size_t tinypki_scale_auth_bytes;

    if (!out || !sizes || !timings || !comparison)
        return;
    tinypki_scale_auth_bytes = sizes->authentication_bundle_bytes
        - sizes->revocation_proof_bytes
        + comparison->tinypki_revocation.proof_bytes;

    fprintf(out, "# Capability Comparison Report\n\n");
    fprintf(out,
        "Generated by `sm2_bench_capability_suite`. Every table keeps the "
        "same scheme order: TinyPKI, OCSP, CRL, and CRLite. CRL now has both "
        "the baseline %u-entry measurement and the scale %u-entry "
        "measurement.\n\n",
        (unsigned)BENCH_BASELINE_CRL_ENTRIES,
        (unsigned)BENCH_SCALE_REVOKED_CERTS);

    fprintf(out, "## Test Conditions\n\n");
    fprintf(out, "| Metric | Value |\n");
    fprintf(out, "| --- | ---: |\n");
    fprintf(out, "| Total certificates in scale run | %u |\n",
        (unsigned)BENCH_SCALE_TOTAL_CERTS);
    fprintf(out, "| Revoked certificates in scale run | %u |\n",
        (unsigned)BENCH_SCALE_REVOKED_CERTS);
    fprintf(out, "| Query samples per round | %u |\n",
        (unsigned)BENCH_SCALE_QUERY_COUNT);
    fprintf(out, "| Deterministic dataset seed | %llu |\n",
        (unsigned long long)BENCH_REPRO_SEED);
    fprintf(out, "| Warmup rounds | %u |\n", (unsigned)BENCH_WARMUP_ROUNDS);
    fprintf(out, "| Measured timing rounds | %u |\n", (unsigned)BENCH_ROUNDS);
    fprintf(out, "| Git commit | `%s` |\n", BENCH_GIT_COMMIT);
    fprintf(out, "| Git dirty | %s |\n", BENCH_GIT_DIRTY ? "yes" : "no");
    fprintf(out, "| OS | %s |\n", bench_os_name());
    fprintf(out, "| Compiler | %s |\n", bench_compiler_name());
    fprintf(out, "| Build mode | %s |\n\n", bench_build_mode());

    fprintf(out, "## Cross-scheme Matrix\n\n");
    fprintf(out,
        "| Scheme | Cert bytes | Verifier storage | Edge/server state | "
        "Foreground bytes | Scale foreground bytes | Full update bytes | "
        "Delta update bytes | Query/verify median | Scale object | Repairs | "
        "Online required |\n");
    fprintf(out,
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | "
        "---: | ---: | --- |\n");
    fprintf(out,
        "| TinyPKI | %zu | %zu | %zu | %zu | %zu | %zu | %zu | %.3f ms | "
        "%zu | 0 | no |\n",
        sizes->cert_bytes, comparison->tinypki_revocation.verifier_cache_bytes,
        comparison->tinypki_revocation.edge_tree_storage_estimate_bytes,
        sizes->authentication_bundle_bytes, tinypki_scale_auth_bytes,
        sizes->epoch_root_bytes, sizes->epoch_root_bytes,
        comparison->tinypki_revocation.verify_absence_ms,
        comparison->tinypki_revocation.proof_bytes);
    fprintf(out,
        "| OCSP | %zu | 0 | 0 | %zu | %zu | 0 | 0 | %.3f ms | %zu | "
        "0 | yes |\n",
        comparison->openssl.x509_cert_bytes,
        comparison->openssl.ocsp_wire_bytes,
        comparison->openssl.ocsp_wire_bytes, comparison->openssl.ocsp_verify_ms,
        comparison->openssl.ocsp_wire_bytes);
    fprintf(out,
        "| CRL | %zu | %zu | 0 | %zu | %zu | %zu | %zu | %.3f ms | %zu | "
        "0 | no |\n",
        comparison->openssl.x509_cert_bytes, comparison->openssl.crl_der_bytes,
        comparison->openssl.crl_der_bytes,
        comparison->openssl.scale_crl_der_bytes,
        comparison->openssl.scale_crl_der_bytes,
        comparison->openssl.crl_delta_bytes,
        comparison->openssl.scale_crl_verify_lookup_ms,
        comparison->openssl.scale_crl_der_bytes);
    fprintf(out,
        "| CRLite | %zu | %zu | 0 | 0 | 0 | %zu | %zu | %.6f ms | %zu | "
        "%zu | no |\n\n",
        comparison->openssl.x509_cert_bytes, comparison->crlite.filter_bytes,
        comparison->crlite.filter_bytes, comparison->crlite.delta_bytes,
        comparison->crlite.lookup_per_query_us / 1000.0,
        comparison->crlite.filter_bytes,
        comparison->crlite.repaired_false_positive_count);

    fprintf(out, "## Timing Details\n\n");
    fprintf(out,
        "| Scheme | Operation measured | Median ms | P95 ms | Mean ms | "
        "Rel stddev | Stable |\n");
    fprintf(out, "| --- | --- | ---: | ---: | ---: | ---: | --- |\n");
    emit_markdown_timing_stats_row(out, "TinyPKI", "export epoch evidence",
        &timings->export_epoch_evidence_stats);
    emit_markdown_timing_stats_row(
        out, "TinyPKI", "witness sign", &timings->witness_sign_stats);
    emit_markdown_timing_stats_row(out, "TinyPKI", "full evidence verification",
        &timings->verify_epoch_bundle_stats);
    emit_markdown_timing_stats_row(out, "TinyPKI", "sparse proof construction",
        &comparison->tinypki_revocation.prove_absence_stats);
    emit_markdown_timing_stats_row(out, "TinyPKI", "sparse proof verification",
        &comparison->tinypki_revocation.verify_absence_stats);
    emit_markdown_timing_stats_row(out, "OCSP", "response verification",
        &comparison->openssl.ocsp_verify_stats);
    emit_markdown_timing_stats_row(out, "CRL", "baseline verify+lookup",
        &comparison->openssl.crl_verify_lookup_stats);
    emit_markdown_timing_stats_row(out, "CRL", "scale verify+lookup",
        &comparison->openssl.scale_crl_verify_lookup_stats);
    emit_markdown_timing_stats_row(out, "CRLite", "cascade lookup batch",
        &comparison->crlite.lookup_stats);
    fprintf(out,
        "\nCRLite per-query median is %.6f us, computed from the %u-query "
        "batch median. The batch row is retained because one timed round "
        "performs many filter queries to avoid timer noise.\n\n",
        comparison->crlite.lookup_per_query_us,
        (unsigned)BENCH_SCALE_QUERY_COUNT);

    fprintf(out, "## Interpretation\n\n");
    fprintf(out,
        "- TinyPKI spends foreground bytes on a carried exact proof, but keeps "
        "verifier storage at %zu B and does not require an online check.\n",
        comparison->tinypki_revocation.verifier_cache_bytes);
    fprintf(out,
        "- OCSP keeps verifier storage at 0 B, but each decision depends on an "
        "online response path and therefore exposes query timing and target "
        "certificate information to the status service.\n");
    fprintf(out,
        "- CRL is simple and offline after download, but the measured scale "
        "CRL "
        "is %zu B and the scale verify+lookup time is %.3f ms.\n",
        comparison->openssl.scale_crl_der_bytes,
        comparison->openssl.scale_crl_verify_lookup_ms);
    fprintf(out,
        "- CRLite has 0 foreground revocation bytes after filters are cached, "
        "but the verifier keeps %zu B of filters and the scale simulation "
        "has %zu repaired false positives. Its timing row is a batch lookup; "
        "the cross-scheme matrix uses the derived per-query median.\n",
        comparison->crlite.filter_bytes,
        comparison->crlite.repaired_false_positive_count);
}

int main(int argc, char **argv)
{
    capability_flow_ctx_t ctx;
    capability_size_metrics_t sizes;
    capability_timing_metrics_t timings;
    comparison_metrics_t comparison;
    FILE *out = stdout;
    FILE *report_out = NULL;
    char report_path[1024];

    memset(&ctx, 0, sizeof(ctx));
    memset(&sizes, 0, sizeof(sizes));
    memset(&timings, 0, sizeof(timings));
    memset(&comparison, 0, sizeof(comparison));
    memset(report_path, 0, sizeof(report_path));

    if (!build_flow(&ctx) || !collect_size_metrics(&ctx, &sizes)
        || !collect_timing_metrics(&ctx, &timings)
        || !collect_comparison_metrics(&comparison))
    {
        fprintf(stderr,
            "TinyPKI capability benchmark failed to collect metrics.\n");
        cleanup_flow(&ctx);
        return 1;
    }

    if (argc > 1)
    {
        if (!bench_output_path_is_safe(argv[1]))
        {
            fprintf(stderr,
                "Refusing benchmark output path outside ./tmp/: %s\n", argv[1]);
            cleanup_flow(&ctx);
            return 1;
        }
        out = fopen(argv[1], "wb");
        if (!out)
        {
            fprintf(stderr, "Failed to open output file: %s\n", argv[1]);
            cleanup_flow(&ctx);
            return 1;
        }
        build_markdown_report_path(argv[1], report_path, sizeof(report_path));
        if (report_path[0] != '\0')
        {
            report_out = fopen(report_path, "wb");
            if (!report_out)
            {
                fprintf(stderr, "Failed to open markdown report: %s\n",
                    report_path);
                fclose(out);
                cleanup_flow(&ctx);
                return 1;
            }
        }
    }

    emit_json(out, &sizes, &timings, &comparison);
    if (report_out)
    {
        emit_markdown_report(report_out, &sizes, &timings, &comparison);
        fclose(report_out);
    }
    if (out != stdout)
        fclose(out);
    cleanup_flow(&ctx);
    return 0;
}
