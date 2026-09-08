#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <openssl/x509.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "log.h"
#include "macro.h"
#include "metrics.h"
#include "report-tsa.h"

// Move to header file.
static inline void EVP_MD_CTX_freep(EVP_MD_CTX **p) {
        if (*p)
                EVP_MD_CTX_free(*p);
}

static inline void TS_REQ_freep(TS_REQ **p) {
        if (*p)
                TS_REQ_free(*p);
}

static inline void TS_MSG_IMPRINT_freep(TS_MSG_IMPRINT **p) {
        if (*p)
                TS_MSG_IMPRINT_free(*p);
}

static inline void X509_ALGOR_freep(X509_ALGOR **p) {
        if (*p)
                X509_ALGOR_free(*p);
}

static int hash_create(uint8_t *nonce, uint8_t *hash_val, unsigned int *hash_len) {
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mdctx = NULL;

        int r;
        r = RAND_bytes(nonce, sizeof(nonce));
        if (r <= 0)
                return log_error_errno(r, "Failed to generate secure random nonce.");

        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
                return log_error_errno(r, "Message digest create failed.");

        r = EVP_DigestInit_ex(mdctx, EVP_sha256(), /* engine= */ NULL);
        if (r <= 0)
                return log_error_errno(r, "Message digest initialization failed.");

        r = EVP_DigestUpdate(mdctx, nonce, sizeof(nonce));
        if (r <= 0)
                return log_error_errno(r, "Message digest update failed.");

        r = EVP_DigestFinal_ex(mdctx, hash_val, hash_len);
        if (r <= 0)
                return log_error_errno(r, "Message digest finalization failed.");

        return 0;
}

static int request_create(const uint8_t *hash_val, const unsigned int hash_len, TS_REQ **ret_ts_req) {
        _cleanup_(TS_REQ_freep) TS_REQ *ts_req = NULL;
        _cleanup_(TS_MSG_IMPRINT_freep) TS_MSG_IMPRINT *ts_imprint = NULL;
        _cleanup_(X509_ALGOR_freep) X509_ALGOR *algo = NULL;
        int r;

        ts_req = TS_REQ_new();
        if (!ts_req)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to create TS_REQ.");
        ts_imprint = TS_MSG_IMPRINT_new();
        if (!ts_imprint)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to create TS_MSG_IMPRINT.");
        algo = X509_ALGOR_new();
        if (!algo)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to create X509_ALGOR.");

        r = TS_REQ_set_version(ts_req, 1);
        if (r != 1)
                return log_error_errno(r, "Failed TS_REQ_set_version.");

        r = X509_ALGOR_set0(algo, OBJ_nid2obj(NID_sha256), V_ASN1_NULL, /*pval=*/NULL);
        if (r != 1)
                return log_error_errno(r, "Failed X509_ALGOR_set0.");

        r = TS_MSG_IMPRINT_set_algo(ts_imprint, algo);
        if (r != 1)
                return log_error_errno(r, "Failed TS_MSG_IMPRINT_set_algo.");

        r = TS_MSG_IMPRINT_set_msg(ts_imprint, (unsigned char *) hash_val, hash_len);
        if (r != 1)
                return log_error_errno(r, "Failed TS_MSG_IMPRINT_set_msg.");

        r = TS_REQ_set_msg_imprint(ts_req, ts_imprint);
        if (r != 1)
                return log_error_errno(r, "Failed TS_REQ_set_msg_imprint.");

        r = TS_REQ_set_cert_req(ts_req, 1);
        if (r != 1)
                return log_error_errno(r, "Failed TS_REQ_set_cert_req.");

        *ret_ts_req = TAKE_PTR(ts_req);
        return 0;
}

static int tsa_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        int r;
        assert(mf && mf->name);
        assert(link);

        uint8_t nonce[32];
        uint8_t hash_val[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;

        r = hash_create(nonce, hash_val, &hash_len);
        if (r < 0)
                return log_error_errno(r, "Failed hash generation");

        _cleanup_(TS_REQ_freep) TS_REQ *ts_req = NULL;
        r = request_create(hash_val, hash_len, &ts_req);
        if (r < 0)
                return log_error_errno(r, "Failed to create request.");

        char hex_str[EVP_MAX_MD_SIZE * 2 + 1];
        for (unsigned int i = 0; i < hash_len; i++) {
                sprintf(&hex_str[i * 2], "%02x", hash_val[i]);
        }

        hex_str[hash_len * 2] = '\0'; /* Ensure it is null-terminated */

        // log_info("Successfully generated TSA hash: %s", hex_str);

        return metric_build_send_string(
                        mf,
                        link,
                        /* object= */ NULL,
                        hex_str,
                        /* fields= */ NULL);
}

static const MetricFamily metric_family_table[] = {
        {
         METRIC_IO_SYSTEMD_TSA_PREFIX "Timestamp",
         "Timestamp token from Timestamp Authority", METRIC_FAMILY_TYPE_STRING,
         .generate = tsa_generate,
         },
        {}
};

int vl_method_describe_metrics(
                sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(
                sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_family_table, link, parameters, flags, userdata);
}
