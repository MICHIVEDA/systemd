#include "sd-varlink.h"

#include "metrics.h"
#include "report-tsa.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ts.h>

#include "log.h"
#include "alloc-util.h"
#include "macro.h"

// Move to header file.
static inline void EVP_MD_CTX_freep(EVP_MD_CTX **p) {
        if(*p)
                EVP_MD_CTX_free(*p);
}



static int tsa_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mdctx = NULL;
        int r;
        assert(mf && mf->name);
        assert(link);

        uint8_t nonce[32];
        uint8_t hash_val[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;


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

        r = EVP_DigestFinal_ex(mdctx, hash_val, &hash_len);
        if (r <= 0)
                return log_error_errno(r, "Message digest finalization failed.");

        char hex_str[EVP_MAX_MD_SIZE * 2 + 1];
        for (unsigned int i = 0; i < hash_len; i++) {
            sprintf(&hex_str[i * 2], "%02x", hash_val[i]);
        }
        hex_str[hash_len * 2] = '\0'; /* Ensure it is null-terminated */

        //log_info("Successfully generated TSA hash: %s", hex_str);

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
                "Timestamp token from Timestamp Authority",
                METRIC_FAMILY_TYPE_STRING,
                .generate = tsa_generate,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_family_table, link, parameters, flags, userdata);
}