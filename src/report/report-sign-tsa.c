#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <openssl/x509.h>

#include "alloc-util.h"
#include "build.h"
#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "metrics.h"
#include "sd-json.h"
#include "sd-varlink.h"
#include "varlink-io.systemd.Metrics.h"
#include "varlink-util.h"
#include "verbs.h"

COMMAND(
    "systemd-report-sign-tsa\0",
    "Sign a report with a timestamp from the TSA server.",
    // Man page?
);

typedef struct SignParameters {
        struct iovec digest;
        const char *algorithm;
} SignParameters;

static void sign_parameters_done(SignParameters *p) {
        iovec_done(&p->digest);
}

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

static int hash_create(uint8_t *nonce, size_t nonce_len, uint8_t *hash_val, unsigned int *hash_len) {
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mdctx = NULL;

        int r;
        r = RAND_bytes(nonce, nonce_len);
        if (r <= 0)
                return log_error_errno(r, "Failed to generate secure random nonce.");

        mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
                return log_error_errno(r, "Message digest create failed.");

        r = EVP_DigestInit_ex(mdctx, EVP_sha256(), /* engine= */ NULL);
        if (r <= 0)
                return log_error_errno(r, "Message digest initialization failed.");

        r = EVP_DigestUpdate(mdctx, nonce, nonce_len);
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

static int request_serialize(const TS_REQ *ts_req, unsigned char **ret_der, int *ret_der_len) {
        unsigned char *der = NULL;
        int len;
        if (!ts_req || !ret_der || !ret_der_len)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid arguments to request_serialize.");

        len = i2d_TS_REQ(ts_req, &der);
        if (len <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOMEM), "Failed to serialize TS_REQ.");
        *ret_der = der;
        *ret_der_len = len;

        return 0;

}

static int tsa_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        int r;
        assert(mf && mf->name);
        assert(link);

        uint8_t nonce[32];
        uint8_t hash_val[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;

        r = hash_create(nonce, sizeof(nonce), hash_val, &hash_len);
        if (r < 0)
                return log_error_errno(r, "Failed hash generation");

        _cleanup_(TS_REQ_freep) TS_REQ *ts_req = NULL;
        r = request_create(hash_val, hash_len, &ts_req);
        if (r < 0)
                return log_error_errno(r, "Failed to create request.");

        unsigned char *der = NULL;
        int der_len = 0;
        r = request_serialize(ts_req, &der, &der_len);
        if (r < 0)
                return r; // Serialize function already logs error.
        char output_str[64];
        snprintf(output_str, sizeof(output_str), "DER length is %d bytes", der_len);

        int ret = metric_build_send_string(
                        mf,
                        link,
                        /* object= */ NULL,
                        output_str,
                        /* fields= */ NULL);
        OPENSSL_free(der);

        return ret;
}

static int vl_method_sign(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "digest",    SD_JSON_VARIANT_STRING, json_dispatch_unhex_iovec,     offsetof(SignParameters, digest),    SD_JSON_MANDATORY },
                { "algorithm", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(SignParameters, algorithm), SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(sign_parameters_done) SignParameters sp = {};
        int r;
        assert(link);
        assert(parameters);

        r  = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &sp);
        if (r != 0)
                return r;

        if (!iovec_is_set(&sp.digest))
                return sd_varlink_error_invalid_parameter_name(link, "digest");

        if (!streq(sp.algorithm, "SHA256"))
                return sd_varlink_error_invalid_paramater_name(link, "algorithm");

        // TSA Config (call )
        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR(
                                        "data",
                                        SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_OBJECT(
                                                                        SD_JSON_BUILD_PAIR_STRING("timestampToken", "dummy"),
                                                                        SD_JSON_BUILD_PAIR_STRING("tsaUrl", "dummy")))));
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        int r;

        r = varlink_server_new(&vs, /*flags=*/ 0, /*userdata=*/ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(vs, &vl_interface_io_systemd_Metrics);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        vs,
                        "io.systemd.Report.Signer.Sign", vl_method_sign);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(vs);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {
                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program can only run as a Varlink service.");
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;
        return vl_server();
}

DEFINE_MAIN_FUNCTION(run);