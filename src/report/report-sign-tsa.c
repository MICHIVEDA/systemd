#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <openssl/x509.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "build.h"
#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "varlink-util.h"
#include "verbs.h"

COMMAND("systemd-report-sign-tsa\0", "Sign a report with a timestamp from the TSA server.",
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

static inline void ASN1_INTEGER_freep(ASN1_INTEGER **p) {
        if (*p)
                ASN1_INTEGER_free(*p);
}

static int build_nonce(ASN1_INTEGER **ret_nonce) {
        int r;
        assert(ret_nonce);

        _cleanup_(ASN1_INTEGER_freep) ASN1_INTEGER *nonce = NULL;

        uint64_t nonce_val;

        if (RAND_bytes((unsigned char *) &nonce_val, sizeof(nonce_val)) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate random nonce.");

        nonce = ASN1_INTEGER_new();
        if (!nonce)
                return log_oom();

        if (ASN1_INTEGER_set_uint64(nonce, nonce_val) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set nonce in ASN1_INTEGER.");

        *ret_nonce = TAKE_PTR(nonce);
        return 0;
}

static int build_timestamp_request(const struct iovec *digest, const char *algorithm, TS_REQ **ret_ts_req) {
        int r;
        assert(digest);
        assert(algorithm);
        assert(ret_ts_req);


        _cleanup_(TS_REQ_freep) TS_REQ *ts_req = NULL;
        _cleanup_(TS_MSG_IMPRINT_freep) TS_MSG_IMPRINT *ts_imprint = NULL;
        _cleanup_(X509_ALGOR_freep) X509_ALGOR *algo = NULL;
        _cleanup_(ASN1_INTEGER_freep) ASN1_INTEGER *nonce = NULL;

        int nid = OBJ_txt2nid(algorithm);
        if (nid == NID_undef)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupperted digest algorithm: %s.", algorithm);

        /* Possibly implement a check digest size is equal to the size expected by the algorithm*/

        ts_req = TS_REQ_new();
        if (!ts_req)
                return log_oom();

        /* version defaults to 1, RFC3161 only defines 1 */
        ts_imprint = TS_MSG_IMPRINT_new();
        if (!ts_imprint)
                return log_oom();

        algo = X509_ALGOR_new();
        if (!algo)
                return log_oom();

        /* redundant given RFC3161 only has one value (1) */
        if (TS_REQ_set_version(ts_req, 1) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set version.");

        if (X509_ALGOR_set0(algo, OBJ_nid2obj(nid), V_ASN1_NULL, /*pval=*/NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set digest algorithm.");

        if (TS_MSG_IMPRINT_set_algo(ts_imprint, algo) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set message imprint algorithm.");

        if (TS_MSG_IMPRINT_set_msg(ts_imprint, digest->iov_base, digest->iov_len) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set message imprint digest.");

        if (TS_REQ_set_msg_imprint(ts_req, ts_imprint) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to attach message imprint.");

        if (TS_REQ_set_cert_req(ts_req, 1) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set certReq flag.");

        r = build_nonce(&nonce);
        if (r < 0)
                return r;

        if (TS_REQ_set_nonce(ts_req, nonce) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to set nonce.");

        *ret_ts_req = TAKE_PTR(ts_req);
        return 0;
}

static int vl_method_sign(
                sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "digest",
                 SD_JSON_VARIANT_STRING, json_dispatch_unhex_iovec,
                 offsetof(SignParameters, digest),
                 SD_JSON_MANDATORY },
                { "algorithm",
                 SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
                 offsetof(SignParameters, algorithm),
                 SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(sign_parameters_done) SignParameters sp = {};
        _cleanup_(TS_REQ_freep) TS_REQ *ts_req = NULL;

        int r;
        assert(link);
        assert(parameters);

        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &sp);
        if (r != 0)
                return r;

        if (!iovec_is_set(&sp.digest))
                return sd_varlink_error_invalid_parameter_name(link, "digest");

        if (!streq(sp.algorithm, "SHA256"))
                return sd_varlink_error_invalid_parameter_name(link, "algorithm");

        r = build_timestamp_request(&sp.digest, sp.algorithm, &ts_req);
        if (r < 0)
                return r;

        // TSA Config (call )
        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR(
                                        "data",
                                        SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_OBJECT(
                                                        SD_JSON_BUILD_PAIR_STRING("timestampToken", "dummy"),
                                                        SD_JSON_BUILD_PAIR_STRING("tsaUrl", "dummy")))));
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        int r;

        r = varlink_server_new(&vs, /*flags=*/0, /*userdata=*/NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(vs, &vl_interface_io_systemd_Metrics);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(vs, "io.systemd.Report.Signer.Sign", vl_method_sign);
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
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r == 0)
                return log_error_errno(
                                SYNTHETIC_ERRNO(EINVAL), "This program can only run as a Varlink service.");
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