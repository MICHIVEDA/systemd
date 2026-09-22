#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "build.h"
#include "log.h"
#include "main-func.h"
#include "string-util.h"
#include "varlink-io.systemd.Report.Signer.h"
#include "varlink-util.h"
#include "verbs.h"

COMMAND("systemd-report-sign-tsa\0", "Timestamp report digests via an RFC 3161 Time Stamping Authority."
        //.man_pages = "systemd-report-sign-tsa@.service(8)\0"
);

typedef struct SignParameters {
        const char *digest;
        const char *algorithm;
} SignParameters;

static int query_tsa(const char *digest, const char *algorithm, char **ret_token) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        _cleanup_(freep) char *token = NULL;
        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        int r;

        assert(digest);
        assert(algorithm);
        assert(ret_token);

        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Timestamp");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to timestampd: %m");

        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Timestamp.Request",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("digest", digest),
                        SD_JSON_BUILD_PAIR_STRING("hashAlgorithm", algorithm));
        if (r < 0)
                return log_error_errno(r, "Failed to call timestampd: %m");
        if (error_id)
                return log_error_errno(
                                sd_varlink_error_to_errno(error_id, reply),
                                "Timestampd returned an error: %s",
                                error_id);

        static const sd_json_dispatch_field table[] = {
                { "token", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, 0, SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(reply, table, SD_JSON_ALLOW_EXTENSIONS, &token);
        if (r < 0)
                return log_error_errno(r, "Failed to parse timestampd reply: %m");

        *ret_token = TAKE_PTR(token);
        return 0;
}

static int vl_method_sign(
                sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "digest",
                 SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
                 offsetof(SignParameters, digest),
                 SD_JSON_MANDATORY },
                { "algorithm",
                 SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
                 offsetof(SignParameters, algorithm),
                 SD_JSON_MANDATORY },
                {}
        };

        _cleanup_(freep) char *token = NULL;
        SignParameters sp = {};
        int r;

        assert(link);
        assert(parameters);

        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &sp);
        if (r != 0)
                return r;

        if (isempty(sp.digest))
                return sd_varlink_error_invalid_parameter_name(link, "digest");

        if (isempty(sp.algorithm))
                return sd_varlink_error_invalid_parameter_name(link, "algorithm");

        r = query_tsa(sp.digest, sp.algorithm, &token);
        if (r < 0)
                return r;

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR(
                                        "data",
                                        SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_STRING(
                                                        "timestampToken", token)))));
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        int r;

        r = varlink_server_new(&vs, /*flags=*/0, /*userdata=*/NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(vs, &vl_interface_io_systemd_Report_Signer);
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
        log_setup();
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return vl_server();
}

DEFINE_MAIN_FUNCTION(run);
