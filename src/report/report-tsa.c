/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "macro.h"
#include "metrics.h"
#include "random-util.h"
#include "report-tsa.h"

/* This is the exact sme function as 'query-tsa in the client signing implmentation.
If both implementations are kept they should share
it instead of redundant code. */
static int timestamp_query(const char *digest, const char *algorithm, char **ret_token) {
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

static int tsa_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        _cleanup_(freep) char *token = NULL;
        _cleanup_(freep) char *hex = NULL;
        uint8_t buf[32]; /* SHA digest length, only the token's genTime matters, not content. */
        int r;

        assert(mf);
        assert(link);

        random_bytes(buf, sizeof(buf)); /* Generate a random 32-byte value, maybe a safer way? */

        hex = hexmem(buf, sizeof(buf));
        if (!hex)
                return log_oom();

        r = timestamp_query(hex, "SHA256", &token);
        if (r < 0)
                return r;

        return metric_build_send_string(mf, link, /* object= */ NULL, token, /* fields= */ NULL);
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
