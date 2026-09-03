#include "sd-json.h"
#include "sd-varlink.h"

#include "verbs.h"

COMMAND(
    "systemd-report-tsa\0",
    "Generate timestamp from the TSA server.",
    // Man page?
);

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *vs = NULL;
        int r;

        r = varlink_server_new(&vs, /*flags=*/ 0, /*userdata=*/ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

                r = sd_varlink_server_add_interface(vs, &vl_interface_io_systemd_Metrics);
        if (r < 0)
                return log_error_errno("Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        vs,
                        "io.systemd.Metrics.List",      vl_method_list_metrics,
                        "io.systemd.Metrics.Describe",  vl_method_describe_metrics);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = sd_varlink_server_loop_auto(vs);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}