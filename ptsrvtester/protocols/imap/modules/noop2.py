"""NOOP2 — NOOP connection count (pre-auth + post-auth if -u/-p)."""
from ..utils.ptprinthelper import get_colored_text
from ..utils.results import conn_limit_count_verdict
from ._common import eng

__MODULELABEL__ = "NOOP connection count"
__MODULECODE__ = "NOOP2"
__ORDER__ = 86


def _flush_ctx(ctx) -> None:
    if getattr(ctx, "json", False):
        return
    lock = getattr(ctx, "print_lock", None)
    if lock is None:
        return
    chunk = lock.get_output_string()
    if chunk:
        import sys
        sys.stdout.write(chunk)
        sys.stdout.flush()
        lock.output_string = ""


def _emit_noop2_result(ctx, result) -> None:
    from ..utils.results import (
        NOOP2_AVG_TIME_OK_MAX_SECONDS,
        NOOP2_ERROR_RATE_OK_MAX_PCT,
        noop1_rt_display,
    )

    verbose = bool(getattr(ctx.args, "debug", False))
    if result.min_rt_seconds is not None:
        min_d = noop1_rt_display(result.min_rt_seconds)
        max_d = noop1_rt_display(result.max_rt_seconds)
        avg_d = noop1_rt_display(result.avg_rt_seconds)
        if (result.avg_rt_seconds or 0) > NOOP2_AVG_TIME_OK_MAX_SECONDS:
            ctx.out(
                f"Time between two commands ({min_d} - {max_d}, avg {avg_d}) "
                f"— over {NOOP2_AVG_TIME_OK_MAX_SECONDS:.0f}s avg under load",
                "VULN",
                indent=4,
            )
        else:
            ctx.out(
                f"Time between two commands ({min_d} - {max_d}, avg {avg_d})",
                "NOTVULN",
                indent=4,
            )
    else:
        ctx.out(
            f"Time between two commands: no successful replies "
            f"({result.total_noops_sent} sent)",
            "VULN",
            indent=4,
        )

    err_rate = result.error_rate_pct
    if err_rate <= NOOP2_ERROR_RATE_OK_MAX_PCT:
        ctx.out(f"Error rate: {err_rate:.0f}%", "NOTVULN", indent=4)
    else:
        ctx.out(
            f"Error rate: {err_rate:.0f}% (over {NOOP2_ERROR_RATE_OK_MAX_PCT:.0f}%)",
            "VULN",
            indent=4,
        )

    storm_base = result.storm_pool_connections or result.connections_established
    disconnected = result.early_disconnect_count
    if storm_base > 0 and disconnected > 0:
        pct = 100.0 * disconnected / storm_base
        ctx.out(
            f"Disconnected connections during test: {disconnected} from {storm_base} ({pct:.0f}%)",
            "TITLE",
            indent=4,
        )
        if verbose:
            for idx, reason, detail in result.terminated_connections:
                ctx.out(
                    get_colored_text(f"Connection #{idx} terminated — {reason} ({detail})", "ADDITIONS"),
                    "TEXT",
                    indent=8,
                )
    _flush_ctx(ctx)


def _maybe_add_conn_limit_vuln(ctx, result, vuln_code: str, phase: str) -> None:
    kind, _ = conn_limit_count_verdict(
        result.connections_established, result.max_connections_attempted,
    )
    if kind != "VULN":
        return
    ctx.report.add_vulnerability(
        vuln_code=vuln_code,
        vuln_request=(
            f"{phase} NOOP connection count "
            f"({result.connections_established}/{result.max_connections_attempted})"
        ),
    )


def run(ctx):
    e = eng(ctx)

    from ..utils.results import VULNS

    ctx.out("Pre-authentication", "TITLE", indent=4)

    try:
        result_preauth = e.test_noop_conn_count_preauth()
    except Exception as ex:
        ctx.out(f"Test failed: {ex}", "ERROR", indent=4)
        result_preauth = None

    if result_preauth and not result_preauth.error_message:
        _emit_noop2_result(ctx, result_preauth)
        _maybe_add_conn_limit_vuln(ctx, result_preauth, VULNS.NoopConnCountPreauth.value, "pre-auth")
    elif result_preauth:
        ctx.out(f"Test error: {result_preauth.error_message}", "ERROR", indent=4)

    if ctx.args.user and ctx.args.password:
        ctx.out("Post-authentication", "TITLE", indent=4)

        try:
            result_postauth = e.test_noop_conn_count_postauth(ctx.args.user, ctx.args.password)
        except Exception as ex:
            ctx.out(f"Test failed: {ex}", "ERROR", indent=4)
            result_postauth = None

        if result_postauth and not result_postauth.error_message:
            _emit_noop2_result(ctx, result_postauth)
            _maybe_add_conn_limit_vuln(ctx, result_postauth, VULNS.NoopConnCountPostauth.value, "post-auth")
        elif result_postauth:
            ctx.out(f"Test error: {result_postauth.error_message}", "ERROR", indent=4)
    else:
        ctx.out("Post-authentication: Skipped (provide -u/--user and -p/--password)", "INFO", indent=4)
