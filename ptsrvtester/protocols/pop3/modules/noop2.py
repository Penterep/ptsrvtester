"""NOOP2 — NOOP connection count (pre-auth + post-auth if -u/-p)."""
from ..utils.connection import test_noop_conn_count_preauth, test_noop_conn_count_postauth
from ..utils.ptprinthelper import get_colored_text
from ..utils.results import (
    POP3_NOOP_PREAUTH_CONN_HIGH_MIN,
    POP3_NOOP_PREAUTH_CONN_INCREASED_MIN,
    POP3_NOOP_PREAUTH_CONN_SIGNIFICANT_MIN,
    POP3_NOOP_POSTAUTH_CONN_ACCT_HIGH_MIN,
    POP3_NOOP_POSTAUTH_CONN_ACCT_INCREASED_MIN,
    POP3_NOOP_POSTAUTH_CONN_ACCT_SIGNIFICANT_MIN,
    POP3_NOOP_POSTAUTH_CONN_IP_HIGH_MIN,
    POP3_NOOP_POSTAUTH_CONN_IP_INCREASED_MIN,
    POP3_NOOP_POSTAUTH_CONN_IP_SIGNIFICANT_MIN,
    VULNS,
)

__MODULELABEL__ = "NOOP connection count"
__MODULECODE__ = "NOOP2"
__ORDER__ = 81


def _evaluate_preauth_conn_count(maintained):
    """Evaluate pre-auth connection count and return (vulnerable, rating)."""
    vulnerable = False
    rating = "OK"

    if maintained >= POP3_NOOP_PREAUTH_CONN_HIGH_MIN:
        rating = "high"
        vulnerable = True
    elif maintained >= POP3_NOOP_PREAUTH_CONN_SIGNIFICANT_MIN:
        rating = "significant"
        vulnerable = True
    elif maintained >= POP3_NOOP_PREAUTH_CONN_INCREASED_MIN:
        rating = "increased"
        vulnerable = True

    return vulnerable, rating


def _evaluate_postauth_conn_count(maintained):
    """Evaluate post-auth connection count and return (vulnerable, rating_ip, rating_acct)."""
    vulnerable = False
    rating_ip = "OK"
    rating_acct = "OK"

    if maintained >= POP3_NOOP_POSTAUTH_CONN_IP_HIGH_MIN:
        rating_ip = "high"
        vulnerable = True
    elif maintained >= POP3_NOOP_POSTAUTH_CONN_IP_SIGNIFICANT_MIN:
        rating_ip = "significant"
        vulnerable = True
    elif maintained >= POP3_NOOP_POSTAUTH_CONN_IP_INCREASED_MIN:
        rating_ip = "increased"
        vulnerable = True

    if maintained >= POP3_NOOP_POSTAUTH_CONN_ACCT_HIGH_MIN:
        rating_acct = "high"
        vulnerable = True
    elif maintained >= POP3_NOOP_POSTAUTH_CONN_ACCT_SIGNIFICANT_MIN:
        rating_acct = "significant"
        vulnerable = True
    elif maintained >= POP3_NOOP_POSTAUTH_CONN_ACCT_INCREASED_MIN:
        rating_acct = "increased"
        vulnerable = True

    return vulnerable, rating_ip, rating_acct


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

    if result.min_rt_seconds is not None:
        min_d = noop1_rt_display(result.min_rt_seconds)
        max_d = noop1_rt_display(result.max_rt_seconds)
        avg_d = noop1_rt_display(result.avg_rt_seconds)
        if (result.avg_rt_seconds or 0) > NOOP2_AVG_TIME_OK_MAX_SECONDS:
            ctx.out(
                f"Time between two commands ({min_d} - {max_d}, avg {avg_d}) "
                f"— over {NOOP2_AVG_TIME_OK_MAX_SECONDS:.0f}s avg under load",
                "VULN",
                indent=8,
            )
        else:
            ctx.out(
                f"Time between two commands ({min_d} - {max_d}, avg {avg_d})",
                "NOTVULN",
                indent=8,
            )
    else:
        ctx.out(
            f"Time between two commands: no successful replies "
            f"({result.total_noops_sent} sent)",
            "VULN",
            indent=8,
        )

    err_rate = result.error_rate_pct
    if err_rate <= NOOP2_ERROR_RATE_OK_MAX_PCT:
        ctx.out(f"Error rate: {err_rate:.0f}%", "NOTVULN", indent=8)
    else:
        ctx.out(
            f"Error rate: {err_rate:.0f}% (over {NOOP2_ERROR_RATE_OK_MAX_PCT:.0f}%)",
            "VULN",
            indent=8,
        )

    if result.early_exit_no_connections:
        ctx.out(
            "Server disconnected all connections before test time limit",
            "VULN",
            indent=8,
        )

    storm_base = result.storm_pool_connections or result.connections_established
    disconnected = result.early_disconnect_count
    if storm_base > 0 and disconnected > 0:
        pct = 100.0 * disconnected / storm_base
        ctx.out(
            f"Disconnected connections during test: {disconnected} from {storm_base} ({pct:.0f}%)",
            "TITLE",
            indent=8,
        )
        for idx, reason, detail in result.terminated_connections:
            ctx.out(
                get_colored_text(f"Connection #{idx} terminated — {reason} ({detail})", "ADDITIONS"),
                "TEXT",
                indent=12,
            )
    _flush_ctx(ctx)


def run(ctx):
    ctx.out("Pre-authentication", "TITLE", indent=4)

    try:
        result_preauth = test_noop_conn_count_preauth(
            ctx.args, debug=ctx.debug, out=ctx.out, flush=lambda: _flush_ctx(ctx),
        )
    except Exception as e:
        ctx.out(f"Test failed: {e}", "ERROR", indent=8)
        result_preauth = None

    if result_preauth and not result_preauth.error_message:
        maintained = result_preauth.connections_maintained
        vulnerable, rating = _evaluate_preauth_conn_count(maintained)
        _emit_noop2_result(ctx, result_preauth)
        if vulnerable:
            ctx.report.add_vulnerability(
                vuln_code=VULNS.NoopConnCountPreauth.value,
                vuln_request=f"pre-auth NOOP connection count ({rating})",
            )
    elif result_preauth:
        ctx.out(f"Test error: {result_preauth.error_message}", "ERROR", indent=8)

    if ctx.args.user and ctx.args.password:
        ctx.out("Post-authentication", "TITLE", indent=4)

        try:
            result_postauth = test_noop_conn_count_postauth(
                ctx.args, ctx.args.user, ctx.args.password,
                debug=ctx.debug, out=ctx.out, flush=lambda: _flush_ctx(ctx),
            )
        except Exception as e:
            ctx.out(f"Test failed: {e}", "ERROR", indent=8)
            result_postauth = None

        if result_postauth and not result_postauth.error_message:
            maintained = result_postauth.connections_maintained
            vulnerable, rating_ip, rating_acct = _evaluate_postauth_conn_count(maintained)
            _emit_noop2_result(ctx, result_postauth)
            if vulnerable:
                ctx.report.add_vulnerability(
                    vuln_code=VULNS.NoopConnCountPostauth.value,
                    vuln_request=f"post-auth NOOP connection count (IP:{rating_ip}, account:{rating_acct})",
                )
        elif result_postauth:
            ctx.out(f"Test error: {result_postauth.error_message}", "ERROR", indent=8)
    else:
        ctx.out("Post-authentication: Skipped (provide -u/--user and -p/--password)", "INFO", indent=4)
