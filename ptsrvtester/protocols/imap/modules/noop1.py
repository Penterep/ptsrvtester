"""NOOP1 — NOOP connection duration (pre-auth + post-auth if -u/-p)."""
from ..utils.helpers import one_cli_user
from ._common import eng

__MODULELABEL__ = "NOOP connection duration"
__MODULECODE__ = "NOOP1"
__ORDER__ = 85


def _fmt_held(seconds: float | None) -> str:
    if seconds is None:
        return "N/A"
    if seconds >= 60:
        return f"{seconds / 60.0:.1f} min"
    return f"{seconds:.1f}s"


def _evaluate_duration(result, thresholds):
    """Evaluate duration result and return (vulnerable, rating)."""
    maintained_min = result.maintained_seconds / 60.0
    vulnerable = False
    rating = "OK"

    high_min, significant_min, increased_min = thresholds
    held = result.disconnect_after_seconds if result.disconnected else result.maintained_seconds
    held = held or 0.0

    if result.hit_test_cap or result.disconnected:
        if held >= high_min:
            rating = "high"
            vulnerable = True
        elif held >= significant_min:
            rating = "significant"
            vulnerable = True
        elif held >= increased_min:
            rating = "increased"
            vulnerable = True

    return vulnerable, rating, maintained_min


def _emit_timing(ctx, result, indent=8):
    from ..utils.results import NOOP1_ERROR_RATE_OK_MAX_PCT, noop1_rt_display

    if result.min_rt_seconds is not None:
        ctx.out(
            f"Time between two commands ({noop1_rt_display(result.min_rt_seconds)} - "
            f"{noop1_rt_display(result.max_rt_seconds)}, avg {noop1_rt_display(result.avg_rt_seconds)})",
            "NOTVULN",
            indent=indent,
        )
        if result.slowdown_detected:
            ctx.out(
                f"Time trolting is configured "
                f"(baseline {noop1_rt_display(result.baseline_avg_seconds)} → "
                f"last {noop1_rt_display(result.last_window_avg_seconds)})",
                "NOTVULN",
                indent=indent,
            )
        else:
            ctx.out("No time trolting is configured", "VULN", indent=indent)
    else:
        ctx.out("No time trolting is configured (not enough samples)", "VULN", indent=indent)

    err_rate = result.error_rate_pct
    if err_rate <= NOOP1_ERROR_RATE_OK_MAX_PCT:
        ctx.out(f"Error rate: {err_rate:.0f}%", "NOTVULN", indent=indent)
    else:
        ctx.out(
            f"Error rate: {err_rate:.0f}% (over {NOOP1_ERROR_RATE_OK_MAX_PCT:.0f}%)",
            "VULN",
            indent=indent,
        )


def _emit_duration(ctx, result, vulnerable):
    held = result.disconnect_after_seconds if result.disconnected else result.maintained_seconds
    bullet = "VULN" if vulnerable else "NOTVULN"
    if result.idle_disconnect:
        ctx.out(
            f"Idle disconnect: connection closed after {_fmt_held(held)} without NOOP",
            bullet,
            indent=8,
        )
    elif result.disconnected:
        ctx.out(f"Connection dropped after {_fmt_held(held)}", bullet, indent=8)
    elif result.hit_test_cap:
        ctx.out(f"No disconnect within {_fmt_held(result.maintained_seconds)}", bullet, indent=8)
    _emit_timing(ctx, result, indent=8)
    ctx.out(
        f"NOOPs: {result.noops_sent} sent, {result.noops_ok} OK, {result.noops_error} errors",
        "INFO",
        indent=8,
    )


def run(ctx):
    e = eng(ctx)

    from ..utils.results import (
        IMAP_NOOP_PREAUTH_DUR_HIGH_MIN,
        IMAP_NOOP_PREAUTH_DUR_INCREASED_MIN,
        IMAP_NOOP_PREAUTH_DUR_SIGNIFICANT_MIN,
        IMAP_NOOP_POSTAUTH_DUR_HIGH_MIN,
        IMAP_NOOP_POSTAUTH_DUR_INCREASED_MIN,
        IMAP_NOOP_POSTAUTH_DUR_SIGNIFICANT_MIN,
        VULNS,
    )

    ctx.out("Pre-authentication", "TITLE", indent=4)
    e._flush_terminal()

    try:
        result_preauth = e.test_noop_duration_preauth()
    except Exception as ex:
        ctx.out(f"Test failed: {ex}", "ERROR", indent=8)
        result_preauth = None

    if result_preauth and not result_preauth.error_message:
        thresholds = (
            IMAP_NOOP_PREAUTH_DUR_HIGH_MIN,
            IMAP_NOOP_PREAUTH_DUR_SIGNIFICANT_MIN,
            IMAP_NOOP_PREAUTH_DUR_INCREASED_MIN,
        )
        vulnerable, rating, _maintained_min = _evaluate_duration(result_preauth, thresholds)
        _emit_duration(ctx, result_preauth, vulnerable)
        if vulnerable:
            ctx.report.add_vulnerability(
                vuln_code=VULNS.NoopDurationPreauth.value,
                vuln_request=f"pre-auth NOOP duration ({rating})",
            )
    elif result_preauth:
        ctx.out(f"Test error: {result_preauth.error_message}", "ERROR", indent=8)

    user = one_cli_user(ctx.args.user)
    if user and ctx.args.password:
        ctx.out("Post-authentication", "TITLE", indent=4)
        e._flush_terminal()

        try:
            result_postauth = e.test_noop_duration_postauth(user, ctx.args.password)
        except Exception as ex:
            ctx.out(f"Test failed: {ex}", "ERROR", indent=8)
            result_postauth = None

        if result_postauth and not result_postauth.error_message:
            thresholds = (
                IMAP_NOOP_POSTAUTH_DUR_HIGH_MIN,
                IMAP_NOOP_POSTAUTH_DUR_SIGNIFICANT_MIN,
                IMAP_NOOP_POSTAUTH_DUR_INCREASED_MIN,
            )
            vulnerable, rating, _maintained_min = _evaluate_duration(result_postauth, thresholds)
            _emit_duration(ctx, result_postauth, vulnerable)
            if vulnerable:
                ctx.report.add_vulnerability(
                    vuln_code=VULNS.NoopDurationPostauth.value,
                    vuln_request=f"post-auth NOOP duration ({rating})",
                )
        elif result_postauth:
            ctx.out(f"Test error: {result_postauth.error_message}", "ERROR", indent=8)
    else:
        ctx.out("Post-authentication: Skipped (provide -u/--user and -p/--password)", "INFO", indent=4)
