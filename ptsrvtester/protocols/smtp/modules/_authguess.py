"""Shared SMTP AUTH guessing used by BRUTE, WEAK and RECYKL.

One run probes the server. Later tests in the same scan reuse that result
and only report their own finding.
"""
from ..utils.helpers import apply_default_brute_creds
from ._common import eng


def _section(ctx, title: str) -> None:
    if getattr(ctx, "json", False):
        return
    ctx.out(title, "INFO", colortext=True)


def _remember(e, test: str) -> None:
    runs = getattr(e, "_auth_probe_runs", None)
    if runs is None:
        runs = {}
        e._auth_probe_runs = runs
    creds = getattr(e.results, "creds", None) or set()
    runs[test] = {
        "guessing": getattr(e, "_brute_guessing", None),
        "creds": set(creds),
    }


def run_auth_guess(ctx, test: str) -> None:
    """Catch-all, then AUTH guesses. ``test`` is BRUTE, WEAK or RECYKL."""
    e = eng(ctx)
    focus = "block" if test == "BRUTE" else "creds"
    if getattr(e, "_auth_guess_done", False):
        _remember(e, test)
        e._stream_brute_result(focus=focus)
        return

    apply_default_brute_creds(ctx.args)
    e._auth_guess_done = True

    _section(ctx, "Catch-all test")
    try:
        catch_all = e._smtp_auth_catch_all()
    except Exception as ex:
        ctx.out(f"Catch-all failed: {ex}", "ERROR", indent=4)
        e._brute_guessing = "not_tested"
        e._brute_guessing_detail = f"Catch-all failed: {ex}"
        _remember(e, test)
        return

    e._auth_catch_all = catch_all
    if catch_all == "indeterminate":
        ctx.out(
            "Server accepted invalid credentials (indeterminate). Results may be false positives.",
            "WARNING",
            indent=4,
        )
    elif catch_all == "unreachable":
        ctx.out("Catch-all timed out or could not connect. Not confirmed.", "WARNING", indent=4)
        e._brute_guessing = "not_tested"
        e._brute_guessing_detail = "Could not connect. Password guessing was not tested."
        _remember(e, test)
        return
    elif catch_all == "unsupported":
        detail = getattr(e, "_auth_catch_all_detail", None) or (
            "AUTH is not offered. Password guessing was not tested."
        )
        ctx.out(detail, "WARNING", indent=4)
        e._brute_guessing = "not_tested"
        e._brute_guessing_detail = detail
        _remember(e, test)
        return
    elif catch_all == "limited":
        detail = "Connection rate limit. Password guessing was not tested."
        ctx.out(detail, "WARNING", indent=4)
        e._brute_guessing = "not_tested"
        e._brute_guessing_detail = detail
        _remember(e, test)
        return
    else:
        ctx.out("Not configured (server rejects invalid creds)", "NOTVULN", indent=4)

    _section(ctx, "Guessing (credential bruteforce)")
    e.do_brute = True
    e.login_bruteforce()
    _remember(e, test)
    e._stream_brute_result(focus=focus)
