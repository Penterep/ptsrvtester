"""Shared POP3 USER/PASS guessing used by BRUTE, WEAK and RECYKL.

One run probes the server. Later tests in the same scan reuse that result
and only report their own finding.
"""
from ..utils.connection import login_bruteforce, test_catch_all
from ..utils.helpers import apply_default_brute_creds


def _section(ctx, title: str) -> None:
    if getattr(ctx, "json", False):
        return
    ctx.out(title, "INFO", colortext=True)


def _remember(ctx, test: str) -> None:
    runs = getattr(ctx.report, "auth_probe_runs", None)
    if runs is None:
        runs = {}
        ctx.report.auth_probe_runs = runs
    creds = getattr(ctx.report, "brute_creds", None) or set()
    runs[test] = {
        "guessing": getattr(ctx, "_brute_guessing", None),
        "creds": set(creds),
    }


def _stream(ctx, focus: str) -> None:
    """``block`` is BRUTE, ``creds`` is WEAK and RECYKL."""
    creds = getattr(ctx.report, "brute_creds", None)
    guessing = getattr(ctx, "_brute_guessing", None)
    if focus == "creds":
        if creds:
            n = len(creds)
            word = "login" if n == 1 else "logins"
            ctx.out(f"Found {n} valid {word}", "TITLE", colortext=False, indent=4)
        elif guessing in ("not_limited", "stopped", "insufficient"):
            ctx.out("No valid login found", "NOTVULN", indent=4)
        elif guessing == "not_tested":
            ctx.out(
                getattr(ctx, "_brute_guessing_detail", None)
                or "Could not connect. Password guessing was not tested.",
                "WARNING",
                indent=4,
            )
        return
    if guessing == "insufficient":
        ctx.out(
            "The test cannot be evaluated. At least 50 combinations must be tested.",
            "WARNING",
            indent=4,
        )
    elif guessing == "not_limited":
        ctx.out("No protection against password guessing", "VULN", indent=4)
    elif guessing == "stopped":
        paren = getattr(ctx, "_brute_block_paren", None)
        msg = f"Attack was blocked ({paren})" if paren else "Attack was blocked"
        ctx.out(msg, "NOTVULN", indent=4)
    elif guessing == "not_tested":
        ctx.out(
            getattr(ctx, "_brute_guessing_detail", None)
            or "Could not connect. Password guessing was not tested.",
            "WARNING",
            indent=4,
        )


def run_auth_guess(ctx, test: str) -> None:
    """Catch-all, then USER/PASS guesses. ``test`` is BRUTE, WEAK or RECYKL."""
    focus = "block" if test == "BRUTE" else "creds"
    if getattr(ctx, "_auth_guess_done", False):
        _remember(ctx, test)
        _stream(ctx, focus)
        return

    ctx._auth_guess_done = True
    ctx.report.brute_creds = set()
    apply_default_brute_creds(ctx.args)

    _section(ctx, "Catch-all test")
    catch_all = test_catch_all(ctx.args, debug=ctx.debug)
    if catch_all == "unreachable":
        ctx.out("Catch-all timed out or could not connect. Not confirmed.", "WARNING", indent=4)
        ctx._brute_guessing = "not_tested"
        ctx._brute_guessing_detail = "Could not connect. Password guessing was not tested."
        _remember(ctx, test)
        _stream(ctx, focus)
        return
    if catch_all == "indeterminate":
        ctx.out(
            "Server accepted invalid credentials (indeterminate). Results may be false positives.",
            "WARNING",
            indent=4,
        )
        ctx.report.update_properties(catchAll="indeterminate")
    else:
        ctx.out("Not configured (server rejects invalid creds)", "NOTVULN", indent=4)

    _section(ctx, "Guessing (credential bruteforce)")
    ctx.report.brute_creds = login_bruteforce(ctx)
    _remember(ctx, test)
    _stream(ctx, focus)
