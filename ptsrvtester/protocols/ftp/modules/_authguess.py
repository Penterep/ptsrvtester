"""Shared FTP USER/PASS guessing used by BRUTE, WEAK and RECYKL.

One run probes the server. Later tests in the same scan reuse that result
and only report their own finding. FTP has no catch-all check.
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
    """USER/PASS guesses. ``test`` is BRUTE, WEAK or RECYKL."""
    e = eng(ctx)
    focus = "block" if test == "BRUTE" else "creds"
    if getattr(e, "_auth_guess_done", False):
        _remember(e, test)
        e._stream_brute_result(focus=focus)
        return

    apply_default_brute_creds(ctx.args)
    e._auth_guess_done = True
    _section(ctx, "Guessing (credential bruteforce)")
    e.login_bruteforce()
    _remember(e, test)
    e._stream_brute_result(focus=focus)
