"""BRUTE — SMTP AUTH bruteforce."""
from ..utils.helpers import apply_default_brute_creds
from ._common import eng

__MODULELABEL__ = ""
__MODULECODE__ = "BRUTE"
__ORDER__ = 95


def _section(ctx, e, title: str) -> None:
    if getattr(ctx, "json", False):
        return
    ctx.out(title, "INFO", colortext=True)
    e._flush_terminal()


def run(ctx):
    e = eng(ctx)
    apply_default_brute_creds(ctx.args)

    _section(ctx, e, "Catch-all test")
    try:
        catch_all = e._smtp_auth_catch_all()
    except Exception as ex:
        ctx.out(f"Catch-all failed: {ex}", "ERROR", indent=4)
        e._flush_terminal()
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
        e._flush_terminal()
        return
    elif catch_all == "unsupported":
        detail = getattr(e, "_auth_catch_all_detail", None) or (
            "AUTH is not offered. Password guessing was not tested."
        )
        ctx.out(detail, "WARNING", indent=4)
        e._brute_guessing = "not_tested"
        e._brute_guessing_detail = detail
        e._flush_terminal()
        return
    elif catch_all == "limited":
        detail = "Connection rate limit. Password guessing was not tested."
        ctx.out(detail, "WARNING", indent=4)
        e._brute_guessing = "not_tested"
        e._brute_guessing_detail = detail
        e._flush_terminal()
        return
    else:
        ctx.out("Not configured (server rejects invalid creds)", "NOTVULN", indent=4)

    e._flush_terminal()
    _section(ctx, e, "Login bruteforce")
    e.do_brute = True
    e.login_bruteforce()
    e._stream_brute_result()
