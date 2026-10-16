"""BRUTE — catch-all probe + USER/PASS bruteforce."""
import sys

from ..utils.connection import login_bruteforce, test_catch_all
from ..utils.helpers import apply_default_brute_creds

__MODULELABEL__ = ""
__MODULECODE__ = "BRUTE"
__ORDER__ = 70


def _section(ctx, title: str) -> None:
    if getattr(ctx, "json", False):
        return
    ctx.out(title, "INFO", colortext=True)
    _flush_pop3(ctx)


def run(ctx):
    ctx.report.brute_creds = set()
    apply_default_brute_creds(ctx.args)

    # Catch-all lives inside BRUTE (not a separate -ts code).
    _section(ctx, "Catch-all test")
    catch_all = test_catch_all(ctx.args, debug=ctx.debug)
    if catch_all == "unreachable":
        ctx.out("Catch-all timed out or could not connect. Not confirmed.", "WARNING", indent=4)
        _flush_pop3(ctx)
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

    _flush_pop3(ctx)
    _section(ctx, "Guessing (credential bruteforce)")
    creds = login_bruteforce(ctx)
    ctx.report.brute_creds = creds
    guessing = getattr(ctx, "_brute_guessing", None)
    if creds:
        n = len(creds)
        word = "login" if n == 1 else "logins"
        ctx.out(f"Found {n} valid {word}", "TITLE", colortext=False, indent=4)
    _pop3_guessing_line(ctx, guessing)


def _flush_pop3(ctx) -> None:
    if getattr(ctx, "json", False):
        return
    lock = getattr(ctx, "print_lock", None)
    if lock is None:
        return
    chunk = lock.get_output_string()
    if chunk:
        sys.stdout.write(chunk)
        sys.stdout.flush()
        lock.output_string = ""


def _pop3_guessing_line(ctx, guessing: str | None) -> None:
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
