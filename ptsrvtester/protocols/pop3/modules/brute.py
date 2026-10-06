"""BRUTE — catch-all probe + USER/PASS bruteforce."""
import sys

from ..utils.connection import login_bruteforce, test_catch_all
from ..utils.helpers import apply_default_brute_creds, password_request_text, shown_password, text_or_file
from ..utils.results import VULNS

__MODULELABEL__ = ""
__MODULECODE__ = "BRUTE"
__ORDER__ = 70


def _section(ctx, title: str) -> None:
    if getattr(ctx, "json", False):
        return
    ctx.out(title, "INFO", colortext=True)
    _flush_pop3(ctx)


def run(ctx):
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
    _section(ctx, "Login bruteforce")
    creds = login_bruteforce(ctx)
    guessing = getattr(ctx, "_brute_guessing", None)
    if creds:
        n = len(creds)
        word = "login" if n == 1 else "logins"
        ctx.out(f"Found {n} valid {word}", "TITLE", colortext=False, indent=4)
        if ctx.json:
            for cred in creds:
                ctx.out(f"user: {cred.user}, password: {shown_password(cred.passw)}", "TEXT", indent=4)
        names = text_or_file(ctx.args.user, None)
        user_str = (
            "username: " + ", ".join(names)
            if names
            else f"usernames: {ctx.args.users}"
        )
        pass_str = (
            password_request_text(ctx.args.password)
            if ctx.args.password is not None
            else f"passwords: {ctx.args.passwords}"
        )
        ctx.report.add_vulnerability(
            vuln_code=VULNS.WeakCreds.value,
            vuln_request=f"{user_str}\n{pass_str}",
            vuln_response="\n".join(
                f"user: {c.user}, password: {shown_password(c.passw)}" for c in creds
            ),
        )
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
    if guessing == "not_limited":
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
