"""BRUTE — catch-all + LOGIN bruteforce."""
from ..utils.helpers import check_if_brute, simple_bruteforce
from ._common import eng

__MODULELABEL__ = "Login bruteforce"
__MODULECODE__ = "BRUTE"
__ORDER__ = 100


def run(ctx):
    e = eng(ctx)
    if not check_if_brute(ctx.args):
        ctx.out(
            "BRUTE requires -u/--user or -U/--users and -p/--password or -P/--passwords",
            "ERROR",
            indent=4,
        )
        return

    ctx.out("Catch-all test", "INFO", colortext=True)
    try:
        catch_all = e._test_catch_all()
    except Exception as ex:
        ctx.out(f"Catch-all failed: {ex}", "ERROR", indent=4)
        return

    e.results.catch_all = catch_all
    if catch_all == "indeterminate":
        ctx.out(
            "Server accepted invalid credentials (indeterminate). Results may be false positives.",
            "WARNING",
            indent=4,
        )
    else:
        ctx.out("Not configured (server rejects invalid creds)", "NOTVULN", indent=4)

    def _on_success(cred):
        if not ctx.json:
            import sys
            sys.stdout.write(f"    user: {cred.user}, password: {cred.passw}\n")
            sys.stdout.flush()

    creds = simple_bruteforce(
        e._try_login,
        ctx.args.user,
        ctx.args.users,
        ctx.args.password,
        ctx.args.passwords,
        ctx.args.spray,
        ctx.args.threads,
        on_success=_on_success if not ctx.json else None,
    )
    e.results.creds = set(creds) if creds else set()
    e._stream_brute_result()
