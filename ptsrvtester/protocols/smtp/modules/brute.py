"""BRUTE — SMTP AUTH bruteforce."""
from ..utils.helpers import check_if_brute, simple_bruteforce
from ._common import eng

__MODULELABEL__ = "Login bruteforce"
__MODULECODE__ = "BRUTE"
__ORDER__ = 95


def run(ctx):
    e = eng(ctx)
    if not check_if_brute(ctx.args):
        ctx.out(
            "BRUTE requires -u/--user or -U/--users and -p/--password or -P/--passwords",
            "ERROR",
            indent=4,
        )
        return

    e.do_brute = True

    def _on_success(cred):
        if not ctx.json:
            import sys
            sys.stdout.write(f"    user: {cred.user}, password: {cred.passw}\n")
            sys.stdout.flush()

    e.results.creds = simple_bruteforce(
        e._try_login,
        ctx.args.user,
        ctx.args.users,
        ctx.args.password,
        ctx.args.passwords,
        ctx.args.spray,
        ctx.args.threads,
        on_success=_on_success if not ctx.json else None,
    )
    e._stream_brute_result()
