"""BRUTE — catch-all probe + USER/PASS bruteforce."""
from ..utils.connection import test_catch_all, try_login
from ..utils.helpers import check_if_brute, simple_bruteforce
from ..utils.results import VULNS

__MODULELABEL__ = "Login bruteforce"
__MODULECODE__ = "BRUTE"
__ORDER__ = 70


def run(ctx):
    if not check_if_brute(ctx.args):
        ctx.out(
            "BRUTE requires -u/--user or -U/--users and -p/--password or -P/--passwords",
            "ERROR",
            indent=4,
        )
        return

    # Catch-all lives inside BRUTE (not a separate -ts code).
    ctx.out("Catch-all test", "INFO", colortext=True)
    catch_all = test_catch_all(ctx.args, debug=ctx.debug)
    if catch_all == "unreachable":
        ctx.out("Could not reach server for catch-all / bruteforce", "ERROR", indent=4)
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

    def _on_success(cred):
        if not ctx.json:
            import sys
            sys.stdout.write(f"    user: {cred.user}, password: {cred.passw}\n")
            sys.stdout.flush()

    creds = simple_bruteforce(
        lambda c: try_login(ctx.args, c, debug=ctx.debug),
        ctx.args.user,
        ctx.args.users,
        ctx.args.password,
        ctx.args.passwords,
        ctx.args.spray,
        ctx.args.threads,
        on_success=_on_success if not ctx.json else None,
    )
    if creds:
        ctx.out(f"Found {len(creds)} valid credentials", "INFO", indent=4)
        if ctx.json:
            for cred in creds:
                ctx.out(f"user: {cred.user}, password: {cred.passw}", "TEXT", indent=4)
        user_str = (
            f"username: {ctx.args.user}"
            if ctx.args.user is not None
            else f"usernames: {ctx.args.users}"
        )
        pass_str = (
            f"password: {ctx.args.password}"
            if ctx.args.password is not None
            else f"passwords: {ctx.args.passwords}"
        )
        ctx.report.add_vulnerability(
            vuln_code=VULNS.WeakCreds.value,
            vuln_request=f"{user_str}\n{pass_str}",
            vuln_response="\n".join(f"user: {c.user}, password: {c.passw}" for c in creds),
        )
