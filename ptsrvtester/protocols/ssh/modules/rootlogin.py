"""ROOTLOGIN — is direct login to the root account permitted?

Two layers (see :mod:`..utils.rootlogin_core` for the pure verdict logic):

  * **Behavioural (always):** read the authentication methods the server
    advertises for ``root`` (via a rejected ``auth_none``) and compare them with
    the methods offered to an ordinary name. If root is offered a password /
    keyboard-interactive method, password-based root login is permitted — the
    classic hardening finding (``PermitRootLogin`` should be ``no`` or
    ``prohibit-password``). If root is offered only public-key / gssapi, that is
    consistent with ``prohibit-password``.
  * **Credentialed (optional):** if a secret is supplied (``-p``/``-P`` password
    or ``--privkeys``), actually try to log in as root and, on success, report
    root access as **confirmed**.

Remote caveat: without valid root credentials, ``PermitRootLogin no`` vs ``yes``
cannot be distinguished — OpenSSH enforces the root policy only when auth would
otherwise succeed. The test therefore reports what is observable and only claims
"confirmed" on an actual successful login. Targets the root account explicitly;
never runs in the default / ALL sweep (``__RUN_IN_ALL__ = False``).
"""
import secrets

# Importing ssh_helpers applies paramiko's legacy-host-key + logging setup as a
# side effect (so old servers still negotiate and paramiko does not spam stderr).
from ptsrvtester.protocols.ssh.utils import ssh_helpers
from ptsrvtester.protocols.ssh.utils.helpers import text_or_file
from ptsrvtester.protocols.ssh.utils.results import SSHCreds, VULNS
from ptsrvtester.protocols.ssh.utils.rootlogin_core import assess_root_login

__MODULELABEL__ = "Root login permitted"
__MODULECODE__ = "ROOTLOGIN"
__ORDER__ = 32
__RUN_IN_ALL__ = False


def _root_creds(a, account: str) -> list[SSHCreds]:
    """Secrets to try as ``account``: private keys if given, else password(s)."""
    if getattr(a, "privkeys", None):
        return [SSHCreds(account, "", pk) for pk in ssh_helpers.parse_privkeys(a.privkeys)]
    passwords = text_or_file(getattr(a, "password", None), getattr(a, "passwords", None))
    return [SSHCreds(account, p, None) for p in passwords]


def _attempt_login(ip: str, port: int, creds_list: list[SSHCreds]):
    """Try each credential as root; (succeeded, attempted)."""
    if not creds_list:
        return None, False
    for c in creds_list:
        if ssh_helpers.try_login(ip, port, c) is not None:
            return True, True
    return False, True


def run(ctx):
    a = ctx.args
    ip, port = ctx.target

    account = a.user if (isinstance(a.user, str) and a.user) else "root"

    ctx.out(f"Checking whether login to '{account}' is permitted on {ip}:{port}",
            "INFO", colortext=True, indent=4)

    # (1) Behavioural probe: methods for root vs an ordinary (random) name.
    try:
        root_methods = ssh_helpers.get_auth_methods_for(ip, port, account)
    except Exception as e:
        ctx.debug(f"root methods probe failed: {e}")
        root_methods = None
    try:
        baseline_name = "ptuser_" + secrets.token_hex(5)
        baseline_methods = ssh_helpers.get_auth_methods_for(ip, port, baseline_name)
    except Exception as e:
        ctx.debug(f"baseline methods probe failed: {e}")
        baseline_methods = None

    # (2) Optional credentialed confirmation.
    creds_list = _root_creds(a, account)
    if creds_list:
        ctx.out(f"Credentials supplied — attempting a real login as '{account}' "
                f"({len(creds_list)} secret(s))", "WARNING", indent=4)
    login_succeeded, login_attempted = _attempt_login(ip, port, creds_list)

    result = assess_root_login(
        account=account,
        root_methods=root_methods,
        baseline_methods=baseline_methods,
        login_succeeded=login_succeeded,
        login_attempted=login_attempted,
    )

    _render(ctx, result)


def _fmt_methods(methods):
    if methods is None:
        return "unknown"
    if not methods:
        return "(none)"
    return ", ".join(methods)


def _render(ctx, r):
    if r.root_methods is not None:
        ctx.out(f"Auth methods offered to '{r.account}': {_fmt_methods(r.root_methods)}",
                "TEXT", indent=4)
        if r.baseline_methods is not None and r.baseline_methods != r.root_methods:
            ctx.out(f"Auth methods offered to an ordinary name: {_fmt_methods(r.baseline_methods)}",
                    "TEXT", indent=4)

    if r.verdict == "confirmed":
        ctx.out(f"Root login: PERMITTED — confirmed a real login as '{r.account}'",
                "VULN", indent=4)
    elif r.verdict == "password-permitted":
        ctx.out(f"Root login: password authentication is ENABLED for '{r.account}' "
                "(root can be targeted by password guessing)", "VULN", indent=4)
    elif r.verdict == "key-only":
        ctx.out(f"Root login: password disabled for '{r.account}'; only key-based methods "
                "offered (consistent with prohibit-password)", "NOTVULN", indent=4)
    elif r.verdict == "disabled":
        ctx.out(f"Root login: appears DISABLED for '{r.account}' (no auth method offered)",
                "OK", indent=4)
    else:
        ctx.out(f"Root login: could not be determined for '{r.account}'", "WARNING", indent=4)

    for n in r.notes:
        ctx.out(n, "TEXT", indent=8)

    with ctx.results_lock:
        ctx.properties["rootLoginAccount"] = r.account
        ctx.properties["rootLoginVerdict"] = r.verdict
        ctx.properties["rootAuthMethods"] = r.root_methods
        if r.password_enabled is not None:
            ctx.properties["rootPasswordEnabled"] = bool(r.password_enabled)
        ctx.properties["rootLoginConfirmed"] = bool(r.login_succeeded)

        if r.is_finding:
            if r.verdict == "confirmed":
                request = f"account: {r.account}\nreal login attempt with supplied credentials"
                response = f"authenticated successfully as '{r.account}' — root access is permitted"
            else:
                request = f"account: {r.account}\nread advertised authentication methods"
                response = (f"server offers a password method to '{r.account}' "
                            f"({_fmt_methods(r.root_methods)}) — password root login is permitted")
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.RootLoginPermitted.value,
                "vuln_request": request,
                "vuln_response": response,
            })
