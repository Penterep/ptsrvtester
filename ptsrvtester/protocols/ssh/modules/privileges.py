"""PRIVS — post-auth privileges & access enumeration (companion to SHELL).

Once an account can log in, SHELL answers *can it get a shell?*; this test answers
*what can that account reach?* It logs in with the supplied credentials and runs a
single enumeration script over one session channel, then classifies the result
(see :mod:`..utils.privileges_core` for the pure verdict logic):

  * **Groups** — ``id`` / ``id -Gn``: which groups the account is in, flagging
    privileged (``sudo``/``wheel``/``admin``) and root-equivalent
    (``docker``/``lxd``/``disk``/``shadow``) membership.
  * **Filesystem** — r/w/x on a fixed list of sensitive paths (via the shell's
    ``test`` builtin — no file contents are ever read) plus writable ``$PATH`` dirs.
  * **Administrative commands** — which dangerous admin binaries the account can
    invoke (``systemctl``/``mount``/``docker``/``useradd``…). Informational.
  * **Sudo** — ``sudo -n -l``: passwordless sudo (especially to ``ALL``) is the
    instant-root finding; password-required sudo is a finding too when a login
    password was supplied.

Runs in the same "Post-auth access" section as SHELL, needs the same inputs
(``-u`` + ``-p``/``-P``/``--privkeys``), and never runs in the default / ALL sweep
(``__RUN_IN_ALL__ = False``).
"""
import paramiko

# Importing ssh_helpers applies paramiko's legacy-host-key + logging setup as a
# side effect (so old servers still negotiate and paramiko does not spam stderr).
from ptsrvtester.protocols.ssh.utils import ssh_helpers  # noqa: F401
from ptsrvtester.protocols.ssh.utils.helpers import text_or_file
from ptsrvtester.protocols.ssh.utils.results import SSHCreds, VULNS
from ptsrvtester.protocols.ssh.utils.privileges_core import (
    ADMIN_COMMANDS,
    SENSITIVE_PATHS,
    M_ID, M_GROUPS, M_PERMS, M_PATHW, M_CMDS, M_SUDOV, M_SUDO, M_END,
    SudoState,
    assess_privileges,
    parse_sections,
)

__MODULELABEL__ = "Post-auth privileges & access"
__MODULECODE__ = "PRIVS"
__ORDER__ = 34
__RUN_IN_ALL__ = False

_CONNECT_TIMEOUT = 10.0
_PROBE_TIMEOUT = 15.0


def _build_script() -> str:
    """One POSIX-sh script emitting marker-delimited sections for the core to parse.

    ``test`` (``[ -r/-w/-x ]``) reflects the account's real effective permissions
    without reading any file; ``sudo -n -l`` is non-interactive (never prompts).
    """
    paths = " ".join(spec.path for spec in SENSITIVE_PATHS)
    cmds = " ".join(ADMIN_COMMANDS)
    return (
        f"echo {M_ID}\n"
        "id 2>/dev/null\n"
        f"echo {M_GROUPS}\n"
        "id -Gn 2>/dev/null || groups 2>/dev/null\n"
        f"echo {M_PERMS}\n"
        f'for p in {paths}; do r=-; w=-; x=-; e=-; '
        '[ -e "$p" ] && e=e; [ -r "$p" ] && r=r; [ -w "$p" ] && w=w; [ -x "$p" ] && x=x; '
        'printf \'%s %s %s %s %s\\n\' "$r" "$w" "$x" "$e" "$p"; done\n'
        f"echo {M_PATHW}\n"
        'printf \'%s\' "$PATH" | tr \':\' \'\\n\' | while IFS= read -r d; do '
        '[ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] && echo "$d"; done\n'
        f"echo {M_CMDS}\n"
        f'for c in {cmds}; do command -v "$c" >/dev/null 2>&1 && echo "$c"; done\n'
        f"echo {M_SUDOV}\n"
        'command -v sudo >/dev/null 2>&1 && echo present || echo absent\n'
        f"echo {M_SUDO}\n"
        "sudo -n -l 2>&1\n"
        f"echo {M_END}\n"
    )


def _priv_creds(a, account: str) -> list[SSHCreds]:
    """Secrets to authenticate as ``account``: private keys if given, else password(s)."""
    if getattr(a, "privkeys", None):
        return [SSHCreds(account, "", pk) for pk in ssh_helpers.parse_privkeys(a.privkeys)]
    passwords = text_or_file(getattr(a, "password", None), getattr(a, "passwords", None))
    return [SSHCreds(account, p, None) for p in passwords]


def _connect(ip: str, port: int, cred: SSHCreds):
    """Authenticate and return an OPEN SSHClient (or None)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy)
    try:
        if cred.privkey is not None:
            client.connect(
                ip, port, username=cred.user, key_filename=cred.privkey.keypath,
                passphrase=cred.privkey.passphrase, look_for_keys=False,
                allow_agent=False, banner_timeout=_CONNECT_TIMEOUT, timeout=_CONNECT_TIMEOUT,
            )
        else:
            client.connect(
                ip, port, username=cred.user, password=cred.passw, look_for_keys=False,
                allow_agent=False, banner_timeout=_CONNECT_TIMEOUT, timeout=_CONNECT_TIMEOUT,
            )
        return client
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        return None


def _run_script(client, script: str, timeout: float = _PROBE_TIMEOUT) -> tuple[str, str]:
    """Run the enumeration script; return ``(stdout, stderr)`` (both may be empty)."""
    try:
        _stdin, stdout, stderr = client.exec_command(script, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        return out, err
    except Exception as e:
        return "", f"{type(e).__name__}: {e}"


def run(ctx):
    a = ctx.args
    ip, port = ctx.target

    account = a.user if (isinstance(a.user, str) and a.user) else (
        a.user[0] if isinstance(a.user, list) and a.user else None)
    if not account:
        ctx.out("PRIVS requires -u/--user (account to test)", "WARNING", indent=4)
        return

    creds = _priv_creds(a, account)
    if not creds:
        ctx.out("PRIVS requires a secret to log in: -p/--password, -P/--passwords or --privkeys",
                "WARNING", indent=4)
        return

    ctx.out(f"Enumerating privileges for '{account}' on {ip}:{port} "
            f"({len(creds)} secret(s))", "INFO", colortext=True, indent=4)

    client = None
    for c in creds:
        client = _connect(ip, port, c)
        if client is not None:
            break

    have_password = bool(getattr(a, "password", None) or getattr(a, "passwords", None))

    if client is None:
        result = assess_privileges(
            account=account, authenticated=False, sections=None, have_password=have_password,
        )
        _render(ctx, result)
        return

    try:
        out, err = _run_script(client, _build_script())
    finally:
        try:
            client.close()
        except Exception:
            pass

    sections = parse_sections(out) if out else {}
    result = assess_privileges(
        account=account, authenticated=True, sections=sections, have_password=have_password,
    )
    if err.strip():
        result.notes.append(f"stderr: {err.strip().splitlines()[0][:200]}")
    _render(ctx, result)


# --- rendering ----------------------------------------------------------------

_SUDO_RENDER = {
    SudoState.NOPASSWD_ALL: ("VULN",
        "PASSWORDLESS sudo to ALL — the account can become root instantly (sudo -n -l)"),
    SudoState.NOPASSWD_SOME: ("VULN",
        "PASSWORDLESS sudo to specific commands — privilege escalation without a password"),
    SudoState.PASSWORD_REQUIRED: ("WARNING",
        "sudo is configured for this account but requires a password"),
    SudoState.NONE: ("OK", "account is not allowed to run sudo"),
    SudoState.ABSENT: ("TEXT", "sudo is not installed on the host"),
    SudoState.UNKNOWN: ("WARNING", "sudo status could not be determined"),
}


def _render(ctx, r):
    if not r.authenticated:
        ctx.out(f"Privileges: NOT TESTED — could not authenticate as '{r.account}'",
                "WARNING", indent=4)
        for n in r.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["privAccount"] = r.account
            ctx.properties["privVerdict"] = "no-auth"
        return

    who = r.username or r.account
    uid_str = f" (uid={r.uid})" if r.uid is not None else ""
    ctx.out(f"Authenticated as '{who}'{uid_str}", "TEXT", indent=4)

    if not r.enumerated:
        ctx.out("Could not run enumeration commands — account looks shell-restricted "
                "(nologin / SFTP-only / forced command)", "OK", indent=4)
        for n in r.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["privAccount"] = r.account
            ctx.properties["privVerdict"] = "restricted"
        return

    _render_groups(ctx, r)
    _render_files(ctx, r)
    _render_commands(ctx, r)
    _render_sudo(ctx, r)

    for n in r.notes:
        ctx.debug(n)

    with ctx.results_lock:
        ctx.properties["privAccount"] = r.account
        ctx.properties["privUsername"] = r.username
        ctx.properties["privUid"] = r.uid
        ctx.properties["privGroups"] = r.groups
        ctx.properties["privPrivilegedGroups"] = r.privileged_groups + r.root_equivalent_groups
        ctx.properties["privWritableSensitive"] = [p.path for p in r.writable_sensitive]
        ctx.properties["privReadableSensitive"] = [p.path for p in r.readable_sensitive]
        ctx.properties["privWritablePathDirs"] = r.writable_path_dirs
        ctx.properties["privAdminCommands"] = r.admin_commands
        ctx.properties["privSudoState"] = r.sudo_state.value

        _push_group_vuln(ctx, r)
        _push_files_vuln(ctx, r)
        _push_sudo_vuln(ctx, r)


def _render_groups(ctx, r):
    ctx.out("User groups", "INFO", colortext=True, indent=4)
    if r.groups:
        ctx.out(", ".join(r.groups), "TEXT", indent=8)
    else:
        ctx.out("(could not read group membership)", "TEXT", indent=8)
    if r.root_equivalent_groups:
        ctx.out(f"root-equivalent group membership: {', '.join(r.root_equivalent_groups)} "
                "(effectively root — e.g. docker/lxd/disk/shadow)", "VULN", indent=8)
    if r.privileged_groups:
        ctx.out(f"privileged group membership: {', '.join(r.privileged_groups)} "
                "(administrative — commonly grants sudo/root)", "VULN", indent=8)
    if not r.group_is_finding and r.groups:
        ctx.out("no privileged group membership", "OK", indent=8)


def _render_files(ctx, r):
    ctx.out("Filesystem access (sensitive paths)", "INFO", colortext=True, indent=4)
    present = [p for p in r.perms if p.present]
    if not present:
        ctx.out("(none of the probed sensitive paths are present/visible)", "TEXT", indent=8)
    for p in present:
        cat = "VULN" if p.is_finding else "TEXT"
        ctx.out(f"{p.mode_str()}  {p.path}  ({p.label})", cat, indent=8)
    if r.writable_path_dirs:
        ctx.out(f"writable directory on $PATH: {', '.join(r.writable_path_dirs)} "
                "(PATH-hijack privilege escalation)", "VULN", indent=8)
    if not r.files_is_finding:
        ctx.out("no writable sensitive files or $PATH directories", "OK", indent=8)


def _render_commands(ctx, r):
    ctx.out("Administrative commands available", "INFO", colortext=True, indent=4)
    if not r.admin_commands:
        ctx.out("none of the probed administrative binaries are on PATH", "OK", indent=8)
        return
    high = f"  (high-risk: {', '.join(r.high_risk_commands)})" if r.high_risk_commands else ""
    ctx.out(", ".join(r.admin_commands), "WARNING", indent=8)
    if high:
        ctx.out(high.strip(), "WARNING", indent=8)
    ctx.out("note: availability alone is not a vulnerability — what they run as depends on "
            "sudo / SUID / group rights above", "TEXT", indent=8)


def _render_sudo(ctx, r):
    ctx.out("Sudo", "INFO", colortext=True, indent=4)
    cat, msg = _SUDO_RENDER[r.sudo_state]
    if r.sudo_state == SudoState.PASSWORD_REQUIRED and r.have_password:
        cat, msg = "VULN", ("sudo requires a password, but a login password was supplied — the "
                            "same secret very likely grants full sudo (privilege escalation)")
    ctx.out(msg, cat, indent=8)
    for e in r.sudo_entries:
        ctx.out(e, "TEXT", indent=8)


# --- deferred vulnerabilities (bound to the shared software node) -------------

def _push_group_vuln(ctx, r):
    if not r.group_is_finding:
        return
    groups = r.root_equivalent_groups + r.privileged_groups
    ctx.deferred_vulns.append({
        "vuln_code": VULNS.PrivilegedGroup.value,
        "vuln_request": f"account: {r.account}\nread group membership (id)",
        "vuln_response": f"member of privilege-granting group(s): {', '.join(groups)}",
    })


def _push_files_vuln(ctx, r):
    if not r.files_is_finding:
        return
    lines = []
    for p in r.writable_sensitive:
        lines.append(f"writable: {p.path} ({p.label})")
    for p in r.readable_sensitive:
        lines.append(f"readable: {p.path} ({p.label})")
    for d in r.writable_path_dirs:
        lines.append(f"writable $PATH dir: {d}")
    ctx.deferred_vulns.append({
        "vuln_code": VULNS.SensitiveFileAccess.value,
        "vuln_request": f"account: {r.account}\ntest r/w/x on sensitive paths and $PATH dirs",
        "vuln_response": "\n".join(lines),
    })


def _push_sudo_vuln(ctx, r):
    if not r.sudo_is_finding:
        return
    if r.sudo_state == SudoState.NOPASSWD_ALL:
        resp = "passwordless sudo to ALL — instant root"
    elif r.sudo_state == SudoState.NOPASSWD_SOME:
        resp = "passwordless sudo to: " + ("; ".join(r.sudo_entries) or "specific commands")
    else:
        resp = "sudo requires a password, but the login password was supplied — likely full sudo"
    ctx.deferred_vulns.append({
        "vuln_code": VULNS.SudoAccess.value,
        "vuln_request": f"account: {r.account}\nsudo -n -l",
        "vuln_response": resp,
    })
