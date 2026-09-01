"""SHELL — is interactive shell / command execution permitted after login?

Some accounts authenticate fine but are deliberately shell-less: their shell is
``/usr/sbin/nologin`` or ``/bin/false``, or they are restricted to SFTP /
port-forwarding, or an ``sshd`` ``ForceCommand`` overrides what runs. This test
logs in with the supplied credentials and checks what the account can actually
do (see :mod:`..utils.shellaccess_core` for the verdict logic):

  * runs a command via ``exec_command`` (an arithmetic marker the shell must
    evaluate — a bare terminal echo of the typed command does not count), and
  * opens an interactive shell (PTY + ``invoke_shell``) and checks the same marker.

Verdict: ``shell`` (interactive shell obtained) or ``exec`` (command execution
only) → shell access is available (finding, ``PTV-SSH-SHELLACCESS``);
``restricted`` → the account is shell-less (reported as OK, with any banner such
as the nologin message captured as evidence).

Needs valid credentials (``-u`` + ``-p``/``-P``/``--privkeys``); never runs in the
default / ALL sweep (``__RUN_IN_ALL__ = False``).
"""
import random
import socket
import time

import paramiko

# Importing ssh_helpers applies paramiko's legacy-host-key + logging setup as a
# side effect (so old servers still negotiate and paramiko does not spam stderr).
from ptsrvtester.protocols.ssh.utils import ssh_helpers  # noqa: F401
from ptsrvtester.protocols.ssh.utils.helpers import text_or_file
from ptsrvtester.protocols.ssh.utils.results import SSHCreds, VULNS
from ptsrvtester.protocols.ssh.utils.shellaccess_core import (
    ProbeOutcome,
    assess_shell_access,
)

__MODULELABEL__ = "Shell access permitted"
__MODULECODE__ = "SHELL"
__ORDER__ = 33
__RUN_IN_ALL__ = False

_CONNECT_TIMEOUT = 10.0
_PROBE_TIMEOUT = 6.0


def _make_marker() -> tuple[str, str]:
    """Return ``(command, expected)``: an ``echo`` whose output proves execution.

    The command contains an arithmetic expansion (``$((a*b))``) so the executed
    output (``PTSHELL<product>_<token>``) differs from the literal command text a
    PTY echoes back — only real evaluation produces the expected string.
    """
    a, b = random.randint(11, 99), random.randint(11, 99)
    token = "%08x" % random.getrandbits(32)
    command = f"echo PTSHELL$(( {a} * {b} ))_{token}"
    expected = f"PTSHELL{a * b}_{token}"
    return command, expected


def _shell_creds(a, account: str) -> list[SSHCreds]:
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


def _probe_exec(client, command: str, expected: str, timeout: float = _PROBE_TIMEOUT) -> ProbeOutcome:
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        try:
            status = stdout.channel.recv_exit_status()
        except Exception:
            status = None
        text = (out + err).strip()
        return ProbeOutcome(ok=(expected in out), output=text, exit_status=status)
    except Exception as e:
        return ProbeOutcome(ok=False, output="", note=f"{type(e).__name__}: {e}")


def _probe_shell(client, command: str, expected: str, timeout: float = _PROBE_TIMEOUT) -> ProbeOutcome:
    try:
        chan = client.invoke_shell()
    except Exception as e:
        return ProbeOutcome(ok=False, output="", note=f"{type(e).__name__}: {e}")
    chan.settimeout(1.0)
    buf = ""
    try:
        # Give a shell a moment to print its prompt / banner, then send the marker.
        time.sleep(0.3)
        _drain(chan, 0.4)
        chan.send(command + "\n")
        deadline = time.time() + timeout
        while time.time() < deadline and expected not in buf:
            try:
                data = chan.recv(4096)
            except socket.timeout:
                continue
            except Exception:
                break
            if not data:
                break
            buf += data.decode(errors="replace")
    finally:
        try:
            chan.close()
        except Exception:
            pass
    return ProbeOutcome(ok=(expected in buf), output=buf.strip())


def _drain(chan, seconds: float) -> str:
    out = ""
    end = time.time() + seconds
    while time.time() < end:
        try:
            data = chan.recv(4096)
        except socket.timeout:
            break
        except Exception:
            break
        if not data:
            break
        out += data.decode(errors="replace")
    return out


def run(ctx):
    a = ctx.args
    ip, port = ctx.target

    account = a.user if (isinstance(a.user, str) and a.user) else (
        a.user[0] if isinstance(a.user, list) and a.user else None)
    if not account:
        ctx.out("SHELL requires -u/--user (account to test)", "WARNING", indent=4)
        return

    creds = _shell_creds(a, account)
    if not creds:
        ctx.out("SHELL requires a secret to log in: -p/--password, -P/--passwords or --privkeys",
                "WARNING", indent=4)
        return

    ctx.out(f"Testing shell access for '{account}' on {ip}:{port} "
            f"({len(creds)} secret(s))", "INFO", colortext=True, indent=4)

    client = None
    for c in creds:
        client = _connect(ip, port, c)
        if client is not None:
            break

    if client is None:
        result = assess_shell_access(account=account, authenticated=False)
        _render(ctx, result)
        return

    try:
        cmd, expected = _make_marker()
        exec_res = _probe_exec(client, cmd, expected)
        cmd2, expected2 = _make_marker()
        shell_res = _probe_shell(client, cmd2, expected2)
    finally:
        try:
            client.close()
        except Exception:
            pass

    result = assess_shell_access(
        account=account, authenticated=True,
        exec_result=exec_res, shell_result=shell_res,
    )
    _render(ctx, result)


def _render(ctx, r):
    if r.verdict == "no-auth":
        ctx.out(f"Shell access: NOT TESTED — could not authenticate as '{r.account}'",
                "WARNING", indent=4)
        for n in r.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["shellAccessAccount"] = r.account
            ctx.properties["shellAccessVerdict"] = "no-auth"
        return

    if r.verdict == "shell":
        ctx.out(f"Shell access: PERMITTED — interactive shell obtained as '{r.account}'",
                "VULN", indent=4)
    elif r.verdict == "exec":
        ctx.out(f"Shell access: PERMITTED — command execution available as '{r.account}' "
                "(no interactive shell)", "VULN", indent=4)
    else:
        ctx.out(f"Shell access: RESTRICTED — '{r.account}' authenticated but got no shell "
                "(nologin / SFTP-only / forced command)", "OK", indent=4)
        if r.banner:
            ctx.out(f"server said: {r.banner.splitlines()[0][:200]}", "TEXT", indent=8)

    for n in r.notes:
        ctx.debug(n)

    with ctx.results_lock:
        ctx.properties["shellAccessAccount"] = r.account
        ctx.properties["shellAccessVerdict"] = r.verdict
        ctx.properties["shellAccessConfirmed"] = r.is_finding
        if r.banner:
            ctx.properties["shellRestrictedBanner"] = r.banner.splitlines()[0][:200]

        if r.is_finding:
            how = "interactive shell" if r.verdict == "shell" else "command execution"
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.ShellAccess.value,
                "vuln_request": f"account: {r.account}\npost-auth: open a session channel and "
                                f"run a command / request a shell",
                "vuln_response": f"{how} obtained as '{r.account}' — shell access is permitted",
            })
