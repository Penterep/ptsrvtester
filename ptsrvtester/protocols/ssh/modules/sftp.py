"""SFTP — SFTP/SCP access control & confinement (post-auth).

Logs in with the supplied credentials, opens one SFTP session and checks how well
the account is confined (see :mod:`..utils.sftp_core` for the verdict logic):

  * SFTP availability (``open_sftp``) and, best-effort, SCP (which needs exec).
  * Chroot confinement — is the real filesystem visible (``/etc/passwd``, ``/bin``)?
  * Read/write outside the tree — reading system files and *bounded* write probes
    to system locations (every file written is removed again).
  * Symlink escape — create a symlink to a system file and read through it.
  * Unexpected SSH capabilities — an SFTP-only account should not also get a
    shell, command execution or port forwarding.
  * ADS write — an NTFS Alternate Data Stream (``file:stream``).

All writes use a unique ``ptsrv_<token>`` name and are cleaned up. Needs valid
credentials (``-u`` + ``-p``/``-P``/``--privkeys``); never runs in the default /
ALL sweep (``__RUN_IN_ALL__ = False``).
"""
import secrets

import paramiko

# Importing ssh_helpers applies paramiko's legacy-host-key + logging setup as a
# side effect (so old servers still negotiate and paramiko does not spam stderr).
from ptsrvtester.protocols.ssh.utils import ssh_helpers  # noqa: F401
from ptsrvtester.protocols.ssh.utils.helpers import text_or_file
from ptsrvtester.protocols.ssh.utils.results import SSHCreds, VULNS
from ptsrvtester.protocols.ssh.utils.sftp_core import (
    SftpObservations,
    assess_sftp,
)

__MODULELABEL__ = "SFTP access control & confinement"
__MODULECODE__ = "SFTP"
__ORDER__ = 37
__RUN_IN_ALL__ = False

_CONNECT_TIMEOUT = 10.0
_PROBE_TIMEOUT = 8.0

# Canonical system paths used to decide whether the real filesystem is visible.
_SYSTEM_READ_PATHS = ("/etc/passwd", "/etc/hostname", "/etc/os-release")
_SYSTEM_STAT_PATHS = ("/bin", "/usr", "/var", "/root", "/home")
# Bounded write-probe destinations outside a typical login dir.
_WRITE_OUTSIDE_DIRS = ("/", "/tmp", "/var/tmp", "..")


def _sftp_creds(a, account: str) -> list[SSHCreds]:
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


# --- individual SFTP probes (each best-effort, never raising out) -------------

def _token() -> str:
    return "ptsrv_" + secrets.token_hex(6)


def _probe_confinement(sftp, obs: SftpObservations) -> None:
    try:
        obs.home = sftp.normalize(".")
    except Exception:
        obs.home = None

    system_reachable = False
    for p in _SYSTEM_READ_PATHS:
        try:
            with sftp.open(p, "r") as fh:
                data = fh.read(64)
            if data:
                obs.system_readable.append(p)
                system_reachable = True
        except Exception:
            pass
    for p in _SYSTEM_STAT_PATHS:
        try:
            sftp.stat(p)
            system_reachable = True
        except Exception:
            pass
    # Visible root shape as an extra signal.
    try:
        root_entries = set(sftp.listdir("/"))
        if {"etc", "bin", "usr"} & root_entries:
            system_reachable = True
    except Exception:
        pass

    obs.confined = not system_reachable


def _probe_write_outside(sftp, obs: SftpObservations) -> None:
    for d in _WRITE_OUTSIDE_DIRS:
        path = (d.rstrip("/") + "/" + _token()) if d != ".." else "../" + _token()
        try:
            with sftp.open(path, "w") as fh:
                fh.write("ptsrvtester write probe\n")
            # Confirm it really landed, then remove it.
            try:
                sftp.stat(path)
                obs.system_writable.append(path)
            except Exception:
                pass
            try:
                sftp.remove(path)
            except Exception:
                obs.notes.append(f"could not remove write probe {path} — please delete manually")
        except Exception:
            pass


def _probe_symlink(sftp, obs: SftpObservations) -> None:
    targets = ("/etc/passwd", "../../../../../../etc/passwd")
    for target in targets:
        link = _token() + "_lnk"
        created = False
        try:
            sftp.symlink(target, link)
            created = True
            obs.symlink_supported = True
            try:
                with sftp.open(link, "r") as fh:
                    data = fh.read(128)
                if b"root:" in (data if isinstance(data, bytes) else data.encode(errors="replace")):
                    obs.symlink_escape = True
                    obs.symlink_detail = f"symlink -> {target} resolved to a real /etc/passwd"
            except Exception:
                pass
        except Exception:
            if obs.symlink_supported is None:
                obs.symlink_supported = False
        finally:
            if created:
                try:
                    sftp.remove(link)
                except Exception:
                    obs.notes.append(f"could not remove symlink {link} — please delete manually")
        if obs.symlink_escape:
            break


def _probe_ads(sftp, obs: SftpObservations) -> None:
    base = _token() + ".txt"
    stream = base + ":ptads"
    base_created = stream_created = False
    try:
        with sftp.open(base, "w") as fh:
            fh.write("base\n")
        base_created = True
        try:
            with sftp.open(stream, "w") as fh:
                fh.write("ads\n")
            stream_created = True
        except Exception:
            obs.ads_supported = False
            return
        # On Linux the colon name is a literal, separate directory entry; on NTFS
        # the stream is hidden (not listed) but readable via the stream name.
        try:
            listed = set(sftp.listdir("."))
        except Exception:
            listed = set()
        readable = False
        try:
            with sftp.open(stream, "r") as fh:
                readable = bool(fh.read(8))
        except Exception:
            pass
        obs.ads_supported = bool(readable and stream not in listed)
    except Exception:
        obs.ads_supported = None
    finally:
        for name in (stream, base):
            try:
                sftp.remove(name)
            except Exception:
                pass
        _ = (base_created, stream_created)


def _probe_capabilities(client, transport, port: int, obs: SftpObservations) -> None:
    # exec
    marker = _token()
    try:
        _in, out, _err = client.exec_command(f"echo {marker}", timeout=_PROBE_TIMEOUT)
        text = out.read().decode(errors="replace")
        obs.exec_ok = marker in text
    except Exception:
        obs.exec_ok = False
    obs.scp_available = obs.exec_ok  # SCP rides on exec

    # interactive shell (PTY + shell)
    try:
        chan = transport.open_session(timeout=_PROBE_TIMEOUT)
        try:
            chan.get_pty()
            chan.invoke_shell()
            obs.shell_ok = True
        except Exception:
            obs.shell_ok = False
        finally:
            try:
                chan.close()
            except Exception:
                pass
    except Exception:
        obs.shell_ok = False

    # local port forwarding (direct-tcpip to loopback:sshd)
    try:
        chan = transport.open_channel("direct-tcpip", ("127.0.0.1", port),
                                      ("127.0.0.1", 0), timeout=_PROBE_TIMEOUT)
        try:
            chan.close()
        except Exception:
            pass
        obs.forward_ok = True
    except paramiko.ChannelException as e:
        obs.forward_ok = getattr(e, "code", None) == 2  # connect-failed still means fwd allowed
    except Exception:
        obs.forward_ok = False


def run(ctx):
    a = ctx.args
    ip, port = ctx.target

    account = a.user if (isinstance(a.user, str) and a.user) else (
        a.user[0] if isinstance(a.user, list) and a.user else None)
    if not account:
        ctx.out("SFTP requires -u/--user (account to test)", "WARNING", indent=4)
        return

    creds = _sftp_creds(a, account)
    if not creds:
        ctx.out("SFTP requires a secret to log in: -p/--password, -P/--passwords or --privkeys",
                "WARNING", indent=4)
        return

    ctx.out(f"Testing SFTP confinement for '{account}' on {ip}:{port} "
            f"({len(creds)} secret(s))", "INFO", colortext=True, indent=4)

    client = None
    for c in creds:
        client = _connect(ip, port, c)
        if client is not None:
            break

    obs = SftpObservations()
    if client is None:
        _render(ctx, assess_sftp(account=account, obs=obs))
        return

    obs.authenticated = True
    try:
        transport = client.get_transport()
        sftp = None
        try:
            sftp = client.open_sftp()
            obs.sftp_available = True
        except Exception as e:
            obs.notes.append(f"open_sftp failed: {type(e).__name__}: {e}")

        if sftp is not None:
            try:
                _probe_confinement(sftp, obs)
                _probe_write_outside(sftp, obs)
                _probe_symlink(sftp, obs)
                _probe_ads(sftp, obs)
            finally:
                try:
                    sftp.close()
                except Exception:
                    pass

        if transport is not None:
            _probe_capabilities(client, transport, port, obs)
    finally:
        try:
            client.close()
        except Exception:
            pass

    _render(ctx, assess_sftp(account=account, obs=obs))


# --- rendering ----------------------------------------------------------------

def _render(ctx, r):
    obs = r.obs
    if not obs.authenticated:
        ctx.out(f"SFTP: NOT TESTED — could not authenticate as '{r.account}'", "WARNING", indent=4)
        for n in r.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["sftpAccount"] = r.account
            ctx.properties["sftpVerdict"] = "no-auth"
        return

    # A. availability
    ctx.out("SFTP / SCP availability", "INFO", colortext=True, indent=4)
    if obs.sftp_available:
        ctx.out("SFTP subsystem: available", "TEXT", indent=8)
    else:
        ctx.out("SFTP subsystem: not available for this account", "OK", indent=8)
    if obs.scp_available is not None:
        ctx.out(f"SCP (exec-based): {'available' if obs.scp_available else 'unavailable'}",
                "TEXT", indent=8)

    if not obs.sftp_available:
        for n in r.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["sftpAccount"] = r.account
            ctx.properties["sftpAvailable"] = False
            ctx.properties["sftpVerdict"] = "no-sftp"
        return

    # B. confinement
    ctx.out("Filesystem confinement (chroot)", "INFO", colortext=True, indent=4)
    if obs.home:
        ctx.out(f"login directory: {obs.home}", "TEXT", indent=8)
    if obs.confined is True:
        ctx.out("confined to a sub-tree (chroot / internal-sftp)", "OK", indent=8)
    elif obs.confined is False:
        ctx.out("NOT confined — the real filesystem is visible", "WARNING", indent=8)
    if obs.system_readable:
        ctx.out("readable system files: " + ", ".join(obs.system_readable), "WARNING", indent=8)
    if obs.system_writable:
        ctx.out("WRITABLE outside the tree: " + ", ".join(obs.system_writable), "VULN", indent=8)

    # C. symlink escape
    ctx.out("Symlink / hardlink escape", "INFO", colortext=True, indent=4)
    if obs.symlink_escape:
        ctx.out(f"symlink escape possible — {obs.symlink_detail}", "VULN", indent=8)
    elif obs.symlink_supported:
        ctx.out("symlinks can be created but did not resolve outside the tree", "OK", indent=8)
    elif obs.symlink_supported is False:
        ctx.out("symlink creation refused by the server", "OK", indent=8)
    ctx.out("note: hardlinks are not exercised (not exposed by the SFTP client)", "TEXT", indent=8)

    # D. restricted-account check
    ctx.out("Restricted-account check (SFTP-only?)", "INFO", colortext=True, indent=4)
    caps = r.extra_capabilities
    if caps:
        ctx.out("account also has: " + ", ".join(caps)
                + " — NOT restricted to file transfer", "VULN" if obs.confined else "WARNING",
                indent=8)
    else:
        ctx.out("no shell / exec / forwarding — account is restricted to file transfer", "OK",
                indent=8)

    # E. ADS
    ctx.out("NTFS Alternate Data Stream (ADS) write", "INFO", colortext=True, indent=4)
    if obs.ads_supported is True:
        ctx.out("ADS write succeeded — data can be hidden in a stream (NTFS server)", "VULN",
                indent=8)
    elif obs.ads_supported is False:
        ctx.out("ADS write not possible (non-NTFS server or rejected)", "OK", indent=8)
    else:
        ctx.out("ADS write could not be determined", "TEXT", indent=8)

    for n in r.notes:
        ctx.debug(n)

    with ctx.results_lock:
        ctx.properties["sftpAccount"] = r.account
        ctx.properties["sftpAvailable"] = True
        ctx.properties["sftpConfined"] = obs.confined
        ctx.properties["sftpHome"] = obs.home
        ctx.properties["sftpSystemReadable"] = obs.system_readable
        ctx.properties["sftpSystemWritable"] = obs.system_writable
        ctx.properties["sftpSymlinkEscape"] = obs.symlink_escape
        ctx.properties["sftpExtraCapabilities"] = caps
        ctx.properties["sftpAdsWritable"] = obs.ads_supported
        _push_vulns(ctx, r)


def _push_vulns(ctx, r):
    obs = r.obs
    if r.no_chroot_finding:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.SftpNoChroot.value,
            "vuln_request": f"account: {r.account}\nSFTP: browse '/', stat system paths",
            "vuln_response": "no ChrootDirectory confinement — the account can browse the real "
                             "filesystem (readable: " + (", ".join(obs.system_readable) or "system paths") + ")",
        })
    if r.write_outside_finding:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.SftpTraversal.value,
            "vuln_request": f"account: {r.account}\nSFTP: write probe outside the login tree",
            "vuln_response": "writable location(s) outside the intended tree: "
                             + ", ".join(obs.system_writable),
        })
    if r.symlink_finding:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.SftpSymlinkEscape.value,
            "vuln_request": f"account: {r.account}\nSFTP: create symlink to a system file and read it",
            "vuln_response": obs.symlink_detail or "a symlink resolved outside the confinement",
        })
    if r.unrestricted_finding:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.SftpUnrestricted.value,
            "vuln_request": f"account: {r.account}\npost-auth: SFTP + shell/exec/forward probes",
            "vuln_response": "the SFTP account also has: " + ", ".join(r.extra_capabilities)
                             + " — it is not restricted to file transfer",
        })
    if r.ads_finding:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.SftpADS.value,
            "vuln_request": f"account: {r.account}\nSFTP: write an NTFS alternate data stream",
            "vuln_response": "an NTFS Alternate Data Stream was written — data can be hidden and "
                             "may bypass content scanning",
        })
