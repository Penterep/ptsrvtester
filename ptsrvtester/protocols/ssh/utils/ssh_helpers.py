"""Network / analysis helpers shared by the SSH modules.

Pure functions (no ``self``) lifted from the old flat ``protocols/ssh.py`` so the
per-test ``modules/*.py`` can reuse them. Imports are absolute on purpose: the
modules are loaded dynamically by ``BaseMain`` with no package parent.
"""
import contextlib
import io
import json
import socket

import paramiko
import paramiko.ssh_exception
from ssh_audit import ssh_audit

from ptsrvtester.protocols.ssh.utils.helpers import filepaths, text_or_file
from ptsrvtester.protocols.ssh.utils.results import (
    BadPubkeyResult,
    CVE,
    CryptoFinding,
    PrivKeyDetails,
    SSHAuditResult,
    SSHCreds,
)

BANNER_TIMEOUT = 10.0


def is_reachable(ip: str, port: int, timeout: float = 5.0) -> bool:
    """Quick TCP reachability probe (connect only, no protocol I/O)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def grab_banner(ip: str, port: int) -> str:
    """Read the raw SSH identification banner (first line)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(BANNER_TIMEOUT)
    try:
        sock.connect((ip, port))
        return sock.recv(4096).strip().splitlines()[0].decode()
    finally:
        try:
            sock.close()
        except Exception:
            pass


def get_host_key(ip: str, port: int) -> str:
    """Return the remote host key as ``"<name> <base64>"`` (raises on failure)."""
    trans = paramiko.Transport((ip, port))
    try:
        trans.start_client()
        hk = trans.get_remote_server_key()
        return hk.get_name() + " " + hk.get_base64()
    finally:
        try:
            trans.close()
        except Exception:
            pass


def get_auth_methods(ip: str, port: int) -> list[str] | None:
    """Return the server's advertised auth methods (via a rejected ``auth_none``)."""
    trans = paramiko.Transport((ip, port))
    am: list[str] | None = None
    try:
        trans.start_client()
        try:
            trans.auth_none("")
        except paramiko.BadAuthenticationType as e:
            am = e.allowed_types
        except Exception:
            pass
    finally:
        try:
            trans.close()
        except Exception:
            pass
    return am


def run_ssh_audit(ip: str, port: int) -> SSHAuditResult:
    """Run ssh-audit and parse its JSON into CVEs + crypto findings."""
    out = ssh_audit.OutputBuffer()
    aconf = ssh_audit.AuditConf(ip, port)
    aconf.json = True

    try:
        # ssh-audit prints its own connection-error/chatter straight to stdout/stderr;
        # keep it out of our (possibly JSON) output — the result is read from `out`.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = ssh_audit.audit(out, aconf)

        if status == ssh_audit.exitcodes.CONNECTION_ERROR:
            return SSHAuditResult(status, [], [])

        bufj = json.loads(out.get_buffer())

        findings: list[CryptoFinding] = []
        recommendations = bufj.get("recommendations", None)
        if recommendations is not None:
            # {"critical": {"del": {"key": [{"name","notes"}, ...]}}}
            for level, actions in recommendations.items():
                for action, categories in actions.items():
                    for category, details in categories.items():
                        for detail in details:
                            findings.append(
                                CryptoFinding(
                                    level, action, category,
                                    detail["name"], detail["notes"],
                                )
                            )

        cves: list[CVE] = []
        cves_ = bufj.get("cves", None)
        if cves_ is not None:
            for cve in cves_:
                cves.append(CVE(cve["name"], cve["description"], float(cve["cvssv2"])))

        return SSHAuditResult(None, findings, cves)
    except SystemExit as e:
        return SSHAuditResult(e.code, [], [])


def check_bad_pubkey(pubkeys_path: str, host_key: str) -> BadPubkeyResult:
    """Compare the server's host key against a directory of known (bad) ``*.pub`` keys."""
    for pubkey_path in filepaths(pubkeys_path, ".pub"):
        with open(pubkey_path, "r") as f:
            line = f.read().strip()
            # Some keys carry a trailing "user@host"; keep only "<type> <base64>".
            pubkey = " ".join(line.split(" ")[:2])
            if pubkey == host_key:
                return BadPubkeyResult(True, pubkey_path)
    return BadPubkeyResult(False, "")


def check_bad_authkeys(ip: str, port: int, authkeys_path: str) -> list[str]:
    """Try each ``*.key`` (with its ``*.yml`` username) as a login; return the ones that work."""
    valid_authkeys: list[str] = []
    for authkey_path in filepaths(authkeys_path, ".key"):
        yml_path = ".".join(authkey_path.split(".")[:-1]) + ".yml"
        with open(yml_path, "r") as f:
            lines = f.read().splitlines()
            user_line = next(l for l in lines if ":user:" in l)
            username = user_line.split(" ")[-1]

        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy)
        valid = False
        try:
            c.connect(
                ip, port,
                look_for_keys=False,
                banner_timeout=10,
                username=username,
                key_filename=authkey_path,
            )
            valid = True
        except Exception:
            pass
        finally:
            c.close()
        if valid:
            valid_authkeys.append(authkey_path)
    return valid_authkeys


def parse_privkeys(privkeys_dir: str) -> list[PrivKeyDetails]:
    """Parse a directory of ``*.key`` private keys and optional ``*.pass`` passphrases."""
    keypaths = filepaths(privkeys_dir, ".key")
    passpaths = filepaths(privkeys_dir, ".pass")
    privkeys: list[PrivKeyDetails] = []
    for keypath in keypaths:
        ppaths = [p for p in passpaths if p == keypath[:-4] + ".pass"]
        if ppaths:
            with open(ppaths[0], "r") as f:
                privkeys.append(PrivKeyDetails(keypath, f.read().strip()))
        else:
            privkeys.append(PrivKeyDetails(keypath, None))
    return privkeys


def build_ssh_creds(args) -> list[SSHCreds]:
    """Build the SSHCreds list from -u/-U + -p/-P/--privkeys, honouring --spray."""
    users = text_or_file(args.user, args.users)
    passwords = text_or_file(args.password, args.passwords)

    privkeys: list[PrivKeyDetails] = []
    if getattr(args, "privkeys", None):
        privkeys = parse_privkeys(args.privkeys)

    # Keys take precedence over passwords when provided.
    secrets = privkeys if getattr(args, "privkeys", None) else passwords

    if getattr(args, "spray", False):
        return [
            SSHCreds(u, s, None) if isinstance(s, str) else SSHCreds(u, "", s)
            for s in secrets
            for u in users
        ]
    return [
        SSHCreds(u, s, None) if isinstance(s, str) else SSHCreds(u, "", s)
        for u in users
        for s in secrets
    ]


def try_login(ip: str, port: int, creds: SSHCreds) -> SSHCreds | None:
    """Attempt a single login with password or private key. Returns creds on success."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy)

    if creds.privkey is not None:
        keypath = creds.privkey.keypath
        passphrase = creds.privkey.passphrase
        password = None
    else:
        keypath = None
        passphrase = None
        password = creds.passw

    try:
        ssh.connect(
            ip, port,
            look_for_keys=False,
            banner_timeout=10,
            username=creds.user,
            password=password,
            key_filename=keypath,
            passphrase=passphrase,
        )
        return creds
    except paramiko.SSHException as e:
        # Server accepted creds but demands a password change -> still valid creds.
        if "change" in str(e).lower() and "password" in str(e).lower():
            return creds
        return None
    except Exception:
        return None
    finally:
        try:
            ssh.close()
        except Exception:
            pass


def cred_to_str(cred: SSHCreds) -> str:
    """Human-readable representation of found credentials (password or key)."""
    if cred.privkey:
        if cred.privkey.passphrase is not None:
            return f"user: {cred.user}, keypath: {cred.privkey.keypath}, passphrase: {cred.privkey.passphrase}"
        return f"user: {cred.user}, keypath: {cred.privkey.keypath}"
    return f"user: {cred.user}, password: {cred.passw}"