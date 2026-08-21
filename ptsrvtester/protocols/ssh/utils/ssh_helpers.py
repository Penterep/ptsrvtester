"""Network / analysis helpers shared by the SSH modules.

Pure functions (no ``self``) lifted from the old flat ``protocols/ssh.py`` so the
per-test ``modules/*.py`` can reuse them. Imports are absolute on purpose: the
modules are loaded dynamically by ``BaseMain`` with no package parent.
"""
import logging
import socket

import paramiko
import paramiko.ssh_exception
from paramiko.message import Message

from ptsrvtester.protocols.ssh.utils.helpers import filepaths, text_or_file
from ptsrvtester.protocols.ssh.utils.results import (
    BadPubkeyResult,
    PrivKeyDetails,
    SSHCreds,
)

BANNER_TIMEOUT = 10.0


class _LegacyDSSKey(paramiko.PKey):
    """Minimal ``ssh-dss`` (DSA/SHA-1) *host* key for verifying legacy servers.

    paramiko 4/5 deleted its ``DSSKey`` class outright, so it can no longer talk
    to servers whose only host key is ``ssh-dss``. We only ever act as an SSH
    *client* verifying the server's host key, so this re-implements just the two
    things paramiko's ``Transport._verify_key`` needs — parse the public key
    blob and verify the exchange-hash signature — on top of ``cryptography``
    (which still supports DSA). Signing is intentionally not implemented.
    """

    name = "ssh-dss"

    def __init__(self, msg=None, data=None):
        if msg is None and data is not None:
            msg = Message(data)
        if msg is None:
            raise paramiko.SSHException("ssh-dss key blob is missing")
        # Blob layout: string "ssh-dss", then mpints p, q, g, y.
        if msg.get_text() != "ssh-dss":
            raise paramiko.SSHException("not an ssh-dss key")
        self.p = msg.get_mpint()
        self.q = msg.get_mpint()
        self.g = msg.get_mpint()
        self.y = msg.get_mpint()

    def asbytes(self) -> bytes:
        m = Message()
        m.add_string("ssh-dss")
        m.add_mpint(self.p)
        m.add_mpint(self.q)
        m.add_mpint(self.g)
        m.add_mpint(self.y)
        return m.asbytes()

    def get_name(self) -> str:
        return "ssh-dss"

    @classmethod
    def identifiers(cls):
        return ["ssh-dss"]

    def get_bits(self) -> int:
        return self.p.bit_length()

    def verify_ssh_sig(self, data, msg) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature,
        )

        # Signature is either the bare 40-byte r||s or the SSH-wrapped
        # (string "ssh-dss", string <40 bytes>) form; accept both.
        raw = msg.asbytes()
        if len(raw) == 40:
            sig = raw
        else:
            if msg.get_text() != "ssh-dss":
                return False
            sig = msg.get_binary()
        if len(sig) != 40:
            return False

        r = int.from_bytes(sig[:20], "big")
        s = int.from_bytes(sig[20:], "big")
        public_key = dsa.DSAPublicNumbers(
            y=self.y,
            parameter_numbers=dsa.DSAParameterNumbers(p=self.p, q=self.q, g=self.g),
        ).public_key()
        try:
            public_key.verify(encode_dss_signature(r, s), data, hashes.SHA1())
            return True
        except InvalidSignature:
            return False


def _silence_paramiko_logging() -> None:
    """Stop paramiko dumping negotiation tracebacks to stderr.

    On a failed key exchange paramiko logs the exception (and its traceback) at
    ERROR level from its own transport thread. With no handler attached to the
    ``paramiko`` logger, Python's last-resort handler prints those records to
    stderr — that is the double ``Exception (client): Incompatible ssh peer``
    traceback. We render our own per-module errors, so a NullHandler keeps
    paramiko's internal noise out of the report.
    """
    logging.getLogger("paramiko").addHandler(logging.NullHandler())


def _enable_legacy_host_keys() -> None:
    """Re-enable the legacy ``ssh-rsa`` and ``ssh-dss`` host-key algorithms.

    paramiko 4/5 dropped ``ssh-rsa`` (SHA-1) and ``ssh-dss`` from its default
    host-key tables (``Transport._preferred_keys`` / ``Transport._key_info``),
    so it refuses old servers that only offer them with
    ``IncompatiblePeer: no acceptable host key``. ``RSAKey`` still understands
    the ``ssh-rsa`` wire format, and :class:`_LegacyDSSKey` reimplements
    ``ssh-dss`` verification on ``cryptography``, so we register both again as
    the *least*-preferred host keys — modern algorithms are still chosen first,
    but legacy SSH servers can be audited again.
    """
    transport = paramiko.Transport
    legacy = {"ssh-rsa": paramiko.RSAKey, "ssh-dss": _LegacyDSSKey}

    key_info = dict(transport._key_info)
    key_info.update({name: cls for name, cls in legacy.items() if name not in key_info})
    transport._key_info = key_info

    added = tuple(name for name in legacy if name not in transport._preferred_keys)
    transport._preferred_keys = tuple(transport._preferred_keys) + added


_silence_paramiko_logging()
_enable_legacy_host_keys()


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


def check_bad_pubkey(pubkeys_path: str, host_key: str) -> BadPubkeyResult:
    """Compare the server's host key against a directory of known (bad) ``*.pub`` keys."""
    for pubkey_path in filepaths(pubkeys_path, ".pub"):
        with open(pubkey_path, "r") as f:
            line = f.read().strip()
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