from __future__ import annotations

import os, ipaddress, socket, argparse
from dataclasses import dataclass
from typing import Callable, Literal
from base64 import b64decode, b64encode
import re

from ptlibs.threads import ptthreads

from ..._base import BaseArgs

# Probable mailbox names for AUTH user-enum when the operator does not pass -u/-U (SMTP -ae, etc.).
default_logins: tuple[str, ...] = (
    "admin",
    "administrator",
    "root",
    "postmaster",
    "webmaster",
    "support",
)

# Synthetic non-existent identities used as invalid baseline alongside candidate names (-ae).
AUTH_ENUM_SYNTHETIC_INVALID_COUNT = 2


def auth_enum_candidate_names(
    args: ArgsWithBruteforce,
    *,
    wordlist: list[str] | None = None,
) -> tuple[list[str], bool]:
    """
    Resolve AUTH enumeration candidate logins.

    Returns ``(names, used_default_logins)``. With ``-u`` or a populated *wordlist*
    (from ``-U``), only those names are used; otherwise ``default_logins``.
    """
    if args.user:
        names = [x.strip() for x in text_or_file(args.user, None) if x.strip()]
        return names, False
    wl = wordlist or []
    if wl:
        return [u.strip() for u in wl if u.strip()], False
    return list(default_logins), True


def auth_enum_ntlm_identity_note(
    used_default_logins: bool,
    candidates: list[str] | tuple[str, ...],
) -> str | None:
    """
    Operator hint for SMTP AUTH NTLM enumeration when identity shape may skew results.

    Shown when built-in ``default_logins`` are used, or when ``-u``/``-U`` names lack
    ``\\`` (NetBIOS) and ``@`` (UPN).
    """
    if used_default_logins:
        return (
            "Note: NTLM is tested with built-in default names (admin, root, …). "
            "For reliable results on Windows/AD, pass -u or -U using DOMAIN\\user (legacy) "
            "or user@domain (UPN)."
        )
    if candidates and not any("\\" in name or "@" in name for name in candidates):
        return (
            "Note: NTLM identity format may affect results; "
            "consider DOMAIN\\user or user@domain in -u/-U."
        )
    return None


def vendor_from_cpe(cpe: str | None) -> str | None:
    """Extract vendor from CPE 2.3 string (e.g. cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:* -> microsoft)."""
    if not cpe or ":" not in cpe:
        return None
    parts = cpe.split(":")
    if len(parts) >= 4 and parts[2] in ("a", "o", "h"):
        return parts[3] or None
    return None


@dataclass(frozen=True)
class Creds:
    user: str
    passw: str


@dataclass
class Target:
    ip: str
    port: int


class ArgsWithBruteforce(BaseArgs):
    user: str | list[str] | None
    users: str | None  # renamed from users_file
    password: str | None  # renamed from passw
    passwords: str | None  # renamed from passw_file
    spray: bool
    threads: int


def add_bruteforce_args(
    parser: argparse.ArgumentParser,
    *,
    user_nargs: str | None = None,
    user_help: str | None = None,
    mutually_exclusive_user_and_users: bool = True,
):
    """
    Adds bruteforce arguments to ArgumentParser
    - username or file with usernames
    - password or file with passwords
    - spray option
    - number of threads

    Args:
        parser (argparse.ArgumentParser)
        user_nargs: if "+", -u accepts one or more usernames (list); else single string.
        user_help: override help for -u (default: "username" or "username(s)" when user_nargs="+").
        mutually_exclusive_user_and_users: if False, -u and -U may both be set (e.g. SMTP -e + file).
    """
    bruteforce = parser.add_argument_group(
        "LOGIN / BRUTEFORCE",
        "user/users + password/passwords",
    )

    _u_help = user_help or (
        "username(s); with -e, merged with lines from -U (optional username file)"
        if user_nargs == "+"
        else "username"
    )
    _users_help = (
        "file with usernames (bruteforce with -p/-P; also name list for -e, -ae, -rl)"
        if not mutually_exclusive_user_and_users
        else "file containing usernames"
    )

    if mutually_exclusive_user_and_users:
        bruteuser = bruteforce.add_mutually_exclusive_group()
        bruteuser.title = "bruteuser"
        if user_nargs == "+":
            bruteuser.add_argument(
                "-u",
                "--user",
                nargs="+",
                metavar="NAME",
                help=_u_help,
            )
        else:
            bruteuser.add_argument("-u", "--user", type=str, help=_u_help)
        bruteuser.add_argument("-U", "--users", type=str, help=_users_help)
    else:
        if user_nargs == "+":
            bruteforce.add_argument(
                "-u",
                "--user",
                nargs="+",
                metavar="NAME",
                help=_u_help,
            )
        else:
            bruteforce.add_argument("-u", "--user", type=str, help=_u_help)
        bruteforce.add_argument("-U", "--users", type=str, help=_users_help)

    # password / passwords file
    brutepass = bruteforce.add_mutually_exclusive_group()
    brutepass.title = "brutepass"
    brutepass.add_argument("-p", "--password", type=str, help="password")
    brutepass.add_argument("-P", "--passwords", type=str, help="file containing passwords")

    # other configuration
    bruteforce.add_argument(
        "--spray",
        action="store_true",
        help="try 1 password/key for all users (instead of trying all passwords/keys for 1 user)",
    )
    bruteforce.add_argument(
        "--brute-threads",
        type=int,
        default=10,
        nargs="?",
        dest="threads",
        help="number of threads for bruteforce (default: 10)",
    )


def check_if_brute(args: ArgsWithBruteforce) -> bool:
    """
    Decides whether to perfrom bruteforce operations
    based on the module arguments

    Args:
        args (ArgsWithBruteforce): module arguments

    Returns:
        bool: whether to perform bruteforce
    """
    if (args.user or args.users) and (args.password or args.passwords):
        return True
    else:
        return False


def threaded_bruteforce(
    creds: list,
    try_login: Callable,
    threads: int,
    on_success: Callable | None = None,
) -> set:
    """
    Generic bruteforce with custom creds list and on_success callback.
    Used by modules (e.g. SSH) that need custom credential types (SSHCreds).

    Args:
        creds: list of credentials to try
        try_login: function(cred) -> cred or None
        threads: number of threads
        on_success: optional callback(cred) when login succeeds

    Returns:
        set of successfully logged-in credentials
    """
    def _wrapped(c):
        r = try_login(c)
        if r is not None and on_success is not None:
            on_success(r)
        return r

    pt = ptthreads.PtThreads(True)
    result = pt.threads(creds, _wrapped, threads)
    found = set(result)
    found.discard(None)
    return found


def simple_bruteforce(
    try_login: Callable[[Creds], Creds | None],
    user: str | None,
    userf: str | None,
    passw: str | None,
    passwf: str | None,
    spray: bool,
    threads: int,
    on_success: Callable[[Creds], None] | None = None,
) -> set[Creds]:
    """
    Performs a login bruteforce attack using an arbitrary login functino.
    Also decides chooses the appropriate values from the provided arguments.

    Args:
        try_login (Callable[[Creds], Creds  |  None]): login function
        user (str | None): username argument
        userf (str | None): users file argument
        passw (str | None): password argument
        passwf (str | None): passwords file argument
        spray (bool): spray argument
        threads (int): threads argument
        on_success (Callable[[Creds], None] | None): optional callback for real-time
            streaming when a credential is found (called from worker thread)

    Returns:
        set[Creds]: a set of valid login credentials
    """
    users = text_or_file(user, userf)
    passwords = text_or_file(passw, passwf)

    if spray:
        creds = [Creds(u, p) for p in passwords for u in users]
    else:
        creds = [Creds(u, p) for u in users for p in passwords]

    def _wrapped_try(cred: Creds) -> Creds | None:
        result = try_login(cred)
        if result is not None and on_success is not None:
            on_success(result)
        return result

    # TODO maybe custom without ptthreads because of missing stop-on-success functionality
    pt_threads = ptthreads.PtThreads(True)
    result = pt_threads.threads(creds, _wrapped_try, threads)
    found_creds: set[Creds] = set(result)

    found_creds.discard(None)

    return found_creds


def valid_target(target: str, port_required: bool = False, domain_allowed: bool = False) -> Target:
    """
    Decides whether the target argument is a valid IP address or hostname
    with optional valid port definition. Designed for automatic usage by argparse.

    Args:
        target (str): target argument
        port_required (bool, optional): whether to require port definition. Defaults to False.
        domain_allowed (bool, optional): whether to allow hostnames. Defaults to False.

    Raises:
        argparse.ArgumentError: invalid format
        argparse.ArgumentError: missing port number
        argparse.ArgumentError: invalid ip address
        argparse.ArgumentError: unresolvable hostname
        argparse.ArgumentError: invalid port number

    Returns:
        Target: parsed Target
    """
    split = target.split(":")
    if not port_required and len(split) > 2:
        raise argparse.ArgumentError(None, "The target has to be IP[:PORT]")

    if port_required and len(split) != 2:
        raise argparse.ArgumentError(None, "The target has to be IP:PORT")

    try:
        ipaddress.ip_address(split[0])
    except:
        if domain_allowed:
            try:
                socket.gethostbyname(split[0])
            except Exception:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve target name '{split[0]}' into IP address"
                )
        else:
            raise argparse.ArgumentError(None, "Invalid target IP address")

    if len(split) > 1:
        try:
            port = int(split[1])
            if port <= 0 or port >= 65536:
                raise ValueError
        except:
            raise argparse.ArgumentError(None, "Invalid PORT number")
    else:
        port = 0

    return Target(split[0], port)


def get_mode(args: argparse.Namespace) -> str:
    """Decides what TLS mode is implied by the module arguments

    Args:
        args (argparse.Namespace): module arguments

    Returns:
        str: TLS / STARTTLS / PLAIN
    """
    if args.tls:
        return "TLS"
    elif args.starttls:
        return "STARTTLS"
    else:
        return "PLAIN"


def one_cli_user(user: str | list[str] | None) -> str | None:
    """Single ``-u`` name, or ``None`` when ``-u`` has zero or several names."""
    names = [x.strip() for x in text_or_file(user, None) if str(x).strip()]
    return names[0] if len(names) == 1 else None


_ENUM_ALL_METHODS = frozenset({"EXPN", "VRFY", "RCPT"})


def enum_methods_from_arg(value) -> set[str]:
    """Methods selected by ``-e``. Missing value and ``ALL`` mean VRFY, EXPN and RCPT."""
    if value is None:
        return set(_ENUM_ALL_METHODS)
    if isinstance(value, (list, tuple, set)):
        methods = {str(item).strip().upper() for item in value if str(item).strip()}
    else:
        text = str(value).strip().upper()
        methods = {text} if text else set()
    if not methods or "ALL" in methods:
        return set(_ENUM_ALL_METHODS)
    return methods


def text_or_file(text: str | list[str] | None, filepath: str | None) -> list[str]:
    """Returns either `text` or `filepath` contents while prefering `text`

    Args:
        text (str | list[str] | None): single value or list (e.g. SMTP -u with nargs+)
        filepath (str | None): file with values

    Returns:
        list[str]: list of picked value(s)
    """
    result = []
    if text is not None:
        if isinstance(text, list):
            result = [str(t).strip() for t in text if t is not None and str(t).strip()]
        else:
            result = [text]
    elif filepath is not None:
        _encodings = ("utf-8", "cp1250", "iso-8859-2", "cp1252", "latin-1")
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
        except FileNotFoundError:
            raise argparse.ArgumentError(None, f"File not found: '{filepath}'")
        except PermissionError:
            raise argparse.ArgumentError(None, f"Cannot read file (permission denied): '{filepath}'")
        except OSError as e:
            raise argparse.ArgumentError(None, f"Cannot read file '{filepath}': {e}")
        for enc in _encodings:
            try:
                result = raw.decode(enc).splitlines()
                break
            except UnicodeDecodeError:
                continue
        else:
            result = raw.decode("utf-8", errors="replace").splitlines()

    return result


def filepaths(directory: str, ext: str) -> list[str]:
    """
    Finds files of given extension in a given directory
    and returns their paths

    Args:
        directory (str): search directory
        ext (str): search file extension

    Returns:
        list[str]: list of file paths
    """
    files: list[str] = []
    for f in os.listdir(directory):
        fullpath = os.path.join(directory, f)
        if os.path.isfile(fullpath) and f.endswith(ext):
            files.append(fullpath)

    return files


def text(data: bytes) -> str | None:
    """
    Attempts to decode bytes as a string

    Args:
        data (bytes): bytes to decode

    Returns:
        str | None: decoded string or None
    """
    try:
        return data.decode()
    except:
        return None


# SMTP-specific helpers (formerly protocols/smtp/helpers.py)

_vendor_from_cpe = vendor_from_cpe


def _registrable_domain_psl(host: str) -> str | None:
    """Get registrable domain from hostname using Public Suffix List (e.g. relay01.prod.amazon.co.jp -> amazon.co.jp).
    Returns None on failure or if ptlibs.tldparser is unavailable.
    """
    host = (host or "").strip()
    if not host or "." not in host:
        return None
    try:
        from ptlibs.tldparser import parse
        r = parse(host)
        if r is None:
            return None
        domain = getattr(r, "domain", None)
        suffix = getattr(r, "suffix", None)
        if domain and suffix:
            return f"{domain}.{suffix}"
        # Unknown suffix (private names such as .home): the parser's domain
        # field is only the last label. Callers keep the original hostname.
        return None
    except Exception:
        return None


class TestFailedError(Exception):
    """Raised when a test fails in run-all mode; caught to continue with next test."""


def _is_private_ip(ip: str) -> bool:
    """True if ip is a private (RFC 1918 / ULA) address. Blacklist services only check public IPs."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def valid_target_smtp(target: str) -> Target:
    return valid_target(target, domain_allowed=True)


def _is_valid_hostname(host: str) -> bool:
    """True if host looks like a valid FQDN (contains dot, not just IP or generic label)."""
    if not host or not isinstance(host, str):
        return False
    host = host.strip()
    if "." not in host or len(host) < 4:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    parts = host.split(".")
    return len(parts) >= 2


SMTP_KNOWN_EXTENSIONS = frozenset(
    {
        "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT",
        "VRFY", "EXPN", "HELP", "SEND", "SOML", "SAML", "TURN", "ETRN", "ATRN",
        "8BITMIME", "SIZE", "CHUNKING", "BINARYMIME", "CHECKPOINT", "DELIVERBY",
        "PIPELINING", "DSN", "AUTH", "BURL", "SMTPUTF8", "STARTTLS", "ENHANCEDSTATUSCODES",
        "VERB", "DEBUG",
    }
)
SMTP_AUTH_METHOD_LEVEL_PLAIN = {
    "PLAIN": "ERROR", "LOGIN": "ERROR", "CRAM-MD5": "ERROR", "DIGEST-MD5": "ERROR",
    "NTLM": "ERROR", "ANONYMOUS": "ERROR", "KERBEROS_V4": "ERROR", "GSSAPI": "ERROR",
    "EXTERNAL": "WARNING",
    "XOAUTH2": "OK", "OAUTHBEARER": "OK", "SCRAM-SHA-1": "OK", "SCRAM-SHA-256": "OK",
}
SMTP_CMD_ERROR = frozenset({"VRFY", "EXPN", "TURN", "VERB", "SEND", "SOML", "SAML", "DEBUG"})
SMTP_CMD_WARNING = frozenset({"ETRN", "ATRN"})
SIZE_OK_MAX = 26214400
SIZE_WARNING_MAX = 52428800


_SIZE_TOKEN_RE = re.compile(r"(?:^|\s)SIZE(?:\s+(\d+))?(?=\s|$)", re.IGNORECASE)


def _size_offer_from_ehlo(ehlo_raw: str | bytes | None) -> tuple[bool, int | None]:
    """Return ``(keyword_present, fixed_maximum)`` from an EHLO reply (RFC 1870).

    ``fixed_maximum`` is the decimal parameter when one was given, including 0
    (0 means no fixed maximum). It is ``None`` when the keyword is absent or
    has no parameter. ``smtp.ehlo()`` strips the ``250`` / ``250-`` prefix;
    a raw transcript may still contain it. A single-line EHLO is scanned too.
    """
    if ehlo_raw is None:
        return False, None
    if isinstance(ehlo_raw, bytes):
        ehlo_raw = ehlo_raw.decode(errors="replace")
    if not isinstance(ehlo_raw, str) or not ehlo_raw.strip():
        return False, None
    present = False
    limit: int | None = None
    for line in ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip()
        upper = line.upper()
        if upper.startswith("250-"):
            line = line[4:].strip()
        elif upper.startswith("250 "):
            line = line[3:].strip()
        for match in _SIZE_TOKEN_RE.finditer(line):
            present = True
            if match.group(1) is not None:
                limit = int(match.group(1))
    return present, limit


def _parse_size_from_ehlo(ehlo_raw: str | bytes | None) -> int | None:
    """Parse EHLO for SIZE extension (RFC 1870).

    Returns the advertised fixed maximum in bytes, ``0`` when the parameter is
    zero, or ``None`` when SIZE is absent or has no number.
    """
    _present, limit = _size_offer_from_ehlo(ehlo_raw)
    return limit


def _parse_rcptmax_from_ehlo(ehlo_raw: str) -> int | None:
    """Parse EHLO for LIMITS RCPTMAX=N (RFC 9422). Returns N or None."""
    if not ehlo_raw or not ehlo_raw.strip():
        return None
    for line in ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip().upper()
        if "LIMITS" not in line:
            continue
        match = re.search(r"RCPTMAX\s*=\s*(\d+)", line, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _parse_ehlo_extension_names(ehlo_raw: str | bytes | None) -> list[str]:
    """Parse EHLO response and return list of ESMTP extension display strings."""
    if ehlo_raw is None:
        return []
    if isinstance(ehlo_raw, bytes):
        ehlo_raw = ehlo_raw.decode(errors="replace")
    if not isinstance(ehlo_raw, str) or not ehlo_raw.strip():
        return []
    lines = ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    extensions: list[str] = []
    first_line = True
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("250-"):
            rest = line[4:].strip()
        elif line.startswith("250 "):
            rest = line[3:].strip()
        else:
            continue
        rest = rest.replace("\r", " ").strip()
        if not rest:
            continue
        parts = rest.split(None, 1)
        key = (parts[0] or "").upper().strip()
        if key == "OK":
            continue
        if "." in key and key not in SMTP_KNOWN_EXTENSIONS:
            continue
        if key not in SMTP_KNOWN_EXTENSIONS and "." not in key:
            if first_line:
                first_line = False
                continue
        extensions.append(rest)
        first_line = False
    return extensions


def _parse_ehlo_commands(ehlo_raw: str, connection_encrypted: bool = False) -> list[tuple[str, str]]:
    """Parse EHLO response into list of (display_string, level) for output."""
    if not ehlo_raw or not ehlo_raw.strip():
        return []
    lines = ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    result: list[tuple[str, str]] = []
    seen_starttls = False
    first_line = True

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("250-"):
            rest = line[4:].strip()
        elif line.startswith("250 "):
            rest = line[3:].strip()
        else:
            rest = line.strip()
        if not rest:
            continue
        rest = rest.replace("\r", " ").strip()
        if not rest:
            continue
        parts = rest.split(None, 1)
        key = (parts[0] or "").upper().strip()
        value = (parts[1] or "").strip() if len(parts) > 1 else ""

        if key == "OK":
            continue

        if "." in key and key not in SMTP_KNOWN_EXTENSIONS:
            continue
        if key not in SMTP_KNOWN_EXTENSIONS and "." not in key:
            if first_line:
                first_line = False
                continue
            result.append((rest, "OK"))
            if key == "STARTTLS":
                seen_starttls = True
            continue

        if key == "STARTTLS":
            seen_starttls = True

        if key == "AUTH":
            methods = value.split() if value else []
            for method in methods:
                method_upper = method.upper()
                level = "OK" if connection_encrypted else SMTP_AUTH_METHOD_LEVEL_PLAIN.get(method_upper, "OK")
                result.append((f"AUTH {method_upper}", level))
            continue

        if key == "SIZE":
            try:
                size_val = int(value) if value else 0
                if size_val <= SIZE_OK_MAX:
                    level = "OK"
                elif size_val <= SIZE_WARNING_MAX:
                    level = "WARNING"
                else:
                    level = "ERROR"
            except (ValueError, TypeError):
                level = "OK"
            result.append((f"SIZE {value}".strip() or "SIZE", level))
            continue

        if key in SMTP_CMD_ERROR:
            level = "ERROR"
        elif key in SMTP_CMD_WARNING:
            level = "WARNING"
        else:
            level = "OK"
        display = f"{key} {value}".strip() if value else key
        result.append((display, level))

    if not seen_starttls and not connection_encrypted:
        result.append(("STARTTLS (is not allowed)", "ERROR"))

    return result


def _normalize_auth_response_for_comparison(response: str) -> str:
    """Normalize SMTP auth response for enumeration comparison."""
    if not response:
        return ""
    normalized = " ".join(response.split())
    normalized = re.sub(r"\s+[a-zA-Z0-9.-]{15,}\s+-\s+[a-zA-Z0-9.]+$", "", normalized)
    return normalized.strip()


def _auth_enum_plain_initial_b64(user: str, password: str) -> str:
    """RFC 4616 PLAIN SASL message, then base64 (ASCII)."""
    authcid = (user or "").encode("utf-8")
    passwd = (password or "").encode("utf-8")
    blob = b"\x00" + authcid + b"\x00" + passwd
    return b64encode(blob).decode("ascii")


def _auth_enum_login_stage_signature(
    stage: Literal["u", "p"],
    code: int,
    resp: bytes,
    bytes_to_str: Callable[[bytes], str],
) -> str:
    """Comparison token for AUTH LOGIN enumeration."""
    txt = bytes_to_str(resp).strip()
    line = f"{code} {txt}" if txt else str(code)
    return f"LOGIN:{stage}:{_normalize_auth_response_for_comparison(line)}"


def _get_auth_methods_from_ehlo(ehlo_raw: str | None) -> set[str]:
    """Extract AUTH method names (LOGIN, NTLM, etc.) from EHLO response."""
    if not ehlo_raw:
        return set()
    methods: set[str] = set()
    for line in ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        rest = line[4:].strip() if line.startswith("250-") else (line[3:].strip() if line.startswith("250 ") else line)
        parts = rest.split(None, 1)
        key = (parts[0] or "").upper()
        if key == "AUTH" and len(parts) > 1:
            for m in parts[1].split():
                methods.add(m.upper())
    return methods


def _get_ehlo_extension_keys(ehlo_raw: str | None) -> list[str]:
    """Extract extension keys from EHLO response. Skips hostname line."""
    if not ehlo_raw:
        return []
    keys: list[str] = []
    first_line = True
    for line in ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        rest = line[4:].strip() if line.startswith("250-") else (line[3:].strip() if line.startswith("250 ") else line)
        parts = rest.split(None, 1)
        key = (parts[0] or "").upper()
        if not key or key == "OK":
            continue
        if first_line and "." in key and key not in SMTP_KNOWN_EXTENSIONS:
            first_line = False
            continue
        first_line = False
        keys.append(key)
    return keys


def _get_hostname_from_ehlo_raw(ehlo_raw: str | None) -> str | None:
    """Extract server hostname from first line of EHLO response."""
    if not ehlo_raw:
        return None
    for line in ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        rest = line[4:].strip() if line.startswith("250-") else (line[3:].strip() if line.startswith("250 ") else line)
        parts = rest.split(None, 1)
        first = (parts[0] or "").strip()
        if first and "." in first and _is_valid_hostname(first):
            return first.lower()
    return None


def _auth_format_decode_login_challenge(resp: bytes | None) -> str | None:
    """Decode first base64 token in SMTP 334 body (typically 'Username:')."""
    if not resp:
        return None
    raw = resp.strip().split()
    if not raw:
        return None
    try:
        return b64decode(raw[0]).decode(errors="replace")
    except Exception:
        return None


def _auth_format_hint_from_challenge_text(text: str | None) -> str | None:
    if not text:
        return None
    low = text.lower()
    if "email" in low or "@" in low:
        return "full email address"
    if "domain\\" in low or "domain/" in low:
        return "NetBIOS format"
    if "username" in low or "login" in low or "user name" in low:
        return "username (ambiguous)"
    return None


# Mixins use `from .helpers import *`; include underscored SMTP helpers (star-import skips `_` names otherwise).
__all__ = [n for n in globals() if not n.startswith("__")]
