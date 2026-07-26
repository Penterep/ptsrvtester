import ipaddress, re
from base64 import b64decode, b64encode
from typing import Callable, Literal


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..utils.helpers import Target, valid_target

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False



__all__ = ['_vendor_from_cpe', '_registrable_domain_psl', 'TestFailedError', '_is_private_ip', 'valid_target_smtp', '_is_valid_hostname', 'SMTP_KNOWN_EXTENSIONS', 'SMTP_AUTH_METHOD_LEVEL_PLAIN', 'SMTP_CMD_ERROR', 'SMTP_CMD_WARNING', 'SIZE_OK_MAX', 'SIZE_WARNING_MAX', '_parse_size_from_ehlo', '_parse_rcptmax_from_ehlo', '_parse_ehlo_extension_names', '_parse_ehlo_commands', '_normalize_auth_response_for_comparison', '_auth_enum_plain_initial_b64', '_auth_enum_login_stage_signature', '_get_auth_methods_from_ehlo', '_get_ehlo_extension_keys', '_get_hostname_from_ehlo_raw', '_auth_format_decode_login_challenge', '_auth_format_hint_from_challenge_text']


def _vendor_from_cpe(cpe: str | None) -> str | None:
    """Extract vendor from CPE 2.3 string (e.g. cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:* -> microsoft)."""
    if not cpe or ":" not in cpe:
        return None
    parts = cpe.split(":")
    if len(parts) >= 4 and parts[2] in ("a", "o", "h"):
        return parts[3] or None
    return None


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
        if domain:
            return domain
        return None
    except Exception:
        return None


# region helper methods


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


# SMTP EHLO: known extensions and security classification for output
SMTP_KNOWN_EXTENSIONS = frozenset(
    {
        "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT",
        "VRFY", "EXPN", "HELP", "SEND", "SOML", "SAML", "TURN", "ETRN", "ATRN",
        "8BITMIME", "SIZE", "CHUNKING", "BINARYMIME", "CHECKPOINT", "DELIVERBY",
        "PIPELINING", "DSN", "AUTH", "BURL", "SMTPUTF8", "STARTTLS", "ENHANCEDSTATUSCODES",
        "VERB", "DEBUG",
    }
)
# AUTH method -> OK / WARNING / ERROR when on PLAIN (cleartext). Over TLS/STARTTLS all are OK.
SMTP_AUTH_METHOD_LEVEL_PLAIN = {
    "PLAIN": "ERROR", "LOGIN": "ERROR", "CRAM-MD5": "ERROR", "DIGEST-MD5": "ERROR",
    "NTLM": "ERROR", "ANONYMOUS": "ERROR", "KERBEROS_V4": "ERROR", "GSSAPI": "ERROR",
    "EXTERNAL": "WARNING",
    "XOAUTH2": "OK", "OAUTHBEARER": "OK", "SCRAM-SHA-1": "OK", "SCRAM-SHA-256": "OK",
}
SMTP_CMD_ERROR = frozenset({"VRFY", "EXPN", "TURN", "VERB", "SEND", "SOML", "SAML", "DEBUG"})
SMTP_CMD_WARNING = frozenset({"ETRN", "ATRN"})
SIZE_OK_MAX = 26214400       # 25 MB
SIZE_WARNING_MAX = 52428800  # 50 MB


def _parse_size_from_ehlo(ehlo_raw: str | bytes | None) -> int | None:
    """Parse EHLO for SIZE extension (RFC 1870). Returns max message size in bytes or None."""
    if ehlo_raw is None:
        return None
    if isinstance(ehlo_raw, bytes):
        ehlo_raw = ehlo_raw.decode(errors="replace")
    if not isinstance(ehlo_raw, str) or not ehlo_raw.strip():
        return None
    for line in ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip().upper()
        if not (line.startswith("250-") or line.startswith("250 ")):
            continue
        rest = line[4:].strip() if line.startswith("250-") else line[3:].strip()
        if not rest.upper().startswith("SIZE"):
            continue
        parts = rest.split(None, 1)
        if len(parts) < 2:
            return None
        try:
            return int(parts[1])
        except (ValueError, TypeError):
            return None
    return None


def _parse_rcptmax_from_ehlo(ehlo_raw: str) -> int | None:
    """Parse EHLO for LIMITS RCPTMAX=N (RFC 9422). Returns N or None."""
    if not ehlo_raw or not ehlo_raw.strip():
        return None
    for line in ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip().upper()
        if "LIMITS" not in line:
            continue
        # e.g. "250-LIMITS MAILMAX=100 RCPTMAX=512" or "250 LIMITS RCPTMAX=20"
        match = re.search(r"RCPTMAX\s*=\s*(\d+)", line, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _parse_ehlo_extension_names(ehlo_raw: str | bytes | None) -> list[str]:
    """
    Parse EHLO response and return list of ESMTP extension display strings (e.g. "SIZE 52428800", "PIPELINING").
    Skips hostname line (first line). Used by HELO-only test to detect if server offers any extensions.
    Always returns a list (never None). Accepts str, bytes, or None.
    """
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
        # Hostname line: key has dot and is not a known extension
        if "." in key and key not in SMTP_KNOWN_EXTENSIONS:
            continue
        # First unknown (no dot) may be hostname; skip once
        if key not in SMTP_KNOWN_EXTENSIONS and "." not in key:
            if first_line:
                first_line = False
                continue
        extensions.append(rest)  # Full display string (e.g. "SIZE 52428800", "PIPELINING")
        first_line = False
    return extensions


def _parse_ehlo_commands(ehlo_raw: str, connection_encrypted: bool = False) -> list[tuple[str, str]]:
    """
    Parse EHLO response into list of (display_string, level) for output.
    Level is OK, WARNING, or ERROR. Hostname line (first line) is skipped.
    Expands AUTH CRAM-MD5 DIGEST-MD5 into separate AUTH CRAM-MD5, AUTH DIGEST-MD5.
    Handles both raw SMTP (250-...) and smtplib-style (no prefix) response.
    When connection_encrypted is True (TLS or STARTTLS), "STARTTLS (is not allowed)" is not
    added, since it is expected and OK on an already-encrypted connection.
    """
    if not ehlo_raw or not ehlo_raw.strip():
        return []
    lines = ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    result: list[tuple[str, str]] = []
    seen_starttls = False
    first_line = True  # RFC: first EHLO line is always server hostname, not an extension

    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Strip SMTP code if present: "250-..." or "250 ..."; else use whole line (smtplib often strips code)
        if line.startswith("250-"):
            rest = line[4:].strip()
        elif line.startswith("250 "):
            rest = line[3:].strip()
        else:
            rest = line.strip()
        if not rest:
            continue
        # Normalize \r so key/value match (SMTP uses \r\n; smtplib may leave \r on lines)
        rest = rest.replace("\r", " ").strip()
        if not rest:
            continue
        # First token is key, rest is value (e.g. "SIZE 29360128", "AUTH CRAM-MD5 DIGEST-MD5")
        parts = rest.split(None, 1)
        key = (parts[0] or "").upper().strip()
        value = (parts[1] or "").strip() if len(parts) > 1 else ""

        # Skip generic 250 completion (e.g. "250 Ok" / "250 OK") – not an extension
        if key == "OK":
            continue

        # Hostname line (key has dot, not a known extension): skip, not a command
        if "." in key and key not in SMTP_KNOWN_EXTENSIONS:
            continue
        # Unknown extension (no dot): show as OK, except first such line is usually hostname (RFC) – skip once
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
                # Over TLS/STARTTLS, AUTH PLAIN/LOGIN etc. are OK (RFC 8314). On plain they are ERROR.
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
    """
    Normalize SMTP auth response for enumeration comparison.
    Strips session-specific parts (e.g. Gmail session IDs, hostname suffixes)
    to avoid false positives when the semantic message is identical.
    """
    if not response:
        return ""
    # Collapse whitespace
    normalized = " ".join(response.split())
    # Remove trailing " <session_id> - <hostname>" (e.g. Gmail " a92af...c88.0 - gsmtp")
    # Require session_id to be 15+ chars to avoid stripping real message text (e.g. "failed")
    normalized = re.sub(r"\s+[a-zA-Z0-9.-]{15,}\s+-\s+[a-zA-Z0-9.]+$", "", normalized)
    return normalized.strip()


def _auth_enum_plain_initial_b64(user: str, password: str) -> str:
    """
    RFC 4616 PLAIN SASL message: [authzid UTF8NUL] authcid UTF8NUL passwd, then base64 (ASCII).
    Empty authzid → message starts with NUL (authcid-only form).
    """
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
    """
    Comparison token for AUTH LOGIN enumeration. ``u`` = 5xx immediately after username;
    ``p`` = 5xx after password step. Some MTAs return the same SMTP text (e.g. 535 5.7.0)
    in both cases for invalid vs valid user; phase still differs and is a user oracle.
    """
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
    """Extract extension keys (VRFY, EXPN, AUTH, etc.) from EHLO response for comparison. Skips hostname line."""
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
        # First line is usually server hostname (has dot)
        if first_line and "." in key and key not in SMTP_KNOWN_EXTENSIONS:
            first_line = False
            continue
        first_line = False
        keys.append(key)
    return keys


def _get_hostname_from_ehlo_raw(ehlo_raw: str | None) -> str | None:
    """Extract server hostname from first line of EHLO response (250 hostname or 250-hostname).
    Returns lowercase (RFC: domain names are case-insensitive in DNS)."""
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


# endregion
