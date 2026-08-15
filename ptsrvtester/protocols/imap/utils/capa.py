"""IMAP CAPABILITY helpers and argparse target helper."""
from __future__ import annotations

import re

from .helpers import Target, valid_target

def valid_target_imap(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port (like SMTP)."""
    return valid_target(target, domain_allowed=True)


def _normalize_imap_login_error_for_enum(msg: str) -> str:
    """
    Normalize IMAP LOGIN failure text for comparison (OWASP-style username oracle).
    Collapses whitespace; strips trailing session/host suffixes similar to SMTP auth enum.
    """
    if not msg:
        return ""
    s = msg if isinstance(msg, str) else str(msg)
    s = " ".join(s.split())
    s = re.sub(r"\s+[a-zA-Z0-9.-]{15,}\s+-\s+[a-zA-Z0-9.]+\s*$", "", s)
    return s.strip().lower()


def _imap_login_exception_text(exc: BaseException) -> str:
    """Readable server text from imaplib.IMAP4.error (often raised with bytes from tagged NO)."""
    if not getattr(exc, "args", None):
        return str(exc)
    a0 = exc.args[0]
    if isinstance(a0, bytes):
        return a0.decode(errors="replace")
    return str(a0)


def _extract_capabilities_from_banner(banner: str | None) -> list[str]:
    """
    Extract CAPABILITY list from banner * OK [CAPABILITY X Y Z] ...
    Pre-auth capabilities in banner must not be lost when CAPABILITY is also called.
    """
    if not banner:
        return []
    match = re.search(r"\[CAPABILITY\s+([^\]]*)\]", banner, re.IGNORECASE)
    if not match:
        return []
    return [c.strip() for c in match.group(1).split() if c.strip()]


# IMAP CAPABILITY: known capabilities and security classification (IANA RFC 3501, 9051, 4959, etc.)
IMAP_KNOWN_CAPABILITIES = frozenset(
    {
        "IMAP4REV1", "IMAP4REV2", "ACL", "BINARY", "CATENATE", "CHILDREN", "COMPRESS=DEFLATE",
        "CONDSTORE", "ENABLE", "ESEARCH", "ID", "IDLE", "LITERAL+", "LITERAL-", "LOGIN-REFERRALS",
        "LOGINDISABLED", "MAILBOX-REFERRALS", "METADATA", "METADATA-SERVER", "MOVE", "MULTIAPPEND",
        "NAMESPACE", "SASL-IR", "SORT", "STARTTLS", "THREAD", "UIDPLUS", "UNSELECT", "UTF8=ACCEPT",
        "UTF8=ONLY", "WITHIN", "LIST-EXTENDED", "LIST-STATUS", "QRESYNC", "CONTEXT=SEARCH",
        "CONTEXT=SORT", "FILTERS", "NOTIFY", "SPECIAL-USE", "CREATE-SPECIAL-USE", "LIST-MYRIGHTS",
        "RIGHTS=", "QUOTA", "QUOTASET", "APPENDLIMIT", "OBJECTID", "PREVIEW", "SAVEDATE",
    }
)
# AUTH= method -> OK / WARNING / ERROR (same as SMTP/POP3 SASL)
IMAP_AUTH_METHOD_LEVEL = {
    "PLAIN": "ERROR", "LOGIN": "ERROR", "CRAM-MD5": "ERROR", "DIGEST-MD5": "ERROR",
    "NTLM": "ERROR", "ANONYMOUS": "ERROR", "KERBEROS_V4": "ERROR", "GSSAPI": "ERROR",
    "EXTERNAL": "WARNING",
    "XOAUTH2": "OK", "OAUTHBEARER": "OK", "SCRAM-SHA-1": "OK", "SCRAM-SHA-256": "OK",
}


def _parse_capability_commands(capability_list: list[str]) -> list[tuple[str, str]]:
    """
    Parse IMAP CAPABILITY list into (display_string, level) for output.
    Level is OK, WARNING, or ERROR. Expands AUTH=X into separate entries.
    If STARTTLS is not advertised, appends [✗] STARTTLS (is not allowed).
    """
    if not capability_list:
        return []
    result: list[tuple[str, str]] = []
    seen_starttls = False

    for capa in capability_list:
        capa = str(capa or "").strip()
        if not capa:
            continue
        capa_upper = capa.upper()

        if capa_upper == "STARTTLS":
            seen_starttls = True

        if capa_upper.startswith("AUTH="):
            method = capa_upper[5:].strip()
            level = IMAP_AUTH_METHOD_LEVEL.get(method, "OK")
            result.append((capa, level))
            continue

        if capa_upper in IMAP_KNOWN_CAPABILITIES or any(
            capa_upper.startswith(p) for p in ("AUTH=", "THREAD=", "SORT=", "COMPRESS=", "QUOTA=", "RIGHTS=", "I18NLEVEL=", "UTF8=")
        ):
            level = "OK"
        else:
            level = "OK"  # Unknown: show as OK

        result.append((capa, level))

    if not seen_starttls:
        result.append(("STARTTLS (is not allowed)", "ERROR"))

    return result


def _capa_level_bullet(level: str) -> str:
    if level == "ERROR":
        return "VULN"
    if level == "WARNING":
        return "WARNING"
    return "NOTVULN"

