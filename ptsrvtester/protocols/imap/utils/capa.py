"""IMAP CAPABILITY helpers and argparse target helper."""
from __future__ import annotations

import re

from .helpers import Target, valid_target

def valid_target_imap(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port (like SMTP)."""
    return valid_target(target, domain_allowed=True)


def _imap_dat_to_text(dat) -> str:
    """IMAP data payload as text (all items; tagged NO/BAD from imaplib)."""
    if dat is None:
        return ""
    items = dat if isinstance(dat, (list, tuple)) else (dat,)
    chunks: list[str] = []
    for last in items:
        if last is None:
            continue
        if isinstance(last, bytes):
            chunks.append(last.decode(errors="replace"))
        else:
            chunks.append(str(last))
    return " ".join(chunks).strip()


def _strip_imap_command_tags_for_enum(msg: str) -> str:
    """Drop per-connection IMAP command tags (imaplib tagpre+seq, e.g. IEHG1).

    Untagged ``* STATUS ...`` lines are kept — those can be a real oracle.
    """
    chunks: list[str] = []
    for chunk in re.split(r"\s*\|\s*", msg):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.match(
            r"^(\*|[\w.-]{1,32})\s+(OK|NO|BAD|BYE|PREAUTH)\b(.*)$",
            chunk,
            re.IGNORECASE,
        )
        if not m:
            chunks.append(chunk)
            continue
        token, status, rest = m.group(1), m.group(2), m.group(3)
        if token == "*":
            chunks.append(f"* {status}{rest}".strip())
        else:
            chunks.append(f"{status}{rest}".strip())
    return " | ".join(chunks)


def _normalize_imap_login_error_for_enum(msg: str, *, status: str | None = None) -> str:
    """
    Signature for username-oracle comparison (OWASP WSTG-IDENT-04).

    Includes tagged status (RFC 3501/9051 NO vs BAD) and IMAP response codes
    (RFC 5530, e.g. AUTHENTICATIONFAILED vs UNAVAILABLE), not only human text.
    Command tags must not be part of the signature — every IMAP session uses a
    new tag, which would otherwise look like a distinct error for every probe.
    """
    if not msg:
        s = ""
    else:
        s = msg if isinstance(msg, str) else str(msg)
        s = _strip_imap_command_tags_for_enum(s)
        s = " ".join(s.split())
        s = re.sub(r"\s+[a-zA-Z0-9.-]{15,}\s+-\s+[a-zA-Z0-9.]+\s*$", "", s)
        s = s.strip().lower()
    st = (status or "").strip().lower()
    if st:
        if s == st:
            s = ""
        elif s.startswith(st + " "):
            s = s[len(st):].strip()
    code_m = re.search(r"\[([a-z0-9_-]+)\]", s, re.IGNORECASE)
    code = code_m.group(1).lower() if code_m else ""
    parts = [p for p in (st, code, s) if p]
    return "|".join(parts)


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


def _parse_capability_commands(
    capability_list: list[str], connection_encrypted: bool = False
) -> list[tuple[str, str]]:
    """
    Parse IMAP CAPABILITY list into (display_string, level) for output.
    Level is OK, WARNING, or ERROR. Expands AUTH=X into separate entries.
    When connection_encrypted is True (TLS or STARTTLS), AUTH= methods are not
    flagged as cleartext and "STARTTLS (is not allowed)" is not appended.
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
            level = (
                "OK"
                if connection_encrypted
                else IMAP_AUTH_METHOD_LEVEL.get(method, "OK")
            )
            result.append((capa, level))
            continue

        if capa_upper in IMAP_KNOWN_CAPABILITIES or any(
            capa_upper.startswith(p) for p in ("AUTH=", "THREAD=", "SORT=", "COMPRESS=", "QUOTA=", "RIGHTS=", "I18NLEVEL=", "UTF8=")
        ):
            level = "OK"
        else:
            level = "OK"  # Unknown: show as OK

        result.append((capa, level))

    if not seen_starttls and not connection_encrypted:
        result.append(("STARTTLS (is not allowed)", "ERROR"))

    return result


def _capa_level_bullet(level: str) -> str:
    if level == "ERROR":
        return "VULN"
    if level == "WARNING":
        return "WARNING"
    return "NOTVULN"

