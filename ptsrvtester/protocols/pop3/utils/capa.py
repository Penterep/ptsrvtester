"""POP3 CAPA classification helpers and argparse target helper."""
from __future__ import annotations

from .helpers import Target, valid_target, text

# Re-export shared helpers used by modules/cli
from .helpers import (  # noqa: F401
    ArgsWithBruteforce,
    Creds,
    add_bruteforce_args,
    check_if_brute,
    get_mode,
    simple_bruteforce,
    vendor_from_cpe,
)

POP3_KNOWN_CAPABILITIES = frozenset(
    {
        "TOP", "UIDL", "USER", "SASL", "RESP-CODES", "LOGIN-DELAY", "PIPELINING",
        "EXPIRE", "IMPLEMENTATION", "STLS", "AUTH-RESP-CODE", "UTF8", "LANG",
    }
)
POP3_SASL_METHOD_LEVEL_PLAIN = {
    "PLAIN": "ERROR", "LOGIN": "ERROR", "CRAM-MD5": "ERROR", "DIGEST-MD5": "ERROR",
    "NTLM": "ERROR", "ANONYMOUS": "ERROR", "KERBEROS_V4": "ERROR", "GSSAPI": "ERROR",
    "EXTERNAL": "WARNING",
    "XOAUTH2": "OK", "OAUTHBEARER": "OK", "SCRAM-SHA-1": "OK", "SCRAM-SHA-256": "OK",
}
POP3_CAPA_WARNING = frozenset({"USER", "IMPLEMENTATION"})


def valid_target_pop3(target: str) -> Target:
    return valid_target(target, domain_allowed=True)


def parse_capa_commands(
    capability: dict[str, list[str]], connection_encrypted: bool = False
) -> list[tuple[str, str]]:
    """Parse POP3 CAPA dict into (display_string, level) rows (OK/WARNING/ERROR)."""
    if not capability:
        return []
    result: list[tuple[str, str]] = []
    seen_stls = False

    for capa, vals in sorted(capability.items()):
        capa_upper = str(capa or "").upper().strip()
        vals_str = [str(v) for v in (vals or [])]

        if capa_upper == "STLS":
            seen_stls = True

        if capa_upper == "SASL":
            for method in vals_str:
                method_upper = method.upper()
                level = "OK" if connection_encrypted else POP3_SASL_METHOD_LEVEL_PLAIN.get(method_upper, "OK")
                result.append((f"SASL {method_upper}", level))
            continue

        level = "WARNING" if capa_upper in POP3_CAPA_WARNING else "OK"
        display = f"{capa_upper} {' '.join(vals_str)}".strip() if vals_str else capa_upper
        result.append((display, level))

    if not seen_stls and not connection_encrypted:
        result.append(("STLS (is not allowed)", "ERROR"))
    return result


def capa_level_bullet(level: str) -> str:
    if level == "ERROR":
        return "VULN"
    if level == "WARNING":
        return "WARNING"
    return "NOTVULN"


def bytes_to_text(value) -> str | None:
    if value is None:
        return None
    return text(value)
