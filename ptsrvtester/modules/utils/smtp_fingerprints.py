"""
SMTP server fingerprinting (PTL-SVC-SMTP-IDENTIFY).
Identifies server software from banner, EHLO, HELP, error syntax, and unknown command responses.
v1.0.5: Behavioral analysis, cert software context, cert domain match.
v1.0.5+: Data leakage scan (e-mail addresses in banner, TLS DN, EHLO, HELP, errors).
"""
import ipaddress
import re
from dataclasses import dataclass
from typing import Final, Literal

from .behavior_profiles import (
    BANNER_EXPECTED_EXTENSIONS,
    EHLO_PROFILES,
    POSTFIX_STRIPPED_KEYS,
    check_banner_ehlo_discrepancy,
    check_banner_unknown_cmd_discrepancy,
    get_ehlo_keys_from_extensions,
    match_ehlo_profile,
    match_ehlo_profile_for_product,
)
from .service_identification import ServiceIdentification, identify_service, is_generic_esmtp_banner

# Scoring weights (percent)
WEIGHT_BANNER = 60
WEIGHT_CLOUD_BANNER = 90  # Cloud providers (Google, Zoho, M365, Proton) – banner authoritative, similar EHLO
WEIGHT_HELP = 30
WEIGHT_EHLO_KEYWORDS = 20
WEIGHT_EHLO_ORDER = 10
WEIGHT_ERROR_SYNTAX = 15
WEIGHT_UNKNOWN_CMD = 10
WEIGHT_TLS_CERT = 25
WEIGHT_TLS_CERT_CORPORATE = 10  # Self-signed with OU/O (Organization Unit/Name) = internal/corporate mail server
WEIGHT_BANNER_CERT_CONSISTENCY = 30  # Banner + cert both confirm same product (strong evidence)
WEIGHT_OS_HINT_CONSISTENCY = 5  # OS hint (TTL) matches expected platform for product (e.g. Exchange→Windows, Postfix→Linux)
WEIGHT_BEHAVIORAL_EHLO_PROFILE = 15  # Weighted Jaccard EHLO match (50–79%)
WEIGHT_BEHAVIORAL_EHLO_STRONG = 25  # Strong weighted match (≥80%) – e.g. J-Cloud ETRN+CRAM-MD5
WEIGHT_CERT_DOMAIN_MATCH = 5  # SAN/Subject domain aligns with target domain
WEIGHT_CERT_SOFTWARE_CONTEXT = 10  # Plesk/HestiaCP/cPanel in cert → inferred MTA
# Penalty when banner product ≠ best behavioral EHLO profile (discrepancy_detected): up to this many points at 100% profile sim
WEIGHT_BEHAVIORAL_CONFLICT_MAX = 15
# Generic ESMTP fallback: generic banner + minimal EHLO + low confidence — penalize spurious product attribution
WEIGHT_IDENTITY_BLUR = -15

_GENERIC_ESMTP_SERVICE_PRODUCT = "Generic ESMTP Service"
_GENERIC_ESMTP_SERVICE_CPE = "cpe:2.3:a:generic:esmtp_service:*:*:*:*:*:*:*:*"

# EHLO fingerprint: (keywords set, order_prefix first 2-3 extensions, product, cpe)
_SMTP_EHLO_FINGERPRINTS: Final[list[tuple[set[str], tuple[str, ...], str, str]]] = [
    # Exchange: X-EXPS, XEXCH50, X-RCPTLIMIT are unique
    ({"X-EXPS", "XEXCH50", "X-LINK2STATE", "XRDST", "X-ANONYMOUSTLS"}, (), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"),
    ({"X-EXPS", "XEXCH50", "X-LINK2STATE"}, (), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"),
    ({"X-EXPS", "XEXCH50"}, (), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"),
    ({"X-RCPTLIMIT"}, (), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"),
    # Barracuda: X-BARRACUDA-* (check before Postfix – unique signature)
    ({"X-BARRACUDA-GW"}, (), "Barracuda Email Security", "cpe:2.3:h:barracuda:email_security_gateway:*:*:*:*:*:*:*:*"),
    ({"X-BARRACUDA-BRTS"}, (), "Barracuda Email Security", "cpe:2.3:h:barracuda:email_security_gateway:*:*:*:*:*:*:*:*"),
    ({"X-BARRACUDA-CPANEL"}, (), "Barracuda Email Security", "cpe:2.3:h:barracuda:email_security_gateway:*:*:*:*:*:*:*:*"),
    # Postfix: XCLIENT, XFORWARD (CHUNKING removed – used by Exchange/MailStore too)
    ({"Postcow", "XCLIENT"}, (), "Mailcow", "cpe:2.3:a:mailcow:mailcow:*:*:*:*:*:*:*:*"),
    ({"XCLIENT", "XFORWARD", "CHUNKING"}, ("PIPELINING", "SIZE"), "Postfix", "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"),
    ({"XCLIENT", "CHUNKING"}, (), "Postfix", "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"),
    # Exim: X_E_N_D_O_F_M_E_S_S_A_G_E_
    ({"X_E_N_D_O_F_M_E_S_S_A_G_E_"}, (), "Exim", "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*"),
    # Sendmail: ETRN, DSN, DELIVERBY
    ({"ETRN", "DSN", "DELIVERBY"}, ("ETRN", "DSN"), "Sendmail", "cpe:2.3:a:sendmail:sendmail:*:*:*:*:*:*:*:*"),
    ({"ETRN", "DELIVERBY"}, ("ETRN",), "Sendmail", "cpe:2.3:a:sendmail:sendmail:*:*:*:*:*:*:*:*"),
    # Cisco
    ({"AsyncOS", "IronPort"}, (), "Cisco Secure Email (IronPort)", "cpe:2.3:h:cisco:secure_email_gateway:*:*:*:*:*:*:*:*"),
]

# Help regex: (pattern, product, version capture group or None)
_SMTP_HELP_PATTERNS: Final[list[tuple[re.Pattern[str], str, bool]]] = [
    (re.compile(r"sendmail\s+version\s+([\d.]+)", re.I), "Sendmail", True),
    (re.compile(r"sendmail\s+(\d+\.\d+)", re.I), "Sendmail", True),
    (re.compile(r"This\s+is\s+sendmail", re.I), "Sendmail", False),
    (re.compile(r"Postfix\s+(\d+\.\d+[.\d]*)", re.I), "Postfix", True),
    (re.compile(r"\bPostfix\b", re.I), "Postfix", False),
    (re.compile(r"This\s+server\s+supports\s+the\s+following\s+commands", re.I), "Microsoft Exchange Server", False),
    (re.compile(r"Exim\s+(\d+\.\d+)", re.I), "Exim", True),
]

# Error syntax: (regex, product) - for "User unknown" style messages
_SMTP_ERROR_SYNTAX: Final[list[tuple[re.Pattern[str], str]]] = [
    (re.compile(r"\.\.\.\s+User\s+unknown", re.I), "Sendmail"),  # three dots
    (re.compile(r"\.\.\.\s+User\s+unknown", re.I), "Sendmail"),
    (re.compile(r":\s*Recipient\s+address\s+rejected", re.I), "Postfix"),  # colon
    (re.compile(r"command\s+not\s+recognized", re.I), "Postfix"),  # 502 5.5.2
    (re.compile(r"Command\s+unrecognized", re.I), "Sendmail"),  # 500 5.5.1
    (re.compile(r"5\.5\.2\s+Error", re.I), "Postfix"),
    (re.compile(r"5\.5\.1\s+Command", re.I), "Sendmail"),
    (re.compile(r"5\.3\.3\s+Unrecognized", re.I), "Microsoft Exchange Server"),
]

# Unknown command response: (status_code_pattern, product)
# Exim: 500 with "Unrecognised" (BR) or "Unrecognized" (US)
_SMTP_UNKNOWN_CMD: Final[list[tuple[re.Pattern[str], str]]] = [
    (re.compile(r"502\s+5\.5\.2"), "Postfix"),
    (re.compile(r"500\s+5\.5\.1"), "Sendmail"),
    (re.compile(r"500\s+5\.3\.3"), "Microsoft Exchange Server"),
    (re.compile(r"500\s+.*[Uu]nrecogni[sz]ed"), "Exim"),
]

# TLS cert fingerprint: (issuer_pattern, subject_san_pattern) -> product, cpe
# Check SAN/Subject first (product-specific hostnames), then issuer (e.g. Let's Encrypt -> Postfix)
_SMTP_TLS_CERT_FINGERPRINTS: Final[list[tuple[re.Pattern[str], re.Pattern[str], str, str]]] = [
    (re.compile(r".*"), re.compile(r"exchange|outlook|microsoft|exch[0-9]+", re.I), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"),
    (re.compile(r".*"), re.compile(r"barracuda", re.I), "Barracuda Email Security Gateway", "cpe:2.3:h:barracuda:email_security_gateway:*:*:*:*:*:*:*:*"),
    (re.compile(r".*"), re.compile(r"ironport|cisco\.com", re.I), "Cisco Secure Email (IronPort)", "cpe:2.3:h:cisco:secure_email_gateway:*:*:*:*:*:*:*:*"),
    (re.compile(r".*"), re.compile(r"postfix|mailcow|postfix-vm", re.I), "Postfix", "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"),
    (re.compile(r".*"), re.compile(r"exim|exim[0-9]", re.I), "Exim", "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*"),
    (re.compile(r".*"), re.compile(r"sendmail", re.I), "Sendmail", "cpe:2.3:a:sendmail:sendmail:*:*:*:*:*:*:*:*"),
    (re.compile(r"Let's Encrypt", re.I), re.compile(r".*"), "Postfix", "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"),  # LE often used with Postfix
]

# Self-signed cert fingerprints: (subject_san_pattern, product, cpe, weight) - only when Subject == Issuer
# Ubuntu/Postfix default: CN=ubuntu. Exchange: CN = internal NetBIOS server name (exch01, mailbox02, etc.)
# Corporate/Internal: OU= or O= in subject = air-gapped or internal company mail server
_SMTP_TLS_SELF_SIGNED_FINGERPRINTS: Final[list[tuple[re.Pattern[str], str, str, int]]] = [
    (re.compile(r"CN=ubuntu\b|ubuntumachine|ubuntu\.local", re.I), "Postfix", "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*", WEIGHT_TLS_CERT),
    (re.compile(r"exchange|exch[0-9]+|mailbox[0-9]+|cas[0-9]*|edge[0-9]*", re.I), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*", WEIGHT_TLS_CERT),
    (re.compile(r",OU=|\bOU=[^,\s]|,O=|\bO=[^,\s]", re.I), "Private/Internal Mail Server", None, WEIGHT_TLS_CERT_CORPORATE),  # No CPE: generic internal/corporate
]

# Banner vs. cert consistency: when banner says product X, cert (Subject/SAN) confirms → +30%
# Maps banner product -> cert patterns (any match = consistency)
_BANNER_CERT_CONSISTENCY: Final[dict[str, list[re.Pattern[str]]]] = {
    "Sendinblue SMTP (Brevo)": [re.compile(r"sendinblue|brevo", re.I)],
    "Microsoft Exchange Server": [re.compile(r"exchange|microsoft|outlook", re.I)],
    "Microsoft SMTP Server": [re.compile(r"exchange|microsoft|outlook", re.I)],
    "Postfix": [re.compile(r"postfix", re.I)],
    "Barracuda Email Security": [re.compile(r"barracuda", re.I)],
    "Cisco Secure Email (IronPort)": [re.compile(r"cisco|ironport", re.I)],
    "Exim": [re.compile(r"exim", re.I)],
    "Sendmail": [re.compile(r"sendmail", re.I)],
    "Google SMTP (Gmail)": [re.compile(r"google\.com|googlemail\.com|gmail\.com", re.I)],
    "Google Workspace": [re.compile(r"google\.com|googlemail\.com|gmail\.com|googleapis", re.I)],
    "Microsoft 365": [re.compile(r"microsoft|outlook|office365", re.I)],
    "Zoho Mail": [re.compile(r"zoho", re.I)],
    "Proton Mail": [re.compile(r"protonmail|proton", re.I)],
    "Fastmail": [re.compile(r"fastmail|messagingengine", re.I)],
    "Yandex Mail": [re.compile(r"yandex", re.I)],
    "Mailgun": [re.compile(r"mailgun\.(org|com)|mailgun", re.I)],
    "SendGrid": [re.compile(r"sendgrid", re.I)],
    "Amazon SES": [re.compile(r"amazonaws|amazonses|ses", re.I)],  # email-smtp.*.amazonaws.com, amazonses.com relay
    "Zimbra Collaboration": [re.compile(r"zimbra|synacor", re.I)],  # older Zimbra certs have Synacor in Subject
    "Mailcow: dockerized": [re.compile(r"mailcow|postcow", re.I)],
    "Proofpoint Email Protection": [re.compile(r"proofpoint", re.I)],
    "Mimecast": [re.compile(r"mimecast", re.I)],
    "FortiMail": [re.compile(r"fortinet|fortimail", re.I)],
    "Oracle Communications Messaging Server": [re.compile(r"oracle", re.I)],
    "MailStore Gateway": [re.compile(r"mailstore|maxkon", re.I)],  # MailStore often uses customer domain in cert
    # Hosting providers: cert holds hostname (e.g. dc80.etius.jp), not product name – match provider domain
    "Postfix (Etius.jp / WebArena)": [re.compile(r"etius\.jp", re.I)],
    "Postfix (DreamHost VPS)": [re.compile(r"dreamhostps\.com|dreamhost", re.I)],
    "Postfix (LWS Hosting)": [re.compile(r"lwspanel\.com", re.I)],
}

# Cert Subject/Issuer → software context (Plesk, HestiaCP, etc.) → inferred MTA product
# Format: (regex_pattern, (context_name, product))
_CERT_SOFTWARE_CONTEXT: Final[list[tuple[re.Pattern[str], tuple[str, str]]]] = [
    (re.compile(r"hestia|hestiacp", re.I), ("HestiaCP", "Exim")),
    (re.compile(r"vesta|vestacp|vesta control panel", re.I), ("VestaCP", "Exim")),
    (re.compile(r"plesk|plesk\.com|info@plesk", re.I), ("Plesk", "Postfix")),
    (re.compile(r"cpanel", re.I), ("cPanel", "Postfix")),
    (re.compile(r"zimbra|synacor", re.I), ("Zimbra", "Zimbra Collaboration")),
    (re.compile(r"fortinet|fortimail", re.I), ("FortiMail", "FortiMail")),
    (re.compile(r"ironport|cisco\.com", re.I), ("Cisco", "Cisco Secure Email (IronPort)")),
]

# Product -> expected OS for TTL-based consistency bonus (+5%). Used when os_hint matches.
_PRODUCT_EXPECTED_OS: Final[dict[str, str]] = {
    "Microsoft Exchange Server": "windows",
    "Microsoft SMTP Server": "windows",
    "Microsoft Exchange Server (custom banner)": "windows",
    "hMailServer": "windows",
    "MailEnable": "windows",
    "MDaemon": "windows",
    "SmarterMail": "windows",
    "Postfix": "linux",
    "Postfix (Default/Stripped)": "linux",
    "Postfix (DreamHost VPS)": "linux",
    "Postfix (LWS Hosting)": "linux",
    "Postfix (Etius.jp / WebArena)": "linux",
    "Sendmail": "linux",
    "Exim": "linux",
    "Mailcow: dockerized": "linux",
    "Sendinblue SMTP (Brevo)": "linux",
    "Amazon SES": "linux",
    "Google SMTP (Gmail)": "linux",
    "Google Workspace": "linux",
    "Microsoft 365": "linux",
    "Zoho Mail": "linux",
    "Proton Mail": "linux",
    "Fastmail": "linux",
    "Yandex Mail": "linux",
    "Mailgun": "linux",
    "SendGrid": "linux",
    "Zimbra Collaboration": "linux",
    "Proofpoint Email Protection": "linux",
    "Mimecast": "linux",
    "FortiMail": "cisco",
    "Barracuda Email Security": "cisco",
    "Barracuda Email Security Gateway": "cisco",
    "Oracle Communications Messaging Server": "linux",
    "Cisco Secure Email (IronPort)": "cisco",
    "MailStore Gateway": "cisco",
    "Enterprise Cloud Gateway": "linux",
}

# OS hint matrix text: generic gateway/appliance profiles use neutral wording (OS not identity-proof).
_GENERIC_OS_HINT_PRODUCTS: Final[frozenset[str]] = frozenset(
    {
        "Network Appliance / Security Gateway",
        "Enterprise Cloud Gateway",
        "Sophos Email Appliance",
    }
)

# TTL Override: when os_hint indicates network appliance (TTL 255) and raw banner contains
# gateway/appliance keywords but banner_sid is None, veto weak Postfix/Exim from EHLO
_GATEWAY_BANNER_KEYWORDS = re.compile(
    r"\b(gateway|appliance|proxy|firewall|cisco|barracuda|mailstore|fortimail|fortinet|sophos)\b",
    re.I,
)
_GATEWAY_KEYWORD_TO_PRODUCT: Final[dict[str, str]] = {
    "mailstore": "MailStore Gateway",
    "barracuda": "Barracuda Email Security",
    "cisco": "Cisco Secure Email (IronPort)",
    "fortimail": "FortiMail",
    "fortinet": "FortiMail",
    "sophos": "Sophos Email Appliance",
}

# Cloud providers: banner authoritative (>80 %), EHLO similar across providers – do not let behavioral override
_CLOUD_PROVIDER_PRODUCTS: Final[frozenset[str]] = frozenset({
    "Google Workspace",
    "Google SMTP (Gmail)",
    "Microsoft 365",
    "Zoho Mail",
    "Proton Mail",
    "Amazon SES",
    "Fastmail",
    "Yandex Mail",
})

# Cloud providers that openly use Postfix in banner – Postfix-like EHLO is expected, not discrepancy
_POSTFIX_BASED_CLOUD_PROVIDERS: Final[frozenset[str]] = frozenset({
    "Proton Mail",  # Banner shows "ESMTP Postfix"; runs Postfix or faithful emulation
})

# Appliance/Gateway products: proxy often passes Postfix/Exim-like EHLO – suppress false discrepancy
_APPLIANCE_PROXY_PRODUCTS: Final[frozenset[str]] = frozenset({
    "MailStore Gateway",
    "Barracuda Email Security",
    "Barracuda Email Security Gateway",
    "Cisco Secure Email (IronPort)",
    "FortiMail",
    "Network Appliance / Security Gateway",
    "Sophos Email Appliance",
    "PowerMTA (Port25)",  # Often presents Postfix-like EHLO when masquerading
    "Plesk",
    "Exim",  # EHLO often overlaps with Enterprise Cloud Gateway; suppress false discrepancy
})

# Appliance banner + Postfix/Exim-like EHLO: vendor-specific integrity text (full sentence).
_APPLIANCE_SPECIFIC_INTEGRITY_NOTES: Final[dict[str, str]] = {
    "Sophos Email Appliance": (
        "Sophos secure email / UTM often exposes Exim- or Postfix-like EHLO; "
        "consistent with Sophos gateway stack."
    ),
}
# Human-readable stack label when a generic “appliance → MTA” explanation fits (not same-MTA case).
_APPLIANCE_INTEGRITY_LABELS: Final[dict[str, str]] = {
    "FortiMail": "FortiMail gateway",
    "Barracuda Email Security": "Barracuda ESG stack",
    "Barracuda Email Security Gateway": "Barracuda ESG stack",
    "Cisco Secure Email (IronPort)": "Cisco AsyncOS environment",
}


@dataclass
class ScoringEntry:
    """Single scoring matrix entry."""
    method: str
    points: int
    detail: str | None


@dataclass(frozen=True)
class DataLeakFinding:
    """E-mail or TLS-exposed identifier in SMTP/TLS surface (-id data leakage section)."""

    email: str  # E-mail address, or comma-separated internal hostnames when kind is internal_hostname
    risk: Literal["low", "medium", "high"]
    sources: tuple[str, ...]
    target_domain_match: bool = False  # True when risk is high (address domain aligns with scan target)
    kind: Literal["email", "internal_hostname"] = "email"


# E-mail-shaped tokens in banner, EHLO, HELP, error text, TLS Subject/Issuer/SAN.
_DATA_LEAK_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"([A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@"
    r"(?:localhost|127\.0\.0\.1|(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,63}))"
    r"(?![A-Za-z0-9._%+-])",
    re.I,
)

_LOW_LEAK_DOMAINS: Final[frozenset[str]] = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "localdomain",
        "invalid",
        "example",
        "test",
    }
)
_LOW_LEAK_PLACEHOLDER_DOMAINS: Final[frozenset[str]] = frozenset(
    {
        "nameserver.tld",
        "domain.tld",
        "hostname.tld",
        "server.tld",
        "yourdomain.tld",
        "mail.local",
    }
)
_LOW_LEAK_DOMAIN_SUFFIXES: Final[tuple[str, ...]] = (
    ".local",
    ".localdomain",
    ".lan",
    ".corp",
    ".internal",
    ".intranet",
    ".private",
    ".priv",
    ".ads",
    ".test",
    ".invalid",
    ".example",
)

# TLS CN/SAN: non-routable / internal naming that should not appear on internet-facing SMTP
_INTERNAL_INFRA_DNS_SUFFIXES: Final[tuple[str, ...]] = (
    ".local",
    ".localdomain",
    ".lan",
    ".internal",
    ".intranet",
    ".private",
    ".priv",
    ".ads",
    ".home",
    ".node",
    ".corp",
)
_INTERNAL_INFRA_HIGH_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".internal", ".intranet", ".corp", ".private", ".priv", ".ads"}
)


def _email_domain_low_risk(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    if d in _LOW_LEAK_DOMAINS:
        return True
    if d in _LOW_LEAK_PLACEHOLDER_DOMAINS:
        return True
    for suf in _LOW_LEAK_DOMAIN_SUFFIXES:
        if d.endswith(suf):
            return True
    if d.endswith(".example.com") or d.endswith(".example.org") or d.endswith(".example.net"):
        return True
    try:
        addr = ipaddress.ip_address(d)
        return bool(addr.is_loopback or addr.is_private or addr.is_link_local)
    except ValueError:
        pass
    return False


def _noreply_local_base(local: str) -> str:
    """Strip plus-addressing for noreply heuristics (noreply+tag@x → noreply)."""
    return (local.split("+", 1)[0]).lower().strip()


def _is_noreply_local_part(local: str) -> bool:
    """Automated / unmonitored mailbox locals — low value for phishing or credential attacks."""
    b = _noreply_local_base(local)
    return b.startswith(
        (
            "noreply",
            "no-reply",
            "no_reply",
            "donotreply",
            "do-not-reply",
            "do_not_reply",
        )
    )


def _normalize_scan_target_host(host: str | None) -> str | None:
    """Hostname for domain-alignment checks; None if IP-only or unusable."""
    if not host or not str(host).strip():
        return None
    h = str(host).strip().lower().rstrip(".")
    if h.startswith("["):
        end = h.find("]")
        if end > 1:
            inner = h[1:end]
            try:
                ipaddress.ip_address(inner)
                return None
            except ValueError:
                return inner.lower().rstrip(".") or None
        return None
    if ":" in h:
        host_part, _, maybe_port = h.rpartition(":")
        if maybe_port.isdigit():
            h = host_part
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    if "." not in h:
        return None
    return h


def _shared_dns_label_suffix_len(a: str, b: str) -> int:
    """Count matching labels from the right (e.g. mail.firma.cz vs firma.cz → 2)."""
    pa = [x for x in a.lower().split(".") if x]
    pb = [x for x in b.lower().split(".") if x]
    if not pa or not pb:
        return 0
    n = 0
    while n < len(pa) and n < len(pb) and pa[-1 - n] == pb[-1 - n]:
        n += 1
    return n


def _email_domain_matches_target(email_domain: str, target_host: str) -> bool:
    """True if e-mail domain is the same org/DNS zone as the scanned target host."""
    e = email_domain.lower().strip(".")
    t = target_host.lower().strip(".")
    if not e or not t:
        return False
    if e == t:
        return True
    if t.endswith("." + e) or e.endswith("." + t):
        return True
    return _shared_dns_label_suffix_len(e, t) >= 2


def _classify_email_leak_risk(addr: str, target_host: str | None) -> Literal["low", "medium", "high"]:
    if "@" not in addr:
        return "low"
    local, dom = addr.rsplit("@", 1)
    if _is_noreply_local_part(local):
        return "low"
    if _email_domain_low_risk(dom):
        return "low"
    tnorm = _normalize_scan_target_host(target_host)
    if tnorm and _email_domain_matches_target(dom, tnorm):
        return "high"
    return "medium"


_RISK_RANK: Final[dict[str, int]] = {"low": 0, "medium": 1, "high": 2}


def _merge_risk(
    a: Literal["low", "medium", "high"], b: Literal["low", "medium", "high"]
) -> Literal["low", "medium", "high"]:
    return a if _RISK_RANK[a] >= _RISK_RANK[b] else b


def _extract_emails_from_text(text: str | None) -> set[str]:
    if not text or not text.strip():
        return set()
    return {m.group(1) for m in _DATA_LEAK_EMAIL_RE.finditer(text)}


def _extract_cn_values_from_dn(dn: str | None) -> list[str]:
    """RFC4514-style DN: collect CN= values (server cert Subject/Issuer)."""
    if not dn or not dn.strip():
        return []
    return [m.group(1).strip() for m in re.finditer(r"\bCN=([^,+\"\\]+)", dn, re.I) if m.group(1).strip()]


def _normalize_tls_san_dns_name(entry: str | None) -> str | None:
    if not entry or not str(entry).strip():
        return None
    e = str(entry).strip()
    up = e.upper()
    # rfc822Name / email SAN — handled by _tls_san_rfc822_email, not as dNSName
    if up.startswith(("EMAIL:", "RFC822:", "RFC822NAME:", "E-MAIL:")):
        return None
    if up.startswith("DNS:"):
        e = e[4:].strip()
        up = e.upper()
    elif up.startswith("IP:") or up.startswith("URI:"):
        return None
    if "@" in e:
        return None
    if not e or "*" in e:
        return None
    return e


def _tls_san_rfc822_email(entry: str | None) -> str | None:
    """RFC822 / email SAN: prefixed (email:, rfc822:) or raw user@domain (cryptography rfc822Name).

    Local-part-only rfc822Name (no @, e.g. postmaster) is valid in PKIX but not a mailbox — ignored for leakage."""
    if not entry or not str(entry).strip():
        return None
    raw = str(entry).strip()
    up = raw.upper()
    for pref in ("EMAIL:", "RFC822:", "RFC822NAME:", "E-MAIL:"):
        if up.startswith(pref):
            body = raw[len(pref) :].strip()
            return body if body and "@" in body else None
    if "*" in raw:
        return None
    if "@" not in raw:
        return None
    if up.startswith("DNS:") or up.startswith("IP:") or up.startswith("URI:"):
        return None
    return raw


def _is_internal_infrastructure_hostname(name: str) -> bool:
    """True for reserved / non-Internet suffixes or single-label host-style tokens (e.g. MAILSERVER)."""
    n = name.strip()
    if not n or "*" in n:
        return False
    low = n.lower().rstrip(".")
    if low in ("localhost", "invalid"):
        return False
    try:
        ipaddress.ip_address(low.strip("[]"))
        return False
    except ValueError:
        pass
    for suf in _INTERNAL_INFRA_DNS_SUFFIXES:
        if low.endswith(suf):
            return True
    if "." not in low:
        if len(low) < 3:
            return False
        return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]$", n, re.I))
    return False


def _internal_hostname_finding_risk(display_name: str) -> Literal["medium", "high"]:
    low = display_name.lower().rstrip(".")
    for suf in _INTERNAL_INFRA_HIGH_SUFFIXES:
        if low.endswith(suf):
            return "high"
    return "medium"


def _collect_tls_internal_hostname_leaks(
    tls_cert_subject: str | None,
    tls_cert_issuer: str | None,
    tls_cert_san: list[str] | None,
) -> DataLeakFinding | None:
    """One aggregated finding for internal / non-routable names in TLS CN and SAN."""
    # key lower -> [display, risk, sources set]
    acc: dict[str, list] = {}

    def _add(disp: str, source: str) -> None:
        if not _is_internal_infrastructure_hostname(disp):
            return
        d = disp.strip()
        lk = d.lower()
        r: Literal["medium", "high"] = _internal_hostname_finding_risk(d)
        if lk not in acc:
            acc[lk] = [d, r, {source}]
        else:
            row = acc[lk]
            row[2].add(source)
            if r == "high":
                row[1] = "high"

    for cn in _extract_cn_values_from_dn(tls_cert_subject):
        _add(cn, "TLS Certificate Subject")
    for cn in _extract_cn_values_from_dn(tls_cert_issuer):
        _add(cn, "TLS Certificate Issuer")
    for san in tls_cert_san or []:
        nm = _normalize_tls_san_dns_name(san)
        if nm:
            _add(nm, "TLS SAN")
        rfc = _tls_san_rfc822_email(san)
        if rfc:
            _add(rfc, "TLS SAN (RFC822)")
    if not acc:
        return None
    items = sorted(acc.values(), key=lambda x: str(x[0]).lower())
    names_display = ", ".join(str(x[0]) for x in items)
    merged_srcs: set[str] = set()
    max_risk: Literal["medium", "high"] = "medium"
    for x in items:
        merged_srcs |= x[2]
        if x[1] == "high":
            max_risk = "high"
    return DataLeakFinding(
        email=names_display,
        risk=max_risk,
        sources=tuple(sorted(merged_srcs)),
        target_domain_match=False,
        kind="internal_hostname",
    )


def _collect_data_leakage_findings(
    banner: str | None,
    ehlo_raw: str | None,
    help_response: str | None,
    error_samples: list[str],
    unknown_cmd_response: str | None,
    tls_cert_subject: str | None,
    tls_cert_issuer: str | None,
    tls_cert_san: list[str] | None,
    target_host: str | None = None,
) -> tuple[DataLeakFinding, ...]:
    """Collect unique e-mails from all passive -id sources; classify low / medium / high exposure."""
    by_key: dict[str, tuple[str, Literal["low", "medium", "high"], set[str]]] = {}
    sources_map: list[tuple[str, str | None]] = [
        ("TLS Certificate Subject", tls_cert_subject),
        ("TLS Certificate Issuer", tls_cert_issuer),
        ("Banner", banner),
        ("EHLO response", ehlo_raw),
        ("HELP response", help_response),
        ("Unknown command response", unknown_cmd_response),
    ]
    for label, blob in sources_map:
        if not blob:
            continue
        for em in _extract_emails_from_text(blob):
            key = em.lower()
            risk = _classify_email_leak_risk(em, target_host)
            if key not in by_key:
                by_key[key] = (em, risk, {label})
            else:
                prev_em, prev_risk, srcs = by_key[key]
                by_key[key] = (prev_em, _merge_risk(prev_risk, risk), srcs | {label})
    for sample in error_samples or []:
        for em in _extract_emails_from_text(sample):
            key = em.lower()
            risk = _classify_email_leak_risk(em, target_host)
            if key not in by_key:
                by_key[key] = (em, risk, {"SMTP error response"})
            else:
                prev_em, prev_risk, srcs = by_key[key]
                by_key[key] = (prev_em, _merge_risk(prev_risk, risk), srcs | {"SMTP error response"})
    for san in tls_cert_san or []:
        san_src = "TLS SAN"
        rfc822 = _tls_san_rfc822_email(san)
        if rfc822:
            key = rfc822.lower()
            risk = _classify_email_leak_risk(rfc822, target_host)
            src = "TLS SAN (RFC822)"
            if key not in by_key:
                by_key[key] = (rfc822, risk, {src})
            else:
                prev_em, prev_risk, srcs = by_key[key]
                by_key[key] = (prev_em, _merge_risk(prev_risk, risk), srcs | {src})
        for em in _extract_emails_from_text(san):
            key = em.lower()
            risk = _classify_email_leak_risk(em, target_host)
            if key not in by_key:
                by_key[key] = (em, risk, {san_src})
            else:
                prev_em, prev_risk, srcs = by_key[key]
                by_key[key] = (prev_em, _merge_risk(prev_risk, risk), srcs | {san_src})
    internal_finding = _collect_tls_internal_hostname_leaks(
        tls_cert_subject, tls_cert_issuer, tls_cert_san
    )
    rank_order = {"high": 0, "medium": 1, "low": 2}
    out: list[DataLeakFinding] = []
    if by_key:
        rows = sorted(by_key.values(), key=lambda t: (rank_order[t[1]], t[0].lower()))
        out.extend(
            DataLeakFinding(
                email=em,
                risk=risk,
                sources=tuple(sorted(srcs)),
                target_domain_match=(risk == "high"),
                kind="email",
            )
            for em, risk, srcs in rows
        )
    if internal_finding is not None:
        out.append(internal_finding)
    if not out:
        return ()
    out.sort(key=lambda f: (rank_order[f.risk], f.email.lower(), 0 if f.kind == "email" else 1))
    return tuple(out)


@dataclass
class ServerIdentifyResult:
    """Result of PTL-SVC-SMTP-IDENTIFY test."""
    product: str | None
    version: str | None
    cpe: str | None
    os: str | None
    confidence_pct: int
    confidence_label: str  # high | medium | low | indeterminate
    hidden_banner: bool
    scoring_matrix: list[ScoringEntry]
    banner: str | None
    ehlo_extensions: list[str]
    ehlo_proprietary: list[str]
    ehlo_order: list[str]
    help_response: str | None
    error_syntax_samples: list[str]
    unknown_cmd_response: str | None
    recommendation: str | None
    anomalous_identity: bool
    banner_claims: str | None
    behavior_matches: str | None
    tls_cert_subject: str | None = None
    tls_cert_issuer: str | None = None
    tls_cert_san: list[str] | None = None
    tls_cert_self_signed: bool = False
    tls_upgrade_failed: bool = False  # True if STARTTLS was attempted but cert not extracted
    tls_upgrade_error: str | None = None  # Exception message when STARTTLS failed (for -vv/--verbose)
    transport_tls: bool = False  # True if SMTP socket was TLS at end of identify probe (465/--tls/STARTTLS)
    starttls_advertised: bool = False  # STARTTLS appeared in EHLO (plaintext policy / UI)
    tls_policy: str | None = None  # "mandatory" | "opportunistic" | "n/a"
    tls_cert_warnings: list[str] | None = None  # SHA-1, weak key, self-signed deliverability risk
    tls_cipher_warnings: list[str] | None = None  # RC4, 3DES, CBC, deprecated protocol
    tls_downgrade_findings: list[str] | None = None  # Phase 2: server accepts weak TLS (downgrade attack path)
    tls_downgrade_probed: bool = False  # True when Phase 2 was run (id_aggressive + TLS)
    os_hint: str | None = None  # Passive: TTL-based OS hint (inference 64/128/255 → Linux/Windows/Cisco)
    # v1.0.5 Behavioral analysis
    behavioral_profile_product: str | None = None  # Best EHLO profile match
    behavioral_profile_sim: int = 0  # Jaccard similarity percent
    behavioral_profile_detail: str | None = None
    behavioral_discrepancies: tuple[str, ...] = ()  # Banner vs EHLO/cmd mismatches
    latency_avg_ms: float | None = None  # RSET/NOOP avg RTT
    latency_jitter_ms: float | None = None  # Stddev of RTT
    cert_domain_match: bool = False  # SAN/Subject domain aligns with target
    cert_software_context: str | None = None  # "HestiaCP → Exim" etc.
    behavioral_matched_verbs: tuple[str, ...] = ()  # EHLO verbs that matched profile (evidence-based)
    behavioral_missing_verbs: tuple[str, ...] = ()  # EHLO verbs expected but missing (evidence-based)
    integrity_note: str | None = None  # Positive note when appliance proxy EHLO is consistent (suppresses false discrepancy)
    data_leakage_findings: tuple[DataLeakFinding, ...] = ()  # E-mails in banner/TLS/EHLO/HELP/errors (-id privacy)
    discrepancy_detected: bool = False  # Banner product vs behavioral EHLO profile (universal identity mismatch)
    discrepancy_banner_product: str | None = None
    discrepancy_behavior_product: str | None = None
    behavioral_hint: str | None = None  # Raw best EHLO profile hint when generic fallback applies (e.g. "Exim (67%)")


def _parse_ehlo_extensions(ehlo_raw: str | None) -> tuple[list[str], list[str], list[str]]:
    """Parse EHLO response into (all_extensions, proprietary_x, order_of_keys).
    First line is hostname, skip. Returns extension keys in order.
    Supports both raw SMTP format (250-XXX) and smtplib-stripped format (no status prefix)."""
    if not ehlo_raw or not ehlo_raw.strip():
        return [], [], []
    lines = ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").strip().split("\n")
    extensions: list[str] = []
    proprietary: list[str] = []
    order_keys: list[str] = []
    first = True
    for line in lines:
        line = line.strip()
        if not line:
            continue
        rest: str
        if line.startswith("250-"):
            rest = line[4:].strip()
        elif line.startswith("250 "):
            rest = line[3:].strip()
        else:
            # smtplib returns reply without 250- prefix (stripped by getreply)
            rest = line
        if not rest or rest.upper() == "OK":
            continue
        parts = rest.split(None, 1)
        key = (parts[0] or "").upper().strip()
        # Skip hostname line (first line with dot in key)
        if first and "." in key:
            first = False
            continue
        if key and key not in ("OK",):
            if key.startswith("X") or "-" in key:
                proprietary.append(key)
            order_keys.append(key)
            extensions.append(rest)
        first = False
    return extensions, proprietary, order_keys


def _is_hidden_banner(banner: str | None, banner_sid: ServiceIdentification | None) -> bool:
    """True if banner is generic/hidden (no product match)."""
    if not banner or not banner.strip():
        return True
    if banner_sid is not None:
        return False
    first = (banner.split("\n")[0] if "\n" in banner else banner).strip()
    generic = (
        "welcome" in first.lower()
        or re.search(r"^220\s+[\w.-]+\s+(?:ESMTP|SMTP)\s+(?:service\s+)?ready\s*$", first, re.I)
        or re.search(r"^220\s+\*+\s*$", first)
    )
    return bool(generic)


def _identify_from_ehlo(
    ehlo_extensions: list[str], ehlo_proprietary: list[str], ehlo_order: list[str]
) -> tuple[str | None, str | None, int]:
    """Match EHLO against fingerprints. Returns (product, cpe, points_earned)."""
    ext_set = {e.split(None, 1)[0].upper() for e in ehlo_extensions if e}
    ext_set.update(k.upper() for k in ehlo_proprietary)
    order_tuple = tuple(ehlo_order[:3])  # First 2-3 elements

    for keywords, order_prefix, product, cpe in _SMTP_EHLO_FINGERPRINTS:
        matched_keywords = keywords & ext_set
        if not matched_keywords:
            continue
        points = WEIGHT_EHLO_KEYWORDS
        if order_prefix and order_tuple and order_tuple[: len(order_prefix)] == order_prefix:
            points += WEIGHT_EHLO_ORDER
        return product, cpe, points
    return None, None, 0


def _identify_from_help(help_text: str | None) -> tuple[str | None, str | None, str | None, int]:
    """Match HELP response. Returns (product, version, cpe, points)."""
    if not help_text or not help_text.strip():
        return None, None, None, 0
    for pattern, product, has_version in _SMTP_HELP_PATTERNS:
        m = pattern.search(help_text)
        if m:
            version = m.group(1) if has_version and m.lastindex and m.lastindex >= 1 else None
            cpe_map = {
                "Sendmail": "cpe:2.3:a:sendmail:sendmail:*:*:*:*:*:*:*:*",
                "Postfix": "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*",
                "Exim": "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*",
                "Microsoft Exchange Server": "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
            }
            cpe = cpe_map.get(product, "*")
            points = WEIGHT_HELP if "version" in help_text.lower() or version else WEIGHT_HELP // 2
            return product, version, cpe, points
    return None, None, None, 0


def _identify_from_error_syntax(samples: list[str]) -> tuple[str | None, int]:
    """Match error message format. Returns (product, points)."""
    if not samples:
        return None, 0
    combined = " ".join(samples)
    for pattern, product in _SMTP_ERROR_SYNTAX:
        if pattern.search(combined):
            return product, WEIGHT_ERROR_SYNTAX
    return None, 0


def _identify_from_unknown_cmd(response: str | None) -> tuple[str | None, int]:
    """Match unknown command response (e.g. FOOBAR). Returns (product, points)."""
    if not response or not response.strip():
        return None, 0
    for pattern, product in _SMTP_UNKNOWN_CMD:
        if pattern.search(response):
            return product, WEIGHT_UNKNOWN_CMD
    return None, 0


def _identify_from_tls_cert(
    subject: str | None,
    issuer: str | None,
    san: list[str],
    is_self_signed: bool = False,
) -> tuple[str | None, str | None, int]:
    """Match TLS cert Subject/Issuer/SAN against fingerprints. Returns (product, cpe, points).
    When Subject == Issuer (self-signed), check product-specific patterns (Ubuntu/Postfix, Exchange NetBIOS)."""
    if not subject and not issuer and not san:
        return None, None, 0
    combined = " ".join([subject or "", issuer or ""] + (san or []))
    if not combined.strip():
        return None, None, 0
    if is_self_signed:
        for san_pat, prod, cpe, weight in _SMTP_TLS_SELF_SIGNED_FINGERPRINTS:
            if san_pat.search(combined):
                return prod, cpe, weight
    for issuer_pat, san_pat, product, cpe in _SMTP_TLS_CERT_FINGERPRINTS:
        if issuer_pat.search(issuer or "") and san_pat.search(combined):
            return product, cpe, WEIGHT_TLS_CERT
    return None, None, 0


def _confidence_label(pct: int) -> str:
    if pct >= 80:
        return "high"
    if pct >= 50:
        return "medium"
    if pct >= 20:
        return "low"
    return "indeterminate"


def _product_identity_key(name: str) -> str:
    """Normalize product name for discrepancy: same family before '(' (e.g. Postfix vs Postfix (VPS))."""
    if not name or not str(name).strip():
        return ""
    return str(name).split("(", 1)[0].strip().lower()


def _build_recommendation(
    hidden_banner: bool,
    confidence_pct: int,
    confidence_label: str,
    anomalous_identity: bool,
    identity_mismatch_banner: str | None = None,
    identity_mismatch_behavior: str | None = None,
) -> str | None:
    if identity_mismatch_banner and identity_mismatch_behavior:
        return (
            f"Identity mismatch detected. The server identifies as '{identity_mismatch_banner}', but its behavioral "
            f"fingerprint matches '{identity_mismatch_behavior}'. This typically suggests an MTA relay / Security "
            f"Gateway (e.g. Proofpoint, FortiMail, Cisco Secure Email), a forwarding proxy, or a Honeypot setup. "
            f"Verify the delivery chain via 'Received' headers or hop-specific latency analysis."
        )
    if anomalous_identity:
        return (
            "The server appears to be misconfigured or intentionally spoofing its "
            "identity (Honeypot/Proxy). Verify the integrity of the SMTP gateway."
        )
    if confidence_label == "indeterminate":
        return (
            "Server identity is heavily masked, possibly by a Load Balancer or Security Gateway."
        )
    if hidden_banner and confidence_pct >= 50:
        return (
            "Identity identified despite hidden banner. To increase security, disable the "
            "'HELP' command and customize error strings."
        )
    return None


_CPE_NUM_COMPONENTS = 11  # CPE 2.3: part,vendor,product,version,update,edition,language,sw_edition,target_sw,target_hw,other


def _normalize_cpe(cpe: str | None) -> str | None:
    """Pad CPE 2.x to exactly 11 components (NVD format)."""
    if not cpe or not cpe.strip() or ":" not in cpe:
        return cpe
    parts = cpe.strip().split(":")
    if len(parts) < 3 or not (parts[0] == "cpe" and parts[1].startswith("2.")):
        return cpe
    components = parts[2:]
    while len(components) < _CPE_NUM_COMPONENTS:
        components.append("*")
    return ":".join(parts[:2] + components[:_CPE_NUM_COMPONENTS])


def _product_cpe_fallback(product: str) -> str:
    """CPE for products not in EHLO_PROFILES."""
    m = {
        "Postfix (Default/Stripped)": "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*",
        "Zimbra Collaboration": "cpe:2.3:a:zimbra:collaboration:*:*:*:*:*:*:*:*",
        "FortiMail": "cpe:2.3:h:fortinet:fortimail:*:*:*:*:*:*:*:*",
        "Cisco Secure Email (IronPort)": "cpe:2.3:h:cisco:secure_email_gateway:*:*:*:*:*:*:*:*",
        "Network Appliance / Security Gateway": "cpe:2.3:a:network:appliance_mta:*:*:*:*:*:*:*:*",
        "Enterprise Cloud Gateway": "cpe:2.3:a:enterprise:cloud_gateway:*:*:*:*:*:*:*:*",
        "MailStore Gateway": "cpe:2.3:a:mailstore:mailstore_gateway:*:*:*:*:*:*:*:*",
        "Barracuda Email Security": "cpe:2.3:h:barracuda:email_security_gateway:*:*:*:*:*:*:*:*",
        "Sophos Email Appliance": "cpe:2.3:a:sophos:email_appliance:*:*:*:*:*:*:*:*",
        "Zoho Mail": "cpe:2.3:a:zoho:mail:*:*:*:*:*:*:*:*",
        "Microsoft 365": "cpe:2.3:a:microsoft:exchange_online:*:*:*:*:*:*:*:*",
        "Proton Mail": "cpe:2.3:a:protonmail:protonmail:*:*:*:*:*:*:*:*",
        "Fastmail": "cpe:2.3:a:fastmail:fastmail:*:*:*:*:*:*:*:*",
        "Yandex Mail": "cpe:2.3:a:yandex:yandex_mail:*:*:*:*:*:*:*:*",
    }
    return m.get(
        product,
        f"cpe:2.3:a:{product.lower().replace(' ', '_').replace('(', '').replace(')', '')}:*:*:*:*:*:*:*:*",
    )


def _cert_domain_matches_target(cert_text: str, target_host: str | None) -> bool:
    """True if any domain in cert (SAN/Subject) matches target host/domain."""
    if not cert_text or not target_host or "." not in target_host:
        return False
    cert_lower = cert_text.lower()
    host_lower = target_host.lower().strip()
    # Check if host or its parent domain appears in cert
    if host_lower in cert_lower:
        return True
    parts = host_lower.split(".")
    for i in range(len(parts) - 1, 0, -1):
        parent = ".".join(parts[i:])
        if len(parent) > 3 and parent in cert_lower:
            return True
    return False


def _hostname_from_banner(banner: str | None) -> str | None:
    """Extract hostname from banner first line (e.g. 'dc80.etius.jp ESMTP' -> dc80.etius.jp)."""
    if not banner or not banner.strip():
        return None
    first_line = (banner.split("\n")[0] if "\n" in banner else banner).strip()
    # Skip leading 220 if present
    first_line = re.sub(r"^220\s+", "", first_line)
    for tok in first_line.split():
        tok = tok.strip()
        if tok and "." in tok and len(tok) > 4 and re.match(r"^[a-z0-9][\w.-]*\.\w+$", tok, re.I):
            return tok
    return None


def identify_smtp_server(
    banner: str | None,
    ehlo_raw: str | None,
    help_response: str | None,
    error_samples: list[str],
    unknown_cmd_response: str | None,
    id_aggressive: bool,
    tls_cert_subject: str | None = None,
    tls_cert_issuer: str | None = None,
    tls_cert_san: list[str] | None = None,
    tls_cert_self_signed: bool = False,
    tls_upgrade_failed: bool = False,
    tls_upgrade_error: str | None = None,
    transport_tls: bool = False,
    starttls_advertised: bool = False,
    tls_policy: str | None = None,
    tls_cert_warnings: list[str] | None = None,
    tls_cipher_warnings: list[str] | None = None,
    tls_downgrade_findings: list[str] | None = None,
    tls_downgrade_probed: bool = False,
    os_hint: str | None = None,
    target_host: str | None = None,  # For cert_domain_match (hostname or PTR)
    latency_avg_ms: float | None = None,
    latency_jitter_ms: float | None = None,
) -> ServerIdentifyResult:
    """
    Perform SMTP server identification from collected responses.
    """
    scoring: list[ScoringEntry] = []
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    os_str: str | None = None
    banner_claims: str | None = None
    behavior_matches: str | None = None
    anomalous_identity = False

    # 1. Banner
    banner_sid = identify_service(banner)
    hidden_banner = _is_hidden_banner(banner, banner_sid)
    if banner_sid:
        product = banner_sid.product
        version = banner_sid.version
        cpe = banner_sid.cpe
        os_str = banner_sid.os
        banner_claims = product
        banner_weight = WEIGHT_CLOUD_BANNER if product in _CLOUD_PROVIDER_PRODUCTS else WEIGHT_BANNER
        scoring.append(ScoringEntry("banner", banner_weight, f"Banner match: {product}"))
    else:
        if banner:
            first_line = (banner.split("\n")[0] if "\n" in banner else banner).strip()
            banner_claims = first_line if first_line else "Generic"

    # 2. EHLO
    ehlo_ext, ehlo_prop, ehlo_order = _parse_ehlo_extensions(ehlo_raw)
    ehlo_product, ehlo_cpe, ehlo_pts = _identify_from_ehlo(ehlo_ext, ehlo_prop, ehlo_order)
    if ehlo_product and ehlo_pts:
        scoring.append(ScoringEntry("ehlo_keywords", ehlo_pts, f"Found: {', '.join(ehlo_prop[:5]) or ehlo_order[:3]}"))
        if not product:
            product = ehlo_product
            cpe = ehlo_cpe
        elif product != ehlo_product:
            # Cloud-first: banner match for cloud providers overrides EHLO – no discrepancy
            if product not in _CLOUD_PROVIDER_PRODUCTS:
                anomalous_identity = True
                behavior_matches = ehlo_product
        if ehlo_pts >= WEIGHT_EHLO_KEYWORDS + WEIGHT_EHLO_ORDER:
            pass  # already in points

    # 3. HELP
    help_product, help_version, help_cpe, help_pts = _identify_from_help(help_response)
    if help_product and help_pts:
        scoring.append(ScoringEntry("help", help_pts, "Leaked version info" if help_version else "Help match"))
        if help_version:
            version = version or help_version
        if not product:
            product = help_product
            cpe = help_cpe or cpe
        elif product != help_product:
            anomalous_identity = True
            behavior_matches = behavior_matches or help_product

    # 4. Error syntax (from VRFY/RCPT or other errors)
    err_product, err_pts = _identify_from_error_syntax(error_samples)
    if err_product and err_pts:
        scoring.append(ScoringEntry("error_syntax", err_pts, f"Regex match: {err_product}"))
        if not product:
            product = err_product
        elif product != err_product:
            anomalous_identity = True
            behavior_matches = behavior_matches or err_product

    # 5. Unknown command / behavioral_unknown_cmd (only when aggressive)
    unk_product: str | None = None
    if id_aggressive and unknown_cmd_response:
        unk_product, unk_pts = _identify_from_unknown_cmd(unknown_cmd_response)
        if unk_product and unk_pts:
            scoring.append(
                ScoringEntry(
                    "behavioral_unknown_cmd",
                    unk_pts,
                    f"Response: {unknown_cmd_response}",
                )
            )
            if not product:
                product = unk_product
            elif product != unk_product:
                anomalous_identity = True
                behavior_matches = behavior_matches or unk_product

    # 6. TLS cert (Subject, Issuer, SAN) - passive, no IDS/IPS alerts
    tls_product, tls_cpe, tls_pts = _identify_from_tls_cert(
        tls_cert_subject, tls_cert_issuer, tls_cert_san or [], tls_cert_self_signed
    )
    if tls_product and tls_pts:
        san_preview = ", ".join((tls_cert_san or [])[:3]) if tls_cert_san else ""
        prefix = "Self-signed; " if tls_cert_self_signed else ""
        tls_detail = f"{prefix}Issuer: {tls_cert_issuer or '—'}; SAN: {san_preview}"
        scoring.append(ScoringEntry("tls_cert", tls_pts, tls_detail))
        if not product:
            product = tls_product
            cpe = tls_cpe
        elif product != tls_product:
            anomalous_identity = True
            behavior_matches = behavior_matches or tls_product

    # 7. Banner vs. cert consistency: banner + cert both confirm same product → +30%
    if (
        banner_claims
        and not tls_upgrade_failed
        and (tls_cert_subject or (tls_cert_san and len(tls_cert_san) > 0))
        and banner_claims in _BANNER_CERT_CONSISTENCY
    ):
        cert_text = " ".join(
            filter(None, [tls_cert_subject or "", " ".join(tls_cert_san or []), tls_cert_issuer or ""])
        )
        for pat in _BANNER_CERT_CONSISTENCY[banner_claims]:
            if pat.search(cert_text):
                scoring.append(
                    ScoringEntry(
                        "banner_cert_match",
                        WEIGHT_BANNER_CERT_CONSISTENCY,
                        f"Banner & cert both confirm: {banner_claims}",
                    )
                )
                break

    # 8b. TTL Override: os_hint=appliance + banner keywords → veto weak Postfix/Exim
    if (
        banner_sid is None
        and product in ("Postfix", "Exim")
        and os_hint
        and ("Cisco" in os_hint or "network appliance" in os_hint.lower())
        and banner
    ):
        for m in _GATEWAY_BANNER_KEYWORDS.finditer(banner):
            keyword = m.group(1).lower()
            override_product = _GATEWAY_KEYWORD_TO_PRODUCT.get(
                keyword, "Network Appliance / Security Gateway"
            )
            product = override_product
            cpe = next((p.cpe for p in EHLO_PROFILES if p.product == override_product), None)
            if not cpe:
                cpe = _product_cpe_fallback(override_product)
            scoring.append(
                ScoringEntry(
                    "ttl_override",
                    WEIGHT_BANNER,  # High weight: banner keyword + TTL 255
                    f"TTL 255 + banner keyword '{keyword}' → {override_product}",
                )
            )
            break

    # 9. Cert software context (Plesk/HestiaCP in Subject/Issuer) → +10%
    cert_text_combined = " ".join(
        filter(None, [tls_cert_subject or "", tls_cert_issuer or ""] + (tls_cert_san or []))
    )
    cert_software_context_str: str | None = None
    if cert_text_combined:
        for pat, (ctx_name, ctx_product) in _CERT_SOFTWARE_CONTEXT:
            if pat.search(cert_text_combined):
                cert_software_context_str = f"{ctx_name} → {ctx_product}"
                scoring.append(
                    ScoringEntry(
                        "cert_software_context",
                        WEIGHT_CERT_SOFTWARE_CONTEXT,
                        cert_software_context_str,
                    )
                )
                if not product:
                    product = ctx_product
                    cpe = next((p.cpe for p in EHLO_PROFILES if p.product == ctx_product), None)
                    if not cpe:
                        cpe = _product_cpe_fallback(ctx_product)
                break

    # 10. Cert domain match (SAN/Subject aligns with target or banner hostname) → +5%
    # Target proves we reached the right server; banner hostname fallback when connecting via IP
    cert_domain_match = False
    cert_match_source: str | None = None
    if cert_text_combined:
        if target_host and _cert_domain_matches_target(cert_text_combined, target_host):
            cert_domain_match = True
            cert_match_source = target_host
        if not cert_domain_match:
            banner_hostname = _hostname_from_banner(banner)
            if banner_hostname and _cert_domain_matches_target(cert_text_combined, banner_hostname):
                cert_domain_match = True
                cert_match_source = banner_hostname
        if cert_domain_match and cert_match_source:
            scoring.append(
                ScoringEntry(
                    "cert_domain_match",
                    WEIGHT_CERT_DOMAIN_MATCH,
                    f"SAN/Subject aligns with target ({cert_match_source})",
                )
            )

    # 11. Behavioral EHLO profile (Jaccard match when banner low/indeterminate)
    beh_product: str | None = None
    beh_sim = 0
    beh_detail: str | None = None
    beh_matched: tuple[str, ...] = ()
    beh_missing: tuple[str, ...] = ()
    ehlo_keys_set = get_ehlo_keys_from_extensions(ehlo_ext) | {
        k.upper() for k in ehlo_prop
    }
    beh_product, beh_sim, beh_detail, beh_matched, beh_missing = match_ehlo_profile(
        ehlo_order, ehlo_ext, ehlo_prop
    )
    raw_beh_product: str | None = beh_product
    raw_beh_sim: int = beh_sim
    # Cloud-first: when banner matched a cloud provider, use only that product's EHLO profile – discard spurious EHLO winners.
    if (
        product
        and product in _CLOUD_PROVIDER_PRODUCTS
        and banner_sid is not None
        and beh_product != product
    ):
        cloud_result = match_ehlo_profile_for_product(
            ehlo_order, ehlo_ext, ehlo_prop, product
        )
        if cloud_result and cloud_result[0] >= 0.35:
            beh_product = product
            beh_sim = round(cloud_result[0] * 100)
            beh_matched = cloud_result[1]
            beh_missing = cloud_result[2]
            sample = ", ".join(sorted(beh_matched)[:6]) if beh_matched else ""
            lacks_str = f"; lacks {', '.join(beh_missing[:3])}" if beh_missing else ""
            beh_detail = f"{sample}{lacks_str}"
    # Plesk/HestiaCP/cPanel/VestaCP context: Enterprise Cloud Gateway EHLO overlap on panel-managed hosts.
    if (
        beh_product == "Enterprise Cloud Gateway"
        and cert_software_context_str
        and any(
            x in (cert_software_context_str or "").lower()
            for x in ("plesk", "hestiacp", "cpanel", "vestacp", "vesta")
        )
    ):
        # Prefer panel-default MTA: VestaCP/HestiaCP → Exim first; Plesk/cPanel → Postfix first
        ctx_lower = (cert_software_context_str or "").lower()
        fallback_order = ("Exim", "Postfix") if ("vesta" in ctx_lower or "hestia" in ctx_lower) else ("Postfix", "Exim")
        for fallback_product in fallback_order:
            fallback_result = match_ehlo_profile_for_product(
                ehlo_order, ehlo_ext, ehlo_prop, fallback_product
            )
            if fallback_result and fallback_result[0] >= 0.35:
                beh_product = fallback_product
                beh_sim = round(fallback_result[0] * 100)
                beh_matched = fallback_result[1]
                beh_missing = fallback_result[2]
                sample = ", ".join(sorted(beh_matched)[:6]) if beh_matched else ""
                lacks_str = f"; lacks {', '.join(beh_missing[:3])}" if beh_missing else ""
                beh_detail = f"{sample}{lacks_str}"
                break
        # If no suitable fallback (shoda < 35 %), ponechat původní beh_product – uživatel vždy vidí EHLO analýzu
    # Variant B: when os_hint suggests Cisco/network appliance (TTL 255) and Enterprise Cloud Gateway match is weak,
    # prefer Network-Appliance profile (avoids wrong attribution for Chinese/appliance servers)
    if (
        beh_product == "Enterprise Cloud Gateway"
        and beh_sim < 70
        and os_hint
        and ("Cisco" in os_hint or "network appliance" in os_hint.lower())
    ):
        app_result = match_ehlo_profile_for_product(
            ehlo_order, ehlo_ext, ehlo_prop, "Network Appliance / Security Gateway"
        )
        if app_result and app_result[0] >= 0.35:
            beh_product = "Network Appliance / Security Gateway"
            beh_sim = round(app_result[0] * 100)
            beh_matched = app_result[1]
            beh_missing = app_result[2]
            sample = ", ".join(sorted(beh_matched)[:6]) if beh_matched else ""
            lacks_str = f"; lacks {', '.join(beh_missing[:3])}" if beh_missing else ""
            beh_detail = f"{sample}{lacks_str}"
    total_before_beh = sum(s.points for s in scoring)
    # Variant B follow-up: when we overrode to Network-Appliance via os_hint, prefer it over weak EHLO
    if (
        beh_product == "Network Appliance / Security Gateway"
        and product == ehlo_product
        and banner_sid is None
    ):
        product = beh_product
        cpe = next((p.cpe for p in EHLO_PROFILES if p.product == beh_product), None)
        pts = min(WEIGHT_BEHAVIORAL_EHLO_PROFILE, 100 - total_before_beh) if beh_sim >= 50 else min(10, 100 - total_before_beh)
        if pts > 0:
            scoring.append(
                ScoringEntry(
                    "behavioral_ehlo_profile",
                    pts,
                    f"{beh_product} profile {beh_sim}% match (weighted)",
                )
            )
            total_before_beh += pts
    # When no banner-based ID (banner_sid is None) and behavioral gives strong match (≥80%),
    # prefer it over weak EHLO keywords (e.g. PIPELINING alone matches Postfix;
    # J-Cloud with ETRN+CRAM-MD5 is more specific).
    if (
        beh_product
        and beh_sim >= 80
        and product == ehlo_product
        and banner_sid is None
    ):
        product = beh_product
        cpe = next((p.cpe for p in EHLO_PROFILES if p.product == beh_product), None)
        pts = min(WEIGHT_BEHAVIORAL_EHLO_STRONG, 100 - total_before_beh)
        if pts > 0:
            scoring.append(
                ScoringEntry(
                    "behavioral_ehlo_profile",
                    pts,
                    f"{beh_product} profile {beh_sim}% match (weighted)",
                )
            )
            total_before_beh += pts

    if (
        beh_product
        and beh_sim >= 35
        and (not product or total_before_beh < 30)
        and product != beh_product  # Skip when first block already set product from behavioral
    ):
        if total_before_beh < 80:  # Only add when not already high
            # Weighted Jaccard thresholds: ≥80% strong, ≥50% standard, ≥35% minimum
            if beh_sim >= 80:
                pts = min(WEIGHT_BEHAVIORAL_EHLO_STRONG, 100 - total_before_beh)
            elif beh_sim >= 50:
                pts = min(WEIGHT_BEHAVIORAL_EHLO_PROFILE, 100 - total_before_beh)
            else:
                pts = min(10, 100 - total_before_beh)  # Weak match
            if pts > 0:
                scoring.append(
                    ScoringEntry(
                        "behavioral_ehlo_profile",
                        pts,
                        f"{beh_product} profile {beh_sim}% match (weighted)",
                    )
                )
                if not product:
                    product = beh_product
                    cpe = next((p.cpe for p in EHLO_PROFILES if p.product == beh_product), None)

    # Canonical behavior for discrepancy display: use beh_product (Behavioral Analysis) when it differs from banner
    if beh_product and product and product != beh_product:
        behavior_matches = beh_product

    # 11b. Kill-switch (Forbidden): X-EXPS/XEXCH50 are Exchange-exclusive (MS-OXSMTP, unixwiz.net).
    # If present, Postfix and Exim are impossible – override immediately.
    _exchange_integrity_note: str | None = None
    exchange_verb_override_applied = False
    _EXCHANGE_FORBIDDEN_VERBS: frozenset[str] = frozenset({"X-EXPS", "XEXCH50"})
    _postfix_or_exim = product and (
        product == "Exim" or product.startswith("Postfix")
    )
    if _EXCHANGE_FORBIDDEN_VERBS & ehlo_keys_set and _postfix_or_exim:
        exchange_verb_override_applied = True
        product = "Microsoft Exchange Server"
        cpe = "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"
        _exchange_integrity_note = (
            "Banner claims Postfix/Exim, but EHLO contains Exchange-exclusive verbs "
            "(X-EXPS/XEXCH50). Identity overridden to Microsoft Exchange."
        )
        scoring.append(
            ScoringEntry(
                "exchange_forbidden_override",
                WEIGHT_BANNER,
                "EHLO has X-EXPS/XEXCH50 (Exchange-exclusive); Postfix/Exim impossible",
            )
        )

    # 11c. Postfix (Default/Stripped): only SIZE, PIPELINING, 8BITMIME + ESMTP banner → min 70% confidence
    if (
        ehlo_keys_set == POSTFIX_STRIPPED_KEYS
        and banner
        and "ESMTP" in (banner.split("\n")[0] if "\n" in banner else banner).upper()
    ):
        if not product or product in ("Postfix", "Postfix (Default/Stripped)"):
            product = "Postfix (Default/Stripped)"
            cpe = "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"
            total_before = sum(s.points for s in scoring)
            pts = max(0, 70 - total_before)
            if pts > 0:
                scoring.append(
                    ScoringEntry(
                        "postfix_default_stripped",
                        pts,
                        "Minimal EHLO (SIZE,PIPELINING,8BITMIME only) + ESMTP banner",
                    )
                )

    # 12. Behavioral discrepancies (banner vs EHLO, banner vs unknown_cmd)
    discrepancies = list(
        check_banner_ehlo_discrepancy(
            banner_claims if banner_claims in BANNER_EXPECTED_EXTENSIONS else None,
            ehlo_keys_set,
        )
    )
    if id_aggressive and unk_product:
        discrepancies.extend(
            check_banner_unknown_cmd_discrepancy(banner_claims, unk_product)
        )
    # Internal domain disclosure: non-Internet suffixes in banner = internal topology leak
    if banner:
        first_line = (banner.split("\n")[0] if "\n" in banner else banner).strip().lower()
        for suffix in (
            ".local",
            ".lan",
            ".internal",
            ".intranet",
            ".private",
            ".priv",
            ".ads",
            ".localdomain",
            ".home",
            ".node",
            ".corp",
        ):
            if suffix in first_line:
                discrepancies.append(
                    f"Internal domain disclosure detected in banner ({suffix})"
                )
                break
    if discrepancies:
        anomalous_identity = True
        behavior_matches = behavior_matches or "EHLO mismatch"

    integrity_note: str | None = _exchange_integrity_note

    # VestaCP/HestiaCP + Exim: EHLO may match Postfix (clean config), but it's panel-managed Exim - suppress false discrepancy
    if (
        cert_software_context_str
        and ("vesta" in (cert_software_context_str or "").lower() or "hestia" in (cert_software_context_str or "").lower())
        and product == "Exim"
        and behavior_matches == "Postfix"
    ):
        anomalous_identity = False
        behavior_matches = cert_software_context_str

    # Plesk: default Postfix often has ETRN, VRFY – behavioral match with Sendmail/Network Appliance is expected, not discrepancy
    if (
        cert_software_context_str
        and "plesk" in (cert_software_context_str or "").lower()
        and product == "Postfix"
        and behavior_matches in ("Sendmail", "Network Appliance / Security Gateway", "Enterprise Cloud Gateway")
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = "Plesk default Postfix often has ETRN/VRFY; behavioral profile consistent."

    # Exim + Enterprise Cloud Gateway: standard Exim EHLO often overlaps that gateway profile
    elif (
        product == "Exim"
        and behavior_matches == "Enterprise Cloud Gateway"
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = "Standard Exim EHLO profile often overlaps Enterprise Cloud Gateway signature; integrity verified."
    # Appliance/Gateway: banner product vs Postfix/Exim-like EHLO — expected stack overlap, not honeypot
    elif (
        product
        and product in _APPLIANCE_PROXY_PRODUCTS
        and behavior_matches in ("Postfix", "Exim")
    ):
        # behavior_matches can be Postfix from EHLO keyword fingerprint while best behavioral profile is still Exim
        _proxy_integrity_same_mta = product == behavior_matches or (
            beh_product is not None
            and _product_identity_key(product or "") == _product_identity_key(beh_product)
        )
        anomalous_identity = False
        behavior_matches = None
        _specific_note = _APPLIANCE_SPECIFIC_INTEGRITY_NOTES.get(product)
        if _specific_note:
            integrity_note = _specific_note
        elif _proxy_integrity_same_mta:
            integrity_note = f"Behavioral profile is consistent with {product}."
        else:
            _label = _APPLIANCE_INTEGRITY_LABELS.get(product)
            if _label is None:
                if product.endswith("Gateway") or product in ("Exim", "Plesk"):
                    _label = product
                else:
                    _label = f"{product} gateway"
            integrity_note = f"Behavioral profile is consistent with {_label}."
    # Postfix (DreamHost VPS): DreamHost runs Postfix; EHLO often matches Postfix or Network Appliance profile
    elif (
        product == "Postfix (DreamHost VPS)"
        and behavior_matches in ("Postfix", "Network Appliance / Security Gateway")
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = "Behavioral profile is consistent with Postfix on DreamHost VPS."
    # Postfix (LWS Hosting): LWS uses robust Postfix config (ETRN, VRFY); Network Appliance profile is valid
    elif (
        product == "Postfix (LWS Hosting)"
        and behavior_matches in ("Postfix", "Network Appliance / Security Gateway")
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = "Behavioral profile is consistent with Postfix on LWS Hosting."
    # Postfix (Etius.jp / WebArena): Japanese hosting; CRAM-MD5+AUTH combo typical for Postfix in Japan
    elif (
        product == "Postfix (Etius.jp / WebArena)"
        and behavior_matches in ("Postfix", "Network Appliance / Security Gateway", "Enterprise Cloud Gateway")
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = "Behavioral profile is consistent with Postfix on Etius.jp (WebArena)."
    # Plain Postfix: weighted EHLO profile "Network Appliance / Security Gateway" matches common RFC extensions
    # (PIPELINING, SIZE, ETRN, DSN, 8BITMIME, …); same overlap as Plesk/DreamHost/LWS cases above.
    elif (
        product
        and (product == "Postfix" or product.startswith("Postfix ("))
        and behavior_matches == "Network Appliance / Security Gateway"
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = (
            "The generic 'Network Appliance / Security Gateway' EHLO profile often overlaps Postfix "
            "(PIPELINING, SIZE, ETRN, DSN, …); this is not by itself evidence of spoofing or a honeypot."
        )
    # Exim: self-signed cert with generic corporate-style DN (OU/O) scores as "Private/Internal Mail Server"
    # while banner and EHLO still identify Exim — same idea as Postfix vs appliance overlap, not honeypot.
    elif (
        product == "Exim"
        and behavior_matches == "Private/Internal Mail Server"
        and tls_cert_self_signed
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = "Banner and EHLO both support Exim; internal-mail identity label is consistent with normal self-managed Exim."

    # Postfix-based cloud providers: Proton Mail etc. openly show Postfix in banner – EHLO match expected
    elif (
        product
        and product in _POSTFIX_BASED_CLOUD_PROVIDERS
        and behavior_matches == "Postfix"
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = "Banner and behavior consistent; provider openly uses Postfix."

    # OS hint (TTL): after final product — generic appliance wording vs product-specific match (+5%).
    if (
        product
        and product not in _CLOUD_PROVIDER_PRODUCTS
        and os_hint
        and "Unknown" not in os_hint
    ):
        hint_os: str | None = None
        if "Linux" in os_hint or "Unix" in os_hint:
            hint_os = "linux"
        elif "Windows" in os_hint:
            hint_os = "windows"
        elif "Cisco" in os_hint:
            hint_os = "cisco"
        if hint_os:
            if product in _GENERIC_OS_HINT_PRODUCTS and hint_os in ("linux", "cisco"):
                scoring.append(
                    ScoringEntry(
                        "os_hint_match",
                        WEIGHT_OS_HINT_CONSISTENCY,
                        f"OS hint ({hint_os}) matches typical appliance environment",
                    )
                )
            else:
                expected_os = _PRODUCT_EXPECTED_OS.get(product)
                if expected_os and hint_os == expected_os:
                    scoring.append(
                        ScoringEntry(
                            "os_hint_match",
                            WEIGHT_OS_HINT_CONSISTENCY,
                            f"OS hint ({hint_os}) matches {product}",
                        )
                    )

    # Universal banner vs behavioral EHLO profile mismatch (any product pair), after integrity suppressions.
    banner_pts_for_discrepancy = sum(s.points for s in scoring if s.method == "banner")
    discrepancy_detected = False
    discrepancy_banner_product: str | None = None
    discrepancy_behavior_product: str | None = None
    if (
        banner_sid is not None
        and beh_product
        and beh_sim >= 50
        and banner_pts_for_discrepancy > 30
        and _product_identity_key(banner_sid.product) != _product_identity_key(beh_product)
        and anomalous_identity
        and not exchange_verb_override_applied
    ):
        discrepancy_detected = True
        discrepancy_banner_product = banner_sid.product
        discrepancy_behavior_product = beh_product
        conflict_penalty = round((beh_sim / 100.0) * WEIGHT_BEHAVIORAL_CONFLICT_MAX)
        if conflict_penalty > 0:
            scoring.append(
                ScoringEntry(
                    "behavioral_conflict",
                    -conflict_penalty,
                    (
                        f"EHLO behavioral profile '{discrepancy_behavior_product}' matches at {beh_sim}% "
                        f"while banner identifies '{discrepancy_banner_product}'"
                    ),
                )
            )

    total_pts = sum(s.points for s in scoring)
    confidence_pct = max(0, min(100, total_pts))
    confidence_label = _confidence_label(confidence_pct)
    recommendation = _build_recommendation(
        hidden_banner,
        confidence_pct,
        confidence_label,
        anomalous_identity,
        identity_mismatch_banner=discrepancy_banner_product if discrepancy_detected else None,
        identity_mismatch_behavior=discrepancy_behavior_product if discrepancy_detected else None,
    )

    behavioral_hint: str | None = None
    if (
        confidence_pct < 40
        and is_generic_esmtp_banner(banner)
        and len(ehlo_keys_set) < 5
        and product not in _CLOUD_PROVIDER_PRODUCTS
        and product != "Postfix (Default/Stripped)"
        and ehlo_keys_set != POSTFIX_STRIPPED_KEYS
        and not exchange_verb_override_applied
    ):
        scoring.append(
            ScoringEntry(
                "identity_blur",
                WEIGHT_IDENTITY_BLUR,
                "Generic banner & minimalist EHLO configuration",
            )
        )
        confidence_pct = max(0, min(100, sum(s.points for s in scoring)))
        confidence_label = "low"
        product = _GENERIC_ESMTP_SERVICE_PRODUCT
        cpe = _normalize_cpe(_GENERIC_ESMTP_SERVICE_CPE)
        version = None
        if raw_beh_product and raw_beh_sim > 0:
            behavioral_hint = f"{raw_beh_product} ({raw_beh_sim}%)"
        discrepancy_detected = False
        discrepancy_banner_product = None
        discrepancy_behavior_product = None
        anomalous_identity = False
        behavior_matches = None
        integrity_note = None
        _beh_like = raw_beh_product or "an indeterminate MTA"
        recommendation = (
            f"Identity is ambiguous. EHLO patterns suggest {_beh_like}-like behavior, "
            "but generic banner and minimal EHLO configuration are typical for hardened "
            "relays or security appliances. Cross-reference with other services "
            "(e.g., ports 445, 3389) to narrow down the host identity."
        )

    # Cloud providers: TTL at anycast networks is unreliable for OS inference – label as "Cloud Infrastructure"
    os_hint_display: str | None = (
        "Cloud Infrastructure" if (product and product in _CLOUD_PROVIDER_PRODUCTS and os_hint) else os_hint
    )

    data_leakage_findings = _collect_data_leakage_findings(
        banner=banner,
        ehlo_raw=ehlo_raw,
        help_response=help_response,
        error_samples=error_samples,
        unknown_cmd_response=unknown_cmd_response,
        tls_cert_subject=tls_cert_subject,
        tls_cert_issuer=tls_cert_issuer,
        tls_cert_san=tls_cert_san,
        target_host=target_host,
    )

    return ServerIdentifyResult(
        product=product,
        version=version,
        cpe=_normalize_cpe(cpe) if cpe else None,
        os=os_str,
        confidence_pct=confidence_pct,
        confidence_label=confidence_label,
        hidden_banner=hidden_banner,
        scoring_matrix=scoring,
        banner=banner,
        ehlo_extensions=ehlo_ext,
        ehlo_proprietary=ehlo_prop,
        ehlo_order=ehlo_order,
        help_response=help_response,
        error_syntax_samples=error_samples,
        unknown_cmd_response=unknown_cmd_response,
        recommendation=recommendation,
        anomalous_identity=anomalous_identity,
        banner_claims=banner_claims,
        behavior_matches=behavior_matches,
        tls_cert_subject=tls_cert_subject,
        tls_cert_issuer=tls_cert_issuer,
        tls_cert_san=tls_cert_san,
        tls_cert_self_signed=tls_cert_self_signed,
        tls_upgrade_failed=tls_upgrade_failed,
        tls_upgrade_error=tls_upgrade_error,
        transport_tls=transport_tls,
        starttls_advertised=starttls_advertised,
        tls_policy=tls_policy,
        tls_cert_warnings=tls_cert_warnings,
        tls_cipher_warnings=tls_cipher_warnings,
        tls_downgrade_findings=tls_downgrade_findings,
        tls_downgrade_probed=tls_downgrade_probed,
        os_hint=os_hint_display,
        behavioral_profile_product=beh_product,
        behavioral_profile_sim=beh_sim,
        behavioral_profile_detail=beh_detail,
        behavioral_discrepancies=tuple(discrepancies),
        latency_avg_ms=latency_avg_ms,
        latency_jitter_ms=latency_jitter_ms,
        cert_domain_match=cert_domain_match,
        cert_software_context=cert_software_context_str,
        behavioral_matched_verbs=beh_matched,
        behavioral_missing_verbs=beh_missing,
        integrity_note=integrity_note,
        data_leakage_findings=data_leakage_findings,
        discrepancy_detected=discrepancy_detected,
        discrepancy_banner_product=discrepancy_banner_product,
        discrepancy_behavior_product=discrepancy_behavior_product,
        behavioral_hint=behavioral_hint,
    )
