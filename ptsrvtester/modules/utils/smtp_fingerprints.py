"""
SMTP server fingerprinting (PTL-SVC-SMTP-IDENTIFY).
Identifies server software from banner, EHLO, HELP, error syntax, and unknown command responses.
v1.0.5: Behavioral analysis, cert software context, cert domain match.
"""
import re
from dataclasses import dataclass
from typing import Final

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
from .service_identification import ServiceIdentification, identify_service

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

# EHLO fingerprint: (keywords set, order_prefix first 2-3 extensions, product, cpe)
_SMTP_EHLO_FINGERPRINTS: Final[list[tuple[set[str], tuple[str, ...], str, str]]] = [
    # Exchange: X-EXPS, XEXCH50, X-RCPTLIMIT are unique
    ({"X-EXPS", "XEXCH50", "X-LINK2STATE", "XRDST", "X-ANONYMOUSTLS"}, (), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*"),
    ({"X-EXPS", "XEXCH50", "X-LINK2STATE"}, (), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*"),
    ({"X-EXPS", "XEXCH50"}, (), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*"),
    ({"X-RCPTLIMIT"}, (), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*"),
    # Barracuda: X-BARRACUDA-* (check before Postfix – unique signature)
    ({"X-BARRACUDA-GW"}, (), "Barracuda Email Security", "cpe:2.3:h:barracuda:email_security_gateway:*"),
    ({"X-BARRACUDA-BRTS"}, (), "Barracuda Email Security", "cpe:2.3:h:barracuda:email_security_gateway:*"),
    ({"X-BARRACUDA-CPANEL"}, (), "Barracuda Email Security", "cpe:2.3:h:barracuda:email_security_gateway:*"),
    # Postfix: XCLIENT, XFORWARD (CHUNKING removed – used by Exchange/MailStore too)
    ({"Postcow", "XCLIENT"}, (), "Mailcow", "cpe:2.3:a:mailcow:mailcow:*"),
    ({"XCLIENT", "XFORWARD", "CHUNKING"}, ("PIPELINING", "SIZE"), "Postfix", "cpe:2.3:a:postfix:postfix:*"),
    ({"XCLIENT", "CHUNKING"}, (), "Postfix", "cpe:2.3:a:postfix:postfix:*"),
    # Exim: X_E_N_D_O_F_M_E_S_S_A_G_E_
    ({"X_E_N_D_O_F_M_E_S_S_A_G_E_"}, (), "Exim", "cpe:2.3:a:exim:exim:*"),
    # Sendmail: ETRN, DSN, DELIVERBY
    ({"ETRN", "DSN", "DELIVERBY"}, ("ETRN", "DSN"), "Sendmail", "cpe:2.3:a:sendmail:sendmail:*"),
    ({"ETRN", "DELIVERBY"}, ("ETRN",), "Sendmail", "cpe:2.3:a:sendmail:sendmail:*"),
    # Cisco
    ({"AsyncOS", "IronPort"}, (), "Cisco Secure Email (IronPort)", "cpe:2.3:h:cisco:secure_email_gateway:*"),
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
    (re.compile(r".*"), re.compile(r"exchange|outlook|microsoft|exch[0-9]+", re.I), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*"),
    (re.compile(r".*"), re.compile(r"barracuda", re.I), "Barracuda Email Security Gateway", "cpe:2.3:h:barracuda:email_security_gateway:*"),
    (re.compile(r".*"), re.compile(r"ironport|cisco\.com", re.I), "Cisco Secure Email (IronPort)", "cpe:2.3:h:cisco:secure_email_gateway:*"),
    (re.compile(r".*"), re.compile(r"postfix|mailcow|postfix-vm", re.I), "Postfix", "cpe:2.3:a:postfix:postfix:*"),
    (re.compile(r".*"), re.compile(r"exim|exim[0-9]", re.I), "Exim", "cpe:2.3:a:exim:exim:*"),
    (re.compile(r".*"), re.compile(r"sendmail", re.I), "Sendmail", "cpe:2.3:a:sendmail:sendmail:*"),
    (re.compile(r"Let's Encrypt", re.I), re.compile(r".*"), "Postfix", "cpe:2.3:a:postfix:postfix:*"),  # LE often used with Postfix
]

# Self-signed cert fingerprints: (subject_san_pattern, product, cpe, weight) - only when Subject == Issuer
# Ubuntu/Postfix default: CN=ubuntu. Exchange: CN = internal NetBIOS server name (exch01, mailbox02, etc.)
# Corporate/Internal: OU= or O= in subject = air-gapped or internal company mail server
_SMTP_TLS_SELF_SIGNED_FINGERPRINTS: Final[list[tuple[re.Pattern[str], str, str, int]]] = [
    (re.compile(r"CN=ubuntu\b|ubuntumachine|ubuntu\.local", re.I), "Postfix", "cpe:2.3:a:postfix:postfix:*", WEIGHT_TLS_CERT),
    (re.compile(r"exchange|exch[0-9]+|mailbox[0-9]+|cas[0-9]*|edge[0-9]*", re.I), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*", WEIGHT_TLS_CERT),
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
    "NTT Docomo": "linux",
    "Enterprise Cloud Gateway": "linux",
}

# TTL Override: when os_hint indicates network appliance (TTL 255) and raw banner contains
# gateway/appliance keywords but banner_sid is None, veto weak Postfix/Exim from EHLO
_GATEWAY_BANNER_KEYWORDS = re.compile(
    r"\b(gateway|appliance|proxy|firewall|cisco|barracuda|mailstore|fortimail|fortinet)\b",
    re.I,
)
_GATEWAY_KEYWORD_TO_PRODUCT: Final[dict[str, str]] = {
    "mailstore": "MailStore Gateway",
    "barracuda": "Barracuda Email Security",
    "cisco": "Cisco Secure Email (IronPort)",
    "fortimail": "FortiMail",
    "fortinet": "FortiMail",
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
    "PowerMTA (Port25)",  # Often presents Postfix-like EHLO when masquerading
    "Plesk",
    "Exim",  # EHLO often overlaps with NTT Docomo; suppress false discrepancy
})


@dataclass
class ScoringEntry:
    """Single scoring matrix entry."""
    method: str
    points: int
    detail: str | None


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
    tls_upgrade_error: str | None = None  # Exception message when STARTTLS failed (for --debug)
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
                "Sendmail": "cpe:2.3:a:sendmail:sendmail:*",
                "Postfix": "cpe:2.3:a:postfix:postfix:*",
                "Exim": "cpe:2.3:a:exim:exim:*",
                "Microsoft Exchange Server": "cpe:2.3:a:microsoft:exchange_server:*",
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


def _build_recommendation(
    hidden_banner: bool,
    confidence_pct: int,
    confidence_label: str,
    anomalous_identity: bool,
) -> str | None:
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
        "Postfix (Default/Stripped)": "cpe:2.3:a:postfix:postfix:*",
        "Zimbra Collaboration": "cpe:2.3:a:zimbra:collaboration:*",
        "FortiMail": "cpe:2.3:h:fortinet:fortimail:*",
        "Cisco Secure Email (IronPort)": "cpe:2.3:h:cisco:secure_email_gateway:*",
        "NTT Docomo": "cpe:2.3:a:ntt:docomo:*",
        "Network Appliance / Security Gateway": "cpe:2.3:a:network:appliance_mta:*",
        "Enterprise Cloud Gateway": "cpe:2.3:a:enterprise:cloud_gateway:*",
        "MailStore Gateway": "cpe:2.3:a:mailstore:mailstore_gateway:*",
        "Barracuda Email Security": "cpe:2.3:h:barracuda:email_security_gateway:*",
        "Zoho Mail": "cpe:2.3:a:zoho:mail:*",
        "Microsoft 365": "cpe:2.3:a:microsoft:exchange_online:*",
        "Proton Mail": "cpe:2.3:a:protonmail:protonmail:*",
        "Fastmail": "cpe:2.3:a:fastmail:fastmail:*",
        "Yandex Mail": "cpe:2.3:a:yandex:yandex_mail:*",
    }
    return m.get(product, f"cpe:2.3:a:{product.lower().replace(' ', '_').replace('(', '').replace(')', '')}:*")


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

    # 8. OS hint (TTL) consistency: os_hint matches expected platform for product → +5%
    # Skip for cloud providers: TTL at anycast networks is unreliable for OS inference.
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
        expected_os = _PRODUCT_EXPECTED_OS.get(product) if product else None
        if hint_os and expected_os and hint_os == expected_os:
            scoring.append(
                ScoringEntry(
                    "os_hint_match",
                    WEIGHT_OS_HINT_CONSISTENCY,
                    f"OS hint ({hint_os}) matches {product}",
                )
            )

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
    # Cloud-first: when banner matched a cloud provider, use only that product's EHLO profile – discard NTT Docomo etc.
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
    # Plesk/HestiaCP/cPanel/VestaCP context: NTT Docomo/Enterprise Cloud Gateway are Western hosting.
    if (
        beh_product in ("Enterprise Cloud Gateway", "NTT Docomo")
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
    _EXCHANGE_FORBIDDEN_VERBS: frozenset[str] = frozenset({"X-EXPS", "XEXCH50"})
    _postfix_or_exim = product and (
        product == "Exim" or product.startswith("Postfix")
    )
    if _EXCHANGE_FORBIDDEN_VERBS & ehlo_keys_set and _postfix_or_exim:
        product = "Microsoft Exchange Server"
        cpe = "cpe:2.3:a:microsoft:exchange_server:*"
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
            cpe = "cpe:2.3:a:postfix:postfix:*"
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
    # Internal domain disclosure: .local, .lan, .internal in banner = internal topology leak
    if banner:
        first_line = (banner.split("\n")[0] if "\n" in banner else banner).strip().lower()
        for suffix in (".local", ".lan", ".internal", ".localdomain"):
            if suffix in first_line:
                discrepancies.append(
                    f"Internal domain disclosure detected in banner ({suffix})"
                )
                break
    if discrepancies:
        anomalous_identity = True
        behavior_matches = behavior_matches or "EHLO mismatch"

    integrity_note: str | None = None

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

    # Exim + NTT Docomo: standard Exim EHLO often overlaps with NTT Docomo signature
    elif (
        product == "Exim"
        and behavior_matches == "NTT Docomo"
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = "Standard Exim EHLO profile often overlaps with NTT Docomo signature; integrity verified."
    # Appliance/Gateway proxy: MailStore, Barracuda, Cisco, FortiMail often pass Postfix/Exim-like EHLO – expected, not discrepancy
    elif (
        product
        and product in _APPLIANCE_PROXY_PRODUCTS
        and behavior_matches in ("Postfix", "Exim")
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = f"Behavioral profile is consistent with {product} proxy."
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

    # Postfix-based cloud providers: Proton Mail etc. openly show Postfix in banner – EHLO match expected
    elif (
        product
        and product in _POSTFIX_BASED_CLOUD_PROVIDERS
        and behavior_matches == "Postfix"
    ):
        anomalous_identity = False
        behavior_matches = None
        integrity_note = "Banner and behavior consistent; provider openly uses Postfix."

    total_pts = sum(s.points for s in scoring)
    confidence_pct = min(100, total_pts)
    confidence_label = _confidence_label(confidence_pct)
    recommendation = _build_recommendation(hidden_banner, confidence_pct, confidence_label, anomalous_identity)

    # Cloud providers: TTL at anycast networks is unreliable for OS inference – label as "Cloud Infrastructure"
    os_hint_display: str | None = (
        "Cloud Infrastructure" if (product and product in _CLOUD_PROVIDER_PRODUCTS and os_hint) else os_hint
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
    )
