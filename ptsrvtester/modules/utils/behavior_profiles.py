"""
Behavioral fingerprints for SMTP server identification (v1.0.5).
EHLO order profiles, weighted Jaccard similarity, discrepancy detection.
"""
from dataclasses import dataclass
from typing import Final

# Verb weights for weighted Jaccard: distinctive verbs get higher weight.
# Common verbs (SIZE, PIPELINING, STARTTLS): 1.0. Unique identifiers: 5–10.
# CRAM-MD5 + ETRN combo strongly indicates Japanese enterprise / older on-prem gateways.
VERB_WEIGHTS: Final[dict[str, float]] = {
    "CRAM-MD5": 8.0,  # Very specific for older/enterprise gateways
    "ETRN": 7.0,  # Rare in modern cloud (AWS, Google lack it)
    "VRFY": 5.0,  # Typical for network appliances (Cisco/FortiMail); often disabled elsewhere
    "XFORWARD": 10.0,  # Clear Postfix
    "XCLIENT": 10.0,  # Clear Postfix
    "X-EXPS": 10.0,  # Clear Exchange
    "XEXCH50": 10.0,
    "X-RCPTLIMIT": 10.0,  # Microsoft Exchange
    "X-LINK2STATE": 8.0,
    "X_E_N_D_O_F_M_E_S_S_A_G_E_": 15.0,  # Unique Exim identifier (filters)
    "LIMITS": 5.0,  # Exim 4.98+ (rate limiting)
    "DSN": 2.0,
    "CHUNKING": 3.0,
    "ENHANCEDSTATUSCODES": 2.0,
    "8BITMIME": 2.0,
    "X-BARRACUDA-BRTS": 10.0,  # Barracuda signature (even with masked banner)
    "X-BARRACUDA-CPANEL": 10.0,
    "X-BARRACUDA-GW": 10.0,
    "PIPE_CONNECT": 10.0,  # NTT Docomo / early pipelining (draft-harris-early-pipe)
    "HELP": 8.0,  # NTT Docomo / unusual EHLO verb
}

# EHLO profile: (product, set of typical extension keys for Jaccard, required_keys for Postfix/Exchange)
# Keys are case-insensitive
@dataclass
class EHLOProfile:
    product: str
    typical_keys: tuple[str, ...]  # Keys typically present (for Jaccard)
    required_if_claimed: tuple[str, ...]  # If banner claims this product, these should be present
    forbidden_disproves: tuple[str, ...]  # If banner claims X, these keys disprove (e.g. X-EXPS = Exchange, not Postfix)
    cpe: str

# Minimal Postfix (Default/Stripped): SIZE, PIPELINING, 8BITMIME only – common on stripped configs
POSTFIX_STRIPPED_KEYS: Final[frozenset[str]] = frozenset({"SIZE", "PIPELINING", "8BITMIME"})

# Order: more specific first. Postfix without XCLIENT can be Plesk/restricted.
EHLO_PROFILES: Final[list[EHLOProfile]] = [
    EHLOProfile(
        "Postfix (Default/Stripped)",
        ("SIZE", "PIPELINING", "8BITMIME"),
        ("PIPELINING",),
        ("X-EXPS", "XEXCH50"),
        "cpe:2.3:a:postfix:postfix:*",
    ),
    EHLOProfile(
        "Microsoft Exchange Server",
        ("X-EXPS", "X-LINK2STATE", "XEXCH50", "X-RCPTLIMIT", "PIPELINING", "SIZE", "STARTTLS", "AUTH"),
        ("X-EXPS",),
        (),
        "cpe:2.3:a:microsoft:exchange_server:*",
    ),
    EHLOProfile(
        "Postfix",
        ("PIPELINING", "SIZE", "VRFY", "CHUNKING", "XCLIENT", "XFORWARD", "STARTTLS"),
        ("PIPELINING",),
        ("X-EXPS", "XEXCH50"),  # Exchange-specific, disproves Postfix
        "cpe:2.3:a:postfix:postfix:*",
    ),
    # Exim: LIMITS since 4.98 (rate limiting), 8BITMIME common. X_E_N_D_O_F_M_E_S_S_A_G_E_ when CHUNKING enabled.
    EHLOProfile(
        "Exim",
        ("SIZE", "PIPELINING", "STARTTLS", "AUTH", "LIMITS", "8BITMIME", "X_E_N_D_O_F_M_E_S_S_A_G_E_"),
        (),
        (),
        "cpe:2.3:a:exim:exim:*",
    ),
    EHLOProfile(
        "Sendmail",
        ("ETRN", "DSN", "DELIVERBY", "PIPELINING", "SIZE", "STARTTLS"),
        ("ETRN",),
        (),
        "cpe:2.3:a:sendmail:sendmail:*",
    ),
    # Fastmail: standard profile (SIZE, STARTTLS, PIPELINING, CHUNKING) – banner authoritative
    EHLOProfile(
        "Fastmail",
        ("SIZE", "STARTTLS", "PIPELINING", "CHUNKING"),
        (),
        ("X-EXPS", "XEXCH50"),
        "cpe:2.3:a:fastmail:fastmail:*",
    ),
    # Yandex Mail: similar to Google (SIZE, STARTTLS, ENHANCEDSTATUSCODES, CHUNKING)
    EHLOProfile(
        "Yandex Mail",
        ("SIZE", "STARTTLS", "ENHANCEDSTATUSCODES", "CHUNKING"),
        (),
        ("X-EXPS", "XEXCH50"),
        "cpe:2.3:a:yandex:yandex_mail:*",
    ),
    # Zoho Mail: minimal EHLO (SIZE, STARTTLS, SMTPUTF8, 8BITMIME), similar to Amazon SES – banner authoritative
    EHLOProfile(
        "Zoho Mail",
        ("SIZE", "STARTTLS", "SMTPUTF8", "8BITMIME", "PIPELINING"),
        (),
        ("X-EXPS", "XEXCH50"),
        "cpe:2.3:a:zoho:mail:*",
    ),
    EHLOProfile(
        "Amazon SES",
        ("PIPELINING", "SIZE", "STARTTLS", "AUTH"),  # Short list, no ETRN/DSN
        (),
        (),  # Could also match Postfix; use lack of ETRN/DSN as hint
        "cpe:2.3:a:amazon:ses:*",
    ),
    EHLOProfile(
        "Cisco Secure Email (IronPort)",
        ("AsyncOS", "IronPort", "PIPELINING", "SIZE", "STARTTLS"),
        ("AsyncOS", "IronPort"),
        (),
        "cpe:2.3:h:cisco:secure_email_gateway:*",
    ),
    # Barracuda Email Security: X-BARRACUDA-* verbs identify even when banner masked
    EHLOProfile(
        "Barracuda Email Security",
        ("PIPELINING", "SIZE", "STARTTLS", "X-BARRACUDA-GW", "X-BARRACUDA-BRTS", "X-BARRACUDA-CPANEL"),
        ("X-BARRACUDA-GW",),  # when banner claims Barracuda, expect at least GW
        ("X-EXPS", "XEXCH50"),
        "cpe:2.3:h:barracuda:email_security_gateway:*",
    ),
    # MailStore Gateway: archive/proxy often has BINARYMIME, CHUNKING
    EHLOProfile(
        "MailStore Gateway",
        ("PIPELINING", "SIZE", "STARTTLS", "CHUNKING", "BINARYMIME"),
        ("CHUNKING", "BINARYMIME"),
        ("X-EXPS", "XEXCH50"),
        "cpe:2.3:a:mailstore:mailstore_gateway:*",
    ),
    # NTT Docomo: Japanese telco SMTP; PIPE_CONNECT, HELP more common than in standard Exim
    EHLOProfile(
        "NTT Docomo",
        ("PIPELINING", "SIZE", "STARTTLS", "AUTH", "8BITMIME", "PIPE_CONNECT", "HELP"),
        (),
        (),
        "cpe:2.3:a:ntt:docomo:*",
    ),
    # Network-Appliance-MTA: Cisco/FortiMail/IronPort. TTL 255, ETRN+VRFY typical.
    # No CRAM-MD5, no AsyncOS in EHLO. Self-signed cert common.
    EHLOProfile(
        "Network Appliance / Security Gateway",
        ("PIPELINING", "SIZE", "VRFY", "ETRN", "STARTTLS", "DSN", "ENHANCEDSTATUSCODES", "8BITMIME"),
        (),
        ("X-EXPS", "XEXCH50"),
        "cpe:2.3:a:network:appliance_mta:*",
    ),
    # Enterprise Cloud Gateway: ETRN + CRAM-MD5 = on-prem/legacy (often modified Postfix/Sendmail).
    # Forbidden: X-EXPS, XEXCH50 (not Exchange).
    EHLOProfile(
        "Enterprise Cloud Gateway",
        ("PIPELINING", "SIZE", "ETRN", "AUTH", "CRAM-MD5", "ENHANCEDSTATUSCODES", "DSN", "8BITMIME", "STARTTLS"),
        ("ETRN",),
        ("X-EXPS", "XEXCH50"),
        "cpe:2.3:a:enterprise:cloud_gateway:*",
    ),
]

# Banner product -> extensions that must be present (discrepancy if missing). Exported for smtp_fingerprints.
BANNER_EXPECTED_EXTENSIONS: Final[dict[str, tuple[str, ...]]] = {
    "Postfix": ("PIPELINING",),  # XCLIENT/XFORWARD often disabled in Plesk
    "Microsoft Exchange Server": ("X-EXPS", "XEXCH50"),
    "Cisco Secure Email (IronPort)": ("AsyncOS", "IronPort"),
    "Barracuda Email Security": ("X-BARRACUDA-GW",),
}

# Banner product -> extensions that disprove (e.g. banner says Postfix but has X-EXPS = Exchange)
BANNER_FORBIDDEN_EXTENSIONS: Final[dict[str, tuple[str, ...]]] = {
    "Postfix": ("X-EXPS", "XEXCH50", "X-LINK2STATE"),
    "Sendmail": ("X-EXPS", "XEXCH50"),
    "Exim": ("X-EXPS", "XEXCH50"),
}


def ehlo_jaccard_similarity(observed: list[str], expected: tuple[str, ...]) -> float:
    """Standard Jaccard index of extension key sets. Returns 0.0–1.0."""
    if not observed and not expected:
        return 0.0
    a = {k.upper().strip() for k in observed if k}
    b = {k.upper().strip() for k in expected if k}
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union else 0.0


def weighted_jaccard_similarity(
    observed: set[str], expected: tuple[str, ...], verb_weights: dict[str, float]
) -> float:
    """
    Weighted Jaccard: sum(w(x) for x in intersection) / sum(w(x) for x in union).
    Distinctive verbs (ETRN, CRAM-MD5, X-EXPS) get higher weight → stronger match signal.
    """
    if not observed and not expected:
        return 0.0
    a = {k.upper().strip() for k in observed if k}
    b = {k.upper().strip() for k in expected if k}
    if not a or not b:
        return 0.0
    inter = a & b
    union_set = a | b
    inter_weight = sum(verb_weights.get(x, 1.0) for x in inter)
    union_weight = sum(verb_weights.get(x, 1.0) for x in union_set)
    return inter_weight / union_weight if union_weight > 0 else 0.0


def get_ehlo_keys_from_extensions(extensions: list[str]) -> set[str]:
    """Extract extension keys (first token) from EHLO extension lines."""
    keys: set[str] = set()
    for ext in extensions:
        parts = (ext or "").split(None, 1)
        if parts:
            keys.add(parts[0].upper().strip())
    return keys


# Optional verb hints: when a typical key is missing, human-readable hint (product, verb) -> hint.
# Keys: product (exact match from EHLO_PROFILES), verb (UPPERCASE – lookup is case-insensitive).
# Sources: Postfix XCLIENT_README/XFORWARD_README; unixwiz.net (XEXCH50); Sendmail O'Reilly (noetrn);
# Exim CVE-2017-16943 / chunking_advertise_hosts; Cisco ESA docs; AWS SES docs; NTT Docomo (bizmw.com).
PROFILE_MISSING_HINTS: Final[dict[tuple[str, str], str]] = {
    # Postfix
    ("Postfix", "XFORWARD"): "optional; often disabled in Plesk",
    ("Postfix", "XCLIENT"): "optional; often disabled in Plesk",
    ("Postfix", "CHUNKING"): "optional",
    ("Postfix", "VRFY"): "optional; may be disabled",
    # Microsoft Exchange – unixwiz.net, MS docs
    ("Microsoft Exchange Server", "XEXCH50"): "optional; disabled in single-server or behind deep-inspection firewall",
    ("Microsoft Exchange Server", "X-LINK2STATE"): "optional; inter-server only, may be absent on edge relay",
    # Exim – CVE-2017-16943, chunking_advertise_hosts
    ("Exim", "X_E_N_D_O_F_M_E_S_S_A_G_E_"): "optional; CHUNKING/BDAT can be disabled for security",
    # Sendmail – O'Reilly Sendmail 3rd Ed, PrivacyOptions noetrn
    ("Sendmail", "ETRN"): "optional; can be disabled via PrivacyOptions noetrn",
    ("Sendmail", "DSN"): "optional",
    ("Sendmail", "DELIVERBY"): "optional",
    # Amazon SES – AWS docs, minimal cloud EHLO
    ("Amazon SES", "AUTH"): "optional on some relay endpoints",
    # Cisco Secure Email – Cisco TAC doc 217162
    ("Cisco Secure Email (IronPort)", "PIPELINING"): "optional; may be absent in some AsyncOS configs",
    # NTT Docomo – bizmw.com and similar; proprietary or heavily customized Postfix
    ("NTT Docomo", "STARTTLS"): "standard for Docomo Business Relay; absence suggests legacy configuration",
    ("NTT Docomo", "AUTH"): "often missing on inbound MX relays; required on outbound submission",
    ("NTT Docomo", "8BITMIME"): "optional; might be filtered by NTT security middleware",
    # Enterprise Cloud Gateway – ETRN + CRAM-MD5, modified Postfix/Sendmail
    ("Enterprise Cloud Gateway", "CRAM-MD5"): "strong identifier; older/enterprise gateways",
    ("Enterprise Cloud Gateway", "ETRN"): "strong identifier; rare in modern cloud",
    # Network Appliance – Cisco/FortiMail/IronPort
    ("Network Appliance / Security Gateway", "VRFY"): "optional; often disabled on mail relays",
    ("Network Appliance / Security Gateway", "ETRN"): "optional; may be disabled for security",
}


def _build_ehlo_all_keys(
    ehlo_order: list[str], ehlo_extensions: list[str], ehlo_proprietary: list[str]
) -> set[str]:
    """Build the set of all EHLO keys (for Jaccard). Shared by match_ehlo_profile and compute_profile_similarity."""
    all_keys: set[str] = set()
    for k in ehlo_order:
        all_keys.add((k or "").upper())
    for ext in ehlo_extensions:
        parts = (ext or "").split(None, 1)
        if parts:
            all_keys.add((parts[0] or "").upper())
            if (parts[0] or "").upper() == "AUTH" and len(parts) > 1:
                for m in (parts[1] or "").split():
                    m = (m or "").upper().strip()
                    if m and m not in ("AUTH", "="):
                        all_keys.add(m)
    for k in ehlo_proprietary:
        all_keys.add((k or "").upper())
    return all_keys


def match_ehlo_profile_for_product(
    ehlo_order: list[str],
    ehlo_extensions: list[str],
    ehlo_proprietary: list[str],
    product_name: str,
) -> tuple[float, tuple[str, ...], tuple[str, ...]] | None:
    """
    Get full match result for a specific profile. Used for os_hint override (variant B).
    Returns (similarity_0_to_1, matched_verbs, missing_verbs) or None if profile not found / forbidden.
    """
    all_keys = _build_ehlo_all_keys(ehlo_order, ehlo_extensions, ehlo_proprietary)
    profile = next((p for p in EHLO_PROFILES if p.product == product_name), None)
    if not profile:
        return None
    if profile.forbidden_disproves and any(
        (fb or "").upper() in all_keys for fb in profile.forbidden_disproves
    ):
        return None
    sim = weighted_jaccard_similarity(all_keys, profile.typical_keys, VERB_WEIGHTS)
    if sim < 0.35:
        return None
    profile_keys_upper = {k.upper() for k in profile.typical_keys}
    matched = tuple(sorted(all_keys & profile_keys_upper))
    missing = tuple(sorted(profile_keys_upper - all_keys))
    return (sim, matched, missing)


def match_ehlo_profile(
    ehlo_order: list[str], ehlo_extensions: list[str], ehlo_proprietary: list[str]
) -> tuple[str | None, float, str, tuple[str, ...], tuple[str, ...]]:
    """
    Find best EHLO profile match by weighted Jaccard similarity.
    Extracts AUTH methods (CRAM-MD5, PLAIN) for stronger identification.
    Returns (product, similarity_pct, detail, matched_verbs, missing_verbs) or (None, 0.0, "", (), ()).
    """
    all_keys = _build_ehlo_all_keys(ehlo_order, ehlo_extensions, ehlo_proprietary)
    keys_list = list(all_keys)
    best_product: str | None = None
    best_sim = 0.0
    best_detail = ""
    best_matched: tuple[str, ...] = ()
    best_missing: tuple[str, ...] = ()

    for profile in EHLO_PROFILES:
        # Skip if server has forbidden keys (e.g. J-Cloud but has X-EXPS = Exchange)
        if profile.forbidden_disproves:
            if any((fb or "").upper() in all_keys for fb in profile.forbidden_disproves):
                continue
        sim = weighted_jaccard_similarity(all_keys, profile.typical_keys, VERB_WEIGHTS)
        if sim > best_sim and sim >= 0.35:  # Lower threshold: weighted can be stricter
            best_sim = sim
            best_product = profile.product
            profile_keys_upper = {k.upper() for k in profile.typical_keys}
            matched = tuple(sorted(all_keys & profile_keys_upper))
            missing = tuple(sorted(profile_keys_upper - all_keys))
            sample = ", ".join(sorted(keys_list)[:6])
            lacks_str = f"; lacks {', '.join(missing[:3])}" if missing else ""
            best_detail = f"{sample}{lacks_str}"
            best_matched = matched
            best_missing = missing

    if best_product and best_sim >= 0.35:
        return best_product, round(best_sim * 100), best_detail, best_matched, best_missing
    return None, 0.0, "", (), ()


def check_banner_ehlo_discrepancy(
    banner_claims: str | None, ehlo_keys: set[str]
) -> list[str]:
    """
    Check for banner vs EHLO discrepancies (honeypot/proxy detection).
    Returns list of discrepancy messages.
    """
    discrepancies: list[str] = []
    if not banner_claims:
        return discrepancies

    claim_upper = (banner_claims or "").upper()
    # banner_claims can be product name ("Postfix") or banner line - check product substrings
    for product, required in BANNER_EXPECTED_EXTENSIONS.items():
        if product.upper() not in claim_upper:
            continue
        for req in required:
            if req.upper() not in ehlo_keys:
                discrepancies.append(
                    f"Banner claims '{product}', but EHLO lacks '{req}' (typical for {product})"
                )
        break

    for product, forbidden in BANNER_FORBIDDEN_EXTENSIONS.items():
        if product.upper() not in claim_upper:
            continue
        for fb in forbidden:
            if fb.upper() in ehlo_keys:
                # Find which product has this
                for p in EHLO_PROFILES:
                    if fb.upper() in (k.upper() for k in p.typical_keys):
                        discrepancies.append(
                            f"Banner claims '{product}', but EHLO has '{fb}' ({p.product}-specific)"
                        )
                        break
        break

    return discrepancies


def check_banner_unknown_cmd_discrepancy(
    banner_claims: str | None, unk_product: str | None
) -> list[str]:
    """
    Check for banner vs unknown command response discrepancy (honeypot/proxy detection).
    When banner claims product X but unknown command response matches product Y, add warning.
    Returns list of discrepancy messages.
    """
    discrepancies: list[str] = []
    if not banner_claims or not unk_product:
        return discrepancies
    claim_upper = (banner_claims or "").upper()
    banner_product: str | None = None
    for product in set(BANNER_EXPECTED_EXTENSIONS) | set(BANNER_FORBIDDEN_EXTENSIONS):
        if product.upper() in claim_upper:
            banner_product = product
            break
    if not banner_product or banner_product == unk_product:
        return discrepancies
    discrepancies.append(
        f"Banner claims '{banner_product}', but unknown command response matches "
        f"'{unk_product}' (possible honeypot/proxy)"
    )
    return discrepancies
