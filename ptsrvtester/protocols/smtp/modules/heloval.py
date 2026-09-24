"""HELOVAL — HELO/EHLO hostname validation."""
import ipaddress, re, smtplib, socket, ssl, statistics, time





from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "HELO/EHLO hostname validation"
__MODULECODE__ = "HELOVAL"
__ORDER__ = 50


def test_helo_validation(e) -> HeloValidationResult:
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
            smtp, status, reply = e.connect()
            if status != 220:
                return (status, e.bytes_to_str(reply))
            status, reply = smtp.docmd("EHLO", hostname)
            raw = e.bytes_to_str(reply)
            e._smtp_vv_io(f"EHLO {hostname}", f"{status} {raw}" if raw else str(status))
            try:
                smtp.quit()
            except Exception:
                pass
            return (status, raw)
        except Exception as ex:
            e._smtp_vv_io(f"EHLO {hostname}", str(ex))
            return (-1, str(ex))

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

def _stream_helo_validation_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.helo_validation_error) is not None:
        pp(f"HELO validation test failed: {err}", bullet_type="VULN", condition=show, indent=4)
        return
    hv = e.results.helo_validation
    if hv is None:
        return
    if hv.indeterminate:
        pp(f"Indeterminate: {hv.detail or 'Baseline failed'}", bullet_type="WARNING", condition=show, indent=4)
        return
    if hv.vulnerable:
        pp(hv.detail, bullet_type="VULN", condition=show, indent=4)
    elif hv.weak_config:
        pp(hv.detail, bullet_type="WARNING", condition=show, indent=4)
    elif hv.ehlo_bypass:
        pp(hv.detail, bullet_type="VULN", condition=show, indent=4)
    else:
        pp(hv.detail, bullet_type="NOTVULN", condition=show, indent=4)
    if hv.accepted_vectors or hv.rejected_vectors:
        acc = ", ".join(hv.accepted_vectors) if hv.accepted_vectors else "(none)"
        rej = ", ".join(hv.rejected_vectors) if hv.rejected_vectors else "(none)"
        pp(f"Accepted: {acc}", bullet_type="TEXT", condition=show, indent=8)
        pp(f"Rejected: {rej}", bullet_type="TEXT", condition=show, indent=8)

def run(ctx):
    e = eng(ctx)
    try:
        e.results.helo_validation = test_helo_validation(e)
    except Exception as ex:
        e.results.helo_validation_error = str(ex)
        ctx.out(f"HELOVAL failed: {ex}", "ERROR", indent=4)
        return
    _stream_helo_validation_result(e)
