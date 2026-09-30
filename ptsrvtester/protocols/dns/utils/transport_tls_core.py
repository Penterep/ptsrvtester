"""Encrypted-transport (DoT / DoH / DoQ) TLS & certificate probe logic.

Goes deeper than the recon TRANSPORT test (which only reports availability):
opens the TLS/QUIC connection and extracts the negotiated TLS version, cipher and
ALPN, and parses the server certificate (validity, expiry, SAN, hostname match).
Verification needs a hostname target (``-tg <fqdn>``); an IP-only target cannot
match the certificate name.
"""
from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field

from cryptography import x509

from ptsrvtester.protocols.dns.utils.results import VULNS

EXPIRY_WARN_DAYS = 14

DEFAULT_TIMEOUT = 6.0
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class TlsProbe:
    connected: bool = False
    tls_version: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    alpn: str | None = None
    cert_der: bytes | None = None
    verify_ok: bool | None = None
    verify_error: str | None = None
    error: str | None = None


def tls_probe(ip: str, port: int, server_hostname: str, alpn: list[str] | None = None,
              timeout: float = DEFAULT_TIMEOUT) -> TlsProbe:
    """Handshake to ip:port (SNI=server_hostname); grab TLS/cipher/ALPN/cert, then verify."""
    result = TlsProbe()

    grab = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    grab.check_hostname = False
    grab.verify_mode = ssl.CERT_NONE
    if alpn:
        try:
            grab.set_alpn_protocols(alpn)
        except NotImplementedError:
            pass
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            with grab.wrap_socket(sock, server_hostname=server_hostname) as ss:
                result.connected = True
                result.tls_version = ss.version()
                c = ss.cipher()
                if c:
                    result.cipher = c[0]
                    result.cipher_bits = c[2]
                result.alpn = ss.selected_alpn_protocol()
                result.cert_der = ss.getpeercert(binary_form=True)
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
        return result

    verify = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            with verify.wrap_socket(sock, server_hostname=server_hostname):
                pass
        result.verify_ok = True
    except ssl.SSLCertVerificationError as e:
        result.verify_ok = False
        result.verify_error = getattr(e, "verify_message", None) or str(e)
    except Exception as e:
        result.verify_ok = False
        result.verify_error = f"{type(e).__name__}: {e}"
    return result


@dataclass
class CertInfo:
    subject_cn: str | None = None
    issuer_cn: str | None = None
    not_after: datetime.datetime | None = None
    days_left: int | None = None
    expired: bool = False
    san: list[str] = field(default_factory=list)
    error: str | None = None


def _cn(name) -> str | None:
    try:
        attrs = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def cert_details(der: bytes) -> CertInfo:
    info = CertInfo()
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:
        info.error = f"{type(e).__name__}: {e}"
        return info
    info.subject_cn = _cn(cert.subject)
    info.issuer_cn = _cn(cert.issuer)
    try:
        na = cert.not_valid_after_utc
    except AttributeError:
        na = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    info.not_after = na
    info.days_left = (na - datetime.datetime.now(datetime.timezone.utc)).days
    info.expired = info.days_left < 0
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info.san = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        info.san = []
    return info


def tls_verdict(probe: TlsProbe, hostname: str):
    """Return (weak_tls: bool, cert: CertInfo|None, invalid_reason: str|None) from a probe."""
    weak = bool(probe.tls_version) and probe.tls_version in WEAK_TLS_VERSIONS
    cert = cert_details(probe.cert_der) if probe.cert_der else None
    invalid: str | None = None
    if probe.verify_ok is False:
        invalid = probe.verify_error or "certificate verification failed"
    elif cert and cert.expired:
        invalid = "certificate expired"
    return weak, cert, invalid


def is_ip(host: str) -> bool:
    """True if *host* is an IP literal (so it cannot validate a certificate name)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def san_matches(cert: CertInfo, hostname: str) -> bool:
    """Simple SAN match (incl. one-level wildcard); the full chain check is verify_ok."""
    host = hostname.lower().rstrip(".")
    for name in cert.san:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def report_tls(ctx, proto: str, host: str, probe: TlsProbe) -> None:
    """Print the certificate details and emit WEAKTLS / TLSCERT findings for a probe.

    Shared by the DoT and DoH modules; the caller prints the availability header
    and any protocol-specific lines (e.g. HTTP/2). Guards ctx state with the lock.
    """
    weak, cert, invalid = tls_verdict(probe, host)
    if cert and cert.error is None:
        ctx.out(f"Certificate: CN={cert.subject_cn}, issuer={cert.issuer_cn}, "
                f"expires {cert.not_after:%Y-%m-%d} ({cert.days_left}d)", "TEXT", indent=4)
        if cert.san:
            ctx.out(f"SAN: {', '.join(cert.san[:6])}" + (" …" if len(cert.san) > 6 else ""), "TEXT", indent=4)

    if is_ip(host):
        ctx.out("Target is an IP address — pass the full hostname (-tg <fqdn>) to validate the "
                "certificate name; against an IP it can only match an IP-SAN.", "TEXT", indent=4)

    if weak:
        ctx.out(f"Weak TLS version negotiated: {probe.tls_version}.", "VULN", indent=4)
        with ctx.results_lock:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.WeakTls.value,
                "vuln_request": f"{proto} handshake to {host}",
                "vuln_response": f"negotiated {probe.tls_version}",
            })
    if invalid:
        ctx.out(f"Invalid certificate: {invalid}.", "VULN", indent=4)
        with ctx.results_lock:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.TlsCert.value,
                "vuln_request": f"{proto} certificate of {host}",
                "vuln_response": invalid,
            })
    elif probe.verify_ok:
        if cert and 0 <= cert.days_left < EXPIRY_WARN_DAYS:
            ctx.out(f"Certificate valid but expires soon ({cert.days_left}d).", "WARNING", indent=4)
        else:
            ctx.out("Certificate valid and trusted.", "OK", indent=4)
