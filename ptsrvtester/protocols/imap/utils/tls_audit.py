"""IMAP TLS version / cipher scan and rating.

Rating sources (cross-checked; used together because no single RFC lists
every OpenSSL cipher name):

TLS protocol versions
  - RFC 8996 (IETF BCP 195, 2021): TLS 1.0 and 1.1 MUST NOT be used.
  - NIST SP 800-52 Rev. 2: TLS 1.2 is the minimum; TLS 1.3 is recommended.
  - PCI DSS 4.0: TLS 1.2 or higher.
  - TLSRef Intermediate (https://docs.tlsref.org/server-side-tls.html,
    Mozilla Server Side TLS lineage, v5.8+/v6.0): TLS 1.2 + TLS 1.3 only.

Cipher suites
  - TLSRef Intermediate (recommended general-purpose config): TLS 1.3
    AES-GCM / ChaCha20-Poly1305, and TLS 1.2 ECDHE + AEAD only
    (AES-GCM / ChaCha20-Poly1305). DHE suites removed in v5.8 (D(HE)at).
  - RFC 7465: RC4 MUST NOT be used.
  - RFC 9155: MD5 and SHA-1 in TLS MUST NOT be used for signatures;
    SHA-1 HMAC with CBC is treated as a weakness here.
  - RFC 9325 (BCP 195 update): prefer AEAD; avoid static RSA key exchange.
  - SWEET32 (CVE-2016-2183): 3DES/DES as a finding.

Certificate identity
  - RFC 9525 / RFC 6125: a single-label left-most ``*.example.com`` matches
    ``imap.example.com``, not ``example.com`` and not ``a.b.example.com``.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import ssl
import subprocess
import time
from typing import Callable, Iterable

from .results import ImapTlsCipherOffer, ImapTlsVersionScan

_TLS13_SUITES: tuple[str, ...] = (
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
)

# OpenSSL names that match TLSRef Intermediate (TLS 1.2 AEAD + ECDHE).
_TLSREF_INTERMEDIATE_TLS12: frozenset[str] = frozenset(
    {
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
    }
)

_SKIP_CIPHER_TOKENS: tuple[str, ...] = ("PSK", "SRP", "KRB5", "GOST")

_VERSIONS: tuple[tuple[str, object], ...] = (
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
)


def rate_tls_version(label: str) -> tuple[str, str]:
    """Return (ok|warn|bad, reason) for a protocol version the server offered."""
    if label in ("SSL 2.0", "SSL 3.0", "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"):
        return "bad", "RFC 8996 / NIST SP 800-52r2: TLS 1.2 is the minimum"
    if label == "TLS 1.2":
        return "ok", "NIST SP 800-52r2 / TLSRef Intermediate minimum"
    if label == "TLS 1.3":
        return "ok", "NIST SP 800-52r2 / TLSRef recommended"
    return "warn", "unclassified TLS version"


def rate_cipher(name: str, version_label: str) -> tuple[str, str]:
    """Return (ok|warn|bad, reason) for an offered cipher suite."""
    n = (name or "").upper().replace(" ", "")
    if not n:
        return "warn", "empty cipher name"
    if version_label == "TLS 1.3" or n.startswith("TLS_AES_") or n.startswith("TLS_CHACHA20_"):
        if n in {s.upper() for s in _TLS13_SUITES} or n.endswith("_CCM_SHA256"):
            return "ok", "TLS 1.3 AEAD (RFC 8446 / TLSRef)"
        return "warn", "non-standard TLS 1.3 suite"
    if any(tok in n for tok in ("NULL", "EXP", "EXPORT", "ADH", "AECDH", "ANON")):
        return "bad", "NULL / EXPORT / anonymous (no authentication)"
    if "RC4" in n:
        return "bad", "RFC 7465: RC4 MUST NOT be used"
    if "MD5" in n:
        return "bad", "RFC 9155: MD5 MUST NOT be used in TLS"
    if "3DES" in n or "DES-CBC" in n or n.startswith("DES-") or "-DES-" in n:
        return "bad", "SWEET32 (CVE-2016-2183): 3DES/DES"
    if n in _TLSREF_INTERMEDIATE_TLS12 or n in {s.upper() for s in _TLSREF_INTERMEDIATE_TLS12}:
        return "ok", "TLSRef Intermediate (ECDHE + AEAD)"
    aead = any(tok in n for tok in ("GCM", "CHACHA20", "CCM"))
    pfs = n.startswith("ECDHE-") or n.startswith("DHE-")
    if aead and n.startswith("ECDHE-"):
        return "ok", "ECDHE + AEAD (aligned with TLSRef Intermediate)"
    if aead and n.startswith("DHE-"):
        return "warn", "DHE AEAD: TLSRef v5.8 removed DHE (D(HE)at / CVE-2002-20001)"
    if aead and not pfs:
        return "warn", "AEAD without forward secrecy (static RSA kex; RFC 9325)"
    if pfs and ("SHA" in n) and "GCM" not in n and "CHACHA" not in n and "CCM" not in n:
        return "warn", "CBC (Lucky13) / SHA-1 MAC — not in TLSRef Intermediate"
    if not pfs:
        return "warn", "no forward secrecy (static RSA; RFC 9325 / TLSRef)"
    return "warn", "not in TLSRef Intermediate cipher set"


def dns_name_matches(pattern: str, host: str) -> bool:
    """RFC 9525 / RFC 6125 single-label wildcard match (case-insensitive)."""
    p = (pattern or "").strip().lower().rstrip(".")
    h = (host or "").strip().lower().rstrip(".")
    if not p or not h:
        return False
    if p.startswith("*."):
        suffix = p[1:]  # ".example.com"
        if not h.endswith(suffix) or h == suffix[1:]:
            return False
        left = h[: -len(suffix)]
        return bool(left) and "." not in left
    return p == h


def identity_matches(host: str, san_dns: Iterable[str], subject_cn: str | None) -> tuple[bool, str, bool]:
    """Return (ok, detail, used_wildcard)."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        for entry in san_dns:
            if entry.upper().startswith("IP ADDRESS:") or entry.upper().startswith("IP:"):
                addr = entry.split(":", 1)[1].strip()
                if addr == host:
                    return True, f"IP matches certificate SAN ({entry})", False
        return False, f"IP target {host} not listed in certificate SAN", False

    dns_names: list[str] = []
    for entry in san_dns:
        if len(entry) > 4 and entry.upper().startswith("DNS:"):
            dns_names.append(entry[4:].strip())
    names = list(dns_names)
    if subject_cn:
        names.append(subject_cn)

    wildcard = False
    for name in names:
        if dns_name_matches(name, host):
            wildcard = name.startswith("*.")
            if wildcard:
                return True, f"Hostname matches wildcard {name} (RFC 9525)", True
            return True, f"Hostname matches certificate name {name}", False
    cn_disp = subject_cn or "(no CN)"
    san_disp = ", ".join(dns_names[:8]) or "(no DNS SAN)"
    return False, f"Hostname mismatch (target {host} not in SAN/CN; CN={cn_disp}; SAN={san_disp})", False


def rate_rsa_key(bits: int | None) -> tuple[str, str]:
    if bits is None:
        return "warn", "key size unknown"
    if bits < 2048:
        return "bad", "NIST SP 800-57 / CA-Browser Forum: RSA < 2048 is not acceptable"
    # TLSRef Intermediate still allows RSA 2048; NIST SP 800-57 through 2030.
    return "ok", "RSA 2048+ (TLSRef Intermediate / CA-Browser Forum minimum)"


def rate_validity(
    *,
    expired: bool,
    not_yet_valid: bool,
    days_left: int | None,
    vuln_days: int,
    warn_days: int,
) -> tuple[str, str]:
    if expired:
        return "bad", "certificate expired"
    if not_yet_valid:
        return "bad", "certificate not yet valid"
    if days_left is None:
        return "warn", "validity dates unavailable"
    if days_left <= vuln_days:
        return "bad", f"{days_left} days remaining (renewal window)"
    if days_left <= warn_days:
        return "warn", f"{days_left} days remaining"
    return "ok", f"{days_left} days remaining"


def parse_rsa_bits(summary: str | None) -> int | None:
    if not summary:
        return None
    m = re.search(r"RSA\s+(\d+)", summary, re.I)
    if m:
        return int(m.group(1))
    return None


def rate_sig_hash(name: str | None) -> tuple[str, str]:
    if not name:
        return "warn", "signature hash unknown"
    low = name.lower()
    if low in ("md5", "sha1", "sha224"):
        return "bad", "RFC 9155: MD5/SHA-1 signatures MUST NOT be used"
    return "ok", "SHA-256 or stronger"


def _skip_cipher_name(name: str) -> bool:
    up = name.upper()
    return any(tok in up for tok in _SKIP_CIPHER_TOKENS)


def _client_ctx(version, *, tls13: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = version
    ctx.maximum_version = version
    if not tls13:
        ctx.set_ciphers("ALL:eNULL:@SECLEVEL=0")
    return ctx


def _cipher_listed_for_version(proto: str, version) -> bool:
    if version == ssl.TLSVersion.TLSv1_2:
        return proto in ("TLSv1.2", "TLSv1.0", "SSLv3")
    if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        return proto in ("TLSv1.0", "SSLv3")
    return False


def _ciphers_for_version(version) -> list[str]:
    try:
        ctx = _client_ctx(version)
    except Exception:
        return []
    names: list[str] = []
    seen: set[str] = set()
    for item in ctx.get_ciphers() or []:
        name = str(item.get("name") or "")
        proto = str(item.get("protocol") or "")
        if not name or name in seen:
            continue
        if proto == "TLSv1.3" or name.startswith("TLS_AES_") or name.startswith("TLS_CHACHA20_"):
            continue
        if _skip_cipher_name(name):
            continue
        if not _cipher_listed_for_version(proto, version):
            continue
        seen.add(name)
        names.append(name)
    return names


class _ImapBuf:
    def __init__(self, sock: socket.socket, timeout: float):
        self.sock = sock
        self.timeout = timeout
        self.buf = b""
        sock.settimeout(timeout)

    def readline(self) -> str:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        if b"\n" not in self.buf:
            line, self.buf = self.buf, b""
            return line.decode(errors="replace").rstrip("\r\n")
        raw, self.buf = self.buf.split(b"\n", 1)
        return raw.decode(errors="replace").rstrip("\r")

    def send(self, data: str) -> None:
        self.sock.sendall(data.encode() if not data.endswith("\r\n") else data.encode())


def _fmt_imap_line(text: str, limit: int = 240) -> str:
    t = (text or "").replace("\r", "").replace("\n", " ").strip()
    if len(t) > limit:
        t = t[: limit - 3] + "..."
    return t


def prepare_imap_for_tls(
    host: str,
    port: int,
    timeout: float,
    *,
    implicit: bool,
    trace: list[str],
    log: Callable[[str], None] | None = None,
) -> tuple[socket.socket | None, bool, str | None]:
    """TCP connect; for STARTTLS complete the IMAP upgrade.

    Returns (socket ready for wrap_socket, starttls_advertised, error).
    """

    def _log(line: str) -> None:
        trace.append(line)
        if log is not None:
            log(line)

    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if implicit:
            _log(f"TCP connect {host}:{port} (implicit TLS)")
            return sock, None, None
        buf = _ImapBuf(sock, timeout)
        greeting = buf.readline()
        if greeting:
            _log(_fmt_imap_line(greeting))
        buf.send("T1 CAPABILITY\r\n")
        _log("T1 CAPABILITY")
        advertised = False
        while True:
            line = buf.readline()
            if not line:
                break
            _log(_fmt_imap_line(line))
            up = line.upper()
            if "STARTTLS" in up:
                advertised = True
            if line.startswith("T1 "):
                break
        if not advertised:
            return sock, False, "STARTTLS not advertised in CAPABILITY"
        buf.send("T2 STARTTLS\r\n")
        _log("T2 STARTTLS")
        while True:
            line = buf.readline()
            if not line:
                return sock, True, "STARTTLS: empty reply"
            _log(_fmt_imap_line(line))
            if line.startswith("T2 "):
                if line.upper().startswith("T2 OK"):
                    return sock, True, None
                return sock, True, f"STARTTLS rejected: {line}"
        return sock, advertised, "STARTTLS: no tagged reply"
    except Exception as e:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        return None, False, str(e)[:400]


def wrap_and_greet(
    sock: socket.socket,
    ctx: ssl.SSLContext,
    sni: str | None,
    timeout: float,
    *,
    trace: list[str] | None = None,
    log: Callable[[str], None] | None = None,
    read_banner: bool = True,
) -> ssl.SSLSocket:
    ssl_sock = ctx.wrap_socket(sock, server_hostname=sni)
    ssl_sock.settimeout(timeout)
    if read_banner:
        try:
            data = ssl_sock.recv(4096)
        except Exception:
            data = b""
        if data and trace is not None:
            text = data.decode(errors="replace").replace("\r\n", "\n").strip()
            for raw in text.split("\n"):
                line = _fmt_imap_line(raw)
                trace.append(line)
                if log is not None:
                    log(line)
    return ssl_sock


def _handshake_one(
    host: str,
    port: int,
    timeout: float,
    *,
    implicit: bool,
    ctx: ssl.SSLContext,
    sni: str | None,
    log: Callable[[str], None] | None = None,
    capture_imap: list[str] | None = None,
    read_banner: bool = False,
) -> tuple[bool, str | None, ssl.SSLSocket | None]:
    imap_trace = capture_imap if capture_imap is not None else []
    first_imap = capture_imap is not None and not capture_imap
    sock, advertised, err = prepare_imap_for_tls(
        host,
        port,
        timeout,
        implicit=implicit,
        trace=imap_trace if first_imap else [],
        log=log if first_imap else None,
    )
    if sock is None:
        return False, err, None
    if not implicit and advertised is False:
        try:
            sock.close()
        except Exception:
            pass
        return False, err or "STARTTLS not advertised", None
    if not implicit and err:
        try:
            sock.close()
        except Exception:
            pass
        return False, err, None
    try:
        ssl_sock = wrap_and_greet(
            sock,
            ctx,
            sni,
            timeout,
            trace=imap_trace if first_imap else None,
            log=log if first_imap else None,
            read_banner=read_banner and first_imap,
        )
        return True, None, ssl_sock
    except ssl.SSLError as e:
        try:
            sock.close()
        except Exception:
            pass
        return False, str(e)[:240], None
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return False, str(e)[:240], None


def _close_ssl(ssl_sock: ssl.SSLSocket | None) -> None:
    if ssl_sock is None:
        return
    try:
        ssl_sock.close()
    except Exception:
        pass


def _version_supported(
    host: str,
    port: int,
    timeout: float,
    *,
    implicit: bool,
    version,
    tls13: bool,
    sni: str | None,
) -> tuple[bool, str | None]:
    try:
        ctx = _client_ctx(version, tls13=tls13)
    except Exception:
        return False, None
    ok, err, ssl_sock = _handshake_one(
        host, port, timeout, implicit=implicit, ctx=ctx, sni=sni, read_banner=False
    )
    negotiated = None
    if ok and ssl_sock is not None:
        try:
            cd = ssl_sock.cipher()
            if cd:
                negotiated = str(cd[0] or "")
        except Exception:
            pass
        _close_ssl(ssl_sock)
    return ok, negotiated


def _probe_cipher(
    host: str,
    port: int,
    timeout: float,
    *,
    implicit: bool,
    version,
    cipher: str,
    sni: str | None,
) -> bool:
    try:
        ctx = _client_ctx(version, tls13=False)
        ctx.set_ciphers(f"{cipher}:@SECLEVEL=0")
    except ssl.SSLError:
        return False
    ok, _, ssl_sock = _handshake_one(
        host, port, timeout, implicit=implicit, ctx=ctx, sni=sni, read_banner=False
    )
    accepted = False
    if ok and ssl_sock is not None:
        try:
            cd = ssl_sock.cipher()
            accepted = bool(cd) and str(cd[0] or "") == cipher
        except Exception:
            accepted = ok
        _close_ssl(ssl_sock)
    return accepted


def _openssl_tls13_cipher(
    host: str,
    port: int,
    timeout: float,
    *,
    implicit: bool,
    suite: str,
    sni: str,
) -> bool:
    openssl = shutil.which("openssl")
    if not openssl:
        return False
    cmd = [
        openssl,
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-tls1_3",
        "-ciphersuites",
        suite,
        "-servername",
        sni or host,
        "-brief",
    ]
    if not implicit:
        cmd.extend(["-starttls", "imap"])
    try:
        proc = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=max(3.0, timeout),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    blob = (proc.stdout or b"") + (proc.stderr or b"")
    text = blob.decode(errors="replace")
    if suite not in text:
        return False
    return "TLSv1.3" in text or "TLS 1.3" in text


def _negotiate_listed(
    host: str,
    port: int,
    timeout: float,
    *,
    implicit: bool,
    version,
    sni: str | None,
    offered: str,
) -> str | None:
    try:
        ctx = _client_ctx(version)
        ctx.set_ciphers(offered)
    except ssl.SSLError:
        return None
    ok, _, ssl_sock = _handshake_one(
        host, port, timeout, implicit=implicit, ctx=ctx, sni=sni, read_banner=False
    )
    name = None
    if ok and ssl_sock is not None:
        try:
            cd = ssl_sock.cipher()
            if cd:
                name = str(cd[0] or "")
        except Exception:
            pass
        _close_ssl(ssl_sock)
    return name


def _ecdhe_auth(name: str) -> str:
    parts = name.upper().split("-")
    return parts[1] if len(parts) > 1 else ""


def _chacha_aes_pair(ciphers: list[str]) -> tuple[str, str] | None:
    """ECDHE AES-GCM + ECDHE ChaCha with the same auth (RSA or ECDSA).

    Prefer AES128-GCM when present (same pairing testssl.sh uses).
    """
    gcms = [
        c
        for c in ciphers
        if c.upper().startswith("ECDHE-") and "GCM" in c.upper() and "CHACHA" not in c.upper()
    ]
    chachas = [c for c in ciphers if c.upper().startswith("ECDHE-") and "CHACHA20" in c.upper()]
    if not gcms or not chachas:
        return None
    gcms.sort(key=lambda n: (0 if "AES128" in n.upper() else 1, n))
    for gcm in gcms:
        auth = _ecdhe_auth(gcm)
        for chacha in chachas:
            if _ecdhe_auth(chacha) == auth:
                return gcm, chacha
    return gcms[0], chachas[0]


def _cipher_order(
    host: str,
    port: int,
    timeout: float,
    *,
    implicit: bool,
    version,
    ciphers: list[str],
    sni: str | None,
    log: Callable[[str], None] | None = None,
) -> tuple[str | None, str | None]:
    """Overall server vs client order, then ChaCha-vs-AES if both exist.

    The ChaCha note matches testssl.sh: overall still *server* order (weak
    suites lose to GCM), but if the client lists ChaCha before AES-GCM the
    server will pick ChaCha (mobile / no AES-NI).
    """
    if len(ciphers) < 2:
        return None, None
    a, b = ciphers[0], ciphers[-1]
    if a == b:
        return None, None

    def _pick(offered: str, label: str) -> str | None:
        if log is not None:
            log(f"TLS ClientHello cipher-order {label}")
        name = _negotiate_listed(
            host, port, timeout, implicit=implicit, version=version, sni=sni, offered=offered
        )
        if log is not None:
            log(f"negotiated {name or 'n/a'}")
        return name

    p1 = _pick(f"{a}:{b}:@SECLEVEL=0", f"{a} then {b}")
    p2 = _pick(f"{b}:{a}:@SECLEVEL=0", f"{b} then {a}")
    if not p1 or not p2:
        return None, None
    overall_server = p1 == p2
    overall_client = p1 == a and p2 == b

    chacha_follows_client = False
    pair = _chacha_aes_pair(ciphers)
    if pair is not None:
        gcm, chacha = pair
        g_first = _pick(f"{gcm}:{chacha}:@SECLEVEL=0", f"{gcm} then {chacha}")
        c_first = _pick(f"{chacha}:{gcm}:@SECLEVEL=0", f"{chacha} then {gcm}")
        chacha_follows_client = g_first == gcm and c_first == chacha

    if overall_server and chacha_follows_client:
        return "server", "server prioritizes ChaCha ciphers when preferred by clients"
    if overall_server:
        return "server", "server selects a fixed preferred suite"
    if overall_client:
        return "client", "server honors the client's cipher order"
    if chacha_follows_client:
        return "server", "server prioritizes ChaCha ciphers when preferred by clients"
    return "mixed", "server preference depends on the offered set"


def scan_tls_versions(
    host: str,
    port: int,
    timeout: float,
    *,
    implicit: bool,
    sni: str | None,
    log: Callable[[str], None] | None = None,
) -> tuple[ImapTlsVersionScan, ...]:
    """Probe offered TLS versions and every accepted cipher suite."""
    out: list[ImapTlsVersionScan] = []
    sni_name = sni or host
    probe_timeout = min(timeout, 5.0)

    def _tls_log(msg: str) -> None:
        if log is not None:
            log(msg)

    for label, version in _VERSIONS:
        tls13 = label == "TLS 1.3"
        t0 = time.perf_counter()
        offered, preferred = _version_supported(
            host,
            port,
            probe_timeout,
            implicit=implicit,
            version=version,
            tls13=tls13,
            sni=sni_name,
        )
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        _tls_log(f"TLS ClientHello {label} (all suites)")
        if not offered:
            _tls_log(f"handshake refused ({elapsed_ms} ms)")
            continue
        extra = f" cipher={preferred}" if preferred else ""
        _tls_log(f"handshake accepted{extra} ({elapsed_ms} ms)")
        ver_rating, ver_reason = rate_tls_version(label)
        offers: list[ImapTlsCipherOffer] = []
        order = None
        order_note = None
        if tls13:
            order = None
            order_note = "not configured (TLS 1.3 has no server cipher order)"
            seen: set[str] = set()
            if preferred:
                r, why = rate_cipher(preferred, label)
                offers.append(ImapTlsCipherOffer(preferred, r, why))
                seen.add(preferred)
            for suite in _TLS13_SUITES:
                if suite in seen:
                    continue
                ok = _openssl_tls13_cipher(
                    host,
                    port,
                    probe_timeout,
                    implicit=implicit,
                    suite=suite,
                    sni=sni_name,
                )
                if ok:
                    _tls_log(f"TLS ClientHello TLS 1.3 ciphersuites={suite}")
                    _tls_log(f"handshake accepted ({suite})")
                    r, why = rate_cipher(suite, label)
                    offers.append(ImapTlsCipherOffer(suite, r, why))
                    seen.add(suite)
        else:
            names = _ciphers_for_version(version)
            for cipher in names:
                ok = _probe_cipher(
                    host,
                    port,
                    probe_timeout,
                    implicit=implicit,
                    version=version,
                    cipher=cipher,
                    sni=sni_name,
                )
                if ok:
                    _tls_log(f"TLS ClientHello {label} cipher={cipher}")
                    _tls_log(f"handshake accepted ({cipher})")
                    r, why = rate_cipher(cipher, label)
                    offers.append(ImapTlsCipherOffer(cipher, r, why))
            if len(offers) >= 2:
                order, order_note = _cipher_order(
                    host,
                    port,
                    probe_timeout,
                    implicit=implicit,
                    version=version,
                    ciphers=[c.name for c in offers],
                    sni=sni_name,
                    log=_tls_log,
                )
        out.append(
            ImapTlsVersionScan(
                version=label,
                offered=True,
                rating=ver_rating,
                rating_reason=ver_reason,
                cipher_order=order,
                cipher_order_note=order_note,
                ciphers=tuple(offers),
            )
        )
    return tuple(out)


def normalize_tls_label(ver: str | None) -> str | None:
    if not ver:
        return None
    raw = ver.strip()
    mapping = {
        "SSLV2": "SSL 2.0",
        "SSLV3": "SSL 3.0",
        "TLSV1": "TLS 1.0",
        "TLSV1.0": "TLS 1.0",
        "TLSV1.1": "TLS 1.1",
        "TLSV1.2": "TLS 1.2",
        "TLSV1.3": "TLS 1.3",
        "TLS 1.0": "TLS 1.0",
        "TLS 1.1": "TLS 1.1",
        "TLS 1.2": "TLS 1.2",
        "TLS 1.3": "TLS 1.3",
    }
    return mapping.get(raw.upper(), raw)


def fallback_version_scan(tls_version: str | None, cipher_name: str | None) -> tuple[ImapTlsVersionScan, ...]:
    label = normalize_tls_label(tls_version)
    if not label:
        return ()
    vr, vwhy = rate_tls_version(label)
    ciphers: tuple[ImapTlsCipherOffer, ...] = ()
    if cipher_name:
        cr, cwhy = rate_cipher(cipher_name, label)
        ciphers = (ImapTlsCipherOffer(cipher_name, cr, cwhy),)
    note = "not configured (TLS 1.3 has no server cipher order)" if label == "TLS 1.3" else None
    return (
        ImapTlsVersionScan(
            version=label,
            offered=True,
            rating=vr,
            rating_reason=vwhy,
            cipher_order=None,
            cipher_order_note=note,
            ciphers=ciphers,
        ),
    )


def connection_mode_label(*, implicit: bool, starttls_advertised: bool | None, handshake_ok: bool) -> str:
    if implicit:
        return "Implicit TLS"
    if starttls_advertised:
        return "STARTTLS"
    if handshake_ok:
        return "STARTTLS"
    return "No certificate"


def rating_to_bullet(level: str) -> str:
    return {"ok": "NOTVULN", "bad": "VULN", "warn": "WARNING"}.get(level, "TITLE")
