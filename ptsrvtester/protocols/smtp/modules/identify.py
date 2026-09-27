"""IDENTIFY — software fingerprinting."""
import ipaddress, re, smtplib, socket, ssl, struct, subprocess, time, dns.resolver
from datetime import datetime, timezone
from base64 import b64decode, b64encode

from ..utils.ptntlmauth.ptntlmauth import get_NegotiateMessage_data, decode_ChallengeMessage_blob

try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
from ..utils.service_identification import identify_service
from ..utils.smtp_fingerprints import (
    ServerIdentifyResult,
    identify_smtp_server,
    _hostname_from_banner,
    _cert_covers_dname,
)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from ..utils.behavior_profiles import PROFILE_MISSING_HINTS
from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "Service Fingerprinting"
__MODULECODE__ = "IDENTIFY"
__ORDER__ = 12


def _probe_ttl_os_hint(e, host: str, port: int) -> str | None:
    """Passive OS fingerprinting via TTL. Infers original TTL (32/64/128/255) from received value."""

    def _ttl_to_hint(received_ttl: int) -> str:
        if 30 <= received_ttl <= 32:
            return f'Likely Linux Container (TTL {received_ttl}, Low TTL)'
        STANDARD_TTL = (64, 128, 255)
        if received_ttl < 33:
            return f'Unknown (TTL {received_ttl}, too few hops to infer)'
        original = 255
        for s in STANDARD_TTL:
            if received_ttl <= s:
                original = s
                break
        if original == 64:
            return f'Likely Linux/Unix (TTL {received_ttl}, inferred 64)'
        if original == 128:
            return f'Likely Windows (TTL {received_ttl}, inferred 128)'
        return f'Likely Cisco/network appliance (TTL {received_ttl}, inferred 255)'

    def _ping_ttl_fallback(targ: str) -> int | None:
        """Fallback: run ping -c 1 and parse TTL from output. Works when IP_RECVTTL ancdata is empty (e.g. cloud LBs)."""
        try:
            proc = subprocess.run(['ping', '-c', '1', '-W', '3', targ], capture_output=True, timeout=5, text=True)
            if proc.returncode != 0:
                return None
            m = re.search('\\bttl[= ](\\d+)\\b', proc.stdout or '', re.I)
            return int(m.group(1)) if m else None
        except (subprocess.SubprocessError, ValueError, OSError):
            return None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.setsockopt(socket.IPPROTO_IP, 12, 1)
        except (OSError, TypeError) as ex:
            if getattr(e.args, 'debug', False):
                e.ptdebug(f'TTL probe: setsockopt IP_RECVTTL failed ({ex})', Out.INFO)
            return None
        sock.connect((host, port))
        try:
            data, ancdata, _flags, _addr = sock.recvmsg(4096, socket.CMSG_SPACE(16))
        except (OSError, AttributeError) as ex:
            if getattr(e.args, 'debug', False):
                e.ptdebug(f'TTL probe: recvmsg failed ({ex})', Out.INFO)
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
        if ttl is None:
            ttl = _ping_ttl_fallback(host)
        if ttl is None:
            return None
        return _ttl_to_hint(ttl)
    except Exception as ex:
        if getattr(e.args, 'debug', False):
            e.ptdebug(f'TTL probe: exception {ex}', Out.INFO)
        return None


def _probe_tls_downgrade(e, host: str, port: int, use_implicit_tls: bool, sni_host: str | None) -> list[str]:
    """Phase 2: Try weak TLS configs. Returns list of findings if server accepts."""
    findings: list[str] = []
    hostname = sni_host or host
    if not hostname or not hostname.strip():
        hostname = host
    connect_tls_direct = use_implicit_tls

    def _try_ctx(name: str, ctx: ssl.SSLContext) -> None:
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=5.0)
            if connect_tls_direct:
                sock_ssl = ctx.wrap_socket(sock, server_hostname=hostname)
                sock_ssl.recv(1024)
                findings.append(name)
            else:
                sock.recv(4096)
                sock.sendall(b'EHLO probe.local\r\n')
                sock.recv(4096)
                sock.sendall(b'STARTTLS\r\n')
                reply = sock.recv(4096).decode(errors='replace')
                if '220' in reply or 'Ready' in reply:
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
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.options |= getattr(ssl, 'OP_NO_TLSv1_1', 0) | getattr(ssl, 'OP_NO_TLSv1_2', 0) | getattr(ssl, 'OP_NO_TLSv1_3', 0)
        _try_ctx('Server accepts TLS 1.0', ctx)
    except Exception:
        pass
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.options |= getattr(ssl, 'OP_NO_TLSv1', 0) | getattr(ssl, 'OP_NO_TLSv1_2', 0) | getattr(ssl, 'OP_NO_TLSv1_3', 0)
        _try_ctx('Server accepts TLS 1.1', ctx)
    except Exception:
        pass
    return findings


def _extract_tls_cert_info(e, smtp: smtplib.SMTP | smtplib.SMTP_SSL) -> tuple[str, str, list[str], bool, list[str], list[str]] | None:
    """Extract Subject, Issuer, SAN, is_self_signed, cert_warnings, cipher_warnings from peer cert.
        Uses getpeercert(binary_form=True) + cryptography when dict form is None (unverified context)."""
    sock = getattr(smtp, 'sock', None)
    if not sock or not isinstance(sock, ssl.SSLSocket):
        return None

    def _analyze_cipher(s: ssl.SSLSocket) -> list[str]:
        """Analyze negotiated cipher/protocol. Returns warnings ordered by severity (CRITICAL, HIGH, MEDIUM, INFO)."""
        try:
            cipher_data = s.cipher()
            if not cipher_data or len(cipher_data) < 2:
                return []
            cipher_name = str(cipher_data[0] or '').upper()
            protocol = str(cipher_data[1] or '').upper()
        except Exception:
            return []
        warnings: list[tuple[int, str]] = []
        if 'SSLv2' in protocol or 'SSLv3' in protocol:
            warnings.append((0, 'CRITICAL: Protocol is ancient and insecure (POODLE, DROWN).'))
        if 'RC4' in cipher_name or 'MD5' in cipher_name:
            warnings.append((0, 'CRITICAL: Broken cryptographic primitives detected.'))
        if 'EXPORT' in cipher_name:
            warnings.append((0, 'CRITICAL: Artificially weakened legacy export cipher (Logjam).'))
        if protocol in ('TLSV1', 'TLSV1.0', 'TLSV1.1'):
            warnings.append((2, 'MEDIUM: Protocol is deprecated. Upgrade to TLS 1.2 or 1.3.'))
        if '3DES' in cipher_name or 'DES' in cipher_name:
            warnings.append((1, 'HIGH: Small block size vulnerable to Sweet32 attack.'))
        if 'CBC' in cipher_name and 'GCM' not in cipher_name and ('CHACHA20' not in cipher_name) and ('POLY1305' not in cipher_name):
            warnings.append((3, 'INFO: Using legacy CBC mode. Consider AEAD (GCM/CHACHA20).'))
        warnings.sort(key=lambda x: x[0])
        return [w[1] for w in warnings]

    def _normalize_cert_text(text: str) -> str:
        """Lowercase and remove wildcard prefix (*.) for predictable matching."""
        if not text:
            return ''
        return text.lower().replace('*.', '')

    def _format_x509_name(x509_tuple: tuple | list) -> str:
        if not x509_tuple:
            return ''
        parts: list[str] = []
        oid_short = {'commonName': 'CN', 'organizationName': 'O', 'countryName': 'C', 'stateOrProvinceName': 'ST', 'localityName': 'L'}
        for item in x509_tuple:
            if isinstance(item, (tuple, list)) and len(item) >= 1:
                pair = item[0] if isinstance(item[0], (tuple, list)) else item
                if isinstance(pair, (tuple, list)) and len(pair) >= 2:
                    name, value = (str(pair[0]), str(pair[1]))
                    short = oid_short.get(name, name)
                    parts.append(f'{short}={value}')
        return ', '.join(parts)

    def _analyze_cert(cert: 'x509.Certificate | None') -> list[str]:
        if cert is None:
            return []
        warnings: list[str] = []
        try:
            if cert.signature_hash_algorithm is not None and cert.signature_hash_algorithm.name == 'sha1':
                warnings.append('SHA-1 signature (deprecated; prefer SHA-256)')
        except Exception:
            pass
        try:
            pubkey = cert.public_key()
            if isinstance(pubkey, rsa.RSAPublicKey) and pubkey.key_size < 2048:
                warnings.append(f'RSA key {pubkey.key_size} bits (< 2048, weak)')
        except Exception:
            pass
        try:
            now = datetime.now(timezone.utc)
            naa = getattr(cert, 'not_valid_after_utc', None)
            if naa is None:
                naa = cert.not_valid_after.replace(tzinfo=timezone.utc)
            nba = getattr(cert, 'not_valid_before_utc', None)
            if nba is None:
                nba = cert.not_valid_before.replace(tzinfo=timezone.utc)
            if now > naa:
                warnings.append('Certificate expired (past not_valid_after)')
            elif now < nba:
                warnings.append('Certificate not yet valid (before not_valid_before)')
            else:
                days_left = (naa - now).days
                if days_left <= 14:
                    warnings.append(f'Certificate expires within {max(0, days_left)} days')
        except Exception:
            pass
        return warnings
    subject, issuer, san_list = ('', '', [])
    cert_obj = None
    cert_dict = None
    try:
        cert_dict = sock.getpeercert()
    except Exception:
        pass
    if cert_dict and isinstance(cert_dict, dict):
        subject = _format_x509_name(cert_dict.get('subject') or ())
        issuer = _format_x509_name(cert_dict.get('issuer') or ())
        for item in cert_dict.get('subjectAltName') or ():
            if not isinstance(item, (tuple, list)) or len(item) < 2:
                continue
            kind = str(item[0]).upper().replace(' ', '')
            val = item[1]
            if kind == 'DNS':
                san_list.append(str(val))
            elif kind in ('EMAIL', 'RFC822', 'RFC822NAME', 'E-MAIL'):
                san_list.append(f'RFC822:{str(val)}')
    elif _HAS_CRYPTOGRAPHY:
        try:
            cert_der = sock.getpeercert(binary_form=True)
            if not cert_der and hasattr(sock, 'get_unverified_chain'):
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
                            san_list.append(f'RFC822:{name.value}')
                        else:
                            v = getattr(name, 'value', None)
                            if isinstance(v, str):
                                san_list.append(v)
                except x509.ExtensionNotFound:
                    pass
        except Exception as ex:
            e.ptdebug(f'TLS cert extraction failed: {ex}', Out.INFO)
            return None
    else:
        return None
    if not subject and (not issuer) and (not san_list):
        return None
    subject = _normalize_cert_text(subject)
    issuer = _normalize_cert_text(issuer)
    san_list = [_normalize_cert_text(str(n)) for n in san_list]
    is_self_signed = bool(subject and issuer and (subject.strip() == issuer.strip()))
    cert_warnings: list[str] = _analyze_cert(cert_obj) if cert_obj else []
    cipher_warnings: list[str] = _analyze_cipher(sock)
    return (subject, issuer, san_list, is_self_signed, cert_warnings, cipher_warnings)


def _pick_mail_domain_for_mx_probe(e, banner: str | None, ehlo_raw: str | None, connect_ip: str) -> str | None:
    """Domain used for MX lookup (``-d`` / resolved / EHLO / banner / PTR registrable)."""
    raw_d = getattr(e.args, 'domain', None)
    if raw_d and str(raw_d).strip():
        return str(raw_d).strip().lower()
    rd = getattr(e.results, 'resolved_domain', None)
    if rd and str(rd).strip():
        return str(rd).strip().lower()
    eh = _get_hostname_from_ehlo_raw(ehlo_raw)
    if eh:
        return (_registrable_domain_psl(eh) or eh).lower()
    bh = _hostname_from_banner(banner)
    if bh:
        return (_registrable_domain_psl(bh) or bh).lower()
    try:
        ipaddress.ip_address(connect_ip)
        ptr_host, _, _ = socket.gethostbyaddr(connect_ip)
        if ptr_host and '.' in ptr_host and _is_valid_hostname(ptr_host.strip()):
            host = ptr_host.strip()
            return (_registrable_domain_psl(host) or host).lower()
    except (OSError, ValueError):
        pass
    return None


def _mx_hostnames_for_ip(e, mail_domain: str, ip: str) -> list[str]:
    """MX exchange names (preference order) whose A/AAAA includes ``ip``."""
    out: list[str] = []
    try:
        answers = dns.resolver.resolve(mail_domain, 'MX', lifetime=6.0)
    except Exception:
        return out
    mx_list = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers], key=lambda x: x[0])
    for _pref, exch in mx_list:
        if not exch or exch in out:
            continue
        hit = False
        for resolver_name in ('A', 'AAAA'):
            try:
                for r in dns.resolver.resolve(exch, resolver_name, lifetime=4.0):
                    if str(r) == ip:
                        hit = True
                        break
            except Exception:
                continue
            if hit:
                break
        if hit:
            out.append(exch)
    return out


def _probe_mx_vs_tls_cert(e, connect_ip: str, banner: str | None, ehlo_raw: str | None, tls_cert_subject: str | None, tls_cert_issuer: str | None, tls_cert_san: list[str]) -> tuple[bool | None, str | None, str | None, str | None]:
    """Returns ``(mx_cert_ok, message, mx_peer_hostname, queried_domain)`` for -id output."""
    mail_dom = _pick_mail_domain_for_mx_probe(e, banner, ehlo_raw, connect_ip)
    cert_blob = ' '.join(filter(None, [tls_cert_subject or '', tls_cert_issuer or ''] + (tls_cert_san or [])))
    if not cert_blob.strip():
        return (None, None, None, None)
    if not mail_dom:
        msg = 'MX vs cert: not checked (no mail domain inferred; pass -d example.com to verify certificate against MX hostnames)'
        return (None, msg, None, None)
    try:
        ipaddress.ip_address(connect_ip)
    except ValueError:
        msg = 'MX vs cert: not checked (target is not an IP — MX A/AAAA match skipped)'
        return (None, msg, None, mail_dom)
    mx_peers = _mx_hostnames_for_ip(e, mail_dom, connect_ip)
    if not mx_peers:
        msg = f'MX vs cert: no MX for "{mail_dom}" resolves to this address ({connect_ip}) — cannot verify operator name in certificate (try -d with the recipient domain)'
        return (False, msg, None, mail_dom)
    primary_mx = mx_peers[0]
    if _cert_covers_dname(cert_blob, primary_mx):
        msg = f'MX vs cert: TLS names cover MX host "{primary_mx}" (preferred MX for "{mail_dom}" whose A/AAAA includes this IP)'
        return (True, msg, primary_mx, mail_dom)
    msg = f'MX vs cert: TLS names do not cover MX host "{primary_mx}" (MX for "{mail_dom}") — possible name mismatch or multi-tenant endpoint'
    return (False, msg, primary_mx, mail_dom)


def _collect_identify_rcpt_error_sample(e, smtp: smtplib.SMTP) -> str | None:
    """MAIL FROM + invalid RCPT TO for error-syntax fingerprinting (default -id)."""
    try:
        smtp.docmd('RSET')
        status_mf, mf_reply = smtp.docmd(f'MAIL FROM:<{_ID_RCPT_ERROR_MAIL_FROM}>')
        if status_mf not in (250, 251):
            return None
        status_rcpt, rcpt_reply = smtp.docmd(f'RCPT TO:<{_ID_RCPT_ERROR_RCPT}>')
        if not rcpt_reply or status_rcpt in (250, 251):
            return None
        if isinstance(rcpt_reply, bytes):
            return rcpt_reply.decode(errors='replace')
        return str(rcpt_reply)
    except Exception:
        return None


def test_server_identify(e) -> ServerIdentifyResult:
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
    tls_policy: str | None = 'n/a'
    id_aggressive = getattr(e.args, 'id_aggressive', False)
    cert_info = None
    mx_cert_ok: bool | None = None
    mx_cert_message: str | None = None
    mx_peer_hostname: str | None = None
    mx_queried_domain: str | None = None
    try:
        host, port = (e.args.target.ip, e.args.target.port)
        os_hint = _probe_ttl_os_hint(e, host, port)
        smtp, status, reply = e.connect()
        if status != 220:
            raise Exception(f"Connection failed: [{status}] {reply.decode(errors='replace')[:200]}")
        banner = reply.decode(errors='replace')
        _, ehlo_bytes = smtp.ehlo(e.fqdn)
        if ehlo_bytes:
            ehlo_raw = ehlo_bytes.decode(errors='replace') if isinstance(ehlo_bytes, bytes) else str(ehlo_bytes or '')
        tls_upgrade_attempted = False
        tls_upgrade_error: str | None = None
        if not isinstance(getattr(smtp, 'sock', None), ssl.SSLSocket) and ehlo_raw and re.search('starttls', ehlo_raw, re.I):
            tls_upgrade_attempted = True
            try:
                ipaddress.ip_address(e.args.target.ip)
                target_is_ip = True
            except ValueError:
                target_is_ip = False
            if not target_is_ip and _is_valid_hostname(e.args.target.ip):
                sni_host = e.args.target.ip.lower().strip()
            else:
                server_hostname = _get_hostname_from_ehlo_raw(ehlo_raw)
                if not server_hostname and banner:
                    first_line = banner.split('\n')[0].split('\r')[0].strip()
                    m = re.match('^220\\s+(\\S+)', first_line)
                    if m and _is_valid_hostname(m.group(1)):
                        server_hostname = m.group(1).lower()
                try:
                    _ = ipaddress.ip_address(e.args.target.ip)
                    sni_host = server_hostname
                    if not sni_host or not sni_host.strip() or sni_host.startswith('.'):
                        try:
                            ptr_host, _, _ = socket.gethostbyaddr(e.args.target.ip)
                            if ptr_host and '.' in ptr_host and _is_valid_hostname(ptr_host):
                                sni_host = ptr_host.lower()
                        except (socket.herror, socket.gaierror, OSError):
                            pass
                    if not sni_host or not sni_host.strip() or sni_host.startswith('.'):
                        sni_host = e.args.target.ip
                except ValueError:
                    sni_host = e.args.target.ip
            try:
                status_stls, _ = smtp.docmd('STARTTLS')
                if status_stls == 220:
                    ctx = ssl._create_unverified_context()
                    sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=sni_host)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    smtp.helo_resp = None
                    smtp.ehlo_resp = None
                    smtp.esmtp_features = {}
                    smtp.does_esmtp = False
            except Exception as ex:
                tls_upgrade_error = str(ex)
                e.ptdebug(f'STARTTLS failed (cert not extracted): {ex}', Out.INFO)
        cert_info = _extract_tls_cert_info(e, smtp)
        if cert_info:
            tls_cert_subject, tls_cert_issuer, tls_cert_san, tls_cert_self_signed, tls_cert_warnings, tls_cipher_warnings = cert_info
        if isinstance(getattr(smtp, 'sock', None), ssl.SSLSocket):
            smtp.ehlo(e.fqdn)
        status_help, help_bytes = smtp.docmd('HELP')
        e._smtp_vv_io('HELP', f'{status_help} {e.bytes_to_str(help_bytes) if help_bytes else ""}')
        if status_help in (211, 214) and help_bytes:
            help_response = help_bytes.decode(errors='replace')
        if not isinstance(getattr(smtp, 'sock', None), ssl.SSLSocket) and ehlo_raw and re.search('starttls', ehlo_raw, re.I):
            status_mail, mail_reply = smtp.docmd('MAIL FROM:<probe@probe.test>')
            reply_str = (mail_reply or b'').decode(errors='replace').upper()
            if status_mail == 530 and ('STARTTLS' in reply_str or 'MUST ISSUE' in reply_str):
                tls_policy = 'mandatory'
            elif status_mail == 250:
                tls_policy = 'opportunistic'
                smtp.docmd('RSET')
        elif isinstance(getattr(smtp, 'sock', None), ssl.SSLSocket):
            pass
        if cert_info is not None or e.args.tls or port == 465 or (ehlo_raw and re.search('starttls', ehlo_raw, re.I)):
            tls_downgrade_probed = True
            sni_host = _get_hostname_from_ehlo_raw(ehlo_raw) if ehlo_raw else None
            if not sni_host and banner:
                m = re.match('^220\\s+(\\S+)', banner.split('\n')[0] if banner else '')
                if m and _is_valid_hostname(m.group(1)):
                    sni_host = m.group(1).lower()
            use_implicit = bool(e.args.tls or port == 465)
            tls_downgrade_findings = _probe_tls_downgrade(e, host, port, use_implicit, sni_host)
        latency_avg_ms = None
        latency_jitter_ms = None
        try:
            rtt_count = 3 if id_aggressive else 1
            rtts: list[float] = []
            for _ in range(rtt_count):
                t0 = time.perf_counter()
                smtp.docmd('RSET')
                rtts.append((time.perf_counter() - t0) * 1000)
            if len(rtts) >= 2:
                latency_avg_ms = sum(rtts) / len(rtts)
                variance = sum(((x - latency_avg_ms) ** 2 for x in rtts)) / len(rtts)
                latency_jitter_ms = variance ** 0.5 if variance >= 0 else 0.0
            elif rtts:
                latency_avg_ms = rtts[0]
        except Exception:
            pass
        target_host = host
        try:
            ipaddress.ip_address(host)
            try:
                ptr_host, _, _ = socket.gethostbyaddr(host)
                if ptr_host and '.' in ptr_host:
                    target_host = ptr_host
            except (socket.herror, socket.gaierror, OSError):
                pass
        except ValueError:
            pass
        if (rcpt_err := _collect_identify_rcpt_error_sample(e, smtp)) is not None:
            error_samples.append(rcpt_err)
        if id_aggressive:
            try:
                smtp.docmd('RSET')
            except Exception:
                pass
            status_vrfy, vrfy_bytes = smtp.docmd('VRFY', 'root')
            if vrfy_bytes and status_vrfy not in (250, 251):
                error_samples.append(vrfy_bytes.decode(errors='replace'))
            status_unk, unk_bytes = smtp.docmd('X-PENTEST')
            e._smtp_vv_io('X-PENTEST', f'{status_unk} {e.bytes_to_str(unk_bytes) if unk_bytes else ""}')
            if unk_bytes:
                unknown_cmd_response = unk_bytes.decode(errors='replace')
            else:
                status_sq, sq_bytes = smtp.docmd('SQUASH')
                if sq_bytes:
                    unknown_cmd_response = sq_bytes.decode(errors='replace')
                else:
                    status_xn, xn_bytes = smtp.docmd('X-NON-EXISTENT')
                    if xn_bytes:
                        unknown_cmd_response = xn_bytes.decode(errors='replace')
                    else:
                        status_fb, fb_bytes = smtp.docmd('FOOBAR')
                        if fb_bytes:
                            unknown_cmd_response = fb_bytes.decode(errors='replace')
            try:
                status_ll, ll_bytes = smtp.docmd('EHLO', 'a' * 1000)
                if ll_bytes and status_ll not in (250, 251):
                    error_samples.append(ll_bytes.decode(errors='replace'))
            except Exception:
                pass
        transport_tls = isinstance(getattr(smtp, 'sock', None), ssl.SSLSocket)
        starttls_advertised = bool(ehlo_raw and re.search('starttls', ehlo_raw, re.I))
        try:
            smtp.quit()
        except Exception:
            pass
        if cert_info:
            mx_cert_ok, mx_cert_message, mx_peer_hostname, mx_queried_domain = _probe_mx_vs_tls_cert(e, host, banner, ehlo_raw, tls_cert_subject, tls_cert_issuer, tls_cert_san)
    except Exception as ex:
        raise
    return identify_smtp_server(banner=banner, ehlo_raw=ehlo_raw, help_response=help_response, error_samples=error_samples, unknown_cmd_response=unknown_cmd_response, id_aggressive=id_aggressive, tls_cert_subject=tls_cert_subject, tls_cert_issuer=tls_cert_issuer, tls_cert_san=tls_cert_san, tls_cert_self_signed=tls_cert_self_signed, tls_upgrade_failed=tls_upgrade_attempted and cert_info is None, tls_upgrade_error=tls_upgrade_error, transport_tls=transport_tls, starttls_advertised=starttls_advertised, tls_policy=tls_policy, tls_cert_warnings=tls_cert_warnings, tls_cipher_warnings=tls_cipher_warnings, tls_downgrade_findings=tls_downgrade_findings, tls_downgrade_probed=tls_downgrade_probed, os_hint=os_hint, target_host=target_host, latency_avg_ms=latency_avg_ms, latency_jitter_ms=latency_jitter_ms, mx_cert_ok=mx_cert_ok, mx_cert_message=mx_cert_message, mx_queried_domain=mx_queried_domain, mx_peer_hostname=mx_peer_hostname)


def _identify_probe_snippet(text: str, max_len: int=120) -> str:
    one = text.replace('\r\n', ' ').replace('\n', ' ').strip()
    if len(one) > max_len:
        return one[:max_len - 3] + '...'
    return one


def _stream_identify_probe_evidence(e, r: ServerIdentifyResult) -> None:
    """HELP / RCPT error / unknown-command samples collected during -id."""
    pp = e._ptprint_raw
    show = not e.use_json
    if not show:
        return
    has_help = bool(r.help_response and r.help_response.strip())
    has_errors = bool(r.error_syntax_samples)
    has_unk = bool(r.unknown_cmd_response and r.unknown_cmd_response.strip())
    if not (has_help or has_errors or has_unk):
        return
    if e.args.debug and not has_errors:
        return
    scored_methods = {s.method for s in r.scoring_matrix or []}
    pp('Protocol probe evidence', bullet_type='TITLE', condition=show, indent=4)
    verbose = e.args.debug
    if has_help and not verbose:
        help_snip = _identify_probe_snippet(r.help_response or '')
        pp(f'HELP: {help_snip}', bullet_type='TITLE' if 'help' in scored_methods else 'TEXT', condition=show, indent=8)
        if verbose and r.help_response and (len((r.help_response or '').strip()) > len(help_snip)):
            for line in (r.help_response or '').replace('\r', '').splitlines()[:10]:
                ln = line.strip()
                if ln:
                    pp(ln, bullet_type='TEXT', condition=show, indent=12)
    for i, sample in enumerate(r.error_syntax_samples or []):
        if not (sample or '').strip():
            continue
        label = 'RCPT error' if i == 0 else f'Error sample {i + 1}'
        snip = _identify_probe_snippet(sample)
        pp(f'{label}: {snip}', bullet_type='TITLE' if 'error_syntax' in scored_methods else 'TEXT', condition=show, indent=8)
        if verbose and len(sample.strip()) > len(snip):
            for line in sample.replace('\r', '').splitlines()[:6]:
                ln = line.strip()
                if ln:
                    pp(ln, bullet_type='TEXT', condition=show, indent=12)
    if has_unk and not verbose:
        snip = _identify_probe_snippet(r.unknown_cmd_response or '')
        pp(f'Unknown command: {snip}', bullet_type='TITLE' if 'behavioral_unknown_cmd' in scored_methods else 'TEXT', condition=show, indent=8)


def _stream_identify_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.identify_error) is not None:
        pp(f'Server identification failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    r = e.results.identify
    if r is None:
        return
    if not show:
        return
    banner_display = (r.banner or '').replace('\r', '').strip()
    if r.hidden_banner and banner_display:
        pp(f'Banner: {banner_display} (Hidden)', bullet_type='TITLE', condition=show, indent=4)
    elif r.banner:
        pp(f'Banner: {banner_display}', bullet_type='TITLE', condition=show, indent=4)
    if r.hidden_banner or not r.scoring_matrix:
        pp('Analyzing behavioral patterns...', bullet_type='TITLE', condition=show, indent=4)
    _stream_identify_probe_evidence(e, r)
    if getattr(r, 'behavioral_profile_product', None) or getattr(r, 'behavioral_profile_detail', None) or getattr(r, 'behavioral_discrepancies', None) or (getattr(r, 'latency_avg_ms', None) is not None) or getattr(r, 'cert_software_context', None):
        pp('Behavioral Analysis', bullet_type='TITLE', condition=show, indent=4)
        if getattr(r, 'behavioral_profile_product', None) and getattr(r, 'behavioral_profile_sim', 0) > 0:
            pp(f"EHLO profile: {r.behavioral_profile_sim}% match '{r.behavioral_profile_product}' {(f'({r.behavioral_profile_detail})' if getattr(r, 'behavioral_profile_detail', None) else '')}", bullet_type='TITLE', condition=show, indent=8)
            matched = getattr(r, 'behavioral_matched_verbs', None) or ()
            missing = getattr(r, 'behavioral_missing_verbs', None) or ()
            product_name = r.behavioral_profile_product or ''
            signature_label = f' ({product_name} signature)' if product_name.strip() else ' (EHLO profile match)'
            if matched:
                pp(f"Matched verbs: {', '.join(matched)}{signature_label}", bullet_type='TITLE', condition=show, indent=8)
            if missing:
                parts = []
                for v in missing:
                    hint = PROFILE_MISSING_HINTS.get((product_name, (v or '').upper()))
                    parts.append(f'{v} ({hint})' if hint else v)
                pp(f"Missing verbs: {', '.join(parts)}", bullet_type='TITLE', condition=show, indent=8)
        if getattr(r, 'latency_avg_ms', None) is not None:
            jitter = getattr(r, 'latency_jitter_ms', None)
            jitter_str = f', jitter {jitter:.0f} ms' if jitter is not None and jitter > 0 else ''
            proxy_hint = ' (possible proxy/filter)' if jitter and jitter > 50 else ' (direct MTA)'
            pp(f'Latency: avg {r.latency_avg_ms:.0f} ms{jitter_str}{proxy_hint}', bullet_type='TITLE', condition=show, indent=8)
        if getattr(r, 'cert_software_context', None):
            pp(f'TLS cert context: {r.cert_software_context}', bullet_type='TEXT', condition=show, indent=8)
        for d in getattr(r, 'behavioral_discrepancies', None) or []:
            pp(d, bullet_type='WARNING', condition=show, indent=8)
    has_tls_cert = bool(r.tls_cert_subject or r.tls_cert_issuer or (r.tls_cert_san and r.tls_cert_san))
    pp('TLS Certificate Info:', bullet_type='TITLE', condition=show, indent=4)
    if has_tls_cert:
        if r.tls_cert_subject:
            pp(f'Subject: {r.tls_cert_subject}', bullet_type='TITLE', condition=show, indent=8)
        if r.tls_cert_san:
            pp(f"SAN: {', '.join(r.tls_cert_san)}", bullet_type='TITLE', condition=show, indent=8)
        if r.tls_cert_issuer:
            pp(f'Issuer: {r.tls_cert_issuer}', bullet_type='TITLE', condition=show, indent=8)
        if r.tls_cert_self_signed:
            pp('Self-signed: yes', bullet_type='VULN', condition=show, indent=8)
        else:
            pp('Self-signed: no', bullet_type='NOTVULN', condition=show, indent=8)
        mx_msg = getattr(r, 'mx_cert_message', None)
        mx_st = getattr(r, 'mx_cert_ok', None)
        if mx_msg:
            if mx_st is True:
                pp(mx_msg, bullet_type='NOTVULN', condition=show, indent=8)
            elif mx_st is False:
                pp(mx_msg, bullet_type='WARNING', condition=show, indent=8)
            else:
                pp(mx_msg, bullet_type='TITLE', condition=show, indent=8)
        if getattr(r, 'tls_policy', None) and r.tls_policy != 'n/a':
            pp(f'TLS policy: {r.tls_policy}', bullet_type='TEXT', condition=show, indent=8)
        if getattr(r, 'tls_downgrade_probed', False):
            downgrade = getattr(r, 'tls_downgrade_findings', None) or []
            if downgrade:
                for w in downgrade:
                    pp(f'TLS downgrade: {w}', bullet_type='WARNING', condition=show, indent=8)
            else:
                pp('TLS downgrade: TLS 1.0/1.1 rejected (Good)', bullet_type='NOTVULN', condition=show, indent=8)
        if getattr(r, 'cert_domain_match', False):
            pp('Cert domain match: SAN aligns with target', bullet_type='NOTVULN', condition=show, indent=8)
        elif has_tls_cert and (r.tls_cert_subject or (r.tls_cert_san and len(r.tls_cert_san) > 0)):
            pp('Cert domain match: no clear SAN/Subject tie to connection target', bullet_type='TITLE', condition=show, indent=8)
        for w in getattr(r, 'tls_cert_warnings', None) or []:
            pp(w, bullet_type='WARNING', condition=show, indent=8)
        for w in getattr(r, 'tls_cipher_warnings', None) or []:
            pp(w, bullet_type='WARNING', condition=show, indent=8)
        if getattr(r, 'os_hint', None):
            pp(f'OS hint: {r.os_hint}', bullet_type='TITLE', condition=show, indent=8)
    else:
        transport_tls = getattr(r, 'transport_tls', False)
        starttls_adv = getattr(r, 'starttls_advertised', False)
        tls_up_fail = getattr(r, 'tls_upgrade_failed', False)
        dbg_tail = f'; {r.tls_upgrade_error}' if e.args.debug and getattr(r, 'tls_upgrade_error', None) else '; try -vv or --verbose'
        if tls_up_fail:
            msg = 'TLS certificate could not be extracted (STARTTLS upgrade or cert parse failed' + dbg_tail + ')'
            pp(msg, bullet_type='VULN', condition=show, indent=8)
        elif transport_tls:
            msg = 'TLS certificate could not be extracted (TLS session; cert parse failed' + dbg_tail + ')'
            pp(msg, bullet_type='VULN', condition=show, indent=8)
        elif starttls_adv:
            pp('TLS certificate could not be extracted', bullet_type='VULN', condition=show, indent=8)
        else:
            pp('STARTTLS not advertised', bullet_type='VULN', condition=show, indent=8)
        if getattr(r, 'tls_downgrade_probed', False):
            downgrade = getattr(r, 'tls_downgrade_findings', None) or []
            if downgrade:
                for w in downgrade:
                    pp(f'TLS downgrade: {w}', bullet_type='WARNING', condition=show, indent=8)
            else:
                pp('TLS downgrade: TLS 1.0/1.1 rejected (Good)', bullet_type='NOTVULN', condition=show, indent=8)
        if getattr(r, 'os_hint', None):
            pp(f'OS hint: {r.os_hint}', bullet_type='TITLE', condition=show, indent=8)
    if r.scoring_matrix:
        pp('Scoring Matrix', bullet_type='TITLE', condition=show, indent=4)
        for s in r.scoring_matrix:
            pts_fmt = f'{s.points:+d}%'
            pp(f"{s.method}: {pts_fmt} {(f'({s.detail})' if s.detail else '')}", bullet_type='TITLE', condition=show, indent=8)
    pp('Identification Result', bullet_type='TITLE', condition=show, indent=4)
    pp(f"Product:     {r.product or 'Unknown'}", bullet_type='TEXT', condition=show, indent=8)
    _bh = getattr(r, 'behavioral_hint', None)
    if _bh and (not str(_bh).rstrip().endswith('(0%)')):
        pp(f'Behavioral hint: {_bh}', bullet_type='TEXT', condition=show, indent=8)
    pp(f"Version:     {r.version or '—'}", bullet_type='TEXT', condition=show, indent=8)
    pp(f'Confidence: {r.confidence_pct}% ({r.confidence_label})', bullet_type='TEXT', condition=show, indent=8)
    if r.cpe:
        pp(f'CPE:        {r.cpe}', bullet_type='TEXT', condition=show, indent=8)
    if getattr(r, 'discrepancy_detected', False) and getattr(r, 'discrepancy_banner_product', None) and getattr(r, 'discrepancy_behavior_product', None):
        pp(f"Discrepancy: Banner claims '{r.discrepancy_banner_product}', behavior matches '{r.discrepancy_behavior_product}'", bullet_type='TITLE', condition=show, indent=8)
    elif r.anomalous_identity:
        pp(f"Discrepancy: Banner claims '{r.banner_claims}', behavior matches '{r.behavior_matches}'", bullet_type='TITLE', condition=show, indent=8)
    if r.integrity_note:
        pp(f'Integrity: {r.integrity_note}', bullet_type='TITLE', condition=show, indent=8)
    if r.recommendation:
        pp(f'Recommendation: {r.recommendation}', bullet_type='TITLE', condition=show, indent=8)
    leaks = getattr(r, 'data_leakage_findings', None) or ()
    if leaks:
        pp('Data Leakage / Privacy', bullet_type='INFO', condition=show, indent=4)
        for leak in leaks:
            src = ', '.join(leak.sources)
            _lk = getattr(leak, 'kind', 'email')
            if _lk == 'internal_hostname':
                if leak.risk == 'high':
                    pp('Information exposure: Internal infrastructure naming leaked in TLS Certificate (Non-routable domain).', bullet_type='WARNING', condition=show, indent=8)
                    pp(f'Extracted: {leak.email} [High Risk]', bullet_type='WARNING', condition=show, indent=8)
                else:
                    pp('Information exposure: Internal infrastructure naming leaked in TLS Certificate (Non-routable domain).', bullet_type='WARNING', condition=show, indent=8)
                    pp(f'Extracted: {leak.email} [Medium Risk]', bullet_type='WARNING', condition=show, indent=8)
                continue
            if leak.risk == 'high':
                pp(f'Sensitive info: E-mail address found in {src} (domain aligns with scan target).', bullet_type='WARNING', condition=show, indent=8)
                pp(f'Extracted: {leak.email} [High Risk]', bullet_type='WARNING', condition=show, indent=8)
            elif leak.risk == 'medium':
                pp(f'Information exposure: Routable address in {src} (domain does not match scan target).', bullet_type='WARNING', condition=show, indent=8)
                pp(f'Extracted: {leak.email} [Medium Risk]', bullet_type='WARNING', condition=show, indent=8)
            else:
                pp(f'Information exposure: Generic, noreply, or non-routable contact in {src}.', bullet_type='TITLE', condition=show, indent=8)
                pp(f'Extracted: {leak.email} [Low Risk]', bullet_type='TITLE', condition=show, indent=8)
        email_leaks = [x for x in leaks if getattr(x, 'kind', 'email') == 'email']
        if email_leaks:
            if any((x.risk == 'high' for x in email_leaks)):
                pp(f'Risk: Address domain matches the scanned host — strong signal for organizational exposure; targeted phishing or brute-force against admin mailboxes is more credible.', bullet_type='TITLE', condition=show, indent=8)
            elif any((x.risk == 'medium' for x in email_leaks)):
                pp(f'Risk: Routable address leaked but not aligned with scan target — still information exposure (e.g. vendor or third-party identity in cert).', bullet_type='TITLE', condition=show, indent=8)
            else:
                pp(f'Risk: Little direct phishing value for noreply / @localhost / reserved domains, but may still indicate default or placeholder TLS/DN setup.', bullet_type='TITLE', condition=show, indent=8)
        if any((getattr(x, 'kind', 'email') == 'internal_hostname' and x.risk in ('medium', 'high') for x in leaks)):
            pp(f'Risk: Exposure of internal hostnames aids in network reconnaissance and targeted internal attacks.', bullet_type='TITLE', condition=show, indent=8)


def run(ctx):
    e = eng(ctx)
    e.args.identify = True
    try:
        e.results.identify = test_server_identify(e)
    except Exception as ex:
        e.results.identify_error = str(ex)
        ctx.out(f"Identify probe failed: {ex}", "ERROR", indent=4)
        return
    _stream_identify_result(e)
