import ipaddress, re, smtplib, socket, ssl, struct, subprocess, time, dns.resolver
from datetime import datetime, timezone
from base64 import b64decode, b64encode

from ....ptntlmauth.ptntlmauth import get_NegotiateMessage_data, decode_ChallengeMessage_blob

try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
from ...utils import ptprinthelper
from ...utils.service_identification import identify_service
from ...utils.smtp_fingerprints import (
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

from ..helpers import *
from ..results import *
from ..registry import *


class ReconMixin:

    def auth_ntlm(self, smtp: smtplib.SMTP) -> NTLMResult:
        """
        Performs NTLM authentication to extract internal server
        information from server's challenge response.
        OWASP: Common finding on MS Exchange - exposes domain/hostname.
        """
        ntlm = None
        try:
            code, resp = smtp.docmd("AUTH NTLM")
            if code == 334:
                smtp.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
                code, resp = smtp.getreply()
                ntlm = decode_ChallengeMessage_blob(b64decode(resp))
        except (
            smtplib.SMTPException,
            ValueError,
            TypeError,
            KeyError,
            struct.error,
            UnicodeDecodeError,
        ):
            ntlm = None

        if ntlm is None:
            self.ptdebug(
                f"Server is not vulnerable to information disclosure via NTLM authentication",
                Out.NOTVULN,
            )
            return NTLMResult(False, None)

        self.ptdebug(
            f"Server is vulnerable to information disclosure via NTLM authentication", Out.VULN
        )
        # OWASP: flag internal domain/hostname (common on MS Exchange)
        internal_hints = (
            ".local",
            ".internal",
            ".intranet",
            ".corp",
            ".lan",
            ".localdomain",
            ".private",
            ".priv",
            ".ads",
        )
        domain_str = (ntlm.netbios_domain or "") + (ntlm.dns_domain or "")
        if any(h in (domain_str or "").lower() for h in internal_hints):
            self.ptdebug(
                "[*] Internal domain/hostname disclosed (common MS Exchange finding)",
                Out.VULN,
            )
        self.ptdebug(f"Target name: {ntlm.target_name}")
        self.ptdebug(f"NetBios domain name: {ntlm.netbios_domain}")
        self.ptdebug(f"NetBios computer name: {ntlm.netbios_computer}")
        self.ptdebug(f"DNS domain name: {ntlm.dns_domain}")
        self.ptdebug(f"DNS computer name: {ntlm.dns_computer}")
        self.ptdebug(f"DNS tree: {ntlm.dns_tree}")
        self.ptdebug(f"OS version: {ntlm.os_version}")

        return NTLMResult(True, ntlm)

    def _probe_ttl_os_hint(self, host: str, port: int) -> str | None:
        """Passive OS fingerprinting via TTL. Infers original TTL (32/64/128/255) from received value."""
        def _ttl_to_hint(received_ttl: int) -> str:
            # Standard initial TTLs (32, 64, 128, 255). Infer original by nearest higher value.
            # TTL 30–32: Virtuozzo/OpenVZ containers (v1.0.5).
            # Received TTL 33–64 → original 64 (Linux/Unix) ~99% confidence.
            if 30 <= received_ttl <= 32:
                return f"Likely Linux Container (TTL {received_ttl}, Low TTL)"
            STANDARD_TTL = (64, 128, 255)  # 32 omitted – rare for SMTP
            if received_ttl < 33:
                return f"Unknown (TTL {received_ttl}, too few hops to infer)"
            original = 255
            for s in STANDARD_TTL:
                if received_ttl <= s:
                    original = s
                    break
            if original == 64:
                return f"Likely Linux/Unix (TTL {received_ttl}, inferred 64)"
            if original == 128:
                return f"Likely Windows (TTL {received_ttl}, inferred 128)"
            return f"Likely Cisco/network appliance (TTL {received_ttl}, inferred 255)"

        def _ping_ttl_fallback(targ: str) -> int | None:
            """Fallback: run ping -c 1 and parse TTL from output. Works when IP_RECVTTL ancdata is empty (e.g. cloud LBs)."""
            try:
                proc = subprocess.run(
                    ["ping", "-c", "1", "-W", "3", targ],
                    capture_output=True,
                    timeout=5,
                    text=True,
                )
                if proc.returncode != 0:
                    return None
                # Typical: "64 bytes from 153.92.246.223: icmp_seq=1 ttl=54 time=..."
                m = re.search(r"\bttl[= ](\d+)\b", proc.stdout or "", re.I)
                return int(m.group(1)) if m else None
            except (subprocess.SubprocessError, ValueError, OSError):
                return None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                # IP_RECVTTL = 12 on Linux; enables TTL in ancillary data
                sock.setsockopt(socket.IPPROTO_IP, 12, 1)
            except (OSError, TypeError) as e:
                if getattr(self.args, "debug", False):
                    self.ptdebug(f"TTL probe: setsockopt IP_RECVTTL failed ({e})", Out.INFO)
                return None
            sock.connect((host, port))
            try:
                data, ancdata, _flags, _addr = sock.recvmsg(4096, socket.CMSG_SPACE(16))
            except (OSError, AttributeError) as e:
                if getattr(self.args, "debug", False):
                    self.ptdebug(f"TTL probe: recvmsg failed ({e})", Out.INFO)
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
            if ttl is None and getattr(self.args, "debug", False):
                self.ptdebug(
                    f"TTL probe: no TTL in ancdata (len={len(ancdata)}); cmsgs={[(c[0],c[1],bool(c[2])) for c in ancdata]}",
                    Out.INFO,
                )
            if ttl is None:
                ttl = _ping_ttl_fallback(host)
                if ttl is not None and getattr(self.args, "debug", False):
                    self.ptdebug(f"TTL probe: fallback ping returned TTL={ttl}", Out.INFO)
            if ttl is None:
                return None
            return _ttl_to_hint(ttl)
        except Exception as e:
            if getattr(self.args, "debug", False):
                self.ptdebug(f"TTL probe: exception {e}", Out.INFO)
            return None

    def _probe_tls_downgrade(
        self, host: str, port: int, use_implicit_tls: bool, sni_host: str | None
    ) -> list[str]:
        """Phase 2: Try weak TLS configs. Returns list of findings if server accepts."""
        findings: list[str] = []
        hostname = sni_host or host
        if not hostname or not hostname.strip():
            hostname = host
        connect_tls_direct = use_implicit_tls  # True = port 465 or --tls; False = STARTTLS

        def _try_ctx(name: str, ctx: ssl.SSLContext) -> None:
            sock = None
            try:
                sock = socket.create_connection((host, port), timeout=5.0)
                if connect_tls_direct:
                    sock_ssl = ctx.wrap_socket(sock, server_hostname=hostname)
                    sock_ssl.recv(1024)
                    findings.append(name)
                else:
                    # STARTTLS path: read 220, send EHLO, read 250, send STARTTLS, wrap
                    sock.recv(4096)
                    sock.sendall(b"EHLO probe.local\r\n")
                    sock.recv(4096)
                    sock.sendall(b"STARTTLS\r\n")
                    reply = sock.recv(4096).decode(errors="replace")
                    if "220" in reply or "Ready" in reply:
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

        # TLS 1.0 only
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0) | getattr(ssl, "OP_NO_TLSv1_2", 0) | getattr(ssl, "OP_NO_TLSv1_3", 0)
            _try_ctx("Server accepts TLS 1.0", ctx)
        except Exception:
            pass

        # TLS 1.1 only
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0) | getattr(ssl, "OP_NO_TLSv1_2", 0) | getattr(ssl, "OP_NO_TLSv1_3", 0)
            _try_ctx("Server accepts TLS 1.1", ctx)
        except Exception:
            pass

        return findings

    def _extract_tls_cert_info(
        self, smtp: smtplib.SMTP | smtplib.SMTP_SSL
    ) -> tuple[str, str, list[str], bool, list[str], list[str]] | None:
        """Extract Subject, Issuer, SAN, is_self_signed, cert_warnings, cipher_warnings from peer cert.
        Uses getpeercert(binary_form=True) + cryptography when dict form is None (unverified context)."""
        sock = getattr(smtp, "sock", None)
        if not sock or not isinstance(sock, ssl.SSLSocket):
            return None

        def _analyze_cipher(s: ssl.SSLSocket) -> list[str]:
            """Analyze negotiated cipher/protocol. Returns warnings ordered by severity (CRITICAL, HIGH, MEDIUM, INFO)."""
            try:
                cipher_data = s.cipher()
                if not cipher_data or len(cipher_data) < 2:
                    return []
                cipher_name = str(cipher_data[0] or "").upper()
                protocol = str(cipher_data[1] or "").upper()
            except Exception:
                return []
            warnings: list[tuple[int, str]] = []  # (priority: 0=critical, 1=high, 2=medium, 3=info), text
            # CRITICAL: SSLv2, SSLv3
            if "SSLv2" in protocol or "SSLv3" in protocol:
                warnings.append((0, "CRITICAL: Protocol is ancient and insecure (POODLE, DROWN)."))
            # CRITICAL: RC4, MD5
            if "RC4" in cipher_name or "MD5" in cipher_name:
                warnings.append((0, "CRITICAL: Broken cryptographic primitives detected."))
            # CRITICAL: EXPORT
            if "EXPORT" in cipher_name:
                warnings.append((0, "CRITICAL: Artificially weakened legacy export cipher (Logjam)."))
            # MEDIUM: TLS 1.0, 1.1
            if protocol in ("TLSV1", "TLSV1.0", "TLSV1.1"):
                warnings.append((2, "MEDIUM: Protocol is deprecated. Upgrade to TLS 1.2 or 1.3."))
            # HIGH: 3DES, DES (DES-CBC3 = 3DES in OpenSSL naming)
            if "3DES" in cipher_name or "DES" in cipher_name:
                warnings.append((1, "HIGH: Small block size vulnerable to Sweet32 attack."))
            # INFO: CBC without AEAD (GCM/CHACHA20)
            if "CBC" in cipher_name and "GCM" not in cipher_name and "CHACHA20" not in cipher_name and "POLY1305" not in cipher_name:
                warnings.append((3, "INFO: Using legacy CBC mode. Consider AEAD (GCM/CHACHA20)."))
            warnings.sort(key=lambda x: x[0])
            return [w[1] for w in warnings]

        def _normalize_cert_text(text: str) -> str:
            """Lowercase and remove wildcard prefix (*.) for predictable matching."""
            if not text:
                return ""
            return text.lower().replace("*.", "")

        def _format_x509_name(x509_tuple: tuple | list) -> str:
            if not x509_tuple:
                return ""
            parts: list[str] = []
            oid_short = {"commonName": "CN", "organizationName": "O", "countryName": "C", "stateOrProvinceName": "ST", "localityName": "L"}
            for item in x509_tuple:
                if isinstance(item, (tuple, list)) and len(item) >= 1:
                    pair = item[0] if isinstance(item[0], (tuple, list)) else item
                    if isinstance(pair, (tuple, list)) and len(pair) >= 2:
                        name, value = str(pair[0]), str(pair[1])
                        short = oid_short.get(name, name)
                        parts.append(f"{short}={value}")
            return ", ".join(parts)

        def _analyze_cert(cert: "x509.Certificate | None") -> list[str]:
            if cert is None:
                return []
            warnings: list[str] = []
            try:
                if cert.signature_hash_algorithm is not None and cert.signature_hash_algorithm.name == "sha1":
                    warnings.append("SHA-1 signature (deprecated; prefer SHA-256)")
            except Exception:
                pass
            try:
                pubkey = cert.public_key()
                if isinstance(pubkey, rsa.RSAPublicKey) and pubkey.key_size < 2048:
                    warnings.append(f"RSA key {pubkey.key_size} bits (< 2048, weak)")
            except Exception:
                pass
            try:
                now = datetime.now(timezone.utc)
                naa = getattr(cert, "not_valid_after_utc", None)
                if naa is None:
                    naa = cert.not_valid_after.replace(tzinfo=timezone.utc)
                nba = getattr(cert, "not_valid_before_utc", None)
                if nba is None:
                    nba = cert.not_valid_before.replace(tzinfo=timezone.utc)
                if now > naa:
                    warnings.append("Certificate expired (past not_valid_after)")
                elif now < nba:
                    warnings.append("Certificate not yet valid (before not_valid_before)")
                else:
                    days_left = (naa - now).days
                    if days_left <= 14:
                        warnings.append(f"Certificate expires within {max(0, days_left)} days")
            except Exception:
                pass
            return warnings

        subject, issuer, san_list = "", "", []
        cert_obj = None
        cert_dict = None
        try:
            cert_dict = sock.getpeercert()
        except Exception:
            pass
        if cert_dict and isinstance(cert_dict, dict):
            subject = _format_x509_name(cert_dict.get("subject") or ())
            issuer = _format_x509_name(cert_dict.get("issuer") or ())
            for item in cert_dict.get("subjectAltName") or ():
                if not isinstance(item, (tuple, list)) or len(item) < 2:
                    continue
                kind = str(item[0]).upper().replace(" ", "")
                val = item[1]
                if kind == "DNS":
                    san_list.append(str(val))
                # rfc822Name: prefix so downstream does not treat local-part-only (e.g. postmaster) as dNSName
                elif kind in ("EMAIL", "RFC822", "RFC822NAME", "E-MAIL"):
                    san_list.append(f"RFC822:{str(val)}")
        elif _HAS_CRYPTOGRAPHY:
            try:
                cert_der = sock.getpeercert(binary_form=True)
                # Fallback: getpeercert(binary_form=True) can return None with CERT_NONE (Python bug #18293).
                # get_unverified_chain() (Python 3.10+) returns list of DER bytes – use first (peer cert).
                if not cert_der and hasattr(sock, "get_unverified_chain"):
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
                                san_list.append(f"RFC822:{name.value}")
                            else:
                                v = getattr(name, "value", None)
                                if isinstance(v, str):
                                    san_list.append(v)
                    except x509.ExtensionNotFound:
                        pass
            except Exception as e:
                self.ptdebug(f"TLS cert extraction failed: {e}", Out.INFO)
                return None
        else:
            return None
        if not subject and not issuer and not san_list:
            return None
        subject = _normalize_cert_text(subject)
        issuer = _normalize_cert_text(issuer)
        san_list = [_normalize_cert_text(str(n)) for n in san_list]
        is_self_signed = bool(subject and issuer and subject.strip() == issuer.strip())
        cert_warnings: list[str] = _analyze_cert(cert_obj) if cert_obj else []
        # Self-signed status is reported once in identify output (icon + "Self-signed: yes"); do not duplicate in cert_warnings.
        cipher_warnings: list[str] = _analyze_cipher(sock)
        return (subject, issuer, san_list, is_self_signed, cert_warnings, cipher_warnings)

    def _pick_mail_domain_for_mx_probe(
        self, banner: str | None, ehlo_raw: str | None, connect_ip: str
    ) -> str | None:
        """Domain used for MX lookup (``-d`` / resolved / EHLO / banner / PTR registrable)."""
        raw_d = getattr(self.args, "domain", None)
        if raw_d and str(raw_d).strip():
            return str(raw_d).strip().lower()
        rd = getattr(self.results, "resolved_domain", None)
        if rd and str(rd).strip():
            return str(rd).strip().lower()
        eh = _get_hostname_from_ehlo_raw(ehlo_raw)
        if eh:
            reg = _registrable_domain_psl(eh)
            if reg:
                return reg.lower()
        bh = _hostname_from_banner(banner)
        if bh:
            reg = _registrable_domain_psl(bh)
            if reg:
                return reg.lower()
        try:
            ipaddress.ip_address(connect_ip)
            ptr_host, _, _ = socket.gethostbyaddr(connect_ip)
            if ptr_host and "." in ptr_host and _is_valid_hostname(ptr_host.strip()):
                reg = _registrable_domain_psl(ptr_host.strip())
                if reg:
                    return reg.lower()
        except (OSError, ValueError):
            pass
        return None

    def _mx_hostnames_for_ip(self, mail_domain: str, ip: str) -> list[str]:
        """MX exchange names (preference order) whose A/AAAA includes ``ip``."""
        out: list[str] = []
        try:
            answers = dns.resolver.resolve(mail_domain, "MX", lifetime=6.0)
        except Exception:
            return out
        mx_list = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0],
        )
        for _pref, exch in mx_list:
            if not exch or exch in out:
                continue
            hit = False
            for resolver_name in ("A", "AAAA"):
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

    def _probe_mx_vs_tls_cert(
        self,
        connect_ip: str,
        banner: str | None,
        ehlo_raw: str | None,
        tls_cert_subject: str | None,
        tls_cert_issuer: str | None,
        tls_cert_san: list[str],
    ) -> tuple[bool | None, str | None, str | None, str | None]:
        """Returns ``(mx_cert_ok, message, mx_peer_hostname, queried_domain)`` for -id output."""
        mail_dom = self._pick_mail_domain_for_mx_probe(banner, ehlo_raw, connect_ip)
        cert_blob = " ".join(
            filter(None, [tls_cert_subject or "", tls_cert_issuer or ""] + (tls_cert_san or []))
        )
        if not cert_blob.strip():
            return None, None, None, None
        if not mail_dom:
            msg = (
                'MX vs cert: not checked (no mail domain inferred; pass -d example.com '
                'to verify certificate against MX hostnames)'
            )
            return None, msg, None, None
        try:
            ipaddress.ip_address(connect_ip)
        except ValueError:
            msg = "MX vs cert: not checked (target is not an IP — MX A/AAAA match skipped)"
            return None, msg, None, mail_dom
        mx_peers = self._mx_hostnames_for_ip(mail_dom, connect_ip)
        if not mx_peers:
            msg = (
                f'MX vs cert: no MX for "{mail_dom}" resolves to this address ({connect_ip}) '
                f"— cannot verify operator name in certificate (try -d with the recipient domain)"
            )
            return False, msg, None, mail_dom
        primary_mx = mx_peers[0]
        if _cert_covers_dname(cert_blob, primary_mx):
            msg = (
                f'MX vs cert: TLS names cover MX host "{primary_mx}" '
                f'(preferred MX for "{mail_dom}" whose A/AAAA includes this IP)'
            )
            return True, msg, primary_mx, mail_dom
        msg = (
            f'MX vs cert: TLS names do not cover MX host "{primary_mx}" '
            f'(MX for "{mail_dom}") — possible name mismatch or multi-tenant endpoint'
        )
        return False, msg, primary_mx, mail_dom

    def _collect_identify_rcpt_error_sample(self, smtp: smtplib.SMTP) -> str | None:
        """MAIL FROM + invalid RCPT TO for error-syntax fingerprinting (default -id)."""
        try:
            smtp.docmd("RSET")
            status_mf, mf_reply = smtp.docmd(f"MAIL FROM:<{_ID_RCPT_ERROR_MAIL_FROM}>")
            if status_mf not in (250, 251):
                return None
            status_rcpt, rcpt_reply = smtp.docmd(f"RCPT TO:<{_ID_RCPT_ERROR_RCPT}>")
            if not rcpt_reply or status_rcpt in (250, 251):
                return None
            if isinstance(rcpt_reply, bytes):
                return rcpt_reply.decode(errors="replace")
            return str(rcpt_reply)
        except Exception:
            return None

    def test_server_identify(self) -> ServerIdentifyResult:
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
        tls_policy: str | None = "n/a"
        id_aggressive = getattr(self.args, "id_aggressive", False)
        cert_info = None
        mx_cert_ok: bool | None = None
        mx_cert_message: str | None = None
        mx_peer_hostname: str | None = None
        mx_queried_domain: str | None = None

        try:
            host, port = self.args.target.ip, self.args.target.port
            os_hint = self._probe_ttl_os_hint(host, port)

            smtp, status, reply = self.connect()
            if status != 220:
                raise Exception(f"Connection failed: [{status}] {reply.decode(errors='replace')[:200]}")
            banner = reply.decode(errors="replace")

            # EHLO (use ehlo() not docmd so esmtp_features is populated for starttls())
            _, ehlo_bytes = smtp.ehlo(self.fqdn)
            if ehlo_bytes:
                ehlo_raw = ehlo_bytes.decode(errors="replace") if isinstance(ehlo_bytes, bytes) else str(ehlo_bytes or "")

            # TLS cert FIRST (right after EHLO): HELP returns multi-line 214 which can desync the
            # protocol buffer; doing STARTTLS before HELP avoids cert extraction failures (e.g. Zoho).
            # Use smtp.starttls() for correct 220 buffer handling (RFC 3207).
            # SNI (Server Name Indication): Zoho, Microsoft, Yandex require SNI in TLS handshake.
            # Priority: 1) user-supplied hostname (target), 2) EHLO first line, 3) banner 220, 4) PTR, 5) IP.
            tls_upgrade_attempted = False
            tls_upgrade_error: str | None = None  # Stored for -vv/--verbose when cert not extracted
            if not isinstance(getattr(smtp, "sock", None), ssl.SSLSocket) and ehlo_raw and re.search(r"starttls", ehlo_raw, re.I):
                tls_upgrade_attempted = True
                # Prefer user-supplied hostname (e.g. mx.zoho.eu) – most reliable for cloud providers
                try:
                    ipaddress.ip_address(self.args.target.ip)
                    target_is_ip = True
                except ValueError:
                    target_is_ip = False
                if not target_is_ip and _is_valid_hostname(self.args.target.ip):
                    sni_host = self.args.target.ip.lower().strip()
                else:
                    server_hostname = _get_hostname_from_ehlo_raw(ehlo_raw)
                    if not server_hostname and banner:
                        first_line = banner.split("\n")[0].split("\r")[0].strip()
                        m = re.match(r"^220\s+(\S+)", first_line)
                        if m and _is_valid_hostname(m.group(1)):
                            server_hostname = m.group(1).lower()
                    try:
                        _ = ipaddress.ip_address(self.args.target.ip)
                        sni_host = server_hostname
                        if not sni_host or not sni_host.strip() or sni_host.startswith("."):
                            try:
                                ptr_host, _, _ = socket.gethostbyaddr(self.args.target.ip)
                                if ptr_host and "." in ptr_host and _is_valid_hostname(ptr_host):
                                    sni_host = ptr_host.lower()
                            except (socket.herror, socket.gaierror, OSError):
                                pass
                        if not sni_host or not sni_host.strip() or sni_host.startswith("."):
                            sni_host = self.args.target.ip
                    except ValueError:
                        sni_host = self.args.target.ip
                # Manual wrap_socket with explicit server_hostname – Zoho/Microsoft/Yandex require SNI
                try:
                    status_stls, _ = smtp.docmd("STARTTLS")
                    if status_stls == 220:
                        ctx = ssl._create_unverified_context()
                        sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=sni_host)
                        smtp.sock = sock_ssl
                        smtp.file = None
                        smtp.helo_resp = None
                        smtp.ehlo_resp = None
                        smtp.esmtp_features = {}
                        smtp.does_esmtp = False
                except Exception as e:
                    tls_upgrade_error = str(e)
                    self.ptdebug(f"STARTTLS failed (cert not extracted): {e}", Out.INFO)

            cert_info = self._extract_tls_cert_info(smtp)
            if cert_info:
                tls_cert_subject, tls_cert_issuer, tls_cert_san, tls_cert_self_signed, tls_cert_warnings, tls_cipher_warnings = cert_info

            # HELP (after STARTTLS to avoid multi-line 214 desync; if on TLS, EHLO first per RFC 3207)
            if isinstance(getattr(smtp, "sock", None), ssl.SSLSocket):
                smtp.ehlo(self.fqdn)  # RFC 3207: must EHLO again after STARTTLS
            status_help, help_bytes = smtp.docmd("HELP")
            if status_help in (211, 214) and help_bytes:
                help_response = help_bytes.decode(errors="replace")

            # Opportunistic vs Mandatory TLS: MAIL FROM on plain (need fresh connection if we upgraded)
            if not isinstance(getattr(smtp, "sock", None), ssl.SSLSocket) and ehlo_raw and re.search(r"starttls", ehlo_raw, re.I):
                status_mail, mail_reply = smtp.docmd("MAIL FROM:<probe@probe.test>")
                reply_str = (mail_reply or b"").decode(errors="replace").upper()
                if status_mail == 530 and ("STARTTLS" in reply_str or "MUST ISSUE" in reply_str):
                    tls_policy = "mandatory"
                elif status_mail == 250:
                    tls_policy = "opportunistic"
                    smtp.docmd("RSET")
            elif isinstance(getattr(smtp, "sock", None), ssl.SSLSocket):
                # We upgraded; policy check skipped (would need fresh plain conn). Default to n/a.
                pass

            # Phase 2: TLS downgrade probe (whenever TLS was used; runs with -id and --id-aggressive)
            if cert_info is not None or self.args.tls or port == 465 or (ehlo_raw and re.search(r"starttls", ehlo_raw, re.I)):
                tls_downgrade_probed = True
                sni_host = _get_hostname_from_ehlo_raw(ehlo_raw) if ehlo_raw else None
                if not sni_host and banner:
                    m = re.match(r"^220\s+(\S+)", (banner.split("\n")[0] if banner else ""))
                    if m and _is_valid_hostname(m.group(1)):
                        sni_host = m.group(1).lower()
                use_implicit = bool(self.args.tls or port == 465)
                tls_downgrade_findings = self._probe_tls_downgrade(host, port, use_implicit, sni_host)

            # Latency measurement (RSET): 1x for -id, 3x for --id-aggressive (jitter) - Phase 3
            latency_avg_ms = None
            latency_jitter_ms = None
            try:
                rtt_count = 3 if id_aggressive else 1
                rtts: list[float] = []
                for _ in range(rtt_count):
                    t0 = time.perf_counter()
                    smtp.docmd("RSET")
                    rtts.append((time.perf_counter() - t0) * 1000)
                if len(rtts) >= 2:
                    latency_avg_ms = sum(rtts) / len(rtts)
                    variance = sum((x - latency_avg_ms) ** 2 for x in rtts) / len(rtts)
                    latency_jitter_ms = (variance**0.5) if variance >= 0 else 0.0
                elif rtts:
                    latency_avg_ms = rtts[0]
            except Exception:
                pass

            # Target host for cert_domain_match (hostname or PTR)
            target_host = host
            try:
                ipaddress.ip_address(host)
                try:
                    ptr_host, _, _ = socket.gethostbyaddr(host)
                    if ptr_host and "." in ptr_host:
                        target_host = ptr_host
                except (socket.herror, socket.gaierror, OSError):
                    pass
            except ValueError:
                pass  # host is hostname

            # RCPT error-syntax probe (default -id): invalid recipient after MAIL FROM.
            if (rcpt_err := self._collect_identify_rcpt_error_sample(smtp)) is not None:
                error_samples.append(rcpt_err)

            # Aggressive: VRFY (collect error), unknown cmd, line length probe
            if id_aggressive:
                try:
                    smtp.docmd("RSET")
                except Exception:
                    pass
                status_vrfy, vrfy_bytes = smtp.docmd("VRFY", "root")
                if vrfy_bytes and status_vrfy not in (250, 251):
                    error_samples.append(vrfy_bytes.decode(errors="replace"))
                # Unknown command: X-PENTEST, fallback SQUASH, X-NON-EXISTENT, FOOBAR
                status_unk, unk_bytes = smtp.docmd("X-PENTEST")
                if unk_bytes:
                    unknown_cmd_response = unk_bytes.decode(errors="replace")
                else:
                    status_sq, sq_bytes = smtp.docmd("SQUASH")
                    if sq_bytes:
                        unknown_cmd_response = sq_bytes.decode(errors="replace")
                    else:
                        status_xn, xn_bytes = smtp.docmd("X-NON-EXISTENT")
                        if xn_bytes:
                            unknown_cmd_response = xn_bytes.decode(errors="replace")
                        else:
                            status_fb, fb_bytes = smtp.docmd("FOOBAR")
                            if fb_bytes:
                                unknown_cmd_response = fb_bytes.decode(errors="replace")
                # Line length probe: EHLO with 1000+ char param (RFC 5321 max 1000) - Postfix: "500 5.5.2 Error: line too long"
                try:
                    status_ll, ll_bytes = smtp.docmd("EHLO", "a" * 1000)
                    if ll_bytes and status_ll not in (250, 251):
                        error_samples.append(ll_bytes.decode(errors="replace"))
                except Exception:
                    pass  # Server may disconnect on long line; continue to quit

            transport_tls = isinstance(getattr(smtp, "sock", None), ssl.SSLSocket)
            starttls_advertised = bool(ehlo_raw and re.search(r"starttls", ehlo_raw, re.I))

            try:
                smtp.quit()
            except Exception:
                pass

            if cert_info:
                mx_cert_ok, mx_cert_message, mx_peer_hostname, mx_queried_domain = self._probe_mx_vs_tls_cert(
                    host,
                    banner,
                    ehlo_raw,
                    tls_cert_subject,
                    tls_cert_issuer,
                    tls_cert_san,
                )
        except Exception as e:
            raise

        return identify_smtp_server(
            banner=banner,
            ehlo_raw=ehlo_raw,
            help_response=help_response,
            error_samples=error_samples,
            unknown_cmd_response=unknown_cmd_response,
            id_aggressive=id_aggressive,
            tls_cert_subject=tls_cert_subject,
            tls_cert_issuer=tls_cert_issuer,
            tls_cert_san=tls_cert_san,
            tls_cert_self_signed=tls_cert_self_signed,
            tls_upgrade_failed=tls_upgrade_attempted and cert_info is None,
            tls_upgrade_error=tls_upgrade_error,
            transport_tls=transport_tls,
            starttls_advertised=starttls_advertised,
            tls_policy=tls_policy,
            tls_cert_warnings=tls_cert_warnings,
            tls_cipher_warnings=tls_cipher_warnings,
            tls_downgrade_findings=tls_downgrade_findings,
            tls_downgrade_probed=tls_downgrade_probed,
            os_hint=os_hint,
            target_host=target_host,
            latency_avg_ms=latency_avg_ms,
            latency_jitter_ms=latency_jitter_ms,
            mx_cert_ok=mx_cert_ok,
            mx_cert_message=mx_cert_message,
            mx_queried_domain=mx_queried_domain,
            mx_peer_hostname=mx_peer_hostname,
        )

    def test_encryption(self) -> EncryptionResult:
        """
        Test which encryption options are available on the target port:
        plaintext, STARTTLS, and implicit TLS (SMTP_SSL).
        Uses fresh connections for each test; does not use self.args.tls/starttls.

        The caller (run() or _run_all_tests()) stores the return value in
        self.results.encryption so that subsequent tests can use it to select
        the appropriate connection type (e.g. prefer STARTTLS when available).
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        plaintext_ok = False
        starttls_ok = False
        tls_ok = False

        # Unverified context for availability probe only (server cert may be
        # self-signed or for different hostname). Use _create_unverified_context
        # for maximum compatibility with real-world servers.
        _ssl_ctx = ssl._create_unverified_context()
        # Port 465 is implicit TLS only (SMTPS): skip plaintext and STARTTLS (they would hang/timeout).
        tls_only_port = port == 465

        if not tls_only_port:
            # 1. STARTTLS (plain then upgrade). RFC 3207: EHLO first, then STARTTLS, then EHLO.
            try:
                smtp = smtplib.SMTP(timeout=timeout)
                try:
                    status, _ = smtp.connect(host, port)
                    if status == 220:
                        status, _ = smtp.docmd("EHLO", self.fqdn)
                        if status == 250:
                            status, _ = smtp.docmd("STARTTLS")
                            if status == 220:
                                try:
                                    _is_ip = ipaddress.ip_address(host)
                                    _sni = None
                                except ValueError:
                                    _sni = host
                                sock_ssl = _ssl_ctx.wrap_socket(
                                    smtp.sock, server_hostname=_sni
                                )
                                smtp.sock = sock_ssl
                                smtp.file = None
                                smtp.helo_resp = None
                                smtp.ehlo_resp = None
                                smtp.esmtp_features = {}
                                smtp.does_esmtp = False
                                status, _ = smtp.docmd("EHLO", self.fqdn)
                                starttls_ok = status == 250
                finally:
                    smtp.close()
            except Exception as e:
                self.ptdebug(f"STARTTLS test failed: {e}", Out.INFO)

            time.sleep(2)

            # 2. Plaintext (no TLS)
            try:
                smtp = smtplib.SMTP(timeout=timeout)
                try:
                    status, _ = smtp.connect(host, port)
                    if status == 220:
                        status, _ = smtp.docmd("EHLO", self.fqdn)
                        plaintext_ok = status == 250
                finally:
                    smtp.close()
            except Exception:
                pass

            time.sleep(2)

        # 3. Implicit TLS (port 465 / SMTPS). Connect manually so we control SNI:
        # when connecting by IP use server_hostname=None (many servers have hostname-only certs).
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            try:
                try:
                    ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                smtp = smtplib.SMTP(timeout=timeout)
                try:
                    smtp.sock = sock_ssl
                    smtp.file = None
                    (status, _) = smtp.getreply()
                    if status == 220:
                        status, _ = smtp.docmd("EHLO", self.fqdn)
                        tls_ok = status == 250
                finally:
                    smtp.close()
            finally:
                try:
                    sock_ssl.close()
                except Exception:
                    pass
        except Exception:
            pass

        return EncryptionResult(plaintext_ok, starttls_ok, tls_ok)

    def _stream_ptr_domain(self) -> None:
        """Stream PTR / resolved domain (like POP3/IMAP/FTP/SSH)."""
        if self.use_json or not (domain := getattr(self.results, "resolved_domain", None)):
            return
        self.ptprint("PTR / Domain", Out.INFO)
        ptprinthelper.ptprint(f"Resolved domain: {domain}", bullet_type="TITLE",
                              condition=not self.use_json, indent=4)

    def _stream_banner_result(self) -> None:
        """Print banner result to terminal (header already printed before initial_info())."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if not self.results.banner_requested:
            return
        if not (info := self.results.info) or info.banner is None:
            self.ptprint("Service Identification", Out.INFO)
            pp("No information found", bullet_type="TITLE", condition=show, indent=4)
            return
        sid = identify_service(info.banner)
        if sid is None:
            banner_bullet = "NOTVULN"
        elif sid.version is not None:
            banner_bullet = "VULN"
        else:
            banner_bullet = "WARNING"
        pp(info.banner, bullet_type=banner_bullet, condition=show, indent=4)
        if sid is None:
            self.ptprint("Service Identification", Out.INFO)
            pp("No information found", bullet_type="TITLE", condition=show, indent=4)
        elif sid is not None:
            self.ptprint("Service Identification", Out.INFO)
            pp(f"Product:  {sid.product}", bullet_type="TEXT", condition=show, indent=4)
            pp(f"Version:  {sid.version if sid.version else 'unknown'}", bullet_type="TEXT", condition=show, indent=4)
            pp(f"CPE:      {sid.cpe}", bullet_type="TEXT", condition=show, indent=4)

    def _stream_ehlo_result(self) -> None:
        """Print EHLO section header(s) and result."""
        if not self.results.commands_requested or not (info := self.results.info) or info.ehlo is None:
            return
        show = not self.use_json
        ehlo_starttls = getattr(info, "ehlo_starttls", None)

        def _print_ehlo_parsed(ehlo_raw: str, connection_encrypted: bool) -> None:
            parsed = _parse_ehlo_commands(ehlo_raw, connection_encrypted=connection_encrypted)
            for display_str, level in parsed:
                if level == "ERROR":
                    b = "VULN"
                elif level == "WARNING":
                    b = "WARNING"
                else:
                    b = "NOTVULN"
                ptprinthelper.ptprint(display_str, bullet_type=b, condition=show, indent=4)

        if ehlo_starttls:
            self.ptprint("EHLO extensions (PLAIN)", Out.INFO)
            if info.ehlo:
                _print_ehlo_parsed(info.ehlo, connection_encrypted=False)
            self.ptprint("EHLO extensions (STARTTLS)", Out.INFO)
            _print_ehlo_parsed(ehlo_starttls, connection_encrypted=True)
        else:
            connection_encrypted = (
                self.args.target.port == 465 or self.args.tls or self.args.starttls
            )
            section_label = " (TLS)" if connection_encrypted else " (PLAIN)"
            self.ptprint(f"EHLO extensions{section_label}", Out.INFO)
            if info.ehlo:
                _print_ehlo_parsed(info.ehlo, connection_encrypted=connection_encrypted)
            if (
                not connection_encrypted
                and "STARTTLS" in (info.ehlo or "").upper()
                and not getattr(info, "ehlo_starttls", None)
            ):
                self.ptprint("EHLO extensions (STARTTLS)", Out.INFO)
                ptprinthelper.ptprint(
                    "Failed to establish STARTTLS connection or STARTTLS command is not available in EHLO (try -vv for debug)",
                    bullet_type="TITLE", condition=show, indent=4,
                )

    def _stream_role_result(self) -> None:
        """Print role identification result."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (role_error := self.results.role_error) is not None:
            pp(f"Role identification failed: {role_error}", bullet_type="VULN", condition=show, indent=4)
            return
        role_r = self.results.role
        if role_r is None:
            return

        port = self.args.target.port

        # Port hint line
        port_labels = {
            25: "typical MTA port",
            587: "typical Submission port (STARTTLS)",
            465: "typical Submission port (implicit TLS)",
            2525: "alternative Submission port",
        }
        port_label = port_labels.get(port, "non-standard SMTP port")
        pp(f"Port {port} ({port_label})", bullet_type="TITLE", condition=show, indent=4)

        # AUTH line
        if role_r.auth_advertised:
            _, methods_plain = self._ehlo_has_auth(
                self.results.info.ehlo if self.results.info else None
            )
            _, methods_starttls = self._ehlo_has_auth(
                getattr(self.results.info, "ehlo_starttls", None) if self.results.info else None
            )
            methods = sorted(set(methods_plain + methods_starttls))
            methods_str = ", ".join(methods) if methods else "unknown"
            pp(f"AUTH advertised in EHLO ({methods_str})", bullet_type="TITLE", condition=show, indent=4)
        else:
            pp("AUTH not advertised in EHLO", bullet_type="TITLE", condition=show, indent=4)

        # RCPT TO probe result line (if probe was performed)
        if role_r.auth_required is True:
            pp("RCPT TO requires authentication", bullet_type="TITLE", condition=show, indent=4)
        elif role_r.auth_required is False:
            pp("RCPT TO accepted without authentication", bullet_type="TITLE", condition=show, indent=4)

        # Greylisting detection (450/451 = server has active anti-spam sender reputation checks)
        if "greylisting detected" in role_r.detail.lower():
            pp("Greylisting detected (server returned 450/451)", bullet_type="TITLE", condition=show, indent=4)

        # Final role line
        role_display = {
            "mta": ("MTA (Public Mail Server)", "NOTVULN"),
            "submission": ("Submission (Mail Submission Agent)", "NOTVULN"),
            "hybrid": ("Hybrid (MTA + Submission) -- consider separating roles", "VULN"),
            "indeterminate": ("Indeterminate -- could not reliably determine role", "WARNING"),
        }
        label, bullet = role_display.get(role_r.role, ("Unknown", "VULN"))
        pp(label, bullet_type=bullet, condition=show, indent=4)

    def _stream_encryption_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (encryption_error := self.results.encryption_error) is not None:
            pp(f"Encryption test failed: {encryption_error}", bullet_type="VULN", condition=show, indent=4)
            return
        enc = self.results.encryption
        if enc is None:
            return
        plaintext_only = enc.plaintext_ok and not enc.starttls_ok and not enc.tls_ok
        any_ok = enc.plaintext_ok or enc.starttls_ok or enc.tls_ok
        if plaintext_only:
            pp("Plaintext only", bullet_type="VULN", condition=show, indent=4)
        elif any_ok:
            if enc.plaintext_ok:
                # Plaintext available together with STARTTLS/TLS = warning
                bullet = "WARNING" if (enc.starttls_ok or enc.tls_ok) else "NOTVULN"
                pp("Plaintext", bullet_type=bullet, condition=show, indent=4)
            if enc.starttls_ok:
                pp("STARTTLS", bullet_type="NOTVULN", condition=show, indent=4)
            if enc.tls_ok:
                pp("TLS", bullet_type="NOTVULN", condition=show, indent=4)
        else:
            pp("No connection mode available (plaintext, STARTTLS, TLS failed)",
               bullet_type="VULN", condition=show, indent=4)

    def _stream_ntlm_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (ntlm_error := self.results.ntlm_error) is not None:
            pp(f"NTLM test failed: {ntlm_error}", bullet_type="VULN", condition=show, indent=4)
            return
        ntlm = self.results.ntlm
        if ntlm is None:
            return
        if not ntlm.success:
            pp("Not available", bullet_type="NOTVULN", condition=show, indent=4)
        elif ntlm.ntlm is not None:
            pp("NTLM information", bullet_type="VULN", condition=show, indent=4)
            for line in (
                f"Target name: {ntlm.ntlm.target_name}",
                f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                f"DNS domain name: {ntlm.ntlm.dns_domain}",
                f"DNS computer name: {ntlm.ntlm.dns_computer}",
                f"DNS tree: {ntlm.ntlm.dns_tree}",
                f"OS version: {ntlm.ntlm.os_version}",
            ):
                for part in (line or "").replace("\r", "").splitlines():
                    pp(part, bullet_type="TEXT", condition=show, indent=8)
