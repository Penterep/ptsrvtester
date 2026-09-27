"""ENCRYPT — plaintext / STARTTLS / implicit TLS."""
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

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng, ensure_info


__MODULELABEL__ = "Encryption"
__MODULECODE__ = "ENCRYPT"
__ORDER__ = 30


def test_encryption(e) -> EncryptionResult:
    """
        Test which encryption options are available on the target port:
        plaintext, STARTTLS, and implicit TLS (SMTP_SSL).
        Uses fresh connections for each test; does not use self.args.tls/starttls.

        The caller (run() or _run_all_tests()) stores the return value in
        self.results.encryption so that subsequent tests can use it to select
        the appropriate connection type (e.g. prefer STARTTLS when available).
        """
    host = e.args.target.ip
    port = e.args.target.port
    timeout = 10.0
    plaintext_ok = False
    starttls_ok = False
    tls_ok = False
    plaintext_incomplete = False
    starttls_incomplete = False
    tls_incomplete = False
    _ssl_ctx = ssl._create_unverified_context()
    tls_only_port = port == 465
    if not tls_only_port:
        try:
            smtp = smtplib.SMTP(timeout=timeout)
            try:
                status, reply = smtp.connect(host, port)
                e._smtp_vv_io('(connect)', f'{status} {e.bytes_to_str(reply) if reply else ""}')
                if status == 220:
                    status, reply = smtp.docmd('EHLO', e.fqdn)
                    e._smtp_vv_io(f'EHLO {e.fqdn}', f'{status} {e.bytes_to_str(reply) if reply else ""}')
                    if status == 250:
                        status, reply = smtp.docmd('STARTTLS')
                        e._smtp_vv_io('STARTTLS', f'{status} {e.bytes_to_str(reply) if reply else ""}')
                        if status == 220:
                            try:
                                _is_ip = ipaddress.ip_address(host)
                                _sni = None
                            except ValueError:
                                _sni = host
                            sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                            smtp.sock = sock_ssl
                            smtp.file = None
                            smtp.helo_resp = None
                            smtp.ehlo_resp = None
                            smtp.esmtp_features = {}
                            smtp.does_esmtp = False
                            status, reply = smtp.docmd('EHLO', e.fqdn)
                            e._smtp_vv_io(f'EHLO {e.fqdn} (after STARTTLS)', f'{status} {e.bytes_to_str(reply) if reply else ""}')
                            starttls_ok = status == 250
            finally:
                smtp.close()
        except Exception as ex:
            e._smtp_vv_io('STARTTLS', str(ex))
            if e._smtp_exc_is_timeout(ex):
                starttls_incomplete = True
        time.sleep(2)
        try:
            smtp = smtplib.SMTP(timeout=timeout)
            try:
                status, reply = smtp.connect(host, port)
                e._smtp_vv_io('(connect cleartext)', f'{status} {e.bytes_to_str(reply) if reply else ""}')
                if status == 220:
                    status, reply = smtp.docmd('EHLO', e.fqdn)
                    e._smtp_vv_io(f'EHLO {e.fqdn}', f'{status} {e.bytes_to_str(reply) if reply else ""}')
                    plaintext_ok = status == 250
            finally:
                smtp.close()
        except Exception as ex:
            e._smtp_vv_io('(connect cleartext)', str(ex))
            if e._smtp_exc_is_timeout(ex):
                plaintext_incomplete = True
        time.sleep(2)
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
                status, reply = smtp.getreply()
                e._smtp_vv_io('(connect implicit TLS)', f'{status} {e.bytes_to_str(reply) if reply else ""}')
                if status == 220:
                    status, reply = smtp.docmd('EHLO', e.fqdn)
                    e._smtp_vv_io(f'EHLO {e.fqdn}', f'{status} {e.bytes_to_str(reply) if reply else ""}')
                    tls_ok = status == 250
            finally:
                smtp.close()
        finally:
            try:
                sock_ssl.close()
            except Exception:
                pass
    except Exception as ex:
        e._smtp_vv_io('(connect implicit TLS)', str(ex))
        if e._smtp_exc_is_timeout(ex):
            tls_incomplete = True
    return EncryptionResult(plaintext_ok, starttls_ok, tls_ok, plaintext_incomplete, starttls_incomplete, tls_incomplete)


def _stream_encryption_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (encryption_error := e.results.encryption_error) is not None:
        pp(f'Encryption test failed: {encryption_error}', bullet_type='VULN', condition=show, indent=4)
        return
    enc = e.results.encryption
    if enc is None:
        return
    any_ok = enc.plaintext_ok or enc.starttls_ok or enc.tls_ok
    any_inc = getattr(enc, 'plaintext_incomplete', False) or getattr(enc, 'starttls_incomplete', False) or getattr(enc, 'tls_incomplete', False)
    plaintext_only = enc.plaintext_ok and (not enc.starttls_ok) and (not enc.tls_ok) and (not any_inc)
    if plaintext_only:
        pp('Cleartext only', bullet_type='VULN', condition=show, indent=4)
        return
    if not any_ok:
        pp('Could not connect. Encryption was not tested.', bullet_type='WARNING', condition=show, indent=4)
        return
    if enc.plaintext_ok:
        bullet = 'WARNING' if enc.starttls_ok or enc.tls_ok else 'VULN'
        if enc.starttls_incomplete or enc.tls_incomplete:
            bullet = 'WARNING'
        pp('Cleartext', bullet_type=bullet, condition=show, indent=4)
    elif enc.plaintext_incomplete:
        pp('Cleartext timed out (not confirmed)', bullet_type='WARNING', condition=show, indent=4)
    if enc.starttls_ok:
        pp('STARTTLS', bullet_type='NOTVULN', condition=show, indent=4)
    elif enc.starttls_incomplete:
        pp('STARTTLS timed out (not confirmed)', bullet_type='WARNING', condition=show, indent=4)
    if enc.tls_ok:
        pp('TLS', bullet_type='NOTVULN', condition=show, indent=4)
    elif enc.tls_incomplete:
        pp('TLS timed out (not confirmed)', bullet_type='WARNING', condition=show, indent=4)


def run(ctx):
    e = eng(ctx)
    try:
        if e.run_all_mode:
            ei = ensure_info(ctx, get_commands=True)
            if getattr(ei.results, "info_error", None):
                return
            e.results.encryption = e.infer_encryption_from_info()
        else:
            e.results.encryption = test_encryption(e)
    except Exception as ex:
        e.results.encryption_error = str(ex)
        ctx.out(f"Encryption probe failed: {ex}", "ERROR", indent=4)
        return
    _stream_encryption_result(e)
