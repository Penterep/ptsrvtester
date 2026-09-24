"""NTLM — AUTH NTLM challenge decode."""
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

from ._common import ensure_info


__MODULELABEL__ = "NTLM information"
__MODULECODE__ = "NTLM"
__ORDER__ = 100


def auth_ntlm(e, smtp: smtplib.SMTP) -> NTLMResult:
    """
        Performs NTLM authentication to extract internal server
        information from server's challenge response.
        OWASP: Common finding on MS Exchange - exposes domain/hostname.
        """
    ntlm = None
    try:
        code, resp = smtp.docmd('AUTH NTLM')
        e._smtp_vv_io('AUTH NTLM', f'{code} {e.bytes_to_str(resp) if resp else ""}')
        if code == 334:
            smtp.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
            code, resp = smtp.getreply()
            e._smtp_vv_io('AUTH NTLM negotiate', f'{code} {e.bytes_to_str(resp) if resp else ""}')
            ntlm = decode_ChallengeMessage_blob(b64decode(resp))
    except (smtplib.SMTPException, TimeoutError, socket.timeout, OSError, ValueError, TypeError, KeyError, struct.error, UnicodeDecodeError) as ex:
        e._smtp_vv_io('AUTH NTLM', str(ex))
        if e._smtp_exc_is_timeout(ex):
            return NTLMResult(False, None, incomplete=True)
        ntlm = None
    if ntlm is None:
        return NTLMResult(False, None)
    return NTLMResult(True, ntlm)


def _stream_ntlm_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (ntlm_error := e.results.ntlm_error) is not None:
        pp(f'NTLM test failed: {ntlm_error}', bullet_type='VULN', condition=show, indent=4)
        return
    ntlm = e.results.ntlm
    if ntlm is None:
        return
    if getattr(ntlm, 'incomplete', False):
        pp('NTLM timed out (not confirmed)', bullet_type='WARNING', condition=show, indent=4)
        return
    if not ntlm.success:
        pp('Not available', bullet_type='NOTVULN', condition=show, indent=4)
    elif ntlm.ntlm is not None:
        pp('NTLM information', bullet_type='VULN', condition=show, indent=4)
        for line in (f'Target name: {ntlm.ntlm.target_name}', f'NetBios domain name: {ntlm.ntlm.netbios_domain}', f'NetBios computer name: {ntlm.ntlm.netbios_computer}', f'DNS domain name: {ntlm.ntlm.dns_domain}', f'DNS computer name: {ntlm.ntlm.dns_computer}', f'DNS tree: {ntlm.ntlm.dns_tree}', f'OS version: {ntlm.ntlm.os_version}'):
            for part in (line or '').replace('\r', '').splitlines():
                pp(part, bullet_type='TEXT', condition=show, indent=8)


def run(ctx):
    e = ensure_info(ctx, get_commands=False)
    if getattr(e.results, "info_error", None):
        return
    try:
        e.results.ntlm = auth_ntlm(e, e.smtp)
    except Exception as ex:
        e.results.ntlm_error = str(ex)
        ctx.out(f"NTLM probe failed: {ex}", "ERROR", indent=4)
        return
    _stream_ntlm_result(e)
