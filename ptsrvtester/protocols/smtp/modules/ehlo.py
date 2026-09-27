"""EHLO — advertised extensions."""
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


__MODULELABEL__ = ""
__MODULECODE__ = "EHLO"
__ORDER__ = 25


def _stream_ehlo_result(e) -> None:
    """Print EHLO section header(s) and result."""
    if not e.results.commands_requested or not (info := e.results.info) or info.ehlo is None:
        return
    show = not e.use_json
    ehlo_starttls = getattr(info, 'ehlo_starttls', None)

    def _print_ehlo_parsed(ehlo_raw: str, connection_encrypted: bool) -> None:
        parsed = _parse_ehlo_commands(ehlo_raw, connection_encrypted=connection_encrypted)
        for display_str, level in parsed:
            if level == 'ERROR':
                b = 'VULN'
            elif level == 'WARNING':
                b = 'WARNING'
            else:
                b = 'NOTVULN'
            e._ptprint_raw(display_str, bullet_type=b, condition=show, indent=4)
    if ehlo_starttls:
        e.ptprint('EHLO extensions (PLAIN)', Out.INFO)
        if info.ehlo:
            _print_ehlo_parsed(info.ehlo, connection_encrypted=False)
        e.ptprint('EHLO extensions (STARTTLS)', Out.INFO)
        _print_ehlo_parsed(ehlo_starttls, connection_encrypted=True)
    else:
        connection_encrypted = e.args.target.port == 465 or e.args.tls or e.args.starttls
        section_label = ' (TLS)' if connection_encrypted else ' (PLAIN)'
        e.ptprint(f'EHLO extensions{section_label}', Out.INFO)
        if info.ehlo:
            _print_ehlo_parsed(info.ehlo, connection_encrypted=connection_encrypted)
        if not connection_encrypted and 'STARTTLS' in (info.ehlo or '').upper() and (not getattr(info, 'ehlo_starttls', None)):
            e.ptprint('EHLO extensions (STARTTLS)', Out.INFO)
            err = getattr(info, 'ehlo_starttls_error', None)
            if e._smtp_text_is_timeout(err):
                msg = 'STARTTLS timed out (not confirmed)'
            else:
                msg = 'STARTTLS (is advertised but cannot be used)'
            e._ptprint_raw(msg, bullet_type='WARNING', condition=show, indent=4)


def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    e.results.commands_requested = True
    if getattr(e.results, "info_error", None):
        return
    _stream_ehlo_result(e)
