"""BANNER — greeting + service identification."""
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


__MODULELABEL__ = "Banner"
__MODULECODE__ = "BANNER"
__ORDER__ = 10


def _stream_banner_result(e) -> None:
    """Print banner result to terminal (header already printed before initial_info())."""
    pp = e._ptprint_raw
    show = not e.use_json
    if not e.results.banner_requested:
        return
    if not (info := e.results.info) or info.banner is None:
        e.ptprint('Service Identification', Out.INFO)
        pp('No information found', bullet_type='TITLE', condition=show, indent=4)
        return
    sid = identify_service(info.banner)
    if sid is None:
        banner_bullet = 'NOTVULN'
    elif sid.version is not None:
        banner_bullet = 'VULN'
    else:
        banner_bullet = 'WARNING'
    pp(info.banner, bullet_type=banner_bullet, condition=show, indent=4)
    if sid is None:
        e.ptprint('Service Identification', Out.INFO)
        pp('No information found', bullet_type='TITLE', condition=show, indent=4)
    elif sid is not None:
        e.ptprint('Service Identification', Out.INFO)
        pp(f'Product:  {sid.product}', bullet_type='TEXT', condition=show, indent=4)
        pp(f"Version:  {(sid.version if sid.version else 'unknown')}", bullet_type='TEXT', condition=show, indent=4)
        pp(f'CPE:      {sid.cpe}', bullet_type='TEXT', condition=show, indent=4)


def _stream_ptr_domain(e) -> None:
    """Stream PTR / resolved domain (like POP3/IMAP/FTP/SSH)."""
    if e.use_json or not (domain := getattr(e.results, 'resolved_domain', None)):
        return
    e.ptprint('PTR / Domain', Out.INFO)
    e._ptprint_raw(f'Resolved domain: {domain}', bullet_type='TITLE', condition=not e.use_json, indent=4)


def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    e.results.banner_requested = True
    if getattr(e.results, "info_error", None):
        return
    _stream_banner_result(e)
    _stream_ptr_domain(e)
