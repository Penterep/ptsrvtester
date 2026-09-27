"""Shared AUTH connection helpers (AUTHENUM / AUTHFMT)."""
from __future__ import annotations

import ipaddress
import smtplib
import ssl
import threading

from ..utils.helpers import _get_auth_methods_from_ehlo


def _auth_enum_connect_aborted(e) -> str | None:
    return getattr(e, "_auth_enum_conn_abort", None)


def _auth_enum_note_connect_abort(e, msg: str) -> None:
    lock = getattr(e, "_auth_enum_abort_lock", None)
    if lock is None:
        lock = threading.Lock()
        e._auth_enum_abort_lock = lock
    with lock:
        if getattr(e, "_auth_enum_conn_abort", None) is None:
            e._auth_enum_conn_abort = msg


def _get_smtp_for_auth_enum(e) -> tuple[smtplib.SMTP, str]:
    """
    Get SMTP connection; EHLO parsed for AUTH extensions (LOGIN / PLAIN / NTLM).
    On port 25/587: if plain EHLO lacks LOGIN, NTLM, and PLAIN but has STARTTLS, upgrade and re-EHLO.

    Uses non-fatal connect so threaded AUTH-ENUM workers never call ``end_error`` on
    transient failures (avoids duplicate error lines and premature ``os._exit``).
    """
    if abort := _auth_enum_connect_aborted(e):
        raise ConnectionError(abort)
    try:
        smtp, status, reply = e.connect(timeout=15.0, fatal=False)
    except ConnectionError as ex:
        _auth_enum_note_connect_abort(e, str(ex))
        raise
    if status != 220:
        msg = f"SMTP Info - [{status}] {e.bytes_to_str(reply)}"
        _auth_enum_note_connect_abort(e, msg)
        raise ConnectionError(msg)
    _, ehlo_bytes = smtp.ehlo(e.fqdn)
    ehlo = ehlo_bytes.decode() if ehlo_bytes else ""
    auth_methods = _get_auth_methods_from_ehlo(ehlo)
    needs_starttls = (
        "LOGIN" not in auth_methods
        and "NTLM" not in auth_methods
        and "PLAIN" not in auth_methods
        and "STARTTLS" in ehlo.upper()
        and e.args.target.port != 465
        and not e.args.tls
        and not e.args.starttls
    )
    if needs_starttls:
        status, _ = smtp.docmd("STARTTLS")
        if status == 220:
            ctx = ssl._create_unverified_context()
            try:
                ipaddress.ip_address(e.args.target.ip)
                server_hostname = None
            except ValueError:
                server_hostname = e.args.target.ip
            sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=server_hostname)
            smtp.sock = sock_ssl
            smtp.file = None
            smtp.helo_resp = None
            smtp.ehlo_resp = None
            smtp.esmtp_features = {}
            smtp.does_esmtp = False
            _, ehlo_bytes = smtp.ehlo(e.fqdn)
            ehlo = ehlo_bytes.decode() if ehlo_bytes else ""
            if e.args.debug and not getattr(e, "_auth_enum_dbg_logged_starttls", False):
                e.ptdebug(
                    "AUTH-ENUM: STARTTLS applied (LOGIN/PLAIN/NTLM was not advertised on plain EHLO); subsequent AUTH probes use TLS"
                )
                e._auth_enum_dbg_logged_starttls = True
    return smtp, ehlo
