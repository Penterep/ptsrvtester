"""HELOONLY — HELO without EHLO extensions."""
import ipaddress, re, smtplib, socket, ssl, statistics, time





from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "HELO-only Test"
__MODULECODE__ = "HELOONLY"
__ORDER__ = 51


def test_helo_only(e) -> HeloOnlyResult:
    """
    Test if server supports EHLO extensions or only basic HELO (PTL-SVC-SMTP-HELOONLY).
    Uses same hostname for both HELO and EHLO to avoid false positives from firewalls/antispam
    that may drop EHLO when they dislike the client IP or hostname.
    """
    host = e.args.target.ip
    port = e.args.target.port
    timeout = 10.0
    helo_host = "test.local"  # Same for both HELO and EHLO - eliminates variable
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and not use_tls
    conn_type = "tls" if use_tls else "starttls" if use_starttls else "plain"

    def _connect_helo_only():
        if use_tls:
            try:
                _is_ip = ipaddress.ip_address(host)
                _sni = None
            except ValueError:
                _sni = host
            sock = socket.create_connection((host, port), timeout=timeout)
            sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
            smtp = smtplib.SMTP(timeout=timeout)
            smtp.sock = sock_ssl
            smtp.file = None
            status, _ = smtp.getreply()
            return smtp, status
        smtp = smtplib.SMTP(timeout=timeout)
        status, _ = smtp.connect(host, port)
        if status != 220:
            return smtp, status
        if use_starttls:
            status_stls, _ = smtp.docmd("STARTTLS")
            if status_stls != 220:
                return smtp, status_stls
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
        return smtp, 220

    try:
        smtp1, conn_status = _connect_helo_only()
        if conn_status != 220:
            try:
                smtp1.close()
            except Exception:
                pass
            if conn_status in (421, 451):
                return HeloOnlyResult(
                    vulnerable=False,
                    indeterminate=True,
                    helo_status=None,
                    helo_reply=None,
                    ehlo_status=None,
                    ehlo_reply=None,
                    extensions=(),
                    connection_type=conn_type,
                    detail="Rate limiting (421/451) - indeterminate",
                )
            return HeloOnlyResult(
                vulnerable=False,
                indeterminate=True,
                helo_status=None,
                helo_reply=None,
                ehlo_status=None,
                ehlo_reply=None,
                extensions=(),
                connection_type=conn_type,
                detail=f"Connection/banner failed: {conn_status}",
            )

        helo_status, helo_reply_bytes = smtp1.docmd("HELO", helo_host)
        helo_reply = helo_reply_bytes.decode(errors="replace") if helo_reply_bytes else None
        e._smtp_vv_io(f"HELO {helo_host}", f"{helo_status} {helo_reply or ''}")
        try:
            smtp1.quit()
        except Exception:
            pass

        time.sleep(1)

        smtp2, conn_status2 = _connect_helo_only()
        if conn_status2 != 220:
            try:
                smtp2.close()
            except Exception:
                pass
            return HeloOnlyResult(
                vulnerable=False,
                indeterminate=True,
                helo_status=helo_status,
                helo_reply=helo_reply,
                ehlo_status=None,
                ehlo_reply=None,
                extensions=(),
                connection_type=conn_type,
                detail="Reconnect failed - indeterminate",
            )

        ehlo_status, ehlo_reply_bytes = smtp2.ehlo(helo_host)
        ehlo_reply = ehlo_reply_bytes.decode(errors="replace") if ehlo_reply_bytes else None
        e._smtp_vv_io(f"EHLO {helo_host}", f"{ehlo_status} {ehlo_reply or ''}")

        # Use smtplib's parsed esmtp_features (reliable) - extract before quit()
        extensions_list: list[str] = []
        if getattr(smtp2, "esmtp_features", None):
            for key, value in smtp2.esmtp_features.items():
                key_upper = (key or "").upper().strip()
                if not key_upper or key_upper == "OK":
                    continue
                if "." in key_upper and key_upper not in SMTP_KNOWN_EXTENSIONS:
                    continue
                if value:
                    extensions_list.append(f"{key_upper} {value.strip()}".strip())
                else:
                    extensions_list.append(key_upper)
        extensions = tuple(extensions_list)

        try:
            smtp2.quit()
        except Exception:
            pass

        if ehlo_status in (421, 451):
            return HeloOnlyResult(
                vulnerable=False,
                indeterminate=True,
                helo_status=helo_status,
                helo_reply=helo_reply,
                ehlo_status=ehlo_status,
                ehlo_reply=ehlo_reply,
                extensions=(),
                connection_type=conn_type,
                detail="Rate limiting on EHLO (421/451) - indeterminate",
            )

        # At least one extension = NOT vulnerable. No extensions or EHLO rejected = vulnerable.
        if ehlo_status == 250 and len(extensions) > 0:
            vulnerable = False
            detail = "Server supports ESMTP extensions."
        else:
            vulnerable = True
            detail = "Server supports only HELO; EHLO rejected or provides no ESMTP extensions."

        return HeloOnlyResult(
            vulnerable=vulnerable,
            indeterminate=False,
            helo_status=helo_status,
            helo_reply=helo_reply,
            ehlo_status=ehlo_status,
            ehlo_reply=ehlo_reply,
            extensions=extensions,
            connection_type=conn_type,
            detail=detail,
        )

    except (socket.timeout, ConnectionRefusedError, OSError) as ex:
        return HeloOnlyResult(
            vulnerable=False,
            indeterminate=True,
            helo_status=None,
            helo_reply=None,
            ehlo_status=None,
            ehlo_reply=None,
            extensions=(),
            connection_type=conn_type,
            detail=str(ex),
        )

def _stream_helo_only_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.helo_only_error) is not None:
        pp(f"HELO-only test failed: {err}", bullet_type="VULN", condition=show, indent=4)
        return
    ho = e.results.helo_only
    if ho is None:
        return

    def _strip_status_prefix(reply: str | None) -> str:
        """Strip leading '250 ' or '250-' from reply for display."""
        if not reply:
            return ""
        r = reply.strip()
        if r.startswith("250 "):
            return r[4:].strip()
        if r.startswith("250-"):
            return r[4:].strip()
        return r

    if not e.args.debug:
        pp(f"Connection: {ho.connection_type}", bullet_type="TITLE", condition=show, indent=4)
        helo_first = (ho.helo_reply or "").replace("\r", "\n").split("\n")[0].strip()
        pp(f"HELO test.local: {ho.helo_status} {_strip_status_prefix(helo_first)}", bullet_type="TITLE", condition=show, indent=4)
        ehlo_first = (ho.ehlo_reply or "").replace("\r", "\n").split("\n")[0].strip()
        pp(f"EHLO test.local: {ho.ehlo_status} {_strip_status_prefix(ehlo_first)}", bullet_type="TITLE", condition=show, indent=4)
        if ho.extensions:
            for ext in ho.extensions:
                pp(ext, bullet_type="TEXT", condition=show, indent=8)
    if ho.indeterminate:
        pp(f"Indeterminate: {ho.detail or 'Could not complete'}", bullet_type="WARNING", condition=show, indent=4)
    elif ho.vulnerable:
        pp(ho.detail, bullet_type="VULN", condition=show, indent=4)
    else:
        pp(ho.detail, bullet_type="NOTVULN", condition=show, indent=4)

def run(ctx):
    e = eng(ctx)
    try:
        e.results.helo_only = test_helo_only(e)
    except Exception as ex:
        e.results.helo_only_error = str(ex)
        ctx.out(f"HELOONLY failed: {ex}", "ERROR", indent=4)
        return
    _stream_helo_only_result(e)
