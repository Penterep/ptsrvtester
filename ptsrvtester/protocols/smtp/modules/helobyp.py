"""HELOBYP — HELO/EHLO restriction bypass."""
import ipaddress, re, smtplib, socket, ssl, statistics, time

from ptlibs.ptdefs import colors


from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "HELO/EHLO Bypass to Open Relay"
__MODULECODE__ = "HELOBYP"
__ORDER__ = 52

_NOT_TESTED = "Could not connect. HELO/EHLO bypass was not tested."
_OPEN_RELAY_IRRELEVANT = "Test is irelevant, because server is set as Open Relay"


def _helobyp_value_line(name: str, bypass: set[str], ehlo_accepted: set[str]) -> tuple[str, str]:
    gray = colors["ADDITIONS"]
    reset = colors["TEXT"]
    if name in bypass:
        return name, "VULN"
    if name not in ehlo_accepted:
        return f"{name} {gray}(not accepted){reset}", "NOTVULN"
    return name, "NOTVULN"


def _stream_helo_bypass_tested_title(e) -> None:
    """Print ``[*] Tested values`` once, after the open-relay probe and before payloads."""
    if e.use_json or getattr(e, "_helobyp_tested_title_shown", False):
        return
    e._ptprint_raw("Tested values", bullet_type="TITLE", condition=True, indent=4)
    e._helobyp_tested_title_shown = True
    e._flush_terminal()


def _stream_helo_bypass_one_value(
    e,
    name: str,
    *,
    bypass: set[str],
    ehlo_accepted: set[str],
) -> None:
    """One EHLO payload: live verdict under ``Tested values`` (after -vv I/O)."""
    if e.use_json:
        return
    e._helobyp_streamed_live = True
    msg, bullet = _helobyp_value_line(name, bypass, ehlo_accepted)
    e._ptprint_raw(msg, bullet_type=bullet, condition=True, indent=8)
    e._flush_terminal()


def test_helo_bypass(e) -> HeloBypassResult:
    """
    Test HELO/EHLO value for bypassing security restrictions (PTV-SVC-SMTP-HELO).
    Each attempt is isolated (new connection) so previous AUTH or EHLO cannot affect state.
    """
    host = e.args.target.ip
    port = e.args.target.port
    timeout = 15.0
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and not use_tls

    def _connect_helo_bypass() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, int]:
        """New connection for each payload - isolated state. Returns (smtp, status)."""
        try:
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
                status, reply = smtp.getreply()
                e.end_if_blocked(status, reply)
                return smtp, status
            smtp = smtplib.SMTP(timeout=timeout)
            status, reply = smtp.connect(host, port)
            if status != 220:
                e.end_if_blocked(status, reply)
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
        except (socket.timeout, ConnectionRefusedError, OSError):
            raise

    def _build_infra_payloads(domain: str | None) -> list[str]:
        """Build Infrastructure payloads from target domain."""
        if not domain or "." not in domain:
            return []
        domain_lower = domain.lower().strip()
        # Dedupe and avoid empty/invalid
        candidates = [
            domain_lower,
            f"mail.{domain_lower}" if not domain_lower.startswith("mail.") else None,
            f"mx1.{domain_lower}",
            f"mx2.{domain_lower}",
            f"vpn.{domain_lower}",
            f"remote.{domain_lower}",
            f"office.{domain_lower}",
        ]
        seen: set[str] = set()
        result: list[str] = []
        for c in candidates:
            if c and c not in seen and _is_valid_hostname(c):
                seen.add(c)
                result.append(c)
        return result

    # Payload groups
    EHLO_GENERIC = ["test", "localhost", "127.0.0.1"]
    EHLO_EXTERNAL = ["gmail.com", "outlook.com"]
    EHLO_DNS = ["nonexistent.invalid"]  # RFC 6761: .invalid never resolves; tests DNS validation
    EHLO_INTERNAL = ["trusted.local", "internal.local", "exchange.local"]

    submission_bypass: list[str] = []
    relay_bypass: list[str] = []
    accepts_invalid: list[str] = []
    tarpitting_list: list[str] = []
    ehlo_comparison: dict = {}
    rcpt_latencies: dict[str, float] = {}

    # Get target domain for Infrastructure payloads (one preliminary connect)
    infra_payloads: list[str] = []
    try:
        smtp_probe, conn_status = _connect_helo_bypass()
        if conn_status == 220:
            _, reply_bytes = smtp_probe.docmd("EHLO", "test")
            reply_str = reply_bytes.decode(errors="replace") if reply_bytes else ""
            server_hostname = _get_hostname_from_ehlo_raw(reply_str)
            if server_hostname:
                reg_domain = _registrable_domain_psl(server_hostname) or server_hostname
                infra_payloads = _build_infra_payloads(reg_domain)
                if server_hostname not in infra_payloads and _is_valid_hostname(server_hostname):
                    infra_payloads.insert(0, server_hostname)
            try:
                smtp_probe.quit()
            except Exception:
                pass
    except Exception:
        pass

    all_payloads = EHLO_GENERIC + EHLO_EXTERNAL + EHLO_DNS + infra_payloads + EHLO_INTERNAL
    # Dedupe preserving order
    seen_payloads: set[str] = set()
    unique_payloads: list[str] = []
    for p in all_payloads:
        if p not in seen_payloads:
            seen_payloads.add(p)
            unique_payloads.append(p)

    if _server_is_open_relay(e, _connect_helo_bypass):
        return HeloBypassResult(
            vulnerable=False,
            indeterminate=False,
            submission_bypass_ehlo=(),
            relay_bypass_ehlo=(),
            accepts_invalid_format=(),
            ehlo_consistent=True,
            ehlo_comparison={},
            tarpitting_detected=(),
            rcpt_latencies={},
            detail=_OPEN_RELAY_IRRELEVANT,
            irrelevant_open_relay=True,
        )

    # Role: port-based hint or ``-R`` / ``--role`` (same as role identification)
    ph = e._role_port_hint()
    port_hint = ph if ph != "unknown" else ("submission" if port in (587, 465, 2525) else "mta")
    rcpt_external = "external-test@gmail.com"
    tested: list[str] = []
    emitted: set[str] = set()

    def _emit_value_result(helo_value: str) -> None:
        if helo_value not in tested or helo_value in emitted:
            return
        emitted.add(helo_value)
        bypass_now = set(submission_bypass) | set(relay_bypass)
        _stream_helo_bypass_one_value(
            e,
            helo_value,
            bypass=bypass_now,
            ehlo_accepted=set(accepts_invalid),
        )

    _stream_helo_bypass_tested_title(e)

    for helo_value in unique_payloads:
        smtp = None
        try:
            smtp, conn_status = _connect_helo_bypass()
            if conn_status != 220:
                if conn_status in (421, 451):
                    return HeloBypassResult(
                        vulnerable=False,
                        indeterminate=True,
                        submission_bypass_ehlo=(),
                        relay_bypass_ehlo=(),
                        accepts_invalid_format=tuple(accepts_invalid),
                        ehlo_consistent=len(set(frozenset(e.get("extensions", [])) for e in ehlo_comparison.values())) <= 1,
                        ehlo_comparison=ehlo_comparison,
                        tarpitting_detected=tuple(tarpitting_list),
                        rcpt_latencies=rcpt_latencies,
                        detail="Rate limiting (421/451)",
                    )
                continue
        except (socket.timeout, ConnectionRefusedError, OSError) as ex:
            if not ehlo_comparison:
                if getattr(e.args, "debug", False) and not e.use_json:
                    e.ptdebug(f"Connect: {ex}", indent_override=4)
                return HeloBypassResult(
                    vulnerable=False,
                    indeterminate=True,
                    submission_bypass_ehlo=(),
                    relay_bypass_ehlo=(),
                    accepts_invalid_format=tuple(accepts_invalid),
                    ehlo_consistent=True,
                    ehlo_comparison=ehlo_comparison,
                    tarpitting_detected=tuple(tarpitting_list),
                    rcpt_latencies=rcpt_latencies,
                    detail=_NOT_TESTED,
                )
            return HeloBypassResult(
                vulnerable=False,
                indeterminate=True,
                submission_bypass_ehlo=tuple(submission_bypass),
                relay_bypass_ehlo=tuple(relay_bypass),
                accepts_invalid_format=tuple(accepts_invalid),
                ehlo_consistent=len(set(frozenset(row.get("extensions", [])) for row in ehlo_comparison.values())) <= 1,
                ehlo_comparison=ehlo_comparison,
                tarpitting_detected=tuple(tarpitting_list),
                rcpt_latencies=rcpt_latencies,
                detail="Reconnect failed",
            )

        try:
            # 1. EHLO <payload>
            ehlo_status, ehlo_reply_bytes = smtp.docmd("EHLO", helo_value)
            ehlo_reply_str = ehlo_reply_bytes.decode(errors="replace") if ehlo_reply_bytes else ""
            e._smtp_vv_io(
                f"EHLO {helo_value}", f"{ehlo_status} {ehlo_reply_str}", indent=8,
            )
            tested.append(helo_value)
            e.end_if_blocked(ehlo_status, ehlo_reply_str)
            extensions = _get_ehlo_extension_keys(ehlo_reply_str)
            ehlo_comparison[helo_value] = {"status": ehlo_status, "extensions": extensions}

            if ehlo_status == 250:
                accepts_invalid.append(helo_value)

            if ehlo_status != 250:
                continue

            # 2. MAIL FROM – measure latency for every payload (auth check may reject here)
            start = time.monotonic()
            mail_status, mail_reply = smtp.docmd("MAIL", "FROM:<tester@example.com>")
            mail_latency = time.monotonic() - start
            e._smtp_vv_io(
                "MAIL FROM:<tester@example.com>",
                f"{mail_status} {e.bytes_to_str(mail_reply)}",
                indent=8,
            )
            e.end_if_blocked(mail_status, mail_reply)

            if mail_status not in (250, 251):
                rcpt_latencies[helo_value] = mail_latency  # Store MAIL latency when rejected here
                if mail_latency > 5.0:
                    tarpitting_list.append(helo_value)
                continue

            # 3. RCPT TO – measure latency
            start = time.monotonic()
            rcpt_status, rcpt_reply = smtp.docmd("RCPT", f"TO:<{rcpt_external}>")
            rcpt_latency = time.monotonic() - start
            e._smtp_vv_io(
                f"RCPT TO:<{rcpt_external}>",
                f"{rcpt_status} {e.bytes_to_str(rcpt_reply)}",
                indent=8,
            )
            e.end_if_blocked(rcpt_status, rcpt_reply)
            rcpt_latencies[helo_value] = rcpt_latency

            if rcpt_latency > 5.0:
                tarpitting_list.append(helo_value)

            # 4. Evaluate: 250=CRITICAL, 530=CORRECT, 550/554=REJECTED
            if rcpt_status in (250, 251):
                if port_hint == "submission":
                    submission_bypass.append(helo_value)
                else:
                    relay_bypass.append(helo_value)
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
            pass
        finally:
            _emit_value_result(helo_value)
            if smtp:
                try:
                    smtp.quit()
                except Exception:
                    try:
                        smtp.close()
                    except Exception:
                        pass

    # Compute ehlo_consistent
    ext_sets = [tuple(e.get("extensions", [])) for e in ehlo_comparison.values()]
    ehlo_consistent = len(set(ext_sets)) <= 1 if ext_sets else True

    vulnerable = bool(submission_bypass or relay_bypass)
    detail_parts = []
    if submission_bypass:
        detail_parts.append(f"Submission bypass with EHLO: {', '.join(submission_bypass)}")
    if relay_bypass:
        detail_parts.append(f"Relay bypass with EHLO: {', '.join(relay_bypass)}")
    if accepts_invalid:
        detail_parts.append(f"Accepts invalid format: {', '.join(accepts_invalid)}")
    if tarpitting_list:
        detail_parts.append(f"Tarpitting detected for: {', '.join(tarpitting_list)}")
    if not detail_parts:
        detail_parts.append("No relay bypass detected (Authorization required)")

    return HeloBypassResult(
        vulnerable=vulnerable,
        indeterminate=False,
        submission_bypass_ehlo=tuple(submission_bypass),
        relay_bypass_ehlo=tuple(relay_bypass),
        accepts_invalid_format=tuple(accepts_invalid),
        ehlo_consistent=ehlo_consistent,
        ehlo_comparison=ehlo_comparison,
        tarpitting_detected=tuple(tarpitting_list),
        rcpt_latencies=rcpt_latencies,
        detail="; ".join(detail_parts),
        tested_ehlo=tuple(tested),
    )

def _server_is_open_relay(e, connect) -> bool:
    """True when open relay is already known, or a fresh probe confirms it."""
    if e.results.open_relay is True and not getattr(e.results, "open_relay_incomplete", False):
        return True
    if e.results.open_relay is False and not getattr(e.results, "open_relay_incomplete", False):
        return False
    from .openrel import open_relay_test
    try:
        smtp, status = connect()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    if status != 220:
        try:
            smtp.close()
        except Exception:
            pass
        return False
    try:
        is_open = open_relay_test(e, smtp, None, None)
    except Exception:
        return False
    finally:
        try:
            smtp.quit()
        except Exception:
            try:
                smtp.close()
            except Exception:
                pass
    e.results.open_relay = bool(is_open)
    if getattr(e.results, "open_relay_incomplete", False):
        return False
    return bool(is_open)


def _stream_helo_bypass_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.helo_bypass_error) is not None:
        pp(f"HELO bypass test failed: {err}", bullet_type="VULN", condition=show, indent=4)
        return
    hb = e.results.helo_bypass
    if hb is None:
        return
    if hb.irrelevant_open_relay:
        pp(_OPEN_RELAY_IRRELEVANT, bullet_type="TITLE", condition=show, indent=4)
        return
    if hb.detail == _NOT_TESTED:
        pp(_NOT_TESTED, bullet_type="WARNING", condition=show, indent=4)
        return
    if hb.indeterminate and not hb.tested_ehlo:
        pp(f"Indeterminate: {hb.detail or 'Could not complete'}", bullet_type="WARNING", condition=show, indent=4)
        return
    if not getattr(e, "_helobyp_streamed_live", False):
        if show:
            _stream_helo_bypass_tested_title(e)
        bypass = set(hb.submission_bypass_ehlo) | set(hb.relay_bypass_ehlo)
        ehlo_accepted = set(hb.accepts_invalid_format)
        for name in hb.tested_ehlo:
            msg, bullet = _helobyp_value_line(name, bypass, ehlo_accepted)
            pp(msg, bullet_type=bullet, condition=show, indent=8)
    if hb.indeterminate:
        pp(f"Indeterminate: {hb.detail or 'Could not complete'}", bullet_type="WARNING", condition=show, indent=4)

def run(ctx):
    e = eng(ctx)
    e._helobyp_streamed_live = False
    e._helobyp_tested_title_shown = False
    try:
        e.results.helo_bypass = test_helo_bypass(e)
    except Exception as ex:
        e.results.helo_bypass_error = str(ex)
        ctx.out(f"HELOBYP failed: {ex}", "ERROR", indent=4)
        return
    _stream_helo_bypass_result(e)
