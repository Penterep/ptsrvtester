"""INVCMD — invalid / non-standard SMTP commands."""
import ipaddress, re, smtplib, socket, ssl, statistics, time





from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "Command Robustness Test"
__MODULECODE__ = "INVCMD"
__ORDER__ = 53


def _inv_comm_reply_for_display(e, status: int | None, reply: str | None) -> str:
    """Strip leading status code from reply to avoid '501 501 ...' duplication."""
    if not reply or status is None:
        return reply or ""
    prefix = f"{status} "
    if reply.startswith(prefix):
        return reply[len(prefix):].lstrip()
    prefix_dash = f"{status}-"
    if reply.startswith(prefix_dash):
        return reply[len(prefix_dash):].lstrip()
    return reply

def _inv_comm_vuln_type(e, status: int | None, got_response: bool, reply: str | None) -> str | None:
    """Determine vulnerability type: acceptance (2xx), timeout, or crash."""
    if status is not None and status < 300:
        return "acceptance"
    if status is None and not got_response:
        r = (reply or "").lower()
        if "timed out" in r or "timeout" in r:
            return "timeout"
        return "crash"
    return None

def _inv_comm_info_leak(e, reply: str | None) -> bool:
    """Detect verbose error messages (paths, versions, stack trace)."""
    if not reply:
        return False
    r = reply.lower()
    patterns = [
        r"/var/", r"/usr/", r"/etc/", r"c:\\", r"c:/",
        r"compiled with", r"version\s+\d", r"openssl\s+[\d.]",
        r"traceback", r"at line", r"exception\s+in", r"stack trace",
        r"\.py\s+line", r"file\s+[\"'].*[\"']",
    ]
    for p in patterns:
        if re.search(p, r, re.IGNORECASE):
            return True
    return False

def _inv_comm_raw_send_recv(
    e,
    raw_cmd: bytes,
    timeout: float = 10.0,
    existing_socket: socket.socket | ssl.SSLSocket | None = None,
) -> tuple[int | None, str | None, bool]:
    """
    Send raw SMTP command over TCP, read reply. Returns (status, reply_text, got_response_before_close).

    If existing_socket is provided (e.g. smtp.sock after EHLO+STARTTLS), uses it directly:
    skips connection/banner, sends raw_cmd, reads reply, does not close the socket.
    Caller establishes the session (EHLO, STARTTLS if needed) and manages the connection.

    If existing_socket is None: creates connection, uses TLS for --tls/port 465,
    reads banner, sends command, reads reply, closes socket.
    """
    got_response = False
    status: int | None = None
    reply_lines: list[str] = []
    host, port = e.args.target.ip, e.args.target.port

    def _send_and_read(sock: socket.socket | ssl.SSLSocket, skip_banner: bool = False) -> None:
        nonlocal got_response, status, reply_lines
        if not skip_banner:
            buf = b""
            while b"\r\n" not in buf and len(buf) < 8192:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                buf += chunk
            got_response = bool(buf)
        else:
            got_response = True
        sock.send(raw_cmd + b"\r\n")
        buf = b""
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
            while b"\r\n" in buf:
                line_bytes, buf = buf.split(b"\r\n", 1)
                line = line_bytes.decode("utf-8", errors="replace")
                reply_lines.append(line)
                if len(line) >= 4 and line[3] in (" ", "\t"):
                    break
            if reply_lines and len(reply_lines[-1]) >= 4 and reply_lines[-1][3] in (" ", "\t"):
                break
        if reply_lines and len(reply_lines[0]) >= 3 and reply_lines[0][:3].isdigit():
            status = int(reply_lines[0][:3])

    try:
        if existing_socket is not None:
            _send_and_read(existing_socket, skip_banner=True)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
            try:
                if e.args.tls or port == 465:
                    ctx = ssl._create_unverified_context()
                    try:
                        try:
                            ipaddress.ip_address(host)
                            sni = None
                        except ValueError:
                            sni = host
                        sock = ctx.wrap_socket(sock, server_hostname=sni)
                    except Exception:
                        return (None, None, False)
                _send_and_read(sock, skip_banner=False)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
    except ssl.SSLError as ex:
        return (None, f"SSL Error: {ex}", False)
    except (BrokenPipeError, ConnectionResetError):
        return (None, "Connection reset by peer", False)
    except Exception:
        pass
    reply_text = "\n".join(reply_lines) if reply_lines else None
    return (status, reply_text, got_response)

def test_invalid_commands(e) -> InvCommResult:
    """
    Test invalid/non-standard SMTP commands (PTL-SVC-SMTP-INVCOMM).
    Verifies server handles invalid commands, long inputs, special chars, and bad sequences.
    421 = Service not available (often Greylisting/Anti-Spam) -> indeterminate.
    Slow response on long input -> possible ReDoS in parser -> weakness.
    Baseline latency measured first (NOOP) for adaptive threshold (e.g. satellite 500ms).
    Constant delay on all invalid commands -> tarpitting (smtpd_error_sleep_time), not parser bug.
    """
    RATE_LIMIT_CODES = (421, 451)  # 421 = often Greylisting/Anti-Spam, not app error
    SLOW_RESPONSE_BASE_SEC = 2.0  # Minimum threshold for ReDoS detection
    SLOW_RESPONSE_EXTRA_SEC = 1.5  # Added to baseline for high-latency links
    TARPIT_STDDEV_MAX = 0.5  # Max std dev of slow response times to consider tarpitting
    TARPIT_MIN_SLOW_COUNT = 2  # Min number of slow responses to detect tarpitting

    tests: list[InvCommTestCase] = []

    def _record(t: InvCommTestCase) -> None:
        tests.append(t)
        if not e.use_json:
            e._inv_streamed_live = True
            _inv_comm_emit_one(e, t, tarpitting=False)
    vulnerable = False
    weakness = False
    indeterminate = False
    baseline_latency_sec: float | None = None

    # Baseline: measure NOOP latency for adaptive slow_response threshold (e.g. satellite 500ms)
    try:
        smtp, conn_status, _ = e.connect()
        if conn_status == 220:
            try:
                smtp.docmd("EHLO", e.fqdn)
                t0 = time.perf_counter()
                status, _ = smtp.docmd("NOOP")
                baseline_latency_sec = time.perf_counter() - t0 if status == 250 else None
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass
    except Exception:
        pass

    slow_threshold = max(SLOW_RESPONSE_BASE_SEC, (baseline_latency_sec or 0) + SLOW_RESPONSE_EXTRA_SEC)

    def _run_docmd_test(cmd: str, args: str, category: str, display: str) -> InvCommTestCase:
        nonlocal vulnerable, weakness, indeterminate
        status: int | None = None
        reply: str | None = None
        session_ok: bool | None = None
        got_response = False
        elapsed: float = 0.0
        t0 = time.perf_counter()
        try:
            smtp, conn_status, conn_reply = e.connect()
            if conn_status != 220:
                elapsed = time.perf_counter() - t0
                if conn_status in RATE_LIMIT_CODES:
                    indeterminate = True
                return InvCommTestCase(
                    category=category, command_display=display,
                    status=conn_status, reply=e.bytes_to_str(conn_reply) if conn_reply else None,
                    session_ok=None, info_leak=False, vulnerable=False,
                    response_time_sec=elapsed if elapsed > 0 else None,
                    slow_response=False, vuln_type=None,
                )
            try:
                if cmd == "RCPT":
                    ehlo_status, ehlo_reply = smtp.docmd("EHLO", e.fqdn)
                    if ehlo_status != 250:
                        elapsed = time.perf_counter() - t0
                        if ehlo_status in RATE_LIMIT_CODES:
                            indeterminate = True
                        return InvCommTestCase(
                            category=category, command_display=display,
                            status=ehlo_status, reply=e.bytes_to_str(ehlo_reply) if ehlo_reply else None,
                            session_ok=None, info_leak=False, vulnerable=False,
                            response_time_sec=elapsed if elapsed > 0 else None,
                            slow_response=False, vuln_type=None,
                        )
                    mail_status, mail_reply = smtp.docmd("MAIL", "FROM:<test@example.com>")
                    if mail_status != 250:
                        elapsed = time.perf_counter() - t0
                        if mail_status in RATE_LIMIT_CODES:
                            indeterminate = True
                        return InvCommTestCase(
                            category=category, command_display=display,
                            status=mail_status, reply=e.bytes_to_str(mail_reply) if mail_reply else None,
                            session_ok=None, info_leak=False, vulnerable=False,
                            response_time_sec=elapsed if elapsed > 0 else None,
                            slow_response=False, vuln_type=None,
                        )
                t0 = time.perf_counter()
                status, reply_bytes = smtp.docmd(cmd, args)
                elapsed = time.perf_counter() - t0
                reply = e.bytes_to_str(reply_bytes) if reply_bytes else None
                got_response = True
                if status in RATE_LIMIT_CODES:
                    indeterminate = True
                if status in (250, 251):
                    vulnerable = True
                if _inv_comm_info_leak(e, reply):
                    weakness = True
                try:
                    rset_status, _ = smtp.docmd("RSET")
                    session_ok = rset_status == 250
                except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                    session_ok = False
                    if got_response:
                        pass
                    else:
                        vulnerable = True
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, socket.timeout) as ex:
            elapsed = time.perf_counter() - t0
            if not got_response:
                vulnerable = True
            reply = str(ex) if reply is None else reply
        except Exception as ex:
            elapsed = time.perf_counter() - t0
            reply = str(ex)
            if not got_response:
                vulnerable = True
        case_vuln = (status in (250, 251) if status else False) or (status is None and not got_response)
        vt = "acceptance" if (status is not None and status < 300) else _inv_comm_vuln_type(e, status, got_response, reply) if case_vuln else None
        return InvCommTestCase(
            category=category,
            command_display=display,
            status=status,
            reply=reply,
            session_ok=session_ok,
            info_leak=_inv_comm_info_leak(e, reply) if reply else False,
            vulnerable=case_vuln,
            response_time_sec=elapsed if elapsed > 0 else None,
            slow_response=False,
            vuln_type=vt,
        )

    def _run_long_input_test(cmd: str, args: str, display: str) -> InvCommTestCase:
        """Run long-input test with timing; flag slow response as possible ReDoS."""
        nonlocal vulnerable, weakness, indeterminate
        status: int | None = None
        reply: str | None = None
        session_ok: bool | None = None
        got_response = False
        elapsed: float = 0.0
        slow = False
        t0 = time.perf_counter()
        try:
            smtp, conn_status, conn_reply = e.connect()
            if conn_status != 220:
                elapsed = time.perf_counter() - t0
                if conn_status in RATE_LIMIT_CODES:
                    indeterminate = True
                return InvCommTestCase(
                    category="long_input", command_display=display,
                    status=conn_status, reply=e.bytes_to_str(conn_reply) if conn_reply else None,
                    session_ok=None, info_leak=False, vulnerable=False,
                    response_time_sec=elapsed if elapsed > 0 else None,
                    slow_response=False, vuln_type=None,
                )
            try:
                if cmd == "MAIL":
                    smtp.docmd("EHLO", e.fqdn)
                t0 = time.perf_counter()
                status, reply_bytes = smtp.docmd(cmd, args)
                elapsed = time.perf_counter() - t0
                reply = e.bytes_to_str(reply_bytes) if reply_bytes else None
                got_response = True
                if status in RATE_LIMIT_CODES:
                    indeterminate = True
                if status in (250, 251):
                    vulnerable = True
                if _inv_comm_info_leak(e, reply):
                    weakness = True
                if elapsed > slow_threshold:
                    slow = True
                    weakness = True
                try:
                    rset_status, _ = smtp.docmd("RSET")
                    session_ok = rset_status == 250
                except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                    session_ok = False
                    if not got_response:
                        vulnerable = True
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, socket.timeout) as ex:
            elapsed = time.perf_counter() - t0
            if not got_response:
                vulnerable = True
            reply = str(ex) if reply is None else reply
        except Exception as ex:
            elapsed = time.perf_counter() - t0
            reply = str(ex)
            if not got_response:
                vulnerable = True
        case_vuln = (status in (250, 251) if status else False) or (status is None and not got_response)
        vt = "acceptance" if (status is not None and status < 300) else _inv_comm_vuln_type(e, status, got_response, reply) if case_vuln else None
        return InvCommTestCase(
            category="long_input",
            command_display=display,
            status=status,
            reply=reply,
            session_ok=session_ok,
            info_leak=_inv_comm_info_leak(e, reply) if reply else False,
            vulnerable=case_vuln,
            response_time_sec=elapsed if elapsed > 0 else None,
            slow_response=slow,
            vuln_type=vt,
        )

    # 1. Invalid commands
    invalid_cmds = [
        ("HELLO", "", "HELLO"),
        ("MAILFROM", ":<>", "MAILFROM:"),
        ("RCPT", ":test@example.com", "RCPT:"),
        ("DATAAAAA", "", "DATAAAAA"),
        ("FOO", "BAR", "FOO BAR"),
        ("HACK", "", "HACK"),
    ]
    for cmd, args, display in invalid_cmds:
        t = _run_docmd_test(cmd, args, "invalid", display)
        _record(t)
        if indeterminate:
            break

    if not indeterminate:
        # 2. Long inputs (10000 chars) - measure response time for ReDoS detection
        long_a = "A" * 10000
        _record(_run_long_input_test("MAIL", f"FROM:<{long_a}@example.com>", "MAIL FROM:<A*10000>"))
        if not indeterminate:
            _record(_run_long_input_test("HELO", long_a, "HELO A*10000"))

    if not indeterminate:
        # 3. Bad sequence: DATA right after EHLO
        bad_seq_elapsed: float = 0.0
        t0_bad = time.perf_counter()
        try:
            smtp, conn_status, _ = e.connect()
            if conn_status == 220:
                try:
                    smtp.docmd("EHLO", e.fqdn)
                    t0_bad = time.perf_counter()
                    status, reply_bytes = smtp.docmd("DATA", "")
                    bad_seq_elapsed = time.perf_counter() - t0_bad
                    reply = e.bytes_to_str(reply_bytes) if reply_bytes else None
                    got_response = True
                    if status in (250, 354):
                        vulnerable = True
                    if _inv_comm_info_leak(e, reply):
                        weakness = True
                    try:
                        rset_status, _ = smtp.docmd("RSET")
                        session_ok = rset_status == 250
                    except Exception:
                        session_ok = False
                    _record(InvCommTestCase(
                        category="bad_sequence",
                        command_display="DATA after EHLO (no MAIL/RCPT)",
                        status=status,
                        reply=reply,
                        session_ok=session_ok,
                        info_leak=_inv_comm_info_leak(e, reply) if reply else False,
                        vulnerable=status in (250, 354) if status else False,
                        response_time_sec=bad_seq_elapsed,
                        slow_response=False,
                        vuln_type="acceptance" if status in (250, 354) else None,
                    ))
                finally:
                    try:
                        smtp.quit()
                    except Exception:
                        pass
        except Exception:
            bad_seq_elapsed = time.perf_counter() - t0_bad
            _record(InvCommTestCase(
                category="bad_sequence",
                command_display="DATA after EHLO (no MAIL/RCPT)",
                status=None,
                reply=None,
                session_ok=None,
                info_leak=False,
                vulnerable=True,
                response_time_sec=bad_seq_elapsed,
                slow_response=False,
                vuln_type="crash",
            ))

    if not indeterminate:
        # 4. Special chars via raw socket (null byte) - plain TCP, implicit TLS, or STARTTLS
        raw_elapsed: float = 0.0
        t0_raw = time.perf_counter()
        if e.args.starttls:
            status, reply, got_response = None, None, False
            try:
                smtp, conn_status, _ = e.connect()
                if conn_status == 220:
                    try:
                        # RFC 3207: send EHLO again after TLS handshake (server may change capabilities)
                        smtp.docmd("EHLO", e.fqdn)
                        t0_raw = time.perf_counter()
                        status, reply, got_response = _inv_comm_raw_send_recv(e, 
                            b"MAIL FROM:<test\x00@test.example.com>",
                            existing_socket=smtp.sock,
                        )
                        raw_elapsed = time.perf_counter() - t0_raw
                    finally:
                        try:
                            smtp.quit()
                        except Exception:
                            pass
            except Exception:
                raw_elapsed = time.perf_counter() - t0_raw
        else:
            status, reply, got_response = None, None, False
            try:
                smtp, conn_status, _ = e.connect()
                if conn_status == 220:
                    try:
                        smtp.docmd("EHLO", e.fqdn)
                        t0_raw = time.perf_counter()
                        status, reply, got_response = _inv_comm_raw_send_recv(e, 
                            b"MAIL FROM:<test\x00@test.example.com>",
                            existing_socket=smtp.sock,
                        )
                        raw_elapsed = time.perf_counter() - t0_raw
                    finally:
                        try:
                            smtp.quit()
                        except Exception:
                            pass
                else:
                    raw_elapsed = 0.0
            except Exception:
                raw_elapsed = 0.0
        if status is None and not got_response:
            vulnerable = True
        case_vuln = (status in (250, 251) if status else False) or (status is None and not got_response)
        vt = "acceptance" if (status is not None and status < 300) else _inv_comm_vuln_type(e, status, got_response, reply) if case_vuln else None
        _record(InvCommTestCase(
            category="special_chars",
            command_display="MAIL FROM:<test\\x00@test.example.com>",
            status=status,
            reply=reply,
            session_ok=None,
            info_leak=_inv_comm_info_leak(e, reply) if reply else False,
            vulnerable=case_vuln,
            response_time_sec=raw_elapsed,
            slow_response=False,
            vuln_type=vt,
        ))
        if status in (250, 251):
            vulnerable = True

    # 5. Session stability check
    if tests and not indeterminate:
        try:
            smtp, conn_status, _ = e.connect()
            if conn_status == 220:
                try:
                    smtp.docmd("EHLO", e.fqdn)
                    status, _ = smtp.docmd("NOOP")
                    if status != 250:
                        pass
                finally:
                    try:
                        smtp.quit()
                    except Exception:
                        pass
        except Exception:
            pass

    # Tarpitting detection: constant delay on invalid commands (smtpd_error_sleep_time) -> not parser bug
    slow_times = [t.response_time_sec for t in tests if getattr(t, "slow_response", False) and getattr(t, "response_time_sec", None) is not None]
    tarpitting_detected = (
        len(slow_times) >= TARPIT_MIN_SLOW_COUNT
        and statistics.stdev(slow_times) < TARPIT_STDDEV_MAX
    )
    if tarpitting_detected:
        weakness_from_slow = any(getattr(t, "slow_response", False) for t in tests)
        if weakness_from_slow:
            weakness = bool(any(_inv_comm_info_leak(e, t.reply) for t in tests if t.reply))

    # Build detail
    vuln_tests = [t for t in tests if t.vulnerable]
    slow_tests = [t for t in tests if getattr(t, "slow_response", False)]
    vulnerable = vulnerable or bool(vuln_tests)  # Ensure overall vulnerable if any test is
    if indeterminate:
        hit = next((t for t in tests if t.status in RATE_LIMIT_CODES), None)
        if hit is not None:
            shown = _inv_comm_reply_for_display(e, hit.status, " ".join((hit.reply or "").split()))
            code_text = f"{hit.status} {shown}".strip() if shown else str(hit.status)
            detail = (
                f"{hit.command_display}: {code_text}. "
                "Service not available, often greylisting or anti-spam, not an application error."
            )
        else:
            detail = "421/451 Service not available, often greylisting or anti-spam, not an application error."
    elif vulnerable:
        bad = vuln_tests[0] if vuln_tests else None
        vt = getattr(bad, "vuln_type", None) if bad else None
        cmd = bad.command_display if bad else "unknown"
        if vt == "acceptance":
            detail = f"Server accepted invalid input '{cmd}' (2xx response)"
        elif vt == "timeout":
            detail = f"No response (timeout) for '{cmd}'"
        else:
            detail = f"Server stopped responding after '{cmd}'"
    elif weakness:
        parts = []
        if slow_tests and not tarpitting_detected:
            parts.append("Slow response on long input (possible ReDoS in parser)")
        if any(_inv_comm_info_leak(e, t.reply) for t in tests if t.reply):
            parts.append("Verbose error messages detected")
        detail = "Server handles invalid commands gracefully; " + "; ".join(parts) if parts else "Server handles invalid commands gracefully"
    else:
        detail = "Server handles invalid commands securely"

    if tarpitting_detected:
        detail = (detail + ". INFO: Tarpitting detected (constant delay on invalid commands - likely smtpd_error_sleep_time, not parser bug)")

    return InvCommResult(
        vulnerable=vulnerable,
        weakness=weakness,
        indeterminate=indeterminate,
        tests=tuple(tests),
        detail=detail,
        baseline_latency_sec=baseline_latency_sec,
        tarpitting_detected=tarpitting_detected,
    )

def _inv_comm_outcome(e, t) -> tuple[str, str]:
    """Result text and bullet. Always include the SMTP code and reply text."""
    reply = " ".join((t.reply or "").replace("\r", " ").split())
    status = t.status
    if status is None and len(reply) >= 3 and reply[:3].isdigit() and (len(reply) == 3 or reply[3] in " -"):
        status = int(reply[:3])
    body = _inv_comm_reply_for_display(e, status, reply) if reply else ""
    if status is not None and body:
        core = f"{status} {body}"
    elif status is not None:
        core = str(status)
    elif body:
        core = body
    else:
        vt = getattr(t, "vuln_type", None)
        if vt == "timeout":
            core = "timeout, no reply"
        elif vt == "acceptance":
            core = "server accepted the command"
        else:
            core = "connection closed, no reply"
    if getattr(t, "vuln_type", None) == "acceptance" and "server accepted" not in core.lower():
        core = f"{core} (server accepted the command)"
    time_str = f" ({t.response_time_sec:.2f}s)" if getattr(t, "response_time_sec", None) is not None else ""
    if status in (421, 451):
        bullet = "WARNING"
    elif t.vulnerable:
        bullet = "VULN"
    else:
        bullet = "TITLE"
    return f"{t.command_display}: {core}{time_str}", bullet


def _inv_comm_emit_one(e, t, *, tarpitting: bool) -> None:
    """One probe: -vv Send/Receive, then the code and server reply."""
    pp = e._ptprint_raw
    recv = t.reply
    if not recv and t.status is not None:
        recv = str(t.status)
    e._smtp_vv_io(t.command_display, recv)
    msg, bullet = _inv_comm_outcome(e, t)
    pp(msg, bullet_type=bullet, condition=True, indent=4)
    if t.info_leak:
        pp("Verbose error (possible info leak)", bullet_type="WARNING", condition=True, indent=8)
    if getattr(t, "slow_response", False):
        if tarpitting:
            pp("Tarpitting (constant delay)", bullet_type="WARNING", condition=True, indent=8)
        else:
            pp("Slow response (possible parser / DoS)", bullet_type="WARNING", condition=True, indent=8)


def _stream_inv_comm_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.inv_comm_error) is not None:
        pp(f"Invalid commands test failed: {err}", bullet_type="TITLE", condition=show, indent=4)
        return
    ic = e.results.inv_comm
    if ic is None:
        return
    if ic.indeterminate:
        pp(f"Indeterminate: {ic.detail or 'Could not complete'}", bullet_type="WARNING", condition=show, indent=4)
        return
    tarpitting = bool(getattr(ic, "tarpitting_detected", False))
    if show and ic.tests and not getattr(e, "_inv_streamed_live", False):
        for t in ic.tests:
            _inv_comm_emit_one(e, t, tarpitting=tarpitting)
    if tarpitting:
        pp(
            "Tarpitting on invalid commands (policy delay, not a parser crash)",
            bullet_type="TITLE",
            condition=show,
            indent=4,
        )
    if ic.vulnerable:
        return
    if ic.weakness:
        pp(ic.detail or "Weakness", bullet_type="WARNING", condition=show, indent=4)
    elif ic.detail:
        pp(ic.detail, bullet_type="NOTVULN", condition=show, indent=4)

def run(ctx):
    e = eng(ctx)
    try:
        e.results.inv_comm = test_invalid_commands(e)
    except Exception as ex:
        e.results.inv_comm_error = str(ex)
        ctx.out(f"INVCMD failed: {ex}", "ERROR", indent=4)
        return
    _stream_inv_comm_result(e)
