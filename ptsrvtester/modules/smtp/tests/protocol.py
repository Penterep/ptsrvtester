import ipaddress, re, smtplib, socket, ssl, statistics, time


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ...utils import ptprinthelper

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from ..helpers import *
from ..results import *
from ..registry import *


class ProtocolMixin:

    def test_helo_validation(self) -> HeloValidationResult:
        """
        Test HELO/EHLO hostname validation per RFC 5321 and best practices.
        Vectors: 123, abc (syntactic), localhost, [127.0.0.1], nonexistent.domain.test (DNS),
        target_domain (impersonation), mail.google.com (baseline).
        Handles 421/451 (rate-limiting) by returning indeterminate.
        Hostnames normalized to lowercase for comparison (RFC: domain names case-insensitive).
        """
        BASELINE = "mail.google.com"
        SYNTAX_VECTORS = ["123", "abc"]
        LOCALHOST = "localhost"
        IP_LITERAL = "[127.0.0.1]"
        DNS_NONEXISTENT = "nonexistent.domain.test"
        RATE_LIMIT_CODES = (421, 451)  # Transient failure / rate-limiting

        accepted: list[str] = []
        rejected: list[str] = []
        ehlo_comparison: dict[str, list[str]] = {}

        def _rate_limit_result(last_vector: str, status: int) -> HeloValidationResult:
            return HeloValidationResult(
                vulnerable=False,
                weak_config=False,
                indeterminate=True,
                ehlo_bypass=None,
                accepted_vectors=accepted.copy(),
                rejected_vectors=rejected.copy(),
                ehlo_comparison=ehlo_comparison if ehlo_comparison else None,
                detail=f"Rate-limiting detected (server returned {status}) during vector '{last_vector}'. Test interrupted.",
            )

        def _try_ehlo(hostname: str) -> tuple[int, str]:
            """Connect, send EHLO hostname, return (status, raw_reply). Close connection."""
            try:
                smtp, status, reply = self.connect()
                if status != 220:
                    return (status, self.bytes_to_str(reply))
                status, reply = smtp.docmd("EHLO", hostname)
                raw = self.bytes_to_str(reply)
                try:
                    smtp.quit()
                except Exception:
                    pass
                return (status, raw)
            except Exception as e:
                return (-1, str(e))

        def _store_ehlo(hostname: str, raw: str) -> None:
            """Store EHLO extensions keyed by hostname.lower() (RFC: domain names case-insensitive)."""
            ehlo_comparison[hostname.lower()] = _get_ehlo_extension_keys(raw)

        # 1. Baseline: mail.google.com
        status, raw = _try_ehlo(BASELINE)
        if status in RATE_LIMIT_CODES:
            return _rate_limit_result(BASELINE, status)
        if status != 250:
            return HeloValidationResult(
                vulnerable=False,
                weak_config=False,
                indeterminate=True,
                ehlo_bypass=None,
                accepted_vectors=[],
                rejected_vectors=[BASELINE],
                ehlo_comparison=None,
                detail=f"Baseline failed: server returned {status} for EHLO {BASELINE} (network/blacklist?)",
            )
        _store_ehlo(BASELINE, raw)
        accepted.append(BASELINE)
        target_domain = _get_hostname_from_ehlo_raw(raw)

        # 2. Syntactic vectors
        for vec in SYNTAX_VECTORS:
            status, _ = _try_ehlo(vec)
            if status in RATE_LIMIT_CODES:
                return _rate_limit_result(vec, status)
            if status == 250:
                accepted.append(vec)
            else:
                rejected.append(vec)

        # 3. localhost
        status, raw = _try_ehlo(LOCALHOST)
        if status in RATE_LIMIT_CODES:
            return _rate_limit_result(LOCALHOST, status)
        if status == 250:
            accepted.append(LOCALHOST)
            _store_ehlo(LOCALHOST, raw)
        else:
            rejected.append(LOCALHOST)

        # 4. IP literal
        status, _ = _try_ehlo(IP_LITERAL)
        if status in RATE_LIMIT_CODES:
            return _rate_limit_result(IP_LITERAL, status)
        if status == 250:
            accepted.append(IP_LITERAL)
        else:
            rejected.append(IP_LITERAL)

        # 5. DNS non-existent
        status, _ = _try_ehlo(DNS_NONEXISTENT)
        if status in RATE_LIMIT_CODES:
            return _rate_limit_result(DNS_NONEXISTENT, status)
        if status == 250:
            accepted.append(DNS_NONEXISTENT)
        else:
            rejected.append(DNS_NONEXISTENT)

        # 6. Identity impersonation (target_domain)
        if target_domain:
            status, raw = _try_ehlo(target_domain)
            if status in RATE_LIMIT_CODES:
                return _rate_limit_result(target_domain, status)
            if status == 250:
                accepted.append(target_domain)
                _store_ehlo(target_domain, raw)
            else:
                rejected.append(target_domain)

        # Classify
        vulnerable = any(v in accepted for v in SYNTAX_VECTORS + [LOCALHOST])
        weak_config = DNS_NONEXISTENT in accepted
        ehlo_bypass: bool | None = None
        baseline_keys = set(ehlo_comparison.get(BASELINE, []))
        for host, keys in ehlo_comparison.items():
            if host == BASELINE:
                continue
            if set(keys) - baseline_keys:
                ehlo_bypass = True
                break
        if ehlo_bypass is None and len(ehlo_comparison) > 1:
            ehlo_bypass = False

        detail_parts: list[str] = []
        if vulnerable:
            detail_parts.append("Accepts syntactic nonsense or localhost")
        if weak_config:
            detail_parts.append("Accepts non-existent FQDN (no DNS lookup)")
        if target_domain and target_domain in accepted:
            detail_parts.append("Accepts identity impersonation (own hostname)")
        if ehlo_bypass:
            detail_parts.append("EHLO extensions differ by hostname (access control bypass)")
        if not detail_parts:
            detail_parts.append("Strict HELO/EHLO validation (RFC 5321 best practices)")

        return HeloValidationResult(
            vulnerable=vulnerable,
            weak_config=weak_config,
            indeterminate=False,
            ehlo_bypass=ehlo_bypass,
            accepted_vectors=accepted,
            rejected_vectors=rejected,
            ehlo_comparison=ehlo_comparison if ehlo_comparison else None,
            detail="; ".join(detail_parts),
        )

    def _inv_comm_reply_for_display(self, status: int | None, reply: str | None) -> str:
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

    def _inv_comm_vuln_type(self, status: int | None, got_response: bool, reply: str | None) -> str | None:
        """Determine vulnerability type: acceptance (2xx), timeout, or crash."""
        if status is not None and status < 300:
            return "acceptance"
        if status is None and not got_response:
            r = (reply or "").lower()
            if "timed out" in r or "timeout" in r:
                return "timeout"
            return "crash"
        return None

    def _inv_comm_info_leak(self, reply: str | None) -> bool:
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
        self,
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
        host, port = self.args.target.ip, self.args.target.port

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
                    if self.args.tls or port == 465:
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
        except ssl.SSLError as e:
            return (None, f"SSL Error: {e}", False)
        except (BrokenPipeError, ConnectionResetError):
            return (None, "Connection reset by peer", False)
        except Exception:
            pass
        reply_text = "\n".join(reply_lines) if reply_lines else None
        return (status, reply_text, got_response)

    def test_invalid_commands(self) -> InvCommResult:
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
        vulnerable = False
        weakness = False
        indeterminate = False
        baseline_latency_sec: float | None = None

        # Baseline: measure NOOP latency for adaptive slow_response threshold (e.g. satellite 500ms)
        try:
            smtp, conn_status, _ = self.connect()
            if conn_status == 220:
                try:
                    smtp.docmd("EHLO", self.fqdn)
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
                smtp, conn_status, conn_reply = self.connect()
                if conn_status != 220:
                    return InvCommTestCase(
                        category=category, command_display=display,
                        status=None, reply=self.bytes_to_str(conn_reply) if conn_reply else None,
                        session_ok=None, info_leak=False, vulnerable=True,
                        vuln_type="crash",
                    )
                try:
                    if cmd == "RCPT":
                        ehlo_status, ehlo_reply = smtp.docmd("EHLO", self.fqdn)
                        if ehlo_status != 250:
                            elapsed = time.perf_counter() - t0
                            if ehlo_status in RATE_LIMIT_CODES:
                                indeterminate = True
                            return InvCommTestCase(
                                category=category, command_display=display,
                                status=ehlo_status, reply=self.bytes_to_str(ehlo_reply) if ehlo_reply else None,
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
                                status=mail_status, reply=self.bytes_to_str(mail_reply) if mail_reply else None,
                                session_ok=None, info_leak=False, vulnerable=False,
                                response_time_sec=elapsed if elapsed > 0 else None,
                                slow_response=False, vuln_type=None,
                            )
                    t0 = time.perf_counter()
                    status, reply_bytes = smtp.docmd(cmd, args)
                    elapsed = time.perf_counter() - t0
                    reply = self.bytes_to_str(reply_bytes) if reply_bytes else None
                    got_response = True
                    if status in RATE_LIMIT_CODES:
                        indeterminate = True
                    if status in (250, 251):
                        vulnerable = True
                    if self._inv_comm_info_leak(reply):
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
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, socket.timeout) as e:
                elapsed = time.perf_counter() - t0
                if not got_response:
                    vulnerable = True
                reply = str(e) if reply is None else reply
            except Exception as e:
                elapsed = time.perf_counter() - t0
                reply = str(e)
                if not got_response:
                    vulnerable = True
            case_vuln = (status in (250, 251) if status else False) or (status is None and not got_response)
            vt = "acceptance" if (status is not None and status < 300) else self._inv_comm_vuln_type(status, got_response, reply) if case_vuln else None
            return InvCommTestCase(
                category=category,
                command_display=display,
                status=status,
                reply=reply,
                session_ok=session_ok,
                info_leak=self._inv_comm_info_leak(reply) if reply else False,
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
                smtp, conn_status, conn_reply = self.connect()
                if conn_status != 220:
                    return InvCommTestCase(
                        category="long_input", command_display=display,
                        status=None, reply=self.bytes_to_str(conn_reply) if conn_reply else None,
                        session_ok=None, info_leak=False, vulnerable=True,
                        response_time_sec=None, slow_response=False,
                        vuln_type="crash",
                    )
                try:
                    if cmd == "MAIL":
                        smtp.docmd("EHLO", self.fqdn)
                    t0 = time.perf_counter()
                    status, reply_bytes = smtp.docmd(cmd, args)
                    elapsed = time.perf_counter() - t0
                    reply = self.bytes_to_str(reply_bytes) if reply_bytes else None
                    got_response = True
                    if status in RATE_LIMIT_CODES:
                        indeterminate = True
                    if status in (250, 251):
                        vulnerable = True
                    if self._inv_comm_info_leak(reply):
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
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, socket.timeout) as e:
                elapsed = time.perf_counter() - t0
                if not got_response:
                    vulnerable = True
                reply = str(e) if reply is None else reply
            except Exception as e:
                elapsed = time.perf_counter() - t0
                reply = str(e)
                if not got_response:
                    vulnerable = True
            case_vuln = (status in (250, 251) if status else False) or (status is None and not got_response)
            vt = "acceptance" if (status is not None and status < 300) else self._inv_comm_vuln_type(status, got_response, reply) if case_vuln else None
            return InvCommTestCase(
                category="long_input",
                command_display=display,
                status=status,
                reply=reply,
                session_ok=session_ok,
                info_leak=self._inv_comm_info_leak(reply) if reply else False,
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
            tests.append(t)
            if indeterminate:
                break

        if not indeterminate:
            # 2. Long inputs (10000 chars) - measure response time for ReDoS detection
            long_a = "A" * 10000
            tests.append(_run_long_input_test("MAIL", f"FROM:<{long_a}@example.com>", "MAIL FROM:<A*10000>"))
            if not indeterminate:
                tests.append(_run_long_input_test("HELO", long_a, "HELO A*10000"))

        if not indeterminate:
            # 3. Bad sequence: DATA right after EHLO
            bad_seq_elapsed: float = 0.0
            t0_bad = time.perf_counter()
            try:
                smtp, conn_status, _ = self.connect()
                if conn_status == 220:
                    try:
                        smtp.docmd("EHLO", self.fqdn)
                        t0_bad = time.perf_counter()
                        status, reply_bytes = smtp.docmd("DATA", "")
                        bad_seq_elapsed = time.perf_counter() - t0_bad
                        reply = self.bytes_to_str(reply_bytes) if reply_bytes else None
                        got_response = True
                        if status in (250, 354):
                            vulnerable = True
                        if self._inv_comm_info_leak(reply):
                            weakness = True
                        try:
                            rset_status, _ = smtp.docmd("RSET")
                            session_ok = rset_status == 250
                        except Exception:
                            session_ok = False
                        tests.append(InvCommTestCase(
                            category="bad_sequence",
                            command_display="DATA after EHLO (no MAIL/RCPT)",
                            status=status,
                            reply=reply,
                            session_ok=session_ok,
                            info_leak=self._inv_comm_info_leak(reply) if reply else False,
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
                tests.append(InvCommTestCase(
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
            if self.args.starttls:
                status, reply, got_response = None, None, False
                try:
                    smtp, conn_status, _ = self.connect()
                    if conn_status == 220:
                        try:
                            # RFC 3207: send EHLO again after TLS handshake (server may change capabilities)
                            smtp.docmd("EHLO", self.fqdn)
                            t0_raw = time.perf_counter()
                            status, reply, got_response = self._inv_comm_raw_send_recv(
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
                    smtp, conn_status, _ = self.connect()
                    if conn_status == 220:
                        try:
                            smtp.docmd("EHLO", self.fqdn)
                            t0_raw = time.perf_counter()
                            status, reply, got_response = self._inv_comm_raw_send_recv(
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
            vt = "acceptance" if (status is not None and status < 300) else self._inv_comm_vuln_type(status, got_response, reply) if case_vuln else None
            tests.append(InvCommTestCase(
                category="special_chars",
                command_display="MAIL FROM:<test\\x00@test.example.com>",
                status=status,
                reply=reply,
                session_ok=None,
                info_leak=self._inv_comm_info_leak(reply) if reply else False,
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
                smtp, conn_status, _ = self.connect()
                if conn_status == 220:
                    try:
                        smtp.docmd("EHLO", self.fqdn)
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
                weakness = bool(any(self._inv_comm_info_leak(t.reply) for t in tests if t.reply))

        # Build detail
        vuln_tests = [t for t in tests if t.vulnerable]
        slow_tests = [t for t in tests if getattr(t, "slow_response", False)]
        vulnerable = vulnerable or bool(vuln_tests)  # Ensure overall vulnerable if any test is
        if indeterminate:
            detail = "421/451 Service not available - often Greylisting or Anti-Spam protection (indeterminate, not necessarily application error)"
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
            if any(self._inv_comm_info_leak(t.reply) for t in tests if t.reply):
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

    def test_helo_only(self) -> HeloOnlyResult:
        """
        Test if server supports EHLO extensions or only basic HELO (PTL-SVC-SMTP-HELOONLY).
        Uses same hostname for both HELO and EHLO to avoid false positives from firewalls/antispam
        that may drop EHLO when they dislike the client IP or hostname.
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        helo_host = "test.local"  # Same for both HELO and EHLO - eliminates variable
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
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
                detail = "Not Vulnerable: Server supports ESMTP extensions."
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

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return HeloOnlyResult(
                vulnerable=False,
                indeterminate=True,
                helo_status=None,
                helo_reply=None,
                ehlo_status=None,
                ehlo_reply=None,
                extensions=(),
                connection_type=conn_type,
                detail=str(e),
            )

    def test_helo_bypass(self) -> HeloBypassResult:
        """
        Test HELO/EHLO value for bypassing security restrictions (PTL-SVC-SMTP-HELO).
        Each attempt is isolated (new connection) so previous AUTH or EHLO cannot affect state.
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 15.0
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls

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

        # Role: port-based hint or ``-R`` / ``--role`` (same as role identification)
        ph = self._role_port_hint()
        port_hint = ph if ph != "unknown" else ("submission" if port in (587, 465, 2525) else "mta")
        rcpt_external = "external-test@gmail.com"

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
                            detail="Rate limiting (421/451) - indeterminate",
                        )
                    continue
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
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
                    detail=str(e),
                )

            try:
                # 1. EHLO <payload>
                ehlo_status, ehlo_reply_bytes = smtp.docmd("EHLO", helo_value)
                ehlo_reply_str = ehlo_reply_bytes.decode(errors="replace") if ehlo_reply_bytes else ""
                extensions = _get_ehlo_extension_keys(ehlo_reply_str)
                ehlo_comparison[helo_value] = {"status": ehlo_status, "extensions": extensions}

                if ehlo_status == 250:
                    accepts_invalid.append(helo_value)

                if ehlo_status != 250:
                    smtp.quit()
                    continue

                # 2. MAIL FROM – measure latency for every payload (auth check may reject here)
                start = time.monotonic()
                mail_status, _ = smtp.docmd("MAIL", "FROM:<tester@example.com>")
                mail_latency = time.monotonic() - start

                if mail_status not in (250, 251):
                    rcpt_latencies[helo_value] = mail_latency  # Store MAIL latency when rejected here
                    if mail_latency > 5.0:
                        tarpitting_list.append(helo_value)
                    smtp.quit()
                    continue

                # 3. RCPT TO – measure latency
                start = time.monotonic()
                rcpt_status, _ = smtp.docmd("RCPT", f"TO:<{rcpt_external}>")
                rcpt_latency = time.monotonic() - start
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
        )

    def _stream_helo_validation_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.helo_validation_error) is not None:
            pp(f"HELO validation test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        hv = self.results.helo_validation
        if hv is None:
            return
        if hv.indeterminate:
            pp(f"Indeterminate: {hv.detail or 'Baseline failed'}", bullet_type="TITLE", condition=show, indent=4)
            return
        if hv.vulnerable:
            pp(f"VULNERABLE: {hv.detail}", bullet_type="VULN", condition=show, indent=4)
        elif hv.weak_config:
            pp(f"WEAK CONFIG: {hv.detail}", bullet_type="WARNING", condition=show, indent=4)
        elif hv.ehlo_bypass:
            pp(f"EHLO bypass: {hv.detail}", bullet_type="VULN", condition=show, indent=4)
        else:
            pp(f"SECURE: {hv.detail}", bullet_type="NOTVULN", condition=show, indent=4)
        if hv.accepted_vectors or hv.rejected_vectors:
            pp(f"Accepted: {hv.accepted_vectors}", bullet_type="TEXT", condition=show, indent=8)
            pp(f"Rejected: {hv.rejected_vectors}", bullet_type="TEXT", condition=show, indent=8)

    def _stream_inv_comm_result(self) -> None:
        """Terminal: all probe lines use the INFO bullet only (-iv); severity stays in the text."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.inv_comm_error) is not None:
            pp(f"Invalid commands test failed: {err}", bullet_type="TITLE", condition=show, indent=4)
            return
        ic = self.results.inv_comm
        if ic is None:
            return
        if ic.indeterminate:
            pp(f"Indeterminate: {ic.detail or 'Could not complete'}", bullet_type="TITLE", condition=show, indent=4)
            return
        if show and ic.tests:
            for t in ic.tests:
                if t.vulnerable:
                    vt = getattr(t, "vuln_type", None) or "crash"
                    time_str = f" ({t.response_time_sec:.2f}s)" if getattr(t, "response_time_sec", None) is not None else ""
                    if vt == "acceptance":
                        reply_part = (t.reply or "2xx").split("\n")[0].strip()
                        msg = f"VULNERABLE (ACCEPTANCE): Server accepted invalid input '{t.command_display}' ({reply_part}){time_str}"
                    elif vt == "timeout":
                        msg = f"VULNERABLE (TIMEOUT): No response (timeout) for '{t.command_display}'{time_str}"
                    else:
                        msg = f"VULNERABLE (CRASH): Server stopped responding after '{t.command_display}'{time_str}"
                    pp(msg, bullet_type="TITLE", condition=show, indent=4)
                else:
                    status_str = str(t.status) if t.status is not None else "connection lost"
                    display_reply = self._inv_comm_reply_for_display(t.status, t.reply)
                    short_reply = display_reply or ""
                    time_str = f" ({t.response_time_sec:.2f}s)" if getattr(t, "response_time_sec", None) is not None else ""
                    pp(f"{t.command_display}: {status_str} {short_reply}{time_str}",
                       bullet_type="TITLE", condition=show, indent=4)
                if t.info_leak:
                    pp("Verbose error (possible info leak)", bullet_type="TITLE", condition=show, indent=8)
                if getattr(t, "slow_response", False):
                    if getattr(ic, "tarpitting_detected", False):
                        pp("Tarpitting detected (constant delay - likely smtpd_error_sleep_time)",
                           bullet_type="TITLE", condition=show, indent=8)
                    else:
                        pp("Slow response (possible ReDoS in parser)", bullet_type="TITLE", condition=show, indent=8)
        if getattr(ic, "tarpitting_detected", False):
            pp("INFO: Tarpitting detected (constant delay on invalid commands - likely smtpd_error_sleep_time, not parser bug)",
               bullet_type="TITLE", condition=show, indent=4)
        if ic.vulnerable:
            pass  # Vulnerabilities already shown per-test above
        elif ic.weakness:
            pp(f"WEAKNESS: {ic.detail}", bullet_type="TITLE", condition=show, indent=4)
        else:
            pp(ic.detail, bullet_type="TITLE", condition=show, indent=4)

    def _stream_helo_only_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.helo_only_error) is not None:
            pp(f"HELO-only test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        ho = self.results.helo_only
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

        pp(f"Connection: {ho.connection_type}", bullet_type="TITLE", condition=show, indent=4)
        helo_first = (ho.helo_reply or "").replace("\r", "\n").split("\n")[0].strip()
        pp(f"HELO test.local: {ho.helo_status} {_strip_status_prefix(helo_first)}", bullet_type="TITLE", condition=show, indent=4)
        ehlo_first = (ho.ehlo_reply or "").replace("\r", "\n").split("\n")[0].strip()
        pp(f"EHLO test.local: {ho.ehlo_status} {_strip_status_prefix(ehlo_first)}", bullet_type="TITLE", condition=show, indent=4)
        if ho.extensions:
            for ext in ho.extensions:
                pp(ext, bullet_type="TEXT", condition=show, indent=8)
        if ho.indeterminate:
            pp(f"Indeterminate: {ho.detail or 'Could not complete'}", bullet_type="TITLE", condition=show, indent=4)
        elif ho.vulnerable:
            pp(f"VULNERABLE: {ho.detail}", bullet_type="VULN", condition=show, indent=4)
        else:
            pp(ho.detail, bullet_type="NOTVULN", condition=show, indent=4)

    def _stream_helo_bypass_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.helo_bypass_error) is not None:
            pp(f"HELO bypass test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        hb = self.results.helo_bypass
        if hb is None:
            return
        if hb.accepts_invalid_format:
            pp(f"Info: Accepts loose EHLO formats: {', '.join(hb.accepts_invalid_format)}",
               bullet_type="TITLE", condition=show, indent=4)
        if hb.tarpitting_detected:
            pp(f"Tarpitting detected for: {', '.join(hb.tarpitting_detected)}",
               bullet_type="TITLE", condition=show, indent=4)
        if hb.indeterminate:
            pp(f"Indeterminate: {hb.detail or 'Could not complete'}", bullet_type="TITLE", condition=show, indent=4)
        elif hb.vulnerable:
            bypass_ehlo = tuple(hb.submission_bypass_ehlo) + tuple(hb.relay_bypass_ehlo)
            pp(f"CRITICAL: Relay/Submission bypass with EHLO: {', '.join(bypass_ehlo)}",
               bullet_type="VULN", condition=show, indent=4)
        else:
            pp("No relay bypass detected (Authorization required)", bullet_type="NOTVULN", condition=show, indent=4)
