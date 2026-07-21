import ipaddress, random, smtplib, socket, ssl, time
from email.mime.text import MIMEText


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


class DeliveryMixin:

    def _alias_variant_title(self, variant: str) -> str:
        return ALIAS_VARIANT_TITLES.get(
            variant,
            variant.replace("_", " ").strip().title() + " test",
        )

    @staticmethod
    def _al_variant_mail_accepted(v: AliasVariantResult) -> bool:
        return v.accepted and not (v.detail and "DATA rejected" in v.detail)

    def _al_variant_outcome_line(self, v: AliasVariantResult) -> str:
        if self._al_variant_mail_accepted(v):
            for line in reversed(v.smtp_trace):
                if line.startswith("DATA:"):
                    code = self._data_trace_status_code(line) or "250"
                    return f"{v.address}: {code} (accepted)"
            return f"{v.address}: 250 (accepted)"
        if v.rejected:
            code = v.smtp_status if v.smtp_status is not None else "?"
            return f"{v.address}: {code} (rejected)"
        if v.error:
            return f"{v.address}: (error)"
        return f"{v.address}: (skipped)"

    def _al_variant_outcome_tail(self, v: AliasVariantResult) -> str | None:
        """Status tail for variant output (without the address prefix)."""
        if self._al_variant_mail_accepted(v):
            return None
        line = self._al_variant_outcome_line(v)
        prefix = f"{v.address}:"
        if line.startswith(prefix):
            tail = line[len(prefix):].strip()
            return tail or None
        return line

    def _al_stream_variant_section(
        self,
        v: AliasVariantResult,
        base_address: str,
        *,
        stream_trace: bool = False,
    ) -> None:
        """Per-variant terminal block for -al."""
        pp = ptprinthelper.ptprint
        pp(self._alias_variant_title(v.variant), bullet_type="TITLE", condition=True, indent=4)
        pp(v.address, bullet_type="TEXT", condition=True, indent=8)
        if stream_trace:
            for line in v.smtp_trace:
                if line.startswith("---"):
                    continue
                self._stream_smtp_trace_line(line, indent_override=12)
        mail_accepted = self._al_variant_mail_accepted(v)
        if mail_accepted and v.test_id:
            self._pp_mail_probe_line(
                pp,
                True,
                accepted=True,
                sent_msg=self._mail_sent_inbox_msg(base_address, v.test_id),
                indent=12,
            )
            if v.uucp_warning:
                pp(
                    "Warning: UUCP syntax accepted",
                    bullet_type="WARNING",
                    condition=True,
                    indent=12,
                )
        else:
            tail = self._al_variant_outcome_tail(v)
            if tail:
                pp(tail, bullet_type="TEXT", condition=True, indent=12)

    def _al_stream_base_section(
        self,
        base_address: str,
        *,
        base_mail_sent: bool = False,
        base_test_id: str = "",
        base_smtp_trace: tuple[str, ...] = (),
        stream_trace: bool = False,
    ) -> None:
        """Terminal block for the base recipient control send."""
        pp = ptprinthelper.ptprint
        pp("Base recipient", bullet_type="TITLE", condition=True, indent=4)
        pp(base_address, bullet_type="TEXT", condition=True, indent=8)
        if stream_trace and base_smtp_trace:
            for line in base_smtp_trace:
                if line.startswith("---"):
                    continue
                self._stream_smtp_trace_line(line, indent_override=12)
        if base_mail_sent and base_test_id:
            self._pp_mail_probe_line(
                pp,
                True,
                accepted=True,
                sent_msg=self._mail_sent_inbox_msg(base_address, base_test_id),
                indent=12,
            )

    def _bcc_stream_section(
        self,
        bc: BccTestResult,
        *,
        stream_trace: bool = False,
    ) -> None:
        """Verbose (-vv) SMTP trace for BCC: full dialog including the DATA payload.

        The DATA trace entry already embeds the message actually transmitted (headers +
        body), so the tester sees exactly what is sent. Nothing is printed without -vv.
        """
        if not stream_trace:
            return
        for line in bc.smtp_trace:
            if line.startswith("---"):
                continue
            self._stream_smtp_trace_line(line, indent_override=4)

    def _bcc_stream_summary_block(self, bc: BccTestResult) -> None:
        """Result footer for BCC: single mail-sent verdict (or failure reason)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if not show:
            return
        if bc.message_accepted and bc.test_id:
            inbox = bc.recipients_to[0] if bc.recipients_to else ""
            self._pp_mail_probe_line(
                pp,
                True,
                accepted=True,
                sent_msg=self._mail_sent_inbox_msg(inbox, bc.test_id),
                indent=4,
            )
        else:
            reason = bc.detail or "Message was not accepted by the server"
            pp(reason, bullet_type="WARNING", condition=True, indent=4)

    def test_bounce_replay(self) -> BounceReplayResult:
        """
        Bounce / backscatter test (PTL-SVC-SMTP-REPLAY).
        Two probes on one connection: (1) MAIL FROM + DATA with From header only;
        (2) MAIL FROM + DATA including Return-Path header — to observe whether the MTA
        mishandles envelope vs header paths for NDRs. Uses 30s timeout per command.
        When -u/-p (or first line of -U/-P) are set, performs AUTH LOGIN after EHLO before probes.
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 30.0
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls

        bounce_addr = _bounce_replay_from_addr(self.args)
        if not bounce_addr:
            return BounceReplayResult(
                vulnerable=False,
                indeterminate=True,
                message_accepted=False,
                rcpt_rejected_in_session=False,
                bounce_addr="",
                recipient_used="",
                test_id="",
                smtp_trace=(),
                tarpitting_or_timeout=False,
                detail="-br requires -m/--mail-from (controlled address for MAIL FROM / bounce checks)",
                message_accepted_return_path=False,
                test_id_return_path="",
            )

        bounce_addr = str(bounce_addr).strip()
        test_id = f"{random.getrandbits(32):08x}"
        test_id_rp = f"{random.getrandbits(32):08x}"
        rcpt_raw = getattr(self.args, "rcpt_to", None) or ""
        recipient = str(rcpt_raw).strip()
        if not recipient:
            return BounceReplayResult(
                vulnerable=False,
                indeterminate=True,
                message_accepted=False,
                rcpt_rejected_in_session=False,
                bounce_addr=bounce_addr,
                recipient_used="",
                test_id=test_id,
                smtp_trace=(),
                tarpitting_or_timeout=False,
                detail="-br requires -r/--rcpt-to (recipient)",
                message_accepted_return_path=False,
                test_id_return_path="",
            )

        msg_id_domain = "example.com"
        if "@" in bounce_addr:
            msg_id_domain = bounce_addr.split("@", 1)[1].strip()
        if not msg_id_domain or "." not in msg_id_domain:
            msg_id_domain = "example.com"

        def _build_body(include_return_path: bool, tid: str) -> str:
            rp = f"Return-Path: <{bounce_addr}>\r\n" if include_return_path else ""
            return (
                f"{rp}"
                f"From: <{bounce_addr}>\r\n"
                f"To: <{recipient}>\r\n"
                f"Subject: {self._outbound_subject()}\r\n"
                f"{EMAIL_HDR_TEST_ID}: {tid}\r\n"
                f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
                f"Message-ID: <{tid}.{int(time.time())}@{msg_id_domain}>\r\n"
                f"\r\n"
                f"{self._outbound_data()}\r\n"
            )

        def _connect_br() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, int]:
            if use_tls:
                try:
                    ipaddress.ip_address(host)
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
                stls_status, _ = smtp.docmd("STARTTLS")
                if stls_status != 220:
                    return smtp, stls_status
                try:
                    ipaddress.ip_address(host)
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

        smtp_trace: list[str] = []
        self._bounce_replay_streamed_live = False

        def _br_trace_append(line: str) -> None:
            """Store SMTP trace for -br; live -vv lines under probe title (indent 8)."""
            smtp_trace.append(line)
            if self.args.debug and not self.use_json:
                self._bounce_replay_streamed_live = True
                self._br_stream_trace_line(line)

        def _br_smtp_reply(status: int, reply) -> str:
            text = self.bytes_to_str(reply).strip().replace("\r\n", " ").replace("\n", " ")
            return f"{status} {text}" if text else str(status)

        def _phase(
            smtp: smtplib.SMTP | smtplib.SMTP_SSL,
            label: str,
            body: str,
        ) -> tuple[bool, bool, bool, bool, str | None]:
            """Returns (data_accepted_250, rcpt_rejected_5xx, mail_rejected, indeterminate, detail)."""
            _br_trace_append(f"--- {label} ---")
            try:
                mail_status, mail_reply = smtp.docmd("MAIL", f"FROM:<{bounce_addr}>")
                mail_line = _br_smtp_reply(mail_status, mail_reply)
                _br_trace_append(f"MAIL FROM: {mail_line}")
            except socket.timeout:
                _br_trace_append("MAIL FROM: timeout")
                return False, False, True, True, "Timeout (30s) on MAIL FROM"
            if mail_status not in (250, 251):
                return False, False, True, False, f"MAIL FROM rejected: {mail_line}"
            try:
                rcpt_status, rcpt_reply = smtp.docmd("RCPT", f"TO:<{recipient}>")
                rcpt_line = _br_smtp_reply(rcpt_status, rcpt_reply)
                _br_trace_append(f"RCPT TO: {rcpt_line}")
            except socket.timeout:
                _br_trace_append("RCPT TO: timeout")
                return False, False, False, True, "Timeout (30s) on RCPT TO"
            if rcpt_status not in (250, 251):
                return False, True, False, False, f"RCPT TO rejected: {rcpt_line}"
            try:
                data_status, data_reply = smtp.data(body)
                data_line = _br_smtp_reply(data_status, data_reply)
                _br_trace_append(self._data_trace_entry(body, reply=data_line))
            except socket.timeout:
                _br_trace_append("DATA: timeout")
                return False, False, False, True, "Timeout (30s) on DATA"
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                _br_trace_append(f"DATA: {e}")
                return False, False, False, True, f"Connection closed during DATA: {e}"
            if data_status == 250:
                return True, False, False, False, None
            return False, False, True, False, f"DATA rejected: {data_line}"

        try:
            smtp, conn_status = _connect_br()
            if conn_status != 220:
                _br_trace_append(f"Connect: {conn_status}")
                try:
                    smtp.quit()
                except Exception:
                    pass
                return BounceReplayResult(
                    vulnerable=False,
                    indeterminate=True,
                    message_accepted=False,
                    rcpt_rejected_in_session=False,
                    bounce_addr=bounce_addr,
                    recipient_used=recipient,
                    test_id=test_id,
                    smtp_trace=tuple(smtp_trace),
                    tarpitting_or_timeout=False,
                    detail=f"Connection failed: {conn_status}",
                    message_accepted_return_path=False,
                    test_id_return_path="",
                )

            self._br_stream_probe_section_title("Test From header without Return-Path")
            auth_used = False
            try:
                ehlo_status, _ = smtp.docmd("EHLO", self.fqdn or "bounce-test.local")
                _br_trace_append(f"EHLO: {ehlo_status}")
            except socket.timeout:
                _br_trace_append("EHLO: timeout")
                try:
                    smtp.quit()
                except Exception:
                    pass
                self._br_stream_probe_verdict(
                    accepted=False,
                    indeterminate=True,
                    detail="Timeout (30s) on EHLO - possible greylisting or tarpitting (WARNING)",
                    bounce_addr=bounce_addr,
                )
                return BounceReplayResult(
                    vulnerable=False,
                    indeterminate=True,
                    message_accepted=False,
                    rcpt_rejected_in_session=False,
                    bounce_addr=bounce_addr,
                    recipient_used=recipient,
                    test_id=test_id,
                    smtp_trace=tuple(smtp_trace),
                    tarpitting_or_timeout=True,
                    detail="Timeout (30s) on EHLO - possible greylisting or tarpitting (WARNING)",
                    message_accepted_return_path=False,
                    test_id_return_path="",
                )

            br_user, br_pass = self._rl_first_creds()
            if br_user and br_pass:
                try:
                    smtp.login(br_user, br_pass)
                    auth_used = True
                    _br_trace_append(f"AUTH LOGIN: OK ({br_user})")
                except smtplib.SMTPAuthenticationError as e:
                    _br_trace_append(f"AUTH LOGIN: failed ({e})")
                    try:
                        smtp.quit()
                    except Exception:
                        pass
                    auth_detail = f"AUTH LOGIN failed for {br_user}: {e}"
                    self._br_stream_probe_verdict(
                        accepted=False,
                        indeterminate=True,
                        detail=auth_detail,
                        bounce_addr=bounce_addr,
                    )
                    return BounceReplayResult(
                        vulnerable=False,
                        indeterminate=True,
                        message_accepted=False,
                        rcpt_rejected_in_session=False,
                        bounce_addr=bounce_addr,
                        recipient_used=recipient,
                        test_id=test_id,
                        smtp_trace=tuple(smtp_trace),
                        tarpitting_or_timeout=False,
                        detail=auth_detail,
                        message_accepted_return_path=False,
                        test_id_return_path="",
                    )
                except (socket.timeout, smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                    _br_trace_append(f"AUTH LOGIN: error ({e})")
                    try:
                        smtp.quit()
                    except Exception:
                        pass
                    auth_detail = f"AUTH LOGIN error for {br_user}: {e}"
                    self._br_stream_probe_verdict(
                        accepted=False,
                        indeterminate=True,
                        detail=auth_detail,
                        bounce_addr=bounce_addr,
                    )
                    return BounceReplayResult(
                        vulnerable=False,
                        indeterminate=True,
                        message_accepted=False,
                        rcpt_rejected_in_session=False,
                        bounce_addr=bounce_addr,
                        recipient_used=recipient,
                        test_id=test_id,
                        smtp_trace=tuple(smtp_trace),
                        tarpitting_or_timeout="timeout" in str(e).lower(),
                        detail=auth_detail,
                        message_accepted_return_path=False,
                        test_id_return_path="",
                    )

            body1 = _build_body(include_return_path=False, tid=test_id)
            acc1, rcpt_rej1, mail_rej1, indet1, det1 = _phase(
                smtp, "Probe 1: MAIL FROM + DATA (From header; no Return-Path in body)", body1
            )
            self._br_stream_probe_verdict(
                accepted=acc1,
                indeterminate=indet1,
                detail=det1,
                bounce_addr=bounce_addr,
                test_id=test_id,
            )
            if indet1:
                try:
                    smtp.quit()
                except Exception:
                    pass
                return BounceReplayResult(
                    vulnerable=False,
                    indeterminate=True,
                    message_accepted=False,
                    rcpt_rejected_in_session=rcpt_rej1,
                    bounce_addr=bounce_addr,
                    recipient_used=recipient,
                    test_id=test_id,
                    smtp_trace=tuple(smtp_trace),
                    tarpitting_or_timeout=True,
                    detail=det1 or "Probe 1 incomplete",
                    message_accepted_return_path=False,
                    test_id_return_path="",
                    probe1_detail=det1,
                    probe1_indeterminate=True,
                    auth_used=auth_used,
                )

            try:
                smtp.docmd("RSET")
                _br_trace_append("RSET")
            except Exception:
                pass

            self._br_stream_probe_section_title("Test From headers and Return-Path")
            body2 = _build_body(include_return_path=True, tid=test_id_rp)
            acc2, rcpt_rej2, mail_rej2, indet2, det2 = _phase(
                smtp, "Probe 2: MAIL FROM + DATA (Return-Path + From headers)", body2
            )
            self._br_stream_probe_verdict(
                accepted=acc2,
                indeterminate=indet2,
                detail=det2,
                bounce_addr=bounce_addr,
                test_id=test_id_rp,
            )

            try:
                smtp.quit()
            except Exception:
                pass

            rcpt_rejected_both = (rcpt_rej1 or rcpt_rej2) and not (acc1 or acc2)
            parts: list[str] = []
            if acc1:
                parts.append(
                    f"Probe 1: server accepted DATA (250) — possible backscatter. "
                    f"Check {bounce_addr} for NDR within 2–5 min. Test ID: {test_id}"
                )
            elif det1 and not acc1 and not indet1:
                parts.append(f"Probe 1: {det1}")
            if indet2:
                parts.append(f"Probe 2: {det2 or 'timeout or connection lost'}")
            elif acc2:
                parts.append(
                    f"Probe 2 (Return-Path in DATA): server accepted DATA (250). "
                    f"Check {bounce_addr} for NDR. Test ID: {test_id_rp}"
                )
            elif det2:
                parts.append(f"Probe 2: {det2}")

            if not parts:
                detail = "NOT VULNERABLE: No successful DATA acceptance in either probe"
            else:
                detail = " ".join(parts)

            return BounceReplayResult(
                vulnerable=False,
                indeterminate=bool(indet2 and not (acc1 or acc2)),
                message_accepted=acc1,
                rcpt_rejected_in_session=rcpt_rejected_both,
                bounce_addr=bounce_addr,
                recipient_used=recipient,
                test_id=test_id,
                smtp_trace=tuple(smtp_trace),
                tarpitting_or_timeout=bool(indet2 and not (acc1 or acc2)),
                detail=detail,
                message_accepted_return_path=acc2,
                test_id_return_path=test_id_rp if acc2 else "",
                probe1_detail=det1,
                probe2_detail=det2,
                probe1_indeterminate=False,
                probe2_indeterminate=indet2,
                auth_used=auth_used,
            )

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return BounceReplayResult(
                vulnerable=False,
                indeterminate=True,
                message_accepted=False,
                rcpt_rejected_in_session="timeout" in str(e).lower(),
                bounce_addr=bounce_addr,
                recipient_used=recipient,
                test_id=test_id,
                smtp_trace=tuple(smtp_trace),
                tarpitting_or_timeout="timeout" in str(e).lower(),
                detail=f"Connection error: {e}",
                message_accepted_return_path=False,
                test_id_return_path="",
            )

    def test_spoof_headers(self) -> SpoofHeaderResult:
        """
        Test header spoofing (From, Reply-To, Return-Path).
        Sends messages with spoofed headers and records accepted vs rejected.
        Uses MIMEText/as_string() for proper CRLF separation (headers vs body).
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt = str(self.args.rcpt_to).strip()
        mail_from = self.args.mail_from or f"spoofhdrtest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        timeout = max(5.0, getattr(self.args, "spoofhdr_timeout", 30.0))
        variants_arg = getattr(self.args, "spoofhdr_variants", None)
        default_variants = ["from", "reply_to", "return_path"]
        if variants_arg:
            variants = [v.strip().lower().replace("-", "_") for v in variants_arg.split(",") if v.strip()]
        else:
            variants = list(default_variants)

        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        auth_user = getattr(self.args, "user", None) or ""
        auth_pass = getattr(self.args, "password", None) or ""
        do_auth = bool(auth_user and auth_pass)

        start_time = time.perf_counter()
        var_results: list[SpoofHeaderVariantResult] = []
        self._spoof_header_streamed_live = False
        VULNERABLE_NOTE = (
            "Message was accepted, but the ultimate impact depends on the target domain's SPF/DMARC "
            "policy and the recipient client's ability to detect spoofing."
        )

        def _sh_trace_append(trace: list[str], line: str) -> None:
            """Store SMTP trace for -sh; printed once under variant title (-vv via _sh_stream_variant_section)."""
            trace.append(line)

        def _connect_sh(trace: list[str]) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, reply = smtp.getreply()
                    if st != 220:
                        _sh_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                        return None, f"Connect: {st}"
                    _sh_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                else:
                    smtp = smtplib.SMTP(timeout=timeout)
                    st, reply = smtp.connect(host, port)
                    if st != 220:
                        _sh_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                        return None, f"Connect: {st}"
                    _sh_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                    if use_starttls:
                        st2, reply2 = smtp.docmd("STARTTLS")
                        _sh_trace_append(trace, f"STARTTLS: {self._smtp_trace_reply(st2, reply2)}")
                        if st2 != 220:
                            return None, f"STARTTLS: {st2}"
                        try:
                            ipaddress.ip_address(host)
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
                ehlo_st, ehlo_reply = smtp.docmd("EHLO", self.fqdn or "spoofhdr-test.local")
                _sh_trace_append(trace, f"EHLO: {self._smtp_trace_reply(ehlo_st, ehlo_reply)}")
                if do_auth:
                    try:
                        smtp.login(auth_user, auth_pass)
                        _sh_trace_append(trace, "AUTH: ok")
                    except smtplib.SMTPAuthenticationError as e:
                        _sh_trace_append(trace, f"AUTH failed: {e}")
                        return None, f"AUTH failed: {e}"
                return smtp, ""
            except Exception as e:
                _sh_trace_append(trace, f"Connect: {e}")
                return None, str(e)

        def _build_sh_msg(test_id: str, **header_fields: str) -> str:
            msg = MIMEText(f"{self._outbound_data()}\r\n", "plain", "utf-8")
            for key, value in header_fields.items():
                msg[key] = value
            msg["To"] = f"<{rcpt}>"
            msg["Subject"] = self._outbound_subject()
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg[EMAIL_HDR_TEST] = "SPOOFHDR"
            msg[EMAIL_HDR_TEST_ID] = test_id
            return msg.as_string()

        def _run_sh_variant(
            variant: str,
            *,
            test_id: str,
            spoof_note: str,
            raw_msg: str,
            envelope_addr: str,
            envelope_header_mismatch: bool,
            accepted_detail: str,
        ) -> SpoofHeaderVariantResult:
            smtp_trace: list[str] = []
            _sh_trace_append(smtp_trace, spoof_note)
            accepted = rejected = err = False
            status_code: int | None = None
            reply_str: str | None = None
            detail = ""

            smtp, conn_err = _connect_sh(smtp_trace)
            if smtp is None:
                err = True
                detail = f"Connection failed: {conn_err}"
            else:
                try:
                    mail_st, mail_reply = smtp.docmd("MAIL", f"FROM:<{envelope_addr}>")
                    _sh_trace_append(
                        smtp_trace,
                        f"MAIL FROM <{envelope_addr}>: {self._smtp_trace_reply(mail_st, mail_reply)}",
                    )
                    if mail_st not in (250, 251):
                        rejected = True
                        status_code = mail_st
                        reply_str = self._smtp_reply_text_one_line(mail_reply)
                        detail = f"MAIL FROM rejected: {mail_st}"
                    else:
                        status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                        status_code = status
                        reply_str = self._smtp_reply_text_one_line(reply)
                        _sh_trace_append(
                            smtp_trace,
                            f"RCPT TO <{rcpt}>: {self._smtp_trace_reply(status, reply)}",
                        )
                        if status not in (250, 251):
                            rejected = True
                            detail = f"RCPT rejected: {status}"
                        else:
                            data_status, data_reply = smtp.data(raw_msg)
                            status_code = data_status
                            reply_str = self._smtp_reply_text_one_line(data_reply)
                            _sh_trace_append(
                                smtp_trace,
                                self._data_trace_entry(raw_msg, data_status, data_reply),
                            )
                            if data_status == 250:
                                accepted = True
                                detail = accepted_detail
                            else:
                                rejected = True
                                detail = f"Server rejected DATA: {data_status}"
                    smtp.quit()
                except Exception as e:
                    err = True
                    _sh_trace_append(smtp_trace, f"error: {e}")
                    detail = str(e)

            result = SpoofHeaderVariantResult(
                variant=variant,
                test_id=test_id,
                accepted=accepted,
                rejected=rejected,
                error=err,
                smtp_status=status_code,
                smtp_reply=reply_str,
                detail=detail or None,
                envelope_header_mismatch=envelope_header_mismatch,
                smtp_trace=tuple(smtp_trace),
            )
            if not self.use_json and self.args.debug:
                self._spoof_header_streamed_live = True
                self._sh_stream_variant_section(result, rcpt, stream_trace=True)
            return result

        if "from" in variants:
            from_header = "CEO <ceo@trusted-company.com>"
            from_test_id = self._new_mail_test_id()
            var_results.append(
                _run_sh_variant(
                    "from",
                    test_id=from_test_id,
                    spoof_note=(
                        f"Spoof: MAIL FROM=<{mail_from}>, From: {from_header}"
                    ),
                    raw_msg=_build_sh_msg(from_test_id, From=from_header),
                    envelope_addr=mail_from,
                    envelope_header_mismatch=True,
                    accepted_detail=(
                        f"Server ACCEPTED message: MAIL FROM (envelope)={mail_from}, "
                        f"From (header)={from_header}"
                    ),
                )
            )

        if "reply_to" in variants:
            from_header = "support@trusted.com"
            reply_to_test_id = self._new_mail_test_id()
            var_results.append(
                _run_sh_variant(
                    "reply_to",
                    test_id=reply_to_test_id,
                    spoof_note=f"Spoof: From: {from_header}, Reply-To: attacker@evil.com",
                    raw_msg=_build_sh_msg(
                        reply_to_test_id,
                        From=from_header,
                        **{"Reply-To": "attacker@evil.com"},
                    ),
                    envelope_addr=mail_from,
                    envelope_header_mismatch=False,
                    accepted_detail="Server ACCEPTED message with spoofed Reply-To: attacker@evil.com",
                )
            )

        if "return_path" in variants:
            return_path_test_id = self._new_mail_test_id()
            var_results.append(
                _run_sh_variant(
                    "return_path",
                    test_id=return_path_test_id,
                    spoof_note="Spoof: Return-Path: <admin@trusted.com>, From: admin@trusted.com",
                    raw_msg=_build_sh_msg(
                        return_path_test_id,
                        From="admin@trusted.com",
                        **{"Return-Path": "<admin@trusted.com>"},
                    ),
                    envelope_addr=mail_from,
                    envelope_header_mismatch=False,
                    accepted_detail=(
                        "Server ACCEPTED message with client-set Return-Path (Backscatter risk)"
                    ),
                )
            )

        elapsed = time.perf_counter() - start_time
        any_accepted = any(v.accepted for v in var_results)
        all_error = len(var_results) > 0 and all(v.error for v in var_results)
        indeterminate = all_error or (len(var_results) == 0)
        detail_parts = []
        if any_accepted:
            accepted_vars = [v.variant for v in var_results if v.accepted]
            detail_parts.append(f"Accepted: {', '.join(accepted_vars)}. Manual check of recipient inbox recommended.")
            from_mismatch = [v for v in var_results if v.variant == "from" and v.accepted and v.envelope_header_mismatch]
            if from_mismatch:
                detail_parts.append(
                    "ENVELOPE vs HEADER MISMATCH: MAIL FROM (envelope) differed from From (header) — server accepted."
                )
        elif not indeterminate:
            detail_parts.append("All variants rejected – server blocks spoofed headers.")
        if indeterminate:
            detail_parts.append("Could not complete – connection or other errors.")

        return SpoofHeaderResult(
            vulnerable=any_accepted,
            indeterminate=indeterminate,
            variants=tuple(var_results),
            elapsed_sec=elapsed,
            detail=" ".join(detail_parts) if detail_parts else None,
            vulnerable_note=VULNERABLE_NOTE if any_accepted else None,
        )

    def test_bcc(self) -> BccTestResult:
        """
        BCC disclosure test – sends message with To, Cc, Bcc; manual verification required.
        Envelope (RCPT TO) contains all recipients; Bcc header in DATA must be stripped by server.
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt_to = str(self.args.rcpt_to).strip()
        cc_raw = getattr(self.args, "cc", None) or ""
        bcc_raw = getattr(self.args, "bcc_test", None) or ""
        cc_list = [a.strip() for a in cc_raw.split(",") if a.strip()]
        bcc_list = [a.strip() for a in bcc_raw.split(",") if a.strip()]
        mail_from = self.args.mail_from or f"bcctest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        timeout = max(5.0, getattr(self.args, "bcc_timeout", 30.0))
        auth_user = getattr(self.args, "user", None) or ""
        auth_pass = getattr(self.args, "password", None) or ""
        do_auth = bool(auth_user and auth_pass)

        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls

        to_addr = rcpt_to
        cc_addrs = cc_list
        bcc_addrs = bcc_list
        all_recipients = [to_addr] + cc_addrs + bcc_addrs

        VERIFICATION_INSTRUCTIONS = (
            "Check all recipients' inboxes. View Message Source / Original Header. "
            "SEARCH for 'Bcc' or Bcc recipient addresses. If NOT FOUND: SECURE. If FOUND: VULNERABLE (BCC disclosure)."
        )

        def _bcc_trace_append(trace: list[str], line: str) -> None:
            trace.append(line)

        def _connect_bcc(trace: list[str]) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, reply = smtp.getreply()
                    if st != 220:
                        _bcc_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                        return None, f"Connect: {st}"
                    _bcc_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                else:
                    smtp = smtplib.SMTP(timeout=timeout)
                    st, reply = smtp.connect(host, port)
                    if st != 220:
                        _bcc_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                        return None, f"Connect: {st}"
                    _bcc_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                    if use_starttls:
                        st2, reply2 = smtp.docmd("STARTTLS")
                        _bcc_trace_append(trace, f"STARTTLS: {self._smtp_trace_reply(st2, reply2)}")
                        if st2 != 220:
                            return None, f"STARTTLS: {st2}"
                        try:
                            ipaddress.ip_address(host)
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
                ehlo_st, ehlo_reply = smtp.docmd("EHLO", self.fqdn or "bcc-test.local")
                _bcc_trace_append(trace, f"EHLO: {self._smtp_trace_reply(ehlo_st, ehlo_reply)}")
                if do_auth:
                    try:
                        smtp.login(auth_user, auth_pass)
                        _bcc_trace_append(trace, "AUTH: ok")
                    except smtplib.SMTPAuthenticationError as e:
                        _bcc_trace_append(trace, f"AUTH failed: {e}")
                        return None, f"AUTH failed: {e}"
                return smtp, ""
            except Exception as e:
                _bcc_trace_append(trace, f"Connect: {e}")
                return None, str(e)

        start_time = time.perf_counter()
        self._bcc_streamed_live = False
        to_hdr = ", ".join(f"<{a}>" for a in [to_addr])
        cc_hdr = ", ".join(f"<{a}>" for a in cc_addrs)
        bcc_hdr = ", ".join(f"<{a}>" for a in bcc_addrs)

        msg = MIMEText(f"{self._outbound_data()}\r\n", "plain", "utf-8")
        msg["From"] = f"<{mail_from}>"
        msg["To"] = to_hdr
        msg["Cc"] = cc_hdr
        msg["Bcc"] = bcc_hdr
        msg["Subject"] = self._outbound_subject()
        msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
        msg[EMAIL_HDR_TEST] = "BCC"
        bcc_test_id = self._new_mail_test_id()
        msg[EMAIL_HDR_TEST_ID] = bcc_test_id
        raw_msg = msg.as_string()

        smtp_trace: list[str] = []
        smtp, conn_err = _connect_bcc(smtp_trace)
        message_accepted = False
        status_code = None
        reply_str = None
        detail = ""

        if smtp is None:
            detail = f"Connection failed: {conn_err}"
        else:
            try:
                mail_st, mail_reply = smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                _bcc_trace_append(
                    smtp_trace,
                    f"MAIL FROM <{mail_from}>: {self._smtp_trace_reply(mail_st, mail_reply)}",
                )
                if mail_st not in (250, 251):
                    detail = f"MAIL FROM rejected: {mail_st}"
                else:
                    for recp in all_recipients:
                        status, reply = smtp.docmd("RCPT", f"TO:<{recp}>")
                        _bcc_trace_append(
                            smtp_trace,
                            f"RCPT TO <{recp}>: {self._smtp_trace_reply(status, reply)}",
                        )
                        if status not in (250, 251):
                            detail = f"RCPT TO:<{recp}> rejected: {status}"
                            break
                    else:
                        data_status, data_reply = smtp.data(raw_msg)
                        _bcc_trace_append(
                            smtp_trace,
                            self._data_trace_entry(raw_msg, data_status, data_reply),
                        )
                        status_code = data_status
                        reply_str = data_reply.decode() if isinstance(data_reply, bytes) else str(data_reply)
                        if data_status == 250:
                            message_accepted = True
                            detail = "Message sent successfully. Manual verification required."
                        else:
                            detail = f"Server rejected DATA: {data_status}"
            except Exception as e:
                _bcc_trace_append(smtp_trace, f"error: {e}")
                detail = str(e)
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass

        elapsed = time.perf_counter() - start_time
        bcc_result = BccTestResult(
            message_accepted=message_accepted,
            smtp_status=status_code,
            smtp_reply=reply_str,
            recipients_to=tuple([to_addr]),
            recipients_cc=tuple(cc_addrs),
            recipients_bcc=tuple(bcc_addrs),
            elapsed_sec=elapsed,
            detail=detail or None,
            verification_instructions=VERIFICATION_INSTRUCTIONS,
            smtp_trace=tuple(smtp_trace),
            test_id=bcc_test_id,
        )
        if not self.use_json and self.args.debug:
            self._bcc_streamed_live = True
            self._bcc_stream_section(bcc_result, stream_trace=True)
        return bcc_result

    def _generate_alias_variants(self, recipient: str) -> dict[str, str]:
        """Generate alias variant addresses from base recipient (e.g. admin@example.com)."""
        if "@" not in recipient:
            return {}
        user, domain = recipient.rsplit("@", 1)
        user = user.strip()
        domain = domain.strip()
        if not user or not domain:
            return {}
        return {
            "case": f"{user.upper()}@{domain}",
            "case_domain": f"{user}@{domain.upper()}",
            "dotted": f"{'.'.join(list(user))}@{domain}",
            "plus": f"{user}+test@{domain}",
            "percent": f"user%{user}@{domain}",
            "bang_simple": f"{user}!{domain}",
            "bang_nested": f"{user}!internal.{domain}@{domain}",
        }

    def test_alias(self) -> AliasTestResult:
        """
        Alias & Addressing bypass test (PTL-SVC-SMTP-ALIAS).
        Sends messages to variant addresses (case, dotted, plus, percent, bang); manual verification required.
        """
        host = self.args.target.ip
        port = self.args.target.port
        base_address = str(self.args.rcpt_to).strip()
        mail_from = self.args.mail_from or f"aliastest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        timeout = max(5.0, getattr(self.args, "alias_timeout", 30.0))
        auth_user = getattr(self.args, "user", None) or ""
        auth_pass = getattr(self.args, "password", None) or ""
        do_auth = bool(auth_user and auth_pass)

        variants_arg = getattr(self.args, "alias_variants", None)
        default_variants = ["case", "case_domain", "dotted", "plus", "percent", "bang_simple", "bang_nested"]
        if variants_arg:
            requested = [v.strip().lower() for v in variants_arg.split(",") if v.strip()]
            variant_names = [v for v in default_variants if v in requested] or default_variants
        else:
            variant_names = default_variants

        all_variants = self._generate_alias_variants(base_address)
        variants_to_test = [(k, all_variants[k]) for k in variant_names if k in all_variants]

        VERIFICATION_INSTRUCTIONS = (
            "Verify if messages sent to '250 OK' addresses bypassed any security "
            "policies (rate limits, attachment filtering, content scanning)."
        )

        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls

        def _al_trace_append(trace: list[str], line: str) -> None:
            trace.append(line)

        def _connect_alias(trace: list[str]) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, reply = smtp.getreply()
                    if st != 220:
                        _al_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                        return None, f"Connect: {st}"
                    _al_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                else:
                    smtp = smtplib.SMTP(timeout=timeout)
                    st, reply = smtp.connect(host, port)
                    if st != 220:
                        _al_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                        return None, f"Connect: {st}"
                    _al_trace_append(trace, f"Connect: {self._smtp_trace_reply(st, reply)}")
                    if use_starttls:
                        st2, reply2 = smtp.docmd("STARTTLS")
                        _al_trace_append(trace, f"STARTTLS: {self._smtp_trace_reply(st2, reply2)}")
                        if st2 != 220:
                            return None, f"STARTTLS: {st2}"
                        try:
                            ipaddress.ip_address(host)
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
                ehlo_st, ehlo_reply = smtp.docmd("EHLO", self.fqdn or "alias-test.local")
                _al_trace_append(trace, f"EHLO: {self._smtp_trace_reply(ehlo_st, ehlo_reply)}")
                if do_auth:
                    try:
                        smtp.login(auth_user, auth_pass)
                        _al_trace_append(trace, "AUTH: ok")
                    except smtplib.SMTPAuthenticationError as e:
                        _al_trace_append(trace, f"AUTH failed: {e}")
                        return None, f"AUTH failed: {e}"
                return smtp, ""
            except Exception as e:
                _al_trace_append(trace, f"Connect: {e}")
                return None, str(e)

        start_time = time.perf_counter()
        var_results: list[AliasVariantResult] = []
        self._alias_streamed_live = False
        base_mail_sent = False
        base_test_id = ""
        base_smtp_trace: tuple[str, ...] = ()

        def _run_alias_probe(
            variant_name: str,
            addr: str,
            *,
            is_bang_simple: bool = False,
        ) -> AliasVariantResult:
            detail_str = None
            accepted = rejected = error = False
            status_code = None
            reply_str = None
            smtp_trace: list[str] = []
            alias_test_id = ""

            smtp, conn_err = _connect_alias(smtp_trace)
            if smtp is None:
                error = True
                detail_str = f"Connection failed: {conn_err}"
            else:
                try:
                    msg = MIMEText(f"{self._outbound_data()}\r\n", "plain", "utf-8")
                    msg["From"] = f"<{mail_from}>"
                    msg["To"] = f"<{addr}>"
                    msg["Subject"] = self._outbound_subject()
                    msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
                    msg[EMAIL_HDR_TEST] = EMAIL_TEST_ALIAS
                    alias_test_id = self._new_mail_test_id()
                    msg[EMAIL_HDR_TEST_ID] = alias_test_id
                    raw_msg = msg.as_string()

                    mail_st, mail_reply = smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                    _al_trace_append(
                        smtp_trace,
                        f"MAIL FROM <{mail_from}>: {self._smtp_trace_reply(mail_st, mail_reply)}",
                    )
                    if mail_st not in (250, 251):
                        rejected = True
                        detail_str = f"MAIL FROM rejected: {mail_st}"
                    else:
                        rcpt_targets = [addr]
                        if addr.lower() != base_address.lower():
                            rcpt_targets.append(base_address)
                        rcpt_ok = True
                        for rcpt_addr in rcpt_targets:
                            status, reply = smtp.docmd("RCPT", f"TO:<{rcpt_addr}>")
                            status_code = status
                            reply_str = self._smtp_reply_text_one_line(reply)
                            _al_trace_append(
                                smtp_trace,
                                f"RCPT TO <{rcpt_addr}>: {self._smtp_trace_reply(status, reply)}",
                            )
                            if status not in (250, 251):
                                rcpt_ok = False
                                rejected = True
                                detail_str = f"[{status}] {reply_str}"
                                break

                        if rcpt_ok:
                            accepted = True
                            data_status, data_reply = smtp.data(raw_msg)
                            _al_trace_append(
                                smtp_trace,
                                self._data_trace_entry(raw_msg, data_status, data_reply),
                            )
                            if data_status != 250:
                                detail_str = f"RCPT OK but DATA rejected: {data_status}"
                except Exception as e:
                    error = True
                    _al_trace_append(smtp_trace, f"error: {e}")
                    detail_str = str(e)
                finally:
                    try:
                        smtp.quit()
                    except Exception:
                        pass

            mail_accepted = accepted and not (detail_str and "DATA rejected" in detail_str)
            uucp_warning = is_bang_simple and mail_accepted
            return AliasVariantResult(
                variant=variant_name,
                address=addr,
                accepted=accepted,
                rejected=rejected,
                error=error,
                smtp_status=status_code,
                smtp_reply=reply_str,
                detail=detail_str,
                uucp_warning=uucp_warning,
                smtp_trace=tuple(smtp_trace),
                test_id=alias_test_id if mail_accepted else "",
            )

        base_probe = _run_alias_probe("base", base_address)
        base_mail_sent = self._al_variant_mail_accepted(base_probe)
        base_test_id = base_probe.test_id
        base_smtp_trace = base_probe.smtp_trace
        if not self.use_json and self.args.debug:
            self._alias_streamed_live = True
            self._al_stream_base_section(
                base_address,
                base_mail_sent=base_mail_sent,
                base_test_id=base_test_id,
                base_smtp_trace=base_smtp_trace,
                stream_trace=True,
            )

        for variant_name, addr in variants_to_test:
            is_bang_simple = variant_name == "bang_simple"
            variant_result = _run_alias_probe(
                variant_name,
                addr,
                is_bang_simple=is_bang_simple,
            )
            var_results.append(variant_result)
            if not self.use_json and self.args.debug:
                self._alias_streamed_live = True
                self._al_stream_variant_section(
                    variant_result,
                    base_address,
                    stream_trace=True,
                )

        elapsed = time.perf_counter() - start_time
        accepted_count = sum(1 for v in var_results if v.accepted)
        detail = f"{accepted_count} variant(s) accepted; manual verification required" if var_results else None

        return AliasTestResult(
            base_address=base_address,
            variants=tuple(var_results),
            elapsed_sec=elapsed,
            detail=detail,
            verification_instructions=VERIFICATION_INSTRUCTIONS,
            base_mail_sent=base_mail_sent,
            base_test_id=base_test_id,
            base_smtp_trace=base_smtp_trace,
        )

    def _br_stream_probe_section_title(self, title: str) -> None:
        """Probe subsection heading for -br (live under -vv, same indent as streamer)."""
        if not self.use_json and self.args.debug:
            self._bounce_replay_streamed_live = True
            ptprinthelper.ptprint(title, bullet_type="TITLE", condition=True, indent=4)

    def _br_stream_probe_verdict(
        self,
        *,
        accepted: bool,
        indeterminate: bool,
        detail: str | None,
        bounce_addr: str,
        test_id: str = "",
    ) -> None:
        """Mail probe verdict line for -br (-vv live stream)."""
        if self.use_json or not self.args.debug:
            return
        bt, msg = self._mail_probe_bullet_msg(
            accepted,
            indeterminate=indeterminate,
            detail=detail,
            sent_msg=self._mail_sent_inbox_msg(bounce_addr, test_id),
        )
        ptprinthelper.ptprint(msg, bullet_type=bt, condition=True, indent=8)

    def _br_stream_trace_line(self, line: str) -> None:
        """-vv SMTP trace for -br (ADDITIONS, indent 8 under probe title)."""
        self._stream_smtp_trace_line(line, indent_override=8)

    def _sh_variant_section_title(self, variant: str) -> str:
        return {
            "from": "From header",
            "reply_to": "Reply-To header",
            "return_path": "Return-Path",
        }.get(variant, variant)

    def _sh_stream_variant_section(
        self,
        v: SpoofHeaderVariantResult,
        rcpt: str,
        *,
        stream_trace: bool = False,
    ) -> None:
        """Per-variant terminal block for -sh (From / Reply-To / Return-Path)."""
        pp = ptprinthelper.ptprint
        pp(self._sh_variant_section_title(v.variant), bullet_type="TITLE", condition=True, indent=4)
        if stream_trace:
            for line in v.smtp_trace:
                if line.startswith("---"):
                    continue
                self._stream_smtp_trace_line(line, indent_override=8)
        if v.accepted:
            pp(
                self._mail_sent_inbox_msg(rcpt, v.test_id),
                bullet_type="NOTVULN",
                condition=True,
                indent=8,
            )
            if v.envelope_header_mismatch:
                pp(
                    "Envelope vs header mismatch: MAIL FROM (envelope) ≠ From (header) — server accepted",
                    bullet_type="WARNING",
                    condition=True,
                    indent=8,
                )
            pp("Vulnerable (spoofing possible)", bullet_type="VULN", condition=True, indent=8)
        elif v.rejected:
            one_line = self._smtp_detail_one_line(v.detail) or v.detail or "rejected"
            pp(f"Message rejected — {one_line}", bullet_type="WARNING", condition=True, indent=8)
            pp("NOT VULNERABLE", bullet_type="NOTVULN", condition=True, indent=8)
        elif v.error:
            one_line = self._smtp_detail_one_line(v.detail) or v.detail or "error"
            pp(f"Test failed — {one_line}", bullet_type="WARNING", condition=True, indent=8)
            pp("Indeterminate", bullet_type="WARNING", condition=True, indent=8)
