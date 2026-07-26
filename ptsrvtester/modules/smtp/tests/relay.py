import secrets, smtplib, sys, threading, time


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
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


class RelayMixin:

    def open_relay_test(self, smtp, mail_from, rcpt_to) -> bool:
        """OWASP/Nmap-style multi-vector open relay test. Tests: empty FROM, internal→external,
        external→external, literal IP sender. Returns True if any vector succeeds."""
        self.ptdebug("Open Relay Test:", title=True)
        verbose = bool(self.args.debug and not self.args.json)
        ext_domain = "external.relaytest.local"
        host_domain = self.fqdn or "relaytest.local"
        target_ip = getattr(self.args.target, "ip", None) or "127.0.0.1"
        sample_to = rcpt_to or f"relaytest@{ext_domain}"
        sample_from = mail_from or f"relaytest@{host_domain}"
        msg = (
            f"From: <{sample_from}>\r\n"
            f"To: <{sample_to}>\r\n"
            f"Subject: {self._outbound_subject()}\r\n"
            f"\r\n"
            f"{self._outbound_data()}\r\n"
        )

        vectors: list[tuple[str, str, str]] = [
            ("MAIL FROM:<> (null sender)", "<>", f"relaytest@{ext_domain}"),
            (f"relaytest@{host_domain} -> external", f"relaytest@{host_domain}", f"relaytest@{ext_domain}"),
            (f"relaytest@[{target_ip}] -> external", f"relaytest@[{target_ip}]", f"relaytest@{ext_domain}"),
            ("external -> external", f"relaytest@{ext_domain}", f"relaytest@other.{ext_domain}"),
        ]

        if mail_from and rcpt_to:
            vectors.insert(0, (f"user: {mail_from} -> {rcpt_to}", mail_from, rcpt_to))

        def _reply_one_line(raw: str | bytes, limit: int = 160) -> str:
            if isinstance(raw, str):
                s = raw.strip().replace("\r\n", " ").replace("\n", " ")
            else:
                s = self.bytes_to_str(raw).strip().replace("\r\n", " ").replace("\n", " ")
            return s if len(s) <= limit else s[: limit - 3] + "..."

        def _envelope_addr(addr: str) -> str:
            if addr == "<>":
                return "<>"
            if addr.startswith("<") and addr.endswith(">"):
                return addr
            return f"<{addr}>"

        def _relay_vector(label: str, from_addr: str, to_addr: str) -> bool:
            """Run one relay vector; return True when DATA is accepted (open relay)."""
            mail_env = _envelope_addr(from_addr)
            rcpt_env = _envelope_addr(to_addr)
            try:
                smtp.docmd("RSET")
            except Exception:
                pass
            try:
                mail_status, mail_reply = smtp.docmd("MAIL FROM:", mail_env)
                mail_rep = _reply_one_line(mail_reply)
                if verbose:
                    self.ptdebug(
                        f"Open relay ({label}): MAIL FROM:{mail_env} → [{mail_status}] {mail_rep}",
                        Out.INFO,
                    )
                if mail_status not in (250, 251):
                    if not verbose:
                        self.ptdebug(
                            f"Relay rejected: {label} — MAIL FROM [{mail_status}] {mail_rep}",
                            Out.INFO,
                        )
                    return False

                rcpt_status, rcpt_reply = smtp.docmd("RCPT TO:", rcpt_env)
                rcpt_rep = _reply_one_line(rcpt_reply)
                if verbose:
                    self.ptdebug(
                        f"Open relay ({label}): RCPT TO:{rcpt_env} → [{rcpt_status}] {rcpt_rep}",
                        Out.INFO,
                    )
                if rcpt_status not in (250, 251, 252):
                    if not verbose:
                        self.ptdebug(
                            f"Relay rejected: {label} — RCPT TO [{rcpt_status}] {rcpt_rep}",
                            Out.INFO,
                        )
                    return False

                data_status, data_reply = smtp.data(msg)
                data_rep = _reply_one_line(data_reply)
                if verbose:
                    self._stream_smtp_trace_line(
                        self._data_trace_entry(msg, data_status, data_reply),
                    )
                if data_status == 250:
                    self.ptdebug(f"Server is vulnerable to Open relay ({label})", Out.VULN)
                    return True
                if not verbose:
                    self.ptdebug(
                        f"Relay rejected: {label} — DATA [{data_status}] {data_rep}",
                        Out.INFO,
                    )
                return False
            except smtplib.SMTPRecipientsRefused as e:
                detail = _reply_one_line(str(e))
                if verbose:
                    self.ptdebug(f"Open relay ({label}): RCPT TO:{rcpt_env} → {detail}", Out.INFO)
                else:
                    self.ptdebug(f"Relay rejected: {label} — RCPT TO {detail}", Out.INFO)
            except smtplib.SMTPResponseException as e:
                code = getattr(e, "smtp_code", "?")
                err = _reply_one_line(getattr(e, "smtp_error", b"") or str(e))
                if verbose:
                    self.ptdebug(f"Open relay ({label}): SMTP [{code}] {err}", Out.INFO)
                else:
                    self.ptdebug(f"Relay rejected: {label} — [{code}] {err}", Out.INFO)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                detail = _reply_one_line(str(e))
                if verbose:
                    self.ptdebug(f"Open relay ({label}): connection error — {detail}", Out.INFO)
                else:
                    self.ptdebug(f"Relay rejected: {label} — {detail}", Out.INFO)
            except Exception as e:
                detail = _reply_one_line(str(e))
                if verbose:
                    self.ptdebug(f"Open relay ({label}): error — {detail}", Out.INFO)
                else:
                    self.ptdebug(f"Relay rejected: {label} — {detail}", Out.INFO)
            try:
                smtp.docmd("RSET")
            except Exception:
                pass
            return False

        for label, from_addr, to_addr in vectors:
            if _relay_vector(label, from_addr, to_addr):
                return True

        self.ptdebug("Server is not vulnerable to Open relay", Out.NOTVULN)
        return False

    @staticmethod
    def _rl_domain_source_phrase(source: str) -> str:
        """Human label for where the RCPT-limit domain was taken from."""
        return {
            "domain_arg": "-d/--domain",
            "banner": "banner",
            "ehlo": "EHLO",
            "fqdn": "client FQDN",
            "ptr": "reverse DNS (PTR)",
            "default": "default fallback",
        }.get(source, source)

    def _stream_rcpt_limit_domain_source(self, domain: str, source: str) -> None:
        src = self._rl_domain_source_phrase(source)
        ptprinthelper.ptprint(
            f"Domain derived from {src}: {domain}",
            bullet_type="TITLE", condition=not self.use_json, indent=4,
        )

    def _run_rcpt_limit_for_domain(
        self,
        smtp: smtplib.SMTP,
        domain: str,
        max_rcpt_attempts: int = RCPT_LIMIT_DEFAULT_ATTEMPTS,
        live_label: list[str] | None = None,
        attempt_hook=None,
        recipients: list[str] | None = None,
        emit_debug=None,
        *,
        send_data_at_end: bool = False,
        envelope_mail_from: str | None = None,
    ) -> RcptLimitResult:
        """Run MAIL FROM + RCPT TO loop for a given domain. Used so we can retry with parent domain.
        Continues on 554/550/553/450 (policy rejection) to probe session error limit (smtpd_hard_error_limit).
        Stops with no_session_limit after RCPT_LIMIT_POLICY_REJECT_CAP consecutive policy rejects when none accepted.
        max_rcpt_attempts caps RCPT iterations when the server keeps accepting (per-message limit probe).
        live_label/attempt_hook are passed from test_rcpt_limit for live progress display.
        attempt_hook(i) is called once per attempt with the current attempt index (after
        the SMTP reply is logged when emit_debug is set, so -vv lines stay on their own row).
        emit_debug (optional): callable(text, out=..., title=...) that clears the in-place
        progress row before printing verbose SMTP trace lines.

        recipients (optional): explicit list of full RCPT TO addresses (e.g. real local users from -U name file).
        When set, the probe iterates this list instead of generating synthetic 1@dom..N@dom; this is
        required for MTAs without open relay so that we can actually trigger the per-message limit.
        """
        max_try = max(1, int(max_rcpt_attempts))
        policy_reject_cap = RCPT_LIMIT_POLICY_REJECT_CAP
        explicit_recipients: list[str] = []
        if recipients:
            explicit_recipients = list(recipients)
            max_try = max(1, min(max_try, len(explicit_recipients)))

        def _reply_one_line(raw: str | bytes, limit: int = 160) -> str:
            if isinstance(raw, str):
                s = raw.strip().replace("\r\n", " ").replace("\n", " ")
            else:
                s = self.bytes_to_str(raw).strip().replace("\r\n", " ").replace("\n", " ")
            return s if len(s) <= limit else s[: limit - 3] + "..."

        def _dbg(text: str, out: Out = Out.INFO, *, title: bool = False) -> None:
            if emit_debug is not None:
                emit_debug(text, out=out, title=title)
            else:
                self.ptdebug(text, out, title=title)

        mail_from_addr = (envelope_mail_from or "").strip("<>").strip() if envelope_mail_from else ""
        mail_from_bracket = self._envelope_mail_from_bracket(envelope_mail_from)

        def _attempt_data_send(accepted_count: int) -> tuple[bool, bool, int | None, str | None]:
            if not send_data_at_end or accepted_count <= 0:
                return False, False, None, None
            probe_uuid = secrets.token_hex(8)
            raw_msg = self._outbound_minimal_probe(
                from_addr=mail_from_addr or f"rls@{domain}",
                message_id_tag="rls",
                domain=domain,
                probe_uuid=probe_uuid,
            )
            try:
                dcode, drp = smtp.data(raw_msg)
                drep = self.bytes_to_str(drp).strip()[:500]
                if self.args.debug and not self.use_json:
                    self._stream_smtp_trace_line(
                        self._data_trace_entry(raw_msg, dcode, drp),
                    )
                else:
                    _dbg(
                        f"Limit-send DATA ({accepted_count} RCPT) → [{dcode}] {_reply_one_line(drep)}",
                        Out.INFO,
                    )
                return True, dcode == 250, dcode, drep
            except Exception as e:
                drep = str(e).strip()[:500]
                _dbg(f"Limit-send DATA failed: {e}", Out.INFO)
                return True, False, None, drep

        def _pack_result(
            accepted: int,
            limit_triggered: bool,
            server_response: str | None,
            rejected_addresses: bool = False,
            **extra,
        ) -> RcptLimitResult:
            send_attempted, send_ok, send_code, send_reply = _attempt_data_send(accepted)
            return RcptLimitResult(
                accepted,
                limit_triggered,
                server_response,
                rejected_addresses,
                limit_send_mode=send_data_at_end,
                limit_send_attempted=send_attempted,
                limit_send_ok=send_ok,
                limit_send_data_code=send_code,
                limit_send_data_reply=send_reply,
                limit_send_mail_from=mail_from_addr or None,
                **extra,
            )

        try:
            status, reply = smtp.docmd("MAIL FROM:", mail_from_bracket)
            if status != 250:
                return _pack_result(0, False, self.bytes_to_str(reply), False)
            _dbg(f"MAIL FROM:{mail_from_bracket} → [{status}] {_reply_one_line(reply)}", Out.INFO)
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, EOFError, OSError) as e:
            return _pack_result(0, True, str(e), False)

        accepted = 0
        failed = 0
        limit_response: str | None = None
        first_policy_response: str | None = None  # First 554/550/553/450 for display

        def _probe_disconnect_after_limit() -> tuple[bool, int]:
            """Send up to RCPT_LIMIT_POSTHIT_PROBE_COUNT extra RCPT TOs after the per-message
            limit has been detected to determine whether the server eventually closes the session.

            Returns (disconnected, attempts_sent):
              - disconnected=True if server returned 421 or closed the socket within the probe;
              - disconnected=False if all probe iterations finished and the session stayed open.
            """
            probe_max = RCPT_LIMIT_POSTHIT_PROBE_COUNT
            for j in range(1, probe_max + 1):
                addr = f"posthit{j}@{domain}"
                try:
                    pst, prep = smtp.docmd("RCPT TO:", f"<{addr}>")
                    _dbg(
                        f"POSTHIT [{j}/{probe_max}] RCPT TO:<{addr}> → "
                        f"[{pst}] {_reply_one_line(prep)}",
                        Out.INFO,
                    )
                    if pst == 421:
                        return True, j
                except (smtplib.SMTPServerDisconnected, ConnectionResetError,
                        BrokenPipeError, EOFError, OSError):
                    _dbg(
                        f"POSTHIT server closed connection after {j} extra rejects",
                        Out.INFO,
                    )
                    return True, j
            return False, probe_max

        for i in range(1, max_try + 1):
            if explicit_recipients:
                rcpt_addr = explicit_recipients[i - 1]
            else:
                rcpt_addr = f"{i}@{domain}"
            if live_label is not None:
                live_label[0] = (
                    f"accepted {accepted} recipients. "
                    f"Attempt to add recipient: {rcpt_addr}"
                )
            try:
                status, reply = smtp.docmd("RCPT TO:", f"<{rcpt_addr}>")
                reply_str = self.bytes_to_str(reply)
                _dbg(
                    f"[{i}/{max_try}] RCPT TO:<{rcpt_addr}> → "
                    f"[{status}] {_reply_one_line(reply_str)}",
                    Out.INFO,
                )
                if attempt_hook is not None:
                    attempt_hook(i)
                if status == 250:
                    accepted += 1
                    continue
                limit_response = f"[{status}] {reply_str}".strip()
                if first_policy_response is None and status in (450, 550, 553, 554):
                    first_policy_response = limit_response

                # Policy rejection (relay/sender/recipient) – continue to probe session limit
                if status in (450, 550, 553, 554):
                    failed += 1
                    if accepted == 0 and failed >= policy_reject_cap:
                        _dbg(
                            f"Server allows {failed} failed RCPTs without disconnect (no smtpd_hard_error_limit)",
                            Out.VULN,
                        )
                        return _pack_result(
                            0, False, first_policy_response, rejected_addresses=True,
                            failed_before_limit=failed, session_limit_triggered=False, no_session_limit=True,
                        )
                    continue

                # Session limit: 421 (rate limit / too many errors)
                if status == 421:
                    _dbg(f"Server session limit after {i} attempts: {limit_response}", Out.INFO)
                    return _pack_result(
                        accepted, True, limit_response, rejected_addresses=(accepted == 0),
                        failed_before_limit=i, session_limit_triggered=True, no_session_limit=False,
                    )

                # Per-message RCPT limit: 452 Too many recipients
                if status == 452:
                    _dbg(f"Server per-message limit after {accepted} recipients: {limit_response}", Out.INFO)
                    result = _pack_result(accepted, True, limit_response, False)
                    disc, posthit_n = _probe_disconnect_after_limit()
                    return result._replace(
                        disconnect_after_limit=disc, posthit_probe_count=posthit_n,
                    )

                # Other 5xx
                if 500 <= status <= 599:
                    _dbg(f"Server limit after {accepted} recipients: {limit_response}", Out.INFO)
                    result = _pack_result(accepted, True, limit_response, False)
                    disc, posthit_n = _probe_disconnect_after_limit()
                    return result._replace(
                        disconnect_after_limit=disc, posthit_probe_count=posthit_n,
                    )

                return _pack_result(accepted, False, limit_response, False)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, EOFError, OSError) as e:
                _dbg(f"Server closed connection after {i} attempts", Out.INFO)
                return _pack_result(
                    accepted, True, str(e), rejected_addresses=(accepted == 0),
                    failed_before_limit=i, session_limit_triggered=True, no_session_limit=False,
                )

        _dbg(f"No limit observed up to {accepted} recipients", Out.VULN)
        return _pack_result(accepted, False, None, False)

    def _rl_name_list_source_phrase(self) -> str:
        """Human label for where -rl recipient names came from (-u vs -U)."""
        has_file = bool(getattr(self.args, "users", None))
        has_cli = bool(self.args.user)
        if has_file and has_cli:
            return "from -u and username file (-U)"
        if has_file:
            return "from username file (-U)"
        if has_cli:
            return "from command line (-u)"
        return "from name list"

    def _rl_build_recipients_from_wordlist(self, domain: str, max_n: int) -> list[str]:
        """Build full RCPT TO addresses from in-memory name list (-u / -U) for MTA-not-relay testing.

        Wordlist entries with ``@`` are kept verbatim (already a full address); bare local parts
        are completed with ``@<domain>`` (banner/EHLO domain). Output is deduplicated and capped
        at ``max_n`` entries to respect the user-provided RCPT TO budget.
        """
        wl = getattr(self, "wordlist", None) or []
        if not wl:
            return []
        seen: set[str] = set()
        out: list[str] = []
        dom = (domain or "").strip().lower().rstrip(".")
        for entry in wl:
            if not isinstance(entry, str):
                continue
            v = entry.strip()
            if not v:
                continue
            if "@" in v:
                addr = v
            else:
                if not dom:
                    continue
                addr = f"{v}@{dom}"
            key = addr.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(addr)
            if len(out) >= max(1, int(max_n)):
                break
        return out

    def _rl_probe_accept_all_rcpt(
        self,
        smtp: smtplib.SMTP,
        domain: str,
        *,
        envelope_mail_from: str | None = None,
        emit_debug=None,
    ) -> tuple[bool, str | None]:
        """Pre-probe: does the server accept a clearly invalid local part via RCPT TO?

        Uses ``RCPT_LIMIT_ACCEPT_ALL_PROBE_LOCAL@domain`` (e.g. ``xxxfoofff@dom``).
        Leaves the session in a clean state (RSET) when the probe finishes.

        Returns ``(accept_all, rate_limit_error)`` where ``rate_limit_error`` is set when
        ``MAIL FROM`` was rejected with a ``too much mail from`` policy response.
        """
        addr = f"{RCPT_LIMIT_ACCEPT_ALL_PROBE_LOCAL}@{domain}"
        mail_bracket = self._envelope_mail_from_bracket(envelope_mail_from)

        def _reply_one_line(raw: str | bytes, limit: int = 160) -> str:
            if isinstance(raw, str):
                s = raw.strip().replace("\r\n", " ").replace("\n", " ")
            else:
                s = self.bytes_to_str(raw).strip().replace("\r\n", " ").replace("\n", " ")
            return s if len(s) <= limit else s[: limit - 3] + "..."

        def _dbg(text: str, out: Out = Out.INFO) -> None:
            if emit_debug is not None:
                emit_debug(text, out=out)
            elif self.args.debug and not self.args.json:
                self.ptdebug(text, out)

        try:
            smtp.docmd("RSET")
        except Exception:
            pass
        try:
            status, reply = smtp.docmd("MAIL FROM:", mail_bracket)
            reply_str = self.bytes_to_str(reply)
            mail_rep = _reply_one_line(reply_str)
            if status not in (250, 251):
                rate_err = _rl_extract_too_much_mail_error(reply_str)
                _dbg(
                    f"Accept-all probe MAIL FROM:{mail_bracket} → [{status}] {mail_rep}",
                    Out.INFO,
                )
                return False, rate_err
            _dbg(
                f"Accept-all probe MAIL FROM:{mail_bracket} → [{status}] {mail_rep}",
                Out.INFO,
            )
            status, reply = smtp.docmd("RCPT TO:", f"<{addr}>")
            reply_str = self.bytes_to_str(reply)
            _dbg(
                f"Accept-all probe RCPT TO:<{addr}> → "
                f"[{status}] {_reply_one_line(reply_str)}",
                Out.INFO,
            )
            accepted = status in (250, 251, 252)
        except Exception as e:
            _dbg(f"Accept-all probe failed: {e}", Out.INFO)
            accepted = False
            rate_err = None
        else:
            rate_err = None
        try:
            smtp.docmd("RSET")
        except Exception:
            pass
        return accepted, rate_err

    def _rl_probe_envelope_mail_from_rate_limit(
        self,
        smtp: smtplib.SMTP,
        envelope_mail_from: str | None,
    ) -> str | None:
        """Return rate-limit text when envelope ``MAIL FROM`` is rejected with ``too much mail``."""
        mail_from_addr = (envelope_mail_from or "").strip("<>").strip() if envelope_mail_from else ""
        mail_from_bracket = self._envelope_mail_from_bracket(envelope_mail_from)
        try:
            smtp.docmd("RSET")
        except Exception:
            pass
        try:
            status, reply = smtp.docmd("MAIL FROM:", mail_from_bracket)
            if status != 250:
                return _rl_extract_too_much_mail_error(self.bytes_to_str(reply))
        except Exception:
            pass
        finally:
            try:
                smtp.docmd("RSET")
            except Exception:
                pass
        return None

    def _rl_rate_limited_result(
        self,
        message: str,
        *,
        domain: str,
        effective_role: str | None,
        auth_required: bool | None,
        open_relay: bool | None,
        recipients_source: str | None,
    ) -> RcptLimitResult:
        """Early exit when the server blocks this client with ``too much mail from``."""
        ptprinthelper.ptprint(message, bullet_type="VULN", condition=not self.use_json, indent=4)
        return RcptLimitResult(
            max_accepted=0,
            limit_triggered=False,
            server_response=message,
            rejected_addresses=False,
            domain_used=domain,
            role=effective_role,
            auth_required=auth_required,
            open_relay=open_relay,
            skipped=True,
            skip_reason="rate_limited",
            skip_message=message,
            recipients_source=recipients_source,
        )

    def _stream_rcpt_limit_precheck_role(
        self,
        effective_role: str | None,
        auth_required: bool | None,
    ) -> None:
        """Print ``[*] Role: …`` immediately after role identification (RCPTLIM pre-check)."""
        show = not self.use_json
        if effective_role is not None:
            ptprinthelper.ptprint(
                self._rl_role_label(effective_role, self.args.target.port, auth_required, rcpt_limit_submission=(effective_role == 'submission')),
                bullet_type="TITLE", condition=show, indent=4,
            )
        else:
            ptprinthelper.ptprint(
                "Role: could not be determined (pre-check failed)",
                bullet_type="TITLE", condition=show, indent=4,
            )

    def _stream_rcpt_limit_precheck_open_relay(
        self,
        open_relay: bool | None,
        domain: str,
        domain_source: str,
    ) -> None:
        """Print open-relay verdict and domain source right after open-relay probe."""
        show = not self.use_json
        if open_relay is True:
            ptprinthelper.ptprint(
                "Open relay: vulnerable (synthetic recipients accepted)",
                bullet_type="TITLE", condition=show, indent=4,
            )
            self._stream_rcpt_limit_domain_source(domain, domain_source)
        elif open_relay is False:
            ptprinthelper.ptprint(
                "Open relay: not vulnerable",
                bullet_type="TITLE", condition=show, indent=4,
            )
            self._stream_rcpt_limit_domain_source(domain, domain_source)

    def _rl_run_precheck(self, domain: str, domain_source: str) -> dict:
        """Pre-check before -rl: detect role + (for MTA/hybrid) open-relay verdict.

        Reuses cached ``self.results.role`` / ``self.results.open_relay`` when already populated
        (e.g. from a prior -ri / -or run inside run-all). Honors ``--role`` override.

        Returns a dict with keys: ``role`` (str|None), ``auth_required`` (bool|None),
        ``auth_methods`` (list[str]), ``port_hint`` (str), ``open_relay`` (bool|None).
        """
        out: dict = {
            "role": None,
            "auth_required": None,
            "auth_methods": [],
            "port_hint": None,
            "open_relay": None,
        }

        forced_role = getattr(self.args, "smtp_role", None)

        # --- Role detection (cached or fresh) ---
        role_obj = self.results.role
        if role_obj is None:
            try:
                # Ensure self.results.info exists (initial_info populates banner/EHLO)
                if not getattr(self.results, "info", None):
                    _, info = self.initial_info(get_commands=True)
                    self.results.info = InfoResult(
                        info.banner,
                        info.ehlo,
                        getattr(info, "ehlo_starttls", None),
                    )
                    self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
                    self.results.banner_requested = False
                    self.results.commands_requested = False
                pre_smtp = self.get_smtp_handler()
                try:
                    pre_smtp.docmd("EHLO", self.fqdn)
                    role_obj = self.test_role(pre_smtp, self.results.info)
                    self.results.role = role_obj
                finally:
                    try:
                        pre_smtp.close()
                    except Exception:
                        pass
            except Exception as e:
                self.ptdebug(f"Pre-check role detection failed: {e}", Out.INFO)

        if role_obj is not None:
            out["role"] = forced_role or role_obj.role
            out["auth_required"] = role_obj.auth_required
            out["port_hint"] = getattr(role_obj, "port_hint", None)
            if rl_err := _rl_extract_too_much_mail_error(role_obj.detail):
                out["rate_limit_error"] = rl_err
        elif forced_role:
            out["role"] = forced_role

        self._stream_rcpt_limit_precheck_role(out.get("role"), out.get("auth_required"))

        # --- Open relay probe (only relevant for MTA/hybrid) ---
        effective_role = out["role"]
        if effective_role in ("mta", "hybrid"):
            if self.results.open_relay is not None:
                out["open_relay"] = self.results.open_relay
            else:
                try:
                    or_smtp = self.get_smtp_handler()
                    try:
                        or_smtp.docmd("EHLO", self.fqdn)
                        open_relay = self.open_relay_test(or_smtp, None, None)
                        self.results.open_relay = open_relay
                        out["open_relay"] = open_relay
                    finally:
                        try:
                            or_smtp.close()
                        except Exception:
                            pass
                except Exception as e:
                    self.ptdebug(f"Pre-check open-relay probe failed: {e}", Out.INFO)
            self._stream_rcpt_limit_precheck_open_relay(out.get("open_relay"), domain, domain_source)
        return out

    @staticmethod
    def _rl_role_label(
        role: str | None,
        port: int | str,
        auth_required: bool | None,
        *,
        rcpt_limit_submission: bool = False,
    ) -> str:
        """Format `[*] Role: ...` info line for the pre-check verdict.

        For ``-rl`` with effective ``submission`` role, EHLO may still report
        ``AUTH not required`` while the RCPT TO probe is intentionally run only
        after ``LOGIN`` (``-u``/``-p``). In that case avoid a misleading
        one-line ``AUTH not required`` that contradicts the skip message.
        """
        role_str = (role or "unknown")
        if role_str == "indeterminate":
            return (
                f"Role: undetermined (port {port}) — "
                "could not classify server (MTA / Submission / Hybrid)"
            )
        if rcpt_limit_submission and role_str == "submission":
            if auth_required is True:
                auth_label = "EHLO: AUTH — -rl probe uses -u/-p"
            elif auth_required is False:
                auth_label = (
                    "EHLO: AUTH not advertised — -rl probe still needs -u/-p "
                    "(or --rl-no-precheck)"
                )
            else:
                auth_label = (
                    "EHLO: AUTH unclear — -rl probe needs -u/-p "
                    "(or --rl-no-precheck)"
                )
            return f"Role: {role_str} (port {port}, {auth_label})"
        # Classic MTA: port hint MTA + no AUTH in EHLO → ``auth_required`` is left
        # ``None`` because the RCPT-auth probe is *skipped* (see ``test_role``), not
        # because we failed to learn anything. Avoid alarming "AUTH inconclusive".
        if role_str == "mta" and auth_required is None:
            auth_label = "EHLO: AUTH not advertised — MTA (RCPT-auth probe skipped)"
            return f"Role: {role_str} (port {port}, {auth_label})"
        if auth_required is True:
            auth_label = "AUTH required"
        elif auth_required is False:
            auth_label = "AUTH not required"
        else:
            auth_label = "AUTH inconclusive"
        return f"Role: {role_str} (port {port}, {auth_label})"

    def test_rcpt_limit(self) -> RcptLimitResult:
        """
        Test RCPT TO limit per message: send MAIL FROM then many RCPT TO
        until server rejects (452 Too many recipients, 421, 5xx) or closes.

        When ``--rl-no-precheck`` is not set, the test first detects the server role
        (and, for MTA/hybrid roles, the open-relay verdict) so it can:
          • run on Submission only after authentication (``-u``/``-p``);
          • use real local recipients from ``-u`` / ``-U`` (valid local usernames) for an MTA that is not an open relay
            (synthetic ``1@dom`` would be rejected as "Relay denied");
          • when ``-u`` / ``-U`` is given, use that name list even if role is indeterminate or open-relay;
          • fall back to synthetic ``1@dom`` only when role is indeterminate/open-relay and no name list was provided.

        When the server is an MTA-not-relay and no valid local usernames are provided via ``-u``/``-U``,
        the test ends with an explicit "skipped" verdict (no false-positive vuln).
        """
        # Live ETA/progress stays on when -vv (--verbose → args.debug); only JSON mode disables it.
        _show_progress = not self.args.json
        _start_time = time.perf_counter()
        _live_label: list[str] = ["Connecting..."]
        _ticker_stop = threading.Event()
        _attempt_ref: list[int] = [0]
        _eta_ref: list[float | None] = [None]
        _max_probe_ref: list[int] = [RCPT_LIMIT_DEFAULT_ATTEMPTS]
        _print_lock = threading.Lock()
        _live_dirty = False

        def _render_progress() -> None:
            nonlocal _live_dirty
            attempt = _attempt_ref[0]
            max_p = _max_probe_ref[0]
            eta = _eta_ref[0]
            if attempt > 0 and max_p > 0:
                pct = min(100, int(attempt * 100 / max_p))
                if eta is not None and eta >= 0:
                    eta_str = self._format_enum_clock_duration(eta)
                    prefix = f"    {eta_str} {pct}% ({attempt}/{max_p})  "
                else:
                    prefix = f"    --:--:-- {pct}% ({attempt}/{max_p})  "
            else:
                prefix = "    "
            line = f"{prefix}{_live_label[0]}"
            with _print_lock:
                sys.stdout.write(f"\033[2K\r{line:<120}")
                sys.stdout.flush()
                _live_dirty = True

        def _clear_progress_line() -> None:
            nonlocal _live_dirty
            if not _show_progress or not _live_dirty:
                return
            with _print_lock:
                if _live_dirty:
                    sys.stdout.write("\033[2K\r")
                    sys.stdout.flush()
                    _live_dirty = False

        def _emit_probe_debug(
            text: str,
            out: Out = Out.INFO,
            *,
            title: bool = False,
        ) -> None:
            """Verbose SMTP trace that won't garble the in-place progress row."""
            nonlocal _live_dirty
            if not self.args.debug or self.args.json:
                return
            with _print_lock:
                if _show_progress and _live_dirty:
                    sys.stdout.write("\033[2K\r")
                    sys.stdout.flush()
                    _live_dirty = False
            self.ptdebug(text, out, title=title)

        def _update_attempt(i: int) -> None:
            elapsed = time.perf_counter() - _start_time
            _attempt_ref[0] = i
            max_p = _max_probe_ref[0]
            remaining = max_p - i
            if i > 0:
                _eta_ref[0] = max(0.0, remaining * (elapsed / i))
            _render_progress()

        def _ticker() -> None:
            while not _ticker_stop.wait(timeout=0.2):
                _render_progress()

        def _end_progress() -> None:
            nonlocal _live_dirty
            _ticker_stop.set()
            with _print_lock:
                sys.stdout.write(f"\033[2K\r{' ' * 120}\r")
                sys.stdout.flush()
                _live_dirty = False

        # ── Pre-check phase (no ticker yet, info lines must stay visible) ──
        no_precheck = bool(getattr(self.args, "rl_no_precheck", False))
        forced_role = getattr(self.args, "smtp_role", None)

        if _rcpt_limit_send_mode(self.args):
            self.ptdebug("RCPT TO limit test (per message, with DATA send)", title=True)
        else:
            self.ptdebug("RCPT TO limit test (per message)", title=True)

        # Populate self.results.info so domain resolution + precheck work the same in
        # standalone (-rl alone) and run-all flows. Also makes the "Initial server
        # information" header (banner + EHLO) visible in -vv (shared helper, used
        # by -ts NOOP1 / -nf2 too).
        self._ensure_initial_info(fail_label="-rl precheck")

        domain, domain_source = self._resolve_rcpt_limit_domain()
        send_mode = _rcpt_limit_send_mode(self.args)
        max_rcpt_attempts = _rcpt_limit_max_attempts(self.args)
        envelope_mail_from: str | None = None
        mail_from_raw = (getattr(self.args, "mail_from", None) or "").strip()
        if mail_from_raw and "@" in mail_from_raw:
            envelope_mail_from = mail_from_raw.strip("<>").strip()
        _max_probe_ref[0] = max_rcpt_attempts

        precheck: dict = {}
        effective_role: str | None = None
        auth_required: bool | None = None
        open_relay: bool | None = None
        recipients: list[str] | None = None
        recipients_source = "synthetic"
        rl_wordlist_notice: tuple[list[str], int] | None = None
        rate_limit_msg: str | None = None

        if no_precheck:
            ptprinthelper.ptprint("Pre-check skipped (--rl-no-precheck)", bullet_type="TITLE",
                                  condition=not self.use_json, indent=4)
        else:
            precheck = self._rl_run_precheck(domain, domain_source)
            effective_role = precheck.get("role")
            auth_required = precheck.get("auth_required")
            open_relay = precheck.get("open_relay")
            rate_limit_msg = precheck.get("rate_limit_error")

            # Decide test path
            if effective_role in ("mta", "hybrid") and open_relay is False:
                # MTA not acting as open relay → synthetic 1@dom would always be rejected.
                # Build recipients from -u / -U name list; without it, the test is skipped explicitly.
                recipients = self._rl_build_recipients_from_wordlist(domain, max_rcpt_attempts)
                if recipients:
                    recipients_source = "wordlist"
                    wl_n = len(getattr(self, "wordlist", None) or [])
                    rl_wordlist_notice = (recipients, wl_n)
                else:
                    msg = (
                        "Server is not an open relay; the test cannot run with synthetic recipients. "
                        "Use -u or -U with valid local usernames (or --rl-no-precheck to attempt a raw probe)."
                    )
                    ptprinthelper.ptprint(f"Skipping: {msg}", bullet_type="TITLE",
                                          condition=not self.use_json, indent=4)
                    return RcptLimitResult(
                        max_accepted=0,
                        limit_triggered=False,
                        server_response=None,
                        rejected_addresses=False,
                        domain_used=domain,
                        role=effective_role,
                        auth_required=auth_required,
                        open_relay=open_relay,
                        skipped=True,
                        skip_reason="mta_not_relay_no_wordlist",
                        skip_message=msg,
                        recipients_source=None,
                    )

            elif effective_role == "submission":
                user, _pw = self._rl_first_creds()
                if not user or not _pw:
                    msg = (
                        "Submission server requires authenticated session for RCPT TO probe. "
                        "Pass -u/--user and -p/--password (or --rl-no-precheck for an anonymous probe)."
                    )
                    ptprinthelper.ptprint(f"Skipping: {msg}", bullet_type="TITLE",
                                          condition=not self.use_json, indent=4)
                    return RcptLimitResult(
                        max_accepted=0,
                        limit_triggered=False,
                        server_response=None,
                        rejected_addresses=False,
                        domain_used=domain,
                        role=effective_role,
                        auth_required=auth_required,
                        open_relay=open_relay,
                        skipped=True,
                        skip_reason="submission_auth_required",
                        skip_message=msg,
                        recipients_source=None,
                    )

            elif effective_role == "indeterminate":
                pass  # recipients / hint resolved after pre-check (honour -u/-U when given)

            if rate_limit_msg:
                return self._rl_rate_limited_result(
                    rate_limit_msg,
                    domain=domain,
                    effective_role=effective_role,
                    auth_required=auth_required,
                    open_relay=open_relay,
                    recipients_source=None,
                )

        if recipients is None:
            wl_recipients = self._rl_build_recipients_from_wordlist(domain, max_rcpt_attempts)
            if wl_recipients:
                recipients = wl_recipients
                recipients_source = "wordlist"
                wl_n = len(getattr(self, "wordlist", None) or [])
                rl_wordlist_notice = (recipients, wl_n)

        if (
            not no_precheck
            and effective_role == "indeterminate"
            and recipients_source == "synthetic"
            and not rate_limit_msg
        ):
            ptprinthelper.ptprint(
                "Continuing with generic RCPT TO probe — "
                "use -U/-u for local recipients or -R to force role",
                bullet_type="TITLE", condition=not self.use_json, indent=4,
            )

        smtp: smtplib.SMTP | None = None
        auth_used = False

        try:
            smtp = self.get_smtp_handler()
            smtp.docmd("EHLO", self.fqdn)

            # Authenticate on the active socket for Submission servers (helper smtp.login)
            if (not no_precheck) and effective_role == "submission":
                user, passwd = self._rl_first_creds()
                if user and passwd:
                    try:
                        if _show_progress:
                            _live_label[0] = f"Authenticating as {user}..."
                            _render_progress()
                        smtp.login(user, passwd)
                        auth_used = True
                        _emit_probe_debug(f"AUTH LOGIN succeeded for user {user}", Out.INFO)
                    except Exception as e:
                        msg = f"AUTH LOGIN failed for {user}: {e}"
                        _emit_probe_debug(msg, Out.INFO)
                        if _show_progress:
                            _end_progress()
                        ptprinthelper.ptprint(msg, bullet_type="VULN",
                                              condition=not self.use_json, indent=4)
                        return RcptLimitResult(
                            max_accepted=0,
                            limit_triggered=False,
                            server_response=str(e),
                            rejected_addresses=False,
                            domain_used=domain,
                            role=effective_role,
                            auth_required=auth_required,
                            open_relay=open_relay,
                            skipped=True,
                            skip_reason="auth_failed",
                            skip_message=msg,
                            recipients_source=None,
                        )

            _probe_emit_debug = _emit_probe_debug if (self.args.debug and _show_progress) else None
            accept_all_via_rcpt, accept_all_rate_err = self._rl_probe_accept_all_rcpt(
                smtp,
                domain,
                envelope_mail_from=envelope_mail_from,
                emit_debug=_probe_emit_debug,
            )
            if accept_all_rate_err:
                return self._rl_rate_limited_result(
                    accept_all_rate_err,
                    domain=domain,
                    effective_role=effective_role,
                    auth_required=auth_required,
                    open_relay=open_relay,
                    recipients_source=recipients_source,
                )
            if env_rate_err := self._rl_probe_envelope_mail_from_rate_limit(
                smtp, envelope_mail_from
            ):
                return self._rl_rate_limited_result(
                    env_rate_err,
                    domain=domain,
                    effective_role=effective_role,
                    auth_required=auth_required,
                    open_relay=open_relay,
                    recipients_source=recipients_source,
                )
            if accept_all_via_rcpt and open_relay is not True:
                self._stream_rcpt_limit_catch_all_notice()
            if rl_wordlist_notice is not None:
                recs, wl_n = rl_wordlist_notice
                self._stream_rcpt_limit_wordlist_notices(recs, wl_n)

            _emit_probe_debug(
                f"RCPT TO limit test summary: domain={domain}, max attempts={max_rcpt_attempts}, "
                f"recipients_source={recipients_source}, auth_used={auth_used}, "
                f"accept_all_via_rcpt={accept_all_via_rcpt}, "
                f"envelope_mail_from={envelope_mail_from or '<>'}",
                Out.INFO,
            )
            # Progress denominator = the number of RCPT attempts we will actually make
            # (capped by the wordlist length when explicit recipients are used).
            if recipients:
                _max_probe_ref[0] = max(1, min(max_rcpt_attempts, len(recipients)))
            else:
                _max_probe_ref[0] = max_rcpt_attempts
            _live_label[0] = "accepted 0 recipients..."
            if _show_progress:
                threading.Thread(target=_ticker, daemon=True).start()
            result = self._run_rcpt_limit_for_domain(
                smtp, domain, max_rcpt_attempts=max_rcpt_attempts,
                live_label=_live_label,
                attempt_hook=_update_attempt if _show_progress else None,
                recipients=recipients,
                emit_debug=_probe_emit_debug,
                send_data_at_end=send_mode,
                envelope_mail_from=envelope_mail_from,
            )
            domain_used = domain

            # Parent-domain retry only makes sense for synthetic recipients (1@dom). With a wordlist
            # the addresses are already explicit, so we do not rewrite them.
            if (
                recipients is None
                and getattr(result, "rejected_addresses", False)
                and not getattr(result, "no_session_limit", False)
                and not getattr(result, "session_limit_triggered", False)
                and not getattr(self.args, "domain", None)
                and domain.count(".") >= 2
            ):
                parent = self._to_parent_domain(domain)
                if parent != domain:
                    _emit_probe_debug(f"Retrying RCPT TO limit with parent domain: {parent}", Out.INFO)
                    try:
                        smtp.docmd("RSET")
                    except Exception:
                        pass
                    _live_label[0] = "accepted 0 recipients..."
                    _attempt_ref[0] = 0
                    _eta_ref[0] = None
                    _max_probe_ref[0] = max_rcpt_attempts
                    result = self._run_rcpt_limit_for_domain(
                        smtp, parent, max_rcpt_attempts=max_rcpt_attempts,
                        live_label=_live_label,
                        attempt_hook=_update_attempt if _show_progress else None,
                        emit_debug=_probe_emit_debug,
                        send_data_at_end=send_mode,
                        envelope_mail_from=envelope_mail_from,
                    )
                    domain_used = parent

            return RcptLimitResult(
                result.max_accepted,
                result.limit_triggered,
                result.server_response,
                getattr(result, "rejected_addresses", False),
                domain_used,
                getattr(result, "failed_before_limit", 0),
                getattr(result, "session_limit_triggered", False),
                getattr(result, "no_session_limit", False),
                role=effective_role,
                auth_required=auth_required,
                auth_used=auth_used,
                open_relay=open_relay,
                skipped=False,
                skip_reason=None,
                skip_message=None,
                recipients_source=recipients_source,
                disconnect_after_limit=getattr(result, "disconnect_after_limit", None),
                posthit_probe_count=getattr(result, "posthit_probe_count", 0),
                accept_all_via_rcpt=accept_all_via_rcpt,
                limit_send_mode=getattr(result, "limit_send_mode", send_mode),
                limit_send_attempted=getattr(result, "limit_send_attempted", False),
                limit_send_ok=getattr(result, "limit_send_ok", False),
                limit_send_data_code=getattr(result, "limit_send_data_code", None),
                limit_send_data_reply=getattr(result, "limit_send_data_reply", None),
                limit_send_mail_from=getattr(result, "limit_send_mail_from", envelope_mail_from),
            )
        finally:
            if _show_progress:
                _end_progress()
            if smtp is not None:
                try:
                    smtp.close()
                except Exception:
                    pass

    def test_rcpt_duplicate(self) -> RcptDuplicateResult:
        """Many RCPT TO for the same address in one MAIL transaction (-rdd / --rcpt-duplicate)."""
        self._ensure_initial_info(fail_label="-rdd")

        raw = (self.args.rcpt_to or "").strip()
        if not raw or "@" not in raw:
            raise ValueError("-rdd requires -r/--rcpt-to as a full address (user@domain)")

        dom = raw.split("@", 1)[1].strip().lower().rstrip(".")
        display_to = raw.strip("<>").strip()
        rcpt_bracket = raw if raw.startswith("<") and raw.endswith(">") else f"<{display_to}>"

        n = int(self.args.rcpt_duplicate or RCPT_DUP_DEFAULT)
        send_data = bool(getattr(self.args, "send", False))
        probe_uuid = self._new_mail_test_id() if send_data else None

        smtp: smtplib.SMTP | None = None
        try:
            smtp = self.get_smtp_handler(timeout=45.0)
            code, reply = smtp.docmd("EHLO", self.fqdn)
            if code != 250:
                raise RuntimeError(
                    f"EHLO failed: [{code}] {self.bytes_to_str(reply).strip()[:400]}"
                )
            try:
                smtp.docmd("RSET")
            except Exception:
                pass

            ok_mail, mail_used = self._try_mail_from_for_rcpt_probe(smtp, dom)
            if not ok_mail:
                raise RuntimeError("MAIL FROM rejected for all candidates (cannot probe RCPT)")

            replies: list[tuple[int, str]] = []
            for i in range(n):
                st, rp = smtp.docmd("RCPT TO:", rcpt_bracket)
                rps = self.bytes_to_str(rp).strip()[:500]
                replies.append((st, rps))
                self._stream_smtp_trace_line(
                    f"RCPT TO: {rcpt_bracket} [{i + 1}/{n}] → {self._smtp_trace_reply(st, rp)}"
                )

            rcpt_ok = tuple(replies)
            first_fail: int | None = None
            for i, (st, _) in enumerate(rcpt_ok):
                if st not in (250, 251, 252):
                    first_fail = i
                    break
            all_2xx = first_fail is None

            data_sent = False
            dcode: int | None = None
            drep: str | None = None

            if send_data and all_2xx:
                raw_msg = self._outbound_minimal_probe(
                    from_addr=f"rdd@{dom}",
                    message_id_tag="rdd",
                    domain=dom,
                    probe_uuid=probe_uuid,
                    to_addr=display_to,
                )
                try:
                    dcode, drp = smtp.data(raw_msg)
                    drep = self.bytes_to_str(drp).strip()[:500]
                    data_sent = dcode == 250
                    if send_data and self.args.debug and not self.use_json:
                        self._stream_smtp_trace_line(
                            self._data_trace_entry(raw_msg, dcode, drp),
                        )
                except Exception as e:
                    drep = str(e).strip()[:500]
                    data_sent = False
            else:
                try:
                    smtp.docmd("RSET")
                except Exception:
                    pass

            return RcptDuplicateResult(
                recipient=display_to,
                duplicate_count=n,
                rcpt_replies=rcpt_ok,
                all_rcpt_2xx=all_2xx,
                first_failure_index=first_fail,
                data_sent=data_sent,
                data_code=dcode,
                data_reply_snippet=drep,
                mail_from_used=mail_used,
                probe_uuid=probe_uuid,
            )
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    try:
                        smtp.close()
                    except Exception:
                        pass

    def _build_accepted_domain_probe_candidates(self) -> list[str]:
        """Ordered domain candidates: -d only, else inferred + parent + invalid.invalid control."""
        seen: set[str] = set()
        out: list[str] = []

        def add(d: str) -> None:
            t = (d or "").strip().lower().rstrip(".")
            if not t or "." not in t or t in seen:
                return
            seen.add(t)
            out.append(t)

        dom_arg = getattr(self.args, "domain", None)
        if dom_arg and str(dom_arg).strip():
            add(str(dom_arg).strip())
        else:
            add(self._get_rcpt_limit_domain())
            if out:
                base = out[-1]
                if base.count(".") >= 2:
                    add(self._to_parent_domain(base))
        add("invalid.invalid")
        return out[:12]

    @staticmethod
    def _rcpt_reply_suggests_unknown_user(reply: str | bytes) -> bool:
        if isinstance(reply, bytes):
            up = reply.upper()
        else:
            up = str(reply).upper()
        keys = (
            "UNKNOWN",
            "USER UNKNOWN",
            "NO SUCH USER",
            "MAILBOX UNAVAILABLE",
            "ADDRESS REJECTED",
            "NOT FOUND",
            "INVALID RECIPIENT",
            "5.1.1",
        )
        return any(k in up for k in keys)

    def _probe_rcpt_acceptance_for_domain(
        self, smtp: smtplib.SMTP, domain: str, random_local: str
    ) -> tuple[int, str, str]:
        """Score one domain: (0–100, confidence high|medium|low|none, short detail)."""
        mail_bracket = self._envelope_mail_from_bracket()
        try:
            smtp.docmd("RSET")
        except Exception:
            pass
        try:
            st_m, rep_m = smtp.docmd("MAIL FROM:", mail_bracket)
        except Exception as e:
            return (0, "none", f"MAIL FROM failed: {e}")
        if st_m != 250:
            return (0, "none", f"MAIL FROM not accepted ({st_m})")
        try:
            st_r, rep_r = smtp.docmd("RCPT TO:", f"<{random_local}@{domain}>")
        except Exception as e:
            return (0, "none", f"RCPT (probe) failed: {e}")
        reply_r = self.bytes_to_str(rep_r) if rep_r else ""
        if 400 <= st_r < 500:
            return (5, "none", f"RCPT probe temporary rejection ({st_r}); try later")
        try:
            smtp.docmd("RSET")
        except Exception:
            pass
        try:
            st_m2, _ = smtp.docmd("MAIL FROM:", mail_bracket)
        except Exception as e:
            return (0, "none", f"MAIL FROM after RSET failed: {e}")
        if st_m2 != 250:
            return (0, "none", f"MAIL FROM not accepted after RSET ({st_m2})")
        try:
            st_p, rep_p = smtp.docmd("RCPT TO:", f"<Postmaster@{domain}>")
        except Exception as e:
            return (0, "none", f"RCPT Postmaster failed: {e}")
        reply_p = self.bytes_to_str(rep_p) if rep_p else ""
        probe_ok = 200 <= st_r < 300
        post_ok = 200 <= st_p < 300
        bad_probe = self._rcpt_response_suggests_bad_domain(reply_r)
        unk_probe = self._rcpt_reply_suggests_unknown_user(reply_r) or (
            550 <= st_r < 560 and not bad_probe and not probe_ok
        )
        if bad_probe and not probe_ok:
            return (0, "none", "Domain-level or relay rejection on probe RCPT")
        # Same signal as -rl "rejected test addresses" with 5.1.1 user unknown: server treats @domain as local.
        if not probe_ok and unk_probe and not bad_probe:
            if post_ok:
                return (
                    95,
                    "high",
                    "Postmaster accepted; probe mailbox rejected as unknown user at this domain",
                )
            return (
                92,
                "high",
                "Probe mailbox rejected as unknown user; server accepts this recipient domain; "
                "Postmaster not accepted or blocked by policy",
            )
        if post_ok and probe_ok:
            return (
                40,
                "low",
                "Server accepts RCPT for probe and Postmaster (possible catch-all or deferred verify)",
            )
        if probe_ok and not post_ok:
            return (
                38,
                "low",
                "Server accepts probe mailbox; Postmaster not accepted (unusual)",
            )
        if not probe_ok and 550 <= st_r < 560 and not bad_probe and not unk_probe:
            return (
                25,
                "none",
                f"RCPT probe rejected ({st_r}) without clear unknown-user semantics",
            )
        return (0, "none", "No clear local-domain signal from RCPT responses")

    def test_probe_accepted_domain(self) -> AcceptedDomainProbeResult:
        """Informational: infer which @domain RCPT treats as locally relevant (RFC 5321 RCPT semantics)."""
        if not getattr(self.results, "info", None):
            _, info = self.initial_info(get_commands=True)
            self.results.info = InfoResult(
                info.banner,
                info.ehlo,
                getattr(info, "ehlo_starttls", None),
            )
            self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
            self.results.banner_requested = False
            self.results.commands_requested = False
        candidates = self._build_accepted_domain_probe_candidates()
        random_local = f"ptsrvnx{secrets.token_hex(4)}"
        best: tuple[int, str, str, str] | None = None  # score, domain, confidence, detail
        universal = False
        tried: list[str] = []
        smtp: smtplib.SMTP | None = None
        try:
            smtp = self.get_smtp_handler()
            smtp.docmd("EHLO", self.fqdn)
            for dom in candidates:
                tried.append(dom)
                sc, conf, det = self._probe_rcpt_acceptance_for_domain(smtp, dom, random_local)
                if dom.lower() == "invalid.invalid" and sc >= 38:
                    universal = True
                if dom.lower() != "invalid.invalid":
                    if best is None or sc > best[0]:
                        best = (sc, dom, conf, det)
        finally:
            if smtp is not None:
                try:
                    smtp.close()
                except Exception:
                    pass
        min_score = 38
        if best is None or best[0] < min_score:
            detail = (best[3] if best else "") or (
                "No tested domain produced a confident local-domain pattern."
            )
            if universal:
                extra = (
                    'Server is "Accept-All" or uses deferred verification '
                    "(invalid.invalid accepted)."
                )
                detail = f"{detail} {extra}".strip() if detail else extra
            return AcceptedDomainProbeResult(
                None,
                "none",
                detail,
                tuple(tried),
                universal,
            )
        _sc, dom, conf, det = best
        placeholder = _accepted_domain_is_placeholder(dom)
        if conf == "high" and (universal or placeholder):
            conf = "medium"
        detail = det
        return AcceptedDomainProbeResult(
            dom, conf, detail, tuple(tried), universal, placeholder,
        )

    def _stream_accepted_domain_probe_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if self.use_json:
            return
        if (err := self.results.accepted_domain_probe_error) is not None:
            pp(f"Test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        r = self.results.accepted_domain_probe
        if r is None:
            return
        if r.universal_accept_detected:
            pp(
                "Server is \"Accept-All\" or uses deferred verification "
                "(invalid.invalid accepted).",
                bullet_type="TITLE", condition=show, indent=4,
            )
        domain_line_bullet = (
            "WARNING"
            if (r.universal_accept_detected or getattr(r, "likely_placeholder_domain", False))
            else "TITLE"
        )
        if r.domain and r.confidence != "none":
            pp(
                f"Accepted recipient domain: {r.domain} (confidence: {r.confidence})",
                bullet_type=domain_line_bullet, condition=show, indent=4,
            )
            if r.detail:
                pp(r.detail, bullet_type="TITLE", condition=show, indent=4)
            if getattr(r, "likely_placeholder_domain", False):
                pp(
                    f"WARNING: {r.domain} matches a known placeholder / example "
                    "domain; this often reflects default MTA configuration, not an operational "
                    "recipient namespace.",
                    bullet_type="WARNING", condition=show, indent=4,
                )
        else:
            no_dom_bullet = "WARNING" if r.universal_accept_detected else "TITLE"
            pp(
                "Could not determine an accepted recipient domain",
                bullet_type=no_dom_bullet, condition=show, indent=4,
            )
            if r.detail:
                pp(r.detail, bullet_type="TITLE", condition=show, indent=4)

    def _accepted_domain_probe_props_json(self) -> dict[str, object]:
        """JSON fragment for -pd (no vulnerabilities)."""
        out: dict[str, object] = {}
        if (err := self.results.accepted_domain_probe_error) is not None:
            out["acceptedRecipientDomainProbeError"] = err
            return out
        pr = self.results.accepted_domain_probe
        if pr is None:
            return out
        obj: dict[str, object] = {
            "domain": pr.domain,
            "confidence": pr.confidence,
            "candidatesTested": list(pr.candidates_tested),
            "universalAcceptDetected": pr.universal_accept_detected,
            "likelyPlaceholderDomain": pr.likely_placeholder_domain,
        }
        if pr.detail:
            obj["detail"] = pr.detail
        out["acceptedRecipientDomainProbe"] = obj
        return out

    @staticmethod
    def _rcpt_response_suggests_bad_domain(response: str | None) -> bool:
        """True when the RCPT server response indicates a domain-level rejection
        (wrong / unroutable domain) rather than a user-level rejection.
        Used to decide whether to show the -d/--domain hint.

        A '550 User unknown' answer means the domain IS known to the server –
        only the local part is absent – so no domain hint is needed.
        Responses that do suggest a bad domain include relay-policy errors,
        unresolvable-domain notices, and catch-all domain rejections."""
        if not response:
            return False
        up = response.upper()
        DOMAIN_INDICATORS = (
            "RELAY ACCESS DENIED",
            "RELAY DENIED",
            "RELAYING DENIED",
            "RELAY NOT PERMITTED",
            "NOT PERMITTED TO RELAY",
            "RELAYING NOT PERMITTED",
            "UNABLE TO RELAY",
            "USER NOT LOCAL",
            "NO SUCH DOMAIN",
            "DOMAIN NOT FOUND",
            "DOMAIN DOES NOT EXIST",
            "DOMAIN UNKNOWN",
            "UNKNOWN DOMAIN",
            "UNROUTEABLE",
            "UNRESOLVABLE",
            "CANNOT ROUTE",
            "INVALID DOMAIN",
            "BAD DESTINATION",
            "NO ROUTE TO HOST",
            "HOST NOT FOUND",
            "NAME OR SERVICE NOT KNOWN",
        )
        return any(kw in up for kw in DOMAIN_INDICATORS)

    def _stream_open_relay_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (open_relay_error := self.results.open_relay_error) is not None:
            pp(f"Open relay test failed: {open_relay_error}", bullet_type="VULN", condition=show, indent=4)
            return
        if (open_relay := self.results.open_relay) is None:
            return
        if open_relay:
            pp("Open relay is allowed", bullet_type="VULN", condition=show, indent=4)
        else:
            pp("Open relay is denied", bullet_type="NOTVULN", condition=show, indent=4)

    @staticmethod
    def _rcpt_limit_recipient_verdict_bullet(max_accepted: int) -> str:
        """Bullet type from accepted RCPT count before limit/cap: ≤100 OK, 101–500 warn, >500 error."""
        n = max_accepted if max_accepted is not None else 0
        if n <= RCPT_LIMIT_VERDICT_OK_MAX:
            return "NOTVULN"
        if n <= RCPT_LIMIT_VERDICT_WARN_MAX:
            return "WARNING"
        return "VULN"

    def _stream_rcpt_limit_catch_all_notice(self) -> None:
        """Print when pre-probe RCPT TO accepts a clearly invalid local part."""
        ptprinthelper.ptprint(
            "Server accepts non-exist recipients in RCPT TO "
            "(likely Catch-all is configured)",
            bullet_type="TITLE", condition=not self.use_json, indent=4,
        )

    def _stream_rcpt_limit_wordlist_notices(self, recipients: list[str], wordlist_size: int) -> None:
        """Deferred MTA-not-relay wordlist info (after accept-all pre-probe)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        pp(
            f"Using {len(recipients)} recipient(s) "
            f"{self._rl_name_list_source_phrase()} for MTA-not-relay probe",
            bullet_type="TITLE", condition=show, indent=4,
        )
        if wordlist_size < RCPT_LIMIT_MIN_RECOMMENDED_NAME_COUNT:
            pp(
                f"For a valid test, a username list with more than "
                f"{RCPT_LIMIT_MIN_RECOMMENDED_NAME_COUNT} valid recipients is required",
                bullet_type="TITLE", condition=show, indent=4,
            )

    def _maybe_stream_rcpt_limit_domain_hint(self, server_response: str | None) -> None:
        """Print -d/--domain hint when auto domain looks wrong (relay / unroutable)."""
        if getattr(self.args, "domain", None):
            return
        if not self._rcpt_response_suggests_bad_domain(server_response):
            return
        ptprinthelper.ptprint(
            "Try -d/--domain <domain> to set recipient domain for this test",
            bullet_type="TITLE", condition=not self.use_json, indent=4,
        )

    def _stream_rcpt_limit_catch_all_delivery_hint(self, rlim: RcptLimitResult) -> None:
        """Manual catch-all bounce follow-up when optional ``-m`` was passed with ``-rl``."""
        bounce_mb = getattr(rlim, "catch_all_bounce_mailbox", None)
        if not bounce_mb:
            return
        pp = ptprinthelper.ptprint
        show = not self.use_json
        probe_local = RCPT_LIMIT_ACCEPT_ALL_PROBE_LOCAL
        probe_domain = getattr(rlim, "domain_used", None) or "domain"
        probe_addr = getattr(rlim, "catch_all_delivery_rcpt", None) or f"{probe_local}@{probe_domain}"

        if getattr(rlim, "catch_all_delivery_attempted", False):
            if getattr(rlim, "catch_all_delivery_data_ok", False):
                pp(f"Check mailbox {bounce_mb} for delivered message",
                   bullet_type="TITLE", condition=show, indent=4)
            else:
                pp(
                    f"Catch-all bounce probe: could not complete delivery to "
                    f"{probe_addr} (MAIL FROM: {bounce_mb}) — manual bounce check may be inconclusive",
                    bullet_type="WARNING", condition=show, indent=4,
                )
        elif not getattr(rlim, "accept_all_via_rcpt", False):
            pp(
                f"Catch-all bounce probe skipped: RCPT TO did not accept "
                f"{probe_local}@{probe_domain} (no message sent; -m not used for bounce check)",
                bullet_type="TITLE", condition=show, indent=4,
            )

    def _stream_rcpt_limit_server_response_verbose(self, server_response: str | None) -> None:
        """Full SMTP reply lines only with -vv/--verbose (``args.debug``)."""
        if not server_response:
            return
        for line in (server_response or "").replace("\r", "").splitlines():
            self.ptdebug(line, Out.TEXT)

    def _stream_rcpt_limit_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        rcptmax_advertised = None
        if (info := getattr(self.results, "info", None)) and getattr(info, "ehlo", None):
            rcptmax_advertised = _parse_rcptmax_from_ehlo(info.ehlo)
        if (rcpt_limit_err := self.results.rcpt_limit_error) is not None:
            if rcptmax_advertised is not None:
                pp(f"Advertised in EHLO (RFC 9422): RCPTMAX={rcptmax_advertised}",
                   bullet_type="TITLE", condition=show, indent=4)
            pp(f"Test failed: {rcpt_limit_err}", bullet_type="VULN", condition=show, indent=4)
            return
        rlim = self.results.rcpt_limit
        if rlim is None:
            return
        # Pre-check verdict / skip path (printed live by test_rcpt_limit; nothing more to do
        # here except announce the per-message verdict, which is already absent for skip cases).
        if getattr(rlim, "skipped", False):
            return
        if getattr(rlim, "auth_used", False):
            pp("Authenticated session used for RCPT TO probe", bullet_type="TITLE", condition=show, indent=4)
        if rcptmax_advertised is not None:
            pp(f"Advertised in EHLO (RFC 9422): RCPTMAX={rcptmax_advertised}",
               bullet_type="TITLE", condition=show, indent=4)
        if getattr(rlim, "session_limit_triggered", False):
            attempts = getattr(rlim, "failed_before_limit", 0)
            attempts_suffix = f" (after {attempts} attempts)" if attempts else ""
            pp(f"Session limit enforced (421 or disconnect){attempts_suffix}",
               bullet_type="NOTVULN", condition=show, indent=4)
            self._stream_rcpt_limit_server_response_verbose(rlim.server_response)
        elif getattr(rlim, "rejected_addresses", False) and getattr(rlim, "no_session_limit", False):
            attempts = getattr(rlim, "failed_before_limit", 0)
            if attempts:
                pp(
                    f"Could not test per-message limit: server rejects {attempts} tested addresses "
                    f"(allowed {attempts} failed RCPTs without disconnect)",
                    bullet_type="WARNING", condition=show, indent=4,
                )
            else:
                pp(
                    "Could not test per-message limit: server rejects tested addresses "
                    "(allowed failed RCPTs without disconnect)",
                    bullet_type="WARNING", condition=show, indent=4,
                )
            self._maybe_stream_rcpt_limit_domain_hint(rlim.server_response)
        elif rlim.limit_triggered:
            pp(
                f"Max {rlim.max_accepted} recipients per message (next recipients are rejected)",
                bullet_type=self._rcpt_limit_recipient_verdict_bullet(rlim.max_accepted),
                condition=show, indent=4,
            )
            disc = getattr(rlim, "disconnect_after_limit", None)
            if disc is True:
                pp("Connection was disconnected after many invalid recipients",
                   bullet_type="NOTVULN", condition=show, indent=4)
            elif disc is False:
                pp("Connection is not disconnected after many invalid recipients",
                   bullet_type="VULN", condition=show, indent=4)
            self._stream_rcpt_limit_server_response_verbose(rlim.server_response)
            if rlim.max_accepted == 0:
                self._maybe_stream_rcpt_limit_domain_hint(rlim.server_response)
        else:
            if rlim.max_accepted == 0:
                rl_err = _rl_extract_too_much_mail_error(rlim.server_response)
                if rl_err:
                    pp(rl_err, bullet_type="VULN", condition=show, indent=4)
                else:
                    pp("Could not test: no recipients accepted", bullet_type="TITLE", condition=show, indent=4)
                self._stream_rcpt_limit_server_response_verbose(rlim.server_response)
                if not rl_err:
                    self._maybe_stream_rcpt_limit_domain_hint(rlim.server_response)
        pp(
            f"Accepted recipients: {rlim.max_accepted}",
            bullet_type=self._rcpt_limit_recipient_verdict_bullet(rlim.max_accepted),
            condition=show, indent=4,
        )
        if getattr(rlim, "limit_send_mode", False):
            mail_from = getattr(rlim, "limit_send_mail_from", None) or "?"
            if getattr(rlim, "limit_send_attempted", False):
                if getattr(rlim, "limit_send_ok", False):
                    pp(
                        f"Message with {rlim.max_accepted} recipient(s) accepted "
                        f"by server (DATA 250, MAIL FROM: {mail_from})",
                        bullet_type="NOTVULN", condition=show, indent=4,
                    )
                    pp(
                        f"Check mailbox {mail_from} for NDR, bounce, "
                        "or other delivery status notifications",
                        bullet_type="TITLE", condition=show, indent=4,
                    )
                else:
                    code = getattr(rlim, "limit_send_data_code", None)
                    reply = (getattr(rlim, "limit_send_data_reply", None) or "").strip()
                    code_s = str(code) if code is not None else "?"
                    pp(
                        f"Message delivery failed after {rlim.max_accepted} "
                        f"accepted RCPT TO (DATA [{code_s}] {reply})".rstrip(),
                        bullet_type="VULN", condition=show, indent=4,
                    )
            elif rlim.max_accepted == 0:
                pp("Message not sent: no RCPT TO accepted in this transaction",
                   bullet_type="TITLE", condition=show, indent=4)
        self._stream_rcpt_limit_catch_all_delivery_hint(rlim)

    def _stream_rcpt_duplicate_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.rcpt_duplicate_error) is not None:
            if _rcpt_duplicate_error_is_environmental(err):
                pp(f"Duplicate RCPT probe could not run: {err}", bullet_type="TITLE", condition=show, indent=4)
            else:
                pp(f"Duplicate RCPT probe failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        r = self.results.rcpt_duplicate
        if r is None:
            return
        if r.all_rcpt_2xx:
            bullet = "VULN" if r.duplicate_count >= 3 else "TITLE"
            pp(
                f"All {r.duplicate_count} duplicate RCPT TO accepted for {r.recipient}",
                bullet_type=bullet, condition=show, indent=4,
            )
        else:
            fi = r.first_failure_index
            c = r.rcpt_replies[fi][0] if fi is not None and fi < len(r.rcpt_replies) else "?"
            pp(
                f"Duplicate RCPT not fully accepted "
                f"(first non-2xx at #{fi + 1 if fi is not None else '?'}: {c})",
                bullet_type="NOTVULN", condition=show, indent=4,
            )
        if r.data_sent and r.probe_uuid:
            self._pp_mail_probe_line(
                pp,
                show,
                accepted=True,
                sent_msg=self._mail_sent_inbox_msg(r.recipient, r.probe_uuid),
                indent=4,
            )
        elif getattr(self.args, "send", False) and not r.data_sent:
            extra = f": {r.data_reply_snippet}" if r.data_reply_snippet else ""
            pp(f"DATA not completed{extra}", bullet_type="TITLE", condition=show, indent=4)
