import base64, ipaddress, os, random, re, secrets, smtplib, socket, ssl, sys, threading, time, unicodedata
from typing import Callable


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from .._base import Out
from ..utils import ptprinthelper
from ..utils.ptprinthelper import get_colored_text
from ..utils.helpers import Creds, get_mode, text_or_file
from ..utils.smtp_fingerprints import ServerIdentifyResult
from ..utils.behavior_profiles import PROFILE_MISSING_HINTS

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from .helpers import *
from .results import *
from .registry import *


class SharedMixin:


    def _outbound_subject(self) -> str:
        val = getattr(self.args, "smtp_subject", None)
        if val is not None:
            return str(val)
        return DEFAULT_SMTP_SUBJECT

    def _outbound_data(self) -> str:
        val = getattr(self.args, "smtp_data", None)
        if val is not None:
            return str(val)
        return DEFAULT_SMTP_DATA

    def _outbound_data_with_url(self, url: str) -> str:
        """Plain body from ``--data`` with an optional URL embedded (SSRF / internal probes)."""
        body = self._outbound_data()
        if not url:
            return body
        if "{{CANARY_URL}}" in body:
            return body.replace("{{CANARY_URL}}", url)
        if url not in body:
            body = f"{body}\n{url}"
        return body

    def _new_mail_test_id(self) -> str:
        return f"{random.getrandbits(32):08x}"

    def _mail_sent_inbox_msg(self, inbox: str, test_id: str) -> str:
        return f"Mail was sent — check inbox {str(inbox).strip()} (message id: {str(test_id).strip()})"

    def _mime_add_test_id_header(self, raw: str, test_id: str) -> str:
        if not test_id or f"{EMAIL_HDR_TEST_ID}:" in raw:
            return raw
        hdr = f"{EMAIL_HDR_TEST_ID}: {test_id}\r\n"
        if "\r\n\r\n" in raw:
            head, rest = raw.split("\r\n\r\n", 1)
            return f"{head}\r\n{hdr}\r\n{rest}"
        return f"{raw.rstrip()}\r\n{hdr}"

    def _av_print_payload_summary(
        self,
        pp,
        summary_line: str,
        payload_test_id: str,
        rcpt: str,
    ) -> None:
        """Terminal summary for one AV payload (normal mode, no SMTP trace)."""
        pp(
            self._av_summary_payload_label(summary_line),
            bullet_type="TEXT",
            condition=True,
            indent=8,
        )
        if "(accepted)" in summary_line and payload_test_id:
            self._pp_mail_probe_line(
                pp,
                True,
                accepted=True,
                sent_msg=self._mail_sent_inbox_msg(rcpt, payload_test_id),
                indent=12,
            )
        elif ":" in summary_line:
            tail = summary_line.split(":", 1)[1].strip()
            if tail:
                pp(tail, bullet_type="TEXT", condition=True, indent=12)

    def _av_stream_category_section(
        self,
        cat: AntivirusCategoryResult,
        rcpt: str,
        *,
        stream_trace: bool = False,
    ) -> None:
        """Per-category terminal block for -av."""
        pp = ptprinthelper.ptprint
        pp(self._av_category_title(cat.category), bullet_type="TITLE", condition=True, indent=4)
        payload_test_ids = cat.payload_test_ids or tuple("" for _ in cat.message_summary)
        if stream_trace:
            summary_iter = iter(zip(cat.message_summary, payload_test_ids))
            section_lines: list[str] = []
            orphan_lines: list[str] = []

            def _flush_section(lines: list[str]) -> None:
                if not lines:
                    return
                try:
                    summary_line, payload_test_id = next(summary_iter)
                except StopIteration:
                    return
                self._av_stream_payload_block(lines, summary_line, payload_test_id, rcpt)

            for line in cat.smtp_trace:
                if line.startswith("---") and line.endswith("---"):
                    if section_lines:
                        _flush_section(section_lines)
                        section_lines = []
                    elif orphan_lines:
                        _flush_section(orphan_lines)
                        orphan_lines = []
                    continue
                if section_lines:
                    section_lines.append(line)
                else:
                    orphan_lines.append(line)
            if section_lines:
                _flush_section(section_lines)
            elif orphan_lines:
                _flush_section(orphan_lines)
            for summary_line, payload_test_id in summary_iter:
                self._av_print_payload_summary(pp, summary_line, payload_test_id, rcpt)
            return
        for line, payload_test_id in zip(cat.message_summary, payload_test_ids):
            self._av_print_payload_summary(pp, line, payload_test_id, rcpt)

    @staticmethod
    def _al_variant_summary_detail(v: AliasVariantResult) -> str | None:
        mail_ok = v.accepted and not (v.detail and "DATA rejected" in v.detail)
        if mail_ok:
            return "1 accepted, 0 rejected, 0 error"
        if v.rejected:
            return SharedMixin._smtp_detail_one_line(v.detail) or v.detail or "rejected"
        if v.error:
            return v.detail or "error"
        return v.detail or "skipped"

    def _outbound_minimal_probe(
        self,
        *,
        from_addr: str,
        message_id_tag: str,
        domain: str,
        probe_uuid: str,
        to_addr: str | None = None,
    ) -> str:
        return _smtp_minimal_probe_data(
            from_addr=from_addr,
            subject=self._outbound_subject(),
            body=self._outbound_data(),
            message_id_tag=message_id_tag,
            domain=domain,
            probe_uuid=probe_uuid,
            to_addr=to_addr,
        )

    # ------------------------------------------------------------------
    # Role identification (MTA / Submission / Hybrid)
    # ------------------------------------------------------------------

    @staticmethod
    def _ehlo_has_auth(ehlo_raw: str | None) -> tuple[bool, list[str]]:
        """Check if EHLO response advertises AUTH. Returns (found, [methods])."""
        if not ehlo_raw:
            return False, []
        methods: list[str] = []
        for line in ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            line = line.strip()
            # Strip SMTP code prefix (250- or 250 )
            if line.startswith("250-"):
                rest = line[4:].strip()
            elif line.startswith("250 "):
                rest = line[3:].strip()
            else:
                rest = line.strip()
            if not rest:
                continue
            parts = rest.split(None, 1)
            key = (parts[0] or "").upper()
            if key == "AUTH":
                value = parts[1].strip() if len(parts) > 1 else ""
                methods.extend(m.upper() for m in value.split() if m)
        return (len(methods) > 0), methods

    def _role_port_hint(self) -> str:
        """Classify port as typical MTA or Submission; ``-R`` / ``--role`` overrides port heuristics."""
        declared = getattr(self.args, "smtp_role", None)
        if declared == "mta":
            return "mta"
        if declared == "submission":
            return "submission"
        port = self.args.target.port
        if port == 25:
            return "mta"
        if port in (587, 465, 2525):
            return "submission"
        return "unknown"

    def _role_rcpt_probe(self, smtp: smtplib.SMTP, target_domain: str | None) -> tuple[bool | None, str]:
        """Send MAIL FROM + RCPT TO without AUTH to determine if server requires authentication.

        Returns (auth_required, detail):
          True   -- server requires auth for RCPT TO (530)
          False  -- server accepts RCPT TO without auth (MTA or hybrid behaviour)
          None   -- could not determine (no domain, connection error, etc.)

        Guarantees: smtp handler is returned to a clean state (RSET) on all code
        paths so that subsequent tests (open_relay, enumeration, ...) can start
        a fresh MAIL transaction without 503 errors.
        """
        if not target_domain:
            # RFC 5321 s4.1.3: Address Literal -- server MUST accept mail for its own IP
            target_domain = f"[{self.target_ip}]"

        ext_domain = "gmail.com"
        mail_from = "<roletest@example.com>"
        local_rcpt = f"postmaster@{target_domain}"
        ext_rcpt = f"roletest@{ext_domain}"

        def _reply_one_line(raw: str | bytes, limit: int = 160) -> str:
            if isinstance(raw, str):
                s = raw.strip().replace("\r\n", " ").replace("\n", " ")
            else:
                s = self.bytes_to_str(raw).strip().replace("\r\n", " ").replace("\n", " ")
            return s if len(s) <= limit else s[: limit - 3] + "..."

        def _log_step(step: str, status: int, reply: str | bytes) -> None:
            self.ptdebug(
                f"Role probe {step} → [{status}] {_reply_one_line(reply)}",
                Out.INFO,
            )

        local_auth_required: bool | None = None
        local_detail = ""

        try:
            # Ensure clean state before probe
            try:
                smtp.docmd("RSET")
            except Exception:
                pass

            # 1. MAIL FROM
            try:
                status, reply = smtp.docmd("MAIL FROM:", mail_from)
                _log_step(f"MAIL FROM:{mail_from}", status, reply)
                if status not in (250, 251):
                    return None, f"MAIL FROM rejected: {status} {self.bytes_to_str(reply)}"
            except Exception as e:
                return None, f"MAIL FROM error: {e}"

            # 2. RCPT TO local domain
            try:
                local_env = f"<{local_rcpt}>"
                status, reply = smtp.docmd("RCPT TO:", local_env)
                reply_str = self.bytes_to_str(reply)
                _log_step(f"RCPT TO (local): {local_env}", status, reply)
                if status in (250, 251):
                    local_auth_required = False
                    local_detail = f"RCPT TO:{local_env} accepted without auth ({status})"
                elif 530 <= status <= 535:
                    local_auth_required = True
                    local_detail = f"RCPT TO:{local_env} requires authentication ({status})"
                elif status in (550, 551, 553):
                    local_auth_required = False
                    local_detail = f"RCPT TO:{local_env} rejected user ({status}) but no auth required"
                elif status in (450, 451, 452):
                    local_auth_required = False
                    local_detail = f"RCPT TO:{local_env} greylisting detected ({status}); no auth required"
                elif status == 421:
                    return None, f"Server closed connection ({status})"
                else:
                    local_detail = f"RCPT TO:{local_env} unexpected response: {status} {reply_str}"
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                return None, f"Connection lost during RCPT TO probe: {e}"
            except Exception as e:
                return None, f"RCPT TO error: {e}"

            # 3. RCPT TO external domain (relay check, only if local was accepted)
            if local_auth_required is False:
                try:
                    smtp.docmd("RSET")
                    status, reply = smtp.docmd("MAIL FROM:", mail_from)
                    _log_step(f"MAIL FROM:{mail_from}", status, reply)
                    if status not in (250, 251):
                        pass
                    else:
                        ext_env = f"<{ext_rcpt}>"
                        status, reply = smtp.docmd("RCPT TO:", ext_env)
                        reply_str = self.bytes_to_str(reply)
                        _log_step(f"RCPT TO (ext): {ext_env}", status, reply)
                        if status in (250, 251):
                            local_detail += f"; RCPT TO:{ext_env} also accepted (possible open relay)"
                except Exception:
                    pass

            if local_auth_required is not None:
                return local_auth_required, local_detail
            return None, local_detail or "Could not determine auth requirement"

        finally:
            # Always reset MAIL transaction state so the smtp handler is clean
            # for any subsequent tests (open_relay, enumeration, bruteforce, ...).
            try:
                smtp.docmd("RSET")
            except Exception:
                pass

    def test_role(self, smtp: smtplib.SMTP, info: InfoResult) -> RoleResult:
        """Identify SMTP server role based on port, AUTH availability, and RCPT TO probe.

        Decision matrix:
          port_hint  | AUTH advertised | RCPT TO probe    | Result
          -----------|-----------------|------------------|------------
          mta (25)   | no              | (skip)           | MTA
          mta (25)   | yes             | auth required    | Submission (unusual port)
          mta (25)   | yes             | no auth required | Hybrid
          sub (587+) | yes             | (skip)           | Submission
          sub (587+) | no              | no auth required | MTA (unusual port)
          sub (587+) | no              | auth required    | Submission
          any        | indeterminate   | indeterminate    | Indeterminate
        """
        self.ptdebug("Role identification test", title=True)

        if getattr(self.args, "smtp_role", None):
            self.ptdebug(
                f"Declared server role (--role): {self.args.smtp_role} "
                "(overrides port-based MTA vs Submission classification)",
                Out.INFO,
            )

        port_hint = self._role_port_hint()

        # Check AUTH in both EHLO (plain) and EHLO after STARTTLS
        auth_plain, methods_plain = self._ehlo_has_auth(info.ehlo)
        auth_starttls, methods_starttls = self._ehlo_has_auth(
            getattr(info, "ehlo_starttls", None)
        )
        auth_advertised = auth_plain or auth_starttls
        auth_methods = sorted(set(methods_plain + methods_starttls))

        target_domain = getattr(self.results, "resolved_domain", None)

        # --- High-confidence cases (no RCPT TO probe needed) ---

        # Port 25 + no AUTH -> pure MTA
        if port_hint == "mta" and not auth_advertised:
            detail = "Port 25, AUTH not advertised"
            return RoleResult("mta", port_hint, False, None, detail)

        # Submission port + AUTH present -> pure Submission (RFC 6409)
        if port_hint == "submission" and auth_advertised:
            methods_str = ", ".join(auth_methods) if auth_methods else "unknown"
            detail = f"Port {self.args.target.port}, AUTH advertised ({methods_str})"
            return RoleResult("submission", port_hint, True, None, detail)

        # --- Cases that need RCPT TO probe ---

        # Port 25 + AUTH present -> could be Hybrid or Submission on unusual port
        # Submission port + no AUTH -> could be MTA on unusual port or misconfigured Submission
        auth_required, probe_detail = self._role_rcpt_probe(smtp, target_domain)

        if port_hint == "mta" and auth_advertised:
            methods_str = ", ".join(auth_methods) if auth_methods else "unknown"
            if auth_required is True:
                detail = f"Port 25 but AUTH required for RCPT TO ({methods_str}); {probe_detail}"
                return RoleResult("submission", port_hint, True, True, detail)
            elif auth_required is False:
                detail = f"Port 25, AUTH advertised ({methods_str}) but RCPT TO accepted without auth; {probe_detail}"
                return RoleResult("hybrid", port_hint, True, False, detail)
            else:
                detail = f"Port 25, AUTH advertised ({methods_str}), probe inconclusive; {probe_detail}"
                return RoleResult("indeterminate", port_hint, True, None, detail)

        if port_hint == "submission" and not auth_advertised:
            if auth_required is True:
                detail = f"Port {self.args.target.port}, AUTH not in EHLO but required for RCPT TO; {probe_detail}"
                return RoleResult("submission", port_hint, False, True, detail)
            elif auth_required is False:
                detail = f"Port {self.args.target.port} (typical Submission) but no AUTH and RCPT TO accepted; {probe_detail}"
                return RoleResult("mta", port_hint, False, False, detail)
            else:
                detail = f"Port {self.args.target.port}, AUTH not in EHLO, probe inconclusive; {probe_detail}"
                return RoleResult("indeterminate", port_hint, False, None, detail)

        # Unknown port
        if auth_advertised:
            methods_str = ", ".join(auth_methods) if auth_methods else "unknown"
            if auth_required is True:
                detail = f"Port {self.args.target.port}, AUTH advertised ({methods_str}), required for RCPT TO; {probe_detail}"
                return RoleResult("submission", port_hint, True, True, detail)
            elif auth_required is False:
                detail = f"Port {self.args.target.port}, AUTH advertised ({methods_str}), RCPT TO accepted without auth; {probe_detail}"
                return RoleResult("hybrid", port_hint, True, False, detail)
            else:
                detail = f"Port {self.args.target.port}, AUTH advertised ({methods_str}), probe inconclusive; {probe_detail}"
                return RoleResult("indeterminate", port_hint, True, None, detail)
        else:
            if auth_required is False:
                detail = f"Port {self.args.target.port}, no AUTH, RCPT TO accepted without auth; {probe_detail}"
                return RoleResult("mta", port_hint, False, False, detail)
            elif auth_required is True:
                detail = f"Port {self.args.target.port}, no AUTH in EHLO but required for RCPT TO; {probe_detail}"
                return RoleResult("submission", port_hint, False, True, detail)
            else:
                detail = f"Port {self.args.target.port}, no AUTH, probe inconclusive; {probe_detail}"
                return RoleResult("indeterminate", port_hint, False, None, detail)

    @staticmethod
    def _to_parent_domain(host: str) -> str:
        """Reduce hostname to parent (second-level) domain: strip leftmost label if 3+ parts."""
        host = (host or "").strip().lower()
        if not host or "." not in host:
            return host
        parts = host.split(".")
        if len(parts) >= 3:
            return ".".join(parts[1:])
        return host

    def _resolve_rcpt_limit_domain(self) -> tuple[str, str]:
        """Return ``(domain, source)`` for RCPT TO limit tests.

        ``source`` is one of: ``domain_arg``, ``banner``, ``ehlo``, ``fqdn``, ``ptr``, ``default``.
        User ``-d`` is used as-is. Server hostnames are reduced via PSL when applicable.
        """
        domain = getattr(self.args, "domain", None)
        if domain and domain.strip():
            return domain.strip(), "domain_arg"
        host: str | None = None
        info = getattr(self.results, "info", None)
        if info and getattr(info, "banner", None):
            line = (info.banner or "").replace("\r", "").split("\n")[0].strip()
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "220":
                host = parts[1]
            elif parts:
                host = parts[0]
            if host and "." in host:
                psl_domain = _registrable_domain_psl(host)
                if psl_domain:
                    return psl_domain, "banner"
                return host, "banner"
        if info and getattr(info, "ehlo", None):
            raw = (info.ehlo or "").replace("\r\n", "\n").replace("\r", "\n")
            for line in raw.split("\n"):
                line = line.strip()
                if line.startswith("250-"):
                    rest = line[4:].strip()
                elif line.startswith("250 "):
                    rest = line[3:].strip()
                else:
                    continue
                if rest and "." in rest.split()[0]:
                    host = rest.split()[0]
                    psl_domain = _registrable_domain_psl(host)
                    if psl_domain:
                        return psl_domain, "ehlo"
                    return host, "ehlo"
        if self.fqdn and "." in self.fqdn and "pentereptools" not in self.fqdn.lower():
            psl_domain = _registrable_domain_psl(self.fqdn)
            if psl_domain:
                return psl_domain, "fqdn"
            return self._to_parent_domain(self.fqdn), "fqdn"
        try:
            ptr_host = socket.gethostbyaddr(self.target_ip)[0]
            if ptr_host and "." in ptr_host:
                psl_domain = _registrable_domain_psl(ptr_host)
                if psl_domain:
                    return psl_domain, "ptr"
                return self._to_parent_domain(ptr_host) if len(ptr_host.split(".")) >= 3 else ptr_host, "ptr"
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            pass
        return "test.com", "default"

    def _get_rcpt_limit_domain(self) -> str:
        """Domain for RCPT TO limit test: -d/--domain, or from server banner/EHLO (via PSL), or fqdn, or test.com.
        User -d is used as-is. Domain from server: FQDN is resolved to registrable domain via Public Suffix List
        (e.g. relay01.prod.amazon.co.jp -> amazon.co.jp); fallback to full hostname or _to_parent_domain if PSL fails.
        """
        return self._resolve_rcpt_limit_domain()[0]

    def _rcpt_limit_section_title(self) -> str:
        if _rcpt_limit_send_mode(self.args):
            return "RCPT TO limit (send)"
        return "RCPT TO limit"

    # ------------------------------------------------------------------
    # RCPT TO limit pre-check: role identification, open-relay verdict,
    # recipient list construction (-U name list), AUTH for submission servers.
    # ------------------------------------------------------------------

    def _rl_pick_first(self, value: object) -> str | None:
        """Pick first non-empty entry from str | list[str] | None."""
        if value is None:
            return None
        if isinstance(value, str):
            v = value.strip()
            return v or None
        if isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str) and item.strip():
                    return item.strip()
        return None

    def _rl_first_creds(self) -> tuple[str | None, str | None]:
        """Return a single (user, password) pair for AUTH LOGIN during -rl on Submission.

        Prefers ``-u/--user`` (first entry) and ``-p/--password``. Falls back to first lines
        of ``-U/--users`` and ``-P/--passwords`` files when single credentials are absent.
        """
        user = self._rl_pick_first(getattr(self.args, "user", None))
        passwd = self._rl_pick_first(getattr(self.args, "password", None))
        if user is None and getattr(self.args, "users", None):
            try:
                lines = [x for x in text_or_file(None, self.args.users) if x.strip()]
                if lines:
                    user = lines[0].strip()
            except Exception:
                pass
        if passwd is None and getattr(self.args, "passwords", None):
            try:
                lines = [x for x in text_or_file(None, self.args.passwords) if x.strip()]
                if lines:
                    passwd = lines[0].strip()
            except Exception:
                pass
        return user, passwd

    def _envelope_mail_from_bracket(self, envelope: str | None = None) -> str:
        """SMTP ``MAIL FROM`` bracket from ``-m`` / explicit envelope, else null sender ``<>``."""
        if envelope is not None:
            addr = str(envelope).strip("<>").strip()
        else:
            raw = (getattr(self.args, "mail_from", None) or "").strip()
            addr = raw.strip("<>").strip() if raw and "@" in raw else ""
        return f"<{addr}>" if addr else "<>"

    def _rl_send_catch_all_delivery_probe(
        self,
        smtp: smtplib.SMTP,
        domain: str,
        bounce_mailbox: str,
        *,
        emit_debug=None,
    ) -> dict:
        """Submit one minimal message to ``xxxfoofff@domain`` for manual catch-all verification.

        ``bounce_mailbox`` is ``-m`` / envelope MAIL FROM; NDR/bounce on delivery failure is
        routed there per RFC 5321. The analyst checks that mailbox manually. Leaves RSET.
        """
        probe_rcpt = f"{RCPT_LIMIT_ACCEPT_ALL_PROBE_LOCAL}@{domain}"
        mail_from = bounce_mailbox.strip("<>").strip()
        mail_bracket = f"<{mail_from}>"
        probe_uuid = secrets.token_hex(8)

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

        out = {
            "probe_rcpt": probe_rcpt,
            "probe_uuid": probe_uuid,
            "data_ok": False,
            "data_code": None,
            "data_reply": None,
        }

        try:
            smtp.docmd("RSET")
        except Exception:
            pass

        mst, mrp = smtp.docmd("MAIL FROM:", mail_bracket)
        _dbg(
            f"Catch-all bounce probe MAIL FROM:{mail_bracket} → "
            f"[{mst}] {_reply_one_line(mrp)}",
            Out.INFO,
        )
        if mst != 250:
            out["data_reply"] = f"MAIL FROM rejected: [{mst}] {_reply_one_line(mrp)}"
            try:
                smtp.docmd("RSET")
            except Exception:
                pass
            return out

        st, rp = smtp.docmd("RCPT TO:", f"<{probe_rcpt}>")
        _dbg(
            f"Catch-all bounce probe RCPT TO:<{probe_rcpt}> → "
            f"[{st}] {_reply_one_line(rp)}",
            Out.INFO,
        )
        if st not in (250, 251, 252):
            out["data_reply"] = f"RCPT TO rejected: [{st}] {_reply_one_line(rp)}"
            try:
                smtp.docmd("RSET")
            except Exception:
                pass
            return out

        raw_msg = self._outbound_minimal_probe(
            from_addr=mail_from,
            message_id_tag="rl-ca",
            domain=domain,
            probe_uuid=probe_uuid,
            to_addr=probe_rcpt,
        )
        try:
            dcode, drp = smtp.data(raw_msg)
            drep = self.bytes_to_str(drp).strip()[:500]
            out["data_code"] = dcode
            out["data_reply"] = drep
            out["data_ok"] = dcode == 250
            if self.args.debug and not self.use_json:
                self._stream_smtp_trace_line(
                    self._data_trace_entry(raw_msg, dcode, drp),
                )
            else:
                _dbg(
                    f"Catch-all bounce probe DATA → [{dcode}] {_reply_one_line(drep)}",
                    Out.INFO,
                )
        except Exception as e:
            out["data_reply"] = str(e).strip()[:500]
            _dbg(f"Catch-all bounce probe DATA failed: {e}", Out.INFO)
        try:
            smtp.docmd("RSET")
        except Exception:
            pass
        return out

    @staticmethod
    def _format_enum_clock_duration(elapsed: float) -> str:
        """Format a non-negative duration as H:MM:SS (enumeration progress ETA / elapsed)."""
        elapsed = max(0.0, float(elapsed))
        total_sec = int(elapsed)
        h, rem = divmod(total_sec, 3600)
        m, s = divmod(rem, 60)
        return f"{h}:{m:02d}:{s:02d}"

    @staticmethod
    def _format_enum_elapsed(start: float) -> str:
        """Elapsed since start (same format as ``_format_enum_clock_duration``)."""
        return SharedMixin._format_enum_clock_duration(time.time() - start)

    @staticmethod
    def _enum_eta_remaining_seconds(completed: int, total: int, elapsed: float) -> float | None:
        """ETA = remaining_tests * elapsed / completed (RFC-style rolling average)."""
        if total <= 0 or completed <= 0:
            return None
        remaining = total - completed
        if remaining <= 0:
            return 0.0
        return remaining * float(elapsed) / float(completed)

    @staticmethod
    def _raw_write(data: bytes) -> None:
        """Write bytes directly to fd 1 (stdout) via os.write(), bypassing all
        Python I/O layers (TextIOWrapper + BufferedWriter).  On Linux, os.write()
        to a TTY/pty is atomic for writes ≤ PIPE_BUF (4096 bytes) and is safe to
        call from multiple threads simultaneously – each write is serialised by the
        kernel.  Fallback to sys.stdout.buffer if fileno() is unavailable."""
        try:
            os.write(1, data)
        except OSError:
            try:
                fd = sys.stdout.fileno()
                os.write(fd, data)
            except Exception:
                try:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except Exception:
                    pass

    def _enum_clock_paint_unlocked(self) -> None:
        """One progress line per attempt: ETA, N% (vs wordlist / -u size), current label."""
        st = self._enum_clock_state
        if st is None:
            return
        start = getattr(self, "_enum_progress_start", None) or time.time()
        idx = int(st["idx"])
        total = int(st["total"])
        label = str(st["label"])
        elapsed = max(0.0, time.time() - start)
        completed = idx - 1
        pct = min(100, int(100 * completed / total)) if total > 0 else 0
        eta_sec = self._enum_eta_remaining_seconds(completed, total, elapsed)
        time_part = (
            self._format_enum_clock_duration(eta_sec)
            if eta_sec is not None
            else "--:--:--"
        )
        line_core = f"{time_part} {pct}% {label}"
        self._raw_write(f"\033[2K\r{line_core}".encode("utf-8", errors="replace"))
        self._enum_progress_line_dirty = True

    def _enum_clock_ensure_started(self) -> None:
        """Single-thread enum: no background ticker — progress updates only from _enum_wait_begin."""
        return

    def _enum_clock_shutdown(self) -> None:
        """Stop clock thread after EXPN/VRFY/RCPT enumeration block."""
        self._enum_wait_end()
        self._enum_clock_stop.set()
        t = self._enum_clock_thread
        if t is not None:
            if t.is_alive():
                t.join(timeout=2.0)
            self._enum_clock_thread = None
        self._enum_clock_stop = threading.Event()

    def _enum_wait_begin(self, idx: int, total: int, label: str) -> None:
        """Start live clock line for one SMTP check (single-thread only)."""
        if self.use_json:
            return
        if getattr(self.args, "enum_threads", 1) > 1:
            return
        with self._enum_progress_print_lock:
            self._enum_clock_state = {"idx": idx, "total": total, "label": label}
        self._enum_clock_ensure_started()
        with self._enum_progress_print_lock:
            self._enum_clock_paint_unlocked()

    def _enum_pause_clock_for_finding(self) -> None:
        """No-op: clock now runs continuously throughout enumeration.
        Stopped only once at the end via _enum_clock_shutdown()."""

    def _enum_wait_end(self) -> None:
        """No-op: clock runs continuously throughout enumeration.
        State is updated per-user by _enum_wait_begin(); stopped only once
        at the very end by _enum_clock_shutdown()."""

    def _enum_progress_newline(self) -> None:
        if self.use_json:
            return
        # Drop the live ``0:00:00 100% …`` line; use ``\r`` only — trailing ``\n`` would leave a blank row before Catch-all.
        if getattr(self, "_enum_progress_line_dirty", False):
            self._raw_write(b"\033[2K\r")
            self._enum_progress_line_dirty = False

    def _mail_from_candidates_rcpt(self, domain: str) -> tuple[str, ...]:
        """Candidates for MAIL FROM before RCPT probes: ``-m`` when set, then null sender, domain, legacy."""
        candidates: list[str] = []
        explicit = self._envelope_mail_from_bracket()
        if explicit != "<>":
            candidates.append(explicit)
        for c in ("<>", f"<mail@{domain}>", "<mail@from.me>"):
            if c not in candidates:
                candidates.append(c)
        return tuple(candidates)

    def _try_mail_from_for_rcpt_probe(
        self, smtp: smtplib.SMTP, domain: str
    ) -> tuple[bool, str | None]:
        """Establish MAIL transaction for RCPT enumeration / probes.

        Order: remembered ``_rcpt_enum_mail_from_ok`` first (reconnect / rate-limit fast path),
        then ``<>``, ``mail@domain``, ``mail@from.me``. Successful candidate is stored on
        ``self._rcpt_enum_mail_from_ok``. RSET between rejected attempts."""
        standard = self._mail_from_candidates_rcpt(domain)
        cached = getattr(self, "_rcpt_enum_mail_from_ok", None)
        trial_order: list[str] = []
        seen: set[str] = set()
        if cached:
            trial_order.append(cached)
            seen.add(cached)
        for c in standard:
            if c not in seen:
                trial_order.append(c)
                seen.add(c)
        if not trial_order:
            trial_order = list(standard)

        for i, candidate in enumerate(trial_order):
            try:
                status, reply = smtp.docmd("MAIL FROM:", candidate)
                reply_str = self.bytes_to_str(reply)
                if status in self._MAIL_RCPT_TRANSACTION_OK:
                    accept_msg = (
                        f"MAIL FROM {candidate} accepted"
                        + (" (cached preference)" if cached and candidate == cached else "")
                        + f": [{status}] {reply_str.strip()[:400]}"
                    )
                    self.ptdebug(accept_msg, Out.INFO)
                    self._rcpt_enum_mail_from_ok = candidate
                    return True, candidate
                self.ptdebug(
                    f"MAIL FROM {candidate} rejected: [{status}] {reply_str.strip()[:400]}",
                    Out.INFO,
                )
            except Exception as e:
                self.ptdebug(f"MAIL FROM {candidate} error: {e}", Out.INFO)
            if i < len(trial_order) - 1:
                try:
                    smtp.docmd("RSET")
                except Exception:
                    pass
        return False, None

    @classmethod
    def _is_valid_local_part(cls, s: str) -> bool:
        """True if s is a valid email local part (RFC 5322 atext / dot-atom, RFC 6531 Unicode)."""
        if not s or len(s) > 64:
            return False
        if s[0] == "." or s[-1] == "." or ".." in s:
            return False
        for c in s:
            if c in cls._ATEXT_ASCII:
                continue
            if ord(c) < 128:
                return False
            cat = unicodedata.category(c)
            if cat not in ("Ll", "Lu", "Lm", "Lo", "Lt", "Nl", "Nd"):
                return False
        return True

    def _ensure_initial_info(self, *, fail_label: str = "test") -> None:
        """Populate ``self.results.info`` via a transient ``initial_info()`` call so
        that ``-vv`` mode reliably shows the **Initial server information** header
        (banner + EHLO response) for any standalone test that does not already
        run inside the run-all/initial_info flow.

        - No-op if ``self.results.info`` is already populated (run-all mode or a
          previous test in the same invocation has cached it).
        - Closes the info handler immediately; the calling test opens its own
          fresh connection. Mirrors the pattern used by ``-rl`` (see
          :py:meth:`test_rcpt_limit`) so output is consistent across
          ``-rl`` / ``-ts NOOP1`` / ``-nf2`` etc.
        """
        if getattr(self.results, "info", None):
            return
        try:
            _info_smtp, _info = self.initial_info(get_commands=True)
            self.results.info = InfoResult(
                _info.banner,
                _info.ehlo,
                getattr(_info, "ehlo_starttls", None),
            )
            self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
            self.results.banner_requested = False
            self.results.commands_requested = False
            try:
                _info_smtp.quit()
            except Exception:
                try:
                    _info_smtp.close()
                except Exception:
                    pass
        except Exception as e:
            self.ptdebug(f"Initial info failed before {fail_label}: {e}", Out.INFO)

    def initial_info(self, get_commands: bool = True) -> tuple[smtplib.SMTP, InfoResult]:
        """Connect and get banner; optionally get EHLO (commands). If PLAIN advertises STARTTLS,
        open a new connection to get EHLO after STARTTLS (keeps main connection plain for other tests)."""
        self.ptdebug("Initial server information", title=True)

        smtp, status, reply = self.connect()
        if status != 220:
            msg = f"SMTP Info - [{status}] {self.bytes_to_str(reply)}"
            if self.use_json:
                self.ptjsonlib.end_error(msg, self.use_json)
            raise Exception(msg)
        banner = reply.decode()
        self.ptdebug("Banner: " + banner, Out.INFO)

        ehlo = None
        ehlo_starttls = None
        if get_commands:
            try:
                _, ehlo_bytes = smtp.ehlo(self.fqdn)
                ehlo = ehlo_bytes.decode()
                self.ptdebug("EHLO response: " + ehlo, Out.INFO)
            except Exception as e:
                msg = (
                    f"Could not negotiate initial EHLO with "
                    f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
                )
                self._fail(msg)

            # If on plain connection and server advertises STARTTLS, get EHLO after STARTTLS
            # via a new connection (same manual STARTTLS as test_encryption: no SNI when IP).
            if (
                ehlo
                and "STARTTLS" in ehlo.upper()
                and self.args.target.port != 465
                and not self.args.tls
            ):
                smtp_stls = None
                try:
                    _ssl_ctx = ssl._create_unverified_context()
                    smtp_stls = smtplib.SMTP(timeout=15.0)
                    status, _ = smtp_stls.connect(self.args.target.ip, self.args.target.port)
                    if status != 220:
                        raise Exception("connect failed")
                    status, _ = smtp_stls.docmd("EHLO", self.fqdn)
                    if status != 250:
                        raise Exception("EHLO failed")
                    status, _ = smtp_stls.docmd("STARTTLS")
                    if status != 220:
                        raise Exception("STARTTLS refused")
                    try:
                        _is_ip = ipaddress.ip_address(self.args.target.ip)
                        _sni = None
                    except ValueError:
                        _sni = self.args.target.ip
                    sock_ssl = _ssl_ctx.wrap_socket(smtp_stls.sock, server_hostname=_sni)
                    smtp_stls.sock = sock_ssl
                    smtp_stls.file = None
                    smtp_stls.helo_resp = None
                    smtp_stls.ehlo_resp = None
                    smtp_stls.esmtp_features = {}
                    smtp_stls.does_esmtp = False
                    status, ehlo_st_bytes = smtp_stls.docmd("EHLO", self.fqdn)
                    if status == 250:
                        ehlo_starttls = ehlo_st_bytes.decode()
                        self.ptdebug("EHLO after STARTTLS: " + ehlo_starttls, Out.INFO)
                except Exception as e:
                    self.ptdebug(f"STARTTLS EHLO failed: {e}", Out.INFO)
                finally:
                    if smtp_stls is not None:
                        try:
                            smtp_stls.close()
                        except Exception:
                            pass

        return smtp, InfoResult(banner, ehlo, ehlo_starttls)

    def _try_login(self, creds: Creds) -> Creds | None:
        smtp, *_ = self.connect()

        try:
            smtp.login(creds.user, creds.passw)
            result = creds
        except:
            result = None
        finally:
            smtp.close()
            return result

    # endregion

    # region streaming (real-time terminal output during run)

    def _get_domain_from_banner_or_ptr(self, info: InfoResult | None) -> str | None:
        """Extract hostname from banner/EHLO or PTR lookup. Returns None on failure."""
        if info:
            # From banner (220 hostname or tokens)
            if info.banner:
                # First: extract domain from angle brackets (e.g. <xxx@domain>)
                for match in re.finditer(r"<[^>]*@([^>]+)>", info.banner):
                    domain = match.group(1).strip().rstrip(".")
                    if _is_valid_hostname(domain):
                        return domain
                # Fallback: space-separated tokens (skip tokens ending with "." like "ready.")
                for token in info.banner.replace(",", " ").replace("(", " ").replace(")", " ").split():
                    token = token.strip().rstrip(".")
                    if token and _is_valid_hostname(token):
                        return token
            # From EHLO first line (250 hostname)
            if info.ehlo:
                for line in (info.ehlo or "").replace("\r\n", "\n").split("\n"):
                    line = line.strip()
                    if line.startswith("250-") or line.startswith("250 "):
                        rest = line[4:].strip() if line.startswith("250-") else line[3:].strip()
                        if rest:
                            first = rest.split()[0]
                            if _is_valid_hostname(first):
                                return first
        try:
            ptr_host = socket.gethostbyaddr(self.target_ip)[0]
            if ptr_host and _is_valid_hostname(ptr_host):
                return ptr_host
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            pass
        return None

    @staticmethod
    def _identify_probe_snippet(text: str, max_len: int = 120) -> str:
        one = text.replace("\r\n", " ").replace("\n", " ").strip()
        if len(one) > max_len:
            return one[: max_len - 3] + "..."
        return one

    def _stream_identify_probe_evidence(self, r: ServerIdentifyResult) -> None:
        """HELP / RCPT error / unknown-command samples collected during -id."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if not show:
            return
        has_help = bool(r.help_response and r.help_response.strip())
        has_errors = bool(r.error_syntax_samples)
        has_unk = bool(r.unknown_cmd_response and r.unknown_cmd_response.strip())
        if not (has_help or has_errors or has_unk):
            return
        scored_methods = {s.method for s in (r.scoring_matrix or [])}
        pp("Protocol probe evidence", bullet_type="TITLE", condition=show, indent=4)
        verbose = self.args.debug
        if has_help:
            help_snip = self._identify_probe_snippet(r.help_response or "")
            pp(
                f"HELP: {help_snip}",
                bullet_type="TITLE" if "help" in scored_methods else "TEXT",
                condition=show, indent=8,
            )
            if verbose and r.help_response and len((r.help_response or "").strip()) > len(help_snip):
                for line in (r.help_response or "").replace("\r", "").splitlines()[:10]:
                    ln = line.strip()
                    if ln:
                        pp(ln, bullet_type="TEXT", condition=show, indent=12)
        for i, sample in enumerate(r.error_syntax_samples or []):
            if not (sample or "").strip():
                continue
            label = "RCPT error" if i == 0 else f"Error sample {i + 1}"
            snip = self._identify_probe_snippet(sample)
            pp(
                f"{label}: {snip}",
                bullet_type="TITLE" if "error_syntax" in scored_methods else "TEXT",
                condition=show, indent=8,
            )
            if verbose and len(sample.strip()) > len(snip):
                for line in sample.replace("\r", "").splitlines()[:6]:
                    ln = line.strip()
                    if ln:
                        pp(ln, bullet_type="TEXT", condition=show, indent=12)
        if has_unk:
            snip = self._identify_probe_snippet(r.unknown_cmd_response or "")
            pp(
                f"Unknown command: {snip}",
                bullet_type="TITLE" if "behavioral_unknown_cmd" in scored_methods else "TEXT",
                condition=show, indent=8,
            )

    def _stream_identify_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.identify_error) is not None:
            pp(f"Server identification failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        r = self.results.identify
        if r is None:
            return
        if not show:
            return
        banner_display = (r.banner or "").replace("\r", "").strip()
        if r.hidden_banner and banner_display:
            pp(f"Banner: {banner_display} (Hidden)", bullet_type="TITLE", condition=show, indent=4)
        elif r.banner:
            pp(f"Banner: {banner_display}", bullet_type="TITLE", condition=show, indent=4)
        if r.hidden_banner or not r.scoring_matrix:
            pp("Analyzing behavioral patterns...", bullet_type="TITLE", condition=show, indent=4)
        self._stream_identify_probe_evidence(r)
        # Behavioral Analysis section (v1.0.5) - Evidence-based: show matched/missing verbs
        if getattr(r, "behavioral_profile_product", None) or getattr(r, "behavioral_profile_detail", None) or getattr(r, "behavioral_discrepancies", None) or getattr(r, "latency_avg_ms", None) is not None or getattr(r, "cert_software_context", None):
            pp("Behavioral Analysis", bullet_type="TITLE", condition=show, indent=4)
            if getattr(r, "behavioral_profile_product", None) and getattr(r, "behavioral_profile_sim", 0) > 0:
                pp(
                    f"EHLO profile: {r.behavioral_profile_sim}% match "
                    f"'{r.behavioral_profile_product}' "
                    f"{f'({r.behavioral_profile_detail})' if getattr(r, 'behavioral_profile_detail', None) else ''}",
                    bullet_type="TITLE", condition=show, indent=8,
                )
                # Evidence-based: matched and missing verbs
                matched = getattr(r, "behavioral_matched_verbs", None) or ()
                missing = getattr(r, "behavioral_missing_verbs", None) or ()
                product_name = r.behavioral_profile_product or ""
                signature_label = (
                    f" ({product_name} signature)" if product_name.strip() else " (EHLO profile match)"
                )
                if matched:
                    pp(f"Matched verbs: {', '.join(matched)}{signature_label}", bullet_type="TITLE", condition=show, indent=8)
                if missing:
                    parts = []
                    for v in missing:
                        # Case-insensitive lookup: verbs normalized to uppercase (server may return "auth" vs "AUTH")
                        hint = PROFILE_MISSING_HINTS.get((product_name, (v or "").upper()))
                        parts.append(f"{v} ({hint})" if hint else v)
                    pp(f"Missing verbs: {', '.join(parts)}", bullet_type="TITLE", condition=show, indent=8)
            if getattr(r, "latency_avg_ms", None) is not None:
                jitter = getattr(r, "latency_jitter_ms", None)
                jitter_str = f", jitter {jitter:.0f} ms" if jitter is not None and jitter > 0 else ""
                proxy_hint = " (possible proxy/filter)" if jitter and jitter > 50 else " (direct MTA)"
                pp(f"Latency: avg {r.latency_avg_ms:.0f} ms{jitter_str}{proxy_hint}",
                   bullet_type="TITLE", condition=show, indent=8)
            if getattr(r, "cert_software_context", None):
                pp(f"TLS cert context: {r.cert_software_context}", bullet_type="TEXT", condition=show, indent=8)
            for d in getattr(r, "behavioral_discrepancies", None) or []:
                pp(d, bullet_type="WARNING", condition=show, indent=8)
        has_tls_cert = bool(
            r.tls_cert_subject or r.tls_cert_issuer or (r.tls_cert_san and r.tls_cert_san)
        )
        pp("TLS Certificate Info:", bullet_type="TITLE", condition=show, indent=4)
        if has_tls_cert:
            if r.tls_cert_subject:
                pp(f"Subject: {r.tls_cert_subject}", bullet_type="TITLE", condition=show, indent=8)
            if r.tls_cert_san:
                pp(f"SAN: {', '.join(r.tls_cert_san)}", bullet_type="TITLE", condition=show, indent=8)
            if r.tls_cert_issuer:
                pp(f"Issuer: {r.tls_cert_issuer}", bullet_type="TITLE", condition=show, indent=8)
            if r.tls_cert_self_signed:
                pp("Self-signed: yes", bullet_type="VULN", condition=show, indent=8)
            else:
                pp("Self-signed: no", bullet_type="NOTVULN", condition=show, indent=8)
            mx_msg = getattr(r, "mx_cert_message", None)
            mx_st = getattr(r, "mx_cert_ok", None)
            if mx_msg:
                if mx_st is True:
                    pp(mx_msg, bullet_type="NOTVULN", condition=show, indent=8)
                elif mx_st is False:
                    pp(mx_msg, bullet_type="WARNING", condition=show, indent=8)
                else:
                    pp(mx_msg, bullet_type="TITLE", condition=show, indent=8)
            if getattr(r, "tls_policy", None) and r.tls_policy != "n/a":
                pp(f"TLS policy: {r.tls_policy}", bullet_type="TEXT", condition=show, indent=8)
            if getattr(r, "tls_downgrade_probed", False):
                downgrade = getattr(r, "tls_downgrade_findings", None) or []
                if downgrade:
                    for w in downgrade:
                        pp(f"TLS downgrade: {w}", bullet_type="WARNING", condition=show, indent=8)
                else:
                    pp("TLS downgrade: TLS 1.0/1.1 rejected (Good)", bullet_type="NOTVULN", condition=show, indent=8)
            if getattr(r, "cert_domain_match", False):
                pp("Cert domain match: SAN aligns with target", bullet_type="NOTVULN", condition=show, indent=8)
            elif has_tls_cert and (r.tls_cert_subject or (r.tls_cert_san and len(r.tls_cert_san) > 0)):
                pp("Cert domain match: no clear SAN/Subject tie to connection target",
                   bullet_type="TITLE", condition=show, indent=8)
            for w in getattr(r, "tls_cert_warnings", None) or []:
                pp(w, bullet_type="WARNING", condition=show, indent=8)
            for w in getattr(r, "tls_cipher_warnings", None) or []:
                pp(w, bullet_type="WARNING", condition=show, indent=8)
            if getattr(r, "os_hint", None):
                pp(f"OS hint: {r.os_hint}", bullet_type="TITLE", condition=show, indent=8)
        else:
            transport_tls = getattr(r, "transport_tls", False)
            starttls_adv = getattr(r, "starttls_advertised", False)
            tls_up_fail = getattr(r, "tls_upgrade_failed", False)
            dbg_tail = (
                f"; {r.tls_upgrade_error}"
                if self.args.debug and getattr(r, "tls_upgrade_error", None)
                else "; try -vv or --verbose"
            )
            if tls_up_fail:
                msg = (
                    "TLS certificate could not be extracted (STARTTLS upgrade or cert parse failed"
                    + dbg_tail
                    + ")"
                )
                pp(msg, bullet_type="VULN", condition=show, indent=8)
            elif transport_tls:
                msg = (
                    "TLS certificate could not be extracted (TLS session; cert parse failed"
                    + dbg_tail
                    + ")"
                )
                pp(msg, bullet_type="VULN", condition=show, indent=8)
            elif starttls_adv:
                pp("TLS certificate could not be extracted", bullet_type="VULN", condition=show, indent=8)
            else:
                pp("STARTTLS not advertised", bullet_type="VULN", condition=show, indent=8)
            if getattr(r, "tls_downgrade_probed", False):
                downgrade = getattr(r, "tls_downgrade_findings", None) or []
                if downgrade:
                    for w in downgrade:
                        pp(f"TLS downgrade: {w}", bullet_type="WARNING", condition=show, indent=8)
                else:
                    pp("TLS downgrade: TLS 1.0/1.1 rejected (Good)", bullet_type="NOTVULN", condition=show, indent=8)
            if getattr(r, "os_hint", None):
                pp(f"OS hint: {r.os_hint}", bullet_type="TITLE", condition=show, indent=8)
        if r.scoring_matrix:
            pp("Scoring Matrix", bullet_type="TITLE", condition=show, indent=4)
            for s in r.scoring_matrix:
                pts_fmt = f"{s.points:+d}%"
                pp(f"{s.method}: {pts_fmt} {f'({s.detail})' if s.detail else ''}",
                   bullet_type="TITLE", condition=show, indent=8)
        pp("Identification Result", bullet_type="TITLE", condition=show, indent=4)
        pp(f"Product:     {r.product or 'Unknown'}", bullet_type="TEXT", condition=show, indent=8)
        _bh = getattr(r, "behavioral_hint", None)
        if _bh and not str(_bh).rstrip().endswith("(0%)"):
            pp(f"Behavioral hint: {_bh}", bullet_type="TEXT", condition=show, indent=8)
        pp(f"Version:     {r.version or '—'}", bullet_type="TEXT", condition=show, indent=8)
        pp(f"Confidence: {r.confidence_pct}% ({r.confidence_label})", bullet_type="TEXT", condition=show, indent=8)
        if r.cpe:
            pp(f"CPE:        {r.cpe}", bullet_type="TEXT", condition=show, indent=8)
        if getattr(r, "discrepancy_detected", False) and getattr(
            r, "discrepancy_banner_product", None
        ) and getattr(r, "discrepancy_behavior_product", None):
            pp(
                f"Discrepancy: Banner claims '{r.discrepancy_banner_product}', "
                f"behavior matches '{r.discrepancy_behavior_product}'",
                bullet_type="TITLE", condition=show, indent=8,
            )
        elif r.anomalous_identity:
            pp(
                f"Discrepancy: Banner claims '{r.banner_claims}', "
                f"behavior matches '{r.behavior_matches}'",
                bullet_type="TITLE", condition=show, indent=8,
            )
        if r.integrity_note:
            pp(f"Integrity: {r.integrity_note}", bullet_type="TITLE", condition=show, indent=8)
        if r.recommendation:
            pp(f"Recommendation: {r.recommendation}", bullet_type="TITLE", condition=show, indent=8)
        leaks = getattr(r, "data_leakage_findings", None) or ()
        if leaks:
            pp("Data Leakage / Privacy", bullet_type="INFO", condition=show, indent=4)
            for leak in leaks:
                src = ", ".join(leak.sources)
                _lk = getattr(leak, "kind", "email")
                if _lk == "internal_hostname":
                    if leak.risk == "high":
                        pp(
                            "Information exposure: Internal infrastructure naming leaked in "
                            "TLS Certificate (Non-routable domain).",
                            bullet_type="WARNING", condition=show, indent=8,
                        )
                        pp(f"Extracted: {leak.email} [High Risk]", bullet_type="WARNING", condition=show, indent=8)
                    else:
                        pp(
                            "Information exposure: Internal infrastructure naming leaked in "
                            "TLS Certificate (Non-routable domain).",
                            bullet_type="WARNING", condition=show, indent=8,
                        )
                        pp(f"Extracted: {leak.email} [Medium Risk]", bullet_type="WARNING", condition=show, indent=8)
                    continue
                if leak.risk == "high":
                    pp(
                        f"Sensitive info: E-mail address found in {src} "
                        f"(domain aligns with scan target).",
                        bullet_type="WARNING", condition=show, indent=8,
                    )
                    pp(f"Extracted: {leak.email} [High Risk]", bullet_type="WARNING", condition=show, indent=8)
                elif leak.risk == "medium":
                    pp(
                        f"Information exposure: Routable address in {src} "
                        f"(domain does not match scan target).",
                        bullet_type="WARNING", condition=show, indent=8,
                    )
                    pp(f"Extracted: {leak.email} [Medium Risk]", bullet_type="WARNING", condition=show, indent=8)
                else:
                    pp(
                        f"Information exposure: Generic, noreply, or non-routable "
                        f"contact in {src}.",
                        bullet_type="TITLE", condition=show, indent=8,
                    )
                    pp(f"Extracted: {leak.email} [Low Risk]", bullet_type="TITLE", condition=show, indent=8)
            email_leaks = [x for x in leaks if getattr(x, "kind", "email") == "email"]
            if email_leaks:
                if any(x.risk == "high" for x in email_leaks):
                    pp(
                        f"Risk: Address domain matches the scanned host — strong signal for "
                        f"organizational exposure; targeted phishing or brute-force against admin mailboxes is more "
                        f"credible.",
                        bullet_type="TITLE", condition=show, indent=8,
                    )
                elif any(x.risk == "medium" for x in email_leaks):
                    pp(
                        f"Risk: Routable address leaked but not aligned with scan target — "
                        f"still information exposure (e.g. vendor or third-party identity in cert).",
                        bullet_type="TITLE", condition=show, indent=8,
                    )
                else:
                    pp(
                        f"Risk: Little direct phishing value for noreply / @localhost / "
                        f"reserved domains, but may still indicate default or placeholder TLS/DN setup.",
                        bullet_type="TITLE", condition=show, indent=8,
                    )
            if any(
                getattr(x, "kind", "email") == "internal_hostname" and x.risk in ("medium", "high")
                for x in leaks
            ):
                pp(
                    f"Risk: Exposure of internal hostnames aids in network reconnaissance "
                    f"and targeted internal attacks.",
                    bullet_type="TITLE", condition=show, indent=8,
                )

    @staticmethod
    def _mail_probe_bullet_msg(
        accepted: bool,
        *,
        indeterminate: bool = False,
        detail: str | None = None,
        sent_msg: str,
    ) -> tuple[str, str]:
        """Return (bullet_type, message) for manual-follow-up mail probes (same semantics as -br)."""
        if accepted:
            return "NOTVULN", sent_msg
        if indeterminate:
            det = self._smtp_detail_one_line(detail) or detail or "Could not complete"
            return "TITLE", f"Indeterminate: {det}"
        msg = (detail or "could not complete").replace("NOT VULNERABLE: ", "")
        msg = SharedMixin._smtp_detail_one_line(msg) or msg
        return "WARNING", f"Mail could not be sent: {msg}"

    @staticmethod
    def _smtp_detail_one_line(text: str | None) -> str | None:
        """Collapse multi-line SMTP / error text to a single terminal line."""
        if text is None:
            return None
        s = str(text).strip()
        if not s:
            return text
        return " ".join(s.replace("\r\n", " ").replace("\n", " ").split())

    def _smtp_reply_text_one_line(self, reply) -> str:
        """Readable SMTP reply body on one line (no status code prefix)."""
        if reply is None:
            return ""
        if isinstance(reply, (bytes, bytearray)):
            text = self.bytes_to_str(reply)
        else:
            text = str(reply)
        return " ".join(text.strip().replace("\r\n", " ").replace("\n", " ").split())

    def _smtp_trace_reply(self, status: int, reply) -> str:
        text = self._smtp_reply_text_one_line(reply)
        return f"{status} {text}" if text else str(status)

    def _readable_payload_lines(
        self,
        raw_payload: str,
        *,
        max_body_lines: int = 40,
        max_line: int = 120,
    ) -> list[str]:
        """Display lines for a sent DATA payload (-vv).

        Headers are shown as sent. A base64 text body is decoded and shown readable
        (with a note that it is base64 on the wire); a binary/large base64 body is
        summarised instead of dumped; other bodies are shown with sane length caps.
        """
        if not raw_payload:
            return []
        text = raw_payload.replace("\r\n", "\n").replace("\r", "\n")
        head, _sep, body = text.partition("\n\n")
        header_lines = [h for h in head.split("\n") if h.strip() != ""]
        out: list[str] = list(header_lines)
        body = body.strip("\n")
        if not body:
            return out
        is_b64 = any(
            h.lower().startswith("content-transfer-encoding:") and "base64" in h.lower()
            for h in header_lines
        )
        out.append("")
        if is_b64:
            try:
                decoded = base64.b64decode(body).decode("utf-8")
                printable = sum(1 for c in decoded if c.isprintable() or c in "\n\t")
                if "\x00" not in decoded and len(decoded) <= 4000 and (
                    not decoded or printable / len(decoded) > 0.9
                ):
                    out.extend(decoded.replace("\r\n", "\n").rstrip("\n").split("\n"))
                    out.append("(note: body is base64-encoded on the wire; shown decoded)")
                    return out
            except Exception:
                pass
            out.append(f"<base64 body: {len(body)} chars on the wire; not shown (binary/large)>")
            return out
        body_lines = body.split("\n")
        for idx, bl in enumerate(body_lines):
            if idx >= max_body_lines:
                out.append(f"... ({len(body_lines) - idx} more line(s))")
                break
            out.append(bl if len(bl) <= max_line else f"{bl[:max_line]}…(+{len(bl) - max_line} chars)")
        return out

    def _data_trace_entry(
        self,
        raw_payload: str,
        data_status=None,
        data_reply=None,
        *,
        reply: str | None = None,
    ) -> str:
        """Trace entry for a DATA step: ``DATA:`` header, readable payload, then server reply.

        Stored as one multiline string in ``smtp_trace``; rendered under -vv via
        :py:meth:`_stream_smtp_trace_line`.
        """
        if reply is None:
            reply = self._smtp_trace_reply(data_status, data_reply)
        lines = ["DATA:"]
        for pl in self._readable_payload_lines(raw_payload):
            lines.append(f"    {pl}")
        if reply:
            lines.append(reply)
        return "\n".join(lines)

    @staticmethod
    def _data_trace_status_code(entry: str) -> str | None:
        """Extract SMTP status code from a ``_data_trace_entry`` (single- or multi-line)."""
        if not entry.startswith("DATA:"):
            return None
        trace_lines = entry.splitlines()
        if len(trace_lines) == 1:
            tail = entry.split(":", 1)[1].strip()
            return tail.split()[0] if tail else None
        for line in reversed(trace_lines):
            s = line.strip()
            if s and s[0].isdigit():
                return s.split()[0]
        return None

    def _stream_smtp_trace_line(
        self,
        line: str,
        *,
        indent_override: int = 4,
    ) -> None:
        """Print one SMTP trace entry under -vv (supports multiline DATA payloads)."""
        if self.use_json or not self.args.debug:
            return
        if line.startswith("---") and line.endswith("---"):
            self.ptdebug(line.strip("- ").strip(), title=True)
            return
        self.ptdebug(line, indent_override=indent_override)

    def _mail_test_trace_append(self, trace: list[str], line: str) -> None:
        """Store SMTP trace line; with -vv print live via :py:meth:`_stream_smtp_trace_line`."""
        trace.append(line)
        self._stream_smtp_trace_line(line)

    def _mail_test_auth_login(
        self,
        smtp,
        trace: list[str],
        *,
        trace_append: Callable[[str], None] | None = None,
    ) -> tuple[bool, str | None]:
        """AUTH LOGIN when ``-u``/``-p`` or first line of ``-U``/``-P`` is set (Submission / port 587).

        Returns ``(auth_used, error_detail)``. ``auth_used`` is True on success; ``error_detail`` is set
        when credentials were provided but login failed; both are false/None when no creds were given.
        """
        user, passwd = self._rl_first_creds()
        if not user or not passwd:
            return False, None

        def _append(line: str) -> None:
            if trace_append is not None:
                trace_append(line)
            else:
                self._mail_test_trace_append(trace, line)

        try:
            smtp.login(user, passwd)
            _append(f"AUTH LOGIN: OK ({user})")
            return True, None
        except smtplib.SMTPAuthenticationError as e:
            _append(f"AUTH LOGIN: failed ({e})")
            return False, f"AUTH LOGIN failed for {user}: {e}"
        except (socket.timeout, smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
            _append(f"AUTH LOGIN: error ({e})")
            return False, f"AUTH LOGIN error for {user}: {e}"

    def _mail_test_live_done(self, label: str, detail: str) -> None:
        """Per-variant/category progress line during test when -vv (same as -av)."""
        if not self.use_json and self.args.debug:
            one_line = self._smtp_detail_one_line(detail) or detail
            ptprinthelper.ptprint(
                f"{label}: {one_line}",
                bullet_type="TITLE",
                condition=True,
                indent=4,
            )

    def _mail_test_stream_probe_verdict(
        self,
        *,
        accepted: bool,
        indeterminate: bool = False,
        detail: str | None = None,
        sent_msg: str,
        follow_up: tuple[str, ...] = (),
    ) -> None:
        """Live [✓]/[!] mail verdict during -vv (same lines as non-debug streamer)."""
        if self.use_json or not self.args.debug:
            return
        self._pp_mail_probe_line(
            ptprinthelper.ptprint,
            True,
            accepted=accepted,
            indeterminate=indeterminate,
            detail=detail,
            sent_msg=sent_msg,
            follow_up=follow_up,
        )

    def _stream_bounce_replay_trace_line(self, line: str) -> None:
        """-vv SMTP trace for -br replay in streamer (ADDITIONS, same as live)."""
        self._br_stream_trace_line(line)

    def _pp_av_variant_row(
        self,
        pp,
        show: bool,
        label: str,
        detail: str | None,
        *,
        sub_lines: tuple[str, ...] = (),
    ) -> None:
        """One variant/category row in terminal stream without -vv (same layout as -av)."""
        pp(f"{label}: {detail or ''}", bullet_type="TITLE", condition=show, indent=4)
        for line in sub_lines:
            pp(line, bullet_type="TEXT", condition=show, indent=8)

    def _pp_mail_probe_line(
        self,
        pp,
        show: bool,
        *,
        accepted: bool,
        indeterminate: bool = False,
        detail: str | None = None,
        sent_msg: str,
        indent: int = 4,
        follow_up: tuple[str, ...] = (),
    ) -> None:
        """Mail send result line — NOTVULN [✓] or WARNING [!], same semantics as -br."""
        bt, msg = self._mail_probe_bullet_msg(
            accepted,
            indeterminate=indeterminate,
            detail=detail,
            sent_msg=sent_msg,
        )
        pp(msg, bullet_type=bt, condition=show, indent=indent)
        if accepted:
            for line in follow_up:
                stripped = line.strip()
                if stripped:
                    pp(stripped, bullet_type="TEXT", condition=show, indent=indent + 4)

    def _pp_mail_variant_probe_sections(
        self,
        pp,
        show: bool,
        *,
        debug: bool,
        rows: tuple[
            tuple[
                str,
                str | None,
                bool,
                bool,
                str | None,
                str,
                tuple[str, ...],
                tuple[str, ...],
                tuple[str, ...],
            ],
            ...,
        ],
    ) -> None:
        """Variant row + optional mail probe bullet (AV layout + -br verdict).

        With -vv, SMTP trace is streamed live during test (_mail_test_trace_append).
        Mail probe verdict lines are streamed live from test_* when supported; otherwise
        printed here (non-debug, or tests that do not stream per-variant verdicts).
        """
        for (
            label,
            detail,
            accepted,
            indet,
            probe_detail,
            sent_msg,
            follow_up,
            smtp_trace,
            msg_summary,
        ) in rows:
            if not debug:
                self._pp_av_variant_row(pp, show, label, detail, sub_lines=msg_summary)
                self._pp_mail_probe_line(
                    pp,
                    show,
                    accepted=accepted,
                    indeterminate=indet,
                    detail=probe_detail,
                    sent_msg=sent_msg,
                    follow_up=follow_up,
                )

    def _pp_av_summary_block(
        self,
        pp,
        *,
        show: bool,
        detail: str | None,
        elapsed_sec: float,
        extra_lines: tuple[str, ...] = (),
        verdict: tuple[str, str] | None = None,
        mail_probe: tuple[bool, bool, str | None, str, tuple[str, ...]] | None = None,
    ) -> None:
        """Summary footer shared by -av-style streamers."""
        pp("Summary", bullet_type="TITLE", condition=show, indent=4)
        if detail:
            pp(detail, bullet_type="TEXT", condition=show, indent=8)
        for line in extra_lines:
            stripped = line.strip()
            if stripped:
                pp(stripped, bullet_type="TEXT", condition=show, indent=8)
        pp(f"Elapsed: {elapsed_sec:.1f} s", bullet_type="TEXT", condition=show, indent=8)
        if mail_probe is not None:
            accepted, indet, probe_detail, sent_msg, follow_up = mail_probe
            self._pp_mail_probe_line(
                pp,
                show,
                accepted=accepted,
                indeterminate=indet,
                detail=probe_detail,
                sent_msg=sent_msg,
                follow_up=follow_up,
            )
        if verdict is not None:
            bt, text = verdict
            pp(text, bullet_type=bt, condition=show, indent=4)

    def _stream_bounce_replay_result(self) -> None:
        # Terminal-only rendering via the shared bullet system (ptprinthelper + ptdefs):
        # ``condition`` suppresses output in JSON mode, ``bullet_type`` picks the icon.
        pp = ptprinthelper.ptprint
        show = not self.use_json                       # finding/result lines

        if (err := self.results.bounce_replay_error) is not None:
            pp(f"Bounce replay test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        br = self.results.bounce_replay
        if br is None or not show:
            return

        # With -vv, probe sections (debug trace + verdict) are streamed live from test_bounce_replay().
        if self.args.debug and getattr(self, "_bounce_replay_streamed_live", False):
            return

        def _probe_bullet_msg(accepted: bool, indet: bool, detail: str | None, test_id: str) -> tuple[str, str]:
            return self._mail_probe_bullet_msg(
                accepted,
                indeterminate=indet,
                detail=detail,
                sent_msg=self._mail_sent_inbox_msg(br.bounce_addr, test_id),
            )

        def _split_trace(trace: tuple[str, ...]):
            """Split smtp_trace into pre-probe lines, Probe 1 label/lines, Probe 2 label/lines."""
            pre: list[str] = []
            p1: list[str] = []
            p2: list[str] = []
            p1_label = ""
            p2_label = ""
            cur = pre
            for line in trace:
                if line.startswith("---"):
                    if cur is pre:
                        p1_label = line.strip("- ").strip()
                        cur = p1
                    else:
                        p2_label = line.strip("- ").strip()
                        cur = p2
                else:
                    cur.append(line)
            return pre, p1_label, p1, p2_label, p2

        pre_lines, p1_label, p1_lines, p2_label, p2_lines = _split_trace(br.smtp_trace)
        has_probe1 = bool(p1_label or p1_lines)
        has_probe2 = bool(p2_label or p2_lines)

        def _emit_trace(line: str) -> None:
            if self.args.debug:
                self._stream_bounce_replay_trace_line(line)

        # Pre-probe failure or missing args (no probe sections in trace)
        if not has_probe1:
            for line in pre_lines:
                _emit_trace(line)
            bt, msg = _probe_bullet_msg(False, br.indeterminate, br.detail, br.test_id)
            pp(msg, bullet_type=bt, condition=show, indent=4)
            return

        # --- Probe 1: From header without Return-Path ---
        pp("Test From header without Return-Path", bullet_type="TITLE", condition=show, indent=4)
        for line in pre_lines:
            _emit_trace(line)
        if p1_label:
            _emit_trace(f"--- {p1_label} ---")
        for line in p1_lines:
            _emit_trace(line)
        p1_bt, p1_msg = _probe_bullet_msg(
            br.message_accepted, br.probe1_indeterminate, br.probe1_detail, br.test_id
        )
        pp(p1_msg, bullet_type=p1_bt, condition=show, indent=8)

        # Probe 1 was indeterminate → Probe 2 never ran
        if br.probe1_indeterminate and not has_probe2:
            return

        # --- Probe 2: From + Return-Path headers ---
        pp("Test From headers and Return-Path", bullet_type="TITLE", condition=show, indent=4)
        if p2_label:
            _emit_trace(f"--- {p2_label} ---")
        for line in p2_lines:
            _emit_trace(line)
        p2_accepted = getattr(br, "message_accepted_return_path", False)
        p2_bt, p2_msg = _probe_bullet_msg(
            p2_accepted, br.probe2_indeterminate, br.probe2_detail,
            getattr(br, "test_id_return_path", "") or br.test_id,
        )
        pp(p2_msg, bullet_type=p2_bt, condition=show, indent=8)

    def _stream_mail_bomb_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.mail_bomb_error) is not None:
            pp(f"Mail bomb test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        mb = self.results.mail_bomb
        if mb is None or not show:
            return

        extra_lines: list[str] = [
            (
                f"sent={mb.sent} delivered={mb.delivered} rate_limited={mb.rate_limited} "
                f"blocked={mb.blocked}"
            ),
        ]
        if mb.avg_rtt_ms is not None:
            extra_lines.append(f"Avg response time: {mb.avg_rtt_ms:.0f} ms")
        if mb.last_error:
            type_hint = f" [{mb.last_error_type}]" if mb.last_error_type else ""
            extra_lines.append(f"Last connection error{type_hint}: {mb.last_error}")
        if mb.vulnerable:
            extra_lines.append("Server accepted large volume without rate limiting.")

        verdict: tuple[str, str] | None
        if mb.indeterminate:
            verdict = ("WARNING", "Indeterminate")
        elif mb.vulnerable:
            verdict = ("VULN", "VULNERABLE")
        elif mb.partial_protection:
            verdict = ("WARNING", "PARTIAL PROTECTION")
        else:
            verdict = ("NOTVULN", "NOT VULNERABLE")
        self._pp_av_summary_block(
            pp,
            show=show,
            detail=mb.detail,
            elapsed_sec=mb.elapsed_sec,
            extra_lines=tuple(extra_lines),
            verdict=verdict,
        )

    def _stream_antivirus_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.antivirus_error) is not None:
            pp(f"Antivirus test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        av = self.results.antivirus
        if av is None:
            return
        if not show:
            return
        # With -vv, test_antivirus() streams each category live via _av_stream_category_section().
        if not (self.args.debug and getattr(self, "_antivirus_streamed_live", False)):
            rcpt = str(self.args.rcpt_to).strip()
            for cat in av.categories:
                self._av_stream_category_section(cat, rcpt, stream_trace=False)

        if av.indeterminate:
            pp("Summary", bullet_type="TITLE", condition=show, indent=4)
            pp(av.detail or "Could not complete", bullet_type="TEXT", condition=show, indent=8)
            pp(f"Elapsed: {av.elapsed_sec:.1f} s", bullet_type="TEXT", condition=show, indent=8)
            pp("Indeterminate", bullet_type="WARNING", condition=show, indent=4)
        elif av.vulnerable:
            pp("Summary", bullet_type="TITLE", condition=show, indent=4)
            pp(av.detail, bullet_type="TEXT", condition=show, indent=8)
            pp("Risky content was accepted at MTA.", bullet_type="TEXT", condition=show, indent=8)
            pp(f"Elapsed: {av.elapsed_sec:.1f} s", bullet_type="TEXT", condition=show, indent=8)
            pp("VULNERABLE", bullet_type="VULN", condition=show, indent=4)
        elif av.partial_protection:
            pp("Summary", bullet_type="TITLE", condition=show, indent=4)
            pp(av.detail, bullet_type="TEXT", condition=show, indent=8)
            pp(f"Elapsed: {av.elapsed_sec:.1f} s", bullet_type="TEXT", condition=show, indent=8)
            pp("PARTIAL PROTECTION", bullet_type="WARNING", condition=show, indent=4)
        else:
            pp("Summary", bullet_type="TITLE", condition=show, indent=4)
            pp(av.detail, bullet_type="TEXT", condition=show, indent=8)
            pp(f"Elapsed: {av.elapsed_sec:.1f} s", bullet_type="TEXT", condition=show, indent=8)
            pp("NOT VULNERABLE", bullet_type="NOTVULN", condition=show, indent=4)

    def _stream_ssrf_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.ssrf_error) is not None:
            pp(f"SSRF test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        sr = self.results.ssrf
        if sr is None or not show:
            return
        rcpt = str(self.args.rcpt_to).strip()
        if sr.canary_url and not getattr(self, "_ssrf_canary_streamed", False):
            pp("Canary URL", bullet_type="TITLE", condition=show, indent=4)
            pp(sr.canary_url, bullet_type="TEXT", condition=show, indent=8)
        if not (self.args.debug and getattr(self, "_ssrf_streamed_live", False)):
            for v in sr.variants:
                self._ssrf_stream_variant_section(v, rcpt, stream_trace=False)
        mail_sent = any(v.accepted > 0 for v in sr.variants)
        extra = tuple(
            p.strip()
            for p in (sr.verification_instructions or "").split("\n")
            if p.strip()
        ) if mail_sent else ()
        self._pp_av_summary_block(
            pp,
            show=show,
            detail=sr.detail,
            elapsed_sec=sr.elapsed_sec,
            extra_lines=extra,
        )

    def _stream_flood_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.flood_error) is not None:
            pp(f"FLOOD test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        fr = self.results.flood
        if fr is None or not show:
            return
        if not self.args.debug:
            if fr.size_advertised:
                lim = fr.size_limit_bytes
                sz_desc = f"advertised ({lim} B limit)" if lim is not None else "advertised"
            else:
                sz_desc = "not advertised"
            enf = fr.size_enforced
            enf_s = "n/a" if enf is None else ("yes" if enf else "no")
            self._pp_av_variant_row(
                pp,
                show,
                "SIZE",
                f"{sz_desc}; enforced: {enf_s}",
            )
            if fr.queue_attempts > 0:
                self._pp_av_variant_row(
                    pp,
                    show,
                    "queue",
                    (
                        f"attempts={fr.queue_attempts}, delivered={fr.messages_accepted}, "
                        f"data_completed={fr.messages_sent}, failed={fr.messages_rejected}"
                    ),
                )
            elif fr.indeterminate:
                other_lines = [
                    x
                    for x in fr.smtp_trace
                    if not (x.startswith("SIZE_") or x.startswith("QUEUE_"))
                ]
                if other_lines:
                    self._pp_av_variant_row(pp, show, "connection", other_lines[0])

        extra: tuple[str, ...] = ()
        if fr.vulnerable and fr.flood_notes:
            extra = fr.flood_notes
        if fr.tarpitting_detected:
            extra = extra + ("Tarpitting detected (defensive slowdown).",)
        verdict: tuple[str, str] | None
        if fr.indeterminate:
            verdict = ("WARNING", "Indeterminate")
        elif fr.vulnerable:
            verdict = ("VULN", "VULNERABLE")
        elif fr.partial_protection:
            verdict = ("WARNING", "PARTIAL PROTECTION")
        else:
            verdict = ("NOTVULN", "NOT VULNERABLE")
        mail_probe: tuple[bool, bool, str | None, str, tuple[str, ...]] | None = None
        if fr.queue_attempts > 0 and fr.test_id:
            rcpt = str(self.args.rcpt_to).strip()
            mail_probe = (
                fr.messages_accepted > 0,
                fr.indeterminate,
                fr.detail,
                self._mail_sent_inbox_msg(rcpt, fr.test_id),
                (),
            )
        self._pp_av_summary_block(
            pp,
            show=show,
            detail=fr.detail,
            elapsed_sec=fr.elapsed_sec,
            extra_lines=extra,
            verdict=verdict,
            mail_probe=mail_probe,
        )

    def _stream_zipxxe_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.zipxxe_error) is not None:
            pp(f"ZIPXXE test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        zr = self.results.zipxxe
        if zr is None or not show:
            return
        rcpt = str(self.args.rcpt_to).strip()
        if zr.canary_url and not getattr(self, "_zipxxe_canary_streamed", False):
            pp("Canary URL", bullet_type="TITLE", condition=show, indent=4)
            pp(zr.canary_url, bullet_type="TEXT", condition=show, indent=8)
        if not (self.args.debug and getattr(self, "_zipxxe_streamed_live", False)):
            for v in zr.variants:
                self._zipxxe_stream_variant_section(v, rcpt, stream_trace=False)
        mail_sent = any(v.accepted > 0 for v in zr.variants)
        extra: tuple[str, ...] = ()
        if zr.all_rejected_at_rcpt:
            extra = (
                "All variants rejected at RCPT phase — content-level protection could not be assessed.",
            )
        if mail_sent:
            extra = extra + tuple(
                p.strip()
                for p in (zr.verification_instructions or "").split("\n")
                if p.strip()
            )
        self._pp_av_summary_block(
            pp,
            show=show,
            detail=zr.detail,
            elapsed_sec=zr.elapsed_sec,
            extra_lines=extra,
        )

    def _stream_spoof_header_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.spoof_header_error) is not None:
            pp(f"Spoof header test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        sh = self.results.spoof_header
        if sh is None or not show:
            return
        if self.args.debug and getattr(self, "_spoof_header_streamed_live", False):
            return
        rcpt = str(self.args.rcpt_to).strip()
        for v in sh.variants:
            self._sh_stream_variant_section(v, rcpt, stream_trace=False)

    def _stream_bcc_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.bcc_test_error) is not None:
            pp(f"BCC test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        bc = self.results.bcc_test
        if bc is None or not show:
            return
        if not (self.args.debug and getattr(self, "_bcc_streamed_live", False)):
            self._bcc_stream_section(bc, stream_trace=False)
        self._bcc_stream_summary_block(bc)

    def _stream_alias_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.alias_test_error) is not None:
            pp(f"Alias test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        al = self.results.alias_test
        if al is None or not show:
            return
        if not (self.args.debug and getattr(self, "_alias_streamed_live", False)):
            self._al_stream_base_section(
                al.base_address,
                base_mail_sent=al.base_mail_sent,
                base_test_id=al.base_test_id,
                base_smtp_trace=al.base_smtp_trace,
                stream_trace=False,
            )
            for v in al.variants:
                self._al_stream_variant_section(v, al.base_address, stream_trace=False)

        mail_sent = any(self._al_variant_mail_accepted(v) for v in al.variants)
        extra = tuple(
            p.strip()
            for p in (al.verification_instructions or "").split("\n")
            if p.strip()
        ) if mail_sent else ()

        self._pp_av_summary_block(
            pp,
            show=show,
            detail=al.detail,
            elapsed_sec=al.elapsed_sec,
            extra_lines=extra,
        )

    def _stream_rate_limit_result(self) -> None:
        # Per-phase verdicts are emitted inline by the test itself (next to each
        # measured value). This hook only handles the top-level failure case
        # (e.g. nothing could be connected at all).
        if (err := self.results.rate_limit_error) is not None:
            ptprinthelper.ptprint(f"Rate limiting test failed: {err}", bullet_type="VULN",
                                  condition=not self.use_json, indent=4)

    def _stream_noop_flood1_result(self) -> None:
        """Render verdicts for -ts NOOP1 (NOOP Flooding, single connection)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.noop_flood1_error) is not None:
            pp(f"NOOP flood test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return

        r = self.results.noop_flood1
        if r is None:
            return

        # 1) Disconnect behaviour.
        if r.disconnected and r.disconnect_after is not None:
            if r.disconnect_after <= NOOP_FLOOD_DISCONNECT_OK_MAX:
                pp(f"Server disconnect after {r.disconnect_after} NOOP commands",
                   bullet_type="NOTVULN", condition=show, indent=4)
            else:
                pp(
                    f"Server disconnects after {r.disconnect_after} "
                    f"NOOP commands (more than {NOOP_FLOOD_DISCONNECT_OK_MAX} accepted)",
                    bullet_type="VULN", condition=show, indent=4,
                )
        else:
            suffix = " (hit time cap)" if r.hit_time_cap else " (hit command cap)"
            pp(f"No disconnect after {r.commands_sent} NOOP commands{suffix}",
               bullet_type="VULN", condition=show, indent=4)

        # 2) Time-trolling / tarpitting.
        if r.baseline_avg_seconds is not None and r.last_window_avg_seconds is not None:
            min_d = _noop_rt_window_display(r.min_rt_seconds)
            max_d = _noop_rt_window_display(r.max_rt_seconds)
            avg_d = _noop_rt_window_display(r.avg_rt_seconds)
            if r.slowdown_detected:
                pp(f"Time between two commands ({min_d} - {max_d}, avg {avg_d})",
                   bullet_type="NOTVULN", condition=show, indent=4)
                pp(
                    f"Time trolting is configured "
                    f"(baseline {_noop_rt_window_display(r.baseline_avg_seconds)} → "
                    f"last {_noop_rt_window_display(r.last_window_avg_seconds)})",
                    bullet_type="NOTVULN", condition=show, indent=4,
                )
            else:
                pp(f"Time between two commands ({min_d} - {max_d}, avg {avg_d})",
                   bullet_type="NOTVULN", condition=show, indent=4)
                pp("No time trolting is configured", bullet_type="VULN", condition=show, indent=4)
        else:
            pp("No time trolting is configured (not enough samples)",
               bullet_type="VULN", condition=show, indent=4)

        # 3) Error rate.
        err_rate = r.error_rate_pct
        if err_rate <= NOOP_FLOOD_ERROR_RATE_OK_MAX_PCT:
            pp(f"Error rate: {err_rate:.0f}%", bullet_type="NOTVULN", condition=show, indent=4)
        else:
            pp(
                f"Error rate: {err_rate:.0f}% "
                f"(over {NOOP_FLOOD_ERROR_RATE_OK_MAX_PCT:.0f}%)",
                bullet_type="VULN", condition=show, indent=4,
            )

    def _stream_noop_flood2_result(self) -> None:
        """Render verdicts for -nf2 (NOOP Flooding DoS test, parallel connections)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.noop_flood2_error) is not None:
            pp(f"NOOP DoS flood test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return

        r = self.results.noop_flood2
        if r is None:
            return

        # 1) Time between two commands (average reaction time under load).
        if r.avg_rt_seconds is not None:
            min_d = _noop_rt_window_display(r.min_rt_seconds)
            max_d = _noop_rt_window_display(r.max_rt_seconds)
            avg_d = _noop_rt_window_display(r.avg_rt_seconds)
            if r.avg_rt_seconds > NOOP_FLOOD2_AVG_TIME_OK_MAX_SECONDS:
                pp(
                    f"Time between two commands ({min_d} - {max_d}, avg {avg_d}) "
                    f"— over {NOOP_FLOOD2_AVG_TIME_OK_MAX_SECONDS:.0f}s avg under load",
                    bullet_type="VULN", condition=show, indent=4,
                )
            else:
                pp(f"Time between two commands ({min_d} - {max_d}, avg {avg_d})",
                   bullet_type="NOTVULN", condition=show, indent=4)
        else:
            pp(
                f"Time between two commands: no successful replies "
                f"({r.commands_sent} sent)",
                bullet_type="VULN", condition=show, indent=4,
            )

        # 2) Error rate under load.
        err_rate = r.error_rate_pct
        if err_rate <= NOOP_FLOOD_ERROR_RATE_OK_MAX_PCT:
            pp(f"Error rate: {err_rate:.0f}%", bullet_type="NOTVULN", condition=show, indent=4)
        else:
            pp(
                f"Error rate: {err_rate:.0f}% "
                f"(over {NOOP_FLOOD_ERROR_RATE_OK_MAX_PCT:.0f}%)",
                bullet_type="VULN", condition=show, indent=4,
            )

        # 3) Connection survival summary — informs the analyst whether the
        #    server endured the storm or kicked clients out.
        if r.early_exit_no_connections:
            # The server actively cut every socket before our time-budget
            # expired — that's effectively a successful disconnect-storm DoS,
            # so flag it as a warning rather than a neutral note.
            pp("Server disconnected all connections before test time limit",
               bullet_type="VULN", condition=show, indent=4)
        storm_base = r.storm_pool_connections or r.established_connections
        if storm_base > 0 and r.disconnected_during_test > 0:
            pct = 100.0 * r.disconnected_during_test / storm_base
            pp(
                f"Disconnected connections during test: "
                f"{r.disconnected_during_test} from {storm_base} "
                f"({pct:.0f}%)",
                bullet_type="TITLE", condition=show, indent=4,
            )
            # Per-connection breakdown (ADDITIONS colour, same as -vv debug output).
            for idx, reason, detail in r.terminated_connections:
                pp(get_colored_text(f"Connection #{idx} terminated — {reason} ({detail})", color="ADDITIONS"),
                   bullet_type="TEXT", condition=show, indent=8)

    def _on_brute_success(self, cred: Creds) -> None:
        """Callback for real-time streaming of found credentials (thread-safe)."""
        with self._brute_stream_lock:
            self.ptprint(f"    user: {cred.user}, password: {cred.passw}")

    def _stream_brute_result(self) -> None:
        creds = self.results.creds
        if creds is None:
            return
        if len(creds) > 0:
            ptprinthelper.ptprint(f"Found {len(creds)} valid credentials", bullet_type="INFO",
                                  condition=not self.use_json, indent=4)
