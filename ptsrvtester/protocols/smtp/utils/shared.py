import base64, ipaddress, os, random, re, secrets, smtplib, socket, ssl, sys, threading, time, unicodedata
from typing import Callable


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
from .ptprinthelper import get_colored_text
from .helpers import Creds, get_mode, text_or_file
from .smtp_fingerprints import ServerIdentifyResult
from .behavior_profiles import PROFILE_MISSING_HINTS

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
            host = _get_hostname_from_ehlo_raw(info.ehlo)
            if host and "." in host:
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
                    self._smtp_vv_io(f"MAIL FROM:{candidate}", f"{status} {reply_str.strip()[:400]}")
                    self._rcpt_enum_mail_from_ok = candidate
                    return True, candidate
                self._smtp_vv_io(f"MAIL FROM:{candidate}", f"{status} {reply_str.strip()[:400]}")
            except Exception as e:
                self._smtp_vv_io(f"MAIL FROM:{candidate}", str(e))
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
        self._smtp_vv_io("(connect)", f"220 {banner}")

        ehlo = None
        ehlo_starttls = None
        ehlo_starttls_error = None
        if get_commands:
            try:
                ehlo_status, ehlo_bytes = smtp.ehlo(self.fqdn)
                ehlo = ehlo_bytes.decode()
                self._smtp_vv_io(f"EHLO {self.fqdn}", f"{ehlo_status} {ehlo}")
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
                    ehlo_starttls_error = str(e)
                    self.ptdebug(f"STARTTLS EHLO failed: {e}", Out.INFO)
                finally:
                    if smtp_stls is not None:
                        try:
                            smtp_stls.close()
                        except Exception:
                            pass

        return smtp, InfoResult(banner, ehlo, ehlo_starttls, ehlo_starttls_error)

    def _try_login(self, creds: Creds) -> Creds | None:
        smtp, *_ = self.connect()

        try:
            smtp.login(creds.user, creds.passw)
            self._smtp_vv_io(f"AUTH LOGIN {creds.user}", "235 Authentication successful")
            result = creds
        except smtplib.SMTPAuthenticationError as ex:
            self._smtp_vv_io(f"AUTH LOGIN {creds.user}", str(ex).strip() or "535 Authentication failed")
            result = None
        except Exception as ex:
            self._smtp_vv_io(f"AUTH LOGIN {creds.user}", str(ex))
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
            det = SharedMixin._smtp_detail_one_line(detail) or detail or "Could not complete"
            return "WARNING", f"Indeterminate: {det}"
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

    _VV_TRACE_ARROW = re.compile(
        r"^(?:(?:Accept-all probe|Role probe)\s+)?"
        r"(?:\[(?P<idx>\d+)/(?P<total>\d+)\]\s+)?"
        r"(?P<cmd>MAIL FROM|RCPT TO(?: \([^)]+\))?|EHLO|HELO|AUTH(?: LOGIN| PLAIN| NTLM)?|STARTTLS|RSET)"
        r"(?P<arg>:[^\u2192]*?| <[^>]+>)?"
        r"\s*(?:\u2192|->)\s*"
        r"(?:\[(?P<code>\d+)\]\s*)?(?P<recv>.*)$",
        re.I,
    )
    _VV_TRACE_COLON = re.compile(
        r"^(?P<cmd>Connect|EHLO|HELO|STARTTLS|AUTH LOGIN|AUTH PLAIN|AUTH NTLM|"
        r"MAIL FROM(?:\s*<[^>]*>)?|RCPT TO(?:\s*<[^>]*>)?):\s*(?P<recv>.*)$",
        re.I,
    )
    _VV_TRACE_RCPT_COUNTED = re.compile(
        r"^RCPT TO:\s*(?P<addr><[^>]+>)\s*\[\d+/\d+\]\s*(?:\u2192|->)\s*(?P<recv>.*)$",
        re.I,
    )

    def _smtp_trace_line_as_vv(self, line: str, *, indent: int = 4) -> bool:
        """Print compact command traces as Send/Receive. DATA dumps stay as-is."""
        s = (line or "").strip()
        if not s or s.startswith(("Send:", "Receive:", "DATA", "SIZE_", "QUEUE_")):
            return False
        m = self._VV_TRACE_RCPT_COUNTED.match(s)
        if m:
            self._smtp_vv_io(f"RCPT TO:{m.group('addr')}", m.group("recv"), indent=indent)
            return True
        m = self._VV_TRACE_ARROW.match(s)
        if m:
            cmd = re.sub(r"\s+", " ", m.group("cmd")).strip()
            arg = (m.group("arg") or "").strip()
            if arg.startswith(":"):
                arg = arg[1:].strip()
            send = f"{cmd}:{arg}" if arg else cmd
            recv = m.group("recv") or ""
            code = m.group("code")
            if code and not recv.startswith(code):
                recv = f"{code} {recv}".strip()
            self._smtp_vv_io(send, recv, indent=indent)
            return True
        m = self._VV_TRACE_COLON.match(s)
        if m:
            cmd = m.group("cmd").strip()
            recv = m.group("recv") or ""
            if cmd.lower() == "connect":
                send = "(connect)"
            elif cmd.upper().startswith("MAIL FROM") and "<" in cmd:
                send = "MAIL FROM:" + cmd[cmd.index("<"):]
            elif cmd.upper().startswith("RCPT TO") and "<" in cmd:
                send = "RCPT TO:" + cmd[cmd.index("<"):]
            else:
                send = cmd
            self._smtp_vv_io(send, recv, indent=indent)
            return True
        return False

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
        if "\n" not in line and self._smtp_trace_line_as_vv(line, indent=indent_override):
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
            _append(f"AUTH LOGIN: 235 Authentication successful ({user})")
            return True, None
        except smtplib.SMTPAuthenticationError as e:
            _append(f"AUTH LOGIN: {e}")
            return False, f"AUTH LOGIN failed for {user}: {e}"
        except (socket.timeout, smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
            _append(f"AUTH LOGIN: {e}")
            return False, f"AUTH LOGIN error for {user}: {e}"

    def _mail_test_live_done(self, label: str, detail: str) -> None:
        """Per-variant/category line as soon as that step finishes (SMTP dialog stays on -vv)."""
        if not self.use_json:
            one_line = self._smtp_detail_one_line(detail) or detail
            self._ptprint_raw(
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
            self._ptprint_raw,
            True,
            accepted=accepted,
            indeterminate=indeterminate,
            detail=detail,
            sent_msg=sent_msg,
            follow_up=follow_up,
        )

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

    def _stream_noop_flood1_result(self) -> None:
        """Render verdicts for -ts NOOP1 (NOOP Flooding, single connection)."""
        pp = self._ptprint_raw
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
        pp = self._ptprint_raw
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

    def _accepted_domain_probe_props_json(self) -> dict[str, object]:
        from ..modules.probedom import _accepted_domain_probe_props_json as _fn
        return _fn(self)

    def _on_brute_success(self, cred: Creds) -> None:
        """Callback for real-time streaming of found credentials (thread-safe)."""
        with self._brute_stream_lock:
            self.ptprint(f"    user: {cred.user}, password: {cred.passw}")

    def _stream_brute_result(self) -> None:
        creds = self.results.creds
        if creds is None:
            return
        if len(creds) > 0:
            self._ptprint_raw(f"Found {len(creds)} valid credentials", bullet_type="INFO",
                                  condition=not self.use_json, indent=4)
