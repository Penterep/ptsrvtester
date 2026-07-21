import os, queue, random, re, smtplib, socket, sys, threading, time
from typing import Callable


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
from ...utils import ptprinthelper
from ...utils.helpers import get_mode
from ...utils.progress import ThreadedProgress

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from ..helpers import *
from ..results import *
from ..registry import *


class EnumMixin:

    def start_interactive_mode(self, smtp: smtplib.SMTP):
        self.ptprint("\n", end="")
        while True:
            user_input = input("[*] INTERACTIVE MODE: ").upper()
            status, reply = smtp.docmd(user_input)
            if user_input in ("EXIT", "QUIT"):
                break
            if user_input == "HELP":
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply))
            if not self.bytes_to_str(reply).endswith("\n"):
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply))
                self.ptprint(f" ")
            else:
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply).replace("\n", "\n      "))

    def expn_vrfy_slow_down_test(self, method: str, smtp):
        if sum(self.slow_down_results.values()) >= 1:
            self.ptdebug(f"New smtp handle required, initiating new smtp connection ...", Out.INFO)
            smtp = self.get_smtp_handler()
            smtp.docmd("EHLO", f"{self.fqdn}")

        self.ptdebug(f"[{method}] SLOW DOWN TEST {' '*6}", Out.INFO, end="\r")

        dummy_data = [
            "".join(random.choices("abcdefghijk", k=random.randint(1, 5))) for i in range(29)
        ]
        half = int(len(dummy_data) / 2)
        is_slow_down = False
        is_unstable_response = False  # OWASP: init to avoid NameError
        initial_time = 0
        last_request_time = 0
        first_half_time = 0
        second_half_time = 0
        for index, user in enumerate(dummy_data):
            endl = "\n" if index + 1 == len(dummy_data) else "\r"
            self.ptdebug(
                f"[{method}] SLOW DOWN TEST [{index+1}/{len(dummy_data)}]", Out.INFO, end=endl
            )
            start_time = time.time()
            try:
                smtp.docmd(method, user)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                return {method.lower(): True}

            end_time = time.time() - start_time

            last_request_time = end_time
            if index == 0:
                initial_time += end_time

            if index < half:
                first_half_time += end_time
            else:
                second_half_time += end_time

            if end_time >= 3:
                is_unstable_response = True
            if end_time >= 3 and is_unstable_response:
                self.ptdebug(f"[{method}] SLOW DOWN TEST [{index+1}/{index+1}]", Out.INFO)
                self.ptdebug(f"Unstable response (>3sec), break", Out.VULN)
                is_slow_down = True
                break

        if (second_half_time - first_half_time) > initial_time * 10:
            is_slow_down = True
        if is_slow_down:
            self.ptdebug(f"{method} Method have slow-down protection implemented", Out.NOTVULN)
        self.ptdebug(f"First request response time: {str(initial_time)[:8]}", Out.INFO)
        self.ptdebug(f"Last request response time:  {str(last_request_time)[:8]}", Out.INFO)

        return {method.lower(): is_slow_down}

    def rcpt_slow_down_test(self, smtp):
        if sum(self.slow_down_results.values()) >= 1:
            smtp = self.get_smtp_handler()
            smtp.docmd("EHLO", f"{self.fqdn}")

        domain = self._get_rcpt_limit_domain()
        try:
            smtp.docmd("RSET")
        except Exception:
            pass
        ok_mail, _ = self._try_mail_from_for_rcpt_probe(smtp, domain)
        if not ok_mail:
            self.ptdebug("[RCPT] SLOW DOWN TEST: no MAIL FROM candidate accepted", Out.INFO)
            return {"rcpt": False}

        self.ptdebug(f"[RCPT] SLOW DOWN TEST {' '*6}", Out.INFO, end="\r")

        dummy_data = [
            "".join(random.choices("abcdefghijk", k=random.randint(1, 5))) for i in range(20)
        ]
        half = int(len(dummy_data) / 2)
        time_data = []
        is_slow_down = False

        first_half_time = 0
        initial_time = 0
        second_half_time = 0
        last_request_time = 0

        is_unstable_response = False
        for index, user in enumerate(dummy_data):
            endl = "\n" if index + 1 == len(dummy_data) else "\r"
            self.ptdebug(f"[RCPT] SLOW DOWN TEST [{index+1}/{len(dummy_data)}]", Out.INFO, end=endl)
            start_time = time.time()
            status, reply = smtp.docmd("RCPT TO:", f"<{user}@{domain}>")
            end_time = time.time() - start_time

            last_request_time = end_time
            if index == 0:
                initial_time += end_time
            if index < half:
                first_half_time += end_time
            else:
                second_half_time += end_time

            if end_time >= 3:
                is_unstable_response = True
            if end_time >= 3 and is_unstable_response:
                is_slow_down = True
                break

        if (second_half_time - first_half_time) > initial_time * 10:
            is_slow_down = True
        if is_slow_down:
            self.ptdebug(f"[RCPT] Method have slow-down protection implemented", Out.NOTVULN)

        self.ptdebug(f"First request response time: {str(initial_time)[:8]}", Out.INFO)
        self.ptdebug(f"Last request response time:  {str(last_request_time)[:8]}", Out.INFO)

        return {"rcpt": is_slow_down}

    def _enumeration_requested_method_set(self) -> set[str]:
        if self.args.enumerate is None:
            return {"EXPN", "VRFY", "RCPT"}
        if isinstance(self.args.enumerate, list):
            return {m.upper() for m in self.args.enumerate if m}
        return {self.args.enumerate.upper()} if self.args.enumerate else {"EXPN", "VRFY", "RCPT"}

    def _wordlist_enumeration_will_run(
        self, enumeration_vulns: dict[str, bool | None], catch_all: str | None
    ) -> bool:
        """True when do_enumeration will actually iterate the wordlist (not only skip messages)."""
        if enumeration_vulns["expn"]:
            return catch_all != "configured"
        if enumeration_vulns["vrfy"]:
            return catch_all != "configured"
        if enumeration_vulns["rcpt"]:
            return catch_all not in (*CATCH_ALL_INDETERMINATE_VARIANTS, "configured")
        return False

    def _stream_enumeration_method_rows(
        self, enum_results: list[EnumResult], catch_all: str | None
    ) -> None:
        """Print EXPN/VRFY/RCPT status lines (same as first loop in _stream_enumeration_result)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        requested_set = self._enumeration_requested_method_set()
        filtered = [e for e in enum_results if e.method.upper() in requested_set]
        for e in filtered:
            if catch_all == "configured":
                pp(f"{e.method.upper()} method: Indeterminate (Useless due to Catch All)",
                   bullet_type="WARNING", condition=show, indent=4)
            elif e.blocked_by_rbl:
                pp(f"{e.method.upper()} method protected by RBL/Reputation (Client IP blocked)",
                   bullet_type="NOTVULN", condition=show, indent=4)
                if e.server_reply:
                    for line in (e.server_reply or "").replace("\r", "").splitlines():
                        pp(line.strip(), bullet_type="TEXT", condition=show, indent=8)
            else:
                slowdown = ""
                if e.slowdown is not None:
                    slowdown = " (rate limited)" if e.slowdown else " (not rate limited)"
                verdict_bullet = "VULN" if e.vulnerable else "NOTVULN"
                if e.vulnerable:
                    if e.server_reply:
                        raw = (e.server_reply or "").replace("\r", "").splitlines()
                        parts = [re.sub(r" +", " ", p.strip()) for p in raw if p.strip()]
                        if parts:
                            if len(parts) == 1:
                                pp(f"{e.method.upper()} method is enabled ({parts[0]}){slowdown}",
                                   bullet_type=verdict_bullet, condition=show, indent=4)
                            else:
                                pp(
                                    f"{e.method.upper()} method is enabled ({parts[0]}{')' if len(parts) == 1 else ''}{slowdown if len(parts) == 1 else ''}",
                                    bullet_type=verdict_bullet, condition=show, indent=4,
                                )
                                for i, part in enumerate(parts[1:]):
                                    is_last = i == len(parts) - 2
                                    pp(f"{part}{')' if is_last else ''}{slowdown if is_last else ''}",
                                       bullet_type="TEXT", condition=show, indent=8)
                        else:
                            pp(f"{e.method.upper()} method is enabled{slowdown}",
                               bullet_type=verdict_bullet, condition=show, indent=4)
                    else:
                        pp(f"{e.method.upper()} method is enabled{slowdown}",
                           bullet_type=verdict_bullet, condition=show, indent=4)
                else:
                    if e.server_reply and "Relay protection active" in e.server_reply:
                        status = "is deny (Relay protection active)"
                    elif e.server_reply and "Administrative prohibition" in e.server_reply:
                        status = "is deny (Administrative prohibition)"
                    else:
                        status = "is deny"
                    pp(f"{e.method.upper()} method {status}{slowdown}",
                       bullet_type=verdict_bullet, condition=show, indent=4)

    @staticmethod
    def _expn_vrfy_result_strings(reply_str: str) -> list[str]:
        """Extract display/enum strings from EXPN/VRFY success reply (bracketed paths, emails, fallback)."""
        found = re.findall(r"<([^<>]*)>", reply_str)
        found = [x.strip() for x in found if x.strip()]
        if found:
            out: list[str] = []
            seen: set[str] = set()
            for x in found:
                if x not in seen:
                    seen.add(x)
                    out.append(x)
            return out
        for line in reply_str.replace("\r\n", "\n").split("\n"):
            m = re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", line)
            if m:
                return [m.group(0)]
        lines = [ln.strip() for ln in reply_str.replace("\r\n", "\n").split("\n") if ln.strip()]
        if lines:
            tail = re.sub(r"^\d{3}\s*", "", lines[0]).strip()
            if tail and len(tail) < 500:
                return [tail]
        return []

    @staticmethod
    def _smtp_command_streaming(
        smtp,
        cmd: str,
        args: str,
        on_first_hit=None,
        debug: bool = False,
        dbg: Callable[[str], None] | None = None,
    ) -> tuple[int, bytes]:
        """Send SMTP command and call on_first_hit(line_bytes) on the very first positive
        (non-5xx) response line – before reading continuation lines.
        Returns (errcode, reply_bytes) identical to smtplib.SMTP.docmd.
        Falls back to smtp.docmd when the underlying file object is not accessible.

        debug=True (-vv) enables timestamped tracing; pass ``dbg`` as ``self.ptdebug``
        so lines use the same ADDITIONS styling and indent as other verbose output.
        If ``dbg`` is omitted, falls back to writing raw bytes to stderr (fd 2)."""
        _MAXLINE: int = getattr(smtplib, "_MAXLINE", 8192)

        def _dbg(msg: str) -> None:
            if debug:
                ts = time.perf_counter()
                text = f"[DBG enum {ts:.3f}] {msg}"
                if dbg is not None:
                    dbg(text)
                else:
                    os.write(2, (text + "\n").encode("utf-8", errors="replace"))

        file = getattr(smtp, "file", None)
        if file is None:
            _dbg(f"no file object, falling back to docmd({cmd!r})")
            status, reply = smtp.docmd(cmd, args)
            if on_first_hit is not None and not (500 <= status <= 599):
                _dbg("calling on_first_hit (docmd fallback)")
                t0 = time.perf_counter()
                on_first_hit(reply[:512] if isinstance(reply, bytes) else reply)
                _dbg(f"on_first_hit done ({time.perf_counter()-t0:.3f}s)")
                try:
                    sys.stdout.flush()
                except Exception:
                    pass
            return status, reply

        # IMPORTANT: do NOT call setblocking(True) here – that is equivalent to
        # settimeout(None) and removes the timeout set on the socket at creation time
        # (15 s by default, 30 s for enumeration connections), causing readline() to
        # block indefinitely on continuation lines.

        # Re-assert TCP_NODELAY immediately before sending the command.
        # _smtp_sock_set_tcp_nodelay() is called once in connect(), but after
        # STARTTLS the sock attribute is replaced with a new SSLSocket that may
        # not have inherited the option; also enforces it after any reconnect.
        # Do NOT use buffering=0 on makefile() – that causes byte-by-byte reads.
        try:
            sk = getattr(smtp, "sock", None)
            if sk is not None:
                sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

        smtp.putcmd(cmd, args)
        _dbg(f"putcmd sent: {cmd} {args!r}")

        resp: list[bytes] = []
        first_hit_fired = False
        code = -1
        line_no = 0

        while True:
            line_no += 1
            t_rl = time.perf_counter()
            try:
                line = file.readline(_MAXLINE + 1)
            except (TimeoutError, socket.timeout):
                _dbg(f"readline #{line_no} TIMEOUT after {time.perf_counter()-t_rl:.3f}s (resp so far: {len(resp)} lines)")
                # Server stopped sending continuation lines within the timeout window.
                # Return whatever we already collected (first positive line was already
                # delivered via on_first_hit, so the finding is already printed).
                if resp:
                    break
                raise smtplib.SMTPServerDisconnected("SMTP readline timed out")
            except OSError as e:
                _dbg(f"readline #{line_no} OSError after {time.perf_counter()-t_rl:.3f}s: {e}")
                raise smtplib.SMTPServerDisconnected(f"Connection unexpectedly closed: {e}")

            _dbg(f"readline #{line_no} took {time.perf_counter()-t_rl:.3f}s → {repr(line[:40])}")

            if not line:
                _dbg(f"readline #{line_no} returned empty (server closed connection)")
                if resp:
                    break
                raise smtplib.SMTPServerDisconnected("Connection unexpectedly closed")
            if len(line) > _MAXLINE:
                raise smtplib.SMTPResponseException(500, b"Line too long")

            resp.append(line[4:].strip(b" \t\r\n"))
            try:
                code = int(line[:3])
            except (ValueError, IndexError):
                code = -1

            if not first_hit_fired and on_first_hit is not None and code != -1 and not (500 <= code <= 599):
                first_hit_fired = True
                _dbg(f"calling on_first_hit (code={code})")
                t0 = time.perf_counter()
                on_first_hit(line[4:].strip(b" \t\r\n"))
                _dbg(f"on_first_hit done ({time.perf_counter()-t0:.3f}s)")
                try:
                    sys.stdout.flush()
                except Exception:
                    pass

            is_last = line[3:4] != b"-"
            _dbg(f"line #{line_no} code={code} last={is_last} char4={repr(line[3:4])}")
            if is_last:
                break

        _dbg(f"streaming done: code={code} lines={len(resp)}")
        return code, b"\n".join(resp)

    @staticmethod
    def _expn_vrfy_quick_display(reply, fallback_user: str) -> str:
        """Fast display string from raw EXPN/VRFY reply (bounded scan; full parse may follow)."""
        if isinstance(reply, bytes):
            chunk = reply[:16384].decode("utf-8", errors="replace")
        else:
            chunk = str(reply)[:16384]
        for m in re.finditer(r"<([^<>]{1,512})>", chunk):
            x = m.group(1).strip()
            if x:
                return x
        m = re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", chunk)
        if m:
            return m.group(0)
        lines = [ln.strip() for ln in chunk.replace("\r\n", "\n").split("\n") if ln.strip()]
        if lines:
            tail = re.sub(r"^\d{3}\s*", "", lines[0]).strip()
            if tail and len(tail) < 500:
                return tail
        return fallback_user

    @staticmethod
    def _rcpt_reply_has_unknown(reply) -> bool:
        """True if RCPT reply suggests unknown user (scan without full UTF-8 decode when bytes)."""
        if isinstance(reply, bytes):
            return b"UNKNOWN" in reply.upper()
        return "UNKNOWN" in str(reply).upper()

    def _enum_streaming_emit_first_finding(self, _idx: int, _total: int, display: str) -> None:
        """Print first EXPN/VRFY hit on its own line (no time/%); progress line stays separate."""
        if self.use_json or getattr(self.args, "enum_threads", 1) > 1:
            return
        self._raw_write(f"\033[2K\r    {display}\n".encode("utf-8", errors="replace"))
        self._enum_progress_line_dirty = False

    def _print_enum_finding(
        self, _idx: int, _total: int, payload: str, *, replace_progress: bool = True
    ) -> None:
        """Print one enumerated value (single-thread); clear the live progress line when replace_progress.

        Multi-thread enumeration prints findings via ``ThreadedProgress`` + ``PrintLock``
        (see ``utils/progress.py``); this path is single-thread only.
        """
        if self.use_json:
            return
        if replace_progress:
            self._raw_write(f"\033[2K\r    {payload}\n".encode("utf-8", errors="replace"))
            self._enum_progress_line_dirty = False
        else:
            self._raw_write(f"    {payload}\n".encode("utf-8", errors="replace"))

    def expn_vrfy_enumeration(self, method, smtp) -> list[str]:
        enum_threads = getattr(self.args, "enum_threads", 1)
        ehlo = (self.results.info and self.results.info.ehlo) or ""
        supports_smtputf8 = "SMTPUTF8" in ehlo.upper()
        if getattr(self, "_wordlist_skipped", 0) > 0:
            self.ptdebug(
                f"Skipped {self._wordlist_skipped} invalid local parts from wordlist",
                Out.INFO,
            )
        self.ptdebug(f"Enumerating users:" + (f" ({enum_threads} threads)" if enum_threads > 1 else ""), Out.INFO)
        enumerated_users: list[str] = []
        total_aliases = 0 if method == "EXPN" else None
        wl_total = len(self.wordlist)

        def _skip_non_ascii_no_utf8(s: str) -> bool:
            return not supports_smtputf8 and any(ord(c) >= 128 for c in s)

        try:
            if enum_threads <= 1:
                if supports_smtputf8:
                    smtp.command_encoding = "utf-8"

                reconnect_after = getattr(self.args, "enum_reconnect_after", None)
                consecutive_failures = 0
                _enum_stream_debug = getattr(self.args, "debug", False)
                _enum_stream_dbg = (
                    (lambda m: self.ptdebug(m)) if _enum_stream_debug else None
                )

                def _do_enum_reconnect() -> None:
                    """Reconnect to reset accumulated teergrube / rate-limit state.
                    Called after a successful find (when --enum-reconnect-after is set)
                    and after N consecutive failures."""
                    nonlocal smtp, consecutive_failures
                    consecutive_failures = 0
                    # Update clock label so the user can see reconnect is in progress
                    # and does not mistake the old user label for a wordlist restart.
                    if not self.use_json and enum_threads <= 1:
                        with self._enum_progress_print_lock:
                            if self._enum_clock_state is not None:
                                self._enum_clock_state = dict(self._enum_clock_state)
                                self._enum_clock_state["label"] = "reconnecting..."
                                self._enum_clock_paint_unlocked()
                    try:
                        smtp = self.get_smtp_handler(timeout=15.0)
                        smtp.docmd("EHLO", self.fqdn)
                        if supports_smtputf8:
                            smtp.command_encoding = "utf-8"
                    except Exception:
                        pass  # best-effort; next putcmd will trigger the existing error handler

                for idx, user in enumerate(self.wordlist, start=1):
                    if _skip_non_ascii_no_utf8(user):
                        continue
                    if not self.use_json:
                        self._enum_wait_begin(idx, wl_total, user)

                    # Streaming callback: fires on the FIRST positive response line,
                    # before any continuation lines arrive.
                    _cur_idx = idx
                    _first_preview: list[str] = []

                    def _on_first_hit(line_bytes, _u=user, _i=_cur_idx):
                        display = self._expn_vrfy_quick_display(line_bytes, _u)
                        _first_preview.append(display)
                        if not self.use_json:
                            self._enum_streaming_emit_first_finding(_i, wl_total, display)

                    try:
                        status, reply = self._smtp_command_streaming(
                            smtp, method, user,
                            on_first_hit=None if self.use_json else _on_first_hit,
                            debug=_enum_stream_debug,
                            dbg=_enum_stream_dbg,
                        )
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                        self.ptdebug(
                            f"{method} enumeration interrupted (connection closed/reset): {e}",
                            Out.INFO,
                        )
                        # Reconnect and immediately retry the same user.
                        # Use a shorter 10 s timeout: if the server was intentionally
                        # silent on the old connection (rate-limit / greylisting), a
                        # fresh TCP connection almost always gets a fast reply, so 10 s
                        # is more than enough and avoids a second full 30 s stall.
                        _first_preview.clear()
                        try:
                            smtp = self.get_smtp_handler(timeout=10.0)
                            smtp.docmd("EHLO", f"{self.fqdn}")
                            if supports_smtputf8:
                                smtp.command_encoding = "utf-8"
                            status, reply = self._smtp_command_streaming(
                                smtp, method, user,
                                on_first_hit=None if self.use_json else _on_first_hit,
                                debug=_enum_stream_debug,
                                dbg=_enum_stream_dbg,
                            )
                            # Retry succeeded: restore 15 s timeout so the rest of
                            # the wordlist is not stuck with the short 10 s window.
                            try:
                                smtp.sock.settimeout(15.0)
                            except Exception:
                                pass
                        except Exception:
                            # Retry also failed – preserve connection for next user.
                            try:
                                smtp = self.get_smtp_handler(timeout=15.0)
                                smtp.docmd("EHLO", f"{self.fqdn}")
                                if supports_smtputf8:
                                    smtp.command_encoding = "utf-8"
                            except Exception:
                                break
                            status, reply = 550, b""
                    finally:
                        if not self.use_json and enum_threads <= 1:
                            self._enum_wait_end()
                    if status != 550:
                        preview = _first_preview[0] if _first_preview else self._expn_vrfy_quick_display(reply, user)
                        if not _first_preview and not self.use_json:
                            self._print_enum_finding(idx, wl_total, preview)
                        reply_str = self.bytes_to_str(reply)
                        user_email = self._expn_vrfy_result_strings(reply_str)
                        if not user_email:
                            user_email = [preview]
                        enumerated_users.extend(user_email)
                        if not self.use_json:
                            for em in user_email:
                                if em != preview:
                                    self._print_enum_finding(
                                        idx, wl_total, em, replace_progress=False
                                    )
                        elif self.use_json:
                            self.ptdebug(user_email[0])
                        if method == "EXPN" and len(user_email) > 1:
                            for alias in user_email[1:]:
                                total_aliases += len(user_email[1:])
                                self.ptdebug(f"{alias}", Out.ADDITIONS)
                        # Reconnect after a find only when --enum-reconnect-after is set;
                        # resets accumulated teergrube delay on the connection.
                        if reconnect_after is not None and reconnect_after != -1:
                            _do_enum_reconnect()
                    else:
                        consecutive_failures += 1
                        if (reconnect_after is not None and reconnect_after > 0
                                and consecutive_failures >= reconnect_after):
                            _do_enum_reconnect()
                if not self.use_json and enum_threads <= 1:
                    self._enum_progress_newline()
            else:
                valid_users = [u for u in self.wordlist if not _skip_non_ascii_no_utf8(u)]
                work_total = len(valid_users)
                user_queue: queue.Queue[str | None] = queue.Queue()
                for u in valid_users:
                    user_queue.put(u)
                for _ in range(enum_threads):
                    user_queue.put(None)
                result_lock = threading.Lock()
                # ptlibs-style live progress + PrintLock per-item output (utils/progress.py).
                progress = ThreadedProgress(work_total, enabled=not self.use_json)

                _enum_stream_debug = getattr(self.args, "debug", False)
                _enum_stream_dbg = (
                    (lambda m: self.ptdebug(m)) if _enum_stream_debug else None
                )

                def worker() -> None:
                    conn = None
                    while True:
                        user = user_queue.get()
                        if user is None:
                            user_queue.task_done()
                            break
                        out = progress.new_output()
                        try:
                            if conn is None:
                                try:
                                    conn = self.get_smtp_handler()
                                    conn.docmd("EHLO", f"{self.fqdn}")
                                    if supports_smtputf8:
                                        conn.command_encoding = "utf-8"
                                except Exception:
                                    continue

                            try:
                                status, reply = self._smtp_command_streaming(
                                    conn, method, user,
                                    on_first_hit=None,
                                    debug=_enum_stream_debug,
                                    dbg=_enum_stream_dbg,
                                )
                            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                                try:
                                    conn = self.get_smtp_handler()
                                    conn.docmd("EHLO", f"{self.fqdn}")
                                    if supports_smtputf8:
                                        conn.command_encoding = "utf-8"
                                    status, reply = conn.docmd(method, user)
                                except Exception:
                                    continue
                            if status != 550:
                                preview = self._expn_vrfy_quick_display(reply, user)
                                reply_str = self.bytes_to_str(reply)
                                user_email = self._expn_vrfy_result_strings(reply_str)
                                if not user_email:
                                    user_email = [preview]
                                with result_lock:
                                    enumerated_users.extend(user_email)
                                if self.use_json:
                                    self.ptdebug(user_email[0])
                                else:
                                    for em in user_email:
                                        out.add_string_to_output(em)
                        finally:
                            if not self.use_json:
                                progress.flush(out, repaint=False)
                                progress.advance(label=user)
                            user_queue.task_done()

                threads_list = [threading.Thread(target=worker) for _ in range(enum_threads)]
                for t in threads_list:
                    t.start()
                for t in threads_list:
                    t.join()
                if not self.use_json:
                    progress.finalize()
                total_aliases = 0

            additional_message = (
                f"(total {len(enumerated_users) + (total_aliases or 0)} with aliases)"
                if method == "EXPN"
                else ""
            )
            self.ptdebug(f" ")
            self.ptdebug(f"-- Enumerated {len(enumerated_users)} emails {additional_message} --")
            self.ptdebug(f" ")

            self.already_enumerated = True
            return enumerated_users
        finally:
            self._enum_clock_shutdown()

    @staticmethod
    def _is_rbl_blocked(reply_text: str) -> bool:
        """Return True when a 5xx reply indicates the client IP is blocked by RBL
        (e.g. Spamhaus, SpamCop). Server rejected before the test could run."""
        up = reply_text.upper()
        RBL_INDICATORS = (
            "LISTED AT", "BLACKLIST", "ON BLACKLIST", "RBL", "ZEN.SPAMHAUS",
            "BLOCKED", "SPAMHAUS",  # e.g. "blocked using sbl.spamhaus.org"
        )
        return any(kw in up for kw in RBL_INDICATORS)

    @staticmethod
    def _is_admin_prohibition(reply_text: str) -> bool:
        """Return True when a 5xx VRFY/EXPN reply indicates an administrative
        block rather than a per-user differentiation response.
        These rejections mean the command is disabled by policy."""
        up = reply_text.upper()
        ADMIN_KEYWORDS = (
            "ADMINISTRATIVE PROHIBITION",
            "DISABLED",
            "NOT ALLOWED",
            "NOT PERMITTED",
            "COMMAND REJECTED",
            "COMMAND NOT ACCEPTED",
            "COMMAND DISABLED",
            "ACCESS DENIED",
        )
        return any(kw in up for kw in ADMIN_KEYWORDS)

    def expn_vrfy_test(self, method, smtp) -> bool:
        """Test VRFY/EXPN for user enumeration (OWASP WSTG-IDEN-003).
        RFC 5321: 250/251/252=success, 550/551=user unknown.

        Vulnerable when server returns 550/551 for invalid user AND the response
        indicates a per-user decision (user unknown, etc.).
        NOT vulnerable when the response indicates an administrative prohibition
        (command disabled by policy) -- these are false positives for customer reports."""
        INVALID_PROBES = ("foofoofoo", "nxuser001", "nxuser002")
        VRFY_EXPN_ACCEPT = (250, 251, 252)
        VRFY_EXPN_REJECT = (550, 551, 553, 554)

        replies: list[tuple[int, str]] = []
        for probe in INVALID_PROBES:
            try:
                status, reply = smtp.docmd(method, probe)
                reply_str = self.bytes_to_str(reply)
                replies.append((status, reply_str))
                if "AUTH" in reply_str.upper():
                    self.ptdebug(f"Testing {method} method: server requires AUTH", Out.INFO)
                    self._enum_test_replies = getattr(self, "_enum_test_replies", {})
                    self._enum_test_replies[method.lower()] = f"[{status}] {reply_str.strip()} (Administrative prohibition)"
                    return False
            except Exception as e:
                self.ptdebug(f"Testing {method} method: {e}", Out.INFO)
                return False

        first_status, first_reply = replies[0]
        self.ptdebug(f"Testing {method} method: [{first_status}] {first_reply}", Out.INFO)

        # Uniform response (all 250) = cannot enumerate (catch-all or misconfigured)
        if all(s in VRFY_EXPN_ACCEPT for s, _ in replies):
            self.ptdebug(
                f"Server returns 250 for all invalid addresses - cannot reliably enumerate ({method})",
                Out.INFO,
            )
            return False

        # Find the first 5xx rejection for analysis
        first_reject = next(
            ((s, r) for s, r in replies if s in VRFY_EXPN_REJECT),
            None,
        )

        self._enum_test_replies = getattr(self, "_enum_test_replies", {})

        if first_reject is None:
            # No 5xx at all (e.g. all 4xx or 502 not implemented) -- not vulnerable
            self.ptdebug(f"Server is not vulnerable to {method} enumeration", Out.INFO)
            return False

        rej_status, rej_text = first_reject
        reject_reply = f"[{rej_status}] {rej_text.strip()}"

        # RBL block = server rejected client IP before test could run (not a vulnerability)
        if rej_status in (550, 554) and self._is_rbl_blocked(rej_text):
            self.ptdebug(f"{method} blocked by RBL (could not test): {reject_reply}", Out.INFO)
            self._enum_test_replies[method.lower()] = reject_reply
            self._enum_blocked_by_rbl = getattr(self, "_enum_blocked_by_rbl", set())
            self._enum_blocked_by_rbl.add(method.lower())
            return False

        # Administrative prohibition = command blocked by policy, NOT per-user differentiation
        if self._is_admin_prohibition(rej_text):
            self.ptdebug(
                f"{method} blocked by administrative policy: {reject_reply}",
                Out.INFO,
            )
            self._enum_test_replies[method.lower()] = f"{reject_reply} (Administrative prohibition)"
            return False

        # Genuine per-user rejection (user unknown, etc.) = enumeration possible
        self._enum_test_replies[method.lower()] = reject_reply
        self.ptdebug(f"Server is vulnerable to {method} enumeration: {reject_reply}", Out.VULN)
        return True

    def newline_to_reply(self, reply):
        reply = self.bytes_to_str(reply)
        if not reply.endswith("\n"):
            reply += "\n"
        return reply

    @staticmethod
    def _is_relay_or_auth_rejection(reply_text: str) -> bool:
        """Return True when a 5xx reply indicates a global relay/auth policy
        rather than a per-recipient user-unknown decision.
        These rejections do NOT prove user enumeration."""
        up = reply_text.upper()
        RELAY_KEYWORDS = (
            "RELAY", "RELAYING", "NOT PERMITTED", "NOT ALLOWED",
            "AUTHENTICATION REQUIRED", "AUTH REQUIRED",
            "IS NOT LOCAL", "NOT LOCAL",
            "SENDER VERIFY", "SENDER REJECTED",
        )
        return any(kw in up for kw in RELAY_KEYWORDS)

    @staticmethod
    def _rcpt_enum_reply_for_display(
        reply_text: str,
        domain: str,
        probes: tuple[str, ...],
    ) -> str:
        """Normalize RCPT probe replies for terminal/JSON display: match VRFY/EXPN style (local part only).

        Servers often echo ``<user@domain>`` in RCPT rejects; EXPN/VRFY lines use bare ``user``."""
        if not reply_text or not domain:
            return reply_text
        out = reply_text
        dom = domain.strip()
        for p in probes:
            out = re.sub(re.escape(f"<{p}@{dom}>"), p, out, flags=re.IGNORECASE)
            out = re.sub(re.escape(f"{p}@{dom}"), p, out, flags=re.IGNORECASE)
        # Any echoed ``<local@domain>`` for this domain (handles case quirks vs. ``_get_rcpt_limit_domain()``).
        if dom:
            out = re.sub(
                re.compile(rf"<([^\s<>]+)@{re.escape(dom)}>", re.IGNORECASE),
                lambda m: m.group(1),
                out,
            )
        return out

    def rcpt_test(self, smtp) -> bool:
        """RCPT enum vulnerability (OWASP WSTG-IDEN-003).
        Uses full addresses <probe@domain> so the server evaluates them against its
        virtual mailbox / alias tables.  RFC 5321: 250/251=accepted, 550/551=rejected.

        Vulnerable when server returns 550/551/553/554 for invalid recipients AND
        the response text indicates a per-recipient decision (user unknown, mailbox
        not found, etc.) -- NOT a global relay/auth policy rejection."""
        RCPT_ACCEPT = (250, 251, 252)
        RCPT_REJECT = (550, 551, 553, 554)
        INVALID_PROBES = ("foofoofoo", "nxuser001", "nxuser002")

        domain = self._get_rcpt_limit_domain()
        self.ptdebug(f"Testing RCPT method with domain: {domain}", Out.INFO)

        # Ensure clean SMTP state (previous test_catchall may have left an open transaction)
        try:
            smtp.docmd("RSET")
        except Exception:
            pass

        ok_mail, _mail_used = self._try_mail_from_for_rcpt_probe(smtp, domain)
        if not ok_mail:
            self.ptdebug(
                "Testing RCPT method: all MAIL FROM candidates rejected (cannot test RCPT)",
                Out.INFO,
            )
            return False

        replies: list[tuple[int, str]] = []
        for probe in INVALID_PROBES:
            try:
                status, reply = smtp.docmd("RCPT TO:", f"<{probe}@{domain}>")
                reply_str = self.bytes_to_str(reply)
                replies.append((status, reply_str))
                if "AUTH" in reply_str.upper():
                    self.ptdebug(f"Testing RCPT method: [{status}] server requires AUTH", Out.INFO)
                    self._enum_test_replies = getattr(self, "_enum_test_replies", {})
                    disp = self._rcpt_enum_reply_for_display(reply_str.strip(), domain, INVALID_PROBES)
                    self._enum_test_replies["rcpt"] = f"[{status}] {disp} (Relay protection active)"
                    return False
            except Exception as e:
                self.ptdebug(f"Testing RCPT method: {e}", Out.INFO)
                return False

        first_status, first_reply = replies[0]
        self.ptdebug(
            "Testing RCPT method: [{}] {}".format(
                first_status,
                self._rcpt_enum_reply_for_display(first_reply.strip(), domain, INVALID_PROBES),
            ),
        )

        # Uniform 250 for all invalid = cannot enumerate (catch-all or accept-all)
        if all(s in RCPT_ACCEPT for s, _ in replies):
            self.ptdebug(
                "Server returns 250 for all invalid addresses - cannot reliably enumerate (RCPT)",
                Out.INFO,
            )
            return False

        # Find the first 5xx rejection for analysis
        first_reject = next(
            ((s, r) for s, r in replies if s in RCPT_REJECT),
            None,
        )

        self._enum_test_replies = getattr(self, "_enum_test_replies", {})

        if first_reject is None:
            # No 5xx at all (e.g. all 4xx) -- inconclusive
            self.ptdebug("Server is not vulnerable to RCPT enumeration", Out.NOTVULN)
            return False

        rej_status, rej_text = first_reject
        rej_disp = self._rcpt_enum_reply_for_display(rej_text.strip(), domain, INVALID_PROBES)
        reject_reply = f"[{rej_status}] {rej_disp}"

        # RBL block = server rejected client IP before test could run (not a vulnerability)
        if rej_status in (550, 554) and self._is_rbl_blocked(rej_text):
            self.ptdebug(f"RCPT blocked by RBL (could not test): {reject_reply}", Out.INFO)
            self._enum_test_replies["rcpt"] = reject_reply
            self._enum_blocked_by_rbl = getattr(self, "_enum_blocked_by_rbl", set())
            self._enum_blocked_by_rbl.add("rcpt")
            return False

        # Relay / auth policy rejection = global block, NOT per-user differentiation
        if self._is_relay_or_auth_rejection(rej_text):
            self.ptdebug(
                f"RCPT rejected by relay/auth policy, not user-based: {reject_reply}",
                Out.INFO,
            )
            self._enum_test_replies["rcpt"] = f"{reject_reply} (Relay protection active)"
            return False

        # Genuine per-recipient rejection (user unknown, mailbox not found, etc.)
        self._enum_test_replies["rcpt"] = reject_reply
        self.ptdebug(f"Server is vulnerable to RCPT enumeration: {reject_reply}", Out.VULN)
        return True

    def test_catchall(self, smtp: smtplib.SMTP) -> CatchAllResult:
        """
        Detect Catch-All mailbox: if server accepts 3 invalid addresses as valid,
        catch-all is configured (VRFY/EXPN) or indeterminate (RCPT).
        Uses VRFY or EXPN when available; otherwise RCPT. RCPT cannot distinguish
        valid address from catch-all, so when all invalid RCPT are accepted the
        result is ``indeterminate_accept_all_rcpt`` (displayed as accept-all via RCPT).
        Per RFC 5321: 250/251/252 are success for VRFY/EXPN; 550 = user unknown.
        OWASP: RCPT uses full addresses (local@domain) for robustness.
        """
        CATCHALL_INVALID = ("catchallnx001", "catchallnx002", "catchallnx003")
        VRFY_EXPN_ACCEPT = (250, 251, 252)
        domain = self._get_rcpt_limit_domain()
        mail_bracket = self._envelope_mail_from_bracket()

        def _choose_method() -> str | None:
            if self.results.enum_results:
                for e in self.results.enum_results:
                    if e.vulnerable and e.method in ("expn", "vrfy", "rcpt"):
                        return e.method
            try:
                status, _ = smtp.docmd("VRFY", "catchallprobe")
                if status in (*VRFY_EXPN_ACCEPT, 550):
                    return "vrfy"
            except Exception:
                pass
            try:
                status, _ = smtp.docmd("EXPN", "catchallprobe")
                if status in (*VRFY_EXPN_ACCEPT, 550):
                    return "expn"
            except Exception:
                pass
            try:
                smtp.docmd("MAIL FROM:", mail_bracket)
                status, _ = smtp.docmd("RCPT TO:", f"<catchallprobe@{domain}>")
                if status in (250, 251, 252, 550):
                    return "rcpt"
            except Exception:
                pass
            return None

        try:
            method = _choose_method()
            if not method:
                return "indeterminate"

            if method in ("vrfy", "expn"):
                cmd = "VRFY" if method == "vrfy" else "EXPN"
                accepted = 0
                for user in CATCHALL_INVALID:
                    try:
                        status, _ = smtp.docmd(cmd, user)
                        if status in VRFY_EXPN_ACCEPT:
                            accepted += 1
                        elif status in (550, 551, 553, 554):
                            return "not_configured"
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                        return "indeterminate"
                return "configured" if accepted == 3 else "indeterminate"

            else:
                # _choose_method may have issued MAIL FROM when probing RCPT; reset first
                try:
                    smtp.docmd("RSET")
                except Exception:
                    pass
                try:
                    smtp.docmd("MAIL FROM:", mail_bracket)
                except Exception:
                    return "indeterminate"
                try:
                    for user in CATCHALL_INVALID:
                        try:
                            status, reply = smtp.docmd("RCPT TO:", f"<{user}@{domain}>")
                            if status in (550, 551, 553, 554) or "UNKNOWN" in self.bytes_to_str(reply).upper():
                                return "not_configured"
                        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                            return "indeterminate"
                    return "indeterminate_accept_all_rcpt"
                finally:
                    try:
                        smtp.docmd("RSET")
                    except Exception:
                        pass
        except Exception:
            return "indeterminate"

    def rcpt_enumeration(self, smtp) -> list[str]:
        enum_threads = getattr(self.args, "enum_threads", 1)
        ehlo = (self.results.info and self.results.info.ehlo) or ""
        supports_smtputf8 = "SMTPUTF8" in ehlo.upper()
        domain = self._get_rcpt_limit_domain()
        if getattr(self, "_wordlist_skipped", 0) > 0:
            self.ptdebug(
                f"Skipped {self._wordlist_skipped} invalid local parts from wordlist",
                Out.INFO,
            )
        self.ptdebug(f"Enumerating users (domain: {domain}):" + (f" ({enum_threads} threads)" if enum_threads > 1 else ""), Out.INFO)
        enumerated_users: list[str] = []
        wl_total = len(self.wordlist)

        def _skip(local: str) -> bool:
            return not supports_smtputf8 and any(ord(c) >= 128 for c in local)

        try:
            if enum_threads <= 1:
                if supports_smtputf8:
                    smtp.command_encoding = "utf-8"

                reconnect_after = getattr(self.args, "enum_reconnect_after", None)
                consecutive_failures = 0

                def _do_rcpt_reconnect() -> None:
                    """Reconnect to reset accumulated teergrube / rate-limit state.
                    Called after a successful find (when --enum-reconnect-after is set)
                    and after N consecutive failures."""
                    nonlocal smtp, consecutive_failures
                    consecutive_failures = 0
                    # Update clock label so the user can see reconnect is in progress
                    # and does not mistake the old user label for a wordlist restart.
                    if not self.use_json and enum_threads <= 1:
                        with self._enum_progress_print_lock:
                            if self._enum_clock_state is not None:
                                self._enum_clock_state = dict(self._enum_clock_state)
                                self._enum_clock_state["label"] = "reconnecting..."
                                self._enum_clock_paint_unlocked()
                    try:
                        smtp = self.get_smtp_handler(timeout=15.0)
                        smtp.docmd("EHLO", self.fqdn)
                        if supports_smtputf8:
                            smtp.command_encoding = "utf-8"
                        self._try_mail_from_for_rcpt_probe(smtp, domain)
                    except Exception:
                        pass  # best-effort; next docmd will trigger the existing error handler

                for idx, user in enumerate(self.wordlist, start=1):
                    local = user.split("@")[0].strip()
                    if _skip(local):
                        continue
                    label = f"{local}@{domain}"
                    if not self.use_json:
                        # Progress bar: local part only (same style as EXPN/VRFY); findings still use full label.
                        self._enum_wait_begin(idx, wl_total, local)
                    try:
                        status, reply = smtp.docmd("RCPT TO:", f"<{local}@{domain}>")
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                        self.ptdebug(
                            f"RCPT enumeration interrupted (connection closed/reset): {e}",
                            Out.INFO,
                        )
                        # Reconnect + immediate retry with 10 s timeout (same rationale
                        # as in expn_vrfy_enumeration: fresh TCP connection gets a fast
                        # reply from servers that silence old connections deliberately).
                        try:
                            smtp = self.get_smtp_handler(timeout=10.0)
                            smtp.docmd("EHLO", f"{self.fqdn}")
                            if supports_smtputf8:
                                smtp.command_encoding = "utf-8"
                            self._try_mail_from_for_rcpt_probe(smtp, domain)
                            status, reply = smtp.docmd("RCPT TO:", f"<{local}@{domain}>")
                            # Retry succeeded: restore 15 s timeout for remaining users.
                            try:
                                smtp.sock.settimeout(15.0)
                            except Exception:
                                pass
                        except Exception:
                            # Retry also failed – preserve connection for next user.
                            try:
                                smtp = self.get_smtp_handler(timeout=15.0)
                                smtp.docmd("EHLO", f"{self.fqdn}")
                                if supports_smtputf8:
                                    smtp.command_encoding = "utf-8"
                                self._try_mail_from_for_rcpt_probe(smtp, domain)
                            except Exception:
                                break
                            status, reply = 550, b""
                    finally:
                        if not self.use_json and enum_threads <= 1:
                            self._enum_wait_end()
                    if status != 550 and not self._rcpt_reply_has_unknown(reply):
                        if not self.use_json:
                            self._print_enum_finding(idx, wl_total, label)
                        elif self.use_json:
                            self.ptdebug(label)
                        enumerated_users.append(label)
                        # Reconnect after a find only when --enum-reconnect-after is set;
                        # resets accumulated teergrube delay on the connection.
                        if reconnect_after is not None and reconnect_after != -1:
                            _do_rcpt_reconnect()
                    else:
                        consecutive_failures += 1
                        if (reconnect_after is not None and reconnect_after > 0
                                and consecutive_failures >= reconnect_after):
                            _do_rcpt_reconnect()
                if not self.use_json and enum_threads <= 1:
                    self._enum_progress_newline()
            else:
                locals_to_try = [u.split("@")[0].strip() for u in self.wordlist if not _skip(u.split("@")[0].strip())]
                work_total = len(locals_to_try)
                user_queue: queue.Queue[str | None] = queue.Queue()
                for local in locals_to_try:
                    user_queue.put(local)
                for _ in range(enum_threads):
                    user_queue.put(None)
                result_lock = threading.Lock()
                # ptlibs-style live progress + PrintLock per-item output (utils/progress.py).
                progress = ThreadedProgress(work_total, enabled=not self.use_json)

                def rcpt_worker() -> None:
                    conn = None
                    while True:
                        local = user_queue.get()
                        if local is None:
                            user_queue.task_done()
                            break
                        label = f"{local}@{domain}"
                        out = progress.new_output()
                        try:
                            if conn is None:
                                try:
                                    conn = self.get_smtp_handler()
                                    conn.docmd("EHLO", f"{self.fqdn}")
                                    if supports_smtputf8:
                                        conn.command_encoding = "utf-8"
                                    self._try_mail_from_for_rcpt_probe(conn, domain)
                                except Exception:
                                    continue
                            try:
                                status, reply = conn.docmd("RCPT TO:", f"<{local}@{domain}>")
                            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                                try:
                                    conn = self.get_smtp_handler()
                                    conn.docmd("EHLO", f"{self.fqdn}")
                                    if supports_smtputf8:
                                        conn.command_encoding = "utf-8"
                                    self._try_mail_from_for_rcpt_probe(conn, domain)
                                    status, reply = conn.docmd("RCPT TO:", f"<{local}@{domain}>")
                                except Exception:
                                    continue
                            if status != 550 and not self._rcpt_reply_has_unknown(reply):
                                if self.use_json:
                                    self.ptdebug(label)
                                else:
                                    out.add_string_to_output(label)
                                with result_lock:
                                    enumerated_users.append(label)
                        finally:
                            if not self.use_json:
                                progress.flush(out, repaint=False)
                                progress.advance(label=local)
                            user_queue.task_done()

                threads_list = [threading.Thread(target=rcpt_worker) for _ in range(enum_threads)]
                for t in threads_list:
                    t.start()
                for t in threads_list:
                    t.join()
                if not self.use_json:
                    progress.finalize()

            self.ptdebug(f" ")
            self.ptdebug(f"-- Enumerated {len(enumerated_users)} users --")
            self.ptdebug(f" ")

            self.already_enumerated = True
            return enumerated_users
        finally:
            self._enum_clock_shutdown()

    def test_enumeration(self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool | None]):
        if self.args.enumerate is None:
            return None

        if self.args.enumerate == "ALL":
            self.args.enumerate = ["VRFY", "EXPN", "RCPT"]

        try:
            if "EXPN" in self.args.enumerate:
                enumeration_vulns.update({"expn": self.expn_vrfy_test("EXPN", smtp)})
            if "VRFY" in self.args.enumerate:
                enumeration_vulns.update({"vrfy": self.expn_vrfy_test("VRFY", smtp)})
            if "RCPT" in self.args.enumerate:
                enumeration_vulns.update({"rcpt": self.rcpt_test(smtp)})
        except Exception as e:
            msg = (
                f"Connection terminated with server "
                f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
            )
            self._fail(msg)

    def test_slowdown_enumeration(
        self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool | None]
    ):
        if self.args.enumerate is None:
            return None

        self.slow_down_results = {"expn": False, "vrfy": False, "rcpt": False}
        if "EXPN" in self.args.enumerate and enumeration_vulns["expn"]:
            self.slow_down_results.update(self.expn_vrfy_slow_down_test("EXPN", smtp))
        if "VRFY" in self.args.enumerate and enumeration_vulns["vrfy"]:
            self.slow_down_results.update(self.expn_vrfy_slow_down_test("VRFY", smtp))
        if "RCPT" in self.args.enumerate and enumeration_vulns["rcpt"]:
            self.slow_down_results.update(self.rcpt_slow_down_test(smtp))

        self.ptdebug("Slow-Down results:", Out.INFO)
        for key, value in self.slow_down_results.items():
            self.ptdebug(f"{key}:{bool(value)}")

    def do_enumeration(
        self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool]
    ) -> dict[str, list[str] | None]:
        """OWASP: skip enumeration when catch-all would make results unreliable."""
        enumeration_results: dict[str, list[str] | None] = {
            "expn": None,
            "vrfy": None,
            "rcpt": None,
        }
        catch_all = getattr(self.results, "catch_all", None)

        if enumeration_vulns["expn"]:
            if catch_all == "configured":
                self.ptdebug("Skipping EXPN enumeration: catch-all configured (results would be false positives)", Out.INFO)
            else:
                enumeration_results["expn"] = self.expn_vrfy_enumeration("EXPN", smtp)
        elif enumeration_vulns["vrfy"]:
            if catch_all == "configured":
                self.ptdebug("Skipping VRFY enumeration: catch-all configured (results would be false positives)", Out.INFO)
            else:
                enumeration_results["vrfy"] = self.expn_vrfy_enumeration("VRFY", smtp)
        elif enumeration_vulns["rcpt"]:
            if catch_all in (*CATCH_ALL_INDETERMINATE_VARIANTS, "configured"):
                self.ptdebug(
                    f"Skipping RCPT enumeration: catch-all {catch_all} (results would be false positives)",
                    Out.INFO,
                )
            else:
                enumeration_results["rcpt"] = self.rcpt_enumeration(smtp)

        return enumeration_results

    def enumeration(self, smtp: smtplib.SMTP) -> list[EnumResult]:
        enumeration_vulns: dict[str, bool | None] = {
            "expn": None,
            "vrfy": None,
            "rcpt": None,
        }
        enumeration_results = None
        self._enum_blocked_by_rbl = set()
        self._rcpt_enum_mail_from_ok = None  # RCPT MAIL FROM: winner for this run (reconnect reuse)
        self._enum_progress_line_dirty = False

        self.test_enumeration(smtp, enumeration_vulns)

        if self.args.slow_down:
            self.test_slowdown_enumeration(smtp, enumeration_vulns)

        enumeration_results: dict[str, list[str] | None] | None = None
        catch_all = getattr(self.results, "catch_all", None)
        self._enum_methods_streamed_early = False
        self._enum_hits_streamed_live = False

        if self.wordlist is not None:
            if not self.use_json:
                partial_enum_rows: list[EnumResult] = []
                for method in enumeration_vulns.keys():
                    if (vulnerable := enumeration_vulns[method]) is not None:
                        if self.args.slow_down:
                            slow_down = self.slow_down_results[method]
                        else:
                            slow_down = None
                        test_replies = getattr(self, "_enum_test_replies", {})
                        server_reply = test_replies.get(method)
                        blocked_by_rbl = method in getattr(self, "_enum_blocked_by_rbl", set())
                        partial_enum_rows.append(
                            EnumResult(method, vulnerable, slow_down, None, server_reply, blocked_by_rbl)
                        )
                self._stream_enumeration_method_rows(partial_enum_rows, catch_all)
                self._enum_methods_streamed_early = True
                if self._wordlist_enumeration_will_run(enumeration_vulns, catch_all):
                    self.ptprint("Enumerated", Out.INFO)
                    sys.stdout.flush()
                    self._enum_progress_start = time.time()
                    self._enum_hits_streamed_live = True
            enumeration_results = self.do_enumeration(smtp, enumeration_vulns)

        enum_results: list[EnumResult] = []

        for method in enumeration_vulns.keys():
            if (vulnerable := enumeration_vulns[method]) is not None:
                if self.args.slow_down:
                    slow_down = self.slow_down_results[method]
                else:
                    slow_down = None

                if self.wordlist is not None and enumeration_results is not None:
                    wordlist_result = enumeration_results[method]
                else:
                    wordlist_result = None

                test_replies = getattr(self, "_enum_test_replies", {})
                server_reply = test_replies.get(method)
                blocked_by_rbl = method in getattr(self, "_enum_blocked_by_rbl", set())
                enum_results.append(
                    EnumResult(method, vulnerable, slow_down, wordlist_result, server_reply, blocked_by_rbl)
                )

        return enum_results

    def _stream_enumeration_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (enum_error := self.results.enum_error) is not None:
            pp(f"Enumeration test failed: {enum_error}", bullet_type="VULN", condition=show, indent=4)
            return
        enum_results = self.results.enum_results
        if enum_results is None:
            return
        catch_all = getattr(self.results, "catch_all", None)
        if self.args.enumerate is None:
            requested_set = {"EXPN", "VRFY", "RCPT"}
        elif isinstance(self.args.enumerate, list):
            requested_set = {m.upper() for m in self.args.enumerate if m}
        else:
            requested_set = {self.args.enumerate.upper()} if self.args.enumerate else {"EXPN", "VRFY", "RCPT"}
        filtered = [e for e in enum_results if e.method.upper() in requested_set]
        skip_methods = getattr(self, "_enum_methods_streamed_early", False)
        skip_hits = getattr(self, "_enum_hits_streamed_live", False)
        if skip_methods:
            self._enum_methods_streamed_early = False
        if skip_hits:
            self._enum_hits_streamed_live = False

        if not skip_methods:
            for e in filtered:
                if catch_all == "configured":
                    pp(f"{e.method.upper()} method: Indeterminate (Useless due to Catch All)",
                       bullet_type="WARNING", condition=show, indent=4)
                elif e.blocked_by_rbl:
                    pp(f"{e.method.upper()} method protected by RBL/Reputation (Client IP blocked)",
                       bullet_type="NOTVULN", condition=show, indent=4)
                    if e.server_reply:
                        for line in (e.server_reply or "").replace("\r", "").splitlines():
                            pp(line.strip(), bullet_type="TEXT", condition=show, indent=8)
                else:
                    slowdown = ""
                    if e.slowdown is not None:
                        slowdown = " (rate limited)" if e.slowdown else " (not rate limited)"
                    verdict_bullet = "VULN" if e.vulnerable else "NOTVULN"
                    if e.vulnerable:
                        if e.server_reply:
                            raw = (e.server_reply or "").replace("\r", "").splitlines()
                            parts = [re.sub(r" +", " ", p.strip()) for p in raw if p.strip()]
                            if parts:
                                if len(parts) == 1:
                                    pp(f"{e.method.upper()} method is enabled ({parts[0]}){slowdown}",
                                       bullet_type=verdict_bullet, condition=show, indent=4)
                                else:
                                    pp(
                                        f"{e.method.upper()} method is enabled ({parts[0]}{')' if len(parts) == 1 else ''}{slowdown if len(parts) == 1 else ''}",
                                        bullet_type=verdict_bullet, condition=show, indent=4,
                                    )
                                    for i, part in enumerate(parts[1:]):
                                        is_last = i == len(parts) - 2
                                        pp(f"{part}{')' if is_last else ''}{slowdown if is_last else ''}",
                                           bullet_type="TEXT", condition=show, indent=8)
                            else:
                                pp(f"{e.method.upper()} method is enabled{slowdown}",
                                   bullet_type=verdict_bullet, condition=show, indent=4)
                        else:
                            pp(f"{e.method.upper()} method is enabled{slowdown}",
                               bullet_type=verdict_bullet, condition=show, indent=4)
                    else:
                        # Show policy note when available (relay protection / admin prohibition)
                        if e.server_reply and "Relay protection active" in e.server_reply:
                            status = "is deny (Relay protection active)"
                        elif e.server_reply and "Administrative prohibition" in e.server_reply:
                            status = "is deny (Administrative prohibition)"
                        else:
                            status = "is deny"
                        pp(f"{e.method.upper()} method {status}{slowdown}",
                           bullet_type=verdict_bullet, condition=show, indent=4)
        if not skip_hits:
            for e in filtered:
                if e.vulnerable and (results := e.results) is not None:
                    sorted_results = sorted(results, key=str)
                    for r in sorted_results:
                        pp(str(r), bullet_type="TEXT", condition=show, indent=4)
        if catch_all == "configured":
            pp("Catch All mailbox configured", bullet_type="TITLE", condition=show, indent=4)
        elif catch_all == "not_configured":
            pp("Catch All mailbox not configured", bullet_type="TITLE", condition=show, indent=4)
        elif catch_all == "indeterminate_accept_all_rcpt":
            pp("Catch All mailbox indeterminate (accept-all via RCPT)", bullet_type="TITLE", condition=show, indent=4)
        elif catch_all == "indeterminate":
            pp("Catch All mailbox indeterminate", bullet_type="TITLE", condition=show, indent=4)
