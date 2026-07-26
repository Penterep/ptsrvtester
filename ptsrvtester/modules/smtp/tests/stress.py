import ipaddress, queue, shutil, smtplib, socket, ssl, statistics, sys, threading, time


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
from ...utils import ptprinthelper
from ...utils.ptprinthelper import get_colored_text

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from ..helpers import *
from ..results import *
from ..registry import *


class StressMixin:

    def rate_limit_test(self) -> RateLimitResult:
        """Rate limiting test – parallel connection flood with two timeout probes.

        Flow:
          1. Connection A: connect + read 220 banner only (no EHLO). Start a watcher
             thread that waits for the server to close the idle banner-only session and
             records the elapsed "Initial response timeout".
          2. Connection B: connect + EHLO. Watcher thread records the "Idle timeout".
          3. Ramp-up: keep opening additional banner-only connections (sequential,
             small delay) until the server refuses (ban) or the attempt budget is hit.
          4. Ban-duration probe (only if banned): retry a new connection every 5 s
             until one is accepted (or the 5 min cap is hit).
          5. Wait for A and B watchers (or their 5 min caps) and emit verdicts.

        A and B run concurrently with steps 3–4; their results are reported as soon
        as they are available (or after the ban-duration step, whichever is later).
        """
        # Live progress stays on when -vv (--verbose → args.debug); only JSON mode disables it.
        _show_progress = not self.args.json
        max_attempts = getattr(self.args, "rate_limit", None) or RATE_LIMIT_DEFAULT_ATTEMPTS
        return self._rate_limit_test_impl(_show_progress, max_attempts)

    def _rate_limit_test_impl(
        self, _show_progress: bool, max_attempts: int
    ) -> RateLimitResult:
        MAX_TIMEOUT = RATE_LIMIT_TIMEOUT_CAP_SECONDS
        MAX_BAN_WAIT = RATE_LIMIT_TIMEOUT_CAP_SECONDS
        RETRY_INTERVAL = 5
        PHASE1_DELAY = 0.15  # seconds between connection attempts (ramp-up)

        _print_lock = threading.Lock()

        self.ptdebug("Rate limiting test", title=True)
        self.ptdebug(
            f"Target {self.args.target.ip}:{self.args.target.port} — up to {max_attempts} parallel "
            f"sessions (ramp {PHASE1_DELAY}s), ban duration probe max {MAX_BAN_WAIT}s, "
            f"banner/idle timeout cap {MAX_TIMEOUT}s."
        )

        def _write_live(label: str, value: str) -> None:
            line = f"    {label} {value}"
            with _print_lock:
                sys.stdout.write(f"\r{line:<120}")
                sys.stdout.flush()

        def _finalize_line(label: str, value: str) -> None:
            line = f"    {label} {value}"
            with _print_lock:
                sys.stdout.write(f"\r{line:<120}\n")
                sys.stdout.flush()

        def _fmt_mmss(seconds: float) -> str:
            return f"{int(seconds // 60):02d}:{int(seconds % 60):02d}"

        def _print_verdict(is_vuln: bool, text: str) -> None:
            ptprinthelper.ptprint(
                text, bullet_type="VULN" if is_vuln else "NOTVULN",
                condition=not self.use_json, indent=8,
            )

        def _print_info(text: str) -> None:
            ptprinthelper.ptprint(text, bullet_type="TITLE",
                                  condition=not self.use_json, indent=8)

        # ── Background watcher: blocks on socket.recv() until the server
        # closes / replies (or the cap is reached) and records the elapsed time.
        def _watch_disconnect(
            smtp,
            start_time: float,
            cap_seconds: float,
            result_cell: list,
            stop_event: threading.Event,
        ) -> None:
            sock = getattr(smtp, "sock", None)
            if sock is None:
                return
            try:
                sock.settimeout(1.0)
            except Exception:
                pass
            while not stop_event.is_set():
                elapsed = time.perf_counter() - start_time
                if elapsed >= cap_seconds:
                    if not result_cell:
                        result_cell.append((cap_seconds, True))
                    return
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                except Exception:
                    if not result_cell and not stop_event.is_set():
                        result_cell.append((time.perf_counter() - start_time, False))
                    return
                # recv returned: either 0 bytes (clean close) or some data (server
                # sent e.g. 421 before closing). In both cases the session is
                # effectively over → record elapsed time and exit.
                if not result_cell and not stop_event.is_set():
                    result_cell.append((time.perf_counter() - start_time, False))
                return

        # ── Phase 1: open A (banner-only), B (after EHLO), then ramp-up
        # Sequential ramp-up: opening many connections in parallel overwhelms the
        # kernel accept queue before the SMTP daemon (anvil) can count them, so a
        # small delay between attempts produces cleaner 421 rejections at the real
        # server limit.
        connections: list = []
        _first_error: list[str | None] = [None]
        watcher_stop = threading.Event()

        a_start_time: float | None = None
        b_start_time: float | None = None
        a_result: list = []
        b_result: list = []

        if _show_progress:
            _write_live("Connected:", "0")

        # Connection A: banner only (no EHLO)
        try:
            smtp_a = self._connect_silent(send_ehlo=False)
            a_start_time = time.perf_counter()
            connections.append(smtp_a)
            threading.Thread(
                target=_watch_disconnect,
                args=(smtp_a, a_start_time, MAX_TIMEOUT, a_result, watcher_stop),
                daemon=True,
            ).start()
            self.ptdebug(
                "Session A (banner-only, no EHLO): TCP open after 220; watcher thread measures "
                "idle disconnect / initial-response timeout.",
                Out.INFO,
            )
            if _show_progress:
                _write_live("Connected:", str(len(connections)))
        except Exception as exc:
            self.ptdebug(f"Session A (banner-only): connect failed — {exc}", Out.INFO)
            _first_error[0] = str(exc)

        time.sleep(PHASE1_DELAY)

        # Connection B: banner + EHLO
        try:
            smtp_b = self._connect_silent(send_ehlo=True)
            b_start_time = time.perf_counter()
            connections.append(smtp_b)
            threading.Thread(
                target=_watch_disconnect,
                args=(smtp_b, b_start_time, MAX_TIMEOUT, b_result, watcher_stop),
                daemon=True,
            ).start()
            self.ptdebug(
                "Session B (banner + EHLO): established; watcher thread measures idle timeout after EHLO.",
                Out.INFO,
            )
            if _show_progress:
                _write_live("Connected:", str(len(connections)))
        except Exception as exc:
            self.ptdebug(f"Session B (EHLO): connect failed — {exc}", Out.INFO)
            if _first_error[0] is None:
                _first_error[0] = str(exc)

        # If we failed to set up any connection at all, fail fast.
        if not connections:
            raise TestFailedError(_first_error[0] or "Could not establish any connection")

        # Remaining ramp-up attempts (banner-only) until ban or budget exhausted.
        banned = False
        remaining = max_attempts - len(connections)
        for _ in range(max(remaining, 0)):
            time.sleep(PHASE1_DELAY)
            try:
                smtp_extra = self._connect_silent(send_ehlo=False)
            except Exception as exc:
                self.ptdebug(
                    f"Ramp-up: next banner-only connection refused or failed — {exc}",
                    Out.INFO,
                )
                if _first_error[0] is None:
                    _first_error[0] = str(exc)
                banned = True
                break
            connections.append(smtp_extra)
            self.ptdebug(
                f"Ramp-up [{len(connections)}/{max_attempts}]: banner-only session established.",
                Out.INFO,
            )
            if _show_progress:
                _write_live("Connected:", str(len(connections)))

        connected = len(connections)
        if _show_progress:
            _finalize_line("Connected:", str(connected))

        self.ptdebug(f"Ramp-up: {connected}/{max_attempts} connections established.")
        if banned:
            self.ptdebug(f"Ramp-up stopped: {_first_error[0]}")

        # Verdicts for the "Connected" block.
        # When banned with >=50 connections: info line [*] plus [✗] threshold line below.
        # When banned with <50 connections: only [OK] (no redundant [*] line).
        if banned and connected >= RATE_LIMIT_CONN_VULN_THRESHOLD:
            _print_info(f"You are banned when {connected} threads was connected")
        elif not banned:
            ptprinthelper.ptprint(
                f"No blocking occurred despite a large number of "
                f"established connections ({connected} connections are active)",
                bullet_type="VULN", condition=not self.use_json, indent=8,
            )

        if connected >= RATE_LIMIT_CONN_VULN_THRESHOLD:
            _print_verdict(
                True,
                f"More then {RATE_LIMIT_CONN_VULN_THRESHOLD} simultaneous SMTP connections "
                "from one IP accepted is too much",
            )
        elif banned:
            _print_verdict(False, f"You are banned when {connected} threads was connected")

        # ── Ban duration probe (only when the server actually banned us) ────
        ban_duration_seconds: float | None = None
        ban_duration_exceeded = False
        ban_duration_probe_ran = False

        if banned:
            ban_duration_probe_ran = True
            start_rl = time.perf_counter()
            _rl_stop = threading.Event()
            self.ptdebug(
                f"Ban duration probe: retry every {RETRY_INTERVAL}s until reconnect or {MAX_BAN_WAIT}s cap.",
                Out.INFO,
            )

            if _show_progress:
                _write_live("Ban duration:", "00:00")

                def _rl_ticker() -> None:
                    while not _rl_stop.wait(0.5):
                        elapsed = time.perf_counter() - start_rl
                        _write_live("Ban duration:", _fmt_mmss(elapsed))

                threading.Thread(target=_rl_ticker, daemon=True).start()

            _ban_try = 0
            while True:
                elapsed = time.perf_counter() - start_rl
                if elapsed >= MAX_BAN_WAIT:
                    ban_duration_exceeded = True
                    ban_duration_seconds = elapsed
                    break
                try:
                    probe = self._connect_silent(send_ehlo=False)
                    ban_duration_seconds = time.perf_counter() - start_rl
                    self.ptdebug(
                        f"Ban probe: reconnect succeeded after {ban_duration_seconds:.2f}s "
                        f"(attempt #{_ban_try + 1}).",
                        Out.INFO,
                    )
                    try:
                        probe.close()
                    except Exception:
                        pass
                    break
                except Exception as exc:
                    _ban_try += 1
                    self.ptdebug(f"Ban probe attempt #{_ban_try}: connect failed — {exc}", Out.INFO)
                wait_end = time.perf_counter() + RETRY_INTERVAL
                while time.perf_counter() < wait_end:
                    time.sleep(0.2)

            _rl_stop.set()

            if _show_progress:
                _finalize_line(
                    "Ban duration:",
                    _rate_limit_duration_display(ban_duration_seconds, ban_duration_exceeded),
                )

            if ban_duration_exceeded:
                self.ptdebug(
                    f"Ban duration: no new connection within {MAX_BAN_WAIT}s (cap)."
                )
                _print_verdict(False, "Ban is bigger then 30s")
            else:
                if ban_duration_seconds is not None:
                    self.ptdebug(
                        f"Ban duration summary: reconnect accepted after {ban_duration_seconds:.2f}s.",
                        Out.INFO,
                    )
                if (
                    ban_duration_seconds is not None
                    and ban_duration_seconds < RATE_LIMIT_BAN_MIN_SECONDS
                ):
                    _print_verdict(True, "Ban duration is too low")
                else:
                    _print_verdict(False, "Ban is bigger then 30s")

        # ── Wait for A and B watchers, print each as it finishes ───────────
        def _await_and_report(
            start_time: float | None,
            result_cell: list,
            label: str,
            cap: float,
            threshold: float,
            bad_msg: str,
            ok_msg: str,
        ) -> tuple[float | None, bool]:
            if start_time is None:
                if _show_progress:
                    _finalize_line(label, "N/A")
                return None, False

            deadline = start_time + cap + 2.0  # small grace beyond cap

            # If the watcher already finished during earlier phases, skip the live
            # ticker entirely and jump straight to the final line below.
            if _show_progress and not result_cell:
                _write_live(label, _fmt_mmss(time.perf_counter() - start_time))
                live_stop = threading.Event()

                def _tick() -> None:
                    while not live_stop.wait(0.5):
                        if result_cell:
                            return
                        _write_live(label, _fmt_mmss(time.perf_counter() - start_time))

                threading.Thread(target=_tick, daemon=True).start()
                while not result_cell and time.perf_counter() < deadline:
                    time.sleep(0.2)
                live_stop.set()
            else:
                while not result_cell and time.perf_counter() < deadline:
                    time.sleep(0.2)

            if not result_cell:
                # Watcher is still stuck – force a cap reading.
                result_cell.append((cap, True))

            elapsed, exceeded = result_cell[0]
            disp = _rate_limit_duration_display(elapsed, exceeded)
            self.ptdebug(
                f"{label.strip()} measured {disp}"
                + (" (hit hard cap)" if exceeded else " (peer closed or replied)"),
                Out.INFO,
            )
            if _show_progress:
                _finalize_line(label, disp)

            if exceeded or elapsed > threshold:
                _print_verdict(True, bad_msg)
            else:
                _print_verdict(False, ok_msg)
            return elapsed, exceeded

        initial_seconds, initial_exceeded = _await_and_report(
            a_start_time,
            a_result,
            "Initial response timeout (without EHLO):",
            MAX_TIMEOUT,
            RATE_LIMIT_INITIAL_TIMEOUT_MAX_SECONDS,
            f"Timeout is too long (more then {RATE_LIMIT_INITIAL_TIMEOUT_MAX_SECONDS}s)",
            f"Timeout is lower then {RATE_LIMIT_INITIAL_TIMEOUT_MAX_SECONDS}s",
        )

        idle_seconds, idle_exceeded = _await_and_report(
            b_start_time,
            b_result,
            "Idle timeout (after EHLO):",
            MAX_TIMEOUT,
            RATE_LIMIT_IDLE_TIMEOUT_MAX_SECONDS,
            f"Timeout is too long (more then {RATE_LIMIT_IDLE_TIMEOUT_MAX_SECONDS}s)",
            f"Timeout is lower then {RATE_LIMIT_IDLE_TIMEOUT_MAX_SECONDS}s",
        )

        # Signal any remaining watchers (cap-hit A/B) to exit, then close all sockets.
        watcher_stop.set()
        for conn in connections:
            try:
                conn.close()
            except Exception:
                pass

        self.ptdebug(
            f"Summary: connected={connected}, banned={banned}, "
            f"ban_duration_seconds={ban_duration_seconds!s}, "
            f"initial_timeout_seconds={initial_seconds!s}, "
            f"idle_timeout_seconds={idle_seconds!s}."
        )

        return RateLimitResult(
            connected=connected,
            max_attempts=max_attempts,
            banned=banned,
            ban_duration_probe_ran=ban_duration_probe_ran,
            ban_duration_seconds=ban_duration_seconds,
            ban_duration_exceeded=ban_duration_exceeded,
            initial_timeout_seconds=initial_seconds,
            initial_timeout_exceeded=initial_exceeded,
            idle_timeout_seconds=idle_seconds,
            idle_timeout_exceeded=idle_exceeded,
        )

    # ── NOOP flooding tests ────────────────────────────────────────────────
    @staticmethod
    def _noop_read_one_reply(sock: socket.socket) -> tuple[int | None, bytes, bool]:
        """Read one SMTP reply (multi-line aware) from a raw socket.

        Returns (status, raw, closed): ``status`` is the 3-digit reply code
        (``None`` on timeout / parse error), ``raw`` is the full reply bytes,
        ``closed`` is True when the server closed the socket (or reset it)
        before a complete reply was received.
        """
        buf = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                return None, bytes(buf), False
            except (OSError, ConnectionError):
                return None, bytes(buf), True
            if not chunk:
                return None, bytes(buf), True
            buf.extend(chunk)
            # Parse reply line-by-line until we hit the final line ("XYZ ..." or "\r\n").
            text = buf.decode("latin-1", errors="replace")
            lines = text.split("\r\n")
            if len(lines) < 2:
                continue
            final_line = None
            for line in lines[:-1]:
                if len(line) >= 4 and line[3:4] == " " and line[:3].isdigit():
                    final_line = line
                    break
            if final_line is not None:
                try:
                    return int(final_line[:3]), bytes(buf), False
                except ValueError:
                    return None, bytes(buf), False

    @staticmethod
    def _noop_flood1_live_progress_text(sent: int, elapsed_seconds: float) -> str:
        """Live ``-ts NOOP1`` progress: ``NOOPs sent: N - Xs left`` (ETA vs command cap)."""
        total = NOOP_FLOOD1_MAX_COMMANDS
        if sent <= 0:
            return f"NOOPs sent: {sent}"
        remaining = max(0, int((total - sent) * (elapsed_seconds / sent)))
        return f"NOOPs sent: {sent} - {remaining}s left"

    @staticmethod
    def _noop_flood1_debug_line(
        commands_sent: int, status: int | None, rt_seconds: float,
    ) -> str:
        """``-vv`` line every ``NOOP_FLOOD1_PROGRESS_EVERY`` commands (via ``ptdebug``)."""
        if status == 250:
            status_part = "250 OK"
        elif status is None:
            status_part = "no reply"
        else:
            status_part = str(status)
        return (
            f"NOOP #{commands_sent}: {status_part} "
            f"(reaction time: {rt_seconds * 1000:.0f}ms)"
        )

    def noop_flood_test_single(self) -> NoopFlood1Result:
        """``-ts NOOP1``: rapid NOOP flood in a single connection (RFC 5321 §4.1.1.9 expects 250)."""
        # Make `-vv` show the standard "Initial server information" header
        # (banner + EHLO response) before the storm — same UX as `-rl`.
        self._ensure_initial_info(fail_label="NOOP flood (single connection)")

        if self.args.debug and not self.args.json:
            sys.stdout.write("\n")
            sys.stdout.flush()

        self.ptdebug(
            f"NOOP Flooding test ({NOOP_FLOOD1_MAX_COMMANDS} NOOPs in 1 connection)",
            title=True,
        )
        self.ptdebug(
            f"Target {self.args.target.ip}:{self.args.target.port} — up to "
            f"{NOOP_FLOOD1_MAX_COMMANDS} NOOPs (hard cap: {NOOP_FLOOD1_OVERALL_CAP_SECONDS:.0f}s, "
            f"per-reply timeout: {NOOP_FLOOD1_TIMEOUT_SECONDS:.0f}s)."
        )

        smtp = self._connect_silent(timeout=NOOP_FLOOD1_TIMEOUT_SECONDS, send_ehlo=True)
        sock = smtp.sock
        try:
            sock.settimeout(NOOP_FLOOD1_TIMEOUT_SECONDS)
        except Exception:
            pass

        _show_progress = not self.args.json
        _print_lock = threading.Lock()
        _live_line_dirty = False

        def _write_live(text: str) -> None:
            if not _show_progress:
                return
            nonlocal _live_line_dirty
            with _print_lock:
                sys.stdout.write(f"\033[2K\r    {text:<110}")
                sys.stdout.flush()
                _live_line_dirty = True

        def _clear_live_line() -> None:
            """Erase the in-place progress row without leaving a blank line."""
            nonlocal _live_line_dirty
            if not _show_progress or not _live_line_dirty:
                return
            with _print_lock:
                sys.stdout.write("\033[2K\r")
                sys.stdout.flush()
            _live_line_dirty = False

        def _finalize_live() -> None:
            _clear_live_line()

        commands_sent = 0
        commands_ok = 0
        commands_error = 0
        rtts: list[float] = []     # all successful round-trip times (for baseline/last-window stats)
        disconnected = False
        disconnect_after: int | None = None
        hit_command_cap = False
        hit_time_cap = False
        overall_start = time.perf_counter()

        try:
            while commands_sent < NOOP_FLOOD1_MAX_COMMANDS:
                elapsed_total = time.perf_counter() - overall_start
                if elapsed_total >= NOOP_FLOOD1_OVERALL_CAP_SECONDS:
                    hit_time_cap = True
                    break

                t0 = time.perf_counter()
                try:
                    sock.sendall(b"NOOP\r\n")
                except (OSError, ConnectionError) as exc:
                    commands_sent += 1
                    commands_error += 1
                    disconnected = True
                    disconnect_after = commands_sent
                    if self.args.debug:
                        self.ptdebug(
                            f"NOOP #{commands_sent}: send failed — {exc}",
                            Out.INFO,
                            indent_override=8,
                        )
                    break

                status, raw, closed = self._noop_read_one_reply(sock)
                rt = time.perf_counter() - t0
                commands_sent += 1

                if status == 250:
                    commands_ok += 1
                    rtts.append(rt)
                else:
                    commands_error += 1

                # Periodic live progress (non-debug only; -vv uses per-N NOOP lines instead).
                if (
                    _show_progress
                    and not self.args.debug
                    and (commands_sent % NOOP_FLOOD1_PROGRESS_EVERY == 0)
                ):
                    _write_live(
                        self._noop_flood1_live_progress_text(
                            commands_sent, time.perf_counter() - overall_start,
                        )
                    )

                # -vv: snapshot every Nth NOOP (ADDITIONS colour, 8-space indent).
                if self.args.debug and (commands_sent % NOOP_FLOOD1_PROGRESS_EVERY == 0):
                    self.ptdebug(
                        self._noop_flood1_debug_line(commands_sent, status, rt),
                        indent_override=8,
                    )

                if closed:
                    disconnected = True
                    disconnect_after = commands_sent
                    if self.args.debug:
                        self.ptdebug(
                            f"NOOP #{commands_sent}: peer closed connection "
                            f"(after {commands_sent} NOOPs).",
                            Out.INFO,
                            indent_override=8,
                        )
                    break
            else:
                hit_command_cap = True
        finally:
            _finalize_live()  # erase in-place ``NOOPs sent: …`` before verdict output
            try:
                smtp.close()
            except Exception:
                pass

        min_rt = min(rtts) if rtts else None
        max_rt = max(rtts) if rtts else None
        avg_rt = (sum(rtts) / len(rtts)) if rtts else None

        # Baseline = mean of the first ≤10 successful NOOPs; last window = last ≤10.
        window = 10
        baseline_avg = (sum(rtts[:window]) / min(len(rtts), window)) if rtts else None
        last_rtts = rtts[-window:] if len(rtts) >= window else rtts
        last_window_avg = (sum(last_rtts) / len(last_rtts)) if last_rtts else None

        slowdown_detected = False
        if baseline_avg is not None and last_window_avg is not None and len(rtts) >= window * 2:
            ratio_ok = last_window_avg >= baseline_avg * NOOP_FLOOD_SLOWDOWN_MIN_RATIO
            abs_ok = last_window_avg >= NOOP_FLOOD_SLOWDOWN_MIN_SECONDS
            slowdown_detected = ratio_ok or abs_ok

        error_rate_pct = (100.0 * commands_error / commands_sent) if commands_sent else 0.0

        self.ptdebug(
            f"Summary: sent={commands_sent}, ok={commands_ok}, error={commands_error} "
            f"({error_rate_pct:.1f}%), disconnected={disconnected} "
            f"(after={disconnect_after}), baseline_avg={baseline_avg}, "
            f"last_window_avg={last_window_avg}, slowdown={slowdown_detected}.",
            Out.INFO,
        )
        if self.args.debug and not self.args.json:
            sys.stdout.write("\n")
            sys.stdout.flush()

        return NoopFlood1Result(
            commands_sent=commands_sent,
            commands_ok=commands_ok,
            commands_error=commands_error,
            disconnected=disconnected,
            disconnect_after=disconnect_after,
            hit_command_cap=hit_command_cap,
            hit_time_cap=hit_time_cap,
            min_rt_seconds=min_rt,
            max_rt_seconds=max_rt,
            avg_rt_seconds=avg_rt,
            baseline_avg_seconds=baseline_avg,
            last_window_avg_seconds=last_window_avg,
            slowdown_detected=slowdown_detected,
            error_rate_pct=error_rate_pct,
        )

    @staticmethod
    def _socket_already_closed(sock: socket.socket) -> bool:
        """Non-blocking probe: True if the peer has already closed the socket.

        A healthy idle SMTP socket has no pending data → ``recv`` raises
        ``BlockingIOError`` (treated as alive). A server-closed socket is readable
        and returns ``b""`` (clean FIN) or raises a connection error (RST).
        """
        if sock is None:
            return True
        try:
            sock.setblocking(False)
        except (OSError, ValueError):
            return True
        try:
            chunk = sock.recv(4096)
            if chunk == b"":
                return True  # clean FIN from the server
            return False     # stray data (e.g. a 4xx notice): treat as still alive
        except BlockingIOError:
            return False     # no data pending → connection still open
        except (OSError, ConnectionError):
            return True      # RST / already-dead socket
        finally:
            try:
                sock.setblocking(True)
                sock.settimeout(NOOP_FLOOD2_RECV_TIMEOUT)
            except (OSError, ValueError):
                pass

    @staticmethod
    def _classify_conn_failure(exc: BaseException) -> str:
        """Bucket a socket/connection failure into ``timeout`` / ``disconnect`` / ``error``."""
        if isinstance(exc, (socket.timeout, TimeoutError)):
            return "timeout"
        if isinstance(
            exc,
            (
                ConnectionRefusedError,
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
                smtplib.SMTPServerDisconnected,
            ),
        ):
            return "disconnect"
        msg = str(exc).lower()
        if "timed out" in msg or "timeout" in msg:
            return "timeout"
        if any(k in msg for k in ("refused", "reset", "disconnect", "closed", "broken pipe", "aborted")):
            return "disconnect"
        return "error"

    def noop_flood_test_parallel(self) -> NoopFlood2Result:
        """-nf2: parallel-connection NOOP DoS. Opens up to N sockets, each sends NOOPs
        as fast as possible for ``NOOP_FLOOD2_RUN_SECONDS`` seconds; aggregates error
        rate and average command reaction time across all threads."""
        # Show the standard "Initial server information" header in -vv before any
        # storm-related log lines (mirrors the -rl flow).
        self._ensure_initial_info(fail_label="-nf2 parallel storm")

        requested = getattr(self.args, "noop_flood2", None) or NOOP_FLOOD2_DEFAULT_CONNECTIONS
        if requested > NOOP_FLOOD2_MAX_CONNECTIONS:
            self.ptdebug(
                f"-nf2: requested {requested} capped to {NOOP_FLOOD2_MAX_CONNECTIONS} "
                "(safety ceiling).",
                Out.INFO,
            )
            requested = NOOP_FLOOD2_MAX_CONNECTIONS

        self.ptdebug(
            f"NOOP Flooding DoS test ({requested} connections within "
            f"{int(NOOP_FLOOD2_RUN_SECONDS)} seconds)",
            title=True,
        )
        self.ptdebug(
            f"Target {self.args.target.ip}:{self.args.target.port} — up to {requested} sockets, "
            f"steady-state duration {NOOP_FLOOD2_RUN_SECONDS:.0f}s, per-reply timeout "
            f"{NOOP_FLOOD2_RECV_TIMEOUT:.0f}s."
        )

        _show_progress = not self.args.json
        _print_lock = threading.Lock()
        _live_dirty = False

        def _write_live(text: str) -> None:
            if not _show_progress:
                return
            nonlocal _live_dirty
            with _print_lock:
                sys.stdout.write(f"\033[2K\r    {text}")
                sys.stdout.flush()
                _live_dirty = True

        def _clear_live() -> None:
            """Erase the in-place live row (leaves no blank line behind)."""
            nonlocal _live_dirty
            if not _show_progress or not _live_dirty:
                return
            with _print_lock:
                sys.stdout.write("\033[2K\r")
                sys.stdout.flush()
            _live_dirty = False

        def _emit_debug(text: str) -> None:
            """Thread-safe ``-vv`` line that won't garble the in-place live row."""
            if not self.args.debug or self.args.json:
                return
            nonlocal _live_dirty
            with _print_lock:
                if _show_progress and _live_dirty:
                    sys.stdout.write("\033[2K\r")
                    sys.stdout.flush()
                    _live_dirty = False
                self.ptdebug(text)

        # ── Phase 1: establish sockets ───────────────────────────────────
        # Every requested socket is attempted (a refusal no longer aborts the
        # ramp-up); failures are bucketed so the analyst sees the real picture.
        # With -t/--threads > 1 the sockets are opened by several worker threads
        # so the pool fills faster (fewer early sockets reaped for idling). The
        # terminal output is identical regardless of the thread count.
        connections: list = []
        est_err = 0
        est_disc = 0
        est_timeout = 0
        ramp_t0 = time.perf_counter()
        ramp_threads = max(1, int(getattr(self.args, "enum_threads", 1) or 1))

        def _establish_one():
            """Open one EHLO'd socket; return (smtp|None, reason|None, exc|None)."""
            try:
                smtp = self._connect_silent(
                    timeout=NOOP_FLOOD2_CONNECT_TIMEOUT, send_ehlo=True
                )
                try:
                    smtp.sock.settimeout(NOOP_FLOOD2_RECV_TIMEOUT)
                except Exception:
                    pass
                return smtp, None, None
            except Exception as exc:
                return None, self._classify_conn_failure(exc), exc

        def _record_result(index: int, smtp, reason, exc) -> None:
            """Bucket one ramp-up outcome and refresh the live progress row."""
            nonlocal est_err, est_disc, est_timeout
            if smtp is not None:
                connections.append(smtp)
            else:
                if reason == "timeout":
                    est_timeout += 1
                elif reason == "disconnect":
                    est_disc += 1
                else:
                    est_err += 1
                _emit_debug(f"Connection #{index + 1} failed — {reason} ({exc})")
            if _show_progress:
                done = len(connections) + est_err + est_disc + est_timeout
                _write_live(
                    f"Connecting: {done}/{requested}     "
                    f"(elapsed {time.perf_counter() - ramp_t0:.1f}s)"
                )

        if ramp_threads <= 1:
            for i in range(requested):
                smtp, reason, exc = _establish_one()
                _record_result(i, smtp, reason, exc)
        else:
            ramp_lock = threading.Lock()
            next_index = [0]

            def _ramp_worker() -> None:
                while True:
                    with ramp_lock:
                        idx = next_index[0]
                        if idx >= requested:
                            return
                        next_index[0] = idx + 1
                    # Network I/O happens outside the lock so threads run in parallel.
                    smtp, reason, exc = _establish_one()
                    with ramp_lock:
                        _record_result(idx, smtp, reason, exc)

            ramp_workers = [
                threading.Thread(target=_ramp_worker, daemon=True)
                for _ in range(min(ramp_threads, requested))
            ]
            for w in ramp_workers:
                w.start()
            for w in ramp_workers:
                w.join()

        established = len(connections)
        _clear_live()
        if not connections:
            raise TestFailedError("Could not establish any connection for -nf2")

        # ── Pre-storm liveness sweep ─────────────────────────────────────
        # The ramp-up is sequential, so the first sockets sit idle while the
        # rest connect. Servers with a per-IP connection cap / idle reaper tear
        # those down before the storm even starts — meaning the pool was never
        # fully alive simultaneously. Detect sockets the server already closed
        # so they count as a connection-handling failure, not a storm casualty.
        live_connections: list = []
        reaped = 0
        for smtp in connections:
            if self._socket_already_closed(smtp.sock):
                reaped += 1
                try:
                    smtp.close()
                except Exception:
                    pass
            else:
                live_connections.append(smtp)
        connections = live_connections
        storm_pool = len(connections)

        # Ramp-up statistics (always visible). The storm treats the *live* pool
        # as 100% — a 100% error rate over 50 live sockets is a different story
        # from 100% errors over 50 sockets that were already gone.
        pp = ptprinthelper.ptprint
        show = not self.use_json
        pp(f"Established {established} connections", bullet_type="TITLE", condition=show, indent=4)
        pp(f"Errors {est_err} connections", bullet_type="TITLE", condition=show, indent=4)
        pp(f"Refused at connect {est_disc} connections", bullet_type="TITLE", condition=show, indent=4)
        pp(f"Timeout {est_timeout} connections", bullet_type="TITLE", condition=show, indent=4)
        pp(f"Dropped while idle {reaped} connections", bullet_type="TITLE", condition=show, indent=4)

        if storm_pool == 0:
            # Every established socket was already closed before we could storm.
            # Strong "server won't hold connections" signal — report, don't crash.
            self.ptdebug(
                f"-nf2: all {established} established sockets were closed before the "
                f"storm (reaped={reaped}); skipping NOOP phase.",
                Out.INFO,
            )
            return NoopFlood2Result(
                requested_connections=requested,
                established_connections=established,
                run_duration_seconds=0.0,
                commands_sent=0,
                commands_ok=0,
                commands_error=0,
                min_rt_seconds=None,
                max_rt_seconds=None,
                avg_rt_seconds=None,
                error_rate_pct=0.0,
                active_connections_end=0,
                disconnected_during_test=0,
                early_exit_no_connections=True,
                establish_errors=est_err,
                establish_disconnected=est_disc,
                establish_timeouts=est_timeout,
                reaped_before_storm=reaped,
                storm_pool_connections=0,
            )

        self.ptdebug(
            f"-nf2: {storm_pool}/{established} sockets alive after sweep "
            f"(reaped={reaped}); starting NOOP storm for {NOOP_FLOOD2_RUN_SECONDS:.0f}s.",
            Out.INFO,
        )

        # ── Phase 2: each thread hammers its socket with NOOPs ───────────
        stop_event = threading.Event()
        results_lock = threading.Lock()
        agg_commands_sent = 0
        agg_commands_ok = 0
        agg_commands_error = 0
        agg_rtts: list[float] = []
        # Per-connection terminations (index, reason, detail) collected as workers die.
        terminated_info: list[tuple[int, str, str]] = []
        # Live count of sockets still up. Decremented as soon as a worker exits
        # its hammer-loop (close/timeout/exception). Read by the progress ticker
        # to render `(active K/N)` and to detect the all-dropped condition.
        active_count = storm_pool

        FLUSH_EVERY = 32  # flush per-thread counters into the shared aggregates this often

        def _flush(local_sent, local_ok, local_err, local_rtts) -> None:
            nonlocal agg_commands_sent, agg_commands_ok, agg_commands_error
            with results_lock:
                agg_commands_sent += local_sent
                agg_commands_ok += local_ok
                agg_commands_error += local_err
                if local_rtts:
                    agg_rtts.extend(local_rtts)

        def _worker(idx: int, smtp) -> None:
            nonlocal active_count
            sock = smtp.sock
            local_sent = 0
            local_ok = 0
            local_err = 0
            local_rtts: list[float] = []
            total_ok = 0  # running per-socket count of 250 OK replies (not reset on flush)
            died_reason: str | None = None  # set only if the *socket* failed during the
                                            # storm, NOT on clean stop_event exit.
            died_cause = ""  # human-readable cause (error text / SMTP code) for the report
            try:
                while not stop_event.is_set():
                    try:
                        t0 = time.perf_counter()
                        sock.sendall(b"NOOP\r\n")
                        status, _raw, closed = self._noop_read_one_reply(sock)
                        rt = time.perf_counter() - t0
                        local_sent += 1
                        if status == 250:
                            local_ok += 1
                            total_ok += 1
                            local_rtts.append(rt)
                        else:
                            local_err += 1
                        if local_sent % FLUSH_EVERY == 0:
                            _flush(local_sent, local_ok, local_err, local_rtts)
                            local_sent = local_ok = local_err = 0
                            local_rtts = []
                        if closed:
                            died_reason = "disconnect"
                            if status is not None:
                                died_cause = (
                                    f"[{status}] "
                                    f"{self.bytes_to_str(_raw).strip()[:80]}"
                                )
                            else:
                                died_cause = "peer closed connection"
                            break
                    except (OSError, ConnectionError) as exc:
                        local_sent += 1
                        local_err += 1
                        died_reason = self._classify_conn_failure(exc)
                        errno = getattr(exc, "errno", None)
                        died_cause = f"{type(exc).__name__}: {exc}"
                        if errno is not None and f"errno {errno}" not in died_cause.lower():
                            died_cause += f" (errno {errno})"
                        break
            finally:
                _flush(local_sent, local_ok, local_err, local_rtts)
                if died_reason is not None:
                    t_rel = time.perf_counter() - run_start
                    if total_ok == 0:
                        timing = f"no successful reply, t={t_rel:.1f}s"
                    else:
                        timing = f"after {total_ok} OK NOOPs, t={t_rel:.1f}s"
                    detail = f"{died_cause}; {timing}" if died_cause else timing
                    with results_lock:
                        active_count -= 1
                        terminated_info.append((idx, died_reason, detail))
                    _emit_debug(f"Connection #{idx} terminated — {died_reason} ({detail})")

        threads: list[threading.Thread] = []
        run_start = time.perf_counter()
        for idx, smtp in enumerate(connections, start=1):
            t = threading.Thread(target=_worker, args=(idx, smtp), daemon=True)
            threads.append(t)
            t.start()

        # Live progress ticker while NOOP storm runs. Also performs early-exit
        # if every socket has been dropped by the server before the time limit
        # — a strong sign of a successful disconnect-storm DoS.
        deadline = run_start + NOOP_FLOOD2_RUN_SECONDS
        early_exit_no_conns = False
        while time.perf_counter() < deadline:
            with results_lock:
                cs, co, ce = agg_commands_sent, agg_commands_ok, agg_commands_error
                active_now = active_count
            if active_now == 0:
                early_exit_no_conns = True
                break
            if _show_progress:
                remaining = int(deadline - time.perf_counter())
                _write_live(
                    f"NOOP storm (active {active_now}/{storm_pool}): {cs} sent "
                    f"(ok={co}, err={ce}) — {remaining:02d}s left"
                )
            time.sleep(0.5)
        stop_event.set()
        for t in threads:
            t.join(timeout=NOOP_FLOOD2_RECV_TIMEOUT + 2.0)
        run_duration = time.perf_counter() - run_start
        _clear_live()

        for smtp in connections:
            try:
                smtp.close()
            except Exception:
                pass

        min_rt = min(agg_rtts) if agg_rtts else None
        max_rt = max(agg_rtts) if agg_rtts else None
        avg_rt = (sum(agg_rtts) / len(agg_rtts)) if agg_rtts else None
        error_rate_pct = (
            100.0 * agg_commands_error / agg_commands_sent if agg_commands_sent else 0.0
        )
        # All workers have joined at this point, so active_count is final.
        # The storm's 100% base is the *live* pool (sockets the server still held
        # when the storm started), not every socket that ever connected.
        with results_lock:
            active_end = max(active_count, 0)
            terminated_sorted = tuple(sorted(terminated_info, key=lambda t: t[0]))
        disconnected_during = max(storm_pool - active_end, 0)

        self.ptdebug(
            f"-nf2 summary: established={established}/{requested} "
            f"(err={est_err}, disc={est_disc}, timeout={est_timeout}, reaped={reaped}), "
            f"storm_pool={storm_pool}, active_end={active_end}, "
            f"dropped_during_test={disconnected_during}, "
            f"early_exit={early_exit_no_conns}, duration={run_duration:.1f}s, "
            f"sent={agg_commands_sent}, ok={agg_commands_ok}, "
            f"error={agg_commands_error} ({error_rate_pct:.1f}%), avg_rt={avg_rt}.",
            Out.INFO,
        )

        return NoopFlood2Result(
            requested_connections=requested,
            established_connections=established,
            run_duration_seconds=run_duration,
            commands_sent=agg_commands_sent,
            commands_ok=agg_commands_ok,
            commands_error=agg_commands_error,
            min_rt_seconds=min_rt,
            max_rt_seconds=max_rt,
            avg_rt_seconds=avg_rt,
            error_rate_pct=error_rate_pct,
            active_connections_end=active_end,
            disconnected_during_test=disconnected_during,
            early_exit_no_connections=early_exit_no_conns,
            establish_errors=est_err,
            establish_disconnected=est_disc,
            establish_timeouts=est_timeout,
            reaped_before_storm=reaped,
            storm_pool_connections=storm_pool,
            terminated_connections=terminated_sorted,
        )

    def _bomb_progress_line_rt(self) -> None:
        """Redraw one terminal line: -bomb progress (non-JSON). Caller should hold bomb lock when updating outcomes.

        Long bars must stay on one physical line: wrapping breaks \\r clears and spams the screen.
        If bomb_count exceeds the terminal width budget, a compact bar (bucketed) + \"k/n\" suffix is used.
        """
        if self.use_json:
            return
        outcomes = getattr(self, "_bomb_rt_outcomes", None)
        n = int(getattr(self, "_bomb_rt_count", 0) or 0)
        if outcomes is None or n <= 0:
            return
        try:
            term_w = max(40, shutil.get_terminal_size(fallback=(100, 24)).columns)
        except (OSError, AttributeError, ValueError):
            term_w = 100

        prefix = f"    {get_colored_text('[*]', 'INFO')} Progress: "
        completed = sum(1 for o in outcomes if o is not None)
        # Budget for glyph columns: leave margin for ANSI + prefix; avoid wrap at ~term_w-1
        budget_1to1 = max(8, term_w - 34)

        if n <= budget_1to1:
            parts: list[str] = []
            for i in range(n):
                o = outcomes[i]
                if o is None:
                    parts.append("░")
                elif o:
                    parts.append(get_colored_text("█", "NOTVULN"))
                else:
                    parts.append(get_colored_text("█", "VULN"))
            bar = "".join(parts)
            line = prefix + bar
        else:
            # Compact: W buckets, each covers a slice of message indices; + numeric suffix
            suffix = f" {completed}/{n}"
            w = max(8, term_w - 34 - len(suffix))
            parts = []
            for j in range(w):
                i0 = (j * n) // w
                i1 = ((j + 1) * n) // w
                if i1 <= i0:
                    i1 = i0 + 1
                seg = outcomes[i0:i1]
                if any(x is None for x in seg):
                    parts.append("░")
                elif all(x is True for x in seg):
                    parts.append(get_colored_text("█", "NOTVULN"))
                elif all(x is False for x in seg):
                    parts.append(get_colored_text("█", "VULN"))
                else:
                    parts.append(get_colored_text("▓", "WARNING"))
            bar = "".join(parts)
            line = prefix + bar + suffix

        sys.stdout.write("\033[2K\r" + line)
        sys.stdout.flush()

    def test_bomb(self) -> BombResult:
        """
        Test mail flooding / rate limiting (PTL-SVC-SMTP-BOMB).
        Sends multiple messages and records delivered vs rate-limited vs blocked.
        Never raises – all errors are caught and recorded.
        """
        host = self.args.target.ip
        port = self.args.target.port
        rcpt = str(self.args.rcpt_to).strip()
        mail_from = self.args.mail_from or f"bombtest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        from_name = getattr(self.args, "from_name", None) or ""
        cc_raw = getattr(self.args, "cc", None) or ""
        cc_list = [a.strip() for a in cc_raw.split(",") if a.strip()] if cc_raw else []
        requested_count = getattr(self.args, "bomb_count", 100)
        bomb_count = max(1, int(requested_count))
        bomb_timeout = max(5.0, getattr(self.args, "bomb_timeout", 60.0))
        bomb_delay = max(0.0, getattr(self.args, "bomb_delay", 0.0))
        bomb_threads = max(1, min(getattr(self.args, "bomb_threads", 1), 50))
        bomb_randomize = getattr(self.args, "bomb_randomize", False)
        socket_timeout = 10.0
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls
        if bomb_threads > 10 and (use_tls or use_starttls) and not self.use_json:
            self.ptprint(
                "[!] Warning: High thread count with TLS may cause client-side CPU bottlenecking. Results might be skewed.",
                Out.TEXT,
            )

        counters = {"delivered": 0, "rate_limited": 0, "blocked": 0, "connection_lost": 0}
        first_rejection_at: list[int | None] = [None]
        sample_test_id_ref: list[str] = [""]
        last_error_ref: list[str] = [""]
        last_error_type_ref: list[str] = [""]
        smtp_trace: list[str] = []
        response_times: list[float] = []  # Elapsed sec per message (for RTT / tarpitting)
        tarpitting_detected = False
        lock = threading.Lock()
        start_time = time.perf_counter()
        outcomes: list[bool | None] = [None] * bomb_count
        abort_500 = threading.Event()
        abort_at_ref: list[int | None] = [None]
        self._bomb_rt_outcomes = outcomes
        self._bomb_rt_count = bomb_count
        self._mail_bomb_live_progress_completed = False
        auth_used_ref = [False]
        if not self.use_json:
            self._bomb_progress_line_rt()

        def _connect_bomb() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            """Returns (smtp, error). On success: (smtp, ""). On failure: (None, str(e))."""
            try:
                if use_tls:
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock = socket.create_connection((host, port), timeout=socket_timeout)
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=socket_timeout)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    status, _ = smtp.getreply()
                    if status != 220:
                        return None, f"Connect: {status}"
                    return smtp, ""
                smtp = smtplib.SMTP(timeout=socket_timeout)
                status, _ = smtp.connect(host, port)
                if status != 220:
                    return None, f"Connect: {status}"
                if use_starttls:
                    st_status, _ = smtp.docmd("STARTTLS")
                    if st_status != 220:
                        return None, f"STARTTLS: {st_status}"
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
                return smtp, ""
            except Exception as e:
                return None, str(e)

        def _send_one(idx: int) -> tuple[str, int | str | None, str]:
            """Returns (reason, status_or_error, error_type). For connection_lost, error_type is classification."""
            msg_test_id = self._new_mail_test_id()
            rid = msg_test_id[:8] if bomb_randomize else ""
            subject = self._outbound_subject()
            if rid:
                subject = f"{subject} [{rid[:4]}]"
            elif bomb_count > 1:
                subject = f"{subject} {idx}"
            body = self._outbound_data() + (f" Id:{rid[:4]}" if rid else "")
            from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f"<{mail_from}>"
            to_hdr = f"<{rcpt}>"
            cc_hdr = ", ".join(f"<{c}>" for c in cc_list) if cc_list else ""
            headers = [f"From: {from_hdr}", f"To: {to_hdr}"]
            if cc_hdr:
                headers.append(f"Cc: {cc_hdr}")
            headers.extend([
                f"Subject: {subject}",
                f"{EMAIL_HDR_TEST_ID}: {msg_test_id}",
                "Date: " + time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime()),
            ])
            msg = "\r\n".join(headers) + "\r\n\r\n" + body + "\r\n"
            recipients = [rcpt] + cc_list

            smtp, conn_err = _connect_bomb()
            if smtp is None:
                err_type, err_msg = _classify_connection_error(Exception(conn_err or "Connection failed"))
                return ("connection_lost", err_msg, err_type)

            try:
                ehlo_s, _ = smtp.docmd("EHLO", self.fqdn or "bomb-test.local")
                if ehlo_s == 500:
                    return ("fatal_500", 500, "")
                used_auth, auth_err = self._mail_test_auth_login(smtp, smtp_trace)
                if auth_err:
                    return ("blocked", auth_err, "auth_failed")
                if used_auth:
                    with lock:
                        auth_used_ref[0] = True
                mail_s, _ = smtp.docmd("MAIL", f"FROM:<{mail_from}>")
                if mail_s == 500:
                    return ("fatal_500", 500, "")
                status, reply = smtp.docmd("RCPT", f"TO:<{rcpt}>")
                if status == 500:
                    return ("fatal_500", 500, "")
                if status in (250, 251):
                    for c in cc_list:
                        s, _ = smtp.docmd("RCPT", f"TO:<{c}>")
                        if s == 500:
                            return ("fatal_500", 500, "")
                        if s not in (250, 251):
                            break
                    data_status, data_reply = smtp.data(msg)
                    if data_status == 500:
                        return ("fatal_500", 500, "")
                    if data_status == 250:
                        if self.args.debug and not self.use_json:
                            if not any(x.startswith("DATA:") for x in smtp_trace):
                                self._mail_test_trace_append(
                                    smtp_trace,
                                    self._data_trace_entry(msg, data_status, data_reply),
                                )
                        with lock:
                            if not sample_test_id_ref[0]:
                                sample_test_id_ref[0] = msg_test_id
                        return ("delivered", 250, "")
                if 400 <= status < 500:
                    return ("rate_limited", status, "")
                if status >= 500:
                    return ("blocked", status, "")
                return ("blocked", status, "")
            except smtplib.SMTPResponseException as e:
                if e.smtp_code == 500:
                    return ("fatal_500", 500, "")
                if 400 <= e.smtp_code < 500:
                    return ("rate_limited", e.smtp_code, "")
                return ("blocked", e.smtp_code, "")
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, OSError, socket.timeout) as e:
                err_type, err_msg = _classify_connection_error(e)
                return ("connection_lost", err_msg, err_type)
            except Exception as e:
                err_type, err_msg = _classify_connection_error(e)
                return ("connection_lost", err_msg, err_type)
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass

        def _bomb_drain_queue(queue_in: queue.Queue) -> None:
            while True:
                try:
                    queue_in.get_nowait()
                except queue.Empty:
                    return
                queue_in.task_done()

        def _worker(queue_in: queue.Queue) -> None:
            while True:
                if abort_500.is_set():
                    _bomb_drain_queue(queue_in)
                    return
                try:
                    idx = queue_in.get_nowait()
                except queue.Empty:
                    return
                if time.perf_counter() - start_time > bomb_timeout:
                    queue_in.task_done()
                    return
                if abort_500.is_set():
                    queue_in.task_done()
                    return
                if bomb_delay > 0:
                    time.sleep(bomb_delay)
                if abort_500.is_set():
                    queue_in.task_done()
                    return
                t0 = time.perf_counter()
                reason, status_or_err, err_type = _send_one(idx)
                elapsed_msg = time.perf_counter() - t0
                with lock:
                    response_times.append(elapsed_msg)
                    ok = reason == "delivered"
                    outcomes[idx - 1] = ok
                    if reason == "delivered":
                        counters["delivered"] += 1
                    elif reason == "rate_limited":
                        counters["rate_limited"] += 1
                        if first_rejection_at[0] is None:
                            first_rejection_at[0] = idx
                    elif reason == "blocked":
                        counters["blocked"] += 1
                        if first_rejection_at[0] is None:
                            first_rejection_at[0] = idx
                    elif reason == "fatal_500":
                        counters["blocked"] += 1
                        if first_rejection_at[0] is None:
                            first_rejection_at[0] = idx
                        abort_at_ref[0] = idx
                        smtp_trace.append(f"SMTP 500 at msg {idx} — test stopped (no further messages)")
                        abort_500.set()
                    else:
                        counters["connection_lost"] += 1
                        if first_rejection_at[0] is None:
                            first_rejection_at[0] = idx
                        err_str = str(status_or_err) if status_or_err else "connection lost"
                        last_error_ref[0] = err_str
                        last_error_type_ref[0] = err_type or "other"
                    if not self.use_json:
                        self._bomb_progress_line_rt()
                queue_in.task_done()
                if reason == "fatal_500":
                    return

        msg_queue: queue.Queue = queue.Queue()
        for i in range(1, bomb_count + 1):
            msg_queue.put(i)
        workers: list[threading.Thread] = []
        for _ in range(bomb_threads):
            t = threading.Thread(target=_worker, args=(msg_queue,))
            t.daemon = True
            t.start()
            workers.append(t)
        try:
            for t in workers:
                t.join(timeout=bomb_timeout + 5)
        finally:
            if not self.use_json:
                try:
                    self._bomb_progress_line_rt()
                except Exception:
                    pass
                sys.stdout.write("\n")
                sys.stdout.flush()
                self._mail_bomb_live_progress_completed = True
        elapsed = time.perf_counter() - start_time

        delivered = counters["delivered"]
        rate_limited = counters["rate_limited"]
        blocked = counters["blocked"]
        connection_lost = counters["connection_lost"]
        sent = sum(1 for o in outcomes if o is not None)
        first_rej = first_rejection_at[0]
        per_message_delivered = tuple(o for o in outcomes if o is not None)
        aborted_500 = abort_at_ref[0] is not None

        # RTT and tarpitting: compare first vs last quartile of response times
        avg_rtt_ms: float | None = None
        if len(response_times) >= 8:
            n = len(response_times)
            quarter = max(1, n // 4)
            first_avg = statistics.mean(response_times[:quarter])
            last_avg = statistics.mean(response_times[-quarter:])
            avg_rtt_ms = statistics.mean(response_times) * 1000.0
            # If last-quartile avg >> first-quartile (e.g. 5x) and > 1s -> tarpitting
            if last_avg > 5.0 * first_avg and last_avg > 1.0 and first_avg > 0.001:
                tarpitting_detected = True

        # Verdict hierarchy: VULNERABLE > PARTIAL > SECURE > INDETERMINATE
        ratio = delivered / sent if sent > 0 else 0.0
        rate_or_blocked = rate_limited > 0 or blocked > 0

        indeterminate = (
            delivered == 0 and rate_limited == 0 and blocked == 0 and connection_lost == sent
        )
        vulnerable = ratio > 0.95 and sent >= 100
        partial_protection = (
            not vulnerable
            and (
                (0.1 < ratio <= 0.95 and sent >= 50)
                or (rate_or_blocked and first_rej is not None and first_rej > 50)
            )
        )

        detail_parts = [f"{delivered}/{sent} delivered"]
        if rate_limited:
            detail_parts.append(f"{rate_limited} rate-limited (4xx)")
        if blocked:
            detail_parts.append(f"{blocked} blocked (5xx)")
        if connection_lost:
            detail_parts.append(f"{connection_lost} connection_lost")
        if partial_protection:
            detail_parts.append(f"partial protection (first rejection at msg {first_rej})")
        if aborted_500 and abort_at_ref[0] is not None:
            detail_parts.append(f"stopped early (SMTP 500 at msg {abort_at_ref[0]})")

        bomb_detail = "; ".join(detail_parts)

        return BombResult(
            vulnerable=vulnerable,
            indeterminate=indeterminate,
            partial_protection=partial_protection,
            sent=sent,
            delivered=delivered,
            rate_limited=rate_limited,
            blocked=blocked,
            connection_lost=connection_lost,
            first_rejection_at=first_rej,
            elapsed_sec=elapsed,
            tarpitting_detected=tarpitting_detected,
            last_error=last_error_ref[0] or "",
            last_error_type=last_error_type_ref[0] or "",
            avg_rtt_ms=avg_rtt_ms,
            smtp_trace=tuple(smtp_trace[-50:]),
            per_message_delivered=per_message_delivered,
            aborted_on_smtp_500=aborted_500,
            abort_at_message=abort_at_ref[0],
            auth_used=auth_used_ref[0],
            detail=bomb_detail,
            sample_test_id=sample_test_id_ref[0],
        )

    def test_flood(self) -> FloodResult:
        """
        Test FLOOD – queue overload, SIZE extension (PTL-SVC-SMTP-FLOOD).
        Phases: SIZE_CHECK, SIZE_ENFORCEMENT, QUEUE_STRESS.
        Panic stop on 421; secure on 452.
        """
        host = self.args.target.ip
        port = self.args.target.port
        mail_from = self.args.mail_from or f"floodtest@{self.fqdn}"
        mail_from = str(mail_from).strip()
        rcpt = getattr(self.args, "rcpt_to", None)
        rcpt = str(rcpt).strip() if rcpt else None
        flood_count = max(1, min(getattr(self.args, "flood_count", 150), 500))
        flood_timeout = max(10.0, getattr(self.args, "flood_timeout", 90.0))
        skip_size_test = getattr(self.args, "flood_skip_size_test", False)
        start_time = time.perf_counter()
        smtp_trace: list[str] = []
        auth_used = False
        _ssl_ctx = ssl._create_unverified_context()
        use_tls = self.args.tls or port == 465
        use_starttls = self.args.starttls and not use_tls

        def _connect_flood() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
            try:
                if use_tls:
                    sock = socket.create_connection((host, port), timeout=15)
                    try:
                        ipaddress.ip_address(host)
                        _sni = None
                    except ValueError:
                        _sni = host
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    smtp = smtplib.SMTP(timeout=15)
                    smtp.sock = sock_ssl
                    smtp.file = None
                    st, _ = smtp.getreply()
                    if st != 220:
                        return None, f"Connect: {st}"
                    return smtp, ""
                smtp = smtplib.SMTP(timeout=15)
                st, _ = smtp.connect(host, port)
                if st != 220:
                    return None, f"Connect: {st}"
                if use_starttls:
                    st2, _ = smtp.docmd("STARTTLS")
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
                return smtp, ""
            except Exception as e:
                return None, str(e)

        smtp, conn_err = _connect_flood()
        if smtp is None:
            return FloodResult(
                vulnerable=False, indeterminate=True, partial_protection=False,
                size_advertised=False, size_limit_bytes=None, size_enforced=None,
                messages_sent=0, messages_accepted=0, messages_rejected=0,
                first_rejection_at=None, tarpitting_detected=False,
                elapsed_sec=time.perf_counter() - start_time,
                smtp_trace=("connection failed: " + conn_err,),
                queue_attempts=0,
                flood_notes=(),
                auth_used=False,
                detail=f"Connection failed: {conn_err}",
            )

        try:
            _, ehlo_raw = smtp.ehlo(self.fqdn or "flood-test.local")
            ehlo_str = ehlo_raw.decode(errors="replace") if isinstance(ehlo_raw, bytes) else str(ehlo_raw or "")
            used_auth, auth_err = self._mail_test_auth_login(smtp, smtp_trace)
            if auth_err:
                elapsed = time.perf_counter() - start_time
                return FloodResult(
                    vulnerable=False, indeterminate=True, partial_protection=False,
                    size_advertised=False, size_limit_bytes=None, size_enforced=None,
                    messages_sent=0, messages_accepted=0, messages_rejected=0,
                    first_rejection_at=None, tarpitting_detected=False, elapsed_sec=elapsed,
                    smtp_trace=tuple(smtp_trace),
                    queue_attempts=0,
                    flood_notes=(),
                    auth_used=False,
                    detail=auth_err,
                )
            if used_auth:
                auth_used = True
            size_limit_bytes = _parse_size_from_ehlo(ehlo_str)
        except Exception:
            ehlo_str = ""
            size_limit_bytes = None
        size_advertised = size_limit_bytes is not None
        size_effective = size_advertised and (size_limit_bytes or 0) > 0
        size_line = (
            f"SIZE_CHECK: {'SIZE ' + str(size_limit_bytes or 0) + ' B' if size_advertised else 'not advertised'}"
        )
        self._mail_test_trace_append(smtp_trace, size_line)

        size_enforced: bool | None = None
        if size_effective and not skip_size_test:
            try:
                status, reply = smtp.docmd("MAIL", f"FROM:<{mail_from}> SIZE=1099511627776")
                self._mail_test_trace_append(smtp_trace, f"SIZE_ENFORCEMENT: MAIL SIZE=1TB -> {status}")
                size_enforced = status == 552
                if status != 552:
                    try:
                        smtp.docmd("RSET")
                    except Exception:
                        pass
            except Exception as e:
                self._mail_test_trace_append(smtp_trace, f"SIZE_ENFORCEMENT: error {e}")
                size_enforced = False
        size_summary = (
            f"{'SIZE ' + str(size_limit_bytes) + ' B advertised' if size_advertised else 'not advertised'}; "
            f"enforced: {'yes' if size_enforced else 'no' if size_enforced is not None else 'n/a'}"
        )
        self._mail_test_live_done("SIZE", size_summary)

        try:
            smtp.quit()
        except Exception:
            pass

        if not rcpt:
            elapsed = time.perf_counter() - start_time
            vuln = not size_effective or (size_limit_bytes == 0) or (size_enforced is False and size_effective)
            no_size_notes: tuple[str, ...] = ()
            if vuln and not size_effective:
                no_size_notes = (
                    "No effective SIZE limit in EHLO — server may accept oversized messages",
                    "Note: SIZE extension is not mandatory per RFC 1870; "
                    "server may enforce limits elsewhere (post-DATA, MTA policy)",
                )
            return FloodResult(
                vulnerable=vuln, indeterminate=False, partial_protection=size_effective and size_enforced and not vuln,
                size_advertised=size_advertised, size_limit_bytes=size_limit_bytes, size_enforced=size_enforced,
                messages_sent=0, messages_accepted=0, messages_rejected=0,
                first_rejection_at=None, tarpitting_detected=False, elapsed_sec=elapsed,
                smtp_trace=tuple(smtp_trace),
                queue_attempts=0,
                flood_notes=no_size_notes,
                auth_used=auth_used,
                detail=f"SIZE {'advertised' if size_advertised else 'not advertised'}; "
                      f"{'enforced' if size_enforced else 'not enforced'}. No -r, QUEUE_STRESS skipped.",
            )

        min_body = "X" * 10
        near_size_body_len = min(int((size_limit_bytes or 26214400) * 0.8), 10 * 1024 * 1024) if size_limit_bytes else 10240
        rtts: list[float] = []
        sent, accepted, rejected = 0, 0, 0
        queue_attempts = 0
        first_rejection_at: int | None = None
        panic_421 = False
        secure_452 = False
        deadline = start_time + flood_timeout
        flood_test_id = self._new_mail_test_id()

        for idx in range(flood_count):
            if time.perf_counter() > deadline:
                self._mail_test_trace_append(
                    smtp_trace,
                    f"QUEUE_STRESS: timeout after {queue_attempts} attempts ({sent} DATA completed)",
                )
                break
            queue_attempts += 1
            body_len = near_size_body_len if (idx % 3 == 1 and size_limit_bytes) else len(min_body)
            body = "X" * body_len
            msg = (
                f"From: <{mail_from}>\r\nTo: <{rcpt}>\r\nSubject: {self._outbound_subject()}\r\n"
                f"{EMAIL_HDR_TEST_ID}: {flood_test_id}\r\n"
                f"MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\n{body}\r\n"
            )
            smtp2, _ = _connect_flood()
            if smtp2 is None:
                break
            try:
                smtp2.docmd("EHLO", self.fqdn or "flood-test.local")
                used_auth, auth_err = self._mail_test_auth_login(smtp2, smtp_trace)
                if auth_err:
                    rejected += 1
                    if first_rejection_at is None:
                        first_rejection_at = idx + 1
                    try:
                        smtp2.quit()
                    except Exception:
                        pass
                    continue
                if used_auth:
                    auth_used = True
                smtp2.docmd("MAIL", f"FROM:<{mail_from}>")
                smtp2.docmd("RCPT", f"TO:<{rcpt}>")
                t0 = time.perf_counter()
                data_status, data_reply = smtp2.data(msg)
                if idx == 0:
                    self._mail_test_trace_append(
                        smtp_trace,
                        self._data_trace_entry(msg, data_status, data_reply),
                    )
                rtt = time.perf_counter() - t0
                rtts.append(rtt)
                sent += 1
                if data_status == 250:
                    accepted += 1
                else:
                    rejected += 1
                    if first_rejection_at is None:
                        first_rejection_at = idx + 1
                    if data_status == 421:
                        panic_421 = True
                        self._mail_test_trace_append(smtp_trace, f"QUEUE_STRESS: 421 at msg {idx+1} - panic stop")
                        try:
                            smtp2.quit()
                        except Exception:
                            pass
                        break
                    if data_status == 452:
                        secure_452 = True
                        self._mail_test_trace_append(smtp_trace, f"QUEUE_STRESS: 452 at msg {idx+1} - disk protection")
                        try:
                            smtp2.quit()
                        except Exception:
                            pass
                        break
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, socket.timeout) as e:
                rejected += 1
                if first_rejection_at is None:
                    first_rejection_at = idx + 1
            try:
                smtp2.quit()
            except Exception:
                pass

        tarpitting_detected = False
        if len(rtts) >= 5:
            first_half = sum(rtts[: len(rtts) // 2]) / (len(rtts) // 2)
            last_half = sum(rtts[-len(rtts) // 2 :]) / (len(rtts) // 2)
            if last_half > first_half * 2.0:
                tarpitting_detected = True
        self._mail_test_trace_append(
            smtp_trace,
            f"QUEUE_STRESS: attempts={queue_attempts}, delivered={accepted} (250 OK), "
            f"data_completed={sent} (no TCP error), failed={rejected} (non-250 or disconnect/timeout)",
        )
        queue_summary = (
            f"attempts={queue_attempts}, delivered={accepted}, "
            f"data_completed={sent}, failed={rejected}"
        )
        self._mail_test_live_done("queue", queue_summary)

        elapsed = time.perf_counter() - start_time
        vuln = (
            not size_effective
            or (size_limit_bytes == 0)
            or (size_enforced is False and size_effective)
            or (accepted >= flood_count * 0.9 and not secure_452 and not panic_421)
        )
        partial = (
            (size_effective and size_enforced)
            or tarpitting_detected
            or secure_452
            or panic_421
            or (first_rejection_at is not None and first_rejection_at < flood_count)
        ) and not vuln
        flood_notes: tuple[str, ...] = ()
        if vuln and not size_effective:
            flood_notes = (
                "No effective SIZE limit in EHLO — server may accept oversized messages",
                "Note: SIZE extension is not mandatory per RFC 1870; "
                "server may enforce limits elsewhere (post-DATA, MTA policy)",
            )
        detail_parts = []
        if size_effective:
            detail_parts.append(f"SIZE {size_limit_bytes} B advertised")
        else:
            detail_parts.append("SIZE not advertised")
        if size_enforced is not None:
            detail_parts.append("enforced" if size_enforced else "not enforced")
        detail_parts.append(
            f"queue: attempts={queue_attempts}, delivered={accepted}, "
            f"data_completed={sent}, failed={rejected}"
        )
        if tarpitting_detected:
            detail_parts.append("tarpitting detected")
        if secure_452:
            detail_parts.append("452 disk protection")
        if panic_421:
            detail_parts.append("421 panic stop")
        return FloodResult(
            vulnerable=vuln, indeterminate=False, partial_protection=partial,
            size_advertised=size_advertised, size_limit_bytes=size_limit_bytes, size_enforced=size_enforced,
            messages_sent=sent, messages_accepted=accepted, messages_rejected=rejected,
            first_rejection_at=first_rejection_at, tarpitting_detected=tarpitting_detected,
            elapsed_sec=elapsed, smtp_trace=tuple(smtp_trace),
            queue_attempts=queue_attempts,
            flood_notes=flood_notes,
            auth_used=auth_used,
            detail="; ".join(detail_parts),
            test_id=flood_test_id if accepted > 0 else "",
        )
