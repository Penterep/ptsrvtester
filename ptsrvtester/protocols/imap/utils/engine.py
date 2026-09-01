"""IMAP protocol engine — ported probe logic used by modules/run(ctx)."""
from __future__ import annotations

import argparse
import imaplib
import ipaddress
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from string import ascii_letters
from typing import Any, Callable, NamedTuple

from .helpers import (
    ArgsWithBruteforce,
    Creds,
    Target,
    check_if_brute,
    get_mode,
    simple_bruteforce,
    text_or_file,
    valid_target,
    vendor_from_cpe,
)
from .ptntlmauth.ptntlmauth import NTLMInfo, decode_ChallengeMessage_blob, get_NegotiateMessage_data
from .service_identification import identify_service

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _IMAP_TLS_CRYPTO = True
except ImportError:
    x509 = None  # type: ignore[assignment]
    rsa = None  # type: ignore[assignment]
    _IMAP_TLS_CRYPTO = False


def valid_target_imap(target: str) -> Target:
    return valid_target(target, domain_allowed=True)


from .capa import (
    IMAP_AUTH_METHOD_LEVEL,
    IMAP_KNOWN_CAPABILITIES,
    _capa_level_bullet,
    _extract_capabilities_from_banner,
    _normalize_imap_login_error_for_enum,
    _imap_login_exception_text,
    _parse_capability_commands,
    valid_target_imap,
)
from .results import *  # noqa: F403
from .results import (  # noqa: F401 — star import skips leading-underscore names
    _EICAR_STANDARD_LINE,
    _IMAP_CONNECT_TIMEOUT_SEC,
    _IMAP_LOAD_DISCONNECT_EARLY_MAX,
    _IMAP_LOAD_ERR_OK_MAX_PCT,
    _IMAP_LOAD_PER_CMD_TIMEOUT_SEC,
    _IMAP_LOAD_PROGRESS_APPEND_INTERVAL,
    _IMAP_LOAD_SEARCH_INTERVAL,
    _IMAP_LOAD_SLOWDOWN_ABS_SEC,
    _IMAP_LOAD_SLOWDOWN_RATIO,
    _IMAP_MBOX_ISO_CMD_TIMEOUT_SEC,
    _IMAP_MBOX_ISO_DICT_PROGRESS_EVERY,
    _IMAP_MBOX_ISO_ENUM_MIN_NONZERO_PATTERNS,
    _IMAP_MBOX_ISO_ENUM_MIN_TOTAL_LISTED,
    _IMAP_MBOX_ISO_LIST_DICTIONARY_PATTERNS,
    _IMAP_MBOX_ISO_LIST_ROOT_MAX_PARSE,
    _IMAP_MBOX_ISO_LIST_SAMPLE,
    _IMAP_TLS_AUDIT_SECTION_TITLE,
    _IMAP_TLS_AUDIT_TIMEOUT_SEC,
    _IMAP_TLS_EXPIRY_VULN_DAYS,
    _IMAP_TLS_EXPIRY_WARN_DAYS,
    _IMAP_USRENUM_DEFAULT_PASSWORD,
    _IMAP_USRENUM_MARKER_LABEL,
    _INVCOMM_INFO_LEAK_MARKERS,
    _INVCOMM_READ_DEADLINE_SEC,
    _INVCOMM_SLOW_BASE_SEC,
    _INVCOMM_SLOW_EXTRA_SEC,
    _LONG_COMMAND_BODY_LEN,
    _SNIFFABLE_AUTH_PROBE_PRIORITY,
)


class Out:
    TEXT = "TEXT"
    TITLE = "TITLE"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    OK = "OK"
    VULN = "VULN"
    NOTVULN = "NOTVULN"
    ADDITIONS = "ADDITIONS"


class ImapEngine:
    """Stateful IMAP probe helper. Modules call tests then stream_* via ctx.out."""

    def __init__(self, args, *, out: Callable = None, debug: Callable = None, report=None):
        self.args = args
        self.out = out or (lambda *a, **k: None)
        self.debug = debug or (lambda *a, **k: None)
        self.report = report
        self.imap = None
        self.use_json = bool(getattr(args, "json", False))
        self.do_brute = check_if_brute(args)
        self._output_lock = threading.Lock()
        self._usrenum_progress_lock = threading.Lock()
        self._usrenum_mt_progress_line_active = False
        self._usrenum_progress_start = None
        self._ntlm_transient_init_emitted = False
        from .results import IMAPResults
        self.results = IMAPResults()

    def _ptprint(self, string="", out=Out.TEXT, title=False, end="\n", json=False, indent=0):
        """Adapt old BaseModule.ptprint to ctx.out buffering."""
        if self.use_json and not json:
            return
        if json and not self.use_json:
            return
        if title:
            cat, color = "INFO", True
        else:
            cat = out.value if hasattr(out, "value") else str(out)
            color = cat == "INFO"
        self.out(string, cat, colortext=color, indent=indent)

    def _ptprint_raw(self, string="", category="TEXT", *args, **kwargs):
        # Accept both BaseModule-style and ptprinthelper kwargs.
        if "bullet_type" in kwargs and (not category or category == "TEXT"):
            category = kwargs["bullet_type"]
        # positional category sometimes passed as second arg already
        if args and isinstance(args[0], str) and category == "TEXT":
            # signature was (msg, bullet_type=...) via keyword mostly
            pass
        cond = kwargs.get("condition", True)
        if not cond:
            return
        indent = kwargs.get("indent", 0)
        color = kwargs.get("colortext", category == "INFO")
        self.out(string, category if isinstance(category, str) else str(category), colortext=color, indent=indent)

    def bind_ctx(self, ctx) -> "ImapEngine":
        """Rebind output sinks for the current module PrintLock."""
        self.out = ctx.out
        self.debug = ctx.debug
        self.report = getattr(ctx, "report", self.report)
        self.use_json = bool(ctx.json)
        return self

    def _emit_section_heading(self, title: str) -> None:
        """Print section title before work starts (align with SMTP/FTP progressive terminal UX)."""
        if self.use_json:
            return
        with self._output_lock:
            self._ptprint(title, Out.INFO)

    def _tprint(self, msg: str, bullet: str = "TEXT", indent: int = 4) -> None:
        self._ptprint_raw(msg, bullet_type=bullet, condition=not self.use_json, indent=indent)

    def _emit_ntlm_transient_init_line(self) -> None:
        """Progress line under [+] NTLM information; erased on TTY before verdict lines."""
        with self._output_lock:
            self._ntlm_transient_init_emitted = True
            self._ptprint_raw(
                "Initializing IMAP session...",
                bullet_type="TITLE",
                condition=not self.use_json,
                indent=4,
            )

    def _clear_ntlm_transient_init_line(self) -> None:
        if self.use_json or not self._ntlm_transient_init_emitted:
            return
        self._ntlm_transient_init_emitted = False
        if not sys.stdout.isatty():
            return
        with self._output_lock:
            sys.stdout.write("\033[1A\033[2K\r")
            sys.stdout.flush()

    def _make_imap_connection(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        """New IMAP session using current TLS/STARTTLS mode (for probes independent of self.imap)."""
        t = _IMAP_CONNECT_TIMEOUT_SEC
        if self.args.tls:
            return imaplib.IMAP4_SSL(self.args.target.ip, self.args.target.port, timeout=t)
        imap = imaplib.IMAP4(self.args.target.ip, self.args.target.port, timeout=t)
        if self.args.starttls:
            imap.starttls()
        return imap

    def _imap_single_known_login(self) -> tuple[str, str] | None:
        """One explicit user+password, no wordlists (same idea as FTP bruteforce single-known)."""
        u = getattr(self.args, "user", None)
        p = getattr(self.args, "password", None)
        uf = getattr(self.args, "users", None)
        pf = getattr(self.args, "passwords", None)
        if u and p and not uf and not pf:
            return (str(u), str(p))
        return None

    def test_connection_limits_imap(self) -> ImapConnLimitsResult:
        """Connection / rate / idle policy probe (PTV-SVC-IMAP-CONN*). Mirrors SMTP -rt structure."""
        _show_progress = not self.use_json
        max_attempts = getattr(self.args, "conn_limits_max", None) or CONN_LIMIT_DEFAULT_ATTEMPTS
        return self._conn_limits_test_impl(_show_progress, max_attempts)

    def _conn_limits_test_impl(self, _show_progress: bool, max_attempts: int) -> ImapConnLimitsResult:
        MAX_TIMEOUT = CONN_LIMIT_TIMEOUT_CAP_SECONDS
        MAX_BAN_WAIT = CONN_LIMIT_TIMEOUT_CAP_SECONDS
        RETRY_INTERVAL = 5
        PHASE1_DELAY = 0.15

        _print_lock = threading.Lock()

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
            bullet = "VULN" if is_vuln else "NOTVULN"
            self._ptprint_raw(text, bullet_type=bullet, condition=_show_progress, indent=8)

        def _print_info(text: str) -> None:
            self._ptprint_raw(text, bullet_type="TITLE", condition=_show_progress, indent=8)

        def _watch_imap_disconnect(
            imap: imaplib.IMAP4 | imaplib.IMAP4_SSL,
            start_time: float,
            cap_seconds: float,
            result_cell: list,
            stop_event: threading.Event,
        ) -> None:
            sock = getattr(imap, "sock", None)
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
                if not data:
                    if not result_cell and not stop_event.is_set():
                        result_cell.append((time.perf_counter() - start_time, False))
                    return
                if not result_cell and not stop_event.is_set():
                    result_cell.append((time.perf_counter() - start_time, False))
                return

        connections: list = []
        _first_error: list[str | None] = [None]
        watcher_stop = threading.Event()

        a_start_time: float | None = None
        b_start_time: float | None = None
        a_result: list = []
        b_result: list = []

        if _show_progress:
            _write_live("Connected:", "0")

        try:
            imap_a = self._make_imap_connection()
            a_start_time = time.perf_counter()
            connections.append(imap_a)
            threading.Thread(
                target=_watch_imap_disconnect,
                args=(imap_a, a_start_time, MAX_TIMEOUT, a_result, watcher_stop),
                daemon=True,
            ).start()
            if _show_progress:
                _write_live("Connected:", str(len(connections)))
        except Exception as exc:
            if _first_error[0] is None:
                _first_error[0] = str(exc)

        time.sleep(PHASE1_DELAY)

        try:
            imap_b = self._make_imap_connection()
            b_start_time = time.perf_counter()
            connections.append(imap_b)
            try:
                imap_b.capability()
            except Exception:
                pass
            threading.Thread(
                target=_watch_imap_disconnect,
                args=(imap_b, b_start_time, MAX_TIMEOUT, b_result, watcher_stop),
                daemon=True,
            ).start()
            if _show_progress:
                _write_live("Connected:", str(len(connections)))
        except Exception as exc:
            if _first_error[0] is None:
                _first_error[0] = str(exc)

        if not connections:
            raise OSError(_first_error[0] or "Could not establish any IMAP connection")

        banned = False
        remaining = max_attempts - len(connections)
        for _ in range(max(remaining, 0)):
            time.sleep(PHASE1_DELAY)
            try:
                imap_extra = self._make_imap_connection()
            except Exception as exc:
                if _first_error[0] is None:
                    _first_error[0] = str(exc)
                banned = True
                break
            connections.append(imap_extra)
            if _show_progress:
                _write_live("Connected:", str(len(connections)))

        connected = len(connections)
        if _show_progress:
            _finalize_line("Connected:", str(connected))

        if banned and connected >= CONN_LIMIT_CONN_IP_THRESHOLD:
            _print_info(f"Further connections refused after {connected} sessions (possible rate / concurrency limit).")
        elif not banned:
            self._ptprint_raw(
                f"No refusal observed while raising concurrent sessions "
                f"({connected}/{max_attempts} established)",
                bullet_type="VULN",
                condition=_show_progress,
                indent=8,
            )

        if not banned and connected >= CONN_LIMIT_CONN_GLOB_THRESHOLD:
            _print_verdict(
                True,
                f"Very high number of concurrent sessions from one client accepted ({connected}); "
                "no global-style ceiling observed within probe budget",
            )
        elif not banned and connected >= CONN_LIMIT_CONN_IP_THRESHOLD:
            _print_verdict(
                True,
                f"Many concurrent sessions from one IP accepted ({connected}) without refusal",
            )
        elif banned:
            _print_verdict(False, "Concurrency or connect refusal observed during ramp-up")

        ban_duration_seconds: float | None = None
        ban_duration_exceeded = False
        ban_duration_probe_ran = False

        if banned:
            ban_duration_probe_ran = True
            start_rl = time.perf_counter()
            _rl_stop = threading.Event()

            if _show_progress:
                _write_live("Ban / backoff window:", "00:00")

                def _rl_ticker() -> None:
                    while not _rl_stop.wait(0.5):
                        elapsed = time.perf_counter() - start_rl
                        _write_live("Ban / backoff window:", _fmt_mmss(elapsed))

                threading.Thread(target=_rl_ticker, daemon=True).start()

            while True:
                elapsed = time.perf_counter() - start_rl
                if elapsed >= MAX_BAN_WAIT:
                    ban_duration_exceeded = True
                    ban_duration_seconds = elapsed
                    break
                try:
                    probe = self._make_imap_connection()
                    ban_duration_seconds = time.perf_counter() - start_rl
                    try:
                        probe.logout()
                    except Exception:
                        try:
                            probe.shutdown()
                        except Exception:
                            pass
                    break
                except Exception:
                    pass
                wait_end = time.perf_counter() + RETRY_INTERVAL
                while time.perf_counter() < wait_end:
                    time.sleep(0.2)

            _rl_stop.set()

            if _show_progress:
                _finalize_line(
                    "Ban / backoff window:",
                    _imap_conn_duration_display(ban_duration_seconds, ban_duration_exceeded),
                )

            if ban_duration_exceeded:
                _print_verdict(False, f"No reconnect within {int(MAX_BAN_WAIT)}s cap (strict limit or long backoff)")
            elif (
                ban_duration_seconds is not None
                and ban_duration_seconds < CONN_LIMIT_BAN_MIN_SECONDS
            ):
                _print_verdict(True, "Backoff / ban window shorter than typical brute-force mitigation window")
            else:
                _print_verdict(False, "Server eventually accepted a new connection after refusal")

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

            deadline = start_time + cap + 2.0

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
                result_cell.append((cap, True))

            elapsed, exceeded = result_cell[0]
            disp = _imap_conn_duration_display(elapsed, exceeded)
            if _show_progress:
                _finalize_line(label, disp)

            if exceeded or elapsed > threshold:
                _print_verdict(True, bad_msg)
            else:
                _print_verdict(False, ok_msg)
            return elapsed, exceeded

        pre_seconds, pre_exceeded = _await_and_report(
            a_start_time,
            a_result,
            "Pre-auth idle (after banner):",
            MAX_TIMEOUT,
            CONN_LIMIT_PREAUTH_IDLE_MAX_OK_SEC,
            f"Pre-auth idle disconnect or limit beyond {int(CONN_LIMIT_PREAUTH_IDLE_MAX_OK_SEC)}s (hit cap or slow idle policy)",
            f"Pre-auth idle ended within {int(CONN_LIMIT_PREAUTH_IDLE_MAX_OK_SEC)}s or server closed sooner",
        )

        post_seconds, post_exceeded = _await_and_report(
            b_start_time,
            b_result,
            "Idle after CAPABILITY:",
            MAX_TIMEOUT,
            CONN_LIMIT_POST_CAP_IDLE_MAX_OK_SEC,
            f"Idle after CAPABILITY beyond {int(CONN_LIMIT_POST_CAP_IDLE_MAX_OK_SEC)}s (hit cap or permissive idle)",
            f"Idle after CAPABILITY within {int(CONN_LIMIT_POST_CAP_IDLE_MAX_OK_SEC)}s or closed sooner",
        )

        watcher_stop.set()
        for conn in connections:
            try:
                conn.logout()
            except Exception:
                try:
                    conn.shutdown()
                except Exception:
                    pass

        seq_ok = 0
        seq_fail = 0
        if _show_progress:
            _write_live("Sequential connects:", f"0/{CONN_LIMIT_RATE_SEQ_ATTEMPTS}")

        for _ in range(CONN_LIMIT_RATE_SEQ_ATTEMPTS):
            try:
                simap = self._make_imap_connection()
                try:
                    simap.logout()
                except Exception:
                    try:
                        simap.shutdown()
                    except Exception:
                        pass
                seq_ok += 1
            except Exception:
                seq_fail += 1
            if _show_progress:
                _write_live("Sequential connects:", f"{seq_ok + seq_fail}/{CONN_LIMIT_RATE_SEQ_ATTEMPTS}")
            time.sleep(CONN_LIMIT_RATE_SEQ_DELAY_SEC)

        if _show_progress:
            _finalize_line("Sequential connects:", f"{seq_ok} ok, {seq_fail} refused")

        if seq_fail == 0 and seq_ok >= CONN_LIMIT_RATE_VULN_MIN_OK:
            _print_verdict(
                True,
                f"High-frequency connect/disconnect burst succeeded ({seq_ok}/{CONN_LIMIT_RATE_SEQ_ATTEMPTS}) "
                "without refusal — weak connect-rate limiting",
            )
        elif seq_fail > 0:
            _print_verdict(False, "Connect-rate limiting or refusal observed during sequential burst")
        else:
            _print_verdict(False, "Sequential burst completed with limited success count")

        auth_parallel_accepted = 0
        auth_parallel_attempted = 0
        auth_login_stopped_early = False
        idle_logged_seconds = None
        idle_logged_exceeded = False
        auth_phase_skip_reason = None
        idle_probe_detail = None

        cred_pair = self._imap_single_known_login()
        if cred_pair is None:
            auth_phase_skip_reason = (
                "Authenticated probes skipped — use -u USER -p PASS without -U/-P wordlists"
            )
        else:
            user, pw = cred_pair
            auth_imaps: list = []
            if _show_progress:
                _write_live("Authenticated sessions:", "0")

            for _ in range(CONN_LIMIT_AUTH_PARALLEL_MAX):
                time.sleep(CONN_LIMIT_AUTH_PARALLEL_DELAY_SEC)
                auth_parallel_attempted += 1
                try:
                    aim = self._make_imap_connection()
                    aim.login(user, pw)
                    auth_imaps.append(aim)
                    auth_parallel_accepted += 1
                except Exception:
                    auth_login_stopped_early = True
                    break
                if _show_progress:
                    _write_live("Authenticated sessions:", str(len(auth_imaps)))

            if _show_progress:
                _finalize_line(
                    "Authenticated sessions:",
                    f"{auth_parallel_accepted} logged in"
                    + (" (login then refused)" if auth_login_stopped_early else ""),
                )

            if auth_parallel_accepted >= CONN_LIMIT_AUTH_PARALLEL_VULN_THRESHOLD and not auth_login_stopped_early:
                _print_verdict(
                    True,
                    f"Many simultaneous sessions with the same account accepted ({auth_parallel_accepted})",
                )
            elif auth_login_stopped_early and auth_parallel_accepted == 0:
                _print_verdict(False, "LOGIN failed — check credentials or account lockout")
                idle_probe_detail = "Skipped IDLE probe (login failed)"
            elif auth_login_stopped_early:
                _print_verdict(
                    False,
                    "Parallel LOGIN limit or refusal observed before reaching high session count",
                )
            else:
                _print_verdict(False, "Parallel authenticated sessions stayed below assessment threshold")

            for aim in auth_imaps:
                try:
                    aim.logout()
                except Exception:
                    try:
                        aim.shutdown()
                    except Exception:
                        pass

            if auth_parallel_accepted > 0 and not (
                auth_login_stopped_early and auth_parallel_accepted == 0
            ):
                idle_imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
                try:
                    idle_imap = self._make_imap_connection()
                    idle_imap.login(user, pw)
                    try:
                        idle_imap.capability()
                    except Exception:
                        pass
                    has_idle = any(
                        str(x).upper().strip() == "IDLE" for x in (idle_imap.capabilities or [])
                    )
                    if not has_idle:
                        idle_probe_detail = "IDLE not advertised in CAPABILITY after LOGIN"
                        _print_info("IDLE probe skipped (capability does not advertise IDLE)")
                    else:
                        tag = idle_imap._new_tag()
                        idle_imap.send(tag + b" IDLE\r\n")
                        entered = False
                        t_dead = time.monotonic() + 20.0
                        while time.monotonic() < t_dead:
                            line = idle_imap.readline()
                            if not line:
                                idle_probe_detail = "no response to IDLE"
                                break
                            if line.startswith(b"+"):
                                entered = True
                                break
                            up = line.upper()
                            if line.startswith(tag) and (b"BAD" in up or b"NO" in up):
                                idle_probe_detail = line.decode("utf-8", errors="replace").strip()[:200]
                                break
                        if entered:
                            idle_start = time.perf_counter()
                            idle_result: list = []
                            idle_stop_ev = threading.Event()
                            threading.Thread(
                                target=_watch_imap_disconnect,
                                args=(idle_imap, idle_start, MAX_TIMEOUT, idle_result, idle_stop_ev),
                                daemon=True,
                            ).start()
                            dl = idle_start + MAX_TIMEOUT + 2.0
                            if _show_progress and not idle_result:
                                _write_live(
                                    "Idle (IDLE command):",
                                    _fmt_mmss(0.0),
                                )
                                tick_stop = threading.Event()

                                def _idle_tick() -> None:
                                    while not tick_stop.wait(0.5):
                                        if idle_result:
                                            return
                                        _write_live(
                                            "Idle (IDLE command):",
                                            _fmt_mmss(time.perf_counter() - idle_start),
                                        )

                                threading.Thread(target=_idle_tick, daemon=True).start()
                                while not idle_result and time.perf_counter() < dl:
                                    time.sleep(0.2)
                                tick_stop.set()
                            else:
                                while not idle_result and time.perf_counter() < dl:
                                    time.sleep(0.2)

                            if not idle_result:
                                idle_result.append((MAX_TIMEOUT, True))

                            ig_elapsed, ig_exceeded = idle_result[0]
                            idle_logged_seconds = ig_elapsed
                            idle_logged_exceeded = ig_exceeded
                            disp_i = _imap_conn_duration_display(ig_elapsed, ig_exceeded)
                            if _show_progress:
                                _finalize_line("Idle (IDLE command):", disp_i)

                            if ig_exceeded or ig_elapsed > CONN_LIMIT_IDLE_AFTER_LOGIN_MAX_OK_SEC:
                                _print_verdict(
                                    True,
                                    f"Authenticated IDLE session lasted {disp_i} — permissive long-lived IDLE",
                                )
                            else:
                                _print_verdict(
                                    False,
                                    f"IDLE session ended within {int(CONN_LIMIT_IDLE_AFTER_LOGIN_MAX_OK_SEC)}s or sooner",
                                )

                            idle_stop_ev.set()
                            try:
                                idle_imap.send(b"DONE\r\n")
                            except Exception:
                                pass
                            try:
                                idle_imap.readline()
                            except Exception:
                                pass
                except Exception as ex:
                    if idle_probe_detail is None:
                        idle_probe_detail = str(ex)
                finally:
                    if idle_imap is not None:
                        try:
                            idle_imap.logout()
                        except Exception:
                            try:
                                idle_imap.shutdown()
                            except Exception:
                                pass

        return ImapConnLimitsResult(
            connected=connected,
            max_attempts=max_attempts,
            banned=banned,
            ban_duration_probe_ran=ban_duration_probe_ran,
            ban_duration_seconds=ban_duration_seconds,
            ban_duration_exceeded=ban_duration_exceeded,
            preauth_idle_seconds=pre_seconds,
            preauth_idle_exceeded=pre_exceeded,
            post_cap_idle_seconds=post_seconds,
            post_cap_idle_exceeded=post_exceeded,
            sequential_accepted=seq_ok,
            sequential_attempts=CONN_LIMIT_RATE_SEQ_ATTEMPTS,
            sequential_refused=seq_fail,
            auth_parallel_accepted=auth_parallel_accepted,
            auth_parallel_attempted=auth_parallel_attempted,
            auth_login_stopped_early=auth_login_stopped_early,
            idle_logged_seconds=idle_logged_seconds,
            idle_logged_exceeded=idle_logged_exceeded,
            auth_phase_skip_reason=auth_phase_skip_reason,
            idle_probe_detail=idle_probe_detail,
        )

    def _test_catch_all(self) -> CatchAllResult:
        """Test if server accepts invalid credentials (LOGIN with random user/pass)."""
        try:
            fake_user = "".join(random.choices(string.ascii_letters + string.digits, k=24))
            fake_pass = "".join(random.choices(string.ascii_letters + string.digits, k=24))
            imap = self.connect()
            try:
                imap.login(fake_user, fake_pass)
                return "indeterminate"
            except Exception:
                return "not_configured"
            finally:
                try:
                    imap.logout()
                except Exception:
                    pass
        except Exception:
            return "not_configured"

    def _do_info(
        self, imap: imaplib.IMAP4 | imaplib.IMAP4_SSL, get_commands: bool = True
    ) -> InfoResult:
        """
        Core info logic: banner, ID, CAPABILITY.
        Merges pre-auth CAPABILITY from banner [CAPABILITY ...] with imap.capabilities.
        If on plain and STARTTLS in capabilities, upgrades and gets CAPABILITY again.
        """
        banner = imap.welcome.decode() if imap.welcome else None
        id_val = None
        capability = None
        capability_starttls = None

        if get_commands:
            capa_from_imap = [str(c) for c in imap.capabilities] if imap.capabilities else []
            capa_from_banner = _extract_capabilities_from_banner(banner)
            capability = list(dict.fromkeys(capa_from_imap + capa_from_banner)) or capa_from_imap or capa_from_banner

            try:
                typ, dat = imap.xatom("ID")
                typ, res = imap._untagged_response(typ, dat, "ID")
                if isinstance(res, list):
                    id_ = next((d for d in res), None)
                    if isinstance(id_, bytes):
                        id_val = id_.decode()
                    elif id_ is not None:
                        id_val = str(id_)
            except Exception:
                pass

            if (
                capability
                and "STARTTLS" in [c.upper() for c in capability]
                and self.args.target.port != 993
                and not self.args.tls
                and not isinstance(imap, imaplib.IMAP4_SSL)
            ):
                try:
                    imap.starttls()
                    capability_starttls = [str(c) for c in imap.capabilities] if imap.capabilities else []
                except Exception:
                    pass

        return InfoResult(banner, id_val, capability, capability_starttls)

    def _silent_info(self) -> InfoResult | None:
        """Load banner, ID and CAPABILITY (for brute-only when -i not set)."""
        try:
            imap = self.connect()
            try:
                return self._do_info(imap, get_commands=True)
            finally:
                try:
                    imap.logout()
                except Exception:
                    pass
        except Exception:
            return None

    @staticmethod
    def _imap_tls_audit_probe_failure(
        mode: str,
        attempted: bool,
        skipped_reason: str | None,
        starttls_advertised: bool | None,
        handshake_ok: bool,
        handshake_error: str | None,
    ) -> ImapTlsAuditProbeResult:
        return ImapTlsAuditProbeResult(
            mode=mode,
            attempted=attempted,
            skipped_reason=skipped_reason,
            starttls_advertised=starttls_advertised,
            handshake_ok=handshake_ok,
            handshake_error=handshake_error,
            tls_version=None,
            cipher_name=None,
            cipher_protocol=None,
            peer_subject=None,
            peer_issuer=None,
            san_dns=tuple(),
            not_before=None,
            not_after=None,
            days_until_expiry=None,
            cert_expired=False,
            cert_not_yet_valid=False,
            weak_tls_version=False,
            weak_cipher=False,
            expires_within_vuln_days=False,
            expires_within_warn_days=False,
            peer_key_summary=None,
            peer_signature_hash=None,
            crypto_warnings=tuple(),
        )

    @staticmethod
    def _imap_tls_format_x509_name(name_seq) -> str:
        if not name_seq:
            return ""
        parts: list[str] = []
        for rdn in name_seq:
            if not isinstance(rdn, (tuple, list)):
                continue
            for item in rdn:
                if isinstance(item, (tuple, list)) and len(item) >= 2:
                    k, v = item[0], item[1]
                    parts.append(f"{k}={v}")
        return ", ".join(parts)[:500]

    @staticmethod
    def _imap_tls_san_entries(cert: dict | None) -> tuple[str, ...]:
        out: list[str] = []
        for it in (cert or {}).get("subjectAltName") or ():
            if isinstance(it, (tuple, list)) and len(it) >= 2:
                out.append(f"{it[0]}:{it[1]}")
        return tuple(out[:48])

    @staticmethod
    def _imap_tls_cipher_issues(cipher_data) -> tuple[bool, list[str]]:
        if not cipher_data or len(cipher_data) < 2:
            return False, []
        name = str(cipher_data[0] or "").upper()
        proto = str(cipher_data[1] or "").upper()
        bad = False
        msgs: list[str] = []
        if "SSLV2" in proto or "SSLV3" in proto:
            bad = True
            msgs.append("SSL 2.0/3.0 protocol")
        if proto in ("TLSV1", "TLSV1.0", "TLSV1.1"):
            bad = True
            msgs.append("TLS 1.0/1.1 deprecated protocol")
        for token in ("NULL", "EXPORT", "ANON", "RC4", "MD5"):
            if token in name:
                bad = True
                msgs.append(f"weak cipher token {token}")
        if "3DES" in name or "DES-CBC" in name or name.startswith("DES-"):
            bad = True
            msgs.append("3DES/DES (Sweet32 class risk)")
        return bad, msgs

    @staticmethod
    def _imap_tls_version_weak(ver: str | None) -> bool:
        if not ver:
            return False
        return ver in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")

    @staticmethod
    def _imap_tls_expiry_metrics(cert: dict | None) -> tuple[int | None, bool, bool, bool, bool]:
        """days_left, expired, not_yet_valid, within_vuln_days, within_warn_days."""
        if not cert or not cert.get("notAfter"):
            return None, False, False, False, False
        na = cert.get("notAfter")
        nb = cert.get("notBefore")
        try:
            exp = ssl.cert_time_to_seconds(str(na))
            now = time.time()
            nbf_sec = ssl.cert_time_to_seconds(str(nb)) if nb else None
        except Exception:
            return None, False, False, False, False
        expired = now > exp
        nyv = nbf_sec is not None and now < nbf_sec
        days_left = int((exp - now) / 86400)
        vuln_days = (not expired) and (not nyv) and 0 <= days_left <= _IMAP_TLS_EXPIRY_VULN_DAYS
        warn_days = (not expired) and (not nyv) and 0 <= days_left <= _IMAP_TLS_EXPIRY_WARN_DAYS
        return days_left, expired, nyv, vuln_days, warn_days

    def _imap_tls_peer_crypto_meta(self, der: bytes) -> tuple[str | None, str | None, list[str]]:
        """DER leaf cert → (signature hash name, key summary, warnings)."""
        if not _IMAP_TLS_CRYPTO or x509 is None or rsa is None or not der:
            return None, None, []
        warns: list[str] = []
        sig_name: str | None = None
        key_summary: str | None = None
        try:
            cert = x509.load_der_x509_certificate(der)
            if cert.signature_hash_algorithm is not None:
                sig_name = cert.signature_hash_algorithm.name
                if sig_name.lower() in ("sha1", "md5", "sha224"):
                    warns.append(f"Weak signature hash ({sig_name})")
            pk = cert.public_key()
            if isinstance(pk, rsa.RSAPublicKey):
                key_summary = f"RSA {pk.key_size}-bit"
                if pk.key_size < 2048:
                    warns.append(f"RSA key size {pk.key_size} (< 2048)")
            else:
                try:
                    from cryptography.hazmat.primitives.asymmetric import ec

                    if isinstance(pk, ec.EllipticCurvePublicKey):
                        key_summary = f"EC {pk.curve.name}"
                except Exception:
                    pass
        except Exception:
            return None, None, []
        return sig_name, key_summary, warns

    def _imap_tls_audit_probe_from_ssl(
        self,
        ssl_sock: ssl.SSLSocket,
        *,
        mode: str,
        attempted: bool,
        skipped_reason: str | None,
        starttls_advertised: bool | None,
        handshake_ok: bool,
        handshake_error: str | None,
    ) -> ImapTlsAuditProbeResult:
        if not handshake_ok:
            return self._imap_tls_audit_probe_failure(
                mode, attempted, skipped_reason, starttls_advertised, False, handshake_error
            )
        cert: dict | None = None
        try:
            cert = ssl_sock.getpeercert()
        except Exception:
            cert = None
        vers = None
        cname = cproto = None
        try:
            vers = ssl_sock.version()
            cd = ssl_sock.cipher()
            if cd:
                cname, cproto = str(cd[0] or ""), str(cd[1] or "")
        except Exception:
            pass
        weak_ver = self._imap_tls_version_weak(vers) or (
            bool(cproto) and cproto.upper() in ("TLSV1", "TLSV1.0", "TLSV1.1")
        )
        weak_c, cw_list = self._imap_tls_cipher_issues(ssl_sock.cipher())
        crypto_extra: list[str] = list(cw_list)
        days_left, expired, nyv, vuln_days, warn_days = self._imap_tls_expiry_metrics(cert)
        subject = self._imap_tls_format_x509_name(cert.get("subject") if cert else None)
        issuer = self._imap_tls_format_x509_name(cert.get("issuer") if cert else None)
        san = self._imap_tls_san_entries(cert)
        nb = str(cert.get("notBefore")) if cert and cert.get("notBefore") else None
        na = str(cert.get("notAfter")) if cert and cert.get("notAfter") else None
        peer_sig: str | None = None
        peer_key: str | None = None
        try:
            der = ssl_sock.getpeercert(binary_form=True)
            if der:
                peer_sig, peer_key, der_warns = self._imap_tls_peer_crypto_meta(der)
                crypto_extra.extend(der_warns)
        except Exception:
            pass
        return ImapTlsAuditProbeResult(
            mode=mode,
            attempted=attempted,
            skipped_reason=skipped_reason,
            starttls_advertised=starttls_advertised,
            handshake_ok=True,
            handshake_error=None,
            tls_version=vers,
            cipher_name=cname,
            cipher_protocol=cproto,
            peer_subject=subject or None,
            peer_issuer=issuer or None,
            san_dns=san,
            not_before=nb,
            not_after=na,
            days_until_expiry=days_left,
            cert_expired=expired,
            cert_not_yet_valid=nyv,
            weak_tls_version=weak_ver,
            weak_cipher=weak_c,
            expires_within_vuln_days=vuln_days,
            expires_within_warn_days=warn_days,
            peer_key_summary=peer_key,
            peer_signature_hash=peer_sig,
            crypto_warnings=tuple(crypto_extra[:12]),
        )

    def _imap_tls_audit_probe_implicit(self, host: str, port: int, timeout: float) -> ImapTlsAuditProbeResult:
        ctx = ssl.create_default_context()
        # Always pass server_hostname: for IP literals it enables SNI + matching against
        # iPAddress subjectAltName; server_hostname=None breaks hostname checking on newer Python
        # ("check_hostname requires server_hostname").
        sni = host
        sock: socket.socket | None = None
        ssl_sock: ssl.SSLSocket | None = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            ssl_sock = ctx.wrap_socket(sock, server_hostname=sni)
            sock = None
            ssl_sock.settimeout(timeout)
            try:
                ssl_sock.recv(4096)
            except Exception:
                pass
            return self._imap_tls_audit_probe_from_ssl(
                ssl_sock,
                mode="implicit_tls",
                attempted=True,
                skipped_reason=None,
                starttls_advertised=None,
                handshake_ok=True,
                handshake_error=None,
            )
        except ssl.SSLError as e:
            return self._imap_tls_audit_probe_failure(
                "implicit_tls", True, None, None, False, str(e)[:500]
            )
        except Exception as e:
            return self._imap_tls_audit_probe_failure(
                "implicit_tls", True, None, None, False, str(e)[:500]
            )
        finally:
            if ssl_sock is not None:
                try:
                    ssl_sock.close()
                except Exception:
                    pass
            elif sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _imap_tls_audit_probe_starttls(self, host: str, port: int, timeout: float) -> ImapTlsAuditProbeResult:
        imap: imaplib.IMAP4 | None = None
        starttls_was_listed = False
        try:
            imap = imaplib.IMAP4(host, port, timeout=timeout)
            imap.sock.settimeout(timeout)
            _ = imap.welcome
            try:
                imap.capability()
            except Exception:
                pass
            caps = [str(c).upper() for c in (imap.capabilities or [])]
            st = any("STARTTLS" in c for c in caps)
            starttls_was_listed = st
            if not st:
                try:
                    imap.logout()
                except Exception:
                    pass
                return ImapTlsAuditProbeResult(
                    mode="starttls",
                    attempted=False,
                    skipped_reason="STARTTLS not advertised in CAPABILITY",
                    starttls_advertised=False,
                    handshake_ok=False,
                    handshake_error=None,
                    tls_version=None,
                    cipher_name=None,
                    cipher_protocol=None,
                    peer_subject=None,
                    peer_issuer=None,
                    san_dns=tuple(),
                    not_before=None,
                    not_after=None,
                    days_until_expiry=None,
                    cert_expired=False,
                    cert_not_yet_valid=False,
                    weak_tls_version=False,
                    weak_cipher=False,
                    expires_within_vuln_days=False,
                    expires_within_warn_days=False,
                    peer_key_summary=None,
                    peer_signature_hash=None,
                    crypto_warnings=tuple(),
                )
            ctx = ssl.create_default_context()
            imap.starttls(ssl_context=ctx)
            ssl_sock = imap.sock
            if not isinstance(ssl_sock, ssl.SSLSocket):
                try:
                    imap.logout()
                except Exception:
                    pass
                return self._imap_tls_audit_probe_failure(
                    "starttls", True, None, True, False, "socket is not TLS after STARTTLS"
                )
            pr = self._imap_tls_audit_probe_from_ssl(
                ssl_sock,
                mode="starttls",
                attempted=True,
                skipped_reason=None,
                starttls_advertised=True,
                handshake_ok=True,
                handshake_error=None,
            )
            try:
                imap.logout()
            except Exception:
                try:
                    imap.shutdown()
                except Exception:
                    pass
            return pr
        except ssl.SSLError as e:
            if imap is not None:
                try:
                    imap.shutdown()
                except Exception:
                    pass
            return self._imap_tls_audit_probe_failure(
                "starttls", True, None, starttls_was_listed, False, str(e)[:500]
            )
        except Exception as e:
            if imap is not None:
                try:
                    imap.shutdown()
                except Exception:
                    pass
            return self._imap_tls_audit_probe_failure(
                "starttls", True, None, starttls_was_listed, False, str(e)[:500]
            )

    def test_imap_tls_audit(self) -> ImapTlsAuditResult:
        """
        Strict TLS + certificate audit for IMAP (PTV-SVC-IMAP-TLSAUDIT).
        Uses ssl.create_default_context() (trusted anchors + hostname / RFC 7817 when SNI is set).
        """
        host = self.args.target.ip
        port = int(self.args.target.port)
        timeout = _IMAP_TLS_AUDIT_TIMEOUT_SEC
        implicit_intended = bool(self.args.tls or port == 993)
        probes: list[ImapTlsAuditProbeResult] = []
        if implicit_intended:
            probes.append(self._imap_tls_audit_probe_implicit(host, port, timeout))
        else:
            probes.append(self._imap_tls_audit_probe_starttls(host, port, timeout))

        reasons: list[str] = []
        for p in probes:
            if p.mode == "implicit_tls" and p.attempted and not p.handshake_ok:
                reasons.append(f"implicit_tls: strict handshake failed ({p.handshake_error or 'n/a'})")
            if p.mode == "starttls" and p.starttls_advertised and p.attempted and not p.handshake_ok:
                reasons.append(f"starttls: strict handshake failed ({p.handshake_error or 'n/a'})")
            if not p.handshake_ok:
                continue
            if p.weak_tls_version:
                reasons.append(f"{p.mode}: weak TLS protocol ({p.tls_version or p.cipher_protocol})")
            if p.weak_cipher:
                reasons.append(f"{p.mode}: weak negotiated cipher ({p.cipher_name})")
            if p.cert_expired:
                reasons.append(f"{p.mode}: certificate expired")
            if p.cert_not_yet_valid:
                reasons.append(f"{p.mode}: certificate not yet valid")
            if p.expires_within_vuln_days:
                reasons.append(
                    f"{p.mode}: certificate expires within {_IMAP_TLS_EXPIRY_VULN_DAYS} days ({p.days_until_expiry}d left)"
                )
            for w in p.crypto_warnings:
                reasons.append(f"{p.mode}: {w}")

        vuln = len(reasons) > 0
        detail = "; ".join(reasons) if reasons else "Strict TLS/certificate checks passed for probed path(s)."
        return ImapTlsAuditResult(
            host=host,
            port=port,
            implicit_tls_intended=implicit_intended,
            probes=tuple(probes),
            vulnerable=vuln,
            detail=detail,
        )

    @staticmethod
    def _imap_tls_audit_terminal_fmt_cert_date(s: str | None) -> str:
        if not s:
            return "unknown"
        t = " ".join(s.strip().split())
        if t.endswith(" GMT"):
            t = t[:-4].strip()
        return t

    @staticmethod
    def _imap_tls_audit_terminal_subject_cn(subject: str | None) -> str | None:
        if not subject:
            return None
        for part in subject.split(","):
            chunk = part.strip()
            if chunk.lower().startswith("commonname="):
                return chunk.split("=", 1)[1].strip()
        return None

    @staticmethod
    def _imap_tls_audit_terminal_identity_level_msg(
        host: str, p: ImapTlsAuditProbeResult
    ) -> tuple[str, str]:
        """Returns (level ok|bad|warn, message) for Identity line."""
        if not p.handshake_ok:
            return ("bad", "Not assessed (TLS handshake did not complete)")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            hn = host.lower()
            dns = [
                s[4:].lower()
                for s in p.san_dns
                if len(s) > 4 and s.upper().startswith("DNS:")
            ]
            cn = IMAP._imap_tls_audit_terminal_subject_cn(p.peer_subject)
            if cn and cn.lower() == hn:
                return ("ok", "Hostname matches certificate SAN/CN")
            if hn in dns:
                return ("ok", "Hostname matches certificate SAN/CN")
            cn_disp = cn or "(no CN in subject)"
            return (
                "bad",
                f"Hostname mismatch (target: {host} not in SAN/CN; cert CN={cn_disp})",
            )
        else:
            return ("ok", "IP target — verified under platform TLS certificate rules")

    @staticmethod
    def _imap_tls_audit_terminal_trust_level_msg(p: ImapTlsAuditProbeResult) -> tuple[str, str]:
        """Returns (level ok|bad|warn, message) for Trust line."""
        if not p.attempted and p.skipped_reason:
            return ("warn", f"Not evaluated ({p.skipped_reason})")
        if not p.handshake_ok:
            err = (p.handshake_error or "unknown error").replace("\n", " ")[:220]
            if p.handshake_error and "CERTIFICATE_VERIFY_FAILED" in p.handshake_error:
                return ("bad", f"Certificate verification failed ({err})")
            return ("bad", f"TLS handshake failed ({err})")
        return ("ok", "Certificate chain is valid and trusted")

    @staticmethod
    def _imap_tls_audit_terminal_protocol_level_msg(p: ImapTlsAuditProbeResult) -> tuple[str, str]:
        """Returns (level ok|bad|warn, message) for Protocol line."""
        if not p.attempted and p.skipped_reason:
            return ("warn", "TLS not established (STARTTLS path not exercised)")
        if not p.handshake_ok:
            return ("bad", "TLS not established")
        ver = (p.tls_version or p.cipher_protocol or "").strip()
        if p.weak_tls_version:
            disp = ver or "negotiated protocol"
            return ("bad", f"Legacy TLS version detected ({disp})")
        if "TLSv1.3" in ver or ver.upper() == "TLSV1.3":
            return ("ok", f"Modern TLS version ({ver})")
        if "TLSv1.2" in ver or ver.upper() == "TLSV1.2":
            return ("ok", f"Secure TLS version ({ver})")
        if ver:
            return ("ok", f"Negotiated TLS ({ver})")
        return ("ok", "TLS session established")

    @staticmethod
    def _imap_tls_audit_terminal_verdict_level_msg(
        tr: ImapTlsAuditResult, p: ImapTlsAuditProbeResult
    ) -> tuple[str, str]:
        """Returns (level ok|bad|warn, message) for final Verdict line."""
        if not p.attempted and p.skipped_reason:
            return ("warn", tr.detail)
        if not tr.vulnerable:
            return ("ok", "No TLS/Certificate issues detected")
        rs = [x.strip() for x in tr.detail.split(";") if x.strip()]
        if len(rs) >= 2:
            return ("bad", "Multiple critical TLS/Certificate security issues")
        one = rs[0].lower() if rs else tr.detail.lower()
        if "handshake failed" in one:
            return ("bad", "TLS handshake failed before full certificate assessment")
        if "expir" in one:
            return ("bad", "Certificate expiry / validity issues")
        if "weak tls" in one or ("protocol" in one and "weak" in one):
            return ("bad", "Weak TLS protocol configuration")
        if "cipher" in one:
            return ("bad", "Weak TLS cipher configuration")
        if any(
            k in one
            for k in (
                "weak signature",
                "rsa key",
                "key size",
                "< 2048",
                "sha-1",
                "sha1",
                "md5",
                "sha224",
            )
        ):
            return ("bad", "Certificate cryptographic weaknesses detected")
        return ("bad", tr.detail[:200])

    def test_encryption(self) -> EncryptionResult:
        """
        Test encryption options: plaintext (143), STARTTLS (143), implicit TLS (993).
        Uses fresh connections; does not use self.args.tls/starttls.
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        plaintext_ok = False
        starttls_ok = False
        tls_ok = False
        _ssl_ctx = ssl._create_unverified_context()
        tls_only_port = port == 993

        if not tls_only_port:
            try:
                imap = imaplib.IMAP4(host, port)
                imap.sock.settimeout(timeout)
                _ = imap.welcome
                plaintext_ok = True
                imap.logout()
            except Exception:
                pass

            try:
                imap = imaplib.IMAP4(host, port)
                imap.sock.settimeout(timeout)
                _ = imap.welcome
                caps = [str(c).upper() for c in (imap.capabilities or [])]
                if "STARTTLS" in caps:
                    imap.starttls()
                    _ = imap.capabilities
                    starttls_ok = True
                imap.logout()
            except Exception:
                pass

        _connect_timeout = 15.0 if tls_only_port else timeout
        try:
            try:
                ipaddress.ip_address(host)
                _sni_first, _sni_fallback = None, host
            except ValueError:
                _sni_first, _sni_fallback = host, None
            for _sni in (_sni_first, _sni_fallback):
                if _sni is None and _sni_fallback is None:
                    continue
                try:
                    sock = socket.create_connection((host, port), timeout=_connect_timeout)
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    sock_ssl.settimeout(_connect_timeout)
                    sock_ssl.sendall(b"a001 CAPABILITY\r\n")
                    line = sock_ssl.recv(1024).decode(errors="replace")
                    sock_ssl.close()
                    if line and ("OK" in line or "CAPABILITY" in line):
                        tls_ok = True
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return EncryptionResult(plaintext_ok, starttls_ok, tls_ok)

    @staticmethod
    def _sniffable_error_level_auth_methods(capability: list[str] | None) -> list[str]:
        """AUTH= mechanisms from CAPABILITY that use credential-bearing cleartext SASL (ERROR tier)."""
        if not capability:
            return []
        methods: list[str] = []
        seen: set[str] = set()
        for c in capability:
            u = str(c or "").strip()
            if u.upper().startswith("AUTH="):
                m = u.split("=", 1)[-1].strip().upper()
                if not m or m in seen:
                    continue
                if IMAP_AUTH_METHOD_LEVEL.get(m, "OK") != "ERROR":
                    continue
                seen.add(m)
                methods.append(m)

        def _prio(x: str) -> int:
            try:
                return _SNIFFABLE_AUTH_PROBE_PRIORITY.index(x)
            except ValueError:
                return len(_SNIFFABLE_AUTH_PROBE_PRIORITY)

        return sorted(methods, key=lambda x: (_prio(x), x))

    def _probe_authenticate_cleartext(self, method: str, timeout: float = 10.0) -> str:
        """
        Open a plain IMAP connection, run CAPABILITY, send AUTHENTICATE <method>.
        Returns: continuation (server sent '+'), tagged_no, tagged_bad, not_advertised, io_error
        """
        host = self.args.target.ip
        port = self.args.target.port
        try:
            imap = imaplib.IMAP4(host, port)
            imap.sock.settimeout(timeout)
            _ = imap.welcome
            try:
                imap.capability()
            except Exception:
                pass
            tag_b = imap._new_tag()
            imap.send(tag_b + b" AUTHENTICATE " + method.encode("ascii", errors="ignore") + b"\r\n")
            res = imap.readline().strip()
            if res.startswith(b"+"):
                imap.send(b"*\r\n")
                try:
                    _ = imap.readline()
                except Exception:
                    pass
                outcome = "continuation"
            else:
                parts = res.split()
                if (
                    len(parts) >= 2
                    and parts[0].upper() == tag_b.upper()
                    and parts[1].upper() in (b"NO", b"BAD")
                ):
                    outcome = "tagged_no" if parts[1].upper() == b"NO" else "tagged_bad"
                else:
                    outcome = "other_response"
            try:
                imap.logout()
            except Exception:
                try:
                    imap.shutdown()
                except Exception:
                    pass
            return outcome
        except Exception:
            return "io_error"

    def test_sniffable_plain_imap(self) -> SniffableResult:
        """
        Evaluate whether IMAP credentials or traffic can be exposed on an unencrypted TCP session
        (standard cleartext port 143): missing STARTTLS and/or AUTHENTICATE continuation '+' on plain.
        """
        if self.args.tls:
            return SniffableResult(
                skipped=True,
                skip_reason="implicit_tls_mode (--tls): use plain IMAP target without --tls",
                plain_ok=False,
                starttls_advertised=False,
                auth_methods=tuple(),
                probes=tuple(),
                vulnerable=False,
            )

        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        capability: list[str] = []
        plain_ok = False
        try:
            imap = imaplib.IMAP4(host, port)
            imap.sock.settimeout(timeout)
            _ = imap.welcome
            try:
                imap.capability()
            except Exception:
                pass
            capability = [str(c) for c in (imap.capabilities or [])]
            plain_ok = True
            try:
                imap.logout()
            except Exception:
                pass
        except Exception:
            plain_ok = False

        if not plain_ok:
            return SniffableResult(
                skipped=False,
                skip_reason=None,
                plain_ok=False,
                starttls_advertised=False,
                auth_methods=tuple(),
                probes=tuple(),
                vulnerable=False,
            )

        caps_upper = {c.upper() for c in capability}
        starttls_advertised = "STARTTLS" in caps_upper
        to_probe = self._sniffable_error_level_auth_methods(capability)
        probes_list: list[tuple[str, str]] = []
        weak_continuation = False
        for m in to_probe:
            outcome = self._probe_authenticate_cleartext(m, timeout=timeout)
            probes_list.append((m, outcome))
            if outcome == "continuation":
                weak_continuation = True
                break

        vulnerable = (not starttls_advertised) or weak_continuation

        return SniffableResult(
            skipped=False,
            skip_reason=None,
            plain_ok=True,
            starttls_advertised=starttls_advertised,
            auth_methods=tuple(to_probe),
            probes=tuple(probes_list),
            vulnerable=vulnerable,
        )

    @staticmethod
    def _imap_inv_extract_tag(cmd: bytes) -> bytes | None:
        m = re.match(br"^([A-Za-z0-9][A-Za-z0-9._@-]*)\s", cmd)
        return m.group(1) if m else None

    def _imap_inv_consume_literal(self, imap: imaplib.IMAP4 | imaplib.IMAP4_SSL, stripped: bytes) -> None:
        m = re.match(br"^\{(\d+)\}$", stripped)
        if not m:
            return
        n = int(m.group(1))
        while n > 0:
            imap.sock.settimeout(30.0)
            chunk = imap.sock.recv(min(65536, n))
            if not chunk:
                break
            n -= len(chunk)

    def _imap_inv_read_until_tagged(
        self,
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL,
        expect_tag: bytes | None,
        deadline: float,
    ) -> tuple[str, list[bytes]]:
        lines: list[bytes] = []
        tag_re = (
            re.compile(re.escape(expect_tag) + br"\s+(OK|NO|BAD)\b", re.I) if expect_tag is not None else None
        )
        while time.monotonic() < deadline:
            imap.sock.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                line = imap.readline()
            except (socket.timeout, ssl.SSLError, OSError, BrokenPipeError) as e:
                lines.append(f"[read error: {e}]".encode())
                return ("disconnect", lines)
            if not line:
                return ("disconnect", lines)
            stripped = line.rstrip(b"\r\n")
            lines.append(line)
            if stripped.startswith(b"+"):
                continue
            upper = stripped.upper()
            if upper.startswith(b"* BYE") or (stripped.startswith(b"* ") and b" BYE" in upper):
                return ("bye", lines)
            if tag_re is not None:
                m = tag_re.match(stripped)
                if m:
                    return (m.group(1).decode().upper(), lines)
            else:
                if stripped.startswith(b"* ") and (
                    upper.startswith(b"* BAD") or upper.startswith(b"* NO")
                ):
                    return ("BAD", lines)
                m2 = re.match(br"^([A-Za-z0-9][A-Za-z0-9._@-]*)\s+(OK|NO|BAD)\b", stripped, re.I)
                if m2:
                    return (m2.group(2).decode().upper(), lines)
            self._imap_inv_consume_literal(imap, stripped)
        return ("timeout", lines)

    @staticmethod
    def _imap_inv_info_leak(lines: list[bytes]) -> bool:
        blob = b"\n".join(lines).lower()
        return any(m in blob for m in _INVCOMM_INFO_LEAK_MARKERS)

    @staticmethod
    def _imap_inv_reply_snippet(lines: list[bytes]) -> str | None:
        if not lines:
            return None
        for line in reversed(lines):
            t = line.decode("utf-8", errors="replace").strip()
            if t and not t.startswith("[read error"):
                return (t[:400] + "…") if len(t) > 400 else t
        return None

    def _imap_inv_follow_capability(self, imap: imaplib.IMAP4 | imaplib.IMAP4_SSL, deadline: float) -> bool:
        tag = imap._new_tag()
        imap.send(tag + b" CAPABILITY\r\n")
        outcome, _ = self._imap_inv_read_until_tagged(imap, tag, deadline)
        return outcome == "OK"

    def _imap_inv_baseline_capability_latency(self) -> float | None:
        try:
            imap = self.connect()
            try:
                t0 = time.perf_counter()
                tag = imap._new_tag()
                imap.send(tag + b" CAPABILITY\r\n")
                outcome, _ = self._imap_inv_read_until_tagged(imap, tag, time.monotonic() + 12.0)
                elapsed = time.perf_counter() - t0
                return elapsed if outcome == "OK" else None
            finally:
                try:
                    imap.logout()
                except Exception:
                    try:
                        imap.shutdown()
                    except Exception:
                        pass
        except Exception:
            return None

    def _imap_inv_run_one_probe(
        self,
        category: str,
        wire: bytes,
        display: str,
        slow_threshold: float,
    ) -> InvCommImapCase:
        expect_tag = self._imap_inv_extract_tag(wire)
        t_start = time.perf_counter()
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        lines: list[bytes] = []
        outcome = "error"
        session_after: bool | None = None
        connect_failed = False
        try:
            imap = self.connect()
            imap.send(wire)
            outcome, lines = self._imap_inv_read_until_tagged(
                imap, expect_tag, time.monotonic() + _INVCOMM_READ_DEADLINE_SEC
            )
        except OSError as e:
            if imap is None:
                connect_failed = True
                outcome = "connect_error"
                lines.append(str(e).encode(errors="replace"))
            else:
                outcome = "disconnect"
                lines.append(str(e).encode(errors="replace"))
        except Exception as e:
            if imap is None:
                connect_failed = True
                outcome = "connect_error"
            else:
                outcome = "error"
            lines.append(str(e).encode(errors="replace"))
        finally:
            elapsed = time.perf_counter() - t_start
            slow = category.startswith("long_") and elapsed > slow_threshold
            leak = self._imap_inv_info_leak(lines)
            snippet = self._imap_inv_reply_snippet(lines)
            pv = False
            if connect_failed:
                pv = False
            elif outcome in ("timeout", "disconnect", "bye"):
                pv = True
            elif outcome == "OK":
                pv = True
            elif outcome == "error":
                pv = True
            if imap is not None and outcome in ("OK", "NO", "BAD"):
                try:
                    session_after = self._imap_inv_follow_capability(imap, time.monotonic() + 12.0)
                except Exception:
                    session_after = False
                if session_after is False:
                    pv = True
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    try:
                        imap.shutdown()
                    except Exception:
                        pass
        return InvCommImapCase(
            category=category,
            command_display=display,
            outcome=outcome,
            reply_snippet=snippet,
            response_time_sec=elapsed,
            slow_response=slow,
            info_leak=leak,
            session_ok_after=session_after,
            probe_vulnerable=pv,
        )

    def test_invalid_commands_imap(self) -> InvCommImapResult:
        """
        Invalid / non-standard IMAP command resilience (PTV-SVC-IMAP-INVCOMM).
        RFC 3501: unknown or malformed client commands should yield tagged BAD/NO and stable sessions.
        """
        baseline = self._imap_inv_baseline_capability_latency()
        slow_th = max(_INVCOMM_SLOW_BASE_SEC, (baseline or 0) + _INVCOMM_SLOW_EXTRA_SEC)
        long_a = b"A" * _LONG_COMMAND_BODY_LEN
        long_b = b"B" * _LONG_COMMAND_BODY_LEN
        probes: list[tuple[str, bytes, str]] = [
            ("invalid_cmd", b"A1 HELLO\r\n", "A1 HELLO"),
            ("invalid_cmd", b"A2 LOGIN\r\n", "A2 LOGIN (no args)"),
            ("invalid_cmd", b"A3 SELECTT INBOX\r\n", "A3 SELECTT INBOX"),
            ("invalid_cmd", b"A4 FETCHX 1 BODY[]\r\n", "A4 FETCHX 1 BODY[]"),
            ("invalid_cmd", b"A5 FOO BAR\r\n", "A5 FOO BAR"),
            ("bad_tag", b"LOGIN user pass\r\n", "LOGIN user pass (no tag)"),
            ("bad_tag", b"A6 A7 SELECT INBOX\r\n", "A6 A7 SELECT INBOX"),
            ("incomplete", b"A8 SELECT\r\n", "A8 SELECT (incomplete)"),
            (
                "long_login",
                b"A9 LOGIN " + long_a + b" pass\r\n",
                f"A9 LOGIN (A×{_LONG_COMMAND_BODY_LEN}) pass",
            ),
            ("long_select", b"A10 SELECT " + long_b + b"\r\n", f"A10 SELECT (B×{_LONG_COMMAND_BODY_LEN})"),
            ("binary_null", b"A11 LOGIN test\x00user pass\r\n", "A11 LOGIN (NUL)"),
            ("binary_high", b"A12 FETCH 1 BODY[\xff]\r\n", "A12 FETCH (0xFF)"),
        ]
        cases = tuple(self._imap_inv_run_one_probe(c, w, d, slow_th) for c, w, d in probes)
        if cases and all(t.outcome == "connect_error" for t in cases):
            return InvCommImapResult(
                tests=cases,
                vulnerable=False,
                weakness=False,
                detail="Could not establish IMAP session for probes (target, port, firewall).",
                baseline_latency_sec=baseline,
            )
        vulnerable = any(t.probe_vulnerable for t in cases)
        weakness = any(t.slow_response or t.info_leak for t in cases)
        bad = [t for t in cases if t.probe_vulnerable]
        if bad:
            detail = (
                "Failing probes (unstable session / unexpected OK / timeout / disconnect): "
                + "; ".join(f"{x.command_display} → {x.outcome}" for x in bad)
            )
        elif weakness:
            detail = (
                "Server responded but slow handling of long input and/or an overly verbose error was observed."
            )
        else:
            detail = "Probes completed without indicators of critical parsing or session weakness (PTV-SVC-IMAP-INVCOMM)."
        return InvCommImapResult(
            tests=cases,
            vulnerable=vulnerable,
            weakness=weakness,
            detail=detail,
            baseline_latency_sec=baseline,
        )

    def connect(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        """
        Establishes a new IMAP connection with the appropriate
        encryption mode according to module arguments

        Returns:
            imaplib.IMAP4 | imaplib.IMAP4_SSL: new connection
        """
        try:
            return self._make_imap_connection()
        except Exception as e:
            msg = (
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
            )
            raise OSError(msg) from e

    def info(self, get_commands: bool = True) -> InfoResult:
        """Performs bannergrabbing; optionally ID and CAPABILITY commands."""
        return self._do_info(self.imap, get_commands)

    def _try_authenticate_anonymous(self, imap: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> bool:
        """RFC 4505 SASL ANONYMOUS over IMAP AUTHENTICATE (imaplib supplies base64 trace)."""

        def authobject(b: bytes):
            return b"".join(
                random.choice(ascii_letters).encode() for _ in range(random.randint(5, 10))
            )

        try:
            typ, _ = imap.authenticate("ANONYMOUS", authobject)
            return typ == "OK"
        except Exception:
            return False

    def _try_login_pair(self, user: str, password: str) -> bool:
        try:
            imap = self.connect()
        except Exception:
            return False
        try:
            try:
                imap.login(user, password)
                return True
            except Exception:
                return False
        finally:
            try:
                imap.logout()
            except Exception:
                try:
                    imap.shutdown()
                except Exception:
                    pass

    @staticmethod
    def _merged_preauth_capabilities(
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL,
    ) -> tuple[str | None, list[str]]:
        banner = imap.welcome.decode() if imap.welcome else None
        capa_imap = [str(c) for c in (imap.capabilities or [])]
        capa_banner = _extract_capabilities_from_banner(banner)
        merged = list(dict.fromkeys(capa_imap + capa_banner)) or capa_imap or capa_banner
        return banner, merged

    @staticmethod
    def _capability_advertises_auth_anonymous(
        capability: list[str] | None, banner: str | None
    ) -> bool:
        if capability:
            for c in capability:
                if str(c).upper().strip() == "AUTH=ANONYMOUS":
                    return True
        if banner and "AUTH=ANONYMOUS" in banner.upper():
            return True
        return False

    @staticmethod
    def _capability_advertises_auth_ntlm(capability: list[str] | None, banner: str | None) -> bool:
        if capability:
            for c in capability:
                if str(c).upper().strip() == "AUTH=NTLM":
                    return True
        if banner and "AUTH=NTLM" in banner.upper():
            return True
        return False

    @staticmethod
    def _capability_advertises_auth_plain(capability: list[str] | None, banner: str | None) -> bool:
        if capability:
            for c in capability:
                if str(c).upper().strip() == "AUTH=PLAIN":
                    return True
        if banner and "AUTH=PLAIN" in banner.upper():
            return True
        return False

    @staticmethod
    def _capability_logindisabled(capability: list[str] | None, banner: str | None) -> bool:
        """True when server advertises LOGINDISABLED (plaintext LOGIN must not be used)."""
        if capability:
            for c in capability:
                if str(c).upper().strip() == "LOGINDISABLED":
                    return True
        if banner and "LOGINDISABLED" in banner.upper():
            return True
        return False

    def test_anonymous_access(self) -> AnonymousAccessResult:
        """
        Probe anonymous and weak default IMAP logins (PTL-SVC-IMAP-ANONYMOUS).
        RFC 4505 (SASL ANONYMOUS); pre-auth CAPABILITY may list AUTH=ANONYMOUS (RFC 3501).
        """
        auth_anonymous_advertised = False
        authenticate_anonymous_ok = False
        login_anonymous_empty_ok = False
        weak_hits: list[str] = []

        imap_cap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        try:
            imap_cap = self.connect()
            banner, merged = self._merged_preauth_capabilities(imap_cap)
            auth_anonymous_advertised = self._capability_advertises_auth_anonymous(merged, banner)
            authenticate_anonymous_ok = self._try_authenticate_anonymous(imap_cap)
        except Exception:
            pass
        finally:
            if imap_cap is not None:
                try:
                    imap_cap.logout()
                except Exception:
                    try:
                        imap_cap.shutdown()
                    except Exception:
                        pass

        login_probes: list[tuple[str, str, str]] = [
            ("anonymous", "", "LOGIN anonymous / empty password"),
            ("anonymous", "anonymous", "LOGIN anonymous / anonymous"),
            ("guest", "", "LOGIN guest / empty password"),
            ("guest", "guest", "LOGIN guest / guest"),
            ("public", "", "LOGIN public / empty password"),
            ("public", "public", "LOGIN public / public"),
        ]
        for user, password, _label in login_probes:
            if self._try_login_pair(user, password):
                if user == "anonymous" and password == "":
                    login_anonymous_empty_ok = True
                else:
                    weak_hits.append(f"{user} / {password if password else '<empty>'}")

        vulnerable = bool(
            authenticate_anonymous_ok or login_anonymous_empty_ok or weak_hits
        )
        parts: list[str] = []
        if auth_anonymous_advertised:
            parts.append("Pre-auth CAPABILITY advertises AUTH=ANONYMOUS")
        if authenticate_anonymous_ok:
            parts.append("AUTHENTICATE ANONYMOUS completed (OK)")
        if login_anonymous_empty_ok:
            parts.append("LOGIN anonymous with empty password succeeded")
        if weak_hits:
            parts.append("Weak default accounts: " + "; ".join(weak_hits))
        if not vulnerable:
            if auth_anonymous_advertised:
                parts.append("SASL ANONYMOUS advertised; authenticated login failed or was denied")
            detail = (
                "; ".join(parts)
                if parts
                else "Anonymous or default accounts (anonymous/guest/public) are not available."
            )
        else:
            detail = "; ".join(parts) if parts else "Anonymous or weak default IMAP access detected."

        return AnonymousAccessResult(
            auth_anonymous_advertised=auth_anonymous_advertised,
            authenticate_anonymous_ok=authenticate_anonymous_ok,
            login_anonymous_empty_ok=login_anonymous_empty_ok,
            weak_credentials_ok=tuple(weak_hits),
            vulnerable=vulnerable,
            detail=detail,
        )

    @staticmethod
    def _eicar_rfc822_bytes() -> bytes:
        """Minimal RFC 822 message whose body is the standard EICAR test line."""
        lines = [
            "From: ptsrvtester <ptsrvtester@invalid>",
            "To: ptsrvtester <ptsrvtester@invalid>",
            "Subject: EICAR antivirus test",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=us-ascii",
            "",
            _EICAR_STANDARD_LINE,
        ]
        return "\r\n".join(lines).encode("ascii")

    def test_eicar_append(self) -> EicarAppendResult:
        """
        APPEND a minimal RFC 822 message containing the EICAR test line.
        OK implies the server accepted the payload without rejecting it as malware (PTV-SVC-IMAP-EICAR).
        """
        mb = (getattr(self.args, "eicar_mailbox", None) or "INBOX").strip() or "INBOX"
        pair = self._imap_single_known_login()
        if not pair:
            return EicarAppendResult(
                skipped=True,
                skip_reason="requires single -u and -p (no wordlists)",
                mailbox=mb,
                append_typ=None,
                append_detail=None,
                vulnerable=False,
            )
        user, password = pair
        msg = self._eicar_rfc822_bytes()
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        try:
            imap = self.connect()
            imap.login(user, password)
            typ, data = imap.append(mb, None, None, msg)
            detail: str | None = None
            if data:
                try:
                    raw = data[0]
                    detail = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
                    detail = detail[:500]
                except Exception:
                    detail = str(data)[:500]
            return EicarAppendResult(
                skipped=False,
                skip_reason=None,
                mailbox=mb,
                append_typ=typ,
                append_detail=detail,
                vulnerable=(typ == "OK"),
            )
        except Exception as e:
            return EicarAppendResult(
                skipped=True,
                skip_reason=str(e),
                mailbox=mb,
                append_typ=None,
                append_detail=None,
                vulnerable=False,
            )
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    try:
                        imap.shutdown()
                    except Exception:
                        pass

    @staticmethod
    def _imap_load_small_rfc822(seq: int) -> bytes:
        """Tiny RFC 822 message for bounded APPEND stress (distinct Subject per message)."""
        body = ("A" * 180) + f"\nseq={seq}\n"
        lines = [
            "From: ptsrvtester <ptsrv@invalid>",
            "To: ptsrvtester <ptsrv@invalid>",
            f"Subject: ptsrv-resload-{seq}",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=us-ascii",
            "",
            body,
        ]
        return "\r\n".join(lines).encode("ascii", errors="replace")

    @staticmethod
    def _imap_resource_load_finish_phase(
        label: str,
        attempted: int,
        ok: int,
        failed: int,
        rtts: list[float],
        disconnected: bool,
        disconnect_after: int | None,
        hit_cap: bool,
    ) -> ImapResourceLoadPhase:
        window = 10
        baseline = (sum(rtts[:window]) / min(len(rtts), window)) if rtts else None
        last_rtts = rtts[-window:] if len(rtts) >= window else rtts
        last_w = (sum(last_rtts) / len(last_rtts)) if last_rtts else None
        slowdown = False
        if baseline is not None and last_w is not None and len(rtts) >= window * 2:
            slowdown = (last_w >= baseline * _IMAP_LOAD_SLOWDOWN_RATIO) or (
                last_w >= _IMAP_LOAD_SLOWDOWN_ABS_SEC
            )
        err_pct = (100.0 * failed / attempted) if attempted else 0.0
        min_rt = min(rtts) if rtts else None
        max_rt = max(rtts) if rtts else None
        avg_rt = (sum(rtts) / len(rtts)) if rtts else None
        return ImapResourceLoadPhase(
            label=label,
            attempted=attempted,
            ok=ok,
            failed=failed,
            disconnected=disconnected,
            disconnect_after=disconnect_after,
            hit_cap=hit_cap,
            min_rt_seconds=min_rt,
            max_rt_seconds=max_rt,
            avg_rt_seconds=avg_rt,
            baseline_avg_seconds=baseline,
            last_window_avg_seconds=last_w,
            slowdown=slowdown,
            error_rate_pct=err_pct,
        )

    def test_imap_resource_load(self) -> ImapResourceLoadResult:
        """
        Bounded authenticated APPEND burst + UID SEARCH ALL loop (PTV-SVC-IMAP-RESLOAD).
        Heuristic similar to SMTP NOOP flood: disconnect early, high error rate, or RT slowdown → weak limits.
        """
        mb = (getattr(self.args, "imap_resource_load_mailbox", None) or "INBOX").strip() or "INBOX"
        pair = self._imap_single_known_login()
        append_max = int(getattr(self.args, "imap_resource_load_append_max", 0) or 0)
        search_max = int(getattr(self.args, "imap_resource_load_search_max", 0) or 0)
        if not pair:
            return ImapResourceLoadResult(
                skipped=True,
                skip_reason="requires single -u and -p (no wordlists)",
                mailbox=mb,
                append_max_requested=append_max,
                search_max_requested=search_max,
                append=None,
                search=None,
                search_skipped_reason=None,
                vulnerable=False,
                detail="Skipped: single known credentials required.",
            )
        user, password = pair
        _show = not self.use_json
        _lock = threading.Lock()

        def _live(text: str) -> None:
            if not _show:
                return
            with _lock:
                sys.stdout.write(f"\r    {text:<110}")
                sys.stdout.flush()

        def _live_done() -> None:
            if not _show:
                return
            with _lock:
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()

        def _login_session() -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
            cl = self.connect()
            cl.login(user, password)
            sock = getattr(cl, "sock", None)
            if sock is not None:
                try:
                    sock.settimeout(_IMAP_LOAD_PER_CMD_TIMEOUT_SEC)
                except Exception:
                    pass
            return cl

        append_phase: ImapResourceLoadPhase | None = None
        search_phase: ImapResourceLoadPhase | None = None
        search_skip: str | None = None
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None

        try:
            imap = _login_session()
            try:
                imap.select(mb)
            except Exception as e:
                return ImapResourceLoadResult(
                    skipped=True,
                    skip_reason=str(e),
                    mailbox=mb,
                    append_max_requested=append_max,
                    search_max_requested=search_max,
                    append=None,
                    search=None,
                    search_skipped_reason=None,
                    vulnerable=False,
                    detail=f"SELECT/EXAMINE {mb!r} failed: {e}",
                )

            a_ok = a_fail = 0
            a_disc = False
            a_disc_after: int | None = None
            a_rtts: list[float] = []
            for i in range(append_max):
                t0 = time.perf_counter()
                try:
                    typ, _dat = imap.append(mb, None, None, self._imap_load_small_rfc822(i))
                    rt = time.perf_counter() - t0
                    if typ == "OK":
                        a_ok += 1
                        a_rtts.append(rt)
                    else:
                        a_fail += 1
                except Exception:
                    a_fail += 1
                    a_disc = True
                    a_disc_after = i + 1
                    break
                if _show and (a_ok + a_fail) % _IMAP_LOAD_PROGRESS_APPEND_INTERVAL == 0:
                    _live(f"APPEND {a_ok + a_fail}/{append_max} ok={a_ok} err={a_fail}")
            a_attempted = a_ok + a_fail
            a_hit_cap = a_attempted >= append_max and not a_disc
            append_phase = self._imap_resource_load_finish_phase(
                "APPEND",
                a_attempted,
                a_ok,
                a_fail,
                a_rtts,
                a_disc,
                a_disc_after,
                a_hit_cap,
            )
            _live_done()

            if search_max > 0:
                if a_disc:
                    try:
                        imap.logout()
                    except Exception:
                        try:
                            imap.shutdown()
                        except Exception:
                            pass
                    imap = None
                    try:
                        imap = _login_session()
                        imap.select(mb)
                    except Exception as e:
                        search_skip = f"reconnect after APPEND disconnect failed: {e}"
                    else:
                        search_skip = None
                s_ok = s_fail = 0
                s_disc = False
                s_disc_after: int | None = None
                s_rtts: list[float] = []
                if imap is not None and search_skip is None:
                    for j in range(search_max):
                        t0 = time.perf_counter()
                        try:
                            typ, _dat = imap.uid("SEARCH", None, "ALL")
                            rt = time.perf_counter() - t0
                            if typ == "OK":
                                s_ok += 1
                                s_rtts.append(rt)
                            else:
                                s_fail += 1
                        except Exception:
                            s_fail += 1
                            s_disc = True
                            s_disc_after = j + 1
                            break
                        if _show and (s_ok + s_fail) % _IMAP_LOAD_SEARCH_INTERVAL == 0:
                            _live(f"UID SEARCH {s_ok + s_fail}/{search_max} ok={s_ok} err={s_fail}")
                    s_attempted = s_ok + s_fail
                    s_hit_cap = s_attempted >= search_max and not s_disc
                    search_phase = self._imap_resource_load_finish_phase(
                        "SEARCH",
                        s_attempted,
                        s_ok,
                        s_fail,
                        s_rtts,
                        s_disc,
                        s_disc_after,
                        s_hit_cap,
                    )
                _live_done()
            else:
                search_skip = "SEARCH phase disabled (--resource-load-search-max 0)"

        finally:
            _live_done()
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    try:
                        imap.shutdown()
                    except Exception:
                        pass

        reasons: list[str] = []
        if append_phase:
            if append_phase.disconnected and append_phase.disconnect_after is not None:
                if append_phase.disconnect_after <= _IMAP_LOAD_DISCONNECT_EARLY_MAX:
                    reasons.append(
                        f"connection dropped during APPEND after only {append_phase.disconnect_after} attempts"
                    )
            if append_phase.slowdown:
                reasons.append("APPEND round-trip slowdown vs baseline (possible tarpit or overload)")
            if append_phase.error_rate_pct > _IMAP_LOAD_ERR_OK_MAX_PCT:
                reasons.append(f"high APPEND error/no-OK rate ({append_phase.error_rate_pct:.1f}%)")
        if search_phase:
            if search_phase.disconnected and search_phase.disconnect_after is not None:
                if search_phase.disconnect_after <= _IMAP_LOAD_DISCONNECT_EARLY_MAX:
                    reasons.append(
                        f"connection dropped during SEARCH after {search_phase.disconnect_after} commands"
                    )
            if search_phase.slowdown:
                reasons.append("SEARCH round-trip slowdown vs baseline")
            if search_phase.error_rate_pct > _IMAP_LOAD_ERR_OK_MAX_PCT:
                reasons.append(f"high SEARCH error rate ({search_phase.error_rate_pct:.1f}%)")
        vuln = len(reasons) > 0
        detail = "; ".join(reasons) if reasons else (
            "Bounded APPEND/SEARCH completed without strong disconnect, slowdown, or error-rate signals."
        )
        return ImapResourceLoadResult(
            skipped=False,
            skip_reason=None,
            mailbox=mb,
            append_max_requested=append_max,
            search_max_requested=search_max,
            append=append_phase,
            search=search_phase,
            search_skipped_reason=search_skip,
            vulnerable=vuln,
            detail=detail,
        )

    @staticmethod
    def _imap_list_line_mailbox_name(line: bytes) -> str | None:
        """Best-effort mailbox name from one untagged LIST line (last quoted string)."""
        s = line.decode(errors="replace")
        parts = re.findall(r'"((?:\\.|[^"\\])*)"', s)
        if not parts:
            return None
        raw = parts[-1]
        return raw.replace("\\\\", "\\").replace('\\"', '"')

    @staticmethod
    def _imap_acl_rights_world_sensitive(rights: str) -> bool:
        """True when world-style identifier holds mail-altering / read-class rights (heuristic)."""
        return bool(set((rights or "").lower()) & set("rwetd"))

    @staticmethod
    def _imap_parse_getacl_world(
        typ: str | None, data
    ) -> tuple[str | None, str | None, str | None, bool, str | None]:
        """
        Extract rights for anyone/anonymous/authenticated from GETACL payload.
        Returns (anyone_rights, anonymous_rights, authenticated_rights, overbroad, raw_truncated).
        """
        if typ != "OK" or not data:
            return None, None, None, False, None
        blob = b"\n".join(x for x in data if isinstance(x, bytes))
        text = blob.decode(errors="replace")
        raw_trunc = text[:6000] if len(text) > 6000 else text
        anyone_r: str | None = None
        anon_r: str | None = None
        auth_r: str | None = None
        over = False
        for ident, rights in re.findall(
            r"\b(anyone|anonymous|guest|authenticated)\s+(\S+)", text, re.IGNORECASE
        ):
            il = ident.lower()
            r_clean = rights.strip()
            sens = IMAP._imap_acl_rights_world_sensitive(r_clean)
            if il in ("anyone", "guest"):
                anyone_r = r_clean if anyone_r is None else f"{anyone_r},{r_clean}"
                if sens:
                    over = True
            elif il == "anonymous":
                anon_r = r_clean if anon_r is None else f"{anon_r},{r_clean}"
                if sens:
                    over = True
            elif il == "authenticated":
                auth_r = r_clean if auth_r is None else f"{auth_r},{r_clean}"
                if sens:
                    over = True
        return anyone_r, anon_r, auth_r, over, raw_trunc

    @staticmethod
    def _imap_foreign_like_mailbox_visible(name: str, fu: str, login: str, own_mb: str) -> bool:
        """Heuristic: LIST name looks like another user's tree (not the logged-in principal)."""
        nl = name.lower()
        fl = fu.lower()
        ll = login.lower()
        ol = (own_mb or "INBOX").lower()
        if not fl or fl == ll:
            return False
        if nl == ol or nl == "inbox":
            return False
        if f"/{fl}/" in f"/{nl}/" or nl.startswith(fl + "/"):
            return True
        if nl == "inbox." + fl or nl.startswith("inbox." + fl + ".") or nl.startswith("inbox." + fl + "/"):
            return True
        if nl.startswith("#mail/" + fl) and (len(nl) == len("#mail/" + fl) or nl[len("#mail/" + fl)] == "/"):
            return True
        if "../" in nl and f"/{fl}/" in nl:
            return True
        if nl.startswith(fl + ".inbox"):
            return True
        return False

    def test_imap_mailbox_iso(self) -> ImapMailboxIsoResult:
        """
        Post-login mailbox isolation & shared-folder hygiene (PTV-SVC-IMAP-AUTHZ-BYPASS).
        Baseline SELECT on own mailbox; cross-mailbox attempts use EXAMINE when supported (read-only).
        LIST "" "*", bounded LIST dictionary, NAMESPACE, GETACL on own mailbox.
        """
        own_mb = (getattr(self.args, "imap_mailbox_iso_mailbox", None) or "INBOX").strip() or "INBOX"
        fu = (getattr(self.args, "imap_mailbox_iso_foreign_user", None) or "user2").strip() or "user2"
        pair = self._imap_single_known_login()
        if not pair:
            return ImapMailboxIsoResult(
                skipped=True,
                skip_reason="requires single -u and -p (no wordlists)",
                own_mailbox=own_mb,
                foreign_user_token=fu,
                login_username="",
                acl_in_capability=False,
                namespace_typ=None,
                namespace_raw=None,
                get_acl_typ=None,
                get_acl_raw=None,
                acl_anyone_rights=None,
                acl_anonymous_rights=None,
                acl_authenticated_rights=None,
                acl_overbroad_world=False,
                list_root_typ=None,
                list_root_count=0,
                list_root_truncated=False,
                list_root_sample=tuple(),
                foreign_like_mailbox_visible_in_root_list=False,
                select_probes=tuple(),
                list_dictionary=tuple(),
                list_dictionary_total_listed=0,
                list_dictionary_nonzero_patterns=0,
                enumeration_signal=False,
                foreign_examine_ok=False,
                vulnerable=False,
                detail="Skipped: single known credentials required.",
            )
        login_user, password = pair
        _show = not self.use_json
        _lock = threading.Lock()

        def _live(msg: str) -> None:
            if not _show:
                return
            with _lock:
                sys.stdout.write(f"\r    {msg:<110}")
                sys.stdout.flush()

        def _live_done() -> None:
            if not _show:
                return
            with _lock:
                sys.stdout.write("\r" + " " * 120 + "\r")
                sys.stdout.flush()

        def _recover_own(imap: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> None:
            try:
                imap.select(own_mb)
            except Exception:
                try:
                    if hasattr(imap, "unselect"):
                        imap.unselect()
                except Exception:
                    pass

        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        namespace_typ: str | None = None
        namespace_raw: str | None = None
        get_acl_typ: str | None = None
        get_acl_raw: str | None = None
        anyone_r = anon_r = auth_r = None
        acl_over = False
        list_root_typ: str | None = None
        list_root_count = 0
        list_root_truncated = False
        list_root_sample: list[str] = []
        foreign_visible_root = False
        dict_rows: list[ImapMailboxIsoListSurveyRow] = []
        select_rows: list[ImapMailboxIsoSelectRow] = []
        acl_in_capa = False

        try:
            imap = self.connect()
            imap.login(login_user, password)
            sock = getattr(imap, "sock", None)
            if sock is not None:
                try:
                    sock.settimeout(_IMAP_MBOX_ISO_CMD_TIMEOUT_SEC)
                except Exception:
                    pass
            caps = [str(c).upper() for c in (imap.capabilities or [])]
            acl_in_capa = "ACL" in caps
            try:
                imap.enable("UTF8=ACCEPT")
            except Exception:
                pass

            try:
                typ0, _ = imap.select(own_mb)
            except Exception as e:
                return ImapMailboxIsoResult(
                    skipped=True,
                    skip_reason=str(e),
                    own_mailbox=own_mb,
                    foreign_user_token=fu,
                    login_username=login_user,
                    acl_in_capability=acl_in_capa,
                    namespace_typ=None,
                    namespace_raw=None,
                    get_acl_typ=None,
                    get_acl_raw=None,
                    acl_anyone_rights=None,
                    acl_anonymous_rights=None,
                    acl_authenticated_rights=None,
                    acl_overbroad_world=False,
                    list_root_typ=None,
                    list_root_count=0,
                    list_root_truncated=False,
                    list_root_sample=tuple(),
                    foreign_like_mailbox_visible_in_root_list=False,
                    select_probes=tuple(),
                    list_dictionary=tuple(),
                    list_dictionary_total_listed=0,
                    list_dictionary_nonzero_patterns=0,
                    enumeration_signal=False,
                    foreign_examine_ok=False,
                    vulnerable=False,
                    detail=f"Baseline SELECT {own_mb!r} failed: {e}",
                )
            if typ0 != "OK":
                return ImapMailboxIsoResult(
                    skipped=True,
                    skip_reason=None,
                    own_mailbox=own_mb,
                    foreign_user_token=fu,
                    login_username=login_user,
                    acl_in_capability=acl_in_capa,
                    namespace_typ=None,
                    namespace_raw=None,
                    get_acl_typ=None,
                    get_acl_raw=None,
                    acl_anyone_rights=None,
                    acl_anonymous_rights=None,
                    acl_authenticated_rights=None,
                    acl_overbroad_world=False,
                    list_root_typ=str(typ0),
                    list_root_count=0,
                    list_root_truncated=False,
                    list_root_sample=tuple(),
                    foreign_like_mailbox_visible_in_root_list=False,
                    select_probes=tuple(),
                    list_dictionary=tuple(),
                    list_dictionary_total_listed=0,
                    list_dictionary_nonzero_patterns=0,
                    enumeration_signal=False,
                    foreign_examine_ok=False,
                    vulnerable=False,
                    detail=f"Baseline SELECT {own_mb!r} returned {typ0!r}",
                )

            try:
                namespace_typ, ns_dat = imap.namespace()
                if ns_dat and isinstance(ns_dat[0], bytes):
                    nst = ns_dat[0].decode(errors="replace")
                    namespace_raw = nst[:4000] if len(nst) > 4000 else nst
                else:
                    namespace_raw = None
            except Exception as e:
                namespace_typ = "EXC"
                namespace_raw = str(e)[:500]

            if acl_in_capa:
                try:
                    get_acl_typ, get_acl_dat = imap.getacl(own_mb)
                    anyone_r, anon_r, auth_r, acl_over, get_acl_raw = self._imap_parse_getacl_world(
                        get_acl_typ, get_acl_dat if get_acl_dat is not None else []
                    )
                except Exception as e:
                    get_acl_typ = "EXC"
                    get_acl_raw = str(e)[:800]
            else:
                get_acl_typ = "SKIP"
                get_acl_raw = "ACL not in CAPABILITY — GETACL not attempted"

            try:
                list_root_typ, list_dat = imap.list('""', "*")
            except Exception as e:
                list_root_typ = "EXC"
                list_dat = []
                list_root_sample = [f"(list error: {e})"][:3]

            names_acc: list[str] = []
            if list_root_typ == "OK" and list_dat:
                for atom in list_dat:
                    if not isinstance(atom, bytes):
                        continue
                    nm = self._imap_list_line_mailbox_name(atom)
                    if nm:
                        names_acc.append(nm)
                        if len(names_acc) >= _IMAP_MBOX_ISO_LIST_ROOT_MAX_PARSE:
                            list_root_truncated = True
                            break
            list_root_count = len(names_acc)
            for nm in names_acc[:_IMAP_MBOX_ISO_LIST_SAMPLE]:
                list_root_sample.append(nm)
            for nm in names_acc:
                if self._imap_foreign_like_mailbox_visible(nm, fu, login_user, own_mb):
                    foreign_visible_root = True
                    break

            n_pat = len(_IMAP_MBOX_ISO_LIST_DICTIONARY_PATTERNS)
            for i, pat in enumerate(_IMAP_MBOX_ISO_LIST_DICTIONARY_PATTERNS, start=1):
                if _show and (i % _IMAP_MBOX_ISO_DICT_PROGRESS_EVERY == 0 or i == n_pat):
                    _live(f"mailbox-iso LIST \"\" {pat!r}  ({i}/{n_pat})")
                lt = ld = None
                lnames: list[str] = []
                try:
                    lt, ldat = imap.list('""', pat)
                    ld = None
                    if lt == "OK" and ldat:
                        for atom in ldat:
                            if not isinstance(atom, bytes):
                                continue
                            nn = self._imap_list_line_mailbox_name(atom)
                            if nn:
                                lnames.append(nn)
                except Exception as e:
                    lt = "EXC"
                    ld = str(e)[:400]
                sample_t = tuple(lnames[:5])
                dict_rows.append(
                    ImapMailboxIsoListSurveyRow(
                        reference='""',
                        pattern=pat,
                        typ=lt,
                        detail=ld,
                        listed_count=len(lnames),
                        sample_mailboxes=sample_t,
                    )
                )
            _live_done()

            probe_specs: list[tuple[str, str]] = [
                ("foreign_slash_inbox", f"{fu}/INBOX"),
                ("foreign_inbox_dotprefix", f"INBOX.{fu}"),
                ("foreign_hashmail", f"#mail/{fu}"),
                ("path_dotdot", f"../{fu}/INBOX"),
                ("foreign_dotinbox", f"{fu}.INBOX"),
                ("unicode_mailbox_us_eacute", "usér2"),
            ]
            for pid, mbx in probe_specs:
                detail: str | None = None
                typ: str | None = None
                ok_sel = False
                try:
                    if hasattr(imap, "examine"):
                        typ, dat = imap.examine(mbx)
                    else:
                        typ, dat = imap.select(mbx)
                    ok_sel = typ == "OK"
                    if dat:
                        try:
                            raw = dat[-1]
                            detail = (
                                raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
                            )[:400]
                        except Exception:
                            detail = str(dat)[:400]
                except Exception as e:
                    typ = "EXC"
                    detail = str(e)[:400]
                if ok_sel and mbx != own_mb:
                    _recover_own(imap)
                elif typ == "EXC":
                    _recover_own(imap)
                select_rows.append(
                    ImapMailboxIsoSelectRow(
                        probe_id=pid,
                        mailbox=mbx,
                        typ=typ,
                        detail=detail,
                        ok_selected=ok_sel,
                    )
                )

        finally:
            _live_done()
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    try:
                        imap.shutdown()
                    except Exception:
                        pass

        dict_total = sum(r.listed_count for r in dict_rows)
        dict_nonzero = sum(1 for r in dict_rows if r.listed_count > 0)
        enum_sig = (dict_total >= _IMAP_MBOX_ISO_ENUM_MIN_TOTAL_LISTED) or (
            dict_nonzero >= _IMAP_MBOX_ISO_ENUM_MIN_NONZERO_PATTERNS and dict_total >= 5
        )
        foreign_ok = any(
            r.ok_selected
            for r in select_rows
            if r.mailbox.strip().lower() != (own_mb or "").strip().lower()
        )
        parts: list[str] = []
        if foreign_ok:
            hits = [f"{r.probe_id}={r.mailbox!r}" for r in select_rows if r.ok_selected]
            parts.append("EXAMINE accepted non-home mailbox path(s): " + "; ".join(hits))
        if acl_over:
            parts.append(
                "GETACL: anyone/anonymous/authenticated has sensitive rights (r/w/e/t/d class heuristic)"
            )
        elif anyone_r or anon_r:
            parts.append(
                "GETACL: world-style identifiers present (review rights even if not flagged sensitive)"
            )
        if foreign_visible_root:
            parts.append(f'LIST "" "*" shows names matching foreign token {fu!r} (information leak risk)')
        if enum_sig:
            parts.append(
                f"LIST dictionary: {dict_nonzero} patterns returned mailboxes ({dict_total} total rows) — enumeration surface"
            )
        if not parts:
            parts.append(
                "No cross-user EXAMINE OK, no broad world ACL rights heuristic, limited LIST exposure by this probe."
            )
        vuln = bool(foreign_ok or acl_over or foreign_visible_root or enum_sig)
        detail = "; ".join(parts)
        return ImapMailboxIsoResult(
            skipped=False,
            skip_reason=None,
            own_mailbox=own_mb,
            foreign_user_token=fu,
            login_username=login_user,
            acl_in_capability=acl_in_capa,
            namespace_typ=namespace_typ,
            namespace_raw=namespace_raw,
            get_acl_typ=get_acl_typ,
            get_acl_raw=get_acl_raw,
            acl_anyone_rights=anyone_r,
            acl_anonymous_rights=anon_r,
            acl_authenticated_rights=auth_r,
            acl_overbroad_world=acl_over,
            list_root_typ=list_root_typ,
            list_root_count=list_root_count,
            list_root_truncated=list_root_truncated,
            list_root_sample=tuple(list_root_sample),
            foreign_like_mailbox_visible_in_root_list=foreign_visible_root,
            select_probes=tuple(select_rows),
            list_dictionary=tuple(dict_rows),
            list_dictionary_total_listed=dict_total,
            list_dictionary_nonzero_patterns=dict_nonzero,
            enumeration_signal=enum_sig,
            foreign_examine_ok=foreign_ok,
            vulnerable=vuln,
            detail=detail,
        )

    def _usrenum_eta_remaining_seconds(self, done: int, total: int, elapsed: float) -> float | None:
        if done <= 0 or total <= 0 or done >= total:
            return None
        return elapsed * (total - done) / done

    def _format_usrenum_clock(self, seconds: float | None) -> str:
        if seconds is None:
            return "--:--:--"
        sec = max(0.0, float(seconds))
        h, rem = divmod(int(sec + 0.5), 3600)
        m, s = divmod(rem, 60)
        return f"{h:d}:{m:02d}:{s:02d}"

    def _usrenum_progress_reset(self) -> None:
        self._usrenum_mt_progress_line_active = False
        self._usrenum_progress_start = time.time()

    def _usrenum_progress_update(self, done: int, total: int, *, label: str = "LOGIN enum") -> None:
        if self.use_json or total <= 0:
            return
        start = self._usrenum_progress_start or time.time()
        elapsed = max(0.0, time.time() - start)
        pct = min(100, max(0, int(100 * done / total)))
        eta_sec = self._usrenum_eta_remaining_seconds(done, total, elapsed)
        time_part = self._format_usrenum_clock(eta_sec)
        line_core = f"{label} {done}/{total}  {time_part}  {pct}%"
        th = max(1, int(getattr(self.args, "imap_usrenum_threads", 1) or 1))
        with self._usrenum_progress_lock:
            if th > 1:
                self._usrenum_mt_progress_line_active = True
                if sys.stdout.isatty():
                    sys.stdout.write(f"\033[2K\r    {line_core}")
                    sys.stdout.flush()
            else:
                sys.stdout.write(f"\r    {line_core}")
                sys.stdout.flush()

    def _usrenum_progress_finalize(self) -> None:
        if self.use_json:
            return
        th = max(1, int(getattr(self.args, "imap_usrenum_threads", 1) or 1))
        with self._usrenum_progress_lock:
            if th > 1 and self._usrenum_mt_progress_line_active:
                if sys.stdout.isatty():
                    sys.stdout.write("\033[2K\r")
                else:
                    sys.stdout.write("\n")
                sys.stdout.flush()
                self._usrenum_mt_progress_line_active = False
            else:
                sys.stdout.write("\033[2K\r")
                sys.stdout.flush()

    def _imap_usrenum_probe_login_wrong_password(
        self, username: str, wrong_password: str, probe_kind: str, probe_index: int
    ) -> ImapUserEnumProbeRow:
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        t0 = time.perf_counter()
        try:
            imap = self.connect()
        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw=None,
                reply_normalized=None,
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=False,
                error=str(e),
                probe_index=probe_index,
            )
        try:
            try:
                imap.capability()
            except Exception:
                pass
            imap.login(username, wrong_password)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw="OK",
                reply_normalized="login_unexpected_ok",
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=True,
                error=None,
                probe_index=probe_index,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            raw = _imap_login_exception_text(e)
            norm = _normalize_imap_login_error_for_enum(raw)
            return ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw=raw,
                reply_normalized=norm or None,
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=False,
                error=None,
                probe_index=probe_index,
            )
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    try:
                        imap.shutdown()
                    except Exception:
                        pass

    def _imap_usrenum_probe_plain_wrong_password(
        self, username: str, wrong_password: str, probe_kind: str, probe_index: int
    ) -> ImapUserEnumProbeRow:
        """RFC 4616 PLAIN: authorization identity \\0 authentication identity \\0 password (UTF-8)."""
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        t0 = time.perf_counter()
        plain_blob = (
            b"\x00"
            + username.encode("utf-8", errors="replace")
            + b"\x00"
            + wrong_password.encode("utf-8", errors="replace")
        )

        def _auth_cb(_chal: bytes) -> bytes:
            return plain_blob

        try:
            imap = self.connect()
        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw=None,
                reply_normalized=None,
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=False,
                error=str(e),
                probe_index=probe_index,
            )
        try:
            try:
                imap.capability()
            except Exception:
                pass
            imap.authenticate("PLAIN", _auth_cb)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw="OK",
                reply_normalized="plain_unexpected_ok",
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=True,
                error=None,
                probe_index=probe_index,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            raw = _imap_login_exception_text(e)
            norm = _normalize_imap_login_error_for_enum(raw)
            return ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw=raw,
                reply_normalized=norm or None,
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=False,
                error=None,
                probe_index=probe_index,
            )
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    try:
                        imap.shutdown()
                    except Exception:
                        pass

    def _analyze_imap_usrenum(
        self,
        rows: list[ImapUserEnumProbeRow],
        *,
        enumeration_method: str = "LOGIN",
        login_disabled_advertised: bool = False,
        auth_plain_advertised: bool = False,
    ) -> ImapUserEnumResult:
        if not rows:
            return ImapUserEnumResult(
                probes=tuple(),
                invalid_baseline_normalized=tuple(),
                enumerated_usernames=tuple(),
                vulnerable=False,
                indeterminate=True,
                detail="No enumeration probes executed.",
                wrong_password_marker=_IMAP_USRENUM_MARKER_LABEL,
                login_disabled_advertised=login_disabled_advertised,
                enumeration_method=enumeration_method,
                auth_plain_advertised=auth_plain_advertised,
            )
        invalid_norms: list[str] = []
        invalid_conn_err = 0
        for r in rows:
            if r.probe_kind != "control_invalid":
                continue
            if r.error:
                invalid_conn_err += 1
            elif r.unexpected_ok:
                pass
            elif r.reply_normalized:
                invalid_norms.append(r.reply_normalized)
        inv_set = set(invalid_norms)
        enumerated: list[str] = []
        for r in rows:
            if r.probe_kind != "wordlist":
                continue
            if r.error:
                continue
            if r.unexpected_ok:
                enumerated.append(r.username)
                continue
            if inv_set and r.reply_normalized and r.reply_normalized not in inv_set:
                enumerated.append(r.username)
        any_wl_unexpected = any(
            r.unexpected_ok for r in rows if r.probe_kind == "wordlist"
        )
        vulnerable = bool(enumerated) or any_wl_unexpected
        indeterminate = False
        if not inv_set and invalid_conn_err >= 2:
            indeterminate = True
        elif not inv_set and len(rows) <= 2:
            indeterminate = True
        auth_label = "LOGIN" if enumeration_method == "LOGIN" else "AUTHENTICATE PLAIN"
        detail_parts: list[str] = []
        if vulnerable:
            if enumerated:
                detail_parts.append(
                    f"Distinct {auth_label} failure (or unexpected OK) vs non-existent baseline suggests username oracle."
                )
            if any_wl_unexpected:
                detail_parts.append(
                    f"{auth_label} succeeded with fixed wrong password for at least one probe."
                )
        elif indeterminate:
            detail_parts.append(
                "Could not establish stable baseline from synthetic invalid usernames (connection or identical errors)."
            )
        else:
            detail_parts.append(
                "No reliable differentiation vs invalid-user baseline in this sample (heuristic)."
            )
        if enumeration_method == "LOGIN" and login_disabled_advertised:
            detail_parts.insert(
                0,
                "CAPABILITY lists LOGINDISABLED (RFC 3501): plaintext LOGIN is disabled; "
                "this test still issues LOGIN — interpret results with caution (SASL may be required).",
            )
        if enumeration_method == "AUTHENTICATE PLAIN" and not auth_plain_advertised:
            detail_parts.insert(
                0,
                "CAPABILITY did not list AUTH=PLAIN; AUTHENTICATE PLAIN may be unavailable or rejected for all probes.",
            )
        return ImapUserEnumResult(
            probes=tuple(rows),
            invalid_baseline_normalized=tuple(sorted(inv_set)),
            enumerated_usernames=tuple(enumerated),
            vulnerable=vulnerable,
            indeterminate=indeterminate,
            detail=" ".join(detail_parts),
            wrong_password_marker=_IMAP_USRENUM_MARKER_LABEL,
            login_disabled_advertised=login_disabled_advertised,
            enumeration_method=enumeration_method,
            auth_plain_advertised=auth_plain_advertised,
        )

    def test_imap_login_user_enumeration(self) -> ImapUserEnumResult:
        wl_path = getattr(self.args, "imap_usrenum_wordlist", None)
        if not wl_path:
            return self._analyze_imap_usrenum(
                [],
                enumeration_method="LOGIN",
                login_disabled_advertised=False,
                auth_plain_advertised=False,
            )
        raw = text_or_file(None, wl_path)
        names = [ln.strip() for ln in raw if ln.strip() and not ln.strip().startswith("#")]
        ue_mx = int(getattr(self.args, "imap_usrenum_max", 0) or 0)
        if ue_mx > 0:
            names = names[:ue_mx]
        pwd = getattr(self.args, "imap_usrenum_password", None) or _IMAP_USRENUM_DEFAULT_PASSWORD
        threads = max(1, int(getattr(self.args, "imap_usrenum_threads", 1) or 1))

        login_disabled_advertised = False
        imap_chk: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        try:
            imap_chk = self.connect()
            try:
                imap_chk.capability()
            except Exception:
                pass
            banner_chk, merged_chk = self._merged_preauth_capabilities(imap_chk)
            login_disabled_advertised = self._capability_logindisabled(merged_chk, banner_chk)
        except Exception:
            pass
        finally:
            if imap_chk is not None:
                try:
                    imap_chk.logout()
                except Exception:
                    try:
                        imap_chk.shutdown()
                    except Exception:
                        pass

        invalid_users = [
            f"enumtest_invalid_{random.getrandbits(32):08x}",
            f"enumtest_invalid_{random.getrandbits(32):08x}",
        ]
        all_rows: list[ImapUserEnumProbeRow] = []
        probe_idx = 0
        total_phases = len(invalid_users) + len(names)
        self._usrenum_progress_reset()

        for inv in invalid_users:
            all_rows.append(
                self._imap_usrenum_probe_login_wrong_password(inv, pwd, "control_invalid", probe_idx)
            )
            probe_idx += 1
            if not self.use_json and total_phases > 0:
                self._usrenum_progress_update(len(all_rows), total_phases, label="LOGIN enum")

        if not names:
            self._usrenum_progress_finalize()
            return self._analyze_imap_usrenum(
                all_rows,
                enumeration_method="LOGIN",
                login_disabled_advertised=login_disabled_advertised,
                auth_plain_advertised=False,
            )

        base_idx = probe_idx

        def run_word(u: str, idx: int) -> ImapUserEnumProbeRow:
            return self._imap_usrenum_probe_login_wrong_password(u, pwd, "wordlist", idx)

        if threads <= 1 or len(names) == 1:
            for u in names:
                all_rows.append(run_word(u, base_idx))
                base_idx += 1
                if not self.use_json and total_phases > 0:
                    self._usrenum_progress_update(len(all_rows), total_phases, label="LOGIN enum")
        else:
            work = [(names[i], base_idx + i) for i in range(len(names))]
            done_lock = threading.Lock()
            completed = [len(invalid_users)]

            def worker(item: tuple[str, int]) -> ImapUserEnumProbeRow:
                u, idx = item
                row = run_word(u, idx)
                if not self.use_json and total_phases > 0:
                    with done_lock:
                        completed[0] += 1
                        self._usrenum_progress_update(completed[0], total_phases, label="LOGIN enum")
                return row

            results_par: list[ImapUserEnumProbeRow] = []
            max_workers = min(threads, len(names))
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futs = [ex.submit(worker, w) for w in work]
                for fut in as_completed(futs):
                    results_par.append(fut.result())
            all_rows.extend(sorted(results_par, key=lambda r: r.probe_index))

        self._usrenum_progress_finalize()
        return self._analyze_imap_usrenum(
            all_rows,
            enumeration_method="LOGIN",
            login_disabled_advertised=login_disabled_advertised,
            auth_plain_advertised=False,
        )

    def test_imap_authenticate_plain_user_enumeration(self) -> ImapUserEnumResult:
        wl_path = getattr(self.args, "imap_usrenum_wordlist", None)
        if not wl_path:
            return self._analyze_imap_usrenum(
                [],
                enumeration_method="AUTHENTICATE PLAIN",
                login_disabled_advertised=False,
                auth_plain_advertised=False,
            )
        raw = text_or_file(None, wl_path)
        names = [ln.strip() for ln in raw if ln.strip() and not ln.strip().startswith("#")]
        ue_mx = int(getattr(self.args, "imap_usrenum_max", 0) or 0)
        if ue_mx > 0:
            names = names[:ue_mx]
        pwd = getattr(self.args, "imap_usrenum_password", None) or _IMAP_USRENUM_DEFAULT_PASSWORD
        threads = max(1, int(getattr(self.args, "imap_usrenum_threads", 1) or 1))

        auth_plain_advertised = False
        imap_chk: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        try:
            imap_chk = self.connect()
            try:
                imap_chk.capability()
            except Exception:
                pass
            banner_chk, merged_chk = self._merged_preauth_capabilities(imap_chk)
            auth_plain_advertised = self._capability_advertises_auth_plain(merged_chk, banner_chk)
        except Exception:
            pass
        finally:
            if imap_chk is not None:
                try:
                    imap_chk.logout()
                except Exception:
                    try:
                        imap_chk.shutdown()
                    except Exception:
                        pass

        invalid_users = [
            f"enumtest_invalid_{random.getrandbits(32):08x}",
            f"enumtest_invalid_{random.getrandbits(32):08x}",
        ]
        all_rows: list[ImapUserEnumProbeRow] = []
        probe_idx = 0
        total_phases = len(invalid_users) + len(names)
        self._usrenum_progress_reset()

        for inv in invalid_users:
            all_rows.append(
                self._imap_usrenum_probe_plain_wrong_password(inv, pwd, "control_invalid", probe_idx)
            )
            probe_idx += 1
            if not self.use_json and total_phases > 0:
                self._usrenum_progress_update(len(all_rows), total_phases, label="PLAIN enum")

        if not names:
            self._usrenum_progress_finalize()
            return self._analyze_imap_usrenum(
                all_rows,
                enumeration_method="AUTHENTICATE PLAIN",
                login_disabled_advertised=False,
                auth_plain_advertised=auth_plain_advertised,
            )

        base_idx = probe_idx

        def run_word(u: str, idx: int) -> ImapUserEnumProbeRow:
            return self._imap_usrenum_probe_plain_wrong_password(u, pwd, "wordlist", idx)

        if threads <= 1 or len(names) == 1:
            for u in names:
                all_rows.append(run_word(u, base_idx))
                base_idx += 1
                if not self.use_json and total_phases > 0:
                    self._usrenum_progress_update(len(all_rows), total_phases, label="PLAIN enum")
        else:
            work = [(names[i], base_idx + i) for i in range(len(names))]
            done_lock = threading.Lock()
            completed = [len(invalid_users)]

            def worker(item: tuple[str, int]) -> ImapUserEnumProbeRow:
                u, idx = item
                row = run_word(u, idx)
                if not self.use_json and total_phases > 0:
                    with done_lock:
                        completed[0] += 1
                        self._usrenum_progress_update(completed[0], total_phases, label="PLAIN enum")
                return row

            results_par: list[ImapUserEnumProbeRow] = []
            max_workers = min(threads, len(names))
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futs = [ex.submit(worker, w) for w in work]
                for fut in as_completed(futs):
                    results_par.append(fut.result())
            all_rows.extend(sorted(results_par, key=lambda r: r.probe_index))

        self._usrenum_progress_finalize()
        return self._analyze_imap_usrenum(
            all_rows,
            enumeration_method="AUTHENTICATE PLAIN",
            login_disabled_advertised=False,
            auth_plain_advertised=auth_plain_advertised,
        )

    def auth_ntlm(self) -> NTLMResult:
        """
        CAPABILITY (pre-auth) for AUTH=NTLM, then AUTHENTICATE NTLM with Negotiate message;
        decode Challenge for NetBIOS/DNS/OS disclosure (PTL-SVC-IMAP-NTLMINFO).
        """
        imap = self.connect()
        auth_ntlm_advertised = False
        try:
            try:
                imap.capability()
            except Exception:
                pass
            banner, merged = self._merged_preauth_capabilities(imap)
            auth_ntlm_advertised = self._capability_advertises_auth_ntlm(merged, banner)
            tag = imap._new_tag().decode()
            imap.send(f"{tag} AUTHENTICATE NTLM\r\n".encode())
            res = imap.readline().strip()
            if res.startswith(b"+"):
                imap.send(b64encode(get_NegotiateMessage_data()) + b"\r\n")
                res = imap.readline().strip()
                # Challenge line may contain '+' inside Base64 — preserve octets after first '+'
                b64_ntlm_challenge = b"+".join(res.split(b"+")[1:])
                ntlminfo = decode_ChallengeMessage_blob(b64decode(b64_ntlm_challenge))
                return NTLMResult(True, ntlminfo, auth_ntlm_advertised)
            return NTLMResult(False, None, auth_ntlm_advertised)
        except Exception:
            return NTLMResult(False, None, auth_ntlm_advertised)
        finally:
            try:
                imap.logout()
            except Exception:
                try:
                    imap.shutdown()
                except Exception:
                    pass

    def _try_login(self, creds: Creds) -> Creds | None:
        """Login attempt function for bruteforce

        Args:
            creds (Creds): Creds to use for login

        Returns:
            Creds | None: Creds if success, None if failed
        """

        try:
            imap = self.connect()
        except OSError:
            return None
        try:
            imap.login(creds.user, creds.passw)
            result = creds
        except:
            result = None
        finally:
            imap.logout()
            return result

    def _on_brute_success(self, cred: Creds) -> None:
        """Callback for real-time streaming of found credentials (thread-safe)."""
        with self._output_lock:
            self._ptprint_raw(
                f"user: {cred.user}, password: {cred.passw}",
                bullet_type="TEXT",
                condition=not self.use_json,
                indent=4,
            )

    def _stream_banner_result(self) -> None:
        """Stream banner + Service Identification immediately (thread-safe)."""
        pp = self._ptprint_raw
        show = not self.use_json
        if not (info := self.results.info) or info.banner is None:
            return
        with self._output_lock:
            sid = identify_service(info.banner)
            if sid is None:
                banner_bullet = "NOTVULN"
            elif sid.version is not None:
                banner_bullet = "VULN"
            else:
                banner_bullet = "WARNING"
            pp(info.banner, bullet_type=banner_bullet, condition=show, indent=4)
            if sid is not None:
                self._ptprint("Service Identification", Out.INFO)
                pp(f"Product:  {sid.product}", bullet_type="TEXT", condition=show, indent=4)
                pp(
                    f"Version:  {sid.version if sid.version else 'unknown'}",
                    bullet_type="TEXT",
                    condition=show,
                    indent=4,
                )
                pp(f"CPE:      {sid.cpe}", bullet_type="TEXT", condition=show, indent=4)

    def _emit_capa_section(self, title: str, capa: list[str]) -> None:
        pp = self._ptprint_raw
        show = not self.use_json
        self._ptprint(title, Out.INFO)
        for display_str, level in _parse_capability_commands(capa):
            pp(display_str, bullet_type=_capa_level_bullet(level), condition=show, indent=4)

    def _stream_capa_result(self) -> None:
        """Stream CAPABILITY capabilities immediately (thread-safe)."""
        if not (info := self.results.info):
            return
        capa = info.capability or getattr(info, "capability_starttls", None)
        if not capa and not info.id:
            return
        with self._output_lock:
            pp = self._ptprint_raw
            show = not self.use_json
            if info.id is not None:
                self._ptprint("ID command", Out.INFO)
                pp(info.id, bullet_type="TEXT", condition=show, indent=4)
            if capa:
                capa_stls = getattr(info, "capability_starttls", None)
                if capa_stls is not None:
                    self._emit_capa_section("CAPABILITY command (PLAIN)", info.capability or [])
                    self._emit_capa_section("CAPABILITY command (STARTTLS)", capa_stls)
                else:
                    encrypted = self.args.target.port == 993 or self.args.tls
                    title = "CAPABILITY command (TLS)" if encrypted else "CAPABILITY command (PLAIN)"
                    self._emit_capa_section(title, capa)

    def _stream_encryption_result(self) -> None:
        """Stream encryption test result to terminal (thread-safe)."""
        pp = self._ptprint_raw
        show = not self.use_json
        with self._output_lock:
            if (err := self.results.encryption_error) is not None:
                pp(f"Encryption test failed: {err}", bullet_type="VULN", condition=show, indent=4)
                return
            enc = self.results.encryption
            if enc is None:
                return
            plaintext_only = enc.plaintext_ok and not enc.starttls_ok and not enc.tls_ok
            any_ok = enc.plaintext_ok or enc.starttls_ok or enc.tls_ok
            if plaintext_only:
                pp("Plaintext only", bullet_type="VULN", condition=show, indent=4)
            elif any_ok:
                if enc.plaintext_ok:
                    bullet = "WARNING" if (enc.starttls_ok or enc.tls_ok) else "NOTVULN"
                    pp("Plaintext", bullet_type=bullet, condition=show, indent=4)
                if enc.starttls_ok:
                    pp("STARTTLS", bullet_type="NOTVULN", condition=show, indent=4)
                if enc.tls_ok:
                    pp("TLS", bullet_type="NOTVULN", condition=show, indent=4)
            else:
                pp(
                    "No connection mode available (plaintext, STARTTLS, TLS failed)",
                    bullet_type="VULN",
                    condition=show,
                    indent=4,
                )

    def _stream_sniffable_result(self) -> None:
        """Stream cleartext IMAP sniffable probe result (thread-safe)."""
        pp = self._ptprint_raw
        show = not self.use_json
        with self._output_lock:
            if (err := getattr(self.results, "sniffable_error", None)) is not None:
                pp(f"Probe failed: {err}", bullet_type="VULN", condition=show, indent=4)
                return
            sn = self.results.sniffable
            if sn is None:
                return
            if sn.skipped:
                pp(f"Skipped: {sn.skip_reason or 'n/a'}", bullet_type="WARNING", condition=show, indent=4)
                return
            if not sn.plain_ok:
                pp("Plain IMAP TCP session not available on target", bullet_type="NOTVULN", condition=show, indent=4)
                return
            if sn.starttls_advertised:
                pp("STARTTLS advertised on cleartext port", bullet_type="NOTVULN", condition=show, indent=4)
            else:
                pp("STARTTLS not advertised on cleartext port", bullet_type="VULN", condition=show, indent=4)
            if sn.auth_methods:
                pp(
                    f"Credential-bearing AUTH mechanisms seen: {', '.join(sn.auth_methods)}",
                    bullet_type="TITLE",
                    condition=show,
                    indent=4,
                )
            else:
                pp(
                    "No credential-bearing AUTH= mechanisms advertised pre-TLS",
                    bullet_type="TITLE",
                    condition=show,
                    indent=4,
                )
            for method, outcome in sn.probes:
                if outcome == "continuation":
                    bullet = "VULN"
                    label = "server sent continuation (+) — cleartext SASL exchange possible"
                elif outcome == "tagged_no":
                    bullet = "NOTVULN"
                    label = "AUTHENTICATE rejected (NO)"
                elif outcome == "tagged_bad":
                    bullet = "NOTVULN"
                    label = "AUTHENTICATE rejected (BAD)"
                elif outcome == "io_error":
                    bullet = "WARNING"
                    label = "probe I/O error"
                else:
                    bullet = "WARNING"
                    label = outcome
                pp(f"{method}: {label}", bullet_type=bullet, condition=show, indent=4)
            if sn.vulnerable:
                pp(
                    "Verdict: cleartext IMAP allows sniffable traffic or credentials",
                    bullet_type="VULN",
                    condition=show,
                    indent=4,
                )
            else:
                pp(
                    "Verdict: no cleartext-only policy detected by this probe",
                    bullet_type="NOTVULN",
                    condition=show,
                    indent=4,
                )

    def _inv_comm_emit_terminal(self, ic: InvCommImapResult) -> None:
        """Shared text layout for invalid-command audit (stream + output replay)."""
        pp = self._ptprint_raw
        show = not self.use_json
        tagged_outcomes = frozenset({"OK", "NO", "BAD"})
        for t in ic.tests:
            time_str = f" ({t.response_time_sec:.2f}s)" if t.response_time_sec is not None else ""
            if t.probe_vulnerable:
                msg = f"VULNERABLE / UNSTABLE: {t.command_display} → {t.outcome}{time_str}"
            else:
                msg = f"{t.command_display}: {t.outcome}{time_str}"
            pp(msg, bullet_type="TITLE", condition=show, indent=4)
            if t.reply_snippet and (t.info_leak or t.probe_vulnerable):
                pp(t.reply_snippet, bullet_type="TEXT", condition=show, indent=8)
            if t.info_leak:
                pp("Verbose error (possible info leak)", bullet_type="TITLE", condition=show, indent=8)
            if t.slow_response:
                pp("Slow response (possible parser / DoS)", bullet_type="TITLE", condition=show, indent=8)
            if (
                t.session_ok_after is False
                and t.outcome in tagged_outcomes
                and not t.probe_vulnerable
            ):
                pp("CAPABILITY follow-up failed (session unstable)", bullet_type="TITLE", condition=show, indent=8)

        if ic.vulnerable:
            pp(ic.detail, bullet_type="VULN", condition=show, indent=4)
        elif ic.weakness:
            pp(f"WEAKNESS: {ic.detail}", bullet_type="WARNING", condition=show, indent=4)
        else:
            pp(ic.detail, bullet_type="NOTVULN", condition=show, indent=4)

    def _stream_inv_comm_result(self) -> None:
        """Terminal output for invalid IMAP command audit (align with SMTP -iv: [i] per line)."""
        with self._output_lock:
            if (err := getattr(self.results, "inv_comm_error", None)) is not None:
                self._ptprint_raw(
                    f"Test failed: {err}",
                    bullet_type="TITLE",
                    condition=not self.use_json,
                    indent=4,
                )
                return
            ic = self.results.inv_comm
            if ic is None:
                return
            self._inv_comm_emit_terminal(ic)

    def _stream_catch_all_result(self) -> None:
        """Stream catch-all test result immediately (thread-safe)."""
        catch_all = getattr(self.results, "catch_all", None)
        if catch_all is None:
            return
        with self._output_lock:
            if catch_all == "indeterminate":
                self._tprint(
                    "Server accepted invalid credentials (indeterminate). Results may be false positives.",
                    bullet="WARNING",
                )
            else:
                self._tprint("Not configured (server rejects invalid creds)", bullet="NOTVULN")

    def _anonymous_emit_terminal(self, ar: AnonymousAccessResult) -> None:
        pp = self._ptprint_raw
        show = not self.use_json
        if ar.auth_anonymous_advertised:
            pp(
                "AUTH=ANONYMOUS offered in pre-login CAPABILITY (or banner)",
                bullet_type="WARNING",
                condition=show,
                indent=4,
            )
        else:
            pp("AUTH=ANONYMOUS not advertised", bullet_type="NOTVULN", condition=show, indent=4)

        if ar.authenticate_anonymous_ok:
            pp("AUTHENTICATE ANONYMOUS: accepted (OK)", bullet_type="VULN", condition=show, indent=4)
        else:
            pp("AUTHENTICATE ANONYMOUS: not accepted", bullet_type="NOTVULN", condition=show, indent=4)

        if ar.login_anonymous_empty_ok:
            pp("LOGIN anonymous with empty password: accepted", bullet_type="VULN", condition=show, indent=4)
        else:
            pp("LOGIN anonymous with empty password: rejected", bullet_type="NOTVULN", condition=show, indent=4)

        for w in ar.weak_credentials_ok:
            pp(f"LOGIN accepted: {w}", bullet_type="VULN", condition=show, indent=4)

        if ar.vulnerable:
            pp(
                "Verdict: anonymous or weak default access — PTL-SVC-IMAP-ANONYMOUS",
                bullet_type="VULN",
                condition=show,
                indent=4,
            )
        else:
            pp(f"Verdict: {ar.detail}", bullet_type="NOTVULN", condition=show, indent=4)

    def _stream_anonymous_result(self) -> None:
        """Stream anonymous auth result immediately (thread-safe)."""
        if (ar := self.results.anonymous) is None:
            return
        with self._output_lock:
            self._anonymous_emit_terminal(ar)

    def _eicar_emit_terminal(self, er: EicarAppendResult) -> None:
        pp = self._ptprint_raw
        show = not self.use_json
        if er.skipped:
            pp(f"Skipped: {er.skip_reason or 'n/a'}", bullet_type="WARNING", condition=show, indent=4)
            return
        if er.vulnerable:
            pp(
                "APPEND accepted EICAR test message — inbound AV may be missing or ineffective "
                f"(PTV-SVC-IMAP-EICAR); server: {er.append_typ}",
                bullet_type="VULN",
                condition=show,
                indent=4,
            )
        else:
            snippet = (er.append_detail or "n/a").replace("\r\n", " ")[:200]
            pp(
                f"APPEND rejected or failed ({er.append_typ}): {snippet}",
                bullet_type="NOTVULN",
                condition=show,
                indent=4,
            )

    def _stream_eicar_result(self) -> None:
        """Stream EICAR probe result immediately (thread-safe)."""
        if (er := self.results.eicar) is None:
            return
        with self._output_lock:
            self._eicar_emit_terminal(er)

    def _imap_resource_load_emit_terminal(self, lr: ImapResourceLoadResult) -> None:
        pp = self._ptprint_raw
        show = not self.use_json
        if lr.skipped:
            pp(f"Skipped: {lr.skip_reason or lr.detail}", bullet_type="WARNING", condition=show, indent=4)
            return
        if lr.append is not None:
            ap = lr.append
            pp(
                f"APPEND: attempted={ap.attempted} ok={ap.ok} failed={ap.failed} "
                f"disconnect={ap.disconnected} err_rate={ap.error_rate_pct:.1f}% "
                f"slowdown={ap.slowdown}",
                bullet_type="TITLE",
                condition=show,
                indent=4,
            )
        if lr.search is not None:
            sp = lr.search
            pp(
                f"UID SEARCH ALL: attempted={sp.attempted} ok={sp.ok} failed={sp.failed} "
                f"disconnect={sp.disconnected} err_rate={sp.error_rate_pct:.1f}% "
                f"slowdown={sp.slowdown}",
                bullet_type="TITLE",
                condition=show,
                indent=4,
            )
        if lr.search_skipped_reason:
            pp(f"SEARCH note: {lr.search_skipped_reason}", bullet_type="TITLE", condition=show, indent=4)
        if lr.vulnerable:
            pp(
                f"Bounded load showed weak limits or instability: {lr.detail}",
                bullet_type="VULN",
                condition=show,
                indent=4,
            )
        else:
            pp(lr.detail, bullet_type="NOTVULN", condition=show, indent=4)

    def _stream_imap_resource_load_result(self) -> None:
        """Stream IMAP resource load probe result (thread-safe)."""
        if (err := getattr(self.results, "imap_resource_load_error", None)) is not None:
            with self._output_lock:
                self._ptprint_raw(
                    f"Resource load probe failed: {err}",
                    bullet_type="VULN",
                    condition=not self.use_json,
                    indent=4,
                )
            return
        if (lr := self.results.imap_resource_load) is None:
            return
        with self._output_lock:
            self._imap_resource_load_emit_terminal(lr)

    def _imap_tls_audit_emit_terminal(self, tr: ImapTlsAuditResult) -> None:
        pp = self._ptprint_raw
        show = not self.use_json

        def line_level(level: str, text: str) -> None:
            bullet = {"ok": "NOTVULN", "bad": "VULN"}.get(level, "WARNING")
            pp(text, bullet_type=bullet, condition=show, indent=4)

        pp(
            f"Target {tr.host!r}:{tr.port} (implicit TLS path: {tr.implicit_tls_intended})",
            bullet_type="TITLE",
            condition=show,
            indent=4,
        )
        for p in tr.probes:
            mode_label = (
                f"Implicit TLS (Port {tr.port})"
                if p.mode == "implicit_tls"
                else f"STARTTLS (Port {tr.port})"
            )
            pp(f"Connection mode: {mode_label}", bullet_type="TITLE", condition=show, indent=4)
            if p.handshake_ok:
                tls_l = p.tls_version or "n/a"
                ciph = p.cipher_name or "n/a"
                pp(f"TLS Version: {tls_l} | Cipher: {ciph}", bullet_type="TITLE", condition=show, indent=4)

            if p.handshake_ok and (p.peer_subject or p.peer_issuer or p.san_dns or p.not_after):
                pp("Certificate Information:", bullet_type="TITLE", condition=show, indent=4)
                if p.peer_subject:
                    pp(f"- Subject:  {p.peer_subject}", bullet_type="TEXT", condition=show, indent=8)
                if p.peer_issuer:
                    pp(f"- Issuer:   {p.peer_issuer}", bullet_type="TEXT", condition=show, indent=8)
                nb_d = self._imap_tls_audit_terminal_fmt_cert_date(p.not_before)
                na_d = self._imap_tls_audit_terminal_fmt_cert_date(p.not_after)
                days = p.days_until_expiry
                if p.cert_expired:
                    days_s = f"({days} days remaining)" if days is not None else "(expired)"
                elif p.cert_not_yet_valid:
                    days_s = "(not yet valid)"
                elif days is not None:
                    days_s = f"({days} days remaining)"
                else:
                    days_s = ""
                validity_line = f"- Validity: {nb_d} to {na_d} {days_s}".rstrip()
                pp(validity_line, bullet_type="TEXT", condition=show, indent=8)
                if p.san_dns:
                    pp(f"- SAN:      {', '.join(p.san_dns)}", bullet_type="TEXT", condition=show, indent=8)
                key_bits: list[str] = []
                if p.peer_key_summary:
                    key_bits.append(p.peer_key_summary)
                if p.peer_signature_hash:
                    key_bits.append(f"Hash: {p.peer_signature_hash}")
                if key_bits:
                    pp(f"- Key:      {' | '.join(key_bits)}", bullet_type="TEXT", condition=show, indent=8)
            elif p.attempted and not p.handshake_ok:
                pp("Certificate Information:", bullet_type="TITLE", condition=show, indent=4)
                pp(
                    "- (Leaf certificate details unavailable — TLS handshake did not complete)",
                    bullet_type="TEXT",
                    condition=show,
                    indent=8,
                )
            else:
                pp("Certificate Information:", bullet_type="TITLE", condition=show, indent=4)
                pp(
                    f"- (Not evaluated: {p.skipped_reason or 'n/a'})",
                    bullet_type="TEXT",
                    condition=show,
                    indent=8,
                )

            tl, tm = self._imap_tls_audit_terminal_trust_level_msg(p)
            line_level(tl, f"Trust: {tm}")
            il, im = self._imap_tls_audit_terminal_identity_level_msg(tr.host, p)
            line_level(il, f"Identity: {im}")
            pl, pm = self._imap_tls_audit_terminal_protocol_level_msg(p)
            line_level(pl, f"Protocol: {pm}")

            warn_parts: list[str] = []
            if p.handshake_ok and p.expires_within_vuln_days and p.days_until_expiry is not None:
                warn_parts.append(
                    f"Certificate expires in {p.days_until_expiry} days (Critical renewal window)"
                )
            elif p.handshake_ok and p.expires_within_warn_days and p.days_until_expiry is not None:
                warn_parts.append(
                    f"Certificate expires in {p.days_until_expiry} days (renewal recommended)"
                )
            if p.handshake_ok and p.weak_cipher and p.cipher_name:
                warn_parts.append(f"Weak negotiated cipher suite ({p.cipher_name})")
            if p.handshake_ok and p.crypto_warnings:
                cw = " and ".join(p.crypto_warnings[:4])
                if len(p.crypto_warnings) > 4:
                    cw += f" (+{len(p.crypto_warnings) - 4} more)"
                warn_parts.append(cw)
            for w in warn_parts:
                line_level("warn", f"Warning: {w}")

            vl, vm = self._imap_tls_audit_terminal_verdict_level_msg(tr, p)
            line_level(vl, f"Verdict: {vm}")

    def _stream_imap_tls_audit_result(self) -> None:
        """Stream IMAP TLS audit result (thread-safe)."""
        if (err := getattr(self.results, "imap_tls_audit_error", None)) is not None:
            with self._output_lock:
                pp = self._ptprint_raw
                show = not self.use_json
                implicit = bool(self.args.tls or int(self.args.target.port) == 993)
                pp(
                    f"Target {self.args.target.ip!r}:{int(self.args.target.port)} "
                    f"(implicit TLS path: {implicit})",
                    bullet_type="TITLE",
                    condition=show,
                    indent=4,
                )
                pp(f"TLS audit failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        if (tr := self.results.imap_tls_audit) is None:
            return
        with self._output_lock:
            self._imap_tls_audit_emit_terminal(tr)

    def _imap_mailbox_iso_emit_terminal(self, mr: ImapMailboxIsoResult) -> None:
        pp = self._ptprint_raw
        show = not self.use_json
        if mr.skipped:
            pp(f"Skipped: {mr.skip_reason or mr.detail}", bullet_type="WARNING", condition=show, indent=4)
            return
        pp(
            f"Baseline mailbox: {mr.own_mailbox!r}; foreign token: {mr.foreign_user_token!r}; "
            f"login: {mr.login_username!r}",
            bullet_type="TITLE",
            condition=show,
            indent=4,
        )
        pp(
            f"NAMESPACE: {mr.namespace_typ or 'n/a'}; GETACL: {mr.get_acl_typ or 'n/a'} "
            f"(ACL in CAPABILITY: {mr.acl_in_capability})",
            bullet_type="TITLE",
            condition=show,
            indent=4,
        )
        pp(
            f"LIST \"\" \"*\": {mr.list_root_typ or 'n/a'} count≈{mr.list_root_count}"
            f"{'+' if mr.list_root_truncated else ''}",
            bullet_type="TITLE",
            condition=show,
            indent=4,
        )
        if mr.list_root_sample:
            for s in mr.list_root_sample[:6]:
                pp(f"sample: {s}", bullet_type="TEXT", condition=show, indent=8)
        for r in mr.select_probes:
            bullet = "VULN" if r.ok_selected else "NOTVULN"
            snip = (r.detail or "").replace("\r\n", " ")[:120]
            pp(
                f"EXAMINE [{r.probe_id}] {r.mailbox!r} → {r.typ or 'n/a'} {snip}",
                bullet_type=bullet,
                condition=show,
                indent=8,
            )
        pp(
            f"LIST dictionary: {mr.list_dictionary_nonzero_patterns} patterns with hits, "
            f"{mr.list_dictionary_total_listed} total LIST rows",
            bullet_type="TITLE",
            condition=show,
            indent=4,
        )
        if mr.acl_anyone_rights or mr.acl_anonymous_rights or mr.acl_authenticated_rights:
            pp(
                f"ACL identifiers — anyone: {mr.acl_anyone_rights!r} anonymous: {mr.acl_anonymous_rights!r} "
                f"authenticated: {mr.acl_authenticated_rights!r}",
                bullet_type="TITLE",
                condition=show,
                indent=4,
            )
        if mr.vulnerable:
            pp(mr.detail, bullet_type="VULN", condition=show, indent=4)
        else:
            pp(mr.detail, bullet_type="NOTVULN", condition=show, indent=4)

    def _stream_imap_mailbox_iso_result(self) -> None:
        """Stream mailbox isolation probe result (thread-safe)."""
        if (err := getattr(self.results, "imap_mailbox_iso_error", None)) is not None:
            with self._output_lock:
                self._ptprint_raw(
                    f"Mailbox isolation probe failed: {err}",
                    bullet_type="VULN",
                    condition=not self.use_json,
                    indent=4,
                )
            return
        if (mr := self.results.imap_mailbox_iso) is None:
            return
        with self._output_lock:
            self._imap_mailbox_iso_emit_terminal(mr)

    def _imap_usrenum_emit_terminal(self, ur: ImapUserEnumResult) -> None:
        pp = self._ptprint_raw
        show = not self.use_json
        if ur.enumeration_method == "LOGIN" and ur.login_disabled_advertised:
            pp(
                "CAPABILITY: LOGINDISABLED — plaintext LOGIN is disabled (RFC 3501). "
                "This probe still uses LOGIN; interpret results with caution (real clients should use SASL).",
                bullet_type="WARNING",
                condition=show,
                indent=4,
            )
        elif ur.enumeration_method == "AUTHENTICATE PLAIN" and not ur.auth_plain_advertised:
            pp(
                "CAPABILITY did not list AUTH=PLAIN — AUTHENTICATE PLAIN may fail or be unsupported; "
                "interpret results with caution.",
                bullet_type="WARNING",
                condition=show,
                indent=4,
            )
        if ur.indeterminate:
            pp(f"Indeterminate: {ur.detail}", bullet_type="WARNING", condition=show, indent=4)
            return
        tag = "LOGIN" if ur.enumeration_method == "LOGIN" else "AUTHENTICATE PLAIN"
        if ur.vulnerable:
            pp(
                f"{tag} differentiates accounts without valid password: {ur.detail}",
                bullet_type="VULN",
                condition=show,
                indent=4,
            )
            for u in ur.enumerated_usernames:
                pp(f"differentiated: {u}", bullet_type="TEXT", condition=show, indent=8)
        else:
            pp(ur.detail, bullet_type="NOTVULN", condition=show, indent=4)

    def _stream_imap_usrenum_login_result(self) -> None:
        """Stream LOGIN user enumeration result (thread-safe)."""
        if (err := getattr(self.results, "imap_usrenum_error", None)) is not None:
            with self._output_lock:
                self._ptprint_raw(
                    f"LOGIN user enumeration failed: {err}",
                    bullet_type="VULN",
                    condition=not self.use_json,
                    indent=4,
                )
            return
        if (ur := self.results.imap_usrenum) is None:
            return
        with self._output_lock:
            self._imap_usrenum_emit_terminal(ur)

    def _stream_imap_usrenum_plain_result(self) -> None:
        """Stream AUTHENTICATE PLAIN user enumeration result (thread-safe)."""
        if (err := getattr(self.results, "imap_usrenum_plain_error", None)) is not None:
            with self._output_lock:
                self._ptprint_raw(
                    f"AUTHENTICATE PLAIN user enumeration failed: {err}",
                    bullet_type="VULN",
                    condition=not self.use_json,
                    indent=4,
                )
            return
        if (ur := self.results.imap_usrenum_plain) is None:
            return
        with self._output_lock:
            self._imap_usrenum_emit_terminal(ur)

    def _stream_ntlm_result(self) -> None:
        """Stream NTLM info result immediately (thread-safe)."""
        if (ntlm := self.results.ntlm) is None:
            return
        pp = self._ptprint_raw
        show = not self.use_json
        with self._output_lock:
            if ntlm.auth_ntlm_advertised:
                pp("Pre-login CAPABILITY lists AUTH=NTLM", bullet_type="WARNING", condition=show, indent=4)
            else:
                pp(
                    "AUTH=NTLM not seen in merged pre-login CAPABILITY (still probing AUTHENTICATE)",
                    bullet_type="TITLE",
                    condition=show,
                    indent=4,
                )
            if not ntlm.success:
                pp(
                    "AUTHENTICATE NTLM did not yield a decodable Challenge",
                    bullet_type="NOTVULN",
                    condition=show,
                    indent=4,
                )
            elif ntlm.ntlm is not None:
                pp(
                    "NTLM Challenge decoded — infrastructure identifiers disclosed",
                    bullet_type="VULN",
                    condition=show,
                    indent=4,
                )
                for line in (
                    f"Target name: {ntlm.ntlm.target_name}",
                    f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                    f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                    f"DNS domain name: {ntlm.ntlm.dns_domain}",
                    f"DNS computer name: {ntlm.ntlm.dns_computer}",
                    f"DNS tree: {ntlm.ntlm.dns_tree}",
                    f"OS version: {ntlm.ntlm.os_version}",
                ):
                    for part in (line or "").replace("\r", "").splitlines():
                        pp(part, bullet_type="TEXT", condition=show, indent=8)

    def _stream_brute_result(self) -> None:
        """Stream brute-force summary (credentials already streamed via on_success) (thread-safe)."""
        creds = self.results.creds
        if creds is None or len(creds) == 0:
            return
        with self._output_lock:
            self._ptprint_raw(
                f"Found {len(creds)} valid credentials",
                bullet_type="INFO",
                condition=not self.use_json,
                indent=4,
            )

    def _stream_conn_limits_result(self) -> None:
        """Inline verdicts are printed during the probe; this handles hard failures only."""
        if (err := getattr(self.results, "conn_limits_error", None)) is not None:
            with self._output_lock:
                self._ptprint_raw(
                    f"Connection limits test failed: {err}",
                    bullet_type="VULN",
                    condition=not self.use_json,
                    indent=4,
                )

    # region output

    def build_json(self, ptjsonlib) -> None:
        """Build JSON node(s). Terminal output is streamed from run()."""
        properties = {
            "software_type": None,
            "name": "imap",
            "version": None,
            "vendor": None,
            "description": None,
        }
        deferred_vulns = []

        # Connection error: use unified error format (status=error, empty nodes)
        if (info_error := getattr(self.results, "info_error", None)) is not None:
            if self.use_json:
                ptjsonlib.end_error(info_error, self.use_json)
            self._ptprint_raw(info_error, bullet_type="VULN", condition=not self.use_json, indent=4)
            return

        # Banner (skip terminal if streamed; always add to properties for JSON)
        if (info := self.results.info) and info.banner is not None:
            sid = identify_service(info.banner)
            vendor = vendor_from_cpe(sid.cpe) if sid else None
            version = sid.version if sid else None
            properties.update(
                {
                    "description": f"Banner: {info.banner}",
                    "version": version,
                    "vendor": vendor,
                }
            )
            if sid is not None:
                if sid.version is not None:
                    deferred_vulns.append({"vuln_code": "PTV-SVC-BANNER"})
                properties.update({"cpe": sid.cpe})
        # ID and CAPABILITY (skip terminal if streamed; always add to properties for JSON)
        if (info := self.results.info) and (info.id is not None or info.capability or getattr(info, "capability_starttls", None)):
            capa = info.capability or []
            capa_stls = getattr(info, "capability_starttls", None)
            if info.id is not None:
                properties.update({"idCommand": info.id})
            if capa or capa_stls:
                def _capa_to_lines(cl: list[str]) -> list[str]:
                    return [d for d, _ in _parse_capability_commands(cl)]
                if capa_stls is not None:
                    json_lines = _capa_to_lines(capa) + ["---"] + _capa_to_lines(capa_stls)
                else:
                    json_lines = _capa_to_lines(capa)
                properties.update({"capabilityCommand": "\n".join(json_lines)})
        # Encryption (skip terminal if streamed; always add to properties for JSON)
        if (encryption_error := self.results.encryption_error) is not None:
            properties.update({"encryptionError": encryption_error})
        elif (enc := self.results.encryption) is not None:
            properties.update(
                {
                    "encryption": {
                        "plaintext": enc.plaintext_ok,
                        "starttls": enc.starttls_ok,
                        "tls": enc.tls_ok,
                    }
                }
            )
        # Cleartext / sniffable IMAP probe (PTV-SVC-SNIFFABLE)
        if (sniff_err := getattr(self.results, "sniffable_error", None)) is not None:
            properties.update({"sniffableError": sniff_err})
        elif (sn := self.results.sniffable) is not None:
            probe_lines: list[str] = []
            if sn.skipped:
                probe_lines.append(f"skipped: {sn.skip_reason or 'yes'}")
            elif not sn.plain_ok:
                probe_lines.append("plain_imap_tcp: not available")
            else:
                probe_lines.append(f"starttls_advertised: {sn.starttls_advertised}")
                if sn.auth_methods:
                    probe_lines.append("auth_methods_pre_tls: " + ", ".join(sn.auth_methods))
                for method, outcome in sn.probes:
                    probe_lines.append(f"AUTHENTICATE {method}: {outcome}")
                probe_lines.append(f"cleartext_sniffable: {sn.vulnerable}")
            properties.update(
                {
                    "sniffableProbe": {
                        "skipped": sn.skipped,
                        "skipReason": sn.skip_reason,
                        "plainOk": sn.plain_ok,
                        "startTlsAdvertised": sn.starttls_advertised,
                        "authMethodsPreTls": list(sn.auth_methods),
                        "authenticateProbes": [{"mechanism": m, "outcome": o} for m, o in sn.probes],
                        "vulnerable": sn.vulnerable,
                    }
                }
            )
            if sn.vulnerable and not sn.skipped and sn.plain_ok:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.Sniffable.value,
                        "vuln_request": "cleartext IMAP TCP (CAPABILITY / AUTHENTICATE probe)",
                        "vuln_response": "\n".join(probe_lines),
                    }
                )
        # Invalid / non-standard commands (PTV-SVC-IMAP-INVCOMM)
        if (ic_err := getattr(self.results, "inv_comm_error", None)) is not None:
            properties.update({"invalidCommandsError": ic_err})
        elif (ic := self.results.inv_comm) is not None:
            properties.update(
                {
                    "invalidCommands": {
                        "vulnerable": ic.vulnerable,
                        "weakness": ic.weakness,
                        "detail": ic.detail,
                        "baselineLatencySec": ic.baseline_latency_sec,
                        "tests": [
                            {
                                "category": t.category,
                                "command": t.command_display,
                                "outcome": t.outcome,
                                "replySnippet": t.reply_snippet,
                                "responseTimeSec": t.response_time_sec,
                                "slowResponse": t.slow_response,
                                "infoLeak": t.info_leak,
                                "sessionOkAfter": t.session_ok_after,
                                "probeVulnerable": t.probe_vulnerable,
                            }
                            for t in ic.tests
                        ],
                    }
                }
            )
            if ic.vulnerable or ic.weakness:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.InvComm.value,
                        "vuln_request": "Invalid / non-standard IMAP command probes",
                        "vuln_response": ic.detail,
                    }
                )
        # Connection limits / rate / idle (PTV-SVC-IMAP-CONN*)
        if (cl_err := getattr(self.results, "conn_limits_error", None)) is not None:
            properties.update({"connLimitsError": cl_err})
        elif (cl := self.results.conn_limits) is not None:
            properties.update(
                {
                    "connLimits": {
                        "connected": cl.connected,
                        "maxAttempts": cl.max_attempts,
                        "banned": cl.banned,
                        "banDurationProbeRan": cl.ban_duration_probe_ran,
                        "banDurationSeconds": cl.ban_duration_seconds,
                        "banDurationExceeded": cl.ban_duration_exceeded,
                        "preauthIdleSeconds": cl.preauth_idle_seconds,
                        "preauthIdleExceeded": cl.preauth_idle_exceeded,
                        "idleAfterCapabilitySeconds": cl.post_cap_idle_seconds,
                        "idleAfterCapabilityExceeded": cl.post_cap_idle_exceeded,
                        "sequentialAccepted": cl.sequential_accepted,
                        "sequentialAttempts": cl.sequential_attempts,
                        "sequentialRefused": cl.sequential_refused,
                        "authParallelAccepted": cl.auth_parallel_accepted,
                        "authParallelAttempted": cl.auth_parallel_attempted,
                        "authLoginStoppedEarly": cl.auth_login_stopped_early,
                        "idleLoggedSeconds": cl.idle_logged_seconds,
                        "idleLoggedExceeded": cl.idle_logged_exceeded,
                        "authPhaseSkipReason": cl.auth_phase_skip_reason,
                        "idleProbeDetail": cl.idle_probe_detail,
                    }
                }
            )
            if (
                cl.auth_parallel_accepted >= CONN_LIMIT_AUTH_PARALLEL_VULN_THRESHOLD
                and not cl.auth_login_stopped_early
            ):
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.ConnCntIp.value,
                        "vuln_request": "Concurrent authenticated IMAP sessions (same account)",
                        "vuln_response": (
                            f"{cl.auth_parallel_accepted} simultaneous LOGINS accepted "
                            f"(attempted {cl.auth_parallel_attempted})"
                        ),
                    }
                )

            if not cl.banned and cl.connected >= CONN_LIMIT_CONN_IP_THRESHOLD:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.ConnCntIp.value,
                        "vuln_request": "Concurrent IMAP sessions from single source (ramp-up probe)",
                        "vuln_response": f"{cl.connected} simultaneous sessions accepted without refusal (budget {cl.max_attempts})",
                    }
                )
            if not cl.banned and cl.connected >= CONN_LIMIT_CONN_GLOB_THRESHOLD:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.ConnCntGlob.value,
                        "vuln_request": "High concurrency IMAP sessions (single-client ramp)",
                        "vuln_response": f"{cl.connected} sessions accepted; no refusal within probe — verify global limits from multiple sources",
                    }
                )
            long_bits: list[str] = []
            if cl.preauth_idle_seconds is not None and (
                cl.preauth_idle_exceeded
                or cl.preauth_idle_seconds > CONN_LIMIT_PREAUTH_IDLE_MAX_OK_SEC
            ):
                long_bits.append(
                    "pre-auth idle: "
                    + _imap_conn_duration_display(cl.preauth_idle_seconds, cl.preauth_idle_exceeded)
                )
            if cl.post_cap_idle_seconds is not None and (
                cl.post_cap_idle_exceeded
                or cl.post_cap_idle_seconds > CONN_LIMIT_POST_CAP_IDLE_MAX_OK_SEC
            ):
                long_bits.append(
                    "idle after CAPABILITY: "
                    + _imap_conn_duration_display(cl.post_cap_idle_seconds, cl.post_cap_idle_exceeded)
                )
            if cl.idle_logged_seconds is not None and (
                cl.idle_logged_exceeded
                or cl.idle_logged_seconds > CONN_LIMIT_IDLE_AFTER_LOGIN_MAX_OK_SEC
            ):
                long_bits.append(
                    "idle after IDLE command (authenticated): "
                    + _imap_conn_duration_display(cl.idle_logged_seconds, cl.idle_logged_exceeded)
                )
            if long_bits:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.ConnLong.value,
                        "vuln_request": "IMAP non-authenticated / lightweight-command / IDLE idle lifetime",
                        "vuln_response": "; ".join(long_bits),
                    }
                )
            if cl.sequential_refused == 0 and cl.sequential_accepted >= CONN_LIMIT_RATE_VULN_MIN_OK:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.ConnRate.value,
                        "vuln_request": "Sequential connect / logout burst (connect-rate limiting)",
                        "vuln_response": (
                            f"{cl.sequential_accepted}/{cl.sequential_attempts} rapid connects succeeded without refusal"
                        ),
                    }
                )

        # Catch-all (skip terminal if streamed; always add to properties for JSON)
        if (catch_all := getattr(self.results, "catch_all", None)) is not None:
            if catch_all == "indeterminate":
                properties.update({"catchAll": "indeterminate"})
        # Anonymous / weak default access (PTL-SVC-IMAP-ANONYMOUS)
        if (ar := self.results.anonymous) is not None:
            properties.update(
                {
                    "anonymousAccess": {
                        "authAnonymousAdvertised": ar.auth_anonymous_advertised,
                        "authenticateAnonymousOk": ar.authenticate_anonymous_ok,
                        "loginAnonymousEmptyOk": ar.login_anonymous_empty_ok,
                        "weakCredentialsOk": list(ar.weak_credentials_ok),
                        "vulnerable": ar.vulnerable,
                        "detail": ar.detail,
                    }
                }
            )
            if ar.vulnerable:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.Anonymous.value,
                        "vuln_request": "AUTHENTICATE ANONYMOUS / LOGIN anonymous|guest|public",
                        "vuln_response": ar.detail,
                    }
                )
        # EICAR APPEND / antivirus ingress (PTV-SVC-IMAP-EICAR)
        if (er := self.results.eicar) is not None:
            properties.update(
                {
                    "eicarAppend": {
                        "skipped": er.skipped,
                        "skipReason": er.skip_reason,
                        "mailbox": er.mailbox,
                        "appendResult": er.append_typ,
                        "appendDetail": er.append_detail,
                        "vulnerable": er.vulnerable,
                    }
                }
            )
            if er.vulnerable and not er.skipped:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.Eicar.value,
                        "vuln_request": f"APPEND EICAR test line to mailbox {er.mailbox!r} (RFC 822 message body)",
                        "vuln_response": er.append_detail or er.append_typ or "OK",
                    }
                )
        def _rl_phase_dict(ph: ImapResourceLoadPhase) -> dict:
            return {
                "label": ph.label,
                "attempted": ph.attempted,
                "ok": ph.ok,
                "failed": ph.failed,
                "disconnected": ph.disconnected,
                "disconnectAfter": ph.disconnect_after,
                "hitCap": ph.hit_cap,
                "minRtSeconds": ph.min_rt_seconds,
                "maxRtSeconds": ph.max_rt_seconds,
                "avgRtSeconds": ph.avg_rt_seconds,
                "baselineAvgSeconds": ph.baseline_avg_seconds,
                "lastWindowAvgSeconds": ph.last_window_avg_seconds,
                "slowdown": ph.slowdown,
                "errorRatePct": ph.error_rate_pct,
            }

        if (rl_err := getattr(self.results, "imap_resource_load_error", None)) is not None:
            properties.update({"resourceLoadProbeError": rl_err})
        elif (rl := self.results.imap_resource_load) is not None:
            rl_props: dict = {
                "skipped": rl.skipped,
                "skipReason": rl.skip_reason,
                "mailbox": rl.mailbox,
                "appendMaxRequested": rl.append_max_requested,
                "searchMaxRequested": rl.search_max_requested,
                "searchSkippedReason": rl.search_skipped_reason,
                "vulnerable": rl.vulnerable,
                "detail": rl.detail,
            }
            if rl.append is not None:
                rl_props["appendPhase"] = _rl_phase_dict(rl.append)
            if rl.search is not None:
                rl_props["searchPhase"] = _rl_phase_dict(rl.search)
            properties.update({"resourceLoadProbe": rl_props})
            if rl.vulnerable and not rl.skipped:
                req_bits = [
                    f"APPEND×{rl.append_max_requested} small RFC822",
                    f"UID SEARCH ALL×{rl.search_max_requested}",
                    f"mailbox={rl.mailbox!r}",
                ]
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.ResourceLoad.value,
                        "vuln_request": "; ".join(req_bits),
                        "vuln_response": rl.detail,
                    }
                )
        if (miso_err := getattr(self.results, "imap_mailbox_iso_error", None)) is not None:
            properties.update({"mailboxIsolationProbeError": miso_err})
        elif (miso := self.results.imap_mailbox_iso) is not None:
            miso_props: dict = {
                "skipped": miso.skipped,
                "skipReason": miso.skip_reason,
                "ownMailbox": miso.own_mailbox,
                "foreignUserToken": miso.foreign_user_token,
                "loginUsername": miso.login_username,
                "aclInCapability": miso.acl_in_capability,
                "namespaceTyp": miso.namespace_typ,
                "namespaceRaw": miso.namespace_raw,
                "getAclTyp": miso.get_acl_typ,
                "getAclRaw": (miso.get_acl_raw or "")[:8000] if miso.get_acl_raw else None,
                "aclAnyoneRights": miso.acl_anyone_rights,
                "aclAnonymousRights": miso.acl_anonymous_rights,
                "aclAuthenticatedRights": miso.acl_authenticated_rights,
                "aclOverbroadWorldHeuristic": miso.acl_overbroad_world,
                "listRootTyp": miso.list_root_typ,
                "listRootCount": miso.list_root_count,
                "listRootTruncated": miso.list_root_truncated,
                "listRootSample": list(miso.list_root_sample),
                "foreignLikeMailboxVisibleInRootList": miso.foreign_like_mailbox_visible_in_root_list,
                "listDictionaryTotalListed": miso.list_dictionary_total_listed,
                "listDictionaryNonzeroPatterns": miso.list_dictionary_nonzero_patterns,
                "enumerationSignal": miso.enumeration_signal,
                "foreignExamineOk": miso.foreign_examine_ok,
                "vulnerable": miso.vulnerable,
                "detail": miso.detail,
                "selectProbes": [
                    {
                        "probeId": p.probe_id,
                        "mailbox": p.mailbox,
                        "typ": p.typ,
                        "detail": p.detail,
                        "okExamine": p.ok_selected,
                    }
                    for p in miso.select_probes
                ],
                "listDictionary": [
                    {
                        "reference": r.reference,
                        "pattern": r.pattern,
                        "typ": r.typ,
                        "detail": r.detail,
                        "listedCount": r.listed_count,
                        "sampleMailboxes": list(r.sample_mailboxes),
                    }
                    for r in miso.list_dictionary
                ],
            }
            properties.update({"mailboxIsolationProbe": miso_props})
            if miso.vulnerable and not miso.skipped:
                req_m = (
                    f"NAMESPACE/GETACL/LIST/SELECT probes; own={miso.own_mailbox!r}; "
                    f"foreign_token={miso.foreign_user_token!r}"
                )
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.AuthzBypass.value,
                        "vuln_request": req_m,
                        "vuln_response": miso.detail,
                    }
                )
        if (tls_err := getattr(self.results, "imap_tls_audit_error", None)) is not None:
            properties.update({"tlsCertificateProbeError": tls_err})
        elif (ta := self.results.imap_tls_audit) is not None:
            ta_props = {
                "host": ta.host,
                "port": ta.port,
                "implicitTlsIntended": ta.implicit_tls_intended,
                "vulnerable": ta.vulnerable,
                "detail": ta.detail,
                "probes": [
                    {
                        "mode": p.mode,
                        "attempted": p.attempted,
                        "skippedReason": p.skipped_reason,
                        "startTlsAdvertised": p.starttls_advertised,
                        "handshakeOk": p.handshake_ok,
                        "handshakeError": p.handshake_error,
                        "tlsVersion": p.tls_version,
                        "cipherName": p.cipher_name,
                        "cipherProtocol": p.cipher_protocol,
                        "peerSubject": p.peer_subject,
                        "peerIssuer": p.peer_issuer,
                        "sanEntries": list(p.san_dns),
                        "notBefore": p.not_before,
                        "notAfter": p.not_after,
                        "daysUntilExpiry": p.days_until_expiry,
                        "certExpired": p.cert_expired,
                        "certNotYetValid": p.cert_not_yet_valid,
                        "weakTlsVersion": p.weak_tls_version,
                        "weakCipher": p.weak_cipher,
                        "expiresWithinVulnWindow": p.expires_within_vuln_days,
                        "expiresWithinWarnWindow": p.expires_within_warn_days,
                        "peerKeySummary": p.peer_key_summary,
                        "peerSignatureHash": p.peer_signature_hash,
                        "cryptoWarnings": list(p.crypto_warnings),
                    }
                    for p in ta.probes
                ],
            }
            properties.update({"tlsCertificateProbe": ta_props})
            if ta.vulnerable:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.TlsAudit.value,
                        "vuln_request": f"strict TLS + certificate audit (RFC 7817 / platform trust) {ta.host!r}:{ta.port}",
                        "vuln_response": ta.detail,
                    }
                )
        # LOGIN user enumeration (PTV-SVC-IMAP-USRENUM)
        if (ue_err := getattr(self.results, "imap_usrenum_error", None)) is not None:
            properties.update({"loginUserEnumError": ue_err})
        elif (ur := self.results.imap_usrenum) is not None:
            properties.update(
                {
                    "loginUserEnum": {
                        "enumerationMethod": ur.enumeration_method,
                        "wrongPasswordMarker": ur.wrong_password_marker,
                        "loginDisabledAdvertised": ur.login_disabled_advertised,
                        "authPlainAdvertised": ur.auth_plain_advertised,
                        "invalidBaselineNormalized": list(ur.invalid_baseline_normalized),
                        "enumeratedUsernames": list(ur.enumerated_usernames),
                        "vulnerable": ur.vulnerable,
                        "indeterminate": ur.indeterminate,
                        "detail": ur.detail,
                        "probes": [
                            {
                                "username": p.username,
                                "probeKind": p.probe_kind,
                                "replyNormalized": p.reply_normalized,
                                "replyRaw": (p.reply_raw or "")[:400],
                                "elapsedMs": p.elapsed_ms,
                                "unexpectedOk": p.unexpected_ok,
                                "error": p.error,
                                "probeIndex": p.probe_index,
                            }
                            for p in ur.probes
                        ],
                    }
                }
            )
            if ur.vulnerable:
                resp_extra = (
                    "\n".join(ur.enumerated_usernames) if ur.enumerated_usernames else ur.detail
                )
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.UserEnumLogin.value,
                        "vuln_request": "LOGIN with fixed wrong password vs non-existent username baseline",
                        "vuln_response": resp_extra,
                    }
                )
        # AUTHENTICATE PLAIN user enumeration (PTV-SVC-IMAP-USRENUM)
        if (uep_err := getattr(self.results, "imap_usrenum_plain_error", None)) is not None:
            properties.update({"authenticatePlainUserEnumError": uep_err})
        elif (urp := self.results.imap_usrenum_plain) is not None:
            properties.update(
                {
                    "authenticatePlainUserEnum": {
                        "enumerationMethod": urp.enumeration_method,
                        "wrongPasswordMarker": urp.wrong_password_marker,
                        "loginDisabledAdvertised": urp.login_disabled_advertised,
                        "authPlainAdvertised": urp.auth_plain_advertised,
                        "invalidBaselineNormalized": list(urp.invalid_baseline_normalized),
                        "enumeratedUsernames": list(urp.enumerated_usernames),
                        "vulnerable": urp.vulnerable,
                        "indeterminate": urp.indeterminate,
                        "detail": urp.detail,
                        "probes": [
                            {
                                "username": p.username,
                                "probeKind": p.probe_kind,
                                "replyNormalized": p.reply_normalized,
                                "replyRaw": (p.reply_raw or "")[:400],
                                "elapsedMs": p.elapsed_ms,
                                "unexpectedOk": p.unexpected_ok,
                                "error": p.error,
                                "probeIndex": p.probe_index,
                            }
                            for p in urp.probes
                        ],
                    }
                }
            )
            if urp.vulnerable:
                resp_plain = (
                    "\n".join(urp.enumerated_usernames) if urp.enumerated_usernames else urp.detail
                )
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.UserEnumLogin.value,
                        "vuln_request": (
                            "AUTHENTICATE PLAIN with fixed wrong password vs non-existent username baseline"
                        ),
                        "vuln_response": resp_plain,
                    }
                )
        # NTLM info disclosure (PTL-SVC-IMAP-NTLMINFO)
        if ntlm := self.results.ntlm:
            ntlm_props: dict = {
                "authNtlmAdvertised": ntlm.auth_ntlm_advertised,
                "challengeDecoded": bool(ntlm.success and ntlm.ntlm is not None),
            }
            if ntlm.ntlm is not None:
                ntlm_props.update(
                    {
                        "targetName": ntlm.ntlm.target_name,
                        "netbiosDomainName": ntlm.ntlm.netbios_domain,
                        "netbiosComputerName": ntlm.ntlm.netbios_computer,
                        "dnsDomainName": ntlm.ntlm.dns_domain,
                        "dnsComputerName": ntlm.ntlm.dns_computer,
                        "dnsTreeName": ntlm.ntlm.dns_tree,
                        "osVersion": ntlm.ntlm.os_version,
                    }
                )
            properties.update({"ntlmInfo": ntlm_props})
            if ntlm.success and ntlm.ntlm is not None:
                out_lines = [
                    f"Target name: {ntlm.ntlm.target_name}",
                    f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                    f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                    f"DNS domain name: {ntlm.ntlm.dns_domain}",
                    f"DNS computer name: {ntlm.ntlm.dns_computer}",
                    f"DNS tree: {ntlm.ntlm.dns_tree}",
                    f"OS version: {ntlm.ntlm.os_version}",
                ]
                req_parts = ["AUTHENTICATE NTLM", "Negotiate (Type 1) → Challenge (Type 2) decode"]
                if ntlm.auth_ntlm_advertised:
                    req_parts.insert(0, "CAPABILITY contained AUTH=NTLM")
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.NTLM.value,
                        "vuln_request": "; ".join(req_parts),
                        "vuln_response": "\n".join(out_lines),
                    }
                )
        # Login bruteforce (skip terminal output if streamed; always add to deferred for JSON)
        if (creds := self.results.creds) is not None and len(creds) > 0:
            json_lines = [f"user: {cred.user}, password: {cred.passw}" for cred in creds]
            if self.args.user is not None:
                user_str = f"username: {self.args.user}"
            else:
                user_str = f"usernames: {self.args.users}"
            if self.args.password is not None:
                passw_str = f"password: {self.args.password}"
            else:
                passw_str = f"passwords: {self.args.passwords}"
            deferred_vulns.append(
                {
                    "vuln_code": VULNS.WeakCreds.value,
                    "vuln_request": f"{user_str}\n{passw_str}",
                    "vuln_response": "\n".join(json_lines),
                }
            )

        # Create node at the end with all collected properties and bind vulnerabilities
        imap_node = ptjsonlib.create_node_object(
            "software",
            None,
            None,
            properties,
        )
        ptjsonlib.add_node(imap_node)
        node_key = imap_node["key"]
        for v in deferred_vulns:
            ptjsonlib.add_vulnerability(node_key=node_key, **v)

        ptjsonlib.set_status("finished", "")
        self._ptprint(ptjsonlib.get_result_json(), json=True)

    # endregion
