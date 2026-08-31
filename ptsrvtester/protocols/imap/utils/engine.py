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
import uuid
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy as email_policy
from email.encoders import encode_base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
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
from . import tls_audit

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
from ptlibs.ptprinthelper import ptprint

from .decompression_payloads import (
    BILLION_LAUGHS_XML,
    build_full_zip_bomb,
    build_minimal_docx_with_xxe,
    build_minimal_zip_bomb,
    build_zip_with_xxe,
    xxe_xml_template,
)
from .results import *  # noqa: F403
from .results import (  # noqa: F401 — star import skips leading-underscore names
    _imap_conn_duration_display,
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
    ImapTlsVersionScan,
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
        self._ctx = ctx
        return self

    def _flush_terminal(self) -> None:
        """Flush PrintLock so verdicts appear before the next live -vv line."""
        if self.use_json:
            return
        ctx = getattr(self, "_ctx", None)
        if ctx is None:
            return
        lock = getattr(ctx, "print_lock", None)
        if lock is None:
            return
        chunk = lock.get_output_string()
        if chunk:
            sys.stdout.write(chunk)
            sys.stdout.flush()
            lock.output_string = ""

    @staticmethod
    def _snip(text: str | bytes | None, limit: int = 160) -> str:
        """One-line reply snippet for -vv traces (avoid dumping huge blobs)."""
        if text is None:
            return ""
        if isinstance(text, bytes):
            text = text.decode(errors="replace")
        text = (text or "").replace("\r", "").replace("\n", " ").strip()
        if len(text) > limit:
            return text[: limit - 3] + "..."
        return text

    def _dbg(self, msg: str, *, indent: int = 4) -> None:
        """Verbose-only (-vv) line via ctx.debug / ADDITIONS."""
        try:
            self.debug(msg, indent=indent)
        except TypeError:
            self.debug(msg)

    def _dbg_capa_list(self, title: str, capa: list[str] | None, *, indent: int = 4) -> None:
        self._dbg(title, indent=indent)
        item_indent = indent + 4
        if not capa:
            self._dbg("(none)", indent=item_indent)
            return
        for c in capa:
            self._dbg(str(c), indent=item_indent)

    def _dbg_usrenum_row(self, method: str, row: "ImapUserEnumProbeRow") -> None:
        kind = row.probe_kind
        user = row.username
        if row.error:
            self._dbg(f"USR-ENUM {method} {kind} {user!r}: connect/error {self._snip(row.error)}")
        elif row.unexpected_ok:
            self._dbg(f"USR-ENUM {method} {kind} {user!r}: unexpected OK")
        else:
            self._dbg(
                f"USR-ENUM {method} {kind} {user!r}: {self._snip(row.reply_raw)} "
                f"(norm={row.reply_normalized!r})"
            )

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

    def _make_imap_connection(self, *, trace: bool = False) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        """New IMAP session using current TLS/STARTTLS mode (for probes independent of self.imap)."""
        t = _IMAP_CONNECT_TIMEOUT_SEC
        mode = get_mode(self.args)
        if trace:
            self._dbg(f"Connecting to {self.args.target.ip}:{self.args.target.port} ({mode})")
        try:
            if self.args.tls:
                imap = imaplib.IMAP4_SSL(self.args.target.ip, self.args.target.port, timeout=t)
            else:
                imap = imaplib.IMAP4(self.args.target.ip, self.args.target.port, timeout=t)
                if self.args.starttls:
                    if trace:
                        self._dbg("Sending STARTTLS (explicit upgrade)")
                    imap.starttls()
                    if trace:
                        self._dbg("STARTTLS upgrade OK")
        except Exception as e:
            if trace:
                self._dbg(f"Connect failed: {e}")
            raise
        if trace:
            banner = imap.welcome.decode(errors="replace") if imap.welcome else ""
            self._dbg(f"Banner: {self._snip(banner)}")
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

    def _imap_usrenum_names_from_cli(self) -> list[str]:
        """Candidate usernames for USRENUM / USRENUMPLAIN from -u / -U (same as BRUTE)."""
        raw = text_or_file(getattr(self.args, "user", None), getattr(self.args, "users", None))
        names = [ln.strip() for ln in raw if ln.strip() and not ln.strip().startswith("#")]
        ue_mx = int(getattr(self.args, "imap_usrenum_max", 0) or 0)
        if ue_mx > 0:
            names = names[:ue_mx]
        return names

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
        _live_dirty = False

        def _end_live() -> None:
            nonlocal _live_dirty
            if not _live_dirty:
                return
            with _print_lock:
                if not _live_dirty:
                    return
                sys.stdout.write("\n")
                sys.stdout.flush()
                _live_dirty = False

        def _write_live(label: str, value: str) -> None:
            nonlocal _live_dirty
            line = f"    {label} {value}"
            with _print_lock:
                sys.stdout.write(f"\r{line:<120}")
                sys.stdout.flush()
                _live_dirty = True

        def _finalize_line(label: str, value: str) -> None:
            nonlocal _live_dirty
            line = f"    {label} {value}"
            with _print_lock:
                sys.stdout.write(f"\r{line:<120}\n")
                sys.stdout.flush()
                _live_dirty = False

        def _fmt_mmss(seconds: float) -> str:
            return f"{int(seconds // 60):02d}:{int(seconds % 60):02d}"

        def _dbg(msg: str, *, indent: int = 4) -> None:
            nonlocal _live_dirty
            with _print_lock:
                if _live_dirty:
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    _live_dirty = False
                self._dbg(msg, indent=indent)

        def _print_verdict(is_vuln: bool, text: str) -> None:
            nonlocal _live_dirty
            with _print_lock:
                if _live_dirty:
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    _live_dirty = False
                if not _show_progress:
                    return
                ptprint(
                    text,
                    bullet_type="VULN" if is_vuln else "NOTVULN",
                    condition=True,
                    indent=8,
                )

        def _print_info(text: str) -> None:
            nonlocal _live_dirty
            with _print_lock:
                if _live_dirty:
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    _live_dirty = False
                if not _show_progress:
                    return
                ptprint(text, bullet_type="TITLE", condition=True, indent=8)

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

        try:
            _dbg("Connection limits test")
            _dbg(
                f"Target {self.args.target.ip}:{self.args.target.port} — up to {max_attempts} parallel "
                f"sessions (ramp {PHASE1_DELAY}s), ban duration probe max {MAX_BAN_WAIT}s, "
                f"banner/idle timeout cap {MAX_TIMEOUT}s."
            )

            if _show_progress:
                _write_live("Connected:", "0")

            try:
                imap_a = self._make_imap_connection()
                a_start_time = time.perf_counter()
                connections.append(imap_a)
                _dbg("Session A (banner-only): connect OK")
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
                _dbg(f"Session A (banner-only): connect failed — {exc}")

            time.sleep(PHASE1_DELAY)

            try:
                imap_b = self._make_imap_connection()
                b_start_time = time.perf_counter()
                connections.append(imap_b)
                try:
                    imap_b.capability()
                except Exception:
                    pass
                _dbg("Session B (CAPABILITY): connect OK")
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
                _dbg(f"Session B (CAPABILITY): connect failed — {exc}")

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
            _dbg(f"Ramp-up: {connected}/{max_attempts} connections established.")
            if banned:
                _dbg(f"Ramp-up stopped: {_first_error[0]}")
            if _show_progress:
                _finalize_line("Connected:", str(connected))

            if banned and connected >= CONN_LIMIT_CONN_IP_THRESHOLD:
                _print_info(f"Further connections refused after {connected} sessions (possible rate / concurrency limit).")
            elif not banned:
                _print_verdict(
                    True,
                    f"No refusal observed while raising concurrent sessions "
                    f"({connected}/{max_attempts} established)",
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
        finally:
            _end_live()

    def _test_catch_all(self) -> CatchAllResult:
        """Test if server accepts invalid credentials (LOGIN with random user/pass)."""
        try:
            fake_user = "".join(random.choices(string.ascii_letters + string.digits, k=24))
            fake_pass = "".join(random.choices(string.ascii_letters + string.digits, k=24))
            self._dbg(f"Catch-all LOGIN {fake_user!r}")
            imap = self.connect()
            try:
                imap.login(fake_user, fake_pass)
                self._dbg("Catch-all LOGIN → accepted (indeterminate)")
                return "indeterminate"
            except Exception as e:
                self._dbg(f"Catch-all rejected (not configured): {self._snip(str(e))}")
                return "not_configured"
            finally:
                try:
                    imap.logout()
                except Exception:
                    pass
        except Exception as e:
            self._dbg(f"Catch-all: connect failed: {e}")
            return "not_configured"

    def _do_info(
        self, imap: imaplib.IMAP4 | imaplib.IMAP4_SSL, get_commands: bool = True
    ) -> InfoResult:
        """
        Core info logic: banner, ID, CAPABILITY (plain / already-encrypted session).
        Merges pre-auth CAPABILITY from banner [CAPABILITY ...] with imap.capabilities.
        Post-STARTTLS CAPABILITY is fetched separately (CAPA module, POP3-style).
        """
        banner = imap.welcome.decode() if imap.welcome else None
        id_val = None
        capability = None

        if get_commands:
            capa_from_imap = [str(c) for c in imap.capabilities] if imap.capabilities else []
            capa_from_banner = _extract_capabilities_from_banner(banner)
            capability = list(dict.fromkeys(capa_from_imap + capa_from_banner)) or capa_from_imap or capa_from_banner
            self._dbg_capa_list("CAPABILITY response:", capability)

            try:
                typ, dat = imap.xatom("ID")
                typ, res = imap._untagged_response(typ, dat, "ID")
                if isinstance(res, list):
                    id_ = next((d for d in res), None)
                    if isinstance(id_, bytes):
                        id_val = id_.decode()
                    elif id_ is not None:
                        id_val = str(id_)
                if id_val:
                    self._dbg(f"ID → {self._snip(id_val)}")
                else:
                    self._dbg("ID: not advertised / empty")
            except Exception as e:
                self._dbg(f"ID failed: {self._snip(str(e))}")

        return InfoResult(banner, id_val, capability, None)

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
        self._dbg(f"{vers or 'n/a'} cipher={cname or 'n/a'}")
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

    def _imap_tls_audit_close_sock(self, sock: socket.socket | ssl.SSLSocket | None) -> None:
        if sock is None:
            return
        try:
            sock.close()
        except Exception:
            pass

    def _imap_tls_audit_wrap(
        self,
        host: str,
        port: int,
        timeout: float,
        *,
        implicit: bool,
        ctx: ssl.SSLContext,
        trace: list[str],
        read_banner: bool,
    ) -> tuple[ssl.SSLSocket | None, bool | None, str | None]:
        def log(msg: str) -> None:
            self._dbg(msg)

        sock, advertised, err = tls_audit.prepare_imap_for_tls(
            host, port, timeout, implicit=implicit, trace=trace, log=log
        )
        if sock is None:
            return None, advertised, err
        if not implicit and advertised is False:
            self._imap_tls_audit_close_sock(sock)
            return None, False, err or "STARTTLS not advertised in CAPABILITY"
        if not implicit and err:
            self._imap_tls_audit_close_sock(sock)
            return None, advertised, err
        try:
            hello = "TLS ClientHello (platform trust store + hostname check)"
            trace.append(hello)
            self._dbg(hello)
            ssl_sock = tls_audit.wrap_and_greet(
                sock,
                ctx,
                host,
                timeout,
                trace=trace,
                log=log,
                read_banner=read_banner,
            )
            return ssl_sock, (None if implicit else advertised), None
        except Exception as e:
            self._imap_tls_audit_close_sock(sock)
            return None, (None if implicit else advertised), str(e)[:500]

    def _imap_tls_audit_finish_probe(
        self,
        *,
        host: str,
        mode: str,
        implicit: bool,
        advertised: bool | None,
        ssl_sock: ssl.SSLSocket | None,
        handshake_ok: bool,
        handshake_error: str | None,
        skipped_reason: str | None,
        attempted: bool,
        cert_trust_ok: bool,
        trace: list[str],
        versions: tuple[ImapTlsVersionScan, ...],
    ) -> ImapTlsAuditProbeResult:
        if ssl_sock is None or not handshake_ok:
            pr = self._imap_tls_audit_probe_failure(
                mode, attempted, skipped_reason, advertised, False, handshake_error
            )
        else:
            pr = self._imap_tls_audit_probe_from_ssl(
                ssl_sock,
                mode=mode,
                attempted=True,
                skipped_reason=None,
                starttls_advertised=advertised,
                handshake_ok=True,
                handshake_error=None,
            )
            trace.append(f"{pr.tls_version or 'n/a'} cipher={pr.cipher_name or 'n/a'}")
        cn = self._imap_tls_audit_terminal_subject_cn(pr.peer_subject)
        id_ok, id_detail, id_wild = tls_audit.identity_matches(host, pr.san_dns, cn)
        if not versions and pr.tls_version:
            versions = tls_audit.fallback_version_scan(pr.tls_version, pr.cipher_name)
        weak_ver = pr.weak_tls_version or any(v.rating == "bad" for v in versions)
        weak_c = pr.weak_cipher or any(
            c.rating == "bad" for v in versions for c in v.ciphers
        )
        conn_mode = tls_audit.connection_mode_label(
            implicit=implicit,
            starttls_advertised=advertised,
            handshake_ok=pr.handshake_ok,
        )
        return pr._replace(
            versions=versions,
            imap_trace=tuple(trace),
            identity_ok=id_ok if pr.handshake_ok else False,
            identity_detail=id_detail if pr.handshake_ok else None,
            identity_wildcard=id_wild if pr.handshake_ok else False,
            cert_trust_ok=bool(cert_trust_ok and pr.handshake_ok),
            connection_mode=conn_mode,
            weak_tls_version=weak_ver,
            weak_cipher=weak_c,
        )

    def test_imap_tls_audit(self) -> ImapTlsAuditResult:
        """
        TLS + certificate audit for IMAP (PTV-SVC-IMAP-TLSAUDIT).

        Enumerates offered TLS versions and cipher suites, then rates them
        against RFC 8996, NIST SP 800-52 Rev. 2 and TLSRef Intermediate
        (Mozilla Server Side TLS lineage). Certificate identity follows
        RFC 9525 wildcard matching.
        """
        host = self.args.target.ip
        port = int(self.args.target.port)
        timeout = _IMAP_TLS_AUDIT_TIMEOUT_SEC
        implicit = bool(self.args.tls or port == 993)
        mode = "implicit_tls" if implicit else "starttls"
        trace: list[str] = []
        advertised: bool | None = True if implicit else None

        strict_ctx = ssl.create_default_context()
        ssl_sock, advertised, err = self._imap_tls_audit_wrap(
            host, port, timeout, implicit=implicit, ctx=strict_ctx, trace=trace, read_banner=True
        )
        cert_trust_ok = ssl_sock is not None
        handshake_ok = ssl_sock is not None
        handshake_error = None if handshake_ok else err
        skipped = None
        attempted = True

        if not implicit and advertised is False:
            attempted = False
            skipped = err or "STARTTLS not advertised in CAPABILITY"
            handshake_ok = False
            probe = self._imap_tls_audit_finish_probe(
                host=host,
                mode=mode,
                implicit=implicit,
                advertised=False,
                ssl_sock=None,
                handshake_ok=False,
                handshake_error=None,
                skipped_reason=skipped,
                attempted=False,
                cert_trust_ok=False,
                trace=trace,
                versions=tuple(),
            )
            return ImapTlsAuditResult(
                host=host,
                port=port,
                implicit_tls_intended=implicit,
                probes=(probe,),
                vulnerable=False,
                detail="STARTTLS not advertised; no certificate to audit on this path.",
            )

        if ssl_sock is None and err:
            self._dbg("TLS handshake (platform trust store + hostname check)")
            self._dbg(f"handshake failed: {self._snip(err)}")
            handshake_error = err
            unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            unverified.check_hostname = False
            unverified.verify_mode = ssl.CERT_NONE
            retry_trace: list[str] = []
            ssl_sock, advertised, unver_err = self._imap_tls_audit_wrap(
                host,
                port,
                timeout,
                implicit=implicit,
                ctx=unverified,
                trace=retry_trace,
                read_banner=True,
            )
            handshake_ok = ssl_sock is not None
            cert_trust_ok = False
            if ssl_sock is None:
                handshake_error = err or unver_err

        versions: tuple[ImapTlsVersionScan, ...] = tuple()
        if handshake_ok:
            try:
                versions = tls_audit.scan_tls_versions(
                    host,
                    port,
                    timeout,
                    implicit=implicit,
                    sni=host,
                    log=self._dbg,
                )
            except Exception as e:
                self._dbg(f"TLS version/cipher scan failed: {self._snip(str(e))}")

        try:
            probe = self._imap_tls_audit_finish_probe(
                host=host,
                mode=mode,
                implicit=implicit,
                advertised=advertised,
                ssl_sock=ssl_sock,
                handshake_ok=handshake_ok,
                handshake_error=handshake_error,
                skipped_reason=skipped,
                attempted=attempted,
                cert_trust_ok=cert_trust_ok,
                trace=trace,
                versions=versions,
            )
        finally:
            self._imap_tls_audit_close_sock(ssl_sock)

        reasons: list[str] = []
        p = probe
        if p.attempted and not p.handshake_ok:
            reasons.append(f"{p.mode}: TLS handshake failed ({p.handshake_error or 'n/a'})")
        if p.handshake_ok and not p.cert_trust_ok:
            reasons.append(f"{p.mode}: certificate chain is not trusted")
        if p.handshake_ok and not p.identity_ok:
            reasons.append(p.identity_detail or "hostname mismatch")
        if p.handshake_ok and p.cert_expired:
            reasons.append(f"{p.mode}: certificate expired")
        if p.handshake_ok and p.cert_not_yet_valid:
            reasons.append(f"{p.mode}: certificate not yet valid")
        if p.handshake_ok and p.expires_within_vuln_days:
            reasons.append(
                f"{p.mode}: certificate expires within {_IMAP_TLS_EXPIRY_VULN_DAYS} days ({p.days_until_expiry}d left)"
            )
        for w in p.crypto_warnings:
            reasons.append(f"{p.mode}: {w}")
        for v in p.versions:
            if v.rating == "bad":
                reasons.append(f"{v.version} offered ({v.rating_reason})")
            for c in v.ciphers:
                if c.rating == "bad":
                    reasons.append(f"{v.version} {c.name}: {c.reason}")

        vuln = len(reasons) > 0
        detail = "; ".join(reasons) if reasons else "No TLS/certificate issues on the probed path."
        return ImapTlsAuditResult(
            host=host,
            port=port,
            implicit_tls_intended=implicit,
            probes=(p,),
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
        if p.identity_detail:
            return ("ok" if p.identity_ok else "bad", p.identity_detail)
        cn = ImapEngine._imap_tls_audit_terminal_subject_cn(p.peer_subject)
        ok, detail, _ = tls_audit.identity_matches(host, p.san_dns, cn)
        return ("ok" if ok else "bad", detail)

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
        Test encryption options: cleartext (143), STARTTLS (143), implicit TLS (993).
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
                self._dbg(f"Cleartext welcome: {self._snip(imap.welcome)}")
                imap.logout()
            except Exception as e:
                self._dbg(f"Cleartext test failed: {e}")

            try:
                imap = imaplib.IMAP4(host, port)
                imap.sock.settimeout(timeout)
                _ = imap.welcome
                self._dbg(f"STARTTLS probe welcome: {self._snip(imap.welcome)}")
                caps = [str(c).upper() for c in (imap.capabilities or [])]
                self._dbg("STARTTLS probe CAPABILITY: " + ", ".join(caps[:12] or ["(none)"]))
                if "STARTTLS" in caps:
                    imap.starttls()
                    _ = imap.capabilities
                    post = [str(c) for c in (imap.capabilities or [])]
                    self._dbg("CAPABILITY after STARTTLS wrap: " + ", ".join(post[:12] or ["(none)"]))
                    starttls_ok = True
                else:
                    self._dbg("STARTTLS not advertised in CAPABILITY")
                imap.logout()
            except Exception as e:
                self._dbg(f"STARTTLS test failed: {e}")

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
                        self._dbg(
                            f"Implicit TLS (SNI={_sni!r}) welcome: {self._snip(line)} → OK"
                        )
                        break
                    self._dbg(
                        f"Implicit TLS (SNI={_sni!r}) welcome: {self._snip(line)} → FAIL"
                    )
                except Exception as e:
                    self._dbg(f"Implicit TLS test failed (SNI={_sni!r}): {e}")
        except Exception as e:
            self._dbg(f"Implicit TLS test failed: {e}")

        return EncryptionResult(plaintext_ok, starttls_ok, tls_ok)

    @staticmethod
    def _auth_methods_from_capa(capability: list[str] | None) -> list[str]:
        methods: list[str] = []
        seen: set[str] = set()
        for c in capability or []:
            u = str(c or "").strip()
            if not u.upper().startswith("AUTH="):
                continue
            m = u.split("=", 1)[-1].strip().upper()
            if not m or m in seen:
                continue
            seen.add(m)
            methods.append(m)

        def _prio(x: str) -> int:
            try:
                return _SNIFFABLE_AUTH_PROBE_PRIORITY.index(x)
            except ValueError:
                return len(_SNIFFABLE_AUTH_PROBE_PRIORITY)

        return sorted(methods, key=lambda x: (_prio(x), x))

    def _imap_connect_auth_path(self, path: str, timeout: float) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        """Open IMAP on cleartext, after STARTTLS, or implicit TLS (ENCRYPT-style)."""
        host = self.args.target.ip
        port = int(self.args.target.port)
        if path == "tls":
            ctx = ssl._create_unverified_context()
            imap = imaplib.IMAP4_SSL(host, port, timeout=timeout, ssl_context=ctx)
            imap.sock.settimeout(timeout)
            return imap
        imap = imaplib.IMAP4(host, port, timeout=timeout)
        imap.sock.settimeout(timeout)
        _ = imap.welcome
        if path == "starttls":
            try:
                imap.capability()
            except Exception:
                pass
            caps = [str(c).upper() for c in (imap.capabilities or [])]
            if "STARTTLS" not in caps:
                try:
                    imap.logout()
                except Exception:
                    pass
                raise RuntimeError("STARTTLS not advertised in CAPABILITY")
            imap.starttls()
        return imap

    def _probe_authenticate_on_path(self, path: str, method: str, timeout: float = 10.0) -> tuple[str, str]:
        """AUTHENTICATE <method> on path. Returns (outcome, reply snippet). Does not print."""
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        try:
            imap = self._imap_connect_auth_path(path, timeout)
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
            return outcome, self._snip(res)
        except Exception as e:
            return "io_error", self._snip(str(e))
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    try:
                        imap.shutdown()
                    except Exception:
                        pass

    def _authlist_emit_path_header(self, label: str) -> None:
        if self.use_json:
            return
        self._ptprint_raw(label, bullet_type="TITLE", condition=True, indent=4)
        self._flush_terminal()
        self._authlist_terminal_emitted = True

    def _authlist_emit_not_available(self) -> None:
        if self.use_json:
            return
        self._ptprint_raw("Not available", bullet_type="NOTVULN", condition=True, indent=8)
        self._flush_terminal()
        self._authlist_terminal_emitted = True

    def _authlist_emit_method_row(self, path: str, row: ImapAuthMechRow) -> None:
        if self.use_json:
            return
        bullet, text = self._authlist_row_display(path, row)
        self._ptprint_raw(text, bullet_type=bullet, condition=True, indent=8)
        self._flush_terminal()
        self._authlist_terminal_emitted = True

    def _authlist_scan_path(self, path: str, timeout: float) -> ImapAuthListPath:
        label = self._authlist_path_label(path)
        self._authlist_emit_path_header(label)
        imap = None
        try:
            imap = self._imap_connect_auth_path(path, timeout)
            banner = imap.welcome.decode(errors="replace") if imap.welcome else ""
            self._dbg(f"{label} welcome: {self._snip(banner)}", indent=8)
            try:
                imap.capability()
            except Exception:
                pass
            capability = [str(c) for c in (imap.capabilities or [])]
            self._dbg_capa_list(f"CAPABILITY ({label}):", capability, indent=8)
            methods = self._auth_methods_from_capa(capability)
            if not methods:
                self._dbg("no AUTH= in CAPABILITY", indent=8)
        except Exception as e:
            self._dbg(f"{label} connect failed: {self._snip(str(e))}", indent=8)
            self._authlist_emit_not_available()
            return ImapAuthListPath(path=path, available=False, skip_reason=str(e)[:240], methods=tuple())
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    try:
                        imap.shutdown()
                    except Exception:
                        pass
        if not methods:
            self._authlist_emit_not_available()
            return ImapAuthListPath(path=path, available=True, skip_reason=None, methods=tuple())
        rows: list[ImapAuthMechRow] = []
        for m in methods:
            outcome, reply = self._probe_authenticate_on_path(path, m, timeout=timeout)
            usable = outcome == "continuation"
            dangerous = IMAP_AUTH_METHOD_LEVEL.get(m, "OK") == "ERROR"
            row = ImapAuthMechRow(name=m, usable=usable, outcome=outcome, dangerous=dangerous)
            rows.append(row)
            self._authlist_emit_method_row(path, row)
            if outcome == "io_error":
                self._dbg(f"AUTHENTICATE {m} failed: {reply}", indent=12)
            else:
                self._dbg(f"AUTHENTICATE {m} → {outcome} {reply}", indent=12)
        return ImapAuthListPath(path=path, available=True, skip_reason=None, methods=tuple(rows))

    def test_imap_authlist(self) -> ImapAuthListResult:
        """AUTH= mechanisms on cleartext, STARTTLS and implicit TLS (SMTP AUTHLIST idea)."""
        timeout = 10.0
        port = int(self.args.target.port)
        tls_only = port == 993
        self._authlist_terminal_emitted = False
        paths: list[ImapAuthListPath] = []
        if not tls_only:
            paths.append(self._authlist_scan_path("cleartext", timeout))
            paths.append(self._authlist_scan_path("starttls", timeout))
        else:
            for skip_path, skip_label in (("cleartext", "Cleartext"), ("starttls", "STARTTLS")):
                self._authlist_emit_path_header(skip_label)
                self._dbg("skipped (implicit TLS port 993)", indent=8)
                self._authlist_emit_not_available()
                paths.append(
                    ImapAuthListPath(
                        path=skip_path,
                        available=False,
                        skip_reason="implicit TLS port 993",
                        methods=tuple(),
                    )
                )
        paths.append(self._authlist_scan_path("tls", timeout))
        reasons: list[str] = []
        for p in paths:
            if p.path != "cleartext" or not p.available:
                continue
            for m in p.methods:
                if m.dangerous and m.usable:
                    reasons.append(f"cleartext AUTH={m.name} usable ({m.outcome})")
        vuln = bool(reasons)
        detail = "; ".join(reasons) if reasons else "No usable dangerous AUTH= mechanisms on cleartext."
        return ImapAuthListResult(paths=tuple(paths), vulnerable=vuln, detail=detail)

    @staticmethod
    def _sniff_cleartext_auth_disallowed(text: str) -> bool:
        """True when the server refuses LOGIN because the session is not TLS (policy, not bad creds)."""
        u = (text or "").upper()
        return any(
            k in u
            for k in (
                "PRIVACYREQUIRED",
                "LOGINDISABLED",
                "CLEARTEXT AUTHENTICATION DISALLOWED",
                "CLEARTEXT AUTHENTICATION IS DISABLED",
                "DISALLOWED ON NON-SECURE",
                "PLAINTEXT AUTHENTICATION DISALLOWED",
            )
        )

    def test_sniffable_plain_imap(self) -> SniffableResult:
        """Cleartext LOGIN + SELECT INBOX (PTV-SVC-SNIFFABLE). Requires -u/-p, not --tls / 993."""
        port = int(self.args.target.port)
        if self.args.tls or port == 993:
            reason = (
                "implicit TLS mode (--tls); SNIFF applies to cleartext only"
                if self.args.tls
                else "implicit TLS port 993; SNIFF applies to cleartext only"
            )
            self._dbg(f"SNIFF skipped: {reason}")
            return SniffableResult(
                skipped=True,
                skip_reason=reason,
                login_ok=False,
                select_ok=False,
                select_typ=None,
                select_detail=None,
                vulnerable=False,
                detail="skipped",
            )
        creds = self._imap_single_known_login()
        if creds is None:
            self._dbg("SNIFF skipped: requires single -u and -p (no wordlists)")
            return SniffableResult(
                skipped=True,
                skip_reason="requires -u/--user and -p/--password (no wordlists)",
                login_ok=False,
                select_ok=False,
                select_typ=None,
                select_detail=None,
                vulnerable=False,
                detail="skipped",
            )
        user, password = creds
        host = self.args.target.ip
        timeout = 10.0
        imap: imaplib.IMAP4 | None = None
        login_ok = False
        try:
            imap = imaplib.IMAP4(host, port, timeout=timeout)
            imap.sock.settimeout(timeout)
            banner = imap.welcome.decode(errors="replace") if imap.welcome else ""
            self._dbg(f"Cleartext welcome: {self._snip(banner)}")
            self._dbg(f"LOGIN {user!r}")
            imap.login(user, password)
            login_ok = True
            self._dbg("LOGIN → OK")
            typ, data = imap.select("INBOX")
            detail = ""
            if data:
                try:
                    detail = " ".join(
                        (x.decode(errors="replace") if isinstance(x, bytes) else str(x)) for x in data if x
                    )[:200]
                except Exception:
                    detail = str(data)[:200]
            self._dbg(f"SELECT INBOX → {typ} {self._snip(detail)}")
            select_ok = str(typ).upper() == "OK"
            return SniffableResult(
                skipped=False,
                skip_reason=None,
                login_ok=True,
                select_ok=select_ok,
                select_typ=str(typ) if typ else None,
                select_detail=detail or None,
                vulnerable=select_ok,
                detail=(
                    "SELECT INBOX succeeded after LOGIN on cleartext"
                    if select_ok
                    else "Not sniffable"
                ),
            )
        except Exception as e:
            msg = _imap_login_exception_text(e)
            self._dbg(f"{'LOGIN' if not login_ok else 'SELECT INBOX'} → {self._snip(msg)}")
            if not login_ok and self._sniff_cleartext_auth_disallowed(msg):
                term = "Not sniffable"
            elif not login_ok:
                term = "LOGIN failed"
            else:
                term = "Not sniffable"
            return SniffableResult(
                skipped=False,
                skip_reason=None,
                login_ok=login_ok,
                select_ok=False,
                select_typ=None,
                select_detail=msg[:240] or None,
                vulnerable=False,
                detail=term,
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
                self._dbg(f"INVCMD baseline CAPABILITY latency: {elapsed:.3f}s")
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
        self._dbg(
            f"INVCMD {display} → {outcome}"
            + (f" {self._snip(snippet)}" if snippet else "")
        )
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
        self._dbg("Invalid command probes")
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
            detail = "Probes completed without indicators of critical parsing or session weakness."
        return InvCommImapResult(
            tests=cases,
            vulnerable=vulnerable,
            weakness=weakness,
            detail=detail,
            baseline_latency_sec=baseline,
        )

    def connect(self, *, trace: bool = False) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        """
        Establishes a new IMAP connection with the appropriate
        encryption mode according to module arguments

        Returns:
            imaplib.IMAP4 | imaplib.IMAP4_SSL: new connection
        """
        try:
            return self._make_imap_connection(trace=trace)
        except Exception as e:
            msg = (
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
            )
            raise OSError(msg) from e

    def info(self, get_commands: bool = True) -> InfoResult:
        """Performs bannergrabbing; optionally ID and CAPABILITY commands."""
        return self._do_info(self.imap, get_commands)

    def fetch_capability_after_starttls(self) -> list[str] | None:
        """Reconnect, STARTTLS-upgrade, and return post-STARTTLS CAPABILITY (None if unavailable)."""
        if self.args.tls or self.args.target.port == 993:
            return None
        imap = None
        try:
            imap = self._make_imap_connection()
        except Exception as e:
            self._dbg(f"STARTTLS / CAPABILITY after STARTTLS failed: {self._snip(str(e))}")
            return None
        try:
            capa = [str(c) for c in imap.capabilities] if imap.capabilities else []
            banner = imap.welcome.decode() if imap.welcome else None
            capa_banner = _extract_capabilities_from_banner(banner)
            capability = list(dict.fromkeys(capa + capa_banner)) or capa or capa_banner
            if "STARTTLS" not in [c.upper() for c in capability]:
                self._dbg("STARTTLS not advertised in CAPABILITY")
                return None
            self._dbg("STARTTLS available — upgrading for post-STARTTLS CAPABILITY")
            imap.starttls()
            capability_starttls = [str(c) for c in imap.capabilities] if imap.capabilities else []
            self._dbg_capa_list("CAPABILITY after STARTTLS:", capability_starttls)
            return capability_starttls
        except Exception as e:
            self._dbg(f"STARTTLS / CAPABILITY after STARTTLS failed: {self._snip(str(e))}")
            return None
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    pass

    def _try_authenticate_anonymous(self, imap: imaplib.IMAP4 | imaplib.IMAP4_SSL) -> bool:
        """RFC 4505 SASL ANONYMOUS over IMAP AUTHENTICATE (imaplib supplies base64 trace)."""

        def authobject(b: bytes):
            return b"".join(
                random.choice(ascii_letters).encode() for _ in range(random.randint(5, 10))
            )

        try:
            typ, dat = imap.authenticate("ANONYMOUS", authobject)
            extra = ""
            if dat:
                try:
                    extra = " " + self._snip(dat[0] if isinstance(dat, list) else dat)
                except Exception:
                    extra = ""
            self._dbg(f"AUTHENTICATE ANONYMOUS → {typ}{extra}")
            return typ == "OK"
        except Exception as e:
            self._dbg(f"AUTHENTICATE ANONYMOUS failed: {self._snip(str(e))}")
            return False

    def _try_login_pair(self, user: str, password: str) -> bool:
        disp = password if password else "<empty>"
        try:
            imap = self.connect()
        except Exception as e:
            self._dbg(f"LOGIN {user!r}: connect failed: {e}")
            return False
        try:
            try:
                self._dbg(f"LOGIN {user!r} / {disp}")
                imap.login(user, password)
                self._dbg(f"LOGIN {user!r} → OK")
                return True
            except Exception as e:
                self._dbg(f"LOGIN {user!r} → failed: {self._snip(str(e))}")
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
            self._dbg(f"AUTH=ANONYMOUS advertised={auth_anonymous_advertised}")
            authenticate_anonymous_ok = self._try_authenticate_anonymous(imap_cap)
        except Exception as e:
            self._dbg(f"Anonymous AUTHENTICATE probe failed: {self._snip(str(e))}")
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
            self._dbg("EICAR skipped: requires single -u and -p (no wordlists)")
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
            self._dbg(f"LOGIN {user!r} → OK")
            typ, data = imap.append(mb, None, None, msg)
            detail: str | None = None
            if data:
                try:
                    raw = data[0]
                    detail = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
                    detail = detail[:500]
                except Exception:
                    detail = str(data)[:500]
            self._dbg(f"APPEND {mb!r} (EICAR) → {typ} {self._snip(detail)}")
            return EicarAppendResult(
                skipped=False,
                skip_reason=None,
                mailbox=mb,
                append_typ=typ,
                append_detail=detail,
                vulnerable=(typ == "OK"),
            )
        except Exception as e:
            self._dbg(f"EICAR APPEND failed: {self._snip(str(e))}")
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

    def _imap_zipxxe_variant_title(self, variant: str) -> str:
        return ZIPXXE_VARIANT_TITLES.get(
            variant,
            variant.replace("_", " ").strip().title() + " test",
        )

    def _imap_zipxxe_variant_payload_label(self, variant: str) -> str:
        return ZIPXXE_VARIANT_PAYLOAD_LABELS.get(
            variant,
            variant.replace("_", " "),
        )

    @staticmethod
    def _imap_zipxxe_trace_status(line: str, prefix: str) -> str | None:
        if not line.startswith(prefix):
            return None
        rest = line.split(":", 1)[1].strip() if ":" in line else ""
        return rest.split()[0] if rest else None

    def _imap_zipxxe_variant_outcome_line(self, v: ZipxxeVariantResult) -> str:
        label = self._imap_zipxxe_variant_payload_label(v.variant)
        if v.accepted > 0:
            for line in reversed(v.imap_trace):
                code = self._imap_zipxxe_trace_status(line, "APPEND")
                if code:
                    return f"{label}: {code} (accepted)"
            return f"{label}: OK (accepted)"
        if v.rejected > 0:
            for line in reversed(v.imap_trace):
                code = self._imap_zipxxe_trace_status(line, "APPEND")
                if code:
                    return f"{label}: {code} (rejected)"
            return f"{label}: NO (rejected)"
        if v.error > 0:
            return f"{label}: (error)"
        return f"{label}: (skipped)"

    def _imap_zipxxe_stream_variant_section(
        self,
        v: ZipxxeVariantResult,
        *,
        stream_trace: bool = False,
    ) -> None:
        """Per-variant terminal block — same layout as SMTP ZIPXXE."""
        if self.use_json:
            return
        pp = ptprint
        pp(self._imap_zipxxe_variant_title(v.variant), bullet_type="TITLE", condition=True, indent=4)
        if stream_trace:
            for line in v.imap_trace:
                if line.startswith("---"):
                    continue
                self._dbg(line, indent=8)
        pp(self._imap_zipxxe_variant_outcome_line(v), bullet_type="TEXT", condition=True, indent=8)
        if v.detail:
            pp(f"Summary: {v.detail}", bullet_type="TEXT", condition=True, indent=8)

    @staticmethod
    def _imap_zipxxe_close(imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None) -> None:
        if imap is None:
            return
        try:
            imap.logout()
        except Exception:
            try:
                imap.shutdown()
            except Exception:
                pass

    def test_imap_zipxxe(self) -> ZipxxeResult:
        """
        APPEND Zip bomb, Billion Laughs and XXE payloads (PTL-SVC-IMAP-ZIPXXE).

        Method (verified sources):
        - RFC 3501 §6.3.11 / RFC 9051 §6.3.12: APPEND is an authenticated-state
          command; the argument is an RFC 822 message; SELECT is not required.
        - OWASP XXE Prevention Cheat Sheet / WSTG XML Injection: SYSTEM entity
          to a canary (OOB), including OOXML (ZIP+XML) containers.
        - Billion Laughs: nested internal entity expansion DoS (DTD still on).
        - Zip bombs: high-ratio DEFLATE; opt-in only (same as SMTP ZIPXXE).
        APPEND OK means the store accepted the message; XML/ZIP impact is
        processing-side and requires manual CPU / canary verification.
        """
        mb = (getattr(self.args, "zipxxe_mailbox", None) or "INBOX").strip() or "INBOX"
        canary_url = str(getattr(self.args, "zipxxe_canary_url", "") or "").strip()
        timeout = max(5.0, float(getattr(self.args, "zipxxe_timeout", 30.0) or 30.0))
        variants_arg = getattr(self.args, "zipxxe_variants", None)
        incl_zip_bomb = bool(getattr(self.args, "zipxxe_zip_bomb", False))
        incl_zip_bomb_full = bool(getattr(self.args, "zipxxe_zip_bomb_full", False))
        default_variants = [
            "billion_laughs_attach",
            "billion_laughs_body",
            "xxe_zip",
            "xxe_docx",
            "xxe_body",
        ]
        if variants_arg:
            variants = [v.strip().lower() for v in str(variants_arg).split(",") if v.strip()]
        else:
            variants = list(default_variants)
        if incl_zip_bomb and "zip_bomb" not in variants:
            variants.append("zip_bomb")
        if incl_zip_bomb_full and "zip_bomb_full" not in variants:
            variants.append("zip_bomb_full")

        VERIFICATION_INSTRUCTIONS = (
            "Monitor server CPU, memory, disk, IMAP responsiveness. For XXE variants, check canary for HTTP requests. "
            "FAIL if significant slowdown, freeze, restart, or disk exhaustion occurs."
        )
        empty = ZipxxeResult(
            manual_verification_required=True,
            canary_url=canary_url,
            mailbox=mb,
            variants=(),
            elapsed_sec=0.0,
            auth_used=False,
            detail="No variants sent; check connection.",
            verification_instructions=VERIFICATION_INSTRUCTIONS,
            all_rejected_at_append=False,
        )
        pair = self._imap_single_known_login()
        if not pair:
            return empty._replace(detail="Skipped: requires single -u and -p (no wordlists)")
        user, password = pair

        self._imap_zipxxe_streamed_live = False
        self._imap_zipxxe_canary_streamed = False
        if not self.use_json and getattr(self.args, "debug", False) and canary_url:
            ptprint("Canary URL", bullet_type="TITLE", condition=True, indent=4)
            ptprint(canary_url, bullet_type="TEXT", condition=True, indent=8)
            self._imap_zipxxe_canary_streamed = True

        def _reply_snip(data) -> str:
            if not data:
                return ""
            try:
                raw = data[0] if isinstance(data, (list, tuple)) else data
                text = raw.decode(errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
            except Exception:
                text = str(data)
            return self._snip(text, limit=200)

        def _build_mime_with_attachment(
            subject: str,
            body: str,
            attachment_data: bytes,
            filename: str,
            test_id: str,
            content_type: str = "application/octet-stream",
        ) -> bytes:
            msg = MIMEMultipart("mixed")
            msg["Subject"] = subject
            msg["From"] = "ptsrvtester <ptsrvtester@invalid>"
            msg["To"] = "ptsrvtester <ptsrvtester@invalid>"
            msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
            msg["X-Test"] = "IMAP-ZIPXXE"
            msg["X-Test-ID"] = test_id
            msg.attach(MIMEText(body, "plain", "utf-8"))
            part = MIMEBase(*content_type.split("/", 1))
            part.set_payload(attachment_data)
            encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=filename)
            msg.attach(part)
            return msg.as_bytes(policy=email_policy.SMTP)

        def _build_xml_body(subject: str, xml_body: str, test_id: str) -> bytes:
            headers = [
                "From: ptsrvtester <ptsrvtester@invalid>",
                "To: ptsrvtester <ptsrvtester@invalid>",
                f"Subject: {subject}",
                "MIME-Version: 1.0",
                "Content-Type: application/xml; charset=utf-8",
                f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}",
                "X-Test: IMAP-ZIPXXE",
                f"X-Test-ID: {test_id}",
                "",
                xml_body,
            ]
            return "\r\n".join(headers).encode("utf-8")

        start_time = time.perf_counter()
        auth_used = False
        var_results: list[ZipxxeVariantResult] = []
        subject = "IMAP ZIPXXE probe"
        body = "ptsrvtester ZIPXXE content probe"

        for var_name in variants:
            if var_name in ("xxe_zip", "xxe_docx", "xxe_body") and not canary_url:
                continue
            sent, accepted, rejected, err_count = 0, 0, 0, 0
            imap_trace: list[str] = []
            zip_test_id = uuid.uuid4().hex[:12]
            imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
            try:
                if var_name == "billion_laughs_attach":
                    raw_msg = _build_mime_with_attachment(
                        subject, body, BILLION_LAUGHS_XML.encode("utf-8"),
                        "billion_laughs.xml", zip_test_id, "application/xml",
                    )
                elif var_name == "billion_laughs_body":
                    raw_msg = _build_xml_body(subject, BILLION_LAUGHS_XML, zip_test_id)
                elif var_name == "xxe_zip":
                    raw_msg = _build_mime_with_attachment(
                        subject, body, build_zip_with_xxe(canary_url),
                        "report.zip", zip_test_id, "application/zip",
                    )
                elif var_name == "xxe_docx":
                    raw_msg = _build_mime_with_attachment(
                        subject, body, build_minimal_docx_with_xxe(canary_url),
                        "document.docx", zip_test_id,
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    )
                elif var_name == "xxe_body":
                    raw_msg = _build_xml_body(subject, xxe_xml_template(canary_url), zip_test_id)
                elif var_name == "zip_bomb":
                    raw_msg = _build_mime_with_attachment(
                        subject, body, build_minimal_zip_bomb(),
                        "zipbomb.zip", zip_test_id, "application/zip",
                    )
                elif var_name == "zip_bomb_full":
                    raw_msg = _build_mime_with_attachment(
                        subject, body, build_full_zip_bomb(),
                        "zipbomb_full.zip", zip_test_id, "application/zip",
                    )
                else:
                    continue

                try:
                    imap = self.connect()
                except Exception as e:
                    err_count = 1
                    imap_trace.append(f"Connect: {self._snip(str(e), limit=240)}")
                else:
                    try:
                        if getattr(imap, "sock", None) is not None:
                            imap.sock.settimeout(timeout)
                    except Exception:
                        pass
                    try:
                        typ, data = imap.login(user, password)
                        imap_trace.append(f"LOGIN: {typ} ({user})")
                        if typ != "OK":
                            err_count = 1
                            imap_trace.append(f"LOGIN failed: {_reply_snip(data)}")
                        else:
                            auth_used = True
                    except Exception as e:
                        err_count = 1
                        imap_trace.append(f"LOGIN: failed ({self._snip(str(e))})")

                    if err_count == 0:
                        typ, data = imap.append(mb, None, None, raw_msg)
                        sent = 1
                        snip = _reply_snip(data)
                        imap_trace.append(f"APPEND {mb}: {typ}" + (f" {snip}" if snip else ""))
                        if typ == "OK":
                            accepted = 1
                        else:
                            rejected = 1
            except Exception as e:
                err_count = 1
                sent = max(sent, 1)
                imap_trace.append(f"error: {self._snip(str(e))}")
            finally:
                self._imap_zipxxe_close(imap)

            detail = (
                f"{accepted} accepted, {rejected} rejected, {err_count} error"
                if sent or err_count
                else "skipped"
            )
            variant_result = ZipxxeVariantResult(
                variant=var_name,
                sent=max(sent, 1) if (accepted or rejected or err_count) else 0,
                accepted=accepted,
                rejected=rejected,
                error=err_count,
                imap_trace=tuple(imap_trace),
                detail=detail,
                test_id=zip_test_id if accepted else "",
            )
            var_results.append(variant_result)
            if not self.use_json and getattr(self.args, "debug", False):
                self._imap_zipxxe_streamed_live = True
                self._imap_zipxxe_stream_variant_section(variant_result, stream_trace=True)

        elapsed = time.perf_counter() - start_time
        total_accepted = sum(v.accepted for v in var_results)
        total_sent = sum(v.sent for v in var_results)
        all_rejected_at_append = (
            len(var_results) > 0
            and all(v.rejected > 0 and v.error == 0 for v in var_results)
        )
        if total_sent == 0:
            detail = "No variants sent; check connection."
        else:
            detail = f"{total_accepted}/{total_sent} variants with successful APPEND (OK)."
        return ZipxxeResult(
            manual_verification_required=True,
            canary_url=canary_url,
            mailbox=mb,
            variants=tuple(var_results),
            elapsed_sec=elapsed,
            auth_used=auth_used,
            detail=detail,
            verification_instructions=VERIFICATION_INSTRUCTIONS,
            all_rejected_at_append=all_rejected_at_append,
        )

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
            self._dbg("Resource load skipped: requires single -u and -p (no wordlists)")
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
        self._dbg(
            f"Resource load test — mailbox {mb!r}, APPEND max={append_max}, SEARCH max={search_max}"
        )
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
            self._dbg(f"LOGIN {user!r} → OK")
            try:
                imap.select(mb)
                self._dbg(f"SELECT {mb!r} → OK")
            except Exception as e:
                self._dbg(f"SELECT {mb!r} failed: {self._snip(str(e))}")
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
            self._dbg(
                f"APPEND phase: attempted={a_attempted} ok={a_ok} failed={a_fail} "
                f"disconnected={a_disc}"
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
                    self._dbg(
                        f"SEARCH phase: attempted={s_attempted} ok={s_ok} failed={s_fail} "
                        f"disconnected={s_disc}"
                    )
                _live_done()
            else:
                search_skip = "SEARCH phase disabled (--resource-load-search-max 0)"
                self._dbg(search_skip)

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
            sens = ImapEngine._imap_acl_rights_world_sensitive(r_clean)
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
            self._dbg("Mailbox isolation skipped: requires single -u and -p (no wordlists)")
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
            self._dbg(f"LOGIN {login_user!r} → OK")
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
                self._dbg(f"SELECT {own_mb!r} failed: {self._snip(str(e))}")
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

            self._dbg(f"SELECT {own_mb!r} → {typ0}")
            try:
                namespace_typ, ns_dat = imap.namespace()
                if ns_dat and isinstance(ns_dat[0], bytes):
                    nst = ns_dat[0].decode(errors="replace")
                    namespace_raw = nst[:4000] if len(nst) > 4000 else nst
                else:
                    namespace_raw = None
                self._dbg(f"NAMESPACE → {namespace_typ} {self._snip(namespace_raw)}")
            except Exception as e:
                namespace_typ = "EXC"
                namespace_raw = str(e)[:500]
                self._dbg(f"NAMESPACE failed: {self._snip(str(e))}")

            if acl_in_capa:
                try:
                    get_acl_typ, get_acl_dat = imap.getacl(own_mb)
                    anyone_r, anon_r, auth_r, acl_over, get_acl_raw = self._imap_parse_getacl_world(
                        get_acl_typ, get_acl_dat if get_acl_dat is not None else []
                    )
                    self._dbg(f"GETACL {own_mb!r} → {get_acl_typ} {self._snip(get_acl_raw)}")
                except Exception as e:
                    get_acl_typ = "EXC"
                    get_acl_raw = str(e)[:800]
                    self._dbg(f"GETACL {own_mb!r} failed: {self._snip(str(e))}")
            else:
                get_acl_typ = "SKIP"
                get_acl_raw = "ACL not in CAPABILITY — GETACL not attempted"
                self._dbg(get_acl_raw)

            try:
                list_root_typ, list_dat = imap.list('""', "*")
            except Exception as e:
                list_root_typ = "EXC"
                list_dat = []
                list_root_sample = [f"(list error: {e})"][:3]
                self._dbg(f"LIST \"\" * failed: {self._snip(str(e))}")

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
            self._dbg(f"LIST \"\" * → {list_root_typ} count={list_root_count}")
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
            dict_total_dbg = sum(r.listed_count for r in dict_rows)
            dict_nz = sum(1 for r in dict_rows if r.listed_count)
            self._dbg(
                f"LIST dictionary: {len(dict_rows)} patterns, "
                f"{dict_nz} nonzero, total listed={dict_total_dbg}"
            )

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
                self._dbg(f"EXAMINE {mbx!r} → {typ} {self._snip(detail)}")
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
            row = ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw=None,
                reply_normalized=None,
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=False,
                error=str(e),
                probe_index=probe_index,
            )
            self._dbg_usrenum_row("LOGIN", row)
            return row
        try:
            try:
                imap.capability()
            except Exception:
                pass
            imap.login(username, wrong_password)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            row = ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw="OK",
                reply_normalized="login_unexpected_ok",
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=True,
                error=None,
                probe_index=probe_index,
            )
            self._dbg_usrenum_row("LOGIN", row)
            return row
        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            raw = _imap_login_exception_text(e)
            norm = _normalize_imap_login_error_for_enum(raw)
            row = ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw=raw,
                reply_normalized=norm or None,
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=False,
                error=None,
                probe_index=probe_index,
            )
            self._dbg_usrenum_row("LOGIN", row)
            return row
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
            row = ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw=None,
                reply_normalized=None,
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=False,
                error=str(e),
                probe_index=probe_index,
            )
            self._dbg_usrenum_row("PLAIN", row)
            return row
        try:
            try:
                imap.capability()
            except Exception:
                pass
            imap.authenticate("PLAIN", _auth_cb)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            row = ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw="OK",
                reply_normalized="plain_unexpected_ok",
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=True,
                error=None,
                probe_index=probe_index,
            )
            self._dbg_usrenum_row("PLAIN", row)
            return row
        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            raw = _imap_login_exception_text(e)
            norm = _normalize_imap_login_error_for_enum(raw)
            row = ImapUserEnumProbeRow(
                username=username,
                probe_kind=probe_kind,
                reply_raw=raw,
                reply_normalized=norm or None,
                elapsed_ms=round(elapsed_ms, 2),
                unexpected_ok=False,
                error=None,
                probe_index=probe_index,
            )
            self._dbg_usrenum_row("PLAIN", row)
            return row
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
        self._dbg(
            f"USR-ENUM {enumeration_method}: enumerated={enumerated!r} "
            f"vulnerable={vulnerable} indeterminate={indeterminate}"
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
        names = self._imap_usrenum_names_from_cli()
        if not names:
            return self._analyze_imap_usrenum(
                [],
                enumeration_method="LOGIN",
                login_disabled_advertised=False,
                auth_plain_advertised=False,
            )
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
            self._dbg(f"USR-ENUM: LOGINDISABLED advertised={login_disabled_advertised}")
        except Exception as e:
            self._dbg(f"USR-ENUM: capability check failed: {self._snip(str(e))}")
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
        self._dbg(f"USR-ENUM: LOGIN — synthetic baseline: {invalid_users!r}")
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
        names = self._imap_usrenum_names_from_cli()
        if not names:
            return self._analyze_imap_usrenum(
                [],
                enumeration_method="AUTHENTICATE PLAIN",
                login_disabled_advertised=False,
                auth_plain_advertised=False,
            )
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
            self._dbg(f"USR-ENUM: AUTH=PLAIN advertised={auth_plain_advertised}")
        except Exception as e:
            self._dbg(f"USR-ENUM PLAIN: capability check failed: {self._snip(str(e))}")
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
        self._dbg(f"USR-ENUM: PLAIN (RFC 4616) — synthetic baseline: {invalid_users!r}")
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
            self._dbg(f"AUTH=NTLM advertised={auth_ntlm_advertised}")
            tag = imap._new_tag().decode()
            imap.send(f"{tag} AUTHENTICATE NTLM\r\n".encode())
            res = imap.readline().strip()
            self._dbg(f"AUTHENTICATE NTLM → {self._snip(res)}")
            if res.startswith(b"+"):
                imap.send(b64encode(get_NegotiateMessage_data()) + b"\r\n")
                res = imap.readline().strip()
                self._dbg(f"AUTHENTICATE NTLM after negotiate → {self._snip(res)}")
                # Challenge line may contain '+' inside Base64 — preserve octets after first '+'
                b64_ntlm_challenge = b"+".join(res.split(b"+")[1:])
                ntlminfo = decode_ChallengeMessage_blob(b64decode(b64_ntlm_challenge))
                self._dbg("NTLM challenge decoded OK")
                if ntlminfo is not None:
                    self._dbg(f"Target name: {ntlminfo.target_name}")
                    self._dbg(f"NetBios domain name: {ntlminfo.netbios_domain}")
                    self._dbg(f"NetBios computer name: {ntlminfo.netbios_computer}")
                    self._dbg(f"DNS domain name: {ntlminfo.dns_domain}")
                    self._dbg(f"DNS computer name: {ntlminfo.dns_computer}")
                    self._dbg(f"DNS tree: {ntlminfo.dns_tree}")
                    self._dbg(f"OS version: {ntlminfo.os_version}")
                return NTLMResult(True, ntlminfo, auth_ntlm_advertised)
            self._dbg("AUTHENTICATE NTLM: server did not return challenge (+)")
            return NTLMResult(False, None, auth_ntlm_advertised)
        except Exception as e:
            self._dbg(f"AUTHENTICATE NTLM failed: {self._snip(str(e))}")
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
        except OSError as e:
            self._dbg(f"Login {creds.user!r}: connect failed: {e}")
            return None
        try:
            self._dbg(f"LOGIN {creds.user!r}")
            imap.login(creds.user, creds.passw)
            self._dbg(f"LOGIN → OK (valid: {creds.user!r})")
            result = creds
        except Exception as e:
            self._dbg(f"LOGIN → failed for {creds.user!r}: {self._snip(str(e))}")
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

    def _imap_connection_encrypted(self) -> bool:
        return bool(self.args.target.port == 993 or self.args.tls)

    def _emit_capa_section(self, title: str, capa: list[str], encrypted: bool) -> None:
        pp = self._ptprint_raw
        show = not self.use_json
        self._ptprint(title, Out.INFO)
        for display_str, level in _parse_capability_commands(capa, encrypted):
            pp(display_str, bullet_type=_capa_level_bullet(level), condition=show, indent=4)

    def _stream_capa_id_and_plain(self) -> None:
        """Stream ID + pre-upgrade (or implicit TLS) CAPABILITY. Call before STARTTLS probe."""
        if not (info := self.results.info):
            return
        capa = info.capability
        if not capa and not info.id:
            return
        with self._output_lock:
            show = not self.use_json
            if info.id is not None:
                self._ptprint("ID command", Out.INFO)
                self._ptprint_raw(info.id, bullet_type="TEXT", condition=show, indent=4)
            if capa:
                encrypted = self._imap_connection_encrypted()
                title = "CAPABILITY command (TLS)" if encrypted else "CAPABILITY command (PLAIN)"
                self._emit_capa_section(title, capa, encrypted)

    def _stream_capa_starttls(self) -> None:
        """Stream post-STARTTLS CAPABILITY section."""
        if not (info := self.results.info):
            return
        capa_stls = getattr(info, "capability_starttls", None)
        if not capa_stls:
            return
        with self._output_lock:
            self._emit_capa_section("CAPABILITY command (STARTTLS)", capa_stls, True)

    def _stream_capa_result(self) -> None:
        """Stream all CAPABILITY sections (used when STARTTLS was already fetched)."""
        self._stream_capa_id_and_plain()
        self._stream_capa_starttls()

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
                pp("Cleartext only", bullet_type="VULN", condition=show, indent=4)
            elif any_ok:
                if enc.plaintext_ok:
                    bullet = "WARNING" if (enc.starttls_ok or enc.tls_ok) else "NOTVULN"
                    pp("Cleartext", bullet_type=bullet, condition=show, indent=4)
                if enc.starttls_ok:
                    pp("STARTTLS", bullet_type="NOTVULN", condition=show, indent=4)
                if enc.tls_ok:
                    pp("TLS", bullet_type="NOTVULN", condition=show, indent=4)
            else:
                pp(
                    "No connection mode available (cleartext, STARTTLS, TLS failed)",
                    bullet_type="VULN",
                    condition=show,
                    indent=4,
                )

    @staticmethod
    def _authlist_path_label(path: str) -> str:
        return {"cleartext": "Cleartext", "starttls": "STARTTLS", "tls": "TLS"}.get(path, path)

    @staticmethod
    def _authlist_row_display(path: str, row: ImapAuthMechRow) -> tuple[str, str]:
        encrypted = path in ("starttls", "tls")
        if row.usable:
            if row.dangerous and not encrypted:
                return ("VULN", f"{row.name} (is advertised and can be used)")
            return ("NOTVULN", row.name)
        return ("WARNING", f"{row.name} (is advertised but cannot be used)")

    def _stream_imap_authlist_result(self) -> None:
        """Replay AUTHLIST if it was not streamed live (JSON / error path)."""
        if getattr(self, "_authlist_terminal_emitted", False):
            return
        pp = self._ptprint_raw
        show = not self.use_json
        with self._output_lock:
            if (err := getattr(self.results, "imap_authlist_error", None)) is not None:
                pp(f"AUTHLIST failed: {err}", bullet_type="VULN", condition=show, indent=4)
                return
            al = getattr(self.results, "imap_authlist", None)
            if al is None:
                return
            for p in al.paths:
                label = self._authlist_path_label(p.path)
                pp(label, bullet_type="TITLE", condition=show, indent=4)
                if not p.available or not p.methods:
                    pp("Not available", bullet_type="NOTVULN", condition=show, indent=8)
                    continue
                for row in p.methods:
                    bullet, text = self._authlist_row_display(p.path, row)
                    pp(text, bullet_type=bullet, condition=show, indent=8)

    def _stream_sniffable_result(self) -> None:
        """Stream cleartext LOGIN + SELECT INBOX (thread-safe)."""
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
            if sn.vulnerable:
                pp(sn.detail, bullet_type="VULN", condition=show, indent=4)
                return
            if sn.detail == "LOGIN failed":
                pp("LOGIN failed", bullet_type="WARNING", condition=show, indent=4)
                return
            pp("Not sniffable", bullet_type="NOTVULN", condition=show, indent=4)

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
                "Verdict: anonymous or weak default access",
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
                f"(server: {er.append_typ})",
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

    def _stream_imap_zipxxe_result(self) -> None:
        """Stream ZIPXXE result (SMTP ZIPXXE layout: variants then Summary)."""
        if self.use_json:
            return
        pp = ptprint
        if (err := self.results.zipxxe_error) is not None:
            pp(f"ZIPXXE test failed: {err}", bullet_type="VULN", condition=True, indent=4)
            return
        zr = self.results.zipxxe
        if zr is None:
            return
        if zr.canary_url and not getattr(self, "_imap_zipxxe_canary_streamed", False):
            pp("Canary URL", bullet_type="TITLE", condition=True, indent=4)
            pp(zr.canary_url, bullet_type="TEXT", condition=True, indent=8)
        if not (getattr(self.args, "debug", False) and getattr(self, "_imap_zipxxe_streamed_live", False)):
            for v in zr.variants:
                self._imap_zipxxe_stream_variant_section(v, stream_trace=False)
        extra: list[str] = []
        if zr.all_rejected_at_append:
            extra.append(
                "All variants rejected at APPEND — content-level processing could not be assessed.",
            )
        if any(v.accepted > 0 for v in zr.variants):
            extra.extend(
                p.strip()
                for p in (zr.verification_instructions or "").split("\n")
                if p.strip()
            )
        pp("Summary", bullet_type="TITLE", condition=True, indent=4)
        if zr.detail:
            pp(zr.detail, bullet_type="TEXT", condition=True, indent=8)
        for line in extra:
            pp(line, bullet_type="TEXT", condition=True, indent=8)
        pp(f"Elapsed: {zr.elapsed_sec:.1f} s", bullet_type="TEXT", condition=True, indent=8)

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

        def field(level: str, text: str, indent: int = 8) -> None:
            pp(text, bullet_type=tls_audit.rating_to_bullet(level), condition=show, indent=indent)

        p = tr.probes[0] if tr.probes else None
        if tr.implicit_tls_intended:
            target_line = f"Target: {tr.host}:{tr.port}"
        else:
            target_line = f"Target: '{tr.host}:{tr.port}' (implicit TLS: not configured)"
        pp(target_line, bullet_type="TITLE", condition=show, indent=4)
        if p is None:
            pp("TLS audit produced no probe result", bullet_type="VULN", condition=show, indent=4)
            return
        pp(f"Connection mode: {p.connection_mode}", bullet_type="TITLE", condition=show, indent=4)

        if p.versions:
            pp("TLS Versions:", bullet_type="TITLE", condition=show, indent=4)
            for v in p.versions:
                order = ""
                if v.version == "TLS 1.3":
                    order = "  order: not configured"
                elif v.cipher_order:
                    order = f"  order: {v.cipher_order}"
                    if v.cipher_order_note:
                        order += f" -- {v.cipher_order_note}"
                field(v.rating, f"{v.version}{order}", indent=8)
                for c in v.ciphers:
                    field(c.rating, c.name, indent=12)
        elif p.handshake_ok and (p.tls_version or p.cipher_name):
            pp("TLS Versions:", bullet_type="TITLE", condition=show, indent=4)
            label = tls_audit.normalize_tls_label(p.tls_version) or (p.tls_version or "unknown")
            vr, _ = tls_audit.rate_tls_version(label)
            field(vr, label, indent=8)
            if p.cipher_name:
                cr, _ = tls_audit.rate_cipher(p.cipher_name, label)
                field(cr, p.cipher_name, indent=12)
        elif not p.attempted and p.skipped_reason:
            pp("TLS Versions:", bullet_type="TITLE", condition=show, indent=4)
            pp(p.skipped_reason, bullet_type="WARNING", condition=show, indent=8)

        pp("Certificate Information:", bullet_type="TITLE", condition=show, indent=4)
        if p.handshake_ok and (p.peer_subject or p.peer_issuer or p.san_dns or p.not_after):
            subj = p.peer_subject or "(none)"
            subj_note = "" if p.identity_ok else "  (hostname does not match)"
            subj_level = "ok" if p.identity_ok else "bad"
            field(subj_level, f"Subject:  {subj}{subj_note}")
            issuer_level = "ok" if p.cert_trust_ok else "bad"
            issuer_note = "" if p.cert_trust_ok else "  (chain not trusted)"
            field(issuer_level, f"Issuer:   {p.peer_issuer or '(none)'}{issuer_note}")
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
            val_level, _ = tls_audit.rate_validity(
                expired=p.cert_expired,
                not_yet_valid=p.cert_not_yet_valid,
                days_left=p.days_until_expiry,
                vuln_days=_IMAP_TLS_EXPIRY_VULN_DAYS,
                warn_days=_IMAP_TLS_EXPIRY_WARN_DAYS,
            )
            field(val_level, f"Validity: {nb_d} to {na_d} {days_s}".rstrip())
            if p.san_dns:
                first, *rest = p.san_dns
                san_label = "SAN: "
                pp(f"{san_label}{first}", bullet_type="TITLE", condition=show, indent=8)
                # TITLE bullet is "[*] " (4 chars); TEXT has none — pad so DNS: lines up.
                pad = " " * (4 + len(san_label))
                for extra in rest:
                    pp(f"{pad}{extra}", bullet_type="TEXT", condition=show, indent=8)
            rsa_bits = tls_audit.parse_rsa_bits(p.peer_key_summary)
            if rsa_bits is not None:
                klev, _ = tls_audit.rate_rsa_key(rsa_bits)
                field(klev, f"Key: {p.peer_key_summary}")
            elif p.peer_key_summary:
                field("ok", f"Key: {p.peer_key_summary}")
            if p.peer_signature_hash:
                hlev, _ = tls_audit.rate_sig_hash(p.peer_signature_hash)
                field(hlev, f"Hash: {p.peer_signature_hash}")
        elif p.attempted and not p.handshake_ok:
            pp(
                "(Leaf certificate details unavailable — TLS handshake did not complete)",
                bullet_type="TEXT",
                condition=show,
                indent=8,
            )
        else:
            pp(
                f"(Not evaluated: {p.skipped_reason or 'n/a'})",
                bullet_type="TEXT",
                condition=show,
                indent=8,
            )

    def _stream_imap_tls_audit_result(self) -> None:
        """Stream IMAP TLS audit result (thread-safe)."""
        if (err := getattr(self.results, "imap_tls_audit_error", None)) is not None:
            with self._output_lock:
                pp = self._ptprint_raw
                show = not self.use_json
                implicit = bool(self.args.tls or int(self.args.target.port) == 993)
                host = self.args.target.ip
                port = int(self.args.target.port)
                if implicit:
                    target_line = f"Target: {host}:{port}"
                else:
                    target_line = f"Target: '{host}:{port}' (implicit TLS: not configured)"
                pp(target_line, bullet_type="TITLE", condition=show, indent=4)
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
            if not (ntlm.success and ntlm.ntlm is not None):
                pp("Not available", bullet_type="NOTVULN", condition=show, indent=4)
                return
            if ntlm.auth_ntlm_advertised:
                pp("Pre-login CAPABILITY lists AUTH=NTLM", bullet_type="WARNING", condition=show, indent=4)
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
                def _capa_to_lines(cl: list[str], encrypted: bool) -> list[str]:
                    return [d for d, _ in _parse_capability_commands(cl, encrypted)]
                if capa_stls is not None:
                    json_lines = _capa_to_lines(capa, False) + ["---"] + _capa_to_lines(capa_stls, True)
                else:
                    json_lines = _capa_to_lines(capa, self._imap_connection_encrypted())
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
        # AUTHLIST (PTV-SVC-IMAP-AUTHMETHODS)
        if (al_err := getattr(self.results, "imap_authlist_error", None)) is not None:
            properties.update({"authListError": al_err})
        elif (al := getattr(self.results, "imap_authlist", None)) is not None:
            path_json = []
            auth_lines: list[str] = []
            for p in al.paths:
                label = self._authlist_path_label(p.path)
                path_json.append(
                    {
                        "path": p.path,
                        "available": p.available,
                        "skipReason": p.skip_reason,
                        "methods": [
                            {
                                "name": m.name,
                                "usable": m.usable,
                                "outcome": m.outcome,
                                "dangerous": m.dangerous,
                            }
                            for m in p.methods
                        ],
                    }
                )
                if not p.available or not p.methods:
                    auth_lines.append(f"{label}: Not available")
                    continue
                for m in p.methods:
                    _, text = self._authlist_row_display(p.path, m)
                    auth_lines.append(f"{label}: {text}")
            properties.update(
                {
                    "authList": {
                        "vulnerable": al.vulnerable,
                        "detail": al.detail,
                        "paths": path_json,
                    }
                }
            )
            if al.vulnerable:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.AuthMethods.value,
                        "vuln_request": "CAPABILITY AUTH= + AUTHENTICATE probe (cleartext / STARTTLS / TLS)",
                        "vuln_response": "\n".join(auth_lines) or al.detail,
                    }
                )
        # Cleartext LOGIN + SELECT INBOX (PTV-SVC-SNIFFABLE)
        if (sniff_err := getattr(self.results, "sniffable_error", None)) is not None:
            properties.update({"sniffableError": sniff_err})
        elif (sn := self.results.sniffable) is not None:
            properties.update(
                {
                    "sniffableProbe": {
                        "skipped": sn.skipped,
                        "skipReason": sn.skip_reason,
                        "loginOk": sn.login_ok,
                        "selectOk": sn.select_ok,
                        "selectTyp": sn.select_typ,
                        "selectDetail": sn.select_detail,
                        "vulnerable": sn.vulnerable,
                        "detail": sn.detail,
                    }
                }
            )
            if sn.vulnerable and not sn.skipped:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.Sniffable.value,
                        "vuln_request": "LOGIN + SELECT INBOX on cleartext IMAP",
                        "vuln_response": sn.detail,
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
        # ZIPXXE APPEND (PTL-SVC-IMAP-ZIPXXE) — manual verification, no auto vuln
        if (zipxxe_err := getattr(self.results, "zipxxe_error", None)) is not None:
            properties.update({"zipxxeError": zipxxe_err})
        elif (zr := getattr(self.results, "zipxxe", None)) is not None:
            properties.update({
                "zipxxe": {
                    "manualVerificationRequired": zr.manual_verification_required,
                    "canaryUrl": zr.canary_url or None,
                    "mailbox": zr.mailbox,
                    "elapsedSec": round(zr.elapsed_sec, 2),
                    "authUsed": zr.auth_used,
                    "detail": zr.detail,
                    "allRejectedAtAppend": zr.all_rejected_at_append,
                    "verificationInstructions": zr.verification_instructions,
                    "variants": [
                        {
                            "variant": v.variant,
                            "sent": v.sent,
                            "accepted": v.accepted,
                            "rejected": v.rejected,
                            "error": v.error,
                            "imapTrace": list(v.imap_trace),
                            "detail": v.detail,
                            "testId": v.test_id or None,
                        }
                        for v in zr.variants
                    ],
                }
            })
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
                        "certTrustOk": p.cert_trust_ok,
                        "identityOk": p.identity_ok,
                        "identityDetail": p.identity_detail,
                        "identityWildcard": p.identity_wildcard,
                        "connectionMode": p.connection_mode,
                        "imapTrace": list(p.imap_trace),
                        "versions": [
                            {
                                "version": v.version,
                                "offered": v.offered,
                                "rating": v.rating,
                                "ratingReason": v.rating_reason,
                                "cipherOrder": v.cipher_order,
                                "cipherOrderNote": v.cipher_order_note,
                                "ciphers": [
                                    {
                                        "name": c.name,
                                        "rating": c.rating,
                                        "reason": c.reason,
                                    }
                                    for c in v.ciphers
                                ],
                            }
                            for v in p.versions
                        ],
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

    # region NOOP Connection Limit Tests

    @staticmethod
    def _imap_noop_safe(imap: imaplib.IMAP4 | imaplib.IMAP4_SSL, tag: str) -> tuple[bool, str | None]:
        """Send NOOP and return (success, error_msg)."""
        try:
            typ, data = imap.noop()
            return (typ == "OK", None)
        except Exception as e:
            return (False, ImapEngine._unwrap_imaplib_error(str(e)))

    def test_noop_duration_preauth(self) -> NoopDurationResult:
        """NOOP1: Keep a pre-auth connection alive with periodic NOOP."""
        self.debug("NOOP duration test (pre-auth): connecting...")
        
        try:
            imap = self._make_imap_connection(trace=False)
            imap.sock.settimeout(IMAP_NOOP_PREAUTH_DUR_TIMEOUT_SECONDS)
        except Exception as e:
            return NoopDurationResult(
                authenticated=False,
                test_duration_seconds=IMAP_NOOP_PREAUTH_DUR_TEST_SECONDS,
                maintained_seconds=0.0,
                noops_sent=0,
                noops_ok=0,
                noops_error=0,
                disconnected=True,
                disconnect_after_seconds=None,
                hit_test_cap=False,
                error_message=f"Connection failed: {e}",
            )
        
        start_time = time.perf_counter()
        noops_sent = 0
        noops_ok = 0
        noops_error = 0
        disconnected = False
        disconnect_after_seconds = None
        hit_test_cap = False
        tag_counter = 0
        
        # Live progress setup
        show_progress = not self.use_json
        live_line_dirty = False
        
        def write_live(text: str):
            nonlocal live_line_dirty
            if not show_progress:
                return
            sys.stdout.write(f"\033[2K\r            {text:<100}")
            sys.stdout.flush()
            live_line_dirty = True
        
        def clear_live():
            nonlocal live_line_dirty
            if not show_progress or not live_line_dirty:
                return
            sys.stdout.write("\033[2K\r")
            sys.stdout.flush()
            live_line_dirty = False
        
        # Initial progress message
        if show_progress:
            write_live(f"Test started, sending first NOOP...")
        
        try:
            while True:
                elapsed = time.perf_counter() - start_time
                if elapsed >= IMAP_NOOP_PREAUTH_DUR_TEST_SECONDS:
                    hit_test_cap = True
                    break
                
                # Send NOOP
                tag_counter += 1
                noops_sent += 1
                tag = f"a{tag_counter:04d}"
                success, error = self._imap_noop_safe(imap, tag)
                if success:
                    noops_ok += 1
                    # Live progress every NOOP
                    if show_progress:
                        elapsed_min = int(elapsed / 60)
                        elapsed_sec = int(elapsed % 60)
                        write_live(f"NOOPs sent: {noops_sent} ({elapsed_min}m {elapsed_sec}s elapsed)")
                    if noops_sent % 5 == 0:
                        self.debug(f"NOOP #{noops_sent}: OK (elapsed: {int(elapsed)}s)")
                else:
                    noops_error += 1
                    disconnected = True
                    disconnect_after_seconds = elapsed
                    self.debug(f"NOOP #{noops_sent}: failed — {error}")
                    break
                
                # Wait for the next NOOP interval
                time.sleep(IMAP_NOOP_PREAUTH_DUR_INTERVAL_SECONDS)
        finally:
            clear_live()
            try:
                imap.logout()
            except Exception:
                pass
        
        maintained_seconds = time.perf_counter() - start_time
        
        return NoopDurationResult(
            authenticated=False,
            test_duration_seconds=IMAP_NOOP_PREAUTH_DUR_TEST_SECONDS,
            maintained_seconds=maintained_seconds,
            noops_sent=noops_sent,
            noops_ok=noops_ok,
            noops_error=noops_error,
            disconnected=disconnected,
            disconnect_after_seconds=disconnect_after_seconds,
            hit_test_cap=hit_test_cap,
            error_message=None,
        )

    def test_noop_duration_postauth(self, username: str, password: str) -> NoopDurationResult:
        """NOOP1: Keep a post-auth connection alive with periodic NOOP."""
        self.debug(f"NOOP duration test (post-auth): connecting and logging in as {username!r}...")
        
        try:
            imap = self._make_imap_connection(trace=False)
            imap.sock.settimeout(IMAP_NOOP_POSTAUTH_DUR_TIMEOUT_SECONDS)
            imap.login(username, password)
        except Exception as e:
            return NoopDurationResult(
                authenticated=True,
                test_duration_seconds=IMAP_NOOP_POSTAUTH_DUR_TEST_SECONDS,
                maintained_seconds=0.0,
                noops_sent=0,
                noops_ok=0,
                noops_error=0,
                disconnected=True,
                disconnect_after_seconds=None,
                hit_test_cap=False,
                error_message=f"Connection/login failed: {e}",
            )
        
        start_time = time.perf_counter()
        noops_sent = 0
        noops_ok = 0
        noops_error = 0
        disconnected = False
        disconnect_after_seconds = None
        hit_test_cap = False
        tag_counter = 0
        
        # Live progress setup
        show_progress = not self.use_json
        live_line_dirty = False
        
        def write_live(text: str):
            nonlocal live_line_dirty
            if not show_progress:
                return
            sys.stdout.write(f"\033[2K\r            {text:<100}")
            sys.stdout.flush()
            live_line_dirty = True
        
        def clear_live():
            nonlocal live_line_dirty
            if not show_progress or not live_line_dirty:
                return
            sys.stdout.write("\033[2K\r")
            sys.stdout.flush()
            live_line_dirty = False
        
        # Initial progress message
        if show_progress:
            write_live(f"Test started, sending first NOOP...")
        
        try:
            while True:
                elapsed = time.perf_counter() - start_time
                if elapsed >= IMAP_NOOP_POSTAUTH_DUR_TEST_SECONDS:
                    hit_test_cap = True
                    break
                
                tag_counter += 1
                noops_sent += 1
                tag = f"a{tag_counter:04d}"
                success, error = self._imap_noop_safe(imap, tag)
                if success:
                    noops_ok += 1
                    # Live progress every NOOP
                    if show_progress:
                        elapsed_min = int(elapsed / 60)
                        elapsed_sec = int(elapsed % 60)
                        write_live(f"NOOPs sent: {noops_sent} ({elapsed_min}m {elapsed_sec}s elapsed)")
                    if noops_sent % 5 == 0:
                        self.debug(f"NOOP #{noops_sent}: OK (elapsed: {int(elapsed)}s)")
                else:
                    noops_error += 1
                    disconnected = True
                    disconnect_after_seconds = elapsed
                    self.debug(f"NOOP #{noops_sent}: failed — {error}")
                    break
                
                time.sleep(IMAP_NOOP_POSTAUTH_DUR_INTERVAL_SECONDS)
        finally:
            clear_live()
            try:
                imap.logout()
            except Exception:
                pass
        
        maintained_seconds = time.perf_counter() - start_time
        
        return NoopDurationResult(
            authenticated=True,
            test_duration_seconds=IMAP_NOOP_POSTAUTH_DUR_TEST_SECONDS,
            maintained_seconds=maintained_seconds,
            noops_sent=noops_sent,
            noops_ok=noops_ok,
            noops_error=noops_error,
            disconnected=disconnected,
            disconnect_after_seconds=disconnect_after_seconds,
            hit_test_cap=hit_test_cap,
            error_message=None,
        )

    def _noop2_ramp_threads(self) -> int:
        return max(1, int(getattr(self.args, "noop2_threads", None) or 1))

    @staticmethod
    def _unwrap_imaplib_error(text: str) -> str:
        """imaplib formats abort/error as ``command: NAME => detail`` — keep only the detail."""
        marker = " => "
        if text.startswith("command:") and marker in text:
            return text.split(marker, 1)[1].strip()
        return text

    @staticmethod
    def _noop2_classify_conn_failure(exc: BaseException) -> tuple[str, str]:
        """Return ``(reason, detail)`` for -vv, matching SMTP NOOP2 wording."""
        detail = ImapEngine._unwrap_imaplib_error(str(exc).strip() or type(exc).__name__)
        if isinstance(exc, (socket.timeout, TimeoutError)):
            return "timeout", detail
        if isinstance(exc, (
            ConnectionRefusedError,
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
            imaplib.IMAP4.abort,
        )):
            return "disconnect", detail
        msg = detail.lower()
        if "timed out" in msg or "timeout" in msg:
            return "timeout", detail
        if any(k in msg for k in ("refused", "reset", "disconnect", "closed", "broken pipe", "aborted", " bye")):
            return "disconnect", detail
        return "error", detail

    def _noop2_establish_pool(self, max_connections: int, opener, *, write_live, show_progress, clear_live=None):
        """Open connections sequentially or with ``-t`` worker threads.

        Every requested slot is attempted (SMTP NOOP2 behaviour). Failures are
        logged at -vv with classified reason and the server/socket text.
        """
        connections: list = []
        fail_count = 0
        ramp_threads = min(self._noop2_ramp_threads(), max_connections)
        lock = threading.Lock()
        next_index = 0

        def progress_text() -> str:
            extra = f" ({fail_count} failed)" if fail_count else ""
            return f"Establishing connections: {len(connections)}/{max_connections}{extra}"

        def emit_fail(idx: int, exc: BaseException) -> None:
            nonlocal fail_count
            fail_count += 1
            reason, detail = self._noop2_classify_conn_failure(exc)
            if clear_live:
                clear_live()
            self.debug(f"Connection #{idx + 1} failed — {reason} ({detail})")
            if show_progress:
                write_live(progress_text())

        def record(conn, idx: int) -> None:
            connections.append((conn, idx))
            if show_progress:
                write_live(progress_text())

        def try_one(idx: int) -> None:
            try:
                conn = opener(idx)
            except Exception as e:
                with lock:
                    emit_fail(idx, e)
                return
            with lock:
                record(conn, idx)

        if ramp_threads <= 1:
            for i in range(max_connections):
                try_one(i)
            return connections

        def worker() -> None:
            nonlocal next_index
            while True:
                with lock:
                    if next_index >= max_connections:
                        return
                    idx = next_index
                    next_index += 1
                try_one(idx)

        workers = [
            threading.Thread(target=worker, daemon=True)
            for _ in range(ramp_threads)
        ]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        return connections

    def test_noop_conn_count_preauth(self) -> NoopConnectionCountResult:
        """NOOP2: How many pre-auth connections can be maintained with NOOP."""
        max_connections = getattr(self.args, 'noop2_connections', None) or NOOP2_DEFAULT_CONNECTIONS
        
        ramp_threads = self._noop2_ramp_threads()
        self.debug(
            f"NOOP connection count test (pre-auth): attempting up to {max_connections} connections"
            + (f" ({ramp_threads} threads)..." if ramp_threads > 1 else "...")
        )
        
        lock = threading.Lock()
        total_noops_sent = 0
        total_noops_ok = 0
        total_noops_error = 0
        early_disconnect_count = 0
        
        # Live progress setup
        show_progress = not self.use_json
        live_line_dirty = False
        
        def write_live(text: str):
            nonlocal live_line_dirty
            if not show_progress:
                return
            sys.stdout.write(f"\033[2K\r            {text:<100}")
            sys.stdout.flush()
            live_line_dirty = True
        
        def clear_live():
            nonlocal live_line_dirty
            if not show_progress or not live_line_dirty:
                return
            sys.stdout.write("\033[2K\r")
            sys.stdout.flush()
            live_line_dirty = False

        def opener(_idx: int):
            imap = self._make_imap_connection(trace=False)
            imap.sock.settimeout(IMAP_NOOP_PREAUTH_CONN_TIMEOUT_SECONDS)
            return imap

        connections = self._noop2_establish_pool(
            max_connections, opener, write_live=write_live, show_progress=show_progress,
            clear_live=clear_live,
        )
        established = len(connections)
        
        clear_live()
        self.debug(
            f"Phase 1 complete: {established}/{max_connections} connections established. "
            f"Holding for {IMAP_NOOP_PREAUTH_CONN_TEST_SECONDS}s with NOOP..."
        )
        
        # Phase 2: Hold connections with periodic NOOP
        start_time = time.perf_counter()
        stop_event = threading.Event()
        
        def noop_worker(imap, idx):
            nonlocal total_noops_sent, total_noops_ok, total_noops_error, early_disconnect_count
            tag_counter = 0
            while not stop_event.is_set():
                time.sleep(IMAP_NOOP_PREAUTH_CONN_INTERVAL_SECONDS)
                if stop_event.is_set():
                    break
                with lock:
                    total_noops_sent += 1
                tag_counter += 1
                tag = f"b{idx:04d}{tag_counter:04d}"
                success, error = self._imap_noop_safe(imap, tag)
                with lock:
                    if success:
                        total_noops_ok += 1
                    else:
                        total_noops_error += 1
                        early_disconnect_count += 1
                        break
        
        threads = []
        for imap, idx in connections:
            t = threading.Thread(target=noop_worker, args=(imap, idx), daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for test duration with live progress
        end_time = time.perf_counter() + IMAP_NOOP_PREAUTH_CONN_TEST_SECONDS
        while time.perf_counter() < end_time:
            time.sleep(1.0)
            if show_progress:
                active = established - early_disconnect_count
                remaining = int(end_time - time.perf_counter())
                write_live(f"Maintaining connections: {active}/{established} active, {remaining}s remaining, {total_noops_ok} NOOPs sent")
        
        stop_event.set()
        clear_live()
        
        # Wait for all threads to finish
        for t in threads:
            t.join(timeout=2.0)
        
        # Close all connections
        for imap, _ in connections:
            try:
                imap.logout()
            except Exception:
                pass
        
        maintained = established - early_disconnect_count
        test_duration = time.perf_counter() - start_time
        
        self.debug(f"Phase 2 complete: {maintained}/{established} connections maintained, {total_noops_ok} NOOPs OK")
        
        return NoopConnectionCountResult(
            authenticated=False,
            max_connections_attempted=max_connections,
            connections_established=established,
            connections_maintained=maintained,
            test_duration_seconds=test_duration,
            total_noops_sent=total_noops_sent,
            total_noops_ok=total_noops_ok,
            total_noops_error=total_noops_error,
            early_disconnect_count=early_disconnect_count,
            error_message=None,
        )

    def test_noop_conn_count_postauth(self, username: str, password: str) -> NoopConnectionCountResult:
        """NOOP2: How many post-auth connections can be maintained with NOOP."""
        # Use 4x the pre-auth default for post-auth (600 if pre-auth is 150)
        default_postauth = (getattr(self.args, 'noop2_connections', None) or NOOP2_DEFAULT_CONNECTIONS) * 4
        max_connections = min(default_postauth, IMAP_NOOP_POSTAUTH_CONN_MAX_ATTEMPTS)
        
        ramp_threads = self._noop2_ramp_threads()
        self.debug(
            f"NOOP connection count test (post-auth): attempting up to {max_connections} connections"
            + (f" ({ramp_threads} threads)..." if ramp_threads > 1 else "...")
        )
        
        lock = threading.Lock()
        total_noops_sent = 0
        total_noops_ok = 0
        total_noops_error = 0
        early_disconnect_count = 0
        
        # Live progress setup
        show_progress = not self.use_json
        live_line_dirty = False
        
        def write_live(text: str):
            nonlocal live_line_dirty
            if not show_progress:
                return
            sys.stdout.write(f"\033[2K\r            {text:<100}")
            sys.stdout.flush()
            live_line_dirty = True
        
        def clear_live():
            nonlocal live_line_dirty
            if not show_progress or not live_line_dirty:
                return
            sys.stdout.write("\033[2K\r")
            sys.stdout.flush()
            live_line_dirty = False

        def opener(_idx: int):
            imap = self._make_imap_connection(trace=False)
            imap.sock.settimeout(IMAP_NOOP_POSTAUTH_CONN_TIMEOUT_SECONDS)
            imap.login(username, password)
            return imap

        connections = self._noop2_establish_pool(
            max_connections, opener, write_live=write_live, show_progress=show_progress,
            clear_live=clear_live,
        )
        established = len(connections)
        
        clear_live()
        self.debug(
            f"Phase 1 complete: {established}/{max_connections} authenticated connections. "
            f"Holding for {IMAP_NOOP_POSTAUTH_CONN_TEST_SECONDS}s with NOOP..."
        )
        
        # Phase 2: Hold connections with periodic NOOP
        start_time = time.perf_counter()
        stop_event = threading.Event()
        
        def noop_worker(imap, idx):
            nonlocal total_noops_sent, total_noops_ok, total_noops_error, early_disconnect_count
            tag_counter = 0
            while not stop_event.is_set():
                time.sleep(IMAP_NOOP_POSTAUTH_CONN_INTERVAL_SECONDS)
                if stop_event.is_set():
                    break
                with lock:
                    total_noops_sent += 1
                tag_counter += 1
                tag = f"c{idx:04d}{tag_counter:04d}"
                success, error = self._imap_noop_safe(imap, tag)
                with lock:
                    if success:
                        total_noops_ok += 1
                    else:
                        total_noops_error += 1
                        early_disconnect_count += 1
                        break
        
        threads = []
        for imap, idx in connections:
            t = threading.Thread(target=noop_worker, args=(imap, idx), daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for test duration with live progress
        end_time = time.perf_counter() + IMAP_NOOP_POSTAUTH_CONN_TEST_SECONDS
        while time.perf_counter() < end_time:
            time.sleep(1.0)
            if show_progress:
                active = established - early_disconnect_count
                remaining = int(end_time - time.perf_counter())
                write_live(f"Maintaining connections: {active}/{established} active, {remaining}s remaining, {total_noops_ok} NOOPs sent")
        
        stop_event.set()
        clear_live()
        
        # Wait for all threads to finish
        for t in threads:
            t.join(timeout=2.0)
        
        # Close all connections
        for imap, _ in connections:
            try:
                imap.logout()
            except Exception:
                pass
        
        maintained = established - early_disconnect_count
        test_duration = time.perf_counter() - start_time
        
        self.debug(f"Phase 2 complete: {maintained}/{established} connections maintained, {total_noops_ok} NOOPs OK")
        
        return NoopConnectionCountResult(
            authenticated=True,
            max_connections_attempted=max_connections,
            connections_established=established,
            connections_maintained=maintained,
            test_duration_seconds=test_duration,
            total_noops_sent=total_noops_sent,
            total_noops_ok=total_noops_ok,
            total_noops_error=total_noops_error,
            early_disconnect_count=early_disconnect_count,
            error_message=None,
        )

    # endregion
