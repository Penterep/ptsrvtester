"""SMTP protocol engine — connection, reporting, and shared helpers used by modules/run(ctx)."""
from __future__ import annotations

import argparse
import socket
import sys
import threading
from base64 import b64encode
from typing import Optional

from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib

from ..._base import Out
from .helpers import *
from .results import *
from .registry import *
from .cli import SMTPArgs

from .enumeration import EnumMixin
from .reporting import ReportingMixin
from .connection import ConnectionMixin
from .shared import SharedMixin


class SmtpEngine(
    EnumMixin,
    ReportingMixin,
    ConnectionMixin,
    SharedMixin,
):
    """Stateful SMTP probe helper. Modules call tests then ``_stream_*`` via ctx.out."""

    _MAIL_RCPT_TRANSACTION_OK = (250, 251, 252)
    _ATEXT_ASCII = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~."
    )
    AUTH_ENUM_PASSWORD = "PtSrv_Test_!@#_2026"
    AUTH_ENUM_METHOD_PROBE_ORDER = ("LOGIN", "PLAIN", "NTLM")
    _AUTH_DOWNGRADE_BOGUS_XOAUTH2 = b64encode(
        b"user=admin\x00auth=Bearer 1234567890\x00\x00"
    ).decode()

    def __init__(self, args, *, ptjsonlib: PtJsonLib | None = None, report=None):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.report = report
        self.smtp = None
        self.use_json = bool(getattr(args, "json", False))
        self.run_all_mode = False
        self._info_error_emitted = False
        self.already_enumerated = None
        self._enum_progress_print_lock = threading.Lock()
        self._enum_clock_thread: threading.Thread | None = None
        self._enum_clock_stop = threading.Event()
        self._enum_clock_state: dict[str, int | str] | None = None
        if not self.use_json and hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(line_buffering=True, write_through=True)
            except (OSError, ValueError, AttributeError):
                pass

        self.rate_limit_is_error = None
        self.is_slow_down = None
        self.fqdn = "example.com" if not args.fqdn else args.fqdn

        self._load_wordlist()

        if args.target.port == 0:
            if args.tls:
                args.target.port = 465
            elif getattr(args, "starttls", False):
                args.target.port = 587
            else:
                args.target.port = 25
        self.target = args.target.ip
        self.port = args.target.port

        self.do_brute = check_if_brute(args)

        try:
            socket.inet_aton(self.target)
            self.target_is_ip = True
        except socket.error:
            self.target_is_ip = False
        if self.target_is_ip:
            self.target_ip = self.target
        else:
            try:
                self.target_ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve domain name '{self.target}' to IP address"
                )

        self._brute_stream_lock = threading.Lock()
        self.out = lambda *a, **k: None
        self.debug = lambda *a, **k: None
        self.results = SMTPResults()
        self._vuln_poc: dict[str, str] = {}

    def bind_ctx(self, ctx) -> "SmtpEngine":
        """Rebind output sinks for the current module PrintLock (IMAP/POP3)."""
        self._ctx = ctx
        self.out = ctx.out
        self.debug = ctx.debug
        self.report = getattr(ctx, "report", self.report)
        self.use_json = bool(getattr(ctx, "json", self.use_json))
        if getattr(ctx, "ptjsonlib", None) is not None:
            self.ptjsonlib = ctx.ptjsonlib
        return self

    def _ptprint(self, string="", out=Out.TEXT, title=False, end="\n", json=False, indent=0):
        """Adapt old BaseModule.ptprint to ctx.out (terminal) or raw stdout (JSON)."""
        if self.use_json and not json:
            return
        if json and not self.use_json:
            return
        if json:
            # ctx.out is suppressed in JSON mode; dump must go to stdout.
            sys.stdout.write(string if str(string).endswith("\n") else f"{string}\n")
            sys.stdout.flush()
            return
        if title:
            cat, color = "INFO", True
        else:
            cat = out.value if hasattr(out, "value") else str(out)
            color = cat == "INFO"
        self.out(string, cat, colortext=color, indent=indent)

    def _ptprint_raw(self, string="", category="TEXT", *args, **kwargs):
        """ptprinthelper.ptprint → ctx.out (bullet_type / condition / indent)."""
        if "bullet_type" in kwargs:
            category = kwargs["bullet_type"]
        elif args and isinstance(args[0], str):
            category = args[0]
        cond = kwargs.get("condition", True)
        if "condition" not in kwargs:
            for a in args:
                if isinstance(a, bool):
                    cond = a
                    break
        if not cond:
            return
        indent = kwargs.get("indent", 0)
        cat = category if isinstance(category, str) else str(category)
        color = kwargs.get("colortext", cat == "INFO")
        self.out(string, cat, colortext=color, indent=indent)

    @staticmethod
    def _smtp_text_is_timeout(text: str | None) -> bool:
        t = (text or "").lower()
        return "timed out" in t or "timeout" in t or "could not connect" in t

    def _smtp_exc_is_timeout(self, exc: BaseException) -> bool:
        if isinstance(exc, (TimeoutError, socket.timeout)):
            return True
        return self._smtp_text_is_timeout(str(exc))

    def _load_wordlist(self) -> None:
        args = self.args
        raw: list[str] = []
        if _smtp_users_file_supplies_name_list(args):
            raw = list(filter(lambda x: x != "", text_or_file(None, args.users)))
        if args.user is not None and (
            args.enumerate is not None
            or getattr(args, "auth_enum", False)
            or _rcpt_limit_active(args)
        ):
            raw.extend(x for x in text_or_file(args.user, None) if x != "")
        if raw:
            self.wordlist = [u for u in raw if self._is_valid_local_part(u.split("@")[0].strip())]
            self._wordlist_skipped = len(raw) - len(self.wordlist)
        else:
            self.wordlist = None
            self._wordlist_skipped = 0

    @staticmethod
    def _validate_smtp_args(args: SMTPArgs) -> None:
        """Validate cross-flag requirements after ``_apply_smtp_tests``."""
        if args.slow_down and args.enumerate is None:
            raise argparse.ArgumentError(None, "--slow-down requires also --enumerate")

        bomb_requested = getattr(args, "bomb", False)
        antivirus_requested = getattr(args, "antivirus", False)
        if bomb_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-bomb requires -r/--rcpt-to (recipient)")
        if antivirus_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-antivirus requires -r/--rcpt-to (recipient)")
        ssrf_requested = getattr(args, "ssrf", False)
        if ssrf_requested:
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-ssrf requires -r/--rcpt-to (recipient)")
            canary = getattr(args, "ssrf_canary_url", None) or ""
            if not canary or not str(canary).strip():
                raise argparse.ArgumentError(None, "-ssrf requires --ssrf-canary-url (canary/callback URL)")
        zipxxe_requested = getattr(args, "zipxxe", False)
        if zipxxe_requested:
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-zipxxe requires -r/--rcpt-to (recipient)")
        spoof_headers_requested = getattr(args, "spoof_headers", False)
        if spoof_headers_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-sh/--spoof-headers requires -r/--rcpt-to (recipient)")
        if getattr(args, "bcc_disclosure", False):
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-ts BCC requires -r/--rcpt-to (recipient)")
        alias_test_requested = getattr(args, "alias_test", False)
        if alias_test_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-al/--alias-test requires -r/--rcpt-to (base recipient)")
        bounce_replay_requested = getattr(args, "bounce_replay", False)
        if bounce_replay_requested:
            if not args.mail_from or not str(args.mail_from).strip():
                raise argparse.ArgumentError(
                    None, "-br/--bounce-replay requires -m/--mail-from (controlled bounce / MAIL FROM address)"
                )
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-br/--bounce-replay requires -r/--rcpt-to (recipient)")
        rl_n = getattr(args, "rcpt_limit", None)
        if rl_n is not None and getattr(args, "send", False):
            if not args.mail_from or not str(args.mail_from).strip() or "@" not in str(args.mail_from):
                raise argparse.ArgumentError(
                    None,
                    "RCPTLIM with --send requires -m/--mail-from (envelope MAIL FROM for delivery)",
                )
        rdd_n = getattr(args, "rcpt_duplicate", None)
        if rdd_n is not None:
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(
                    None, "-rdd/--rcpt-duplicate requires -r/--rcpt-to (same address is probed)"
                )
            if rdd_n < 2:
                raise argparse.ArgumentError(None, "-rdd/--rcpt-duplicate N must be at least 2")
            if rdd_n > RCPT_DUP_MAX:
                raise argparse.ArgumentError(
                    None, f"-rdd/--rcpt-duplicate N must not exceed {RCPT_DUP_MAX}"
                )
        if zipxxe_requested:
            variants_arg = getattr(args, "zipxxe_variants", None)
            # Default list includes xxe_*; those are skipped in the module when no canary is set.
            # Require the URL only when an XXE variant was requested explicitly.
            zipxxe_variants = [
                v.strip().lower()
                for v in str(variants_arg or "").split(",")
                if v.strip()
            ]
            xxe_variants = {"xxe_zip", "xxe_docx", "xxe_body"}
            needs_canary = any(v in xxe_variants for v in zipxxe_variants)
            if needs_canary:
                canary = getattr(args, "zipxxe_canary_url", None) or ""
                if not canary or not str(canary).strip():
                    raise argparse.ArgumentError(
                        None,
                        "-zipxxe with xxe_zip/xxe_docx/xxe_body requires --zipxxe-canary-url (canary/callback URL)",
                    )

        if args.interactive and args.json:
            raise argparse.ArgumentError(None, "--interactive cannot be used together with --json")

    def _fail(self, msg: str) -> None:
        """In run-all mode: raise TestFailedError. Otherwise: end_error + SystemExit."""
        if self.run_all_mode:
            raise TestFailedError(msg)
        if self.ptjsonlib is not None:
            self.ptjsonlib.end_error(msg, self.use_json)
        raise SystemExit

    def note_poc(self, code: str, *pairs: tuple[str, str]) -> None:
        """Remember the Send/Receive lines that prove one vulnerability.

        Later pairs for the same code are ignored. The full session stays in
        ``results.log``; this is only the proving snippet.
        """
        if not code or code in self._vuln_poc or not pairs:
            return
        lines: list[str] = []
        for send, recv in pairs:
            if not send:
                continue
            recv_s = "(no reply)" if recv in (None, "") else " ".join(str(recv).split())
            lines.append(f"Send: {send}")
            lines.append(f"Receive: {recv_s}")
        if lines:
            self._vuln_poc[code] = "\r\n".join(lines)

    def _add_to_json_log(self, line: str) -> None:
        """Append one line to results.log when -j is active (ptjsonlib.add_to_log)."""
        if not self.use_json or not line:
            return
        ptjsonlib = getattr(self, "ptjsonlib", None)
        add_to_log = getattr(ptjsonlib, "add_to_log", None) if ptjsonlib is not None else None
        if callable(add_to_log):
            add_to_log(line)

    def ptdebug(
        self,
        string: str,
        out: Out = Out.TEXT,
        title: bool = False,
        end: str = "\n",
        *,
        indent_override: Optional[int] = None,
    ) -> None:
        """Hand the line to ``ctx.debug``: always logged, printed only on ``-vv``."""
        lines = string.splitlines() or [string]
        indent = 4 if indent_override is None else indent_override

        if end != "\n":
            ctx = getattr(self, "_ctx", None)
            log = getattr(ctx, "log", None) if ctx is not None else None
            show = bool(getattr(self.args, "debug", False)) and not self.use_json
            for i, line in enumerate(lines):
                if line and callable(log):
                    log(line)
                elif line and self.use_json:
                    self._add_to_json_log(line)
                if not show:
                    continue
                last = i == len(lines) - 1
                ptprinthelper.ptprint(
                    line,
                    "ADDITIONS",
                    True,
                    end=end if last else "\n",
                    flush=True,
                    colortext=True,
                    indent=indent,
                )
            return

        ctx = getattr(self, "_ctx", None)
        dbg = getattr(ctx, "debug", None) if ctx is not None else None
        for line in lines:
            if not line:
                continue
            if callable(dbg):
                try:
                    dbg(line, indent=indent)
                except TypeError:
                    dbg(line)
            elif self.use_json:
                self._add_to_json_log(line)

    def _smtp_vv_io(self, send: str | None, recv: str | None, *, indent: int = 4) -> None:
        """Real SMTP line, then Receive. Logged always; printed on ``-vv``."""
        if not send:
            return
        recv_s = "(no reply)" if recv in (None, "") else " ".join(str(recv).split())
        self.ptdebug(f"Send: {send}", indent_override=indent)
        self.ptdebug(f"Receive: {recv_s}", indent_override=indent)

    def ptprint(
        self,
        string: str,
        out: Out = Out.TEXT,
        title: bool = False,
        end: str = "\n",
        json: bool = False,
    ):
        self._ptprint(string, out=out, title=title, end=end, json=json)

    def infer_encryption_from_info(self) -> EncryptionResult:
        """Lightweight ENCRYPT used in ALL / default suite (no three-mode probe).

        STARTTLS is OK only when a live post-STARTTLS EHLO was obtained. Advertised
        but failed STARTTLS is incomplete — not a confirmed missing mode.
        """
        info = self.results.info
        if self.args.target.port == 465:
            return EncryptionResult(plaintext_ok=False, starttls_ok=False, tls_ok=True)
        if info and info.ehlo_starttls:
            return EncryptionResult(plaintext_ok=True, starttls_ok=True, tls_ok=False)
        advertised = bool(info and info.ehlo and "STARTTLS" in info.ehlo.upper())
        if advertised:
            return EncryptionResult(
                plaintext_ok=True, starttls_ok=False, tls_ok=False,
                starttls_incomplete=True,
            )
        return EncryptionResult(plaintext_ok=True, starttls_ok=False, tls_ok=False)
