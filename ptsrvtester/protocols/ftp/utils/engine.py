"""FTP protocol engine — ported probe logic used by modules/run(ctx)."""
from __future__ import annotations

import argparse
import collections
import ftplib
import ipaddress
import posixpath
import random
import re
import string
import secrets
import select
import socket
import ssl
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from io import BytesIO
from ssl import SSLSocket
from string import ascii_uppercase
from typing import Any, Callable, NamedTuple

from ptlibs.ptprinthelper import out_if

from .ptprinthelper import get_colored_text
from ptlibs.threads import ptthreads

from .progress import ThreadedProgress
from .helpers import (
    ArgsWithBruteforce,
    Creds,
    Target,
    brute_passwords,
    check_if_brute,
    get_mode,
    one_cli_user,
    shown_password,
    simple_bruteforce,
    text_or_file,
    valid_target,
    vendor_from_cpe,
)
from .service_identification import identify_service
from .decompression_payloads import BILLION_LAUGHS_XML, build_full_zip_bomb, build_huge_zip_bomb
from .ftp_types import *  # noqa: F403
from .ftp_types import (  # noqa: F401
    _conn_limits_pasv_post_suspect,
    _conn_limits_pasv_pre_suspect,
    _ftp_list_line_directory_rel_name,
)


class Out:
    TEXT = "TEXT"; TITLE = "TITLE"; INFO = "INFO"; WARNING = "WARNING"; ERROR = "ERROR"
    OK = "OK"; VULN = "VULN"; NOTVULN = "NOTVULN"; ADDITIONS = "ADDITIONS"


class FtpEngine:
    """Stateful FTP probe helper for plugin modules."""

    def __init__(self, args, *, out: Callable = None, debug: Callable = None, report=None):
        self.args = args
        self.out = out or (lambda *a, **k: None)
        self.debug = debug or (lambda *a, **k: None)
        self.report = report
        self.ftp = None
        self.use_json = bool(getattr(args, "json", False))
        self.do_brute = check_if_brute(args)
        self._output_lock = threading.Lock()
        self.results = FTPResults()

    def bind_ctx(self, ctx) -> "FtpEngine":
        self.out = ctx.out
        self.debug = ctx.debug
        self.report = getattr(ctx, "report", self.report)
        self.use_json = bool(ctx.json)
        self._ctx = ctx
        return self

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

    @staticmethod
    def _ftp_text_is_unconfirmed(text: str | None) -> bool:
        """Timeout or no connection: the check did not finish, so it is not a verdict."""
        t = (text or "").lower()
        return any(
            s in t
            for s in (
                "timed out",
                "timeout",
                "could not connect",
                "connection refused",
                "connection reset",
                "network is unreachable",
                "no route to host",
            )
        )

    @staticmethod
    def _ftp_server_reply(text: str | None) -> bool:
        s = (text or "").strip()
        return len(s) >= 3 and s[:3].isdigit()

    def _dbg(self, msg: str, *, indent: int = 4) -> None:
        """Verbose-only (-vv) line via ctx.debug / ADDITIONS."""
        try:
            self.debug(msg, indent=indent)
        except TypeError:
            self.debug(msg)

    def _flush_terminal(self) -> None:
        """Flush PrintLock so a -vv line appears immediately above its result."""
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

    def _dbg_extra_lines(self, text: str | None, *, max_lines: int = 12) -> None:
        if not text:
            return
        for line in text.replace("\r", "").splitlines()[1:max_lines]:
            if line.strip():
                self._dbg(line, indent=8)

    def _ptprint(self, string="", out=Out.TEXT, title=False, end="\n", json=False, indent=0):
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
        if "bullet_type" in kwargs and (not category or category == "TEXT"):
            category = kwargs["bullet_type"]
        if not kwargs.get("condition", True):
            return
        indent = kwargs.get("indent", 0)
        color = kwargs.get("colortext", category == "INFO")
        self.out(string, category if isinstance(category, str) else str(category), colortext=color, indent=indent)

    def _emit_section_heading(self, title: str) -> None:
        """Print section title before work starts (align with SMTP progressive terminal UX)."""
        if self.use_json:
            return
        with self._output_lock:
            self._ptprint(title, Out.INFO)

    def _tprint(self, msg: str, bullet: str = "TEXT", indent: int = 4) -> None:
        self._ptprint_raw(msg, bullet_type=bullet, condition=not self.use_json, indent=indent)

    def _ftp_any_primary_action(self) -> bool:
        """True if any test flag is set other than standalone -eu (used for user-enum-only fast path)."""
        a = self.args
        return bool(
            a.info
            or a.banner
            or a.commands
            or getattr(a, "isencrypt", False)
            or a.anonymous
            or a.access
            or a.access_list
            or a.bounce
            or self.do_brute
            or getattr(a, "enum_paths", False)
            or getattr(a, "modes", False)
            or getattr(a, "pasv_port_audit", False)
            or getattr(a, "conn_limits_audit", False)
            or getattr(a, "chroot_audit", False)
            or getattr(a, "active_audit", False)
            or getattr(a, "active_audit_full", False)
            or getattr(a, "cmd_audit", False)
            or getattr(a, "cmd_audit_active", False)
            or getattr(a, "invalid_cmd_audit", False)
            or getattr(a, "eicar_probe", False)
            or getattr(a, "ftp_dos_probes", False)
        )

    def _fail(self, msg: str) -> None:
        """In run-all mode: raise TestFailedError. Otherwise: end_error + SystemExit."""
        if hasattr(self, 'run_all_mode') and self.run_all_mode:
            raise TestFailedError(msg)
        else:
            self.ptjsonlib.end_error(msg, self.use_json)
            raise SystemExit

    def _ftp_is_single_known_login(self) -> bool:
        """True when CLI supplies one username and one password (no -U/-P wordlists)."""
        u = one_cli_user(getattr(self.args, "user", None))
        p = getattr(self.args, "password", None)
        uf = getattr(self.args, "users", None)
        pf = getattr(self.args, "passwords", None)
        return bool(u and p and not uf and not pf)

    def _get_path_enum_creds(self) -> Creds | None:
        """Get credentials: anonymous, or first successful login from -u/-p or wordlists."""
        if self.results.anonymous:
            return Creds("anonymous", "")
        if self.results.creds and len(self.results.creds) > 0:
            return next(iter(self.results.creds))
        return None

    def connect(self, *, trace: bool = False) -> ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit:
        """
        Establishes a new FTP connection with the appropriate
        encryption mode according to module arguments

        Returns:
            ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit: new connection
        """
        timeout = 10
        mode = get_mode(self.args)
        if trace:
            self._dbg(f"Connecting to {self.args.target.ip}:{self.args.target.port} ({mode})")
        try:
            if self.args.tls:
                ftp = FTP_TLS_implicit()
                ftp.connect(self.args.target.ip, self.args.target.port, timeout=timeout)
            elif self.args.starttls:
                ftp = ftplib.FTP_TLS()
                ftp.connect(self.args.target.ip, self.args.target.port, timeout=timeout)
                if trace:
                    self._dbg("Sending AUTH TLS (explicit upgrade)")
                ftp.auth()
                if trace:
                    self._dbg("AUTH TLS upgrade OK")
            else:
                ftp = ftplib.FTP()
                ftp.connect(self.args.target.ip, self.args.target.port, timeout=timeout)
        except Exception as e:
            if trace:
                self._dbg(f"Connect failed: {e}")
            msg = (
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({mode}): {e}"
            )
            raise OSError(msg) from e

        if trace:
            self._dbg(f"Banner: {self._snip(ftp.welcome)}")
        # Passive/Active mode
        ftp.set_pasv(not self.args.active)
        return ftp

    def info(self, get_commands: bool = True) -> InfoResult:
        """Performs bannergrabbing; optionally HELP, SYST and STAT commands.

        Returns:
            InfoResult: (banner, help_response, syst, stat)
        """
        banner = self.ftp.welcome
        if banner is None:
            banner = ""

        help_response = None
        syst = None
        stat = None
        if get_commands:
            try:
                help_response = self.ftp.sendcmd("HELP")
                if help_response and help_response.strip():
                    help_response = help_response.strip()
                else:
                    help_response = None
                if help_response:
                    self._dbg(f"HELP → {self._snip(help_response)}")
                    self._dbg_extra_lines(help_response, max_lines=24)
                else:
                    self._dbg("HELP: empty / not advertised")
            except Exception as e:
                help_response = str(e).strip() or "HELP failed"
                self._dbg(f"HELP failed: {self._snip(help_response)}")
            try:
                syst = self.ftp.sendcmd("SYST")
                if re.match(r"[0-9]+ UNIX Type: L8", syst or ""):
                    self._dbg(f"SYST → {self._snip(syst)} (generic L8, ignored)")
                else:
                    self._dbg(f"SYST → {self._snip(syst)}")
            except Exception as e:
                syst = str(e).strip() or "SYST failed"
                self._dbg(f"SYST failed: {self._snip(syst)}")
            try:
                if not self.results.anonymous and self.results.creds is not None:
                    for creds in self.results.creds:
                        self.ftp.login(creds.user, creds.passw)
                        break
                stat = self.ftp.sendcmd("STAT")
                self._dbg(f"STAT → {self._snip(stat)}")
                self._dbg_extra_lines(stat)
            except Exception as e:
                stat = str(e).strip() or "STAT failed"
                self._dbg(f"STAT failed: {self._snip(stat)}")

        return InfoResult(banner, help_response, syst, stat)

    def _missing_login_line(self) -> str:
        """Why a test that needs a session cannot log in."""
        anon_failed = self.results.anonymous is False
        tried_user = check_if_brute(self.args)
        if anon_failed and tried_user:
            return "Anonymous login failed and the supplied login was rejected."
        if anon_failed:
            return "Anonymous login failed. Use -u and -p."
        if tried_user:
            return "Login failed. Check -u and -p."
        return "Use -u and -p, or -A if anonymous login is enabled."

    def _is_login_skip(self, text: str | None) -> bool:
        t = text or ""
        return t.startswith((
            "Anonymous login failed",
            "Login failed. Check -u and -p.",
            "Use -u and -p, or -A",
        ))

    def anonymous(self) -> bool:
        """Attempts anonymous authentication

        Returns:
            bool: result
        """
        try:
            self._dbg("USER anonymous")
            self.ftp.login()
            self._dbg("PASS → OK (anonymous)")
            return True
        except ftplib.Error as e:
            if self._ftp_text_is_unconfirmed(str(e)):
                raise
            self._dbg(f"PASS → failed: {self._snip(str(e))}")
            return False

    def access_check(self) -> AccessCheckResult:
        """
        Attempts to login with all available valid credentials
        (including anonymous) and perform:
        - directory listing
        - file write
        - file read
        - file delete (just cleanup)

        Returns:
            AccessCheckResult: results
        """
        access_permissions: list[AccessPermissions] = []

        # Construct a list of all valid credentials
        all_creds: list[Creds] = []

        if self.results.anonymous:
            all_creds.append(Creds("anonymous", ""))

        if self.results.creds is not None:
            all_creds.extend(self.results.creds)

        if len(all_creds) == 0:
            self._dbg("Access check skipped: no valid credentials")
            return AccessCheckResult([self._missing_login_line()], None)

        # Check all credentials
        errors: list[str] = []
        for creds in all_creds:
            self._dbg(f"Access check as {creds.user!r}")
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
                self._dbg(f"LOGIN {creds.user!r} → OK")
            except Exception as e:
                self._dbg(f"LOGIN {creds.user!r} → failed: {self._snip(str(e))}")
                # Valid creds but server-side error
                errors.append(str(e))
                access_permissions.append(AccessPermissions(creds, None, None, None, None))
                continue

            write, read, delete = None, None, None
            ach = AccessCheckHelper()

            # Directory listing
            try:
                ftp.dir(ach.read_callback)
                nlines = len(ach.lines_read or [])
                self._dbg(f"LIST → {nlines} line(s)")
            except Exception as e:
                # Unexpected error, maybe timeout or similar
                errors.append(str(e))
                access_permissions.append(AccessPermissions(creds, None, None, None, None))
                continue

            # Root and top-level directories from LIST (format varies by server/OS)
            directories: list[str] = [""]
            if ach.lines_read is not None:
                for l in ach.lines_read:
                    if not l or l[0] != "d":
                        continue
                    dir_name = _ftp_list_line_directory_rel_name(l)
                    if dir_name:
                        directories.append(dir_name)

            text = BytesIO(b"FILE WRITE TEST")
            filename = "".join(random.choices(ascii_uppercase, k=15)) + ".txt"

            # Check permissions in parsed directories
            for dir in directories:
                # Record only the first successful hit
                if write is not None:
                    break

                text.seek(0)
                filepath = dir + "/" + filename

                # Write
                try:
                    ftp.storlines("STOR " + filepath, text)
                    write = filepath
                    self._dbg(f"STOR {filepath!r} → OK")
                except ftplib.Error as e:
                    self._dbg(f"STOR {filepath!r} → failed: {self._snip(str(e))}")

                # Read
                if write:
                    try:
                        ftp.retrlines("RETR " + filepath, nop_callback)
                        read = filepath
                        self._dbg(f"RETR {filepath!r} → OK")
                    except ftplib.Error as e:
                        self._dbg(f"RETR {filepath!r} → failed: {self._snip(str(e))}")

                # Delete
                if write:
                    try:
                        ftp.delete(filepath)
                        delete = filepath
                        self._dbg(f"DELE {filepath!r} → OK")
                    except ftplib.Error as e:
                        self._dbg(f"DELE {filepath!r} → failed: {self._snip(str(e))}")

            access_permissions.append(
                AccessPermissions(
                    creds,
                    ach.lines_read,
                    write,
                    read,
                    delete,
                )
            )

        if len(errors) == 0:
            return AccessCheckResult(None, access_permissions)
        else:
            return AccessCheckResult(errors, access_permissions)

    @staticmethod
    def _eicar_reply_suggests_missing(msg: str) -> bool:
        """Heuristic for SIZE/RETR/DELE failures that imply the uploaded object is absent."""
        lower = msg.lower()
        needles = (
            "not found",
            "no such file",
            "couldn't open",
            "could not open",
            "can't open",
            "cannot open",
            "failed to open",
            "does not exist",
            "unknown file",
            "file unavailable",
        )
        return any(n in lower for n in needles)

    @staticmethod
    def _eicar_size_unsupported(msg: str) -> bool:
        m = msg.lower()
        return (
            "502" in msg
            or "504" in msg
            or "command not implemented" in m
            or "not implemented" in m
            or "unsupported" in m and "size" in m
        )

    def _eicar_probe_one_account(self, creds: Creds, delay: float) -> FtpEicarRow:
        """Upload EICAR, wait, verify presence via SIZE/RETR, DELE cleanup."""
        ftp = self.connect()

        def _fail_early(stor_error: str | None) -> FtpEicarRow:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass
            return FtpEicarRow(
                creds,
                "",
                False,
                stor_error,
                delay,
                None,
                None,
                False,
                None,
                None,
                False,
                False,
                False,
                None,
                None,
            )

        try:
            ftp.login(creds.user, creds.passw)
            self._dbg(f"LOGIN {creds.user!r} → OK")
        except Exception as e:
            self._dbg(f"LOGIN {creds.user!r} → failed: {self._snip(str(e))}")
            try:
                ftp.close()
            except Exception:
                pass
            return FtpEicarRow(
                creds,
                "",
                False,
                str(e),
                delay,
                None,
                None,
                False,
                None,
                None,
                False,
                False,
                False,
                None,
                None,
            )

        ach = AccessCheckHelper()
        directories: list[str] = [""]
        try:
            ftp.dir(ach.read_callback)
            if ach.lines_read is not None:
                for l in ach.lines_read:
                    if not l or l[0] != "d":
                        continue
                    dn = _ftp_list_line_directory_rel_name(l)
                    if dn:
                        directories.append(dn)
        except Exception:
            directories = [""]

        filename = "EICAR_" + "".join(random.choices(ascii_uppercase, k=8)) + ".com"
        stor_ok = False
        stor_err: str | None = None
        used_path = ""

        for dir in directories:
            if stor_ok:
                break
            filepath = dir + "/" + filename
            bio = BytesIO(EICAR_STANDARD_TEST_FILE)
            try:
                ftp.storbinary("STOR " + filepath, bio)
                stor_ok = True
                used_path = filepath
                self._dbg(f"STOR {filepath!r} (EICAR) → OK")
            except ftplib.Error as e:
                stor_err = str(e)
                self._dbg(f"STOR {filepath!r} (EICAR) → failed: {self._snip(str(e))}")

        if not stor_ok:
            return _fail_early(stor_err)

        try:
            time.sleep(max(0.0, delay))
        except Exception:
            pass

        size_bytes: int | None = None
        size_err: str | None = None
        try:
            size_bytes = ftp.size(used_path)
            self._dbg(f"SIZE {used_path!r} → {size_bytes}")
        except ftplib.error_perm as e:
            size_err = str(e)
            self._dbg(f"SIZE {used_path!r} → {self._snip(str(e))}")
        except ftplib.Error as e:
            size_err = str(e)
            self._dbg(f"SIZE {used_path!r} → {self._snip(str(e))}")

        buf = BytesIO()
        retr_ok = False
        retr_match: bool | None = None
        retr_err: str | None = None
        try:
            ftp.retrbinary("RETR " + used_path, buf.write)
            retr_ok = True
            retr_match = buf.getvalue() == EICAR_STANDARD_TEST_FILE
            self._dbg(f"RETR {used_path!r} → OK match={retr_match}")
        except ftplib.Error as e:
            retr_err = str(e)
            self._dbg(f"RETR {used_path!r} → failed: {self._snip(str(e))}")

        size_vanished = (
            bool(size_err)
            and not self._eicar_size_unsupported(size_err)
            and self._eicar_reply_suggests_missing(size_err)
        )
        retr_missing = retr_err is not None and self._eicar_reply_suggests_missing(retr_err)
        retr_unconfirmed = bool(retr_err) and (
            self._ftp_text_is_unconfirmed(retr_err) or not self._ftp_server_reply(retr_err)
        )
        size_wrong = (
            size_bytes is not None
            and size_bytes != len(EICAR_STANDARD_TEST_FILE)
            and (retr_ok or retr_missing)
            and not retr_unconfirmed
        )
        retr_bad = bool(retr_ok and retr_match is False)
        vanished = size_vanished or size_wrong or retr_missing or retr_bad

        delete_ok = False
        delete_err: str | None = None
        delete_note: str | None = None
        try:
            ftp.delete(used_path)
            delete_ok = True
            self._dbg(f"DELE {used_path!r} → OK")
        except ftplib.error_perm as e:
            delete_err = str(e)
            if self._eicar_reply_suggests_missing(str(e)):
                delete_note = (
                    "DELE failed with missing-file style reply — file likely already removed "
                    "(on-access AV / quarantine); treated as protection signal, not test failure."
                )
        except ftplib.Error as e:
            delete_err = str(e)
            if self._eicar_reply_suggests_missing(str(e)):
                delete_note = (
                    "DELE failed with missing-file style reply — file likely already removed "
                    "(on-access AV / quarantine); treated as protection signal, not test failure."
                )

        on_access = vanished or (delete_note is not None)

        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass

        return FtpEicarRow(
            creds,
            used_path,
            True,
            None,
            delay,
            size_bytes,
            size_err,
            retr_ok,
            retr_match,
            retr_err,
            vanished,
            on_access,
            delete_ok,
            delete_err,
            delete_note,
        )

    def test_eicar_antivirus_probe(self) -> FtpEicarAuditResult:
        """EICAR upload audit (PTL-SVC-FTP-ANTIVIRUS): delayed verify for on-access scanners."""
        delay = max(0.0, float(getattr(self.args, "eicar_post_stor_delay", 0.5) or 0.0))
        all_creds: list[Creds] = []
        if self.results.anonymous:
            all_creds.append(Creds("anonymous", ""))
        if self.results.creds is not None:
            all_creds.extend(self.results.creds)
        if not all_creds:
            self._dbg("EICAR skipped: no logged-in account")
            detail = self._missing_login_line()
            return FtpEicarAuditResult(delay, tuple(), detail, False, False)
        rows = tuple(self._eicar_probe_one_account(c, delay) for c in all_creds)
        risky = any(
            r.stor_ok and r.retr_payload_match is True and not r.vanished_after_stor_suspected
            for r in rows
        )
        blocked_all = bool(rows) and all(not r.stor_ok for r in rows)
        n_stor = sum(1 for r in rows if r.stor_ok)
        n_van = sum(1 for r in rows if r.vanished_after_stor_suspected)
        n_onacc = sum(1 for r in rows if r.on_access_scan_suspected)
        detail = (
            f"Accounts tested: {len(rows)}; STOR ok: {n_stor}; "
            f"vanished_after_stor_suspected: {n_van}; on_access_signals: {n_onacc}; "
            f"EICAR still retrievable unchanged after delay: {'yes' if risky else 'no'}."
        )
        return FtpEicarAuditResult(delay, rows, detail, risky, blocked_all)

    def _ftp_stor_binary_timed(
        self,
        ftp: ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit,
        cmd: str,
        data: bytes,
    ) -> FtpStorTimingOutcome:
        """Mirror ftplib.storbinary but measure time from last payload byte sent to final voidresp() (typically 226)."""
        if not data:
            return FtpStorTimingOutcome(False, "empty payload", None, None, None, None, False)
        blocksize = 8192
        t_last_byte_sent: float | None = None
        t_start = time.perf_counter()
        try:
            ftp.voidcmd("TYPE I")
            with ftp.transfercmd(cmd) as conn:
                bio = BytesIO(data)
                while True:
                    buf = bio.read(blocksize)
                    if not buf:
                        break
                    conn.sendall(buf)
                    t_last_byte_sent = time.perf_counter()
                try:
                    conn.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            reply = ftp.voidresp()
            t_done = time.perf_counter()
            code, line = self._ftp_parse_reply_line(reply)
            total = t_done - t_start
            delta = (t_done - t_last_byte_sent) if t_last_byte_sent is not None else total
            return FtpStorTimingOutcome(True, None, code, line, total, delta, False)
        except socket.timeout:
            t_done = time.perf_counter()
            total = t_done - t_start
            delta = (
                (t_done - t_last_byte_sent)
                if t_last_byte_sent is not None
                else None
            )
            try:
                ftp.abort()
            except Exception:
                pass
            return FtpStorTimingOutcome(
                False,
                "socket.timeout waiting for STOR / control completion",
                None,
                None,
                total,
                delta,
                True,
            )
        except (ftplib.error_reply, ftplib.error_temp, ftplib.error_perm) as e:
            t_done = time.perf_counter()
            total = t_done - t_start
            raw = e.args[0] if e.args else str(e)
            rs = raw if isinstance(raw, str) else str(raw)
            code, line = self._ftp_parse_reply_line(rs)
            delta = (
                (t_done - t_last_byte_sent)
                if t_last_byte_sent is not None
                else total
            )
            return FtpStorTimingOutcome(False, rs, code, line, total, delta, False)
        except OSError as e:
            t_done = time.perf_counter()
            total = t_done - t_start
            delta = (
                (t_done - t_last_byte_sent)
                if t_last_byte_sent is not None
                else total
            )
            return FtpStorTimingOutcome(False, str(e), None, None, total, delta, False)

    def _ftp_dos_policy_block_hit(self, code: int | None, text: str | None) -> bool:
        """550/451-style denials counted as protective (content/type policy or quota)."""
        if code is not None and code in FTP_DOS_POLICY_BLOCK_CODES:
            return True
        low = (text or "").lower()
        phrases = (
            "access denied",
            "permission denied",
            "not allowed",
            "prohibited",
        )
        # Avoid flagging benign "transfer complete" / "opening" replies
        if code is not None and 200 <= code < 300:
            return False
        if any(p in low for p in phrases):
            return True
        if ("virus" in low or "infected" in low) and code is not None and code >= 400:
            return True
        return False

    def _ftp_dos_probe_row(
        self,
        ftp: ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit,
        *,
        probe_label: str,
        remote_filename: str,
        payload: bytes,
    ) -> FtpDosProbeRow:
        o = self._ftp_stor_binary_timed(ftp, "STOR " + remote_filename, payload)
        stor_line = (o.reply_line or o.error or "").strip() or None
        blocked = False
        if o.ok:
            blocked = self._ftp_dos_policy_block_hit(o.reply_code, o.reply_line)
        else:
            blocked = self._ftp_dos_policy_block_hit(o.reply_code, o.error)

        noop_ok: bool | None = None
        noop_err: str | None = None
        noop_elapsed: float | None = None
        if o.ok and not blocked:
            t_n0 = time.perf_counter()
            try:
                ftp.voidcmd("NOOP")
                noop_ok = True
            except Exception as e_noop:
                try:
                    _ = ftp.pwd()
                    noop_ok = True
                    noop_err = None
                except Exception as e_pwd:
                    noop_ok = False
                    noop_err = f"{e_noop}; PWD fallback: {e_pwd}"
            noop_elapsed = time.perf_counter() - t_n0

        delete_ok = False
        delete_err: str | None = None
        if o.ok:
            try:
                ftp.delete(remote_filename)
                delete_ok = True
            except ftplib.Error as e:
                delete_err = str(e)

        delta = o.delta_last_byte_to_226_seconds
        suspected = False
        if o.timed_out:
            suspected = True
        elif o.ok and not blocked:
            if delta is not None and delta >= FTP_DOS_DELTA_WARN_SEC:
                suspected = True
            if noop_elapsed is not None and noop_elapsed >= FTP_DOS_NOOP_WARN_SEC:
                suspected = True
            if noop_ok is False:
                suspected = True

        row = FtpDosProbeRow(
            probe_label,
            remote_filename,
            len(payload),
            o.ok,
            o.error,
            stor_line,
            o.reply_code,
            o.total_seconds,
            delta,
            noop_ok,
            noop_err,
            noop_elapsed,
            blocked,
            suspected,
            o.timed_out,
            delete_ok,
            delete_err,
        )
        self._ftp_dos_emit_probe(row)
        return row

    def _ftp_dos_section_title(self, r: FtpDosProbeRow) -> str:
        label = r.probe_label or ""
        if "XML" in label:
            return "XML entity expansion"
        if "Overlap" in label:
            return "Large zip bomb"
        if "Decompression" in label or r.remote_filename.endswith(".zip"):
            return "Zip bomb"
        return r.remote_filename

    def _ftp_dos_reply(self, r: FtpDosProbeRow) -> tuple[str, str]:
        """Indented server reply. Color only when the transfer stalled or was not confirmed."""
        if r.timed_out:
            return "VULN", "timed out"
        snippet = (r.stor_reply_snippet or "").strip()
        if r.blocked_by_policy:
            base = snippet or (str(r.reply_code) if r.reply_code is not None else "rejected")
            if not base.endswith("(rejected)"):
                base = f"{base} (rejected)"
            return "TEXT", base
        if not r.stor_ok:
            if self._ftp_text_is_unconfirmed(r.stor_error):
                return "WARNING", "was not confirmed"
            detail = self._snip(snippet or r.stor_error or "failed")
            if r.reply_code is not None and not detail.startswith(str(r.reply_code)):
                detail = f"{r.reply_code} {detail}".strip()
            return "WARNING", detail
        base = snippet or (
            f"{r.reply_code} Transfer complete" if r.reply_code is not None else "226 Transfer complete"
        )
        extra: list[str] = []
        bullet = "TEXT"
        if r.background_processing_suspected:
            bullet = "WARNING"
            delay = r.delta_last_byte_to_226_seconds
            if delay is not None and delay >= FTP_DOS_DELTA_WARN_SEC:
                extra.append(f"reply {delay:.1f}s")
            if r.noop_ok is False:
                extra.append("control connection failed")
            elif (
                r.noop_elapsed_seconds is not None
                and r.noop_elapsed_seconds >= FTP_DOS_NOOP_WARN_SEC
            ):
                extra.append(f"NOOP {r.noop_elapsed_seconds:.1f}s")
        note = "accepted" if not extra else "accepted, " + ", ".join(extra)
        return bullet, f"{base} ({note})"

    def _ftp_dos_print_probe(self, r: FtpDosProbeRow, *, debug: bool) -> None:
        """Section title, file name, then the server reply. -vv trace sits under the file name."""
        self._flush_terminal()
        self._tprint(self._ftp_dos_section_title(r), "TITLE")
        self._tprint(r.remote_filename, "TEXT", indent=8)
        self._flush_terminal()
        if debug:
            if r.timed_out:
                recv = "timed out"
            else:
                recv = self._snip(r.stor_reply_snippet or r.stor_error or "(no reply)")
            self._dbg(f"STOR {r.remote_filename} → {recv}", indent=12)
            if r.stor_ok and not r.blocked_by_policy:
                if r.noop_ok is True:
                    self._dbg("NOOP → OK", indent=12)
                elif r.noop_ok is False:
                    self._dbg(f"NOOP → {self._snip(r.noop_error)}", indent=12)
            if r.stor_ok:
                if r.delete_ok:
                    self._dbg(f"DELE {r.remote_filename} → OK", indent=12)
                elif r.delete_error:
                    self._dbg(f"DELE {r.remote_filename} → {self._snip(r.delete_error)}", indent=12)
            self._flush_terminal()
        bullet, text = self._ftp_dos_reply(r)
        self._tprint(text, bullet, indent=12)
        if r.stor_ok and not r.delete_ok:
            self._tprint("Cleanup failed", "WARNING", indent=12)
        self._flush_terminal()

    def _ftp_dos_emit_probe(self, r: FtpDosProbeRow) -> None:
        if self.use_json:
            return
        self._ftp_dos_print_probe(r, debug=True)
        self._dos_probes_emitted = True

    def test_ftp_processing_resilience_probes(self) -> FtpDosAuditResult:
        """PTL-SVC-FTP-PROC-DOS: one login, sequential STOR probes, timing + NOOP stability."""
        self._dos_probes_emitted = False
        tmo = float(getattr(self.args, "ftp_dos_timeout", 30.0) or 30.0)
        large = bool(getattr(self.args, "ftp_dos_large", False))
        zip_mode = "overlap" if large else "deflate"
        creds = self._get_path_enum_creds()
        if creds is None:
            self._dbg("DOS skipped: no credentials")
            return FtpDosAuditResult(
                tmo,
                zip_mode,
                "",
                tuple(),
                self._missing_login_line(),
                False,
                False,
            )

        ftp = self.connect()

        try:
            ftp.login(creds.user, creds.passw)
            self._dbg(f"LOGIN {creds.user!r} → OK")
        except Exception as e:
            self._dbg(f"LOGIN {creds.user!r} → failed: {self._snip(str(e))}")
            try:
                ftp.close()
            except Exception:
                pass
            return FtpDosAuditResult(
                tmo,
                zip_mode,
                creds.user,
                tuple(),
                f"LOGIN failed: {e}",
                False,
                False,
            )

        if getattr(ftp, "sock", None) is not None:
            ftp.sock.settimeout(tmo)

        rows: list[FtpDosProbeRow] = []
        rows.append(
            self._ftp_dos_probe_row(
                ftp,
                probe_label="billion_laughs.xml (XML DoS)",
                remote_filename="billion_laughs.xml",
                payload=BILLION_LAUGHS_XML.encode("utf-8"),
            )
        )
        rows.append(
            self._ftp_dos_probe_row(
                ftp,
                probe_label=(
                    "zipbomb-overlap.zip (Overlap DoS)"
                    if large
                    else "zipbomb.zip (Decompression DoS)"
                ),
                remote_filename="zipbomb-overlap.zip" if large else "zipbomb.zip",
                payload=build_huge_zip_bomb() if large else build_full_zip_bomb(),
            )
        )

        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass

        probes_t = tuple(rows)
        all_blocked = bool(probes_t) and all(r.blocked_by_policy for r in probes_t)
        suspected = any(r.background_processing_suspected for r in probes_t)
        if all_blocked:
            suspected = False

        nb = sum(1 for r in probes_t if r.blocked_by_policy)
        nsus = sum(1 for r in probes_t if r.background_processing_suspected)
        ntimeout = sum(1 for r in probes_t if r.timed_out)
        detail = (
            f"{tmo}s cap per socket op; ZIP={zip_mode}; probes={len(probes_t)}; "
            f"policy_blocked={nb}; post_processing_signals={nsus}; STOR_timeouts={ntimeout}."
        )
        return FtpDosAuditResult(
            tmo,
            zip_mode,
            creds.user,
            probes_t,
            detail,
            suspected,
            all_blocked,
        )

    def _on_brute_success(self, cred: Creds) -> None:
        """Callback for real-time streaming of found credentials (thread-safe).
        Streams login success immediately; permissions come from access_check() in output()."""
        with self._output_lock:
            self._ptprint_raw(
                f"user: {cred.user}, password: {shown_password(cred.passw)}",
                bullet_type="TEXT",
                condition=not self.use_json,
                indent=4,
            )

    def _enum_expect_pwd(self, base: str, path: str) -> str:
        raw = path.replace("\\", "/")
        if raw.startswith("/"):
            return self._chroot_norm_pwd(raw)
        return self._chroot_norm_pwd(posixpath.join(self._chroot_norm_pwd(base), raw))

    def _enum_show(self, lines: list[str], row: PathEnumResult | None) -> None:
        """-vv lines, then the hit. One path stays together across threads."""
        if self.use_json:
            return
        lock = getattr(self, "_enumpath_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._enumpath_lock = lock
        with lock:
            for line in lines:
                self._dbg(line)
            if row is not None:
                self._tprint(self._enumpath_text(row), "VULN")
                if row.cleanup_failed:
                    self._tprint("Cleanup failed", "WARNING")
                self._enumpath_streamed = True
            self._flush_terminal()

    @staticmethod
    def _enumpath_text(row: PathEnumResult) -> str:
        if row.login_directory:
            if row.writable and row.deletable:
                return f"{row.path} allows write and delete"
            if row.writable:
                return f"{row.path} allows write"
        if row.is_directory:
            if row.writable and row.deletable:
                return f"{row.path} is reachable (write and delete allowed)"
            if row.writable:
                return f"{row.path} is reachable (write allowed)"
            return f"{row.path} is reachable"
        bits: list[str] = []
        if row.size is not None:
            bits.append(f"{row.size} B")
        if row.mtime:
            bits.append(f"mtime {row.mtime}")
        if row.readable:
            bits.append("readable")
        if not bits:
            return f"{row.path} exists"
        return f"{row.path} ({', '.join(bits)})"

    def _enum_claim_dir(self, pwd: str) -> bool:
        """True the first time this directory is used for the write/delete probe."""
        key = self._chroot_norm_pwd(pwd)
        seen = getattr(self, "_enum_write_seen", None)
        if seen is None:
            seen = set()
            self._enum_write_seen = seen
        lock = getattr(self, "_enumpath_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._enumpath_lock = lock
        with lock:
            if key in seen:
                return False
            seen.add(key)
            return True

    def _enum_mark_seen(self, pwd: str) -> bool:
        """True the first time this directory is entered."""
        key = self._chroot_norm_pwd(pwd)
        with self._enumpath_lock:
            seen = self._enum_visited
            if key in seen:
                return False
            seen.add(key)
            return True

    def _enum_file_path(self, directory: str, name: str) -> str:
        base = self._chroot_norm_pwd(directory)
        leaf = name.replace("\\", "/").lstrip("/")
        if base == "/":
            return f"/{leaf}"
        return f"{base.rstrip('/')}/{leaf}"

    def _enum_try_file(self, ftp: ftplib.FTP, directory: str, name: str) -> PathEnumResult | None:
        """SIZE only after CWD 550. A CWD that does not fail that way is not a file."""
        notes: list[str] = []
        parent = self._chroot_norm_pwd(directory)
        try:
            ftp.cwd(name)
            try:
                pwd_after = ftp.pwd()
            except (ftplib.Error, AttributeError):
                pwd_after = ""
        except ftplib.error_perm as exc:
            err = str(exc)
            notes.append(f"CWD {name!r} → {self._snip(err)}")
            if "550" not in err:
                self._enum_show(notes, None)
                return None
        except ftplib.Error as exc:
            notes.append(f"CWD {name!r} → {self._snip(str(exc))}")
            self._enum_show(notes, None)
            return None
        else:
            expect = self._enum_expect_pwd(parent, name)
            shown = pwd_after or "unknown"
            if pwd_after and self._chroot_norm_pwd(pwd_after) == expect:
                notes.append(f"CWD {name!r} → directory pwd={pwd_after}")
            else:
                notes.append(f"CWD {name!r} → pwd={shown} (not {expect})")
            self._enum_show(notes, None)
            back: list[str] = []
            self._enum_leave(ftp, parent, back)
            self._enum_show(back, None)
            return None
        try:
            size = ftp.size(name)
        except ftplib.Error as exc:
            notes.append(f"SIZE {name!r} → {self._snip(str(exc))}")
            self._enum_show(notes, None)
            return None
        notes.append(f"SIZE {name!r} → {size} B")
        mtime = None
        try:
            reply = ftp.sendcmd(f"MDTM {name}")
            notes.append(f"MDTM {name!r} → {self._snip(reply)}")
            parts = reply.split()
            if len(parts) > 1 and parts[0].startswith("213"):
                mtime = parts[1]
        except ftplib.Error as exc:
            notes.append(f"MDTM {name!r} → {self._snip(str(exc))}")
        readable = self._enum_readable(ftp, name, notes)
        row = PathEnumResult(
            path=self._enum_file_path(directory, name),
            exists=True,
            is_directory=False,
            size=size,
            mtime=mtime,
            readable=readable,
        )
        self._enum_show(notes, row)
        return row

    def _enum_leave(self, ftp: ftplib.FTP, parent: str, notes: list[str]) -> None:
        """Return to the parent directory. CDUP first, then the absolute path."""
        parent_n = self._chroot_norm_pwd(parent)
        try:
            now = self._chroot_norm_pwd(ftp.pwd())
        except (ftplib.Error, AttributeError):
            now = ""
        if now == parent_n:
            return
        try:
            ftp.sendcmd("CDUP")
            after = ftp.pwd()
            notes.append(f"CDUP → pwd={after}")
            if self._chroot_norm_pwd(after) == parent_n:
                return
        except Exception as exc:
            notes.append(f"CDUP → {self._snip(str(exc))}")
        try:
            ftp.cwd(parent)
            after = ftp.pwd()
            notes.append(f"CWD {parent!r} → pwd={after}")
        except Exception as exc:
            notes.append(f"CWD {parent!r} → {self._snip(str(exc))}")

    def _enum_login_directory(self, creds: Creds, files: list[str]) -> list[PathEnumResult]:
        """Write/delete once in the start directory, then the file wordlist there."""
        ftp = self.connect()
        notes: list[str] = []
        rows: list[PathEnumResult] = []
        try:
            ftp.login(creds.user, creds.passw)
            base_path = getattr(self.args, "base_path", "") or ""
            if base_path:
                try:
                    ftp.cwd(base_path)
                except ftplib.Error as exc:
                    notes.append(f"CWD {base_path!r} → {self._snip(str(exc))}")
            try:
                pwd = ftp.pwd()
            except (ftplib.Error, AttributeError):
                pwd = base_path or "/"
            self._enum_mark_seen(pwd)
            if self._enum_claim_dir(pwd):
                probe = ".ptsrvtester_probe_" + secrets.token_hex(4)
                writable, deletable, cleanup_failed = self._enum_write_delete(ftp, probe, notes)
                if writable:
                    row = PathEnumResult(
                        path=self._chroot_norm_pwd(pwd),
                        exists=True,
                        is_directory=True,
                        size=None,
                        writable=writable,
                        deletable=deletable,
                        cleanup_failed=cleanup_failed,
                        login_directory=True,
                    )
                    self._enum_show(notes, row)
                    rows.append(row)
                    notes = []
                else:
                    self._enum_show(notes, None)
                    notes = []
            for name in files:
                hit = self._enum_try_file(ftp, pwd, name)
                if hit is not None:
                    rows.append(hit)
            return rows
        except Exception as exc:
            notes.append(f"Login directory → {self._snip(str(exc))}")
            self._enum_show(notes, None)
            return rows
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def _enum_write_delete(
        self, ftp: ftplib.FTP, stor_path: str, notes: list[str]
    ) -> tuple[bool, bool, bool]:
        """Prove write and delete with our own file. Returns writable, deletable, cleanup_failed."""
        try:
            ftp.storbinary(f"STOR {stor_path}", BytesIO(b"ptsrvtester\n"))
        except Exception as exc:
            notes.append(f"STOR {stor_path!r} → {self._snip(str(exc))}")
            return False, False, False
        notes.append(f"STOR {stor_path!r} → OK")
        try:
            ftp.delete(stor_path)
        except Exception as exc:
            notes.append(f"DELE {stor_path!r} → {self._snip(str(exc))}")
            return True, False, True
        notes.append(f"DELE {stor_path!r} → OK")
        return True, True, False

    def _enum_readable(self, ftp: ftplib.FTP, path: str, notes: list[str]) -> bool:
        """RETR a short prefix and discard it. The file body is not logged."""
        try:
            ftp.voidcmd("TYPE I")
        except Exception:
            pass
        try:
            sock = ftp.transfercmd(f"RETR {path}")
        except Exception as exc:
            notes.append(f"RETR {path!r} → {self._snip(str(exc))}")
            return False
        got = b""
        try:
            sock.settimeout(8)
            try:
                got = sock.recv(2048) or b""
            except Exception:
                pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        try:
            ftp.voidresp()
            notes.append(f"RETR {path!r} → OK")
            return True
        except Exception as exc:
            if got:
                notes.append(f"RETR {path!r} → OK")
                return True
            notes.append(f"RETR {path!r} → {self._snip(str(exc))}")
            return False

    def _enum_enter_dirs(
        self,
        ftp: ftplib.FTP,
        here: str,
        dir_names: list[str],
        file_names: list[str],
        depth_left: int,
        out: list[PathEnumResult],
    ) -> None:
        """Try directory names from the current directory, then step back with CDUP."""
        if depth_left < 1:
            return
        here_n = self._chroot_norm_pwd(here)
        for name in dir_names:
            notes: list[str] = []
            try:
                ftp.cwd(name)
                try:
                    pwd_after = ftp.pwd()
                except (ftplib.Error, AttributeError):
                    pwd_after = ""
            except ftplib.error_perm as exc:
                notes.append(f"CWD {name!r} → {self._snip(str(exc))}")
                self._enum_show(notes, None)
                continue
            except ftplib.Error as exc:
                notes.append(f"CWD {name!r} → {self._snip(str(exc))}")
                self._enum_show(notes, None)
                continue
            expect = self._enum_expect_pwd(here_n, name)
            landed = bool(pwd_after) and self._chroot_norm_pwd(pwd_after) == expect
            if not landed:
                shown = pwd_after or "unknown"
                notes.append(f"CWD {name!r} → pwd={shown} (not {expect})")
                self._enum_show(notes, None)
                back: list[str] = []
                self._enum_leave(ftp, here_n, back)
                self._enum_show(back, None)
                continue
            if not self._enum_mark_seen(pwd_after):
                notes.append(f"CWD {name!r} → pwd={pwd_after} (already visited)")
                self._enum_show(notes, None)
                back = []
                self._enum_leave(ftp, here_n, back)
                self._enum_show(back, None)
                continue
            notes.append(f"CWD {name!r} → directory pwd={pwd_after}")
            writable = deletable = cleanup_failed = False
            if self._enum_claim_dir(pwd_after):
                probe = ".ptsrvtester_probe_" + secrets.token_hex(4)
                writable, deletable, cleanup_failed = self._enum_write_delete(ftp, probe, notes)
            row = PathEnumResult(
                path=self._chroot_norm_pwd(pwd_after),
                exists=True,
                is_directory=True,
                size=None,
                writable=writable,
                deletable=deletable,
                cleanup_failed=cleanup_failed,
            )
            self._enum_show(notes, row)
            out.append(row)
            for fname in file_names:
                hit = self._enum_try_file(ftp, pwd_after, fname)
                if hit is not None:
                    out.append(hit)
            if depth_left > 1:
                self._enum_enter_dirs(ftp, pwd_after, dir_names, file_names, depth_left - 1, out)
            back = []
            self._enum_leave(ftp, here_n, back)
            self._enum_show(back, None)

    def _path_enum_worker(
        self, chunk: list[str], creds: Creds, files: list[str], depth: int
    ) -> list[PathEnumResult]:
        """One connection. Directory names from the start directory, then CDUP back."""
        results: list[PathEnumResult] = []
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            base_path = getattr(self.args, "base_path", "") or ""
            if base_path:
                try:
                    ftp.cwd(base_path)
                except ftplib.Error:
                    pass
            try:
                here = ftp.pwd()
            except (ftplib.Error, AttributeError):
                here = base_path or "/"
            self._enum_enter_dirs(ftp, here, chunk, files, depth, results)
        finally:
            try:
                ftp.close()
            except Exception:
                pass
        return results

    def path_enumeration(
        self, creds: Creds, directories: list[str], files: list[str], depth: int
    ) -> list[PathEnumResult]:
        """Directory wordlist from the start directory. Files inside each directory entered."""
        if not directories and not files:
            return []
        depth = max(1, int(depth))
        self._enumpath_lock = threading.Lock()
        self._enum_write_seen = set()
        self._enum_visited = set()
        self._enumpath_streamed = False
        enum_threads = max(1, int(getattr(self.args, "threads", None) or 5))
        self._dbg(
            f"Path enumeration: {len(directories)} directories, {len(files)} files, "
            f"depth={depth}, threads={enum_threads}"
        )
        self._flush_terminal()
        flat: list[PathEnumResult] = list(self._enum_login_directory(creds, files))
        if not directories:
            return flat
        k, m = divmod(len(directories), enum_threads)
        chunks = [
            directories[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)]
            for i in range(enum_threads)
        ]
        chunks = [c for c in chunks if c]

        def worker(chunk: list[str]) -> list[PathEnumResult]:
            return self._path_enum_worker(chunk, creds, files, depth)

        pt = ptthreads.PtThreads(print_errors=False)
        raw_returns = pt.threads(chunks, worker, min(len(chunks), enum_threads)) or []
        seen = {row.path for row in flat}
        for r in raw_returns:
            if isinstance(r, list):
                for p in r:
                    if p.path not in seen:
                        seen.add(p.path)
                        flat.append(p)
        return flat

    @staticmethod
    def _norm_ftp_reply_text(s: str) -> str:
        if not s:
            return ""
        t = s.strip().lower()
        t = re.sub(r"\s+", " ", t)
        return t[:240]

    _FTP_USER_ENUM_TIMING_WARMUP = 3

    @staticmethod
    def _user_enum_reply_template(line: str, username: str | None = None) -> str:
        """Drop an echoed account name. Do not rewrite phrases such as 'user logged in'."""
        t = re.sub(r"\s+", " ", (line or "").strip()).lower()
        if username:
            u = username.strip().lower()
            if u:
                t = re.sub(rf"\bfor\s+{re.escape(u)}\b", "for <u>", t)
                t = t.replace(f"'{u}'", "'<u>'").replace(f'"{u}"', '"<u>"')
                if len(u) > 8 and "for <u>" not in t:
                    for n in range(min(len(u), 180), 8, -1):
                        if re.search(rf"\bfor\s+{re.escape(u[:n])}\b", t):
                            t = re.sub(rf"\bfor\s+{re.escape(u[:n])}\b", "for <u>", t)
                            break
        t = re.sub(r"'[^'\n]+'", "'<u>'", t)
        t = re.sub(r'"[^"\n]+"', '"<u>"', t)
        t = re.sub(r"\bfor\s+\S+", "for <u>", t)
        return t[:240]

    @staticmethod
    def _user_enum_timing_after_warmup(ms_ordered: list[float], max_drop: int) -> list[float]:
        """Drop first max_drop samples when cohort is long enough (TCP/TLS cold start, jitter)."""
        if len(ms_ordered) > max_drop:
            return ms_ordered[max_drop:]
        return list(ms_ordered)

    def _user_enum_keepalive_tarpitting_hint(self, ok_rows: list[FtpUserEnumProbeRow]) -> bool:
        """True when PASS-phase latency tends to grow across sequential probes (one session)."""
        ordered = sorted(ok_rows, key=lambda r: r.probe_index)
        seq = [
            float(r.pass_elapsed_ms)
            for r in ordered
            if r.pass_elapsed_ms is not None and r.user_reply_code in (331, 332)
        ]
        if len(seq) < 4:
            return False
        diffs = [seq[i + 1] - seq[i] for i in range(len(seq) - 1)]
        need = max(2, (len(diffs) + 1) // 2)
        return sum(1 for d in diffs if d > 35.0) >= need

    def _user_enum_dbg_reply(self, code: int | None, line: str) -> str:
        shown = self._snip(line)
        if code is None or shown.startswith(str(code)):
            return shown
        return f"{code} {shown}".strip()

    def _user_enum_trace(self, msg: str, output) -> None:
        if not getattr(self.args, "debug", False) or self.use_json:
            return
        if output is None:
            self._dbg(msg)
            return
        line = out_if(msg, "ADDITIONS", True, colortext=True, indent=0)
        if line:
            output.add_string_to_output(line.rstrip("\n"))

    @staticmethod
    def _user_enum_progress_label(username: str, kind: str) -> str:
        if kind != "wordlist":
            return kind
        if len(username) > 24:
            return username[:21] + "..."
        return username

    def _user_enum_show(self, progress: ThreadedProgress, output, username: str, kind: str) -> None:
        progress.flush(output, repaint=False)
        progress.advance(label=self._user_enum_progress_label(username, kind))

    def _ftp_parse_reply_line(self, msg: str) -> tuple[int | None, str]:
        s = str(msg).strip()
        if len(s) >= 3 and s[:3].isdigit():
            return int(s[:3]), s
        return None, s

    def _ftp_user_pass_probe(
        self,
        ftp: ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit,
        username: str,
        wrong_pass: str,
        probe_kind: str,
        probe_index: int,
        output=None,
    ) -> FtpUserEnumProbeRow:
        ucode: int | None = None
        uline = ""
        shown = username if len(username) <= 32 else username[:29] + "..."
        try:
            uresp = ftp.sendcmd("USER " + username)
            ucode, uline = self._ftp_parse_reply_line(uresp)
        except ftplib.error_perm as e:
            raw = str(e.args[0]) if e.args else str(e)
            ucode, uline = self._ftp_parse_reply_line(raw)
        except Exception as e:
            self._user_enum_trace(
                f"{shown!r}: USER failed {self._snip(str(e))}", output
            )
            return FtpUserEnumProbeRow(
                username, probe_kind, None, "", None, "", None, False, str(e), probe_index
            )

        pcode: int | None = None
        pline = ""
        pass_ms: float | None = None

        if ucode in (331, 332):
            t0 = time.perf_counter()
            try:
                presp = ftp.sendcmd("PASS " + wrong_pass)
                pcode, pline = self._ftp_parse_reply_line(presp)
            except ftplib.error_perm as e:
                raw = str(e.args[0]) if e.args else str(e)
                pcode, pline = self._ftp_parse_reply_line(raw)
            except Exception as e:
                pass_ms = (time.perf_counter() - t0) * 1000
                self._user_enum_trace(
                    f"{shown!r}: USER {self._user_enum_dbg_reply(ucode, uline)}; "
                    f"PASS error {self._snip(str(e))}",
                    output,
                )
                return FtpUserEnumProbeRow(
                    username, probe_kind, ucode, uline, None, "", pass_ms, False, str(e), probe_index
                )
            pass_ms = (time.perf_counter() - t0) * 1000
        else:
            pcode = ucode
            pline = uline

        conn_ok = True
        try:
            ftp.voidcmd("NOOP")
        except Exception:
            conn_ok = False

        self._user_enum_trace(
            f"{shown!r}: USER {self._user_enum_dbg_reply(ucode, uline)}; "
            f"PASS {self._user_enum_dbg_reply(pcode, pline)}",
            output,
        )
        return FtpUserEnumProbeRow(
            username, probe_kind, ucode, uline, pcode, pline, pass_ms, conn_ok, None, probe_index
        )

    def _user_enum_close(self, ftp) -> None:
        if ftp is None:
            return
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass

    def _user_enum_one(
        self,
        ftp,
        item: tuple[str, str, int],
        wrong_pass: str,
        output,
        *,
        own_connection: bool,
    ) -> FtpUserEnumProbeRow:
        username, kind, pidx = item
        session = ftp
        if own_connection or session is None:
            session = self.connect()
            own_connection = True
        try:
            return self._ftp_user_pass_probe(session, username, wrong_pass, kind, pidx, output)
        finally:
            if own_connection:
                self._user_enum_close(session)

    def _user_enum_run(
        self,
        work: list[tuple[str, str, int]],
        wrong_pass: str,
        threads: int,
        *,
        keep_alive: bool,
    ) -> list[FtpUserEnumProbeRow]:
        progress = ThreadedProgress(
            len(work),
            enabled=not self.use_json,
            indent=4,
            bar_indent=4,
        )
        rows: list[FtpUserEnumProbeRow] = []
        baseline = [item for item in work if item[1] == "control_invalid_random"]
        rest = [item for item in work if item[1] != "control_invalid_random"]
        ftp = None

        def drain(items: list[tuple[str, str, int]]) -> None:
            nonlocal ftp
            for item in items:
                output = progress.new_output()
                if keep_alive and ftp is None:
                    ftp = self.connect()
                row = self._user_enum_one(
                    ftp, item, wrong_pass, output, own_connection=not keep_alive
                )
                rows.append(row)
                if keep_alive and (row.error or not row.connection_ok_after):
                    self._user_enum_close(ftp)
                    ftp = None
                self._user_enum_show(progress, output, item[0], item[1])

        try:
            drain(baseline)
            if keep_alive or threads <= 1 or len(rest) <= 1:
                drain(rest)
                return rows

            rows_lock = threading.Lock()

            def work_item(item, output) -> str:
                username, kind, _pidx = item
                row = self._user_enum_one(None, item, wrong_pass, output, own_connection=True)
                with rows_lock:
                    rows.append(row)
                return self._user_enum_progress_label(username, kind)

            progress.run(rest, work_item, threads, finalize=False)
            rows.sort(key=lambda row: row.probe_index)
            return rows
        finally:
            if keep_alive:
                self._user_enum_close(ftp)
            progress.finalize()

    def _analyze_user_enum_result(
        self,
        rows: list[FtpUserEnumProbeRow],
        do_timing: bool,
        *,
        used_keep_alive: bool,
        parallel_threads: int,
    ) -> FtpUserEnumResult:
        ok_rows = [r for r in rows if r.error is None]
        user_codes = sorted({r.user_reply_code for r in ok_rows if r.user_reply_code is not None})
        tnotes: list[str] = []

        pass_norms: list[str] = []
        for r in ok_rows:
            if r.user_reply_code in (331, 332) and r.pass_reply_line:
                pass_norms.append(self._user_enum_reply_template(r.pass_reply_line, r.username))
        distinct_pass_norms = tuple(sorted(set(pass_norms)))

        sim_min: float | None = None
        enumeration_suspected = False
        detail_parts: list[str] = []

        baseline = next(
            (self._user_enum_probe_signature(r) for r in ok_rows if r.probe_kind == "control_invalid_random"),
            None,
        )
        wordlist_rows = [r for r in ok_rows if r.probe_kind == "wordlist"]
        if baseline is not None:
            odd = [r for r in wordlist_rows if self._user_enum_probe_signature(r) != baseline]
            if odd:
                enumeration_suspected = True
                detail_parts.append("A listed name got a different reply from a name that does not exist.")
        elif len({self._user_enum_probe_signature(r) for r in wordlist_rows}) >= 2:
            enumeration_suspected = True
            detail_parts.append("Listed names did not all get the same reply.")

        timing_anomaly = False
        tarpit_hint = False
        if do_timing and used_keep_alive:
            tarpit_hint = self._user_enum_keepalive_tarpitting_hint(ok_rows)

        timing_control_median_ms: float | None = None
        timing_wordlist_median_ms: float | None = None
        slow_samples: list[tuple[str, float]] = []

        if do_timing:
            wu = self._FTP_USER_ENUM_TIMING_WARMUP
            cand_rows = [
                r
                for r in ok_rows
                if r.probe_kind == "wordlist"
                and r.pass_elapsed_ms is not None
                and r.user_reply_code in (331, 332)
            ]
            cand_rows.sort(key=lambda r: r.probe_index)
            cand_ms = [float(r.pass_elapsed_ms) for r in cand_rows]
            ctrl_rows = [
                r
                for r in ok_rows
                if r.probe_kind.startswith("control")
                and r.pass_elapsed_ms is not None
                and r.user_reply_code in (331, 332)
            ]
            ctrl_rows.sort(key=lambda r: r.probe_index)
            ctrl_ms = [float(r.pass_elapsed_ms) for r in ctrl_rows]

            would_time_anomaly = False
            time_detail = ""
            if len(cand_ms) >= 2 and len(ctrl_ms) >= 1:
                cand_adj = self._user_enum_timing_after_warmup(cand_ms, wu)
                ctrl_adj = self._user_enum_timing_after_warmup(ctrl_ms, wu)
                if len(cand_ms) > wu or len(ctrl_ms) > wu:
                    tnotes.append("timingMedianAfterWarmupDropFirst3PerCohort")
                if len(cand_adj) >= 1 and len(ctrl_adj) >= 1:
                    mc = float(statistics.median(ctrl_adj))
                    mw = float(statistics.median(cand_adj))
                    timing_control_median_ms = mc
                    timing_wordlist_median_ms = mw
                    thr = mc * 2.0 + 20.0
                    for r in cand_rows:
                        if r.pass_elapsed_ms is not None:
                            ms = float(r.pass_elapsed_ms)
                            if ms > thr:
                                slow_samples.append((r.username, ms))
                    if mw > mc * 2.0 + 20.0:
                        would_time_anomaly = True
                        time_detail = (
                            f"PASS-phase median latency (post-warmup): wordlist {mw:.1f} ms vs controls {mc:.1f} ms "
                            "(--user-enum-timing; median, not mean)."
                        )
            if parallel_threads > 1:
                tnotes.append("parallelConnectionsTimingComparedByGlobalProbeOrder")

            if would_time_anomaly and tarpit_hint:
                timing_anomaly = False
                slow_samples.clear()
                detail_parts.append(
                    "Timing comparison suppressed: sequential PASS latency grows like tarpitting/delay policy, "
                    "not a reliable user-oracle signal in --user-enum-keep-alive mode."
                )
                tnotes.append("timingSuppressedSuspectedTarpitting")
            elif would_time_anomaly:
                timing_anomaly = True
                detail_parts.append(time_detail)
                if used_keep_alive and not tarpit_hint:
                    tnotes.append("keepAliveMayStillTarpitWithoutMonotonicPattern")

        accepted_wrong_pass = [
            r
            for r in ok_rows
            if r.user_reply_code in (331, 332)
            and r.pass_reply_code is not None
            and 200 <= r.pass_reply_code < 300
        ]
        if accepted_wrong_pass and len(accepted_wrong_pass) == len(ok_rows):
            detail_parts.append(
                "Wrong password was accepted for every name, including controls. That is not a username oracle."
            )
        elif accepted_wrong_pass:
            enumeration_suspected = True
            shown = ", ".join(repr(r.username) for r in accepted_wrong_pass[:6])
            detail_parts.append(
                f"Wrong password was accepted for {shown} and refused for other names."
            )

        if not detail_parts:
            detail_parts.append("No strong USER/PASS differentiation observed in this sample (heuristic).")

        return FtpUserEnumResult(
            probes=tuple(rows),
            fixed_password_marker="(fixed_wrong_password_sent)",
            distinct_user_reply_codes=tuple(user_codes),
            distinct_pass_reply_norms=distinct_pass_norms,
            enumeration_suspected=enumeration_suspected,
            timing_anomaly_suspected=timing_anomaly,
            pass_text_similarity_min=sim_min,
            detail=" ".join(detail_parts),
            timing_notes=tuple(tnotes),
            timing_control_median_ms=timing_control_median_ms,
            timing_wordlist_median_ms=timing_wordlist_median_ms,
            timing_slow_usernames_ms=tuple(slow_samples),
        )

    def test_user_enumeration(self) -> FtpUserEnumResult:
        """PTL-SVC-FTP-USRENUM: USER then fixed wrong PASS; control users + optional timing / keep-alive."""
        user = getattr(self.args, "user", None)
        users_file = getattr(self.args, "users", None) or getattr(self.args, "user_enum_wordlist", None)
        if user is None and not users_file:
            raise ValueError("USRENUM requires -u/--user or -U/--users")
        raw = text_or_file(user, users_file)
        names = [ln.strip() for ln in raw if ln.strip() and not ln.strip().startswith("#")]
        if not names:
            raise ValueError("USRENUM requires -u/--user or -U/--users")
        ue_mx = int(getattr(self.args, "user_enum_max", 0) or 0)
        if ue_mx > 0:
            names = names[:ue_mx]
        hex8 = secrets.token_hex(4)
        work: list[tuple[str, str, int]] = []
        pidx = 0
        # Known-nonexistent name first, so later names are compared to that reply.
        work.append((f"enumtest_invalid_{hex8}", "control_invalid_random", pidx))
        pidx += 1
        for n in names:
            work.append((n, "wordlist", pidx))
            pidx += 1

        pwd = (
            getattr(self.args, "password", None)
            or getattr(self.args, "user_enum_password", None)
            or "PtsrvUEnumWrongPass!77~"
        )
        keep_alive = bool(getattr(self.args, "user_enum_keep_alive", False))
        threads = max(1, int(getattr(self.args, "threads", None) or 1))
        do_timing = bool(getattr(self.args, "user_enum_timing", False))
        rows = self._user_enum_run(work, pwd, threads, keep_alive=keep_alive)

        return self._analyze_user_enum_result(
            rows, do_timing, used_keep_alive=keep_alive, parallel_threads=threads
        )

    def _parse_pasv_ip(self, reply: str) -> str | None:
        """Extract IP from PASV 227 reply. RFC 1123: format varies, scan for digits."""
        m = re.search(r"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", reply)
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
        return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private ranges (10.x, 172.16-31.x, 192.168.x)."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False

    def _modes_line(self, text: str, bullet: str) -> None:
        if self.use_json:
            return
        self._tprint(text, bullet)
        self._modes_streamed = True
        self._flush_terminal()

    def _modes_report_passive(self, ok: bool, err: str | None) -> None:
        if ok:
            self._modes_line("Passive: available", "NOTVULN")
        elif self._ftp_text_is_unconfirmed(err):
            self._modes_line("Passive timed out (not confirmed)", "WARNING")
        else:
            self._modes_line("Passive: not available", "VULN")

    def _modes_report_active(self, ok: bool, err: str | None) -> None:
        if ok:
            self._modes_line("Active: available", "NOTVULN")
        elif self._ftp_server_reply(err):
            self._modes_line("Active: not available", "VULN")
        else:
            self._modes_line("Active timed out (not confirmed)", "WARNING")
            self._modes_line(
                "Active mode was not confirmed. A timeout can also mean the tester is behind NAT or a firewall.",
                "WARNING",
            )

    def test_modes(self, creds: Creds) -> ModesResult:
        """
        Test passive and active mode availability. Requires data transfer (LIST/NLST).
        Checks PASV response for IP leakage (internal IP advertised when connecting from outside).
        """
        passive_ok = False
        active_ok = False
        passive_error: str | None = None
        active_error: str | None = None
        pasv_ip_leak: str | None = None
        target_ip = self.args.target.ip
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            try:
                target_ip = socket.gethostbyname(target_ip)
            except Exception:
                target_ip = ""

        # Test passive mode + IP leakage
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            ftp.set_pasv(True)
            self._dbg(f"LOGIN {creds.user!r} → OK (passive probe)")
            # Get raw 227 reply for IP leakage check. ftplib processes PASV internally in
            # transfercmd(), but sendcmd("PASV") returns the raw response string for parsing.
            # voidcmd("PASV") would also return it for 2xx; we use sendcmd for explicitness.
            try:
                reply = ftp.sendcmd("PASV")
                self._dbg(f"PASV → {self._snip(reply)}")
                pasv_ip = self._parse_pasv_ip(reply)
                # IP leak: PASV IP differs from target (e.g. internal IP exposed when connecting from outside)
                if pasv_ip and target_ip and pasv_ip != target_ip:
                    pasv_ip_leak = pasv_ip
                    self._modes_line(
                        f"PASV Internal IP Leak: server advertised {pasv_ip_leak}",
                        "VULN",
                    )
            except ftplib.Error as e:
                self._dbg(f"PASV → failed: {self._snip(str(e))}")
            try:
                ach = AccessCheckHelper()
                ftp.dir(ach.read_callback)
                passive_ok = True
                self._dbg("LIST (PASV) → OK")
            except Exception as e:
                passive_error = str(e).strip()
                self._dbg(f"LIST (PASV) → failed: {self._snip(passive_error)}")
        except Exception as e:
            passive_error = str(e).strip()
            self._dbg(f"Passive probe failed: {self._snip(passive_error)}")
        finally:
            try:
                ftp.close()
            except Exception:
                pass
        self._modes_report_passive(passive_ok, passive_error)

        # Test active mode (new connection)
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            ftp.set_pasv(False)
            self._dbg(f"LOGIN {creds.user!r} → OK (active probe)")
            try:
                ach = AccessCheckHelper()
                ftp.dir(ach.read_callback)
                active_ok = True
                self._dbg("LIST (PORT/active) → OK")
            except Exception as e:
                active_error = str(e).strip()
                self._dbg(f"LIST (PORT/active) → failed: {self._snip(active_error)}")
        except Exception as e:
            active_error = str(e).strip()
            self._dbg(f"Active probe failed: {self._snip(active_error)}")
        finally:
            try:
                ftp.close()
            except Exception:
                pass
        self._modes_report_active(active_ok, active_error)

        return ModesResult(
            passive_ok=passive_ok,
            active_ok=active_ok,
            pasv_ip_leak=pasv_ip_leak,
            passive_error=passive_error,
            active_error=active_error,
        )

    def _pasv_list_data_port_once(self, ftp: ftplib.FTP) -> tuple[int | None, str | None]:
        """
        Force passive mode, open a real LIST data channel, return the server's TCP data port
        (client socket getpeername), then drain listing and complete the transfer.
        """
        ftp.set_pasv(True)
        to = 20.0
        old_to = None
        try:
            try:
                old_to = ftp.sock.gettimeout()
                ftp.sock.settimeout(to)
            except Exception:
                pass
            sock = ftp.transfercmd("LIST")
            port: int | None = None
            try:
                sock.settimeout(to)
                peer = sock.getpeername()
                if isinstance(peer, tuple) and len(peer) >= 2:
                    port = int(peer[1])
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            try:
                ftp.voidresp()
            except ftplib.Error as e:
                # Some servers still completed data; port observation remains useful
                if port is None:
                    return None, str(e).strip() or repr(e)
            return port, None
        except Exception as e:
            err = str(e).strip() or type(e).__name__
            try:
                ftp.close()
            except Exception:
                pass
            return None, err
        finally:
            try:
                if old_to is not None:
                    ftp.sock.settimeout(old_to)
            except Exception:
                pass

    def test_pasv_port_range_audit(
        self, creds: Creds, sample_count: int, max_span_threshold: int
    ) -> PasvPortRangeResult:
        """
        PTL-SVC-FTP-PASIVE: several separate control connections, each login + passive LIST;
        if observed port spread (max-min) exceeds max_span_threshold, flag wide passive range
        (firewall rule burden / larger attack surface).
        """
        min_for_verdict = 4
        probes: list[PasvPortRangeProbe] = []
        ports_ok: list[int] = []

        self._flush_terminal()
        for i in range(sample_count):
            ftp = self.connect()
            err: str | None = None
            port: int | None = None
            try:
                ftp.login(creds.user, creds.passw)
                port, err = self._pasv_list_data_port_once(ftp)
                if port is not None:
                    ports_ok.append(port)
                    self._dbg(f"PASV sample {i + 1} → {port}")
                else:
                    self._dbg(f"PASV sample {i + 1} failed — {self._snip(err) or 'no data port'}")
            except Exception as e:
                err = str(e).strip() or type(e).__name__
                self._dbg(f"PASV sample {i + 1} failed — {self._snip(err)}")
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass
                self._flush_terminal()
            probes.append(PasvPortRangeProbe(sample_index=i, data_port=port, error=err))

        ok_t = tuple(ports_ok)
        if len(ports_ok) < min_for_verdict:
            detail = (
                f"Only {len(ports_ok)}/{sample_count} passive LIST transfers yielded a data port; "
                "need at least 4 for a spread estimate. Check connectivity, TLS vs plaintext, or permissions."
            )
            result = PasvPortRangeResult(
                probes=tuple(probes),
                successful_ports=ok_t,
                min_port=min(ports_ok) if ports_ok else None,
                max_port=max(ports_ok) if ports_ok else None,
                observed_span=(max(ports_ok) - min(ports_ok)) if len(ports_ok) >= 2 else None,
                max_span_threshold=max_span_threshold,
                min_samples_for_verdict=min_for_verdict,
                wide_passive_range=False,
                inconclusive=True,
                detail=detail,
            )
            self._pasvport_report(result)
            return result

        lo, hi = min(ports_ok), max(ports_ok)
        span = hi - lo
        wide = span > max_span_threshold
        detail = (
            f"Observed data ports across {len(ports_ok)} successful sample(s): "
            f"min={lo}, max={hi}, span={span} (threshold maxSpan={max_span_threshold}). "
            + (
                "Spread is large in this run — firewall policies may need a very wide passive port allow-list."
                if wide
                else "Spread stays within the configured threshold (prefer also documenting the server's configured passive range in policy)."
            )
        )
        result = PasvPortRangeResult(
            probes=tuple(probes),
            successful_ports=ok_t,
            min_port=lo,
            max_port=hi,
            observed_span=span,
            max_span_threshold=max_span_threshold,
            min_samples_for_verdict=min_for_verdict,
            wide_passive_range=wide,
            inconclusive=False,
            detail=detail,
        )
        self._pasvport_report(result)
        return result

    def _pasvport_line(self, text: str, bullet: str) -> None:
        if self.use_json:
            return
        self._tprint(text, bullet)
        self._pasvport_streamed = True
        self._flush_terminal()

    def _pasvport_report(self, ppr: PasvPortRangeResult) -> None:
        """One verdict. Sample lines are -vv only and already flushed."""
        n_ok = len(ppr.successful_ports)
        n_all = len(ppr.probes)
        if ppr.inconclusive:
            self._pasvport_line(
                f"Passive port range was not confirmed ({n_ok}/{n_all} samples)",
                "WARNING",
            )
            return
        span = ppr.observed_span
        bound = ppr.max_span_threshold
        if ppr.wide_passive_range:
            self._pasvport_line(
                f"Passive port range {ppr.min_port}-{ppr.max_port} is not limited (span {span} > {bound})",
                "VULN",
            )
            return
        self._pasvport_line(
            f"Passive port range {ppr.min_port}-{ppr.max_port} is limited (span {span} ≤ {bound})",
            "NOTVULN",
        )

    def _conn_limits_read220_quit(self, sock: socket.socket) -> tuple[bool, str | None]:
        sock.settimeout(12.0)
        buf = b""
        try:
            while b"\n" not in buf and len(buf) < 8192:
                c = sock.recv(2048)
                if not c:
                    return False, "EOF before banner line"
                buf += c
                if b"220" in buf:
                    break
            if b"220" not in buf:
                return False, "no 220 in initial response"
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
            return True, None
        except Exception as e:
            return False, str(e)

    def _conn_limits_drain_banner_raw(self, sock: socket.socket) -> tuple[bool, str | None]:
        sock.settimeout(12.0)
        buf = b""
        while b"220" not in buf and len(buf) < 16384:
            c = sock.recv(2048)
            if not c:
                return False, "EOF before 220"
            buf += c
        return True, None

    @staticmethod
    def _conn_limits_readline_socket(
        sock: socket.socket, buf: bytearray, timeout: float = 30.0
    ) -> tuple[str, bool]:
        sock.settimeout(timeout)
        while True:
            if b"\n" in buf:
                idx = buf.index(b"\n")
                raw = bytes(buf[: idx + 1])
                del buf[: idx + 1]
                return raw.decode(errors="replace").strip(), False
            chunk = sock.recv(4096)
            if not chunk:
                return "", True
            buf.extend(chunk)

    def _conn_limits_pasv_pre_auth_session(self, attempts: int) -> ConnLimitsPasvSpam:
        if attempts <= 0:
            return ConnLimitsPasvSpam(0, 0, 0, 0, None, None)
        host = self.args.target.ip
        port = self.args.target.port
        n227 = n530 = nother = 0
        last: str | None = None
        err: str | None = None
        try:
            if self.args.starttls:
                ftp = ftplib.FTP_TLS()
                ftp.connect(host, port, timeout=10)
                ftp.sock.settimeout(25.0)
                ftp.auth()
                for _ in range(attempts):
                    r = ftp.sendcmd("PASV")
                    last = r[:200]
                    c = self._reply_code(r)
                    if c == 227:
                        n227 += 1
                    elif c == 530:
                        n530 += 1
                    else:
                        nother += 1
                try:
                    ftp.quit()
                except Exception:
                    ftp.close()
                return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, None)

            if self.args.tls:
                ctx = ssl.create_default_context()
                raw = socket.create_connection((host, port), timeout=10)
                ss = ctx.wrap_socket(raw, server_hostname=host)
                okb, e = self._conn_limits_drain_banner_raw(ss)
                if not okb:
                    try:
                        ss.close()
                    except Exception:
                        pass
                    return ConnLimitsPasvSpam(0, 0, 0, 0, None, e or "banner")
                buf = bytearray()
                for _ in range(attempts):
                    ss.sendall(b"PASV\r\n")
                    line, eof = self._conn_limits_readline_socket(ss, buf, 25.0)
                    if eof and not line:
                        err = "EOF during PASV phase"
                        break
                    last = line[:200]
                    c = self._reply_code(line) if line else None
                    if c == 227:
                        n227 += 1
                    elif c == 530:
                        n530 += 1
                    else:
                        nother += 1
                try:
                    ss.sendall(b"QUIT\r\n")
                except Exception:
                    pass
                try:
                    ss.close()
                except Exception:
                    pass
                return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, err)

            raw = socket.create_connection((host, port), timeout=10)
            okb, e = self._conn_limits_drain_banner_raw(raw)
            if not okb:
                try:
                    raw.close()
                except Exception:
                    pass
                return ConnLimitsPasvSpam(0, 0, 0, 0, None, e or "banner")
            buf = bytearray()
            for _ in range(attempts):
                raw.sendall(b"PASV\r\n")
                line, eof = self._conn_limits_readline_socket(raw, buf, 25.0)
                if eof and not line:
                    err = "EOF during PASV phase"
                    break
                last = line[:200]
                c = self._reply_code(line) if line else None
                if c == 227:
                    n227 += 1
                elif c == 530:
                    n530 += 1
                else:
                    nother += 1
            try:
                raw.sendall(b"QUIT\r\n")
            except Exception:
                pass
            try:
                raw.close()
            except Exception:
                pass
            return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, err)
        except Exception as e:
            return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, str(e))

    def _conn_limits_pasv_post_auth_session(self, creds: Creds, attempts: int) -> ConnLimitsPasvSpam:
        if attempts <= 0:
            return ConnLimitsPasvSpam(0, 0, 0, 0, None, None)
        n227 = n530 = nother = 0
        last: str | None = None
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            ftp.sock.settimeout(25.0)
            for _ in range(attempts):
                r = ftp.sendcmd("PASV")
                last = r[:200]
                c = self._reply_code(r)
                if c == 227:
                    n227 += 1
                elif c == 530:
                    n530 += 1
                else:
                    nother += 1
            try:
                ftp.quit()
            except Exception:
                ftp.close()
            return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, None)
        except Exception as e:
            try:
                ftp.close()
            except Exception:
                pass
            return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, str(e))

    _CONN_COUNT_DEFAULT = 100
    _CONN_COUNT_THRESHOLD = 50
    _CONN_DURATION_DEFAULT = 300.0
    _CONN_DURATION_RECOMMENDED = 180.0
    _CONN_PREAUTH_IDLE_OK = 60.0
    _CONN_POST_IDLE_OK = 180.0
    _CONN_BAN_MIN = 30.0
    _CONN_AUTH_PARALLEL_MAX = 30
    _CONN_AUTH_VULN = 10
    _CONN_PASV_ATTEMPTS = 18

    def _connlim_line(self, text: str, bullet: str) -> None:
        if self.use_json:
            return
        self._tprint(text, bullet)
        self._connlim_streamed = True
        self._flush_terminal()

    def _connlim_idle_line(self, label: str, measured: float, exceeded: bool, threshold: float, cap: float) -> bool:
        """Print one idle verdict. Return True when --duration is too short to decide."""
        if exceeded and cap <= threshold:
            return True
        secs = int(round(measured))
        bound = int(threshold)
        if measured > threshold:
            self._connlim_line(f"{label}: {secs}s (> {bound}s)", "VULN")
        else:
            self._connlim_line(f"{label}: {secs}s (≤ {bound}s)", "NOTVULN")
        return False

    def _conn_limits_watch_idle(
        self,
        ftp: ftplib.FTP,
        cap: float,
        live,
    ) -> tuple[float, bool]:
        """Wait until the server closes the control connection or ``cap`` seconds pass."""
        sock = ftp.sock
        start = time.perf_counter()
        buf = b""
        while True:
            elapsed = time.perf_counter() - start
            if elapsed >= cap:
                return cap, True
            live(elapsed)
            wait = min(0.5, cap - elapsed)
            try:
                if isinstance(sock, ssl.SSLSocket) and sock.pending() > 0:
                    readable = True
                else:
                    readable = bool(select.select([sock], [], [], wait)[0])
            except (OSError, ValueError):
                return time.perf_counter() - start, False
            if not readable:
                continue
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, TimeoutError, ssl.SSLWantReadError):
                continue
            except Exception:
                return time.perf_counter() - start, False
            if not chunk:
                return time.perf_counter() - start, False
            buf += chunk
            if b"421" in buf or b"426" in buf:
                return time.perf_counter() - start, False

    def test_connection_limits_audit(self, creds_post: Creds | None) -> ConnLimitsAuditResult:
        """Connection count, refusal backoff, idle time, and FTP PASV allocation."""
        count = max(1, int(getattr(self.args, "conn_limit_count", None) or self._CONN_COUNT_DEFAULT))
        cap = float(getattr(self.args, "conn_limit_duration", None) or self._CONN_DURATION_DEFAULT)
        if cap <= 0:
            cap = self._CONN_DURATION_DEFAULT
        threads = max(1, int(getattr(self.args, "threads", None) or 1))
        show = not self.use_json and sys.stdout.isatty()
        live_dirty = False
        print_lock = threading.Lock()

        def _end_live() -> None:
            nonlocal live_dirty
            if not live_dirty:
                return
            with print_lock:
                if live_dirty:
                    sys.stdout.write("\033[2K\r")
                    sys.stdout.flush()
                    live_dirty = False

        def _write_live(text: str) -> None:
            nonlocal live_dirty
            if not show:
                return
            line = get_colored_text(f"    {text}", "ADDITIONS")
            with print_lock:
                sys.stdout.write(f"\033[2K\r{line}")
                sys.stdout.flush()
                live_dirty = True

        def _vv(msg: str) -> None:
            nonlocal live_dirty
            with print_lock:
                if live_dirty and bool(getattr(self.args, "debug", False)):
                    sys.stdout.write("\033[2K\r")
                    sys.stdout.flush()
                    live_dirty = False
            self._dbg(msg)
            if bool(getattr(self.args, "debug", False)):
                self._flush_terminal()

        def _close_all(rows: list) -> None:
            for ftp in rows:
                try:
                    ftp.close()
                except Exception:
                    pass
            rows.clear()

        if self.args.tls:
            crypto_mode = "implicit_tls"
        elif self.args.starttls:
            crypto_mode = "starttls"
        else:
            crypto_mode = "plain"

        held: list[ftplib.FTP] = []
        est_err = est_disc = est_timeout = 0
        first_err: str | None = None
        connected = 0
        pasv_pre = ConnLimitsPasvSpam(0, 0, 0, 0, None, None)
        pasv_post: ConnLimitsPasvSpam | None = None
        idle_pre_r = ConnLimitsIdleProbe(False, 0.0, False, "not run")
        idle_post_r: ConnLimitsIdleProbe | None = None
        slow_r = ConnLimitsSlowAuth(False, 0.0, None, None, "not used")
        risk: list[str] = []
        duration_warned = False

        try:
            _vv("Connection limits test")
            _vv(
                f"Target {self.args.target.ip}:{self.args.target.port} — up to {count} parallel "
                f"sessions ({threads} thread{'s' if threads != 1 else ''}), idle wait {cap:.0f}s."
            )
            _write_live("Connected: 0")

            def _open_one(idx: int) -> tuple[int, ftplib.FTP | None, BaseException | None]:
                try:
                    return idx, self.connect(), None
                except Exception as exc:
                    return idx, None, exc

            def _fail_kind(exc: BaseException) -> tuple[str, str]:
                cause = exc.__cause__ or exc
                # ftplib raises bare EOFError when the peer closes before a full banner line.
                if isinstance(cause, EOFError):
                    return "disconnect", "peer closed connection"
                detail = str(cause).strip() or type(cause).__name__
                if isinstance(cause, (socket.timeout, TimeoutError)):
                    return "timeout", detail
                msg = detail.lower()
                if "timed out" in msg or "timeout" in msg:
                    return "timeout", detail
                if isinstance(cause, (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
                    return "disconnect", detail
                if any(k in msg for k in ("refused", "reset", "closed", "broken pipe", "aborted", "421", "too many", "eof")):
                    return "disconnect", detail
                return "error", detail

            workers = min(threads, count)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(_open_one, i) for i in range(1, count + 1)]
                for fut in as_completed(futures):
                    idx, ftp, exc = fut.result()
                    if ftp is not None:
                        held.append(ftp)
                        _write_live(f"Connected: {len(held)}")
                        continue
                    kind, detail = _fail_kind(exc or OSError("connect failed"))
                    if first_err is None:
                        first_err = detail
                    if kind == "timeout":
                        est_timeout += 1
                    elif kind == "disconnect":
                        est_disc += 1
                    else:
                        est_err += 1
                    _vv(f"Connection #{idx} failed — {kind} ({detail})")
            connected = len(held)
            dropped = 0
            for ftp in held:
                sock = getattr(ftp, "sock", None)
                if sock is None:
                    dropped += 1
                    continue
                try:
                    sock.setblocking(False)
                    peeked = sock.recv(1, socket.MSG_PEEK)
                    sock.setblocking(True)
                    if peeked == b"":
                        dropped += 1
                except BlockingIOError:
                    try:
                        sock.setblocking(True)
                    except Exception:
                        pass
                except Exception:
                    dropped += 1
            _end_live()
            _vv(f"Ramp-up: {connected}/{count} connections established.")
            if not self.use_json:
                self.out(f"Established {connected} connections", "TITLE", indent=4)
                self.out(f"Errors {est_err} connections", "TITLE", indent=4)
                self.out(f"Refused at connect {est_disc} connections", "TITLE", indent=4)
                self.out(f"Timeouts during connecting {est_timeout}", "TITLE", indent=4)
                self.out(f"Dropped while idle {dropped} connections", "TITLE", indent=4)
                self._connlim_streamed = True
                self._flush_terminal()
            if connected <= 0:
                self._connlim_line(
                    "Could not open any connection. Connection limit was not tested.",
                    "WARNING",
                )
            elif count <= self._CONN_COUNT_THRESHOLD and connected >= count:
                self._connlim_line(
                    f"Cannot determine connection limit (count too low, Recommended > {self._CONN_COUNT_THRESHOLD})",
                    "WARNING",
                )
            elif connected > self._CONN_COUNT_THRESHOLD:
                self._connlim_line(f"Connection limit > {self._CONN_COUNT_THRESHOLD}", "VULN")
                risk.append(f"Connection limit > {self._CONN_COUNT_THRESHOLD}")
            else:
                self._connlim_line(f"Connection limit ≤ {self._CONN_COUNT_THRESHOLD}", "NOTVULN")

            if 0 < connected < count:
                start_rl = time.perf_counter()
                banned_for = cap
                exceeded_ban = True
                _write_live("Ban / backoff window: 00:00")
                while True:
                    elapsed = time.perf_counter() - start_rl
                    if elapsed >= cap:
                        break
                    _write_live(
                        f"Ban / backoff window: {int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
                    )
                    try:
                        probe = self.connect()
                        banned_for = time.perf_counter() - start_rl
                        exceeded_ban = False
                        try:
                            probe.quit()
                        except Exception:
                            probe.close()
                        break
                    except Exception:
                        time.sleep(0.5)
                _end_live()
                if exceeded_ban:
                    self._connlim_line(f"Reconnect blocked for {int(cap)}s+ after refusal", "NOTVULN")
                elif banned_for < self._CONN_BAN_MIN:
                    self._connlim_line("Ban/backoff window shorter than 30s", "VULN")
                    risk.append("Ban/backoff window shorter than 30s")
                else:
                    self._connlim_line("Reconnect allowed after ban", "NOTVULN")

            if connected > 0:
                pasv_pre = self._conn_limits_pasv_pre_auth_session(self._CONN_PASV_ATTEMPTS)
                _vv(
                    f"PASV before login: 227={pasv_pre.reply227} "
                    f"530={pasv_pre.reply530} other={pasv_pre.reply_other}"
                )
                if _conn_limits_pasv_pre_suspect(pasv_pre):
                    self._connlim_line(
                        "PASV before login is not limited (allocates data ports)",
                        "VULN",
                    )
                    risk.append("PASV before login is not limited (allocates data ports)")

                idle_ftp = None
                try:
                    idle_ftp = self.connect()
                    elapsed, exceeded = self._conn_limits_watch_idle(
                        idle_ftp,
                        cap,
                        lambda sec: _write_live(
                            f"Pre-auth idle: {int(sec // 60):02d}:{int(sec % 60):02d}"
                        ),
                    )
                except Exception as exc:
                    elapsed, exceeded = 0.0, False
                    _vv(f"Pre-auth idle: connect failed — {exc}")
                finally:
                    if idle_ftp is not None:
                        try:
                            idle_ftp.close()
                        except Exception:
                            pass
                _end_live()
                state = "still open" if exceeded else "closed"
                _vv(f"Pre-auth idle: {state} after {elapsed:.0f}s")
                idle_pre_r = ConnLimitsIdleProbe(True, elapsed, not exceeded, state)
                if self._connlim_idle_line(
                    "Pre-auth idle timeout", elapsed, exceeded, self._CONN_PREAUTH_IDLE_OK, cap
                ):
                    self._connlim_line(
                        f"Duration too low to evaluate idle timeouts (Recommended > {int(self._CONN_DURATION_RECOMMENDED)})",
                        "WARNING",
                    )
                    duration_warned = True
                if not exceeded and elapsed <= self._CONN_PREAUTH_IDLE_OK:
                    pass
                elif exceeded and elapsed > self._CONN_PREAUTH_IDLE_OK:
                    risk.append(f"Pre-auth idle timeout: {int(round(elapsed))}s")

            if creds_post is not None and connected > 0:
                accepted = 0
                stopped = False
                _write_live("Authenticated sessions: 0")
                auth_held: list[ftplib.FTP] = []
                for _ in range(self._CONN_AUTH_PARALLEL_MAX):
                    time.sleep(0.15)
                    try:
                        aim = self.connect()
                        aim.login(creds_post.user, creds_post.passw)
                        auth_held.append(aim)
                        accepted += 1
                        _write_live(f"Authenticated sessions: {accepted}")
                    except Exception:
                        stopped = True
                        break
                _end_live()
                _close_all(auth_held)
                _vv(f"Authenticated sessions: {accepted}")
                if accepted >= self._CONN_AUTH_VULN and not stopped:
                    self._connlim_line(
                        f"No per-account session limit ({accepted} parallel logins accepted)",
                        "VULN",
                    )
                    risk.append(f"No per-account session limit ({accepted} parallel logins accepted)")
                elif stopped and accepted == 0:
                    self._connlim_line("LOGIN failed — check credentials or account lockout", "NOTVULN")
                elif stopped:
                    self._connlim_line("Per-account session limit is enforced", "NOTVULN")
                else:
                    self._connlim_line("Per-account session count below threshold", "NOTVULN")

                if accepted > 0:
                    pasv_post = self._conn_limits_pasv_post_auth_session(
                        creds_post, self._CONN_PASV_ATTEMPTS
                    )
                    _vv(
                        f"PASV after login: 227={pasv_post.reply227} "
                        f"530={pasv_post.reply530} other={pasv_post.reply_other}"
                    )
                    if _conn_limits_pasv_post_suspect(pasv_post):
                        self._connlim_line("PASV after login is not limited", "VULN")
                        risk.append("PASV after login is not limited")
                    elif pasv_post.error and self._ftp_text_is_unconfirmed(pasv_post.error):
                        self._connlim_line("PASV after login was not confirmed", "WARNING")
                    else:
                        self._connlim_line("PASV after login is limited", "NOTVULN")

                    post_ftp = None
                    try:
                        post_ftp = self.connect()
                        post_ftp.login(creds_post.user, creds_post.passw)
                        elapsed_p, exceeded_p = self._conn_limits_watch_idle(
                            post_ftp,
                            cap,
                            lambda sec: _write_live(
                                f"Post-login idle: {int(sec // 60):02d}:{int(sec % 60):02d}"
                            ),
                        )
                    except Exception as exc:
                        elapsed_p, exceeded_p = 0.0, False
                        _vv(f"Post-login idle: failed — {exc}")
                    finally:
                        if post_ftp is not None:
                            try:
                                post_ftp.close()
                            except Exception:
                                pass
                    _end_live()
                    state_p = "still open" if exceeded_p else "closed"
                    _vv(f"Post-login idle: {state_p} after {elapsed_p:.0f}s")
                    note = "NOOP succeeded after idle window (weak idle kick)" if exceeded_p else state_p
                    idle_post_r = ConnLimitsIdleProbe(True, elapsed_p, not exceeded_p, note)
                    if self._connlim_idle_line(
                        "Post-login idle timeout",
                        elapsed_p,
                        exceeded_p,
                        self._CONN_POST_IDLE_OK,
                        cap,
                    ) and not duration_warned:
                        self._connlim_line(
                            f"Duration too low to evaluate idle timeouts (Recommended > {int(self._CONN_DURATION_RECOMMENDED)})",
                            "WARNING",
                        )
                    if exceeded_p and elapsed_p > self._CONN_POST_IDLE_OK:
                        risk.append(f"Post-login idle timeout: {int(round(elapsed_p))}s")
        finally:
            _end_live()
            _close_all(held)

        parallel = ConnLimitsParallelOutcome(
            attempted=count,
            succeeded=connected,
            failed=max(0, count - connected),
            error_samples=(first_err[:240],) if first_err else (),
        )
        detail = "; ".join(risk) if risk else "No insufficient connection limit in this run."
        return ConnLimitsAuditResult(
            crypto_mode=crypto_mode,
            parallel=parallel,
            sequential=ConnLimitsSequentialOutcome(0, 0, 0, 0.0, ()),
            pasv_pre_auth=pasv_pre,
            pasv_post_auth=pasv_post,
            idle_pre_auth=idle_pre_r,
            slow_auth=slow_r,
            idle_post_auth=idle_post_r,
            limits_insufficient_suspected=bool(risk),
            risk_factors=tuple(risk),
            detail=detail,
        )

    _CHROOT_STRONG_CWD_PATHS = frozenset(
        {
            "/etc",
            "/root",
            "/proc",
            "/sys",
            "/var/log",
            "/var/www",
            "/srv",
            "/dev",
            "/boot",
            "/bin",
            "/sbin",
            "/usr",
        }
    )
    _CHROOT_DOTDOT_MAX_STEPS = 32
    _CHROOT_REL_STEPS = 8

    @staticmethod
    def _chroot_norm_pwd(p: str) -> str:
        s = (p or "").strip().strip('"').strip("'")
        if not s:
            return "/"
        return posixpath.normpath(s.replace("\\", "/"))

    @staticmethod
    def _chroot_strict_ancestor(ancestor: str, descendant: str) -> bool:
        a = FtpEngine._chroot_norm_pwd(ancestor)
        d = FtpEngine._chroot_norm_pwd(descendant)
        if a == d:
            return False
        if a == "/":
            return d != "/"
        base = a.rstrip("/")
        return d.startswith(base + "/")

    def _chroot_cwd_landed(self, path: str, row: ChrootCwdProbeRow) -> bool:
        """CWD reached the path only when PWD afterwards is that path."""
        if not row.success or not row.pwd_after:
            return False
        return self._chroot_norm_pwd(row.pwd_after) == self._chroot_norm_pwd(path)

    def _chroot_probe_cwd_fresh(self, creds: Creds, path: str, probe_id: str) -> ChrootCwdProbeRow:
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            ftp.cwd(path)
            pa = ftp.pwd()
            self._dbg(f"CWD {path!r} → OK pwd={pa}")
            return ChrootCwdProbeRow(probe_id, path, True, pa, None)
        except ftplib.error_perm as e:
            self._dbg(f"CWD {path!r} → {self._snip(str(e))}")
            return ChrootCwdProbeRow(probe_id, path, False, None, str(e).strip()[:400])
        except Exception as e:
            self._dbg(f"CWD {path!r} → {self._snip(str(e))}")
            return ChrootCwdProbeRow(probe_id, path, False, None, str(e).strip()[:400])
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def _chroot_rel_path(self, tail: str) -> str:
        return ("../" * self._CHROOT_REL_STEPS) + tail.lstrip("/")

    @staticmethod
    def _chroot_write_outside(login_pwd: str, landed: str, name: str) -> bool:
        """True when the created directory is above the login directory. A relative reply stays inside it."""
        landed_n = FtpEngine._chroot_norm_pwd(landed)
        if posixpath.basename(landed_n) != name or not landed_n.startswith("/"):
            return False
        login_n = FtpEngine._chroot_norm_pwd(login_pwd)
        if login_n == "/" or landed_n == login_n:
            return False
        return not landed_n.startswith(login_n.rstrip("/") + "/")

    def _chroot_probe_retr_fresh(self, creds: Creds, path: str) -> tuple[bool, str | None, int]:
        """RETR the path and discard the body. Success is a completed transfer."""
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            total = 0

            def _take(chunk: bytes) -> None:
                nonlocal total
                total += len(chunk)

            ftp.retrbinary("RETR " + path, _take)
            self._dbg(f"RETR {path!r} → {total} bytes")
            return True, None, total
        except Exception as e:
            self._dbg(f"RETR {path!r} → {self._snip(str(e))}")
            return False, str(e).strip()[:240], 0
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def _chroot_rmd_probe(self, creds: Creds, paths: list[str], name: str) -> bool:
        targets: list[str] = []
        for path in paths:
            if not path:
                continue
            if posixpath.basename(self._chroot_norm_pwd(path)) != name:
                continue
            if path not in targets:
                targets.append(path)
        if not targets:
            return False
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            for path in targets:
                try:
                    ftp.rmd(path)
                    self._dbg(f"RMD {path!r} → OK")
                    return True
                except Exception as e:
                    self._dbg(f"RMD {path!r} → {self._snip(str(e))}")
            return False
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def _chroot_probe_mkd_escape(self, creds: Creds, login_pwd: str) -> bool:
        """MKD a throwaway directory via ../. Remove it. A line is printed only when it landed outside."""
        name = ".ptsrvtester_probe_" + secrets.token_hex(4)
        rel = self._chroot_rel_path(name)
        ftp = self.connect()
        created = False
        outside = False
        landed: str | None = None
        try:
            ftp.login(creds.user, creds.passw)
            try:
                made = ftp.mkd(rel)
                created = True
                shown = made.strip() if isinstance(made, str) else "OK"
                self._dbg(f"MKD {rel!r} → {shown}")
                if isinstance(made, str) and made.strip():
                    landed = made.strip().strip('"').strip("'")
            except Exception as e:
                self._dbg(f"MKD {rel!r} → {self._snip(str(e))}")
                if not self.use_json:
                    self._flush_terminal()
                return False
            try:
                ftp.cwd(rel)
                pwd_now = ftp.pwd()
                self._dbg(f"CWD {rel!r} → OK pwd={pwd_now}")
                if self._chroot_write_outside(login_pwd, pwd_now, name):
                    outside = True
                    landed = pwd_now
            except Exception as e:
                self._dbg(f"CWD {rel!r} → {self._snip(str(e))}")
            if landed and self._chroot_write_outside(login_pwd, landed, name):
                outside = True
        finally:
            try:
                ftp.close()
            except Exception:
                pass
        if outside:
            self._chroot_line("../" + name, "VULN")
        elif not self.use_json:
            self._flush_terminal()
        if not created:
            return False
        removed = self._chroot_rmd_probe(creds, [rel, landed or ""], name)
        if not removed:
            self._chroot_line("Cleanup failed", "WARNING")
        elif not self.use_json:
            self._flush_terminal()
        return outside

    def _chroot_dotdot_chain(self, creds: Creds, max_steps: int | None = None) -> ChrootDotdotResult:
        """
        Repeated CWD ... Early exit: server rejects .., PWD stops changing (at chroot/top),
        or PWD read fails. max_steps is only a safety cap for abnormal symlink loops.
        """
        cap = max_steps if max_steps is not None else self._CHROOT_DOTDOT_MAX_STEPS
        ftp = self.connect()
        p0 = ""
        try:
            ftp.login(creds.user, creds.passw)
            p0 = ftp.pwd()
            self._dbg(f"PWD initial={p0!r}")
            last = p0
            steps = 0
            reason = "max_steps_cap"
            for _ in range(cap):
                try:
                    ftp.cwd("..")
                except ftplib.error_perm:
                    reason = "cwd_dotdot_rejected"
                    break
                except Exception as e:
                    reason = f"error:{type(e).__name__}"
                    break
                try:
                    pn = ftp.pwd()
                except Exception:
                    reason = "pwd_failed"
                    break
                if self._chroot_norm_pwd(pn) == self._chroot_norm_pwd(last):
                    reason = "pwd_unchanged"
                    break
                last = pn
                steps += 1
            self._dbg(f"CWD .. chain: steps={steps} reason={reason} pwd_final={last!r}")
            return ChrootDotdotResult(steps, p0, last, reason)
        except Exception as e:
            return ChrootDotdotResult(0, p0 or "?", None, str(e)[:160])
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def _chroot_line(self, text: str, bullet: str) -> None:
        if self.use_json:
            return
        self._tprint(text, bullet)
        self._chroot_streamed = True
        self._flush_terminal()

    def test_chroot_audit(self, creds: Creds) -> ChrootAuditResult:
        """PTL-SVC-FTP-CHROOT: CWD to host-like paths, .. chain, RETR of passwd/shadow, MKD via ../."""
        ftp0 = self.connect()
        pwd_initial: str
        try:
            ftp0.login(creds.user, creds.passw)
            pwd_initial = ftp0.pwd()
        finally:
            try:
                ftp0.close()
            except Exception:
                pass

        base_probes: list[tuple[str, str]] = [
            ("slash", "/"),
            ("etc", "/etc"),
            ("root_dir", "/root"),
            ("home", "/home"),
            ("proc", "/proc"),
            ("sys", "/sys"),
            ("var_log", "/var/log"),
            ("var_www", "/var/www"),
            ("srv", "/srv"),
            ("dev", "/dev"),
            ("bin", "/bin"),
            ("sbin", "/sbin"),
            ("usr", "/usr"),
            ("boot", "/boot"),
            ("tmp", "/tmp"),
        ]

        rows: list[ChrootCwdProbeRow] = []
        confirmed = False
        for pid, pth in base_probes:
            row = self._chroot_probe_cwd_fresh(creds, pth, pid)
            rows.append(row)
            if row.success or not self._ftp_text_is_unconfirmed(row.error_or_reply):
                confirmed = True
            if pth in self._CHROOT_STRONG_CWD_PATHS or pth == "/home":
                if self._chroot_cwd_landed(pth, row):
                    self._chroot_line(pth, "VULN")
                elif row.error_or_reply and self._ftp_text_is_unconfirmed(row.error_or_reply):
                    if not self.use_json:
                        self._flush_terminal()
                else:
                    self._chroot_line(pth, "NOTVULN")
            elif not self.use_json:
                self._flush_terminal()

        dot = self._chroot_dotdot_chain(creds)
        pwd0n = self._chroot_norm_pwd(pwd_initial)
        pwd_fn = self._chroot_norm_pwd(dot.pwd_final or pwd_initial)
        dotdot_escape = False
        if dot.steps_ok > 0 and dot.pwd_final and pwd0n and pwd_fn:
            if self._chroot_strict_ancestor(pwd_fn, pwd0n) and pwd_fn != "/":
                dotdot_escape = True
        if dotdot_escape:
            self._chroot_line("..", "VULN")
        elif not self.use_json:
            self._flush_terminal()

        home_parent_ok = any(self._chroot_cwd_landed("/home", r) for r in rows if r.path == "/home")
        home_sibling = bool(
            home_parent_ok
            and pwd0n.startswith("/home/")
            and pwd0n.rstrip("/") != "/home"
        )

        strong_hits: list[str] = []
        for r in rows:
            if self._chroot_cwd_landed(r.path, r) and r.path in self._CHROOT_STRONG_CWD_PATHS:
                strong_hits.append(r.path)

        passwd_ok, passwd_err, passwd_sz = self._chroot_probe_retr_fresh(creds, "/etc/passwd")
        if passwd_ok or not self._ftp_text_is_unconfirmed(passwd_err):
            confirmed = True
        if passwd_ok:
            self._chroot_line("/etc/passwd", "VULN")
        elif not self.use_json:
            self._flush_terminal()
        passwd_rel_ok, passwd_rel_err, passwd_rel_sz = self._chroot_probe_retr_fresh(
            creds, self._chroot_rel_path("etc/passwd")
        )
        if passwd_rel_ok or not self._ftp_text_is_unconfirmed(passwd_rel_err):
            confirmed = True
        if passwd_rel_ok and not passwd_ok:
            self._chroot_line("../etc/passwd", "VULN")
        elif not self.use_json:
            self._flush_terminal()
        shadow_ok, shadow_err, shadow_sz = self._chroot_probe_retr_fresh(creds, "/etc/shadow")
        if shadow_ok or not self._ftp_text_is_unconfirmed(shadow_err):
            confirmed = True
        if shadow_ok:
            self._chroot_line("/etc/shadow", "VULN")
        elif not self.use_json:
            self._flush_terminal()
        shadow_rel_ok, shadow_rel_err, shadow_rel_sz = self._chroot_probe_retr_fresh(
            creds, self._chroot_rel_path("etc/shadow")
        )
        if shadow_rel_ok or not self._ftp_text_is_unconfirmed(shadow_rel_err):
            confirmed = True
        if shadow_rel_ok and not shadow_ok:
            self._chroot_line("../etc/shadow", "VULN")
        elif not self.use_json:
            self._flush_terminal()
        write_outside = self._chroot_probe_mkd_escape(creds, pwd_initial)
        if not confirmed:
            self._chroot_line("Could not connect. Isolation was not tested.", "WARNING")
        elif not getattr(self, "_chroot_streamed", False):
            self._chroot_line("Users are isolated", "NOTVULN")

        passwd_bytes = passwd_sz if passwd_ok else passwd_rel_sz if passwd_rel_ok else None
        shadow_bytes = shadow_sz if shadow_ok else shadow_rel_sz if shadow_rel_ok else None
        broken = (
            len(strong_hits) > 0
            or passwd_ok
            or passwd_rel_ok
            or shadow_ok
            or shadow_rel_ok
            or home_parent_ok
            or write_outside
            or dotdot_escape
        )

        parts: list[str] = []
        if strong_hits:
            parts.append(f"CWD succeeded to sensitive path(s): {', '.join(sorted(set(strong_hits)))}.")
        if passwd_ok or passwd_rel_ok:
            parts.append("RETR /etc/passwd returned the file.")
        if shadow_ok or shadow_rel_ok:
            parts.append("RETR /etc/shadow returned the file.")
        if home_sibling:
            parts.append("CWD /home succeeded while login PWD was under /home/<user> (possible cross-user directory access).")
        elif home_parent_ok:
            parts.append("CWD /home succeeded.")
        if write_outside:
            parts.append("MKD via ../ created a directory outside the login directory.")
        if dotdot_escape:
            parts.append(
                f"Repeated CWD .. reached strict parent of login directory (final PWD ~ {pwd_fn!r}, steps={dot.steps_ok})."
            )
        if not parts:
            parts.append(
                "No obvious host-level path breakout in this probe set; chroot may still use a synthetic '/' — confirm manually."
            )

        detail = " ".join(parts)
        return ChrootAuditResult(
            pwd_initial=pwd_initial,
            cwd_probes=tuple(rows),
            dotdot=dot,
            home_parent_accessible=home_parent_ok,
            system_paths_accessible=tuple(sorted(set(strong_hits))),
            passwd_size_ok=passwd_ok or passwd_rel_ok,
            shadow_size_ok=shadow_ok or shadow_rel_ok,
            dotdot_parent_escape_suspected=dotdot_escape,
            isolation_broken_suspected=broken,
            detail=detail,
            passwd_size_bytes=passwd_bytes,
            shadow_size_bytes=shadow_bytes,
            passwd_retr_ok=passwd_ok,
            shadow_retr_ok=shadow_ok,
            passwd_retr_relative_ok=passwd_rel_ok,
            shadow_retr_relative_ok=shadow_rel_ok,
            write_escape_ok=write_outside,
        )

    @staticmethod
    def _reply_code(reply: str) -> int | None:
        r = reply.strip()
        if len(r) >= 3 and r[:3].isdigit():
            return int(r[:3])
        return None

    @staticmethod
    def _format_port_command(ip: str, port: int) -> str:
        octets = [int(x) for x in ip.split(".")]
        if len(octets) != 4 or any(x < 0 or x > 255 for x in octets):
            raise ValueError("IPv4 required for PORT")
        p1, p2 = port // 256, port % 256
        if p1 < 0 or p1 > 255 or p2 < 0 or p2 > 255:
            raise ValueError("port out of range for PORT encoding")
        return f"PORT {octets[0]},{octets[1]},{octets[2]},{octets[3]},{p1},{p2}"

    def _ftp_send_cmd(self, ftp: ftplib.FTP, cmd: str) -> str:
        try:
            resp = ftp.sendcmd(cmd)
        except ftplib.Error as e:
            resp = str(e).strip() if str(e).strip() else repr(e)
        self._dbg(f"{cmd} → {self._snip(resp)}")
        self._dbg_extra_lines(resp)
        return resp

    def _ftp_send_cmd_site_help_all_safe(self, ftp: ftplib.FTP) -> tuple[str | None, str | None]:
        """
        SITE HELP ALL can reset the TCP session or hang on some servers; never propagate.
        Returns (reply, None) on success, (None, error_message) on failure.
        """
        try:
            return self._ftp_send_cmd(ftp, "SITE HELP ALL"), None
        except (OSError, EOFError, socket.timeout, TimeoutError) as e:
            return None, f"{type(e).__name__}: {e}"
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"

    def _local_control_ipv4(self, ftp: ftplib.FTP) -> str | None:
        try:
            sock = ftp.sock
            addr = sock.getsockname()[0]
            ipaddress.IPv4Address(addr)
            if str(addr) == "0.0.0.0":
                return None
            return addr
        except Exception:
            return None

    @staticmethod
    def _parse_active_audit_low_ports(spec: str) -> list[int]:
        ports: list[int] = []
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                p = int(part, 10)
            except ValueError:
                continue
            if 1 <= p < 1000:
                ports.append(p)
        return ports or [80, 443, 21]

    @staticmethod
    def _hint_pasv_preauth(code: int | None) -> str | None:
        if code == 227:
            return (
                "PASV allowed before login (informational). Hardened servers often use 530; "
                "227 is not RFC-forbidden but expands pre-auth attack surface."
            )
        if code == 530:
            return "Login required before PASV (strict / preferred policy for access control)."
        if code == 502:
            return "PASV not implemented or disabled on server."
        if code == 421:
            return "Service unavailable or control connection closing."
        if code == 504:
            return "PASV parameter not implemented."
        return None

    @staticmethod
    def _hint_port_preauth_own(code: int | None) -> str | None:
        if code == 530:
            return "Login required before PORT (expected for hardened servers)."
        if code == 200:
            return "PORT accepted before login (unusual; review server policy)."
        if code in (500, 501, 502):
            return "PORT rejected or syntax error before login."
        if code == 504:
            return "PORT parameter rejected (RFC 2577 style for bad port)."
        return None

    @staticmethod
    def _hint_port_preauth_foreign(code: int | None) -> str | None:
        if code == 200:
            return "PORT to non-client IP accepted before login (FTP bounce risk)."
        if code in (530, 500, 501, 502, 504):
            return "PORT to third-party address rejected before login (bounce mitigation)."
        return None

    @staticmethod
    def _hint_d0_list(code: int | None) -> str | None:
        if code in (150, 125):
            return (
                "Server accepted LIST without prior PASV/PORT on control trace — data phase started; "
                "client did not use ftplib auto-PASV (raw LIST)."
            )
        if code == 226:
            return "Transfer complete without explicit PASV/PORT in our capture (unusual for single reply)."
        if code == 425:
            return "Cannot open data connection — server requires explicit PASV/PORT (strict RFC-style)."
        if code in (503, 501):
            return "Bad sequence or syntax — likely requires PASV/PORT first."
        if code == 530:
            return "Not logged in or command refused."
        return None

    def _active_audit_step_verdict(
        self, s: ActiveAuditStep, aa: ActiveAuditResult
    ) -> tuple[str | None, str | None]:
        """Terminal verdict (NOTVULN / VULN / WARNING) for one active-audit step; (None, None) = omit."""
        c = s.code
        name = s.name
        phase = s.phase
        reply_l = (s.reply or "").lower()
        cmd_s = s.command or ""

        if cmd_s == "(skipped)" or name in ("port_skipped", "port_sessions"):
            note_l = (s.note or "").lower()
            if "non-ipv4" in note_l or "ipv4" in note_l:
                return "WARNING", "IPv4 required for PORT tests; audit incomplete"
            return None, None

        if phase == "preAuth":
            if name == "pasv":
                if c == 530:
                    return "NOTVULN", "Login required before PASV (strict policy)"
                if c == 227:
                    return "WARNING", "PASV allowed before login (informational attack surface)"
                if c == 502:
                    return "NOTVULN", "PASV not implemented or disabled on server"
                if c in (501, 504):
                    return "NOTVULN", "PASV not available or parameter rejected"
            if name in ("port_own_high", "port_own_1930", "port_own"):
                if c == 530:
                    return "NOTVULN", "Login required before PORT (expected for hardened servers)"
                if c == 200:
                    return "VULN", "PORT accepted before login (unusual — review policy)"
            if name == "port_foreign":
                if c == 200:
                    return "VULN", "Third-party PORT accepted before login (FTP bounce risk)"
                if c in (530, 500, 501, 502, 504):
                    return "NOTVULN", "Third-party PORT rejected before login (bounce mitigation)"

        if phase == "postAuth":
            if name == "d0_list_raw":
                if c in (425, 503, 501):
                    return "NOTVULN", "Strict RFC-style state (PASV/PORT required first)"
                if c == 530:
                    return "NOTVULN", "Login or sequence required before data channel"
            if name == "pasv_list":
                if s.reply == "ok" or c == 226:
                    return "NOTVULN", "Passive data transfer OK"
                if s.reply == "failed":
                    return "WARNING", "Passive LIST failed (see reply)"
            if name == "pasv":
                if c == 227:
                    return "NOTVULN", "Passive mode available after login"
            if name == "list_active":
                if "data transfer ok" in reply_l:
                    return "NOTVULN", "Active-mode LIST completed (data path OK)"
                if c is not None or self._ftp_server_reply(s.reply):
                    return "VULN", "Server refused the active data transfer"
                return (
                    "WARNING",
                    "Active-mode LIST was not confirmed. A timeout can also mean the tester is behind NAT or a firewall.",
                )

            if name == "port_foreign_list":
                if c == 200:
                    return "VULN", "PORT 200 to foreign IP — bounce risk (verify with capture)"
                if c in (500, 501, 502, 504, 530):
                    return "NOTVULN", "Third-party PORT rejected (bounce risk mitigated)"

            if name.startswith("port_own_low_"):
                if c in (500, 501, 502, 504, 530):
                    return "NOTVULN", "Low data port (<1024) rejected"

            if name in ("port_own_high_list", "port_own_1930_list"):
                if c == 200:
                    return "WARNING", "PORT accepted — verify data path and policy"
                if c in (500, 501, 502, 504) and "illegal" in reply_l:
                    return "NOTVULN", "PORT rejected (active mode disabled or restricted)"
                if c == 530:
                    return "NOTVULN", "PORT refused (policy)"
                if c == 500 and "illegal" not in reply_l:
                    return "NOTVULN", "PORT rejected by server"

            if name in ("port_own_high", "port_foreign", "port_low") and c is not None:
                if c == 200 and name == "port_foreign":
                    return "VULN", "Third-party PORT accepted after login (bounce risk)"
                if c == 200:
                    return "WARNING", "PORT command accepted (check follow-up behaviour)"
                if c in (500, 501, 502, 504) and "illegal" in reply_l:
                    return "NOTVULN", "PORT rejected (active mode disabled or restricted)"
                if c == 530:
                    return "NOTVULN", "PORT refused or login required"

        return None, None

    def _print_active_audit_terminal(self, aa: ActiveAuditResult) -> None:
        """Structured terminal output for active mode policy audit (aligned with other FTP sections)."""
        bounce_header = False
        printed_pre = False
        post_header = False

        self._ptprint("Active mode policy", Out.INFO)

        for s in aa.steps:
            if s.phase == "preAuth" and not printed_pre:
                self._ptprint("Pre-authentication checks", Out.INFO)
                printed_pre = True
            if s.phase == "postAuth" and not post_header:
                self._ptprint("Post-authentication checks", Out.INFO)
                post_header = True
            if (
                s.phase == "postAuth"
                and s.name in ("port_foreign_list", "port_foreign")
                and not bounce_header
            ):
                self._ptprint("FTP bounce (foreign IP)", Out.INFO)
                bounce_header = True

            c = s.code
            code_s = f" [{c}]" if c is not None else ""
            cmd_s = s.command if s.command else "(no command)"
            self._ptprint(f"    [{s.phase}/{s.name}] {cmd_s}{code_s}", Out.TEXT)
            if s.reply:
                r = s.reply[:500] + ("…" if len(s.reply) > 500 else "")
                self._ptprint(f"        {r}", Out.TEXT)
            if s.list_reply:
                lc = s.list_code
                lc_s = f" [list {lc}]" if lc is not None else ""
                lr = s.list_reply[:400] + ("…" if len(s.list_reply or "") > 400 else "")
                self._ptprint(f"        list:{lc_s} {lr}", Out.TEXT)

            v_col, v_msg = self._active_audit_step_verdict(s, aa)
            if v_msg and v_col:
                self._tprint(v_msg, v_col, indent=8)
            elif s.interpretation:
                self._ptprint(f"        hint: {s.interpretation}", Out.TEXT)
            if s.note and not (cmd_s == "(skipped)" and v_msg):
                self._ptprint(f"        note: {s.note}", Out.TEXT)

        if not aa.post_auth_ran:
            self._tprint(
                self._missing_login_line(),
                "WARNING",
            )

        doc_net_ip = "192.0.2.1"
        if aa.foreign_ip_accepted:
            self._tprint(
                f"PORT accepted for non-client IP (bounce risk; tested {doc_net_ip})",
                "VULN",
            )
            self._ptprint(
                "    Verify with a packet capture whether the server opens TCP to the stated IP:port.",
                Out.TEXT,
            )
        if aa.low_port_accepted:
            lp = ", ".join(str(p) for p in aa.low_ports_accepted) if aa.low_ports_accepted else "<1000"
            self._tprint(
                f"PORT accepted for low data port(s): {lp} (RFC 2577: suggest reject < 1024)",
                "VULN",
            )
        if aa.list_after_own_port_ok is False:
            list_step = next((s for s in aa.steps if s.name == "list_active"), None)
            if list_step is not None and not self._ftp_server_reply(list_step.reply):
                self._tprint(
                    "Active-mode LIST was not confirmed. A timeout can also mean the tester is behind NAT or a firewall.",
                    "WARNING",
                )

        self._ptprint("Summary", Out.INFO)
        passive_ok = any(
            (x.name == "pasv_list" and x.reply == "ok")
            or (x.name == "pasv" and x.code == 227)
            for x in aa.steps
        )
        passive_txt = (
            "Available / data transfer OK" if passive_ok else "Not verified or failed in this run"
        )
        self._tprint(f"Passive mode:    {passive_txt}", "TITLE")

        if not aa.post_auth_ran:
            self._tprint("Active mode:     Not assessed (no post-login audit)", "WARNING")
            self._tprint("Overall status:  Incomplete audit", "WARNING")
            return

        active_vuln = aa.foreign_ip_accepted or aa.low_port_accepted
        port_rejected = any(
            x.name.endswith("_list")
            and x.code in (500, 501, 502, 504)
            and "illegal" in (x.reply or "").lower()
            for x in aa.steps
        )
        ipv4_skip = any(
            "non-ipv4" in (x.note or "").lower() for x in aa.steps if x.command == "(skipped)"
        )

        if active_vuln:
            self._tprint("Active mode:     PORT policy risk (foreign or low port accepted)", "VULN")
        elif ipv4_skip:
            self._tprint("Active mode:     Not fully assessed (IPv4 required for PORT probes)", "WARNING")
        elif port_rejected and not aa.foreign_ip_accepted:
            self._tprint(
                "Active mode:     Disabled / rejected (no 200 on bounce/low-port probes in this run)",
                "NOTVULN",
            )
        else:
            self._tprint("Active mode:     No bounce/low-port PORT acceptance (200) observed", "NOTVULN")

        if active_vuln:
            self._tprint("Overall status:  Review PORT policy (bounce / low port)", "VULN")
        elif ipv4_skip:
            self._tprint("Overall status:  Inconclusive (partial audit)", "WARNING")
        else:
            self._tprint("Overall status:  No bounce/low-port finding from this run", "NOTVULN")

    def _raw_list_without_pasv_port(self, ftp: ftplib.FTP) -> tuple[str, int | None]:
        """Send LIST on control channel without ftplib issuing PASV/PORT first (D0)."""
        try:
            ftp.putcmd("LIST")
            resp = ftp.getmultiline()
        except Exception as e:
            return str(e).strip() or repr(e), None
        code = self._reply_code(resp)
        if code == 150:
            try:
                ftp.putcmd("ABOR")
                _ = ftp.getmultiline()
            except Exception:
                pass
        return resp, code

    def _active_port_list_plaintext(
        self, ftp: ftplib.FTP, local_ip: str, data_port: int
    ) -> tuple[str, int | None, str, int | None, bool, str | None]:
        """
        After login: bind local data port, PORT command, LIST, accept server connection.
        Returns: port_reply, port_code, list_control_log, list_final_code, data_received, error_note
        """
        if self.args.tls or self.args.starttls:
            pcmd = self._format_port_command(local_ip, data_port)
            pr = self._ftp_send_cmd(ftp, pcmd)
            pc = self._reply_code(pr)
            return pr, pc, "", None, False, "TLS: active PORT+LIST not automated; use plaintext or packet capture"

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        to = 15.0
        try:
            listener.bind((local_ip, data_port))
            listener.listen(1)
            listener.settimeout(to)
        except OSError as e:
            try:
                listener.close()
            except Exception:
                pass
            return "", None, "", None, False, f"bind {local_ip}:{data_port} failed: {e}"

        try:
            pcmd = self._format_port_command(local_ip, data_port)
            port_reply = self._ftp_send_cmd(ftp, pcmd)
            pc = self._reply_code(port_reply)
            if pc != 200:
                return port_reply, pc, "", None, False, None

            ftp.putcmd("LIST")
            line1 = ftp.getmultiline()
            lc1 = self._reply_code(line1)
            if lc1 in (425, 500, 501, 502, 530, 503):
                return port_reply, pc, line1, lc1, False, None

            try:
                datasock, _ = listener.accept()
            except socket.timeout:
                return port_reply, pc, line1, lc1, False, "data connection accept timeout"

            datasock.settimeout(to)
            chunks: list[bytes] = []
            try:
                while True:
                    chunk = datasock.recv(8192)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except socket.timeout:
                pass
            finally:
                try:
                    datasock.close()
                except Exception:
                    pass

            data_ok = len(b"".join(chunks)) > 0
            try:
                line2 = ftp.getmultiline()
            except Exception as e:
                line2 = str(e)
            lc2 = self._reply_code(line2)
            return port_reply, pc, f"{line1} || {line2}", lc2, data_ok, None
        finally:
            try:
                listener.close()
            except Exception:
                pass

    def _foreign_port_then_list(
        self, ftp: ftplib.FTP, foreign_ip: str, data_port: int
    ) -> tuple[str, int | None, str, int | None]:
        """PORT to documentation IP then LIST; observe control replies (no local listener on foreign IP)."""
        pcmd = self._format_port_command(foreign_ip, data_port)
        pr = self._ftp_send_cmd(ftp, pcmd)
        pc = self._reply_code(pr)
        if pc != 200:
            return pr, pc, "", None
        ftp.putcmd("LIST")
        try:
            line1 = ftp.getmultiline()
        except Exception as e:
            return pr, pc, str(e), None
        lc1 = self._reply_code(line1)
        try:
            old_to = ftp.sock.gettimeout()
        except Exception:
            old_to = None
        merged, lc2 = line1, lc1
        try:
            ftp.sock.settimeout(8.0)
            line2 = ftp.getmultiline()
            lc2 = self._reply_code(line2)
            merged = f"{line1} || {line2}"
        except Exception:
            pass
        finally:
            try:
                if old_to is not None:
                    ftp.sock.settimeout(old_to)
            except Exception:
                pass
        return pr, pc, merged, lc2

    def test_active_audit_full(self, creds: Creds | None, low_ports_spec: str) -> ActiveAuditResult:
        """
        Full PTL-SVC-FTP-ACTIVE methodology: isolated sessions, interpretation hints,
        D0 raw LIST, PORT+LIST per variant, multiple low ports.
        """
        self._dbg("Active-mode full methodology")
        doc_net_ip = "192.0.2.1"
        foreign_data_port = 7 * 256 + 138
        local_high_port = 40123
        low_ports = self._parse_active_audit_low_ports(low_ports_spec)

        steps: list[ActiveAuditStep] = []
        foreign_accepted = False
        low_accepted_ports: list[int] = []
        list_after_own_ok: bool | None = None

        # --- Pre-auth (single connection) ---
        pre = self.connect()
        try:
            pasv_r = self._ftp_send_cmd(pre, "PASV")
            pc = self._reply_code(pasv_r)
            steps.append(
                ActiveAuditStep(
                    "preAuth",
                    "pasv",
                    "PASV",
                    pasv_r,
                    pc,
                    None,
                    self._hint_pasv_preauth(pc),
                    None,
                    None,
                )
            )
            local_pre = self._local_control_ipv4(pre)
            if local_pre:
                for pname, port_n in (("port_own_high", local_high_port), ("port_own_1930", foreign_data_port)):
                    cmd = self._format_port_command(local_pre, port_n)
                    pr = self._ftp_send_cmd(pre, cmd)
                    c = self._reply_code(pr)
                    steps.append(
                        ActiveAuditStep(
                            "preAuth",
                            pname,
                            cmd,
                            pr,
                            c,
                            None,
                            self._hint_port_preauth_own(c),
                            None,
                            None,
                        )
                    )
            else:
                steps.append(
                    ActiveAuditStep(
                        "preAuth",
                        "port_own",
                        "(skipped)",
                        "",
                        None,
                        "non-IPv4 or 0.0.0.0 local control address",
                        None,
                        None,
                        None,
                    )
                )

            fcmd = self._format_port_command(doc_net_ip, foreign_data_port)
            fr = self._ftp_send_cmd(pre, fcmd)
            fc = self._reply_code(fr)
            steps.append(
                ActiveAuditStep(
                    "preAuth",
                    "port_foreign",
                    fcmd,
                    fr,
                    fc,
                    None,
                    self._hint_port_preauth_foreign(fc),
                    None,
                    None,
                )
            )
            if fc == 200:
                foreign_accepted = True
        finally:
            try:
                pre.close()
            except Exception:
                pass

        post_ran = False
        if creds is None:
            return ActiveAuditResult(
                tuple(steps),
                post_ran,
                foreign_accepted,
                len(low_accepted_ports) > 0,
                list_after_own_ok,
                tuple(low_accepted_ports),
                True,
            )

        post_ran = True

        def session_pasv_list() -> None:
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
                ftp.set_pasv(True)
                ach = AccessCheckHelper()
                try:
                    ftp.dir(ach.read_callback)
                    ok = True
                    lr = "directory listing completed (passive)"
                except ftplib.Error as e:
                    ok = False
                    lr = str(e).strip()
                steps.append(
                    ActiveAuditStep(
                        "postAuth",
                        "pasv_list",
                        "PASV + LIST (via dir, passive)",
                        "ok" if ok else "failed",
                        226 if ok else self._reply_code(lr),
                        None,
                        "Baseline passive data transfer after login.",
                        lr[:500] if lr else None,
                        self._reply_code(lr),
                    )
                )
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

        def session_d0() -> None:
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
                resp, code = self._raw_list_without_pasv_port(ftp)
                steps.append(
                    ActiveAuditStep(
                        "postAuth",
                        "d0_list_raw",
                        "LIST (raw, no prior PASV/PORT)",
                        resp[:800],
                        code,
                        None,
                        self._hint_d0_list(code),
                        None,
                        None,
                    )
                )
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

        session_d0()
        session_pasv_list()

        local = None
        s0 = self.connect()
        try:
            s0.login(creds.user, creds.passw)
            local = self._local_control_ipv4(s0)
        finally:
            try:
                s0.close()
            except Exception:
                pass

        if not local:
            steps.append(
                ActiveAuditStep(
                    "postAuth",
                    "port_sessions",
                    "(skipped)",
                    "",
                    None,
                    "non-IPv4 local socket; PORT+LIST sessions skipped",
                    None,
                    None,
                    None,
                )
            )
            return ActiveAuditResult(
                tuple(steps),
                post_ran,
                foreign_accepted,
                len(low_accepted_ports) > 0,
                list_after_own_ok,
                tuple(low_accepted_ports),
                True,
            )

        def run_port_list_session(step_name: str, data_port: int, foreign: bool) -> None:
            nonlocal foreign_accepted, list_after_own_ok
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
                if foreign:
                    pr, pc, lr, lc = self._foreign_port_then_list(ftp, doc_net_ip, data_port)
                    hint = self._hint_port_preauth_foreign(pc)
                    steps.append(
                        ActiveAuditStep(
                            "postAuth",
                            step_name,
                            self._format_port_command(doc_net_ip, data_port),
                            pr,
                            pc,
                            "Foreign IP: LIST may fail or timeout; 200 on PORT is still bounce risk.",
                            hint,
                            lr[:800] if lr else None,
                            lc,
                        )
                    )
                    if pc == 200:
                        foreign_accepted = True
                    return

                pr, pc, lr, lc, data_ok, err_note = self._active_port_list_plaintext(ftp, local, data_port)
                if step_name == "port_own_high_list" and data_ok:
                    list_after_own_ok = True
                hint = None
                tls_skip = bool(err_note and "TLS" in err_note)
                if (
                    pc == 200
                    and data_port < 1000
                    and not tls_skip
                    and data_port not in low_accepted_ports
                ):
                    hint = "PORT accepted for port <1000; RFC 2577 recommends rejecting <1024 (often 504)."
                    low_accepted_ports.append(data_port)
                inter = None
                if pc and pc != 200:
                    inter = "PORT or data phase rejected (see reply)."
                elif pc == 200 and data_port >= 1000 and data_ok:
                    inter = "Active PORT+LIST completed for high/ephemeral data port."
                elif pc == 200 and data_port >= 1000 and not data_ok:
                    inter = "PORT accepted but data transfer incomplete (timeout/NAT/firewall possible)."
                steps.append(
                    ActiveAuditStep(
                        "postAuth",
                        step_name,
                        self._format_port_command(local, data_port),
                        pr,
                        pc,
                        err_note,
                        inter or hint,
                        lr[:800] if lr else None,
                        lc,
                    )
                )
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

        run_port_list_session("port_own_high_list", local_high_port, False)
        run_port_list_session("port_own_1930_list", foreign_data_port, False)
        run_port_list_session("port_foreign_list", foreign_data_port, True)

        for lp in low_ports:
            run_port_list_session(f"port_own_low_{lp}", lp, False)

        return ActiveAuditResult(
            tuple(steps),
            post_ran,
            foreign_accepted,
            len(low_accepted_ports) > 0,
            list_after_own_ok,
            tuple(low_accepted_ports),
            True,
        )

    def test_active_audit_quick(self, creds: Creds | None) -> ActiveAuditResult:
        """
        PTL-SVC-FTP-ACTIVE: PASV/PORT policy (pre- and post-login), foreign IP and low-port PORT.
        Uses 192.0.2.1 (RFC 5737 TEST-NET-1) as non-client address for bounce-style checks.
        """
        self._dbg("Active-mode policy audit")
        # RFC 5737 documentation block — must not target real third parties
        doc_net_ip = "192.0.2.1"
        foreign_data_port = 7 * 256 + 138  # 1930, example from audit methodology
        local_high_port = 40123
        low_test_port = 80  # < 1000 per test spec; RFC 2577 recommends rejecting < 1024

        steps: list[ActiveAuditStep] = []
        foreign_accepted = False
        low_port_accepted = False
        list_after_own_port_ok: bool | None = None

        # --- Pre-authentication ---
        pre_ftp = self.connect()
        try:
            pasv_reply = self._ftp_send_cmd(pre_ftp, "PASV")
            steps.append(
                ActiveAuditStep(
                    "preAuth",
                    "pasv",
                    "PASV",
                    pasv_reply,
                    self._reply_code(pasv_reply),
                    None,
                )
            )
            local_pre = self._local_control_ipv4(pre_ftp)
            if local_pre:
                port_cmd = self._format_port_command(local_pre, local_high_port)
                pr = self._ftp_send_cmd(pre_ftp, port_cmd)
                code = self._reply_code(pr)
                steps.append(
                    ActiveAuditStep("preAuth", "port_own_high", port_cmd, pr, code, None)
                )
            else:
                steps.append(
                    ActiveAuditStep(
                        "preAuth",
                        "port_own_high",
                        "(skipped)",
                        "",
                        None,
                        "non-IPv4 or unknown local control address",
                    )
                )

            fcmd = self._format_port_command(doc_net_ip, foreign_data_port)
            fr = self._ftp_send_cmd(pre_ftp, fcmd)
            fc = self._reply_code(fr)
            steps.append(ActiveAuditStep("preAuth", "port_foreign", fcmd, fr, fc, None))
            if fc == 200:
                foreign_accepted = True
        finally:
            try:
                pre_ftp.close()
            except Exception:
                pass

        # --- Post-authentication ---
        post_ran = False
        if creds is None:
            return ActiveAuditResult(
                tuple(steps),
                post_ran,
                foreign_accepted,
                low_port_accepted,
                list_after_own_port_ok,
                (low_test_port,) if low_port_accepted else (),
                False,
            )

        post_ran = True

        def run_post(name: str, cmd: str) -> ActiveAuditStep:
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
                reply = self._ftp_send_cmd(ftp, cmd)
                return ActiveAuditStep(
                    "postAuth",
                    name,
                    cmd,
                    reply,
                    self._reply_code(reply),
                    None,
                )
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

        steps.append(run_post("pasv", "PASV"))

        local = None
        ftp_one = self.connect()
        try:
            ftp_one.login(creds.user, creds.passw)
            local = self._local_control_ipv4(ftp_one)
        finally:
            try:
                ftp_one.close()
            except Exception:
                pass

        if local:
            pcmd_own = self._format_port_command(local, local_high_port)
            st = run_post("port_own_high", pcmd_own)
            steps.append(st)

            pcmd_foreign = self._format_port_command(doc_net_ip, foreign_data_port)
            st_f = run_post("port_foreign", pcmd_foreign)
            steps.append(st_f)
            if self._reply_code(st_f.reply) == 200:
                foreign_accepted = True

            pcmd_low = self._format_port_command(local, low_test_port)
            st_l = run_post("port_low", pcmd_low)
            steps.append(st_l)
            if self._reply_code(st_l.reply) == 200:
                low_port_accepted = True

            ftp_l = self.connect()
            try:
                ftp_l.login(creds.user, creds.passw)
                ftp_l.set_pasv(False)
                ach = AccessCheckHelper()
                list_err = ""
                try:
                    ftp_l.dir(ach.read_callback)
                    list_after_own_port_ok = True
                except Exception as e:
                    list_after_own_port_ok = False
                    list_err = str(e).strip()
            finally:
                try:
                    ftp_l.close()
                except Exception:
                    pass
            steps.append(
                ActiveAuditStep(
                    "postAuth",
                    "list_active",
                    "LIST (dir, client active mode)",
                    "data transfer ok" if list_after_own_port_ok else (list_err or "data transfer failed"),
                    self._reply_code(list_err) if list_err else None,
                    None,
                )
            )
        else:
            steps.append(
                ActiveAuditStep(
                    "postAuth",
                    "port_skipped",
                    "",
                    "",
                    None,
                    "non-IPv4 local socket; post-auth PORT tests skipped",
                )
            )

        return ActiveAuditResult(
            tuple(steps),
            post_ran,
            foreign_accepted,
            low_port_accepted,
            list_after_own_port_ok,
            (low_test_port,) if low_port_accepted else (),
            False,
        )

    _CMD_AUDIT_MAX = 65536
    _CMD_ACTIVE_PROBE_TIMEOUT = 12.0
    _CMD_ACTIVE_PATTERNS: dict[str, re.Pattern[str]] = {
        "chown": re.compile(r"\bSITE\s+CHOWN\b", re.I),
        "chmod": re.compile(r"\bSITE\s+CHMOD\b", re.I),
        "exec": re.compile(r"\bSITE\s+(EXEC|EXECUTE|RUN)\b", re.I),
        "cpfr": re.compile(r"\bSITE\s+CPFR\b", re.I),
        "cpto": re.compile(r"\bSITE\s+CPTO\b", re.I),
        "umask": re.compile(r"\bSITE\s+UMASK\b", re.I),
        "symlink": re.compile(r"\bSITE\s+(SYMLINK|LINK|LN)\b", re.I),
    }

    _INV_AUDIT_TIMEOUT = 8.0
    _INV_AUDIT_LONG_LEN = 4096
    _INV_AUDIT_REPLY_TEXT_MAX = 4096
    # 3xx on these probes is non‑RFC‑typical (RFC 959: USER→331/332 is normal; see _inv_2xx_counts_toward_vulnerable).
    _INV_3XX_CRITICAL_PROBE_IDS = frozenset({"long_buffer_cwd", "format_string_stat"})
    # RFC 959 §5.4: STAT replies are 211/212/213/214 (and 215 NAME); not a protocol anomaly.
    _INV_STAT_SUCCESS_CODES = frozenset({211, 212, 213, 214, 215})
    # Double-CRLF smuggle: read possible 2nd FTP reply without blocking the main probe timeout.
    _INV_SMUGGLE_FOLLOWUP_TIMEOUT = 0.75
    _INV_DRAIN_CHUNK_TIMEOUT = 0.2
    _INV_DRAIN_MAX_BYTES = 65536

    _CMD_AUDIT_CRITICAL: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\bSITE\s+EXECUTE\b", re.I), "SITE EXECUTE"),
        (re.compile(r"\bSITE\s+EXEC\b", re.I), "SITE EXEC"),
        (re.compile(r"\bSITE\s+RUN\b", re.I), "SITE RUN"),
    )
    _CMD_AUDIT_HIGH: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\bSITE\s+CHOWN\b", re.I), "SITE CHOWN"),
        (re.compile(r"\bSITE\s+CHMOD\b", re.I), "SITE CHMOD"),
        (re.compile(r"\bSITE\s+UMASK\b", re.I), "SITE UMASK"),
        (re.compile(r"\bSITE\s+SYMLINK\b", re.I), "SITE SYMLINK"),
        (re.compile(r"\bSITE\s+LINK\b", re.I), "SITE LINK"),
        (re.compile(r"\bSITE\s+LN\b", re.I), "SITE LN"),
        (re.compile(r"\bSITE\s+CPFR\b", re.I), "SITE CPFR"),
        (re.compile(r"\bSITE\s+CPTO\b", re.I), "SITE CPTO"),
    )
    _CMD_AUDIT_MEDIUM: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\bSITE\s+WHO\b", re.I), "SITE WHO"),
        (re.compile(r"\bSITE\s+IDLE\b", re.I), "SITE IDLE"),
    )

    def _truncate_cmd_audit_reply(self, text: str) -> tuple[str, bool]:
        if len(text) <= self._CMD_AUDIT_MAX:
            return text, False
        return text[: self._CMD_AUDIT_MAX] + "\n... [truncated]", True

    @staticmethod
    def _parse_feat_feature_labels(feat_reply: str) -> tuple[str, ...]:
        """Parse FEAT (RFC 2389) response lines into feature labels."""
        ordered: list[str] = []
        seen: set[str] = set()
        for raw in feat_reply.splitlines():
            line = raw.rstrip("\r")
            if len(line) < 2 or line[0] != " " or line[1] == " ":
                continue
            part = line.strip()
            if not part:
                continue
            first = part.split(None, 1)[0].upper()
            if first in ("211", "END") or first.startswith("211-"):
                continue
            if first.endswith(":"):
                continue
            tok = part.split(None, 1)[0]
            u = tok.upper()
            if u not in seen:
                seen.add(u)
                ordered.append(tok)
        return tuple(ordered)

    def _cmd_audit_scan_text(self, text: str, source: str) -> list[CmdAuditRisk]:
        risks: list[CmdAuditRisk] = []
        if not text or not text.strip():
            return risks
        for pat, label in self._CMD_AUDIT_CRITICAL:
            if pat.search(text):
                risks.append(CmdAuditRisk("critical", label, source))
        for pat, label in self._CMD_AUDIT_HIGH:
            if pat.search(text):
                risks.append(CmdAuditRisk("high", label, source))
        for pat, label in self._CMD_AUDIT_MEDIUM:
            if pat.search(text):
                risks.append(CmdAuditRisk("medium", label, source))
        if source == "featResponse":
            for w in ("MDTM", "SIZE", "MLST", "MLSD"):
                if re.search(rf"\b{re.escape(w)}\b", text, re.I):
                    risks.append(CmdAuditRisk("medium", f"FEAT {w}", "featResponse"))
        return risks

    @staticmethod
    def _cmd_audit_merge_risks(items: list[CmdAuditRisk]) -> tuple[CmdAuditRisk, ...]:
        by_k: dict[tuple[str, str, str], CmdAuditRisk] = {}
        for r in items:
            k = (r.tier, r.token, r.source)
            if k not in by_k:
                by_k[k] = r
        order = {"critical": 0, "high": 1, "medium": 2}
        return tuple(sorted(by_k.values(), key=lambda x: (order.get(x.tier, 9), x.token, x.source)))

    _CMD_AUDIT_SOURCE_LABEL: dict[str, str] = {
        "helpPreAuth": "HELP (pre-auth)",
        "featResponse": "FEAT response",
        "siteHelpPreAuth": "SITE HELP (pre-auth)",
        "siteHelpAllPreAuth": "SITE HELP ALL (pre-auth)",
        "siteHelpPostAuth": "SITE HELP (post-auth)",
        "siteHelpAllPostAuth": "SITE HELP ALL (post-auth)",
    }

    def _cmd_audit_blob_for_source(self, ca: CommandAuditResult, source: str) -> str:
        m = {
            "helpPreAuth": ca.help_pre_auth,
            "featResponse": ca.feat_response,
            "siteHelpPreAuth": ca.site_help_pre or "",
            "siteHelpAllPreAuth": ca.site_help_all_pre or "",
            "siteHelpPostAuth": ca.site_help_post or "",
            "siteHelpAllPostAuth": ca.site_help_all_post or "",
        }
        return m.get(source, "") or ""

    def _cmd_audit_snippet_for_risk(self, ca: CommandAuditResult, risk: CmdAuditRisk) -> str:
        blob = self._cmd_audit_blob_for_source(ca, risk.source)
        if not blob.strip():
            return "(empty response for this source)"
        parts = risk.token.split()
        needle = None
        for kw in reversed(parts):
            ku = kw.upper()
            if ku in ("FEAT", "SITE"):
                continue
            needle = kw
            break
        if not needle and parts:
            needle = parts[-1]
        if not needle:
            needle = risk.token
        for line in blob.splitlines():
            if re.search(rf"\b{re.escape(needle)}\b", line, re.I):
                s = line.strip()
                return s[:400] + ("…" if len(s) > 400 else "")
        for line in blob.splitlines():
            if line.strip():
                s = line.strip()
                return s[:400] + ("…" if len(s) > 400 else "")
        s = blob.strip()
        return s[:400] + ("…" if len(s) > 400 else "")

    @staticmethod
    def _cmd_audit_risk_explain(risk: CmdAuditRisk) -> tuple[str | None, str, str | None]:
        tok = risk.token.upper()
        tier = risk.tier

        def t(vuln: str | None, risk_t: str, info: str | None = None) -> tuple[str | None, str, str | None]:
            return (vuln, risk_t, info)

        if tier == "critical":
            return t(
                "Server advertises SITE EXEC / EXECUTE / RUN (implementation-dependent).",
                "If callable by unprivileged users, may lead to remote command execution or full host compromise.",
                None,
            )

        if "SYMLINK" in tok or tok.endswith(" LINK") or tok.endswith(" LN"):
            return t(
                "Advertised capability to create symbolic links on the server side.",
                "High potential for path traversal or access to files outside the intended FTP root.",
                None,
            )
        if "CHOWN" in tok:
            return t(
                "Advertised SITE CHOWN (change file ownership).",
                "May allow privilege escalation or unauthorized ownership changes if not strictly restricted.",
                None,
            )
        if "CHMOD" in tok:
            return t(
                "Advertised SITE CHMOD (change file permissions).",
                "May allow weakening permissions or making sensitive files world-readable if abused.",
                None,
            )
        if "UMASK" in tok:
            return t(
                "Advertised SITE UMASK (default permission mask).",
                "May affect security of newly created files if misconfigured or abused.",
                None,
            )
        if "CPFR" in tok or "CPTO" in tok:
            return t(
                "Advertised SITE CPFR/CPTO (FTP “copy” / server-side file copy).",
                "Associated with historical FTP bounce / abuse scenarios; verify server policy and access control.",
                None,
            )
        if "WHO" in tok:
            return t(
                None,
                "SITE WHO can expose logged-in users or session metadata.",
                "Useful for reconnaissance; impact depends on daemon implementation.",
            )
        if "IDLE" in tok:
            return t(
                None,
                "SITE IDLE may allow tuning or probing idle timeouts.",
                "Minor information or DoS relevance depending on server.",
            )
        if "MDTM" in tok:
            return t(
                None,
                "Allows remote determination of exact file modification times.",
                "Useful for fingerprinting files or coordinating time-based attacks.",
            )
        if "SIZE" in tok:
            return t(
                None,
                "Allows remote determination of exact file sizes.",
                "Can confirm existence of sensitive files or support side-channel style analysis before exfiltration.",
            )
        if "MLST" in tok or "MLSD" in tok:
            return t(
                None,
                "Provides detailed filesystem metadata in a unified, machine-readable format (RFC 3659 style).",
                "Simplifies automated target enumeration and data gathering.",
            )

        return t(
            None,
            f"Capability matched in captured text ({risk.token}). Review whether it is required and properly restricted.",
            None,
        )

    @staticmethod
    def _cmd_audit_label(token: str) -> str:
        parts = token.split()
        if len(parts) >= 2 and parts[0].upper() in ("FEAT", "SITE"):
            return " ".join(parts[1:])
        return token

    def _print_cmd_audit_terminal(self, ca: CommandAuditResult) -> None:
        if self._ftp_text_is_unconfirmed(ca.help_pre_auth) and self._ftp_text_is_unconfirmed(ca.feat_response):
            self._tprint("Could not connect. Commands were not tested.", "WARNING")
            return
        if not ca.matched_risks:
            self._tprint("No dangerous commands", "NOTVULN")
            return
        for r in ca.matched_risks:
            bullet = "VULN" if r.tier in ("critical", "high") else "WARNING"
            self._tprint(self._cmd_audit_label(r.token), bullet)

    def _cmd_active_line(self, p: CmdActiveProbeResult) -> tuple[str, str]:
        parts = (p.command_sent or "").split()
        label = " ".join(parts[:2]) if len(parts) >= 2 else (p.command_sent or p.probe_id)
        if p.error and self._ftp_text_is_unconfirmed(p.error):
            return "WARNING", f"{label} was not confirmed"
        if p.reply_code is not None and 200 <= p.reply_code < 300:
            return "VULN", f"{label} is allowed"
        if p.reply_code is not None:
            return "NOTVULN", f"{label} is not allowed"
        return "WARNING", f"{label} was not confirmed"

    def _inv_command_label(self, p: InvalidCmdProbeResult) -> str:
        if p.probe_id == "long_buffer_cwd":
            return f"CWD ({self._INV_AUDIT_LONG_LEN} bytes)"
        if p.probe_id == "long_buffer_user":
            return f"USER ({self._INV_AUDIT_LONG_LEN} bytes)"
        if p.probe_id == "unicode_invalid_cwd":
            return "CWD (invalid bytes)"
        if p.probe_id == "double_newline_smuggle":
            return "USER test / PASS test"
        if p.probe_id == "user_null_byte":
            return r"USER root\x00admin"
        return p.line_sent_preview or p.probe_id

    @staticmethod
    def _inv_pad_run(text: str | None, run: int = 8) -> str | None:
        """Character repeated from a long probe, echoed back in a later reply."""
        match = re.search(r"(.)\1{%d,}" % (run - 1), text or "")
        return match.group(1) if match else None

    def _inv_smuggle_receives(self, text: str | None) -> list[str]:
        """Replies read after the blank line, hidden from the first Receive line."""
        if not text or "--- smuggle_followup ---" not in text:
            return []
        out: list[str] = []
        for block in text.split("--- smuggle_followup ---")[1:]:
            block = block.split("---", 1)[0].strip()
            if not block:
                continue
            match = re.match(r"\(code=(None|\d+)\)\s*(.*)", block, re.S)
            if not match:
                out.append(self._snip(" ".join(block.split())))
                continue
            code_s, body = match.group(1), " ".join(match.group(2).split())
            if code_s == "None":
                out.append(self._snip(body) or "(no reply)")
                continue
            code = int(code_s)
            shown = self._inv_reply_body(code, body)
            out.append(f"{code} {shown}".strip() if shown else str(code))
        return out

    def _inv_reply_body(self, code: int | None, text: str | None) -> str:
        raw = (text or "").split("---", 1)[0]
        line = ""
        for part in raw.splitlines():
            part = " ".join(part.split())
            if part:
                line = part
                break
        if code is not None:
            prefix = str(code)
            if line.startswith(prefix):
                line = line[len(prefix):].lstrip(" -")
        line = re.sub(r"(.)\1{7,}", lambda m: m.group(1) * 4 + "...", line, count=1)
        return self._snip(line)

    def _inv_pad_kind(self, p: InvalidCmdProbeResult) -> str | None:
        """'source' when this long line was echoed. 'leftover' when a later reply is still that line."""
        echoed = self._inv_pad_run(p.reply_text)
        if p.probe_id in ("long_buffer_cwd", "long_buffer_user") and echoed == "A":
            self._inv_pad_char = "A"
            return "source"
        pad = getattr(self, "_inv_pad_char", None)
        if pad and echoed == pad:
            return "leftover"
        return None

    def _inv_probe_verdict(self, p: InvalidCmdProbeResult) -> tuple[str, str, list[str]]:
        """One result line. Bullet matches SMTP/IMAP: star, warning, or vulnerability."""
        label = self._inv_command_label(p)
        if getattr(self, "_inv_show_phase", False):
            where = "Before login" if p.phase == "preAuth" else "After login"
            label = f"{where}, {label}"
        body = self._inv_reply_body(p.reply_code, p.reply_text)
        cls = p.classification
        notes: list[str] = []
        if cls == "connection_lost":
            return "VULN", f"{label}: connection closed", notes
        if cls == "reply_timeout":
            return "VULN", f"{label}: no reply", notes
        if cls == "no_reply_code":
            return "WARNING", f"{label}: no numeric reply", notes
        if p.reply_code is not None and body:
            core = f"{label}: {p.reply_code} {body}"
        elif p.reply_code is not None:
            core = f"{label}: {p.reply_code}"
        else:
            core = f"{label}: {body or 'no reply'}"
        if cls == "positive_2xx_unexpected":
            return "VULN", f"{core} (server accepted the command)", notes
        if cls == "null_byte_possible_login_230":
            notes.append("Login succeeded after a null byte in the username")
            if p.follow_up_command:
                fu_body = self._inv_reply_body(p.follow_up_reply_code, p.follow_up_reply_snippet)
                if p.follow_up_reply_code is not None and fu_body:
                    notes.append(f"{p.follow_up_command}: {p.follow_up_reply_code} {fu_body}")
                elif p.follow_up_reply_code is not None:
                    notes.append(f"{p.follow_up_command}: {p.follow_up_reply_code}")
            return "VULN", core, notes
        if cls == "null_byte_user_truncation_331":
            notes.append("Null byte in USER was treated as the end of the name")
            return "WARNING", core, notes
        if cls == "continuation_3xx":
            bullet = "VULN" if p.probe_id in self._INV_3XX_CRITICAL_PROBE_IDS else "WARNING"
            return bullet, core, notes
        if cls == "double_crlf_probe_reply" and "smuggle_followup" in (p.reply_text or ""):
            notes.append("Extra reply after a blank line")
            return "WARNING", core, notes
        if p.reply_code == 421:
            return "WARNING", core, notes
        pad_kind = self._inv_pad_kind(p)
        if pad_kind == "source":
            notes.append("Server did not read the long line as one command")
            return "WARNING", core, notes
        if pad_kind == "leftover":
            return "WARNING", f"{label}: reply is still the previous long line", notes
        return "TITLE", core, notes

    def _inv_emit_probe(self, p: InvalidCmdProbeResult) -> None:
        """-vv Send/Receive, then one result line."""
        if self.use_json:
            return
        label = self._inv_command_label(p)
        cls = p.classification
        if cls == "connection_lost":
            recv = "connection closed"
        elif cls == "reply_timeout":
            recv = "(no reply)"
        else:
            body = self._inv_reply_body(p.reply_code, p.reply_text)
            if p.reply_code is not None and body:
                recv = f"{p.reply_code} {body}"
            elif p.reply_code is not None:
                recv = str(p.reply_code)
            else:
                recv = body or "(no reply)"
        self._dbg(f"Send: {label}")
        self._dbg(f"Receive: {recv}")
        for extra in self._inv_smuggle_receives(p.reply_text):
            self._dbg(f"Receive: {extra}")
        if p.follow_up_command:
            fu_body = self._inv_reply_body(p.follow_up_reply_code, p.follow_up_reply_snippet)
            if p.follow_up_reply_code is not None and fu_body:
                fu = f"{p.follow_up_reply_code} {fu_body}"
            elif p.follow_up_reply_code is not None:
                fu = str(p.follow_up_reply_code)
            else:
                fu = fu_body or "(no reply)"
            self._dbg(f"Send: {p.follow_up_command}")
            self._dbg(f"Receive: {fu}")
        self._flush_terminal()
        bullet, text, notes = self._inv_probe_verdict(p)
        self._tprint(text, bullet)
        for note in notes:
            self._tprint(note, "TEXT", indent=8)
        self._flush_terminal()
        self._inv_terminal_emitted = True

    def _print_invalid_cmd_audit_terminal(self, inv: InvalidCmdAuditResult) -> None:
        """Setup and login notes. Probe lines are already printed next to their -vv trace."""
        if inv.setup_error:
            if self._ftp_text_is_unconfirmed(inv.setup_error):
                self._tprint("Could not connect. Invalid commands were not tested.", "WARNING")
            else:
                self._tprint(self._snip(inv.setup_error), "WARNING")
            if inv.obsolete_tls_suspected:
                self._tprint("Server requires obsolete TLS.", "VULN")
            return
        if not getattr(self, "_inv_terminal_emitted", False):
            for sess in (inv.pre_auth, inv.post_auth):
                if sess is None:
                    continue
                self._inv_pad_char = None
                for p in sess.probes:
                    bullet, text, notes = self._inv_probe_verdict(p)
                    self._tprint(text, bullet)
                    for note in notes:
                        self._tprint(note, "TEXT", indent=8)
        if inv.post_auth_login_error and not getattr(self, "_inv_login_note_emitted", False):
            self._tprint("Login failed. Commands after login were not tested.", "WARNING")
        if inv.obsolete_tls_suspected:
            self._tprint("Server requires obsolete TLS.", "VULN")

    def test_command_audit(self, creds: Creds | None) -> CommandAuditResult:
        """
        PTL-SVC-FTP-CMD: passive enumeration via HELP, FEAT, SITE HELP / SITE HELP ALL.
        """
        self._dbg("Command surface audit (HELP / FEAT / SITE)")
        trunc_flag = False
        site_all_pre_err: str | None = None
        site_all_post_err: str | None = None

        def take(raw: str) -> str:
            nonlocal trunc_flag
            out, t = self._truncate_cmd_audit_reply(raw)
            if t:
                trunc_flag = True
            return out

        pre = self.connect()
        try:
            help_r = take(self._ftp_send_cmd(pre, "HELP"))
            feat_r = take(self._ftp_send_cmd(pre, "FEAT"))
            site_pre: str | None = None
            site_all_pre: str | None = None
            if re.search(r"\bSITE\b", help_r, re.I):
                site_pre = take(self._ftp_send_cmd(pre, "SITE HELP"))
                raw_all, err = self._ftp_send_cmd_site_help_all_safe(pre)
                if err:
                    site_all_pre_err = err
                elif raw_all is not None:
                    site_all_pre = take(raw_all)
        finally:
            try:
                pre.close()
            except Exception:
                pass

        site_post: str | None = None
        site_all_post: str | None = None
        if creds is not None:
            post = self.connect()
            try:
                post.login(creds.user, creds.passw)
                site_post = take(self._ftp_send_cmd(post, "SITE HELP"))
                raw_all_p, err_p = self._ftp_send_cmd_site_help_all_safe(post)
                if err_p:
                    site_all_post_err = err_p
                elif raw_all_p is not None:
                    site_all_post = take(raw_all_p)
            finally:
                try:
                    post.close()
                except Exception:
                    pass

        feat_labels = self._parse_feat_feature_labels(feat_r)
        risks: list[CmdAuditRisk] = []
        risks.extend(self._cmd_audit_scan_text(help_r, "helpPreAuth"))
        risks.extend(self._cmd_audit_scan_text(feat_r, "featResponse"))
        if site_pre:
            risks.extend(self._cmd_audit_scan_text(site_pre, "siteHelpPreAuth"))
        if site_all_pre:
            risks.extend(self._cmd_audit_scan_text(site_all_pre, "siteHelpAllPreAuth"))
        if site_post:
            risks.extend(self._cmd_audit_scan_text(site_post, "siteHelpPostAuth"))
        if site_all_post:
            risks.extend(self._cmd_audit_scan_text(site_all_post, "siteHelpAllPostAuth"))

        merged = self._cmd_audit_merge_risks(risks)
        result = CommandAuditResult(
            help_r,
            feat_r,
            site_pre,
            site_all_pre,
            site_post,
            site_all_post,
            feat_labels,
            merged,
            trunc_flag,
            site_all_pre_err,
            site_all_post_err,
        )
        if getattr(self, "_cmd_audit_emit", False) and not self.use_json:
            self._print_cmd_audit_terminal(result)
            self._cmd_audit_streamed = True
            self._flush_terminal()
        return result

    def _cmd_passive_audit_blob(self, ca: CommandAuditResult | None) -> str:
        if ca is None:
            return ""
        parts = [
            ca.help_pre_auth,
            ca.feat_response,
            ca.site_help_pre or "",
            ca.site_help_all_pre or "",
            ca.site_help_post or "",
            ca.site_help_all_post or "",
        ]
        return "\n".join(parts)

    def _cmd_advertised_in_passive(self, ca: CommandAuditResult | None, key: str) -> bool:
        pat = self._CMD_ACTIVE_PATTERNS.get(key)
        if pat is None or ca is None:
            return False
        return bool(pat.search(self._cmd_passive_audit_blob(ca)))

    @staticmethod
    def _cmd_active_set_socket_timeout(ftp: ftplib.FTP, seconds: float) -> None:
        if getattr(ftp, "sock", None) is not None:
            ftp.sock.settimeout(seconds)

    def _cmd_active_reconnect_if_needed(self, creds: Creds, ftp: ftplib.FTP | None) -> ftplib.FTP:
        if ftp is not None:
            try:
                self._cmd_active_set_socket_timeout(ftp, 5.0)
                ftp.sendcmd("NOOP")
                return ftp
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass
        n = self.connect()
        n.login(creds.user, creds.passw)
        n.set_pasv(not self.args.active)
        return n

    def _cmd_active_send_probe(self, ftp: ftplib.FTP, cmd: str) -> tuple[int | None, str, str | None]:
        try:
            self._cmd_active_set_socket_timeout(ftp, self._CMD_ACTIVE_PROBE_TIMEOUT)
            r = ftp.sendcmd(cmd)
            line = r.strip().split("\n")[0][:500]
            code = int(line[:3]) if len(line) >= 3 and line[:3].isdigit() else None
            self._dbg(f"{cmd} → {self._snip(line if code is None or line.startswith(str(code)) else f'{code} {line}')}")
            return code, line, None
        except ftplib.error_perm as e:
            s = str(e).strip()
            line = s.split("\n")[0][:500]
            code = int(line[:3]) if len(line) >= 3 and line[:3].isdigit() else None
            self._dbg(f"{cmd} → {self._snip(line if code is None or line.startswith(str(code)) else f'{code} {line}')}")
            return code, line, None
        except ftplib.error_temp as e:
            s = str(e).strip()
            line = s.split("\n")[0][:500]
            code = int(line[:3]) if len(line) >= 3 and line[:3].isdigit() else None
            self._dbg(f"{cmd} → {self._snip(line if code is None or line.startswith(str(code)) else f'{code} {line}')}")
            return code, line, None
        except (TimeoutError, socket.timeout, OSError, EOFError) as e:
            err = f"{type(e).__name__}: {e}"
            self._dbg(f"{cmd} → {self._snip(err)}")
            return None, "", err
        except Exception as e:
            self._dbg(f"{cmd} → {self._snip(str(e))}")
            return None, "", f"{type(e).__name__}: {e}"

    @staticmethod
    def _cmd_active_classify_code(code: int | None, error: str | None) -> str:
        if error:
            el = error.lower()
            if "timeout" in el or "timed out" in el:
                return "timeout_or_connection_lost"
            if "reset" in el or "broken pipe" in el or "eof" in el:
                return "connection_reset_or_eof"
            return "probe_error"
        if code == 530:
            return "not_logged_in_or_insufficient_privilege"
        if code == 550:
            return "action_denied_or_file_unavailable"
        if code is not None and 200 <= code < 300:
            return "command_accepted"
        if code in (501, 502, 504, 421):
            return "not_implemented_bad_sequence_or_syntax"
        if code == 500:
            return "syntax_error_or_unknown_command"
        if code is None:
            return "no_numeric_reply_code"
        return f"ftp_reply_{code}"

    def test_command_audit_active(
        self, creds: Creds, passive: CommandAuditResult | None
    ) -> CommandAuditActiveResult:
        """
        Safe SITE probes (no system paths). Per-probe socket timeout; DELE cleanup; 530 vs 550 in classification.
        """
        self._dbg(f"Safe SITE probes post-login as {creds.user!r}")
        timeout_s = self._CMD_ACTIVE_PROBE_TIMEOUT
        probe_name = f".ptsrvtester_probe_{secrets.token_hex(4)}"
        copy_name = f".ptsrvtester_probe_cp_{secrets.token_hex(4)}"
        link_name = f".ptsrvtester_probe_lnk_{secrets.token_hex(4)}"
        ftp: ftplib.FTP | None = None
        probes: list[CmdActiveProbeResult] = []
        probe_created = False
        cleanup_errs: list[str] = []

        def run_one(pid: str, cmd: str, adv_key: str) -> None:
            nonlocal ftp
            ftp = self._cmd_active_reconnect_if_needed(creds, ftp)
            code, line, err = self._cmd_active_send_probe(ftp, cmd)
            cls = self._cmd_active_classify_code(code, err)
            row = CmdActiveProbeResult(
                pid, cmd, code, line, cls, self._cmd_advertised_in_passive(passive, adv_key), err
            )
            probes.append(row)
            if not self.use_json:
                bullet, text = self._cmd_active_line(row)
                self._tprint(text, bullet)
                self._cmd_active_streamed = True
                self._flush_terminal()

        try:
            ftp = self.connect()
            ftp.login(creds.user, creds.passw)
            ftp.set_pasv(not self.args.active)
            self._cmd_active_set_socket_timeout(ftp, timeout_s)
            try:
                ftp.storbinary(f"STOR {probe_name}", BytesIO(b"PTS"))
            except Exception as e:
                return CommandAuditActiveResult(
                    timeout_s, None, True, None, tuple(), str(e)
                )
            probe_created = True

            run_one("umask", "SITE UMASK", "umask")
            run_one("chmod", f"SITE CHMOD 644 {probe_name}", "chmod")
            run_one("chown", f"SITE CHOWN __ptsrvtest_invalid_user__ {probe_name}", "chown")
            run_one("symlink", f"SITE SYMLINK {probe_name} {link_name}", "symlink")
            run_one("cpfr", f"SITE CPFR {probe_name}", "cpfr")
            run_one("cpto", f"SITE CPTO {copy_name}", "cpto")
            run_one("exec", "SITE EXEC", "exec")
        finally:
            if probe_created:
                try:
                    cf = self._cmd_active_reconnect_if_needed(creds, ftp)
                    self._cmd_active_set_socket_timeout(cf, timeout_s)
                    for victim in (link_name, copy_name, probe_name):
                        try:
                            cf.delete(victim)
                        except ftplib.Error as e:
                            cleanup_errs.append(f"{victim}: {e}")
                        except Exception as e:
                            cleanup_errs.append(f"{victim}: {type(e).__name__}: {e}")
                    try:
                        cf.close()
                    except Exception:
                        pass
                except Exception as e:
                    cleanup_errs.append(f"cleanup: {e}")
            else:
                if ftp is not None:
                    try:
                        ftp.close()
                    except Exception:
                        pass

        ce = "; ".join(cleanup_errs) if cleanup_errs else None
        if ce and not self.use_json:
            self._tprint("Cleanup failed", "WARNING")
            self._cmd_active_streamed = True
            self._flush_terminal()
        return CommandAuditActiveResult(
            timeout_s, probe_name, len(cleanup_errs) == 0, ce, tuple(probes), None
        )

    @staticmethod
    def _inv_recv_one_line_raw(
        sock: socket.socket, timeout: float, max_len: int = 65536
    ) -> tuple[bytes, str | None]:
        sock.settimeout(timeout)
        buf = bytearray()
        try:
            while len(buf) < max_len:
                ch = sock.recv(1)
                if not ch:
                    return bytes(buf), "connection_closed" if not buf else None
                buf += ch
                if buf.endswith(b"\n"):
                    break
            return bytes(buf), None
        except socket.timeout:
            return bytes(buf), "timeout"
        except OSError as e:
            return bytes(buf), f"{type(e).__name__}: {e}"

    @classmethod
    def _inv_read_ftp_reply_raw(
        cls, sock: socket.socket, timeout: float
    ) -> tuple[int | None, str, str | None]:
        lines: list[str] = []
        code: int | None = None
        err: str | None = None
        max_lines = 64
        for _ in range(max_lines):
            raw, line_err = cls._inv_recv_one_line_raw(sock, timeout)
            if line_err and line_err != "connection_closed":
                err = line_err
            if not raw:
                if not lines:
                    return None, "", err or "connection_closed"
                break
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(line)
            if len(line) >= 4 and line[0:3].isdigit():
                c = int(line[0:3])
                if line[3] == "-":
                    continue
                if line[3] == " ":
                    code = c
                    break
            elif len(line) >= 3 and line[0:3].isdigit() and len(line) == 3:
                code = int(line[0:3])
                break
            if line_err == "connection_closed":
                err = line_err
                break
            if err == "timeout":
                break
        else:
            err = err or "too_many_reply_lines"
        return code, "\n".join(lines), err

    @staticmethod
    def _inv_drain_control_socket(
        sock: socket.socket,
        max_bytes: int,
        chunk_timeout: float,
        restore_timeout: float | None,
    ) -> tuple[int, bytes]:
        """Read until idle timeout or EOF; avoids leaving tail bytes for a later session on same socket."""
        buf = bytearray()
        sock.settimeout(chunk_timeout)
        try:
            while len(buf) < max_bytes:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
        finally:
            if restore_timeout is not None:
                try:
                    sock.settimeout(restore_timeout)
                except OSError:
                    pass
        return len(buf), bytes(buf)

    @staticmethod
    def _inv_audit_ssl_context() -> ssl.SSLContext:
        """
        Same idea as pentest/self-signed clients: wrap plain socket after implicit TLS or 234 (AUTH TLS).
        Uses create_default_context() (typically TLS 1.2+ only); handshake failure vs. old TLS 1.0/1.1-only
        servers may surface as connection/setup errors — see PTL-SVC-FTP-INVCOMM-implementation.md.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _inv_classify_ssl_handshake_error(exc: ssl.SSLError) -> tuple[bool, str]:
        """
        Returns (obsolete_tls_suspected_for_old_tls_finding, tls_handshake_hint).
        "Obsolete" branch: OpenSSL / Python wording for rejected legacy protocol version.
        """
        s = str(exc)
        sl = s.lower()
        sl_nospace = sl.replace(" ", "")
        definite = (
            "unsupported_protocol" in sl_nospace
            or "version_too_low" in sl_nospace
            or "wrong_version_number" in sl_nospace
            or "wrong version number" in sl
        )
        admin = (
            "The server likely requires obsolete TLS (e.g. 1.0/1.1) or offers an incompatible handshake; "
            "the client (Python ssl.create_default_context) typically requires TLS 1.2+. "
            "The invalid-command audit (-iv) over the encrypted channel could not complete. "
            "Obsolete protocol versions increase exposure to known protocol-level weaknesses "
            "(legacy stack — verify daemon version)."
        )
        if definite:
            return True, admin
        if any(
            x in sl
            for x in (
                "version",
                "protocol",
                "wrong alert",
                "alert handshake",
                "tlsv1",
                "sslv3",
            )
        ):
            return False, (
                "Potential TLS version/protocol mismatch (server may require TLS < 1.2). "
                "See setupError for OpenSSL/Python wording."
            )
        return False, f"TLS handshake error (see setupError): {s[:400]}"

    def _inv_wrap_tls_control_socket(
        self, ctx: ssl.SSLContext, raw_sock: socket.socket, host: str
    ) -> socket.socket:
        try:
            return ctx.wrap_socket(
                raw_sock, server_hostname=host if ssl.HAS_SNI else None
            )
        except ssl.SSLError as e:
            obsolete, hint = self._inv_classify_ssl_handshake_error(e)
            raise InvCmdAuditSetupError(
                f"TLS handshake failed: {e}",
                tls_handshake_hint=hint,
                obsolete_tls_suspected=obsolete,
            ) from e

    def _inv_open_control_socket_raw(self) -> socket.socket:
        """Raw control TCP (+ TLS); consume welcome. No ftplib makefile — safe for \\x00 on wire."""
        host = str(self.args.target.ip)
        port = self.args.target.port
        t = 10.0
        ctx = self._inv_audit_ssl_context()
        raw_sock = socket.create_connection((host, port), timeout=t)
        try:
            if self.args.tls:
                sock = self._inv_wrap_tls_control_socket(ctx, raw_sock, host)
                sock.settimeout(t)
                c, text, err = self._inv_read_ftp_reply_raw(sock, t)
                if c != 220:
                    sock.close()
                    raise OSError(f"Expected 220 after implicit TLS, got {c}: {text[:400]}")
                return sock

            if self.args.starttls:
                raw_sock.settimeout(t)
                c, text, err = self._inv_read_ftp_reply_raw(raw_sock, t)
                if c != 220:
                    raw_sock.close()
                    raise OSError(f"Expected 220 before STARTTLS, got {c}: {text[:400]}")
                raw_sock.sendall(b"AUTH TLS\r\n")
                c2, t2, err2 = self._inv_read_ftp_reply_raw(raw_sock, t)
                if c2 != 234:
                    raw_sock.close()
                    raise OSError(f"Expected 234 after AUTH TLS, got {c2}: {t2[:400]}")
                sock = self._inv_wrap_tls_control_socket(ctx, raw_sock, host)
                sock.settimeout(t)
                return sock

            raw_sock.settimeout(t)
            c, text, err = self._inv_read_ftp_reply_raw(raw_sock, t)
            if c != 220:
                raw_sock.close()
                raise OSError(f"Expected 220 welcome, got {c}: {text[:400]}")
            return raw_sock
        except Exception:
            try:
                raw_sock.close()
            except Exception:
                pass
            raise

    @staticmethod
    def _inv_line_preview(payload: bytes, limit: int = 120) -> str:
        p = payload.replace(b"\r", b"").replace(b"\n", b"")
        if b"\x00" in p:
            p = p.replace(b"\x00", b"\\x00")
        try:
            s = p.decode("utf-8", errors="replace")
        except Exception:
            s = repr(p[:limit])
        return s if len(s) <= limit else s[: limit - 3] + "..."

    def _inv_probe_definitions(self) -> tuple[tuple[str, str, bytes], ...]:
        n = self._INV_AUDIT_LONG_LEN
        return (
            ("unknown_hello", "unknown_verb", b"HELLO"),
            ("user_typo", "syntax_typo", b"USERR ptsrvtest"),
            ("user_null_byte", "null_byte_injection", b"USER root\x00admin"),
            ("long_buffer_cwd", "buffer_long_line", b"CWD " + b"A" * n),
            ("long_buffer_user", "buffer_long_line", b"USER " + b"A" * n),
            ("format_string_stat", "format_string_probe", b"STAT %n%s%p%s%n"),
            ("path_traversal_rnfr", "path_traversal", b"RNFR ../../etc/passwd"),
            ("cmd_injection_site", "command_injection_site", b"SITE CHMOD 777; id; whoami"),
            ("bad_port", "data_channel_malformed", b"PORT 999,999,999,999,999,999"),
            ("pasv_garbage", "data_channel_malformed", b"PASV x"),
            ("list_typo", "syntax_typo", b"LISTT"),
            ("cwd_utf8", "encoding_stress", b"CWD " + "\u00e9test".encode("utf-8")),
            (
                "unicode_invalid_cwd",
                "encoding_stress",
                b"CWD " + b"\xff\xfe\xfd\xfc",
            ),
            # Last: may leave extra protocol data on the wire if the server parses multiple lines.
            ("double_newline_smuggle", "request_smuggling", b"USER test\r\n\r\nPASS test"),
        )

    def _inv_classify_probe(self, probe_id: str, code: int | None, recv_err: str | None) -> str:
        if recv_err in ("connection_closed",) or (
            recv_err and "reset" in recv_err.lower()
        ):
            return "connection_lost"
        if recv_err == "timeout":
            return "reply_timeout"
        if code is None:
            return "no_reply_code"
        if 200 <= code < 300:
            if (
                probe_id == "format_string_stat"
                and code in self._INV_STAT_SUCCESS_CODES
            ):
                return "stat_success_rfc_2xx"
            return "positive_2xx_unexpected"
        if code == 331 and probe_id == "user_null_byte":
            return "null_byte_user_truncation_331"
        if code == 230 and probe_id == "user_null_byte":
            return "null_byte_possible_login_230"
        if probe_id == "double_newline_smuggle" and code is not None:
            return "double_crlf_probe_reply"
        if 300 <= code < 400:
            return "continuation_3xx"
        if 400 <= code < 500:
            return "client_error_4xx"
        if 500 <= code < 600:
            return "server_error_5xx"
        return "other_reply"

    @classmethod
    def _inv_2xx_counts_toward_vulnerable(cls, probe_id: str, code: int) -> bool:
        """RFC-aligned filter: some 2xx are defined success for the command under test."""
        if probe_id == "format_string_stat" and code in cls._INV_STAT_SUCCESS_CODES:
            return False
        return True

    def _inv_raw_login(self, sock: socket.socket, creds: Creds, timeout: float) -> tuple[bool, str | None]:
        user_b = creds.user.encode("utf-8", errors="replace")
        pass_b = creds.passw.encode("utf-8", errors="replace")
        sock.sendall(b"USER " + user_b + b"\r\n")
        c, text, err = self._inv_read_ftp_reply_raw(sock, timeout)
        if err == "connection_closed":
            return False, "connection closed after USER"
        if c == 331 or c == 332:
            sock.sendall(b"PASS " + pass_b + b"\r\n")
            c2, t2, e2 = self._inv_read_ftp_reply_raw(sock, timeout)
            if c2 == 230 or c2 == 202:
                return True, None
            return False, f"PASS reply {c2}: {t2[:200]}"
        if c == 230:
            return True, None
        return False, f"USER reply {c}: {text[:200]}"

    def _inv_rate_session(
        self,
        probes: tuple[InvalidCmdProbeResult, ...],
        had_drop: bool,
        reconnect_ok: bool,
        null_suspect: bool,
    ) -> str:
        if any(
            p.reply_code is not None
            and 200 <= p.reply_code < 300
            and self._inv_2xx_counts_toward_vulnerable(p.probe_id, p.reply_code)
            for p in probes
        ):
            return "Vulnerable"
        if any(
            p.reply_code is not None
            and 300 <= p.reply_code < 400
            and p.probe_id in self._INV_3XX_CRITICAL_PROBE_IDS
            for p in probes
        ):
            return "Vulnerable"
        if any(p.classification == "null_byte_possible_login_230" for p in probes):
            return "Vulnerable"
        if had_drop:
            return "Degraded" if reconnect_ok else "Vulnerable"
        if null_suspect:
            return "Degraded"
        if any(
            p.classification == "continuation_3xx"
            and p.probe_id not in ("user_null_byte",)
            for p in probes
        ):
            return "Degraded"
        if any(
            p.probe_id in ("long_buffer_cwd", "long_buffer_user") and self._inv_pad_run(p.reply_text) == "A"
            for p in probes
        ):
            return "Degraded"
        return "Stable"

    def _inv_run_invalid_session(
        self, phase: str, sock: socket.socket, timeout: float
    ) -> InvalidCmdSessionResult:
        probes_out: list[InvalidCmdProbeResult] = []
        had_drop = False
        null_suspect = False
        stop = False
        self._inv_pad_char = None
        for probe_id, intent_label, payload in self._inv_probe_definitions():
            if stop:
                break
            line_on_wire = payload if payload.endswith(b"\r\n") else payload + b"\r\n"
            hexl = line_on_wire.hex()
            preview = self._inv_line_preview(payload)
            code: int | None = None
            text = ""
            recv_err: str | None = None
            ok_after = True
            err: str | None = None
            classification = "skipped"
            fu_cmd: str | None = None
            fu_code: int | None = None
            fu_snip: str | None = None
            nb_outcome: str | None = None
            try:
                sock.sendall(line_on_wire)
                code, text, recv_err = self._inv_read_ftp_reply_raw(sock, timeout)
                if recv_err in ("connection_closed", "timeout") or (
                    recv_err and "Broken pipe" in recv_err
                ):
                    ok_after = False
                    had_drop = True
                    stop = True
                if recv_err and recv_err not in ("connection_closed", "timeout"):
                    err = recv_err
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                ok_after = False
                had_drop = True
                stop = True
                err = f"{type(e).__name__}: {e}"
            if probe_id == "double_newline_smuggle" and ok_after:
                t_fu = min(self._INV_SMUGGLE_FOLLOWUP_TIMEOUT, timeout)
                extra_blocks: list[str] = []
                for _ in range(4):
                    c2, t2, e2 = self._inv_read_ftp_reply_raw(sock, t_fu)
                    if e2 == "connection_closed":
                        ok_after = False
                        had_drop = True
                        stop = True
                        recv_err = recv_err or e2
                        err = err or e2
                        break
                    has_body = bool((t2 or "").strip()) or c2 is not None
                    if e2 == "timeout" and not has_body:
                        break
                    if has_body:
                        extra_blocks.append(
                            f"(code={c2}) {t2}" if c2 is not None else (t2 or "")
                        )
                    if e2 == "timeout":
                        break
                if extra_blocks:
                    text = (text or "") + "\n--- smuggle_followup ---\n" + (
                        "\n--- smuggle_followup ---\n".join(extra_blocks)
                    )
                if ok_after:
                    n_drain, _dr = self._inv_drain_control_socket(
                        sock,
                        self._INV_DRAIN_MAX_BYTES,
                        self._INV_DRAIN_CHUNK_TIMEOUT,
                        timeout,
                    )
                    if n_drain:
                        text = (text or "") + f"\n--- drained_after_smuggle_bytes={n_drain} ---\n"
            classification = self._inv_classify_probe(probe_id, code, recv_err or err)
            if probe_id == "user_null_byte" and code in (331, 230):
                null_suspect = True
            if probe_id == "user_null_byte" and code == 331:
                nb_outcome = "truncation_username_prompt_password_331"
            elif probe_id == "user_null_byte" and code == 230 and ok_after:
                fu_cmd = "PWD"
                try:
                    sock.sendall(b"PWD\r\n")
                    pc, pt, pe = self._inv_read_ftp_reply_raw(sock, timeout)
                    fu_code = pc
                    fu_snip = (pt or "")[:800]
                    tl = (pt or "").lower()
                    if pc in (257, 250):
                        if "root" in tl or "/root" in tl:
                            nb_outcome = "critical_suspected_root_context_after_null_user_pwd_ok"
                        else:
                            nb_outcome = "logged_in_after_null_user_verify_with_pwd_response"
                    else:
                        nb_outcome = "logged_in_230_pwd_follow_up_unexpected"
                    if pe in ("connection_closed", "timeout") or (
                        pe and "Broken pipe" in pe
                    ):
                        ok_after = False
                        had_drop = True
                        stop = True
                except (BrokenPipeError, ConnectionResetError, OSError) as e:
                    ok_after = False
                    had_drop = True
                    stop = True
                    fu_snip = str(e)[:200]
                    nb_outcome = "logged_in_230_pwd_follow_up_failed"
            probes_out.append(
                InvalidCmdProbeResult(
                    phase,
                    probe_id,
                    intent_label,
                    hexl,
                    preview,
                    code,
                    text[: self._INV_AUDIT_REPLY_TEXT_MAX] if text else "",
                    classification,
                    ok_after,
                    err,
                    fu_cmd,
                    fu_code,
                    fu_snip,
                    nb_outcome,
                )
            )
            self._inv_emit_probe(probes_out[-1])

        reconnect_ok = False
        if had_drop:
            time.sleep(1.0)
            try:
                s2 = self._inv_open_control_socket_raw()
                s2.close()
                reconnect_ok = True
            except Exception:
                reconnect_ok = False
            if not self.use_json:
                self._dbg("Reconnect: ok" if reconnect_ok else "Reconnect: failed")
                self._flush_terminal()
                if not reconnect_ok:
                    where = ""
                    if getattr(self, "_inv_show_phase", False):
                        where = "before login " if phase == "preAuth" else "after login "
                    self._tprint(f"A new connection {where}was refused after the drop", "VULN")
                    self._flush_terminal()

        rating = self._inv_rate_session(
            tuple(probes_out), had_drop, reconnect_ok, null_suspect
        )
        return InvalidCmdSessionResult(
            phase, tuple(probes_out), rating, null_suspect, had_drop
        )

    def _inv_overall_resilience(
        self, pre: InvalidCmdSessionResult | None, post: InvalidCmdSessionResult | None
    ) -> str:
        order = {"Stable": 0, "Degraded": 1, "Vulnerable": 2}
        best = "Stable"
        for s in (pre, post):
            if s is None:
                continue
            if order.get(s.resilience_rating, 0) > order[best]:
                best = s.resilience_rating
        return best

    def test_invalid_command_audit(
        self, creds: Creds | None
    ) -> InvalidCmdAuditResult:
        """
        PTL-SVC-FTP-INVCOMM: invalid / malformed control lines via raw socket (bytes on wire).
        Includes USER root\\x00… null-byte probe; resilienceRating Stable|Degraded|Vulnerable.
        """
        self._inv_terminal_emitted = False
        self._inv_login_note_emitted = False
        self._inv_show_phase = creds is not None
        timeout = self._INV_AUDIT_TIMEOUT
        pre: InvalidCmdSessionResult | None = None
        post: InvalidCmdSessionResult | None = None
        try:
            s = self._inv_open_control_socket_raw()
        except InvCmdAuditSetupError as e:
            return InvalidCmdAuditResult(
                timeout,
                None,
                None,
                "Stable",
                False,
                str(e),
                None,
                tls_handshake_hint=e.tls_handshake_hint,
                obsolete_tls_suspected=e.obsolete_tls_suspected,
            )
        except Exception as e:
            return InvalidCmdAuditResult(timeout, None, None, "Stable", False, str(e), None)
        try:
            pre = self._inv_run_invalid_session("preAuth", s, timeout)
        finally:
            try:
                s.close()
            except Exception:
                pass

        post: InvalidCmdSessionResult | None = None
        post_login_err: str | None = None
        post_tls_hint: str | None = None
        post_obsolete_tls = False
        if creds is not None:
            try:
                s2 = self._inv_open_control_socket_raw()
            except InvCmdAuditSetupError as e:
                post_login_err = f"post-auth connection: {e}"
                post_tls_hint = e.tls_handshake_hint
                post_obsolete_tls = e.obsolete_tls_suspected
            except Exception as e:
                post_login_err = f"post-auth connection: {e}"
            else:
                try:
                    ok, lerr = self._inv_raw_login(s2, creds, timeout)
                    if ok:
                        post = self._inv_run_invalid_session("postAuth", s2, timeout)
                    else:
                        post_login_err = lerr or "login failed"
                finally:
                    try:
                        s2.close()
                    except Exception:
                        pass

        overall = self._inv_overall_resilience(pre, post)
        null_any = bool(
            (pre and pre.null_byte_truncation_suspected)
            or (post and post.null_byte_truncation_suspected)
        )
        if post_login_err and not self.use_json:
            self._dbg(f"After login: {self._snip(post_login_err)}")
            self._flush_terminal()
            self._tprint("Login failed. Commands after login were not tested.", "WARNING")
            self._flush_terminal()
            self._inv_login_note_emitted = True
        return InvalidCmdAuditResult(
            timeout,
            pre,
            post,
            overall,
            null_any,
            None,
            post_login_err,
            tls_handshake_hint=post_tls_hint,
            obsolete_tls_suspected=post_obsolete_tls,
        )

    def test_encryption(self) -> EncryptionResult:
        """
        Test encryption options: plaintext (21), AUTH TLS (explicit), implicit TLS (990).
        Uses fresh connections; does not use self.args.tls/starttls.
        AUTH TLS sends AUTH TLS command then TLS handshake (RFC 2228).
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        plaintext_ok = False
        auth_tls_ok = False
        tls_ok = False
        plaintext_incomplete = False
        auth_tls_incomplete = False
        tls_incomplete = False
        _ssl_ctx = ssl._create_unverified_context()
        tls_only_port = port == 990

        if not tls_only_port:
            # 1. Plaintext (no TLS)
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=timeout)
                _ = ftp.welcome
                plaintext_ok = True
                self._dbg(f"Plaintext welcome: {self._snip(ftp.welcome)}")
                ftp.close()
            except Exception as e:
                plaintext_incomplete = self._ftp_text_is_unconfirmed(str(e))
                self._dbg(f"Plaintext test failed: {e}")

            # 2. AUTH TLS (explicit: plain connect, then AUTH TLS + TLS handshake)
            try:
                ftp = ftplib.FTP_TLS()
                ftp.connect(host, port, timeout=timeout)
                _ = ftp.welcome
                self._dbg(f"AUTH TLS probe welcome: {self._snip(ftp.welcome)}")
                ftp.auth()
                self._dbg("AUTH TLS → handshake OK")
                auth_tls_ok = True
                ftp.close()
            except Exception as e:
                auth_tls_incomplete = self._ftp_text_is_unconfirmed(str(e))
                self._dbg(f"AUTH TLS test failed: {e}")

        # 3. Implicit TLS (port 990)
        _connect_timeout = 15.0 if tls_only_port else timeout

        def _try_implicit_tls(sni):
            nonlocal tls_incomplete
            ftp = FTP_TLS_implicit()
            ftp.context = _ssl_ctx
            try:
                ftp.connect(host, port, timeout=_connect_timeout)
                _ = ftp.welcome
                self._dbg(
                    f"Implicit TLS (SNI={sni!r}) welcome: {self._snip(ftp.welcome)} → OK"
                )
                return True
            except Exception as e:
                self._dbg(f"Implicit TLS test failed (SNI={sni!r}): {e}")
                if self._ftp_text_is_unconfirmed(str(e)):
                    tls_incomplete = True
                return False
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

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
                    if _try_implicit_tls(_sni):
                        tls_ok = True
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return EncryptionResult(
            plaintext_ok,
            auth_tls_ok,
            tls_ok,
            plaintext_incomplete,
            auth_tls_incomplete,
            tls_incomplete,
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

    _FTP_HELP_TOKEN = re.compile(r"^[A-Z][A-Z0-9]{0,15}\*?$")
    # RFC 959 SITE is ordinary. These arguments are not (same set as the command-surface audit).
    _FTP_SITE_ERROR = (
        (re.compile(r"\bSITE\s+(?:EXEC|EXECUTE|RUN)\b", re.I), "SITE EXEC"),
    )
    _FTP_SITE_WARNING = (
        (re.compile(r"\bSITE\s+CHMOD\b", re.I), "SITE CHMOD"),
        (re.compile(r"\bSITE\s+CHOWN\b", re.I), "SITE CHOWN"),
        (re.compile(r"\bSITE\s+UMASK\b", re.I), "SITE UMASK"),
        (re.compile(r"\bSITE\s+(?:SYMLINK|LINK|LN)\b", re.I), "SITE SYMLINK"),
        (re.compile(r"\bSITE\s+CPFR\b", re.I), "SITE CPFR"),
        (re.compile(r"\bSITE\s+CPTO\b", re.I), "SITE CPTO"),
        (re.compile(r"\bSITE\s+WHO\b", re.I), "SITE WHO"),
        (re.compile(r"\bSITE\s+IDLE\b", re.I), "SITE IDLE"),
    )

    def _ftp_commands_encrypted(self) -> bool:
        port = getattr(getattr(self.args, "target", None), "port", None)
        return bool(port == 990 or getattr(self.args, "tls", False) or getattr(self.args, "starttls", False))

    def _ftp_help_command_rows(self, help_text: str) -> list[tuple[str, bool]]:
        """Implemented command names from a HELP listing. A trailing * means unimplemented."""
        rows: list[tuple[str, bool]] = []
        seen: set[str] = set()
        for raw in (help_text or "").replace("\r", "").splitlines():
            body = re.sub(r"^\d{3}[ -]", "", raw).strip()
            toks = body.split()
            if not toks:
                continue
            matched = [t for t in toks if self._FTP_HELP_TOKEN.match(t)]
            if not matched or len(matched) != len(toks):
                continue
            for tok in matched:
                implemented = not tok.endswith("*")
                name = tok[:-1] if tok.endswith("*") else tok
                if name in seen:
                    continue
                seen.add(name)
                if implemented:
                    rows.append((name, True))
        return rows

    def _ftp_command_level(self, name: str) -> str:
        """OK, WARNING, or ERROR. Ordinary RFC commands stay OK."""
        if name == "CCC":
            # RFC 2228: CCC drops integrity and confidentiality on the control connection.
            return "WARNING"
        return "OK"

    def _ftp_command_rows(self, help_text: str | None, syst: str | None, stat: str | None) -> list[tuple[str, str]]:
        """One (label, level) row per advertised command, in EHLO/CAPA order."""
        text = help_text or ""
        listed = self._ftp_help_command_rows(text)
        names = {name for name, _ in listed}
        rows: list[tuple[str, str]] = []
        syst_body = ""
        if syst:
            m = re.match(r"^\s*215[ -](.*)$", syst, re.S)
            syst_body = (m.group(1) if m else "").strip().splitlines()[0].strip() if m else ""
        generic_syst = bool(re.match(r"UNIX Type:\s*L8\b", syst_body, re.I))
        for name, _implemented in listed:
            label = name
            level = self._ftp_command_level(name)
            if name == "SYST" and syst_body:
                label = f"SYST {syst_body}"
                if not generic_syst:
                    level = "WARNING"
            elif name == "STAT" and stat and re.match(r"^\s*21[123]\b", stat):
                label = "STAT before login"
                level = "WARNING"
            rows.append((label, level))
        if "SYST" not in names and syst_body:
            rows.append((f"SYST {syst_body}", "OK" if generic_syst else "WARNING"))
        for pattern, label in self._FTP_SITE_ERROR:
            if pattern.search(text):
                rows.append((label, "ERROR"))
        for pattern, label in self._FTP_SITE_WARNING:
            if pattern.search(text):
                rows.append((label, "WARNING"))
        if listed and "AUTH" not in names and not self._ftp_commands_encrypted():
            # RFC 4217: cleartext FTP should offer AUTH TLS, as EHLO should offer STARTTLS.
            rows.append(("AUTH TLS (is not allowed)", "ERROR"))
        email = re.search(r"[\w.+-]+@[\w.-]+\.\w+", text)
        if email:
            rows.append((f"HELP contact {email.group(0)}", "WARNING"))
        if help_text and not listed and not rows:
            rows.append((f"HELP: {self._snip(help_text)}", "WARNING"))
        return rows

    @staticmethod
    def _ftp_command_bullet(level: str) -> str:
        if level == "ERROR":
            return "VULN"
        if level == "WARNING":
            return "WARNING"
        return "NOTVULN"

    def _stream_commands_result(self) -> None:
        """HELP/SYST/STAT as one classified list. -vv lines were recorded in info()."""
        if getattr(self, "_commands_streamed", False):
            return
        if not self.results.commands_requested or self.use_json:
            return
        if not (info := self.results.info):
            return
        if info.help_response is None and info.syst is None and info.stat is None:
            return
        rows = self._ftp_command_rows(info.help_response, info.syst, info.stat)
        title = "FTP commands (TLS)" if self._ftp_commands_encrypted() else "FTP commands (PLAIN)"
        with self._output_lock:
            self._ptprint(title, Out.INFO)
            for label, level in rows:
                self._ptprint_raw(
                    label,
                    bullet_type=self._ftp_command_bullet(level),
                    condition=True,
                    indent=4,
                )
        self._commands_streamed = True
        self._flush_terminal()

    def _stream_encryption_result(self) -> None:
        """Stream encryption test result to terminal (thread-safe)."""
        pp = self._ptprint_raw
        show = not self.use_json
        with self._output_lock:
            if (encryption_error := self.results.encryption_error) is not None:
                pp(f"Encryption test failed: {encryption_error}", bullet_type="VULN", condition=show, indent=4)
                return
            enc = self.results.encryption
            if enc is None:
                return
            any_ok = enc.plaintext_ok or enc.auth_tls_ok or enc.tls_ok
            any_inc = enc.plaintext_incomplete or enc.auth_tls_incomplete or enc.tls_incomplete
            plaintext_only = (
                enc.plaintext_ok and not enc.auth_tls_ok and not enc.tls_ok and not any_inc
            )
            if not any_ok and any_inc:
                pp(
                    "Could not connect. Encryption was not tested.",
                    bullet_type="WARNING",
                    condition=show,
                    indent=4,
                )
            elif plaintext_only:
                pp("Plaintext only", bullet_type="VULN", condition=show, indent=4)
            elif any_ok or any_inc:
                if enc.plaintext_ok:
                    bullet = "WARNING" if (enc.auth_tls_ok or enc.tls_ok or any_inc) else "NOTVULN"
                    pp("Plaintext", bullet_type=bullet, condition=show, indent=4)
                elif enc.plaintext_incomplete:
                    pp("Plaintext timed out (not confirmed)", bullet_type="WARNING", condition=show, indent=4)
                if enc.auth_tls_ok:
                    pp("AUTH TLS", bullet_type="NOTVULN", condition=show, indent=4)
                elif enc.auth_tls_incomplete:
                    pp("AUTH TLS timed out (not confirmed)", bullet_type="WARNING", condition=show, indent=4)
                if enc.tls_ok:
                    pp("Implicit TLS", bullet_type="NOTVULN", condition=show, indent=4)
                elif enc.tls_incomplete:
                    pp("Implicit TLS timed out (not confirmed)", bullet_type="WARNING", condition=show, indent=4)
            else:
                pp(
                    "Could not connect. Encryption was not tested.",
                    bullet_type="WARNING",
                    condition=show,
                    indent=4,
                )

    def _stream_anonymous_result(self) -> None:
        """Stream anonymous auth result immediately (thread-safe)."""
        pp = self._ptprint_raw
        show = not self.use_json
        if (anonymous := self.results.anonymous) is None:
            return
        with self._output_lock:
            if anonymous:
                pp("Enabled", bullet_type="VULN", condition=show, indent=4)
            else:
                pp("Disabled", bullet_type="NOTVULN", condition=show, indent=4)

    @staticmethod
    def _access_fact(value: str | None) -> str:
        return value if value else "no"

    def _stream_access_check_terminal(self) -> None:
        """Print --access results under [+] Access check."""
        pp = self._ptprint_raw
        show = not self.use_json
        access = self.results.access
        if access is None:
            return
        with self._output_lock:
            if access.errors:
                for e in access.errors:
                    pp(e, bullet_type="WARNING", condition=show, indent=4)
            if access.results:
                for p in access.results:
                    pp(
                        f"user: {p.creds.user}, password: {p.creds.passw}",
                        bullet_type="TEXT",
                        condition=show,
                        indent=4,
                    )
                    if (
                        p.dirlist is None
                        and not p.write
                        and not p.read
                        and not p.delete
                        and any(self._ftp_text_is_unconfirmed(err) for err in (access.errors or []))
                    ):
                        pp(
                            "Access was not confirmed. The connection timed out or never completed.",
                            bullet_type="WARNING",
                            condition=show,
                            indent=8,
                        )
                        continue
                    listing = "yes" if p.dirlist is not None else "no"
                    for line in (
                        f"Directory listing: {listing}",
                        f"Write: {self._access_fact(p.write)}",
                        f"Read: {self._access_fact(p.read)}",
                        f"Delete: {self._access_fact(p.delete)}",
                    ):
                        pp(line, bullet_type="TEXT", condition=show, indent=8)
            if access.errors and self.results.anonymous is not True:
                pp(
                    "Use --anonymous (-A), or -u USER -p PASS, or wordlists (-U/-P).",
                    bullet_type="WARNING",
                    condition=show,
                    indent=4,
                )

    def _stream_brute_result(self) -> None:
        """Found logins, then whether the server stopped password guessing."""
        creds = self.results.creds
        guessing = getattr(self, "_brute_guessing", None)
        if (creds is None or len(creds) == 0) and guessing is None:
            return
        with self._output_lock:
            if creds:
                n = len(creds)
                word = "login" if n == 1 else "logins"
                self._ptprint_raw(
                    f"Found {n} valid {word}",
                    bullet_type="INFO",
                    condition=not self.use_json,
                    indent=4,
                )
            if guessing == "not_limited":
                self._tprint("No protection against password guessing", "VULN")
            elif guessing == "stopped":
                self._tprint("Password guessing was stopped", "NOTVULN")
            elif guessing == "not_tested":
                self._tprint(
                    getattr(self, "_brute_guessing_detail", None)
                    or "Could not connect. Password guessing was not tested.",
                    "WARNING",
                )

    def _stream_directory_listing_result(self) -> None:
        if self.use_json or not self.args.access_list:
            return
        access = self.results.access
        if access is None or access.results is None:
            return
        with self._output_lock:
            try:
                p = next(p for p in access.results if p.dirlist is not None and len(p.dirlist) > 0)
                self._ptprint("Directory listing", Out.INFO)
                for line in "\n".join(p.dirlist).splitlines():
                    self._tprint(line, "TEXT", indent=4)
            except StopIteration:
                self._ptprint("Directory listing failed (no access or empty listing)", Out.INFO)

    def _stream_path_enum_result(self) -> None:
        if self.use_json or getattr(self, "_enumpath_streamed", False):
            return
        err = getattr(self.results, "path_enum_error", None)
        if err is not None:
            self._tprint(err, "WARNING" if self._is_login_skip(err) else "VULN")
            return
        self._tprint("No wordlist path was reachable", "NOTVULN")

    def _stream_modes_result(self) -> None:
        if self.use_json or getattr(self, "_modes_streamed", False):
            return
        with self._output_lock:
            if (err := getattr(self.results, "modes_error", None)) is not None:
                self._tprint(err, "WARNING" if self._is_login_skip(err) else "VULN")
            elif (modes := getattr(self.results, "modes", None)) is not None:
                passive_open = self._ftp_text_is_unconfirmed(modes.passive_error)
                if (
                    not modes.passive_ok
                    and not modes.active_ok
                    and passive_open
                    and self._ftp_text_is_unconfirmed(modes.active_error)
                ):
                    self._tprint(
                        "Could not connect. Data modes were not tested.",
                        "WARNING",
                    )
                else:
                    if modes.passive_ok:
                        self._tprint("Passive: available", "NOTVULN")
                    elif passive_open:
                        self._tprint("Passive timed out (not confirmed)", "WARNING")
                    else:
                        self._tprint("Passive: not available", "VULN")
                    if modes.active_ok:
                        self._tprint("Active: available", "NOTVULN")
                    elif self._ftp_server_reply(modes.active_error):
                        self._tprint("Active: not available", "VULN")
                    else:
                        self._tprint("Active timed out (not confirmed)", "WARNING")
                        self._tprint(
                            "Active mode was not confirmed. A timeout can also mean the tester is behind NAT or a firewall.",
                            "WARNING",
                        )
                if modes.pasv_ip_leak:
                    self._tprint(
                        f"PASV Internal IP Leak: server advertised {modes.pasv_ip_leak}",
                        "VULN",
                    )

    def _stream_pasv_port_range_result(self) -> None:
        if self.use_json or getattr(self, "_pasvport_streamed", False):
            return
        err = getattr(self.results, "pasv_port_range_error", None)
        if err is not None:
            bullet = "WARNING" if self._ftp_text_is_unconfirmed(err) or self._is_login_skip(err) else "VULN"
            self._tprint(err, bullet)
        elif (ppr := getattr(self.results, "pasv_port_range", None)) is not None:
            self._pasvport_report(ppr)

    def _stream_conn_limits_result(self) -> None:
        if self.use_json or getattr(self, "_connlim_streamed", False):
            return
        err = getattr(self.results, "conn_limits_error", None)
        if err is not None:
            self._tprint(f"Connection limits test failed: {err}", "VULN")

    def _stream_chroot_audit_result(self) -> None:
        if self.use_json or getattr(self, "_chroot_streamed", False):
            return
        with self._output_lock:
            if (err := getattr(self.results, "chroot_audit_error", None)) is not None:
                bullet = "WARNING" if self._ftp_text_is_unconfirmed(err) or self._is_login_skip(err) else "VULN"
                self._tprint(err, bullet)

    def _stream_active_audit_result(self) -> None:
        if self.use_json:
            return
        with self._output_lock:
            if (err := getattr(self.results, "active_audit_error", None)) is not None:
                self._ptprint("Active mode policy", Out.INFO)
                self._tprint(err, "VULN")
            elif (aa := getattr(self.results, "active_audit", None)) is not None:
                self._print_active_audit_terminal(aa)

    def _stream_cmd_audit_result(self) -> None:
        if self.use_json or getattr(self, "_cmd_audit_streamed", False):
            return
        with self._output_lock:
            if (err := getattr(self.results, "cmd_audit_error", None)) is not None:
                bullet = "WARNING" if self._ftp_text_is_unconfirmed(err) else "VULN"
                self._tprint("Could not connect. Commands were not tested." if bullet == "WARNING" else err, bullet)
            elif (ca := getattr(self.results, "cmd_audit", None)) is not None:
                self._print_cmd_audit_terminal(ca)

    def _stream_cmd_audit_active_result(self) -> None:
        if self.use_json or getattr(self, "_cmd_active_streamed", False):
            return
        with self._output_lock:
            if (err := getattr(self.results, "cmd_audit_active_error", None)) is not None:
                bullet = "WARNING" if self._ftp_text_is_unconfirmed(err) or self._is_login_skip(err) else "VULN"
                self._tprint(err, bullet)
            elif (caa := getattr(self.results, "cmd_audit_active", None)) is not None:
                if caa.setup_error:
                    bullet = "WARNING" if self._ftp_text_is_unconfirmed(caa.setup_error) else "VULN"
                    self._tprint(caa.setup_error, bullet)
                else:
                    for p in caa.probes:
                        bullet, text = self._cmd_active_line(p)
                        self._tprint(text, bullet)
                    if not caa.cleanup_ok:
                        self._tprint("Cleanup failed", "WARNING")

    def _stream_invalid_cmd_audit_result(self) -> None:
        if self.use_json:
            return
        with self._output_lock:
            if (err := getattr(self.results, "invalid_cmd_audit_error", None)) is not None:
                self._tprint(f"Invalid commands test failed: {self._snip(err)}", "WARNING")
            elif (inv := getattr(self.results, "invalid_cmd_audit", None)) is not None:
                self._print_invalid_cmd_audit_terminal(inv)

    def _stream_user_enum_result(self) -> None:
        if self.use_json:
            return
        with self._output_lock:
            if (err := getattr(self.results, "user_enum_error", None)) is not None:
                self._ptprint("Username enumeration audit (-eu / PTL-SVC-FTP-USRENUM)", Out.INFO)
                self._tprint(err, "VULN")
            elif (ue := getattr(self.results, "user_enum", None)) is not None:
                self._print_user_enum_terminal(ue)

    def _stream_eicar_audit_result(self) -> None:
        if self.use_json:
            return
        with self._output_lock:
            if (err := getattr(self.results, "eicar_audit_error", None)) is not None:
                self._ptprint("Antivirus probe (EICAR)", Out.INFO)
                self._tprint(err, "VULN")
            elif (ea := getattr(self.results, "eicar_audit", None)) is not None:
                self._print_eicar_audit_terminal(ea)

    def _stream_dos_audit_result(self) -> None:
        if self.use_json:
            return
        with self._output_lock:
            if (err := getattr(self.results, "dos_audit_error", None)) is not None:
                self._tprint(err, "WARNING" if self._is_login_skip(err) else "VULN")
            elif (dos := getattr(self.results, "dos_audit", None)) is not None:
                self._print_ftp_dos_audit_terminal(dos)

    def _stream_bounce_result(self) -> None:
        if self.use_json or (bounce := self.results.bounce) is None:
            return
        with self._output_lock:
            if (creds := bounce.used_creds) is None:
                self._ptprint("Bounce attack failed (no valid credentials)", Out.INFO)
                return
            self._ptprint("Bounce attack", Out.INFO)
            self._tprint(f"Creds used: {creds.user}:{creds.passw}", "TEXT")
            if bounce.bounce_accepted:
                self._tprint("Bounce is allowed", "VULN")
            else:
                self._tprint("Bounce is denied", "NOTVULN")
            if not bounce.bounce_accepted:
                return
            if (r := bounce.request) is None:
                self._tprint(f"Target port reachable: {bounce.port_accessible}", "TEXT", indent=8)
            else:
                res = f"Yes ({r.ftpserver_filepath})" if r.stored else "No"
                self._tprint(f"Stored on FTP server: {res}", "TEXT", indent=8)
                res = "Yes" if r.uploaded else "No"
                self._tprint(f"Sent to bounce target: {res}", "TEXT", indent=8)
                res = "Yes" if r.cleaned else "No"
                self._tprint(f"Cleaned up: {res}", "TEXT", indent=8)

    _FTP_BRUTE_LOCK_RE = re.compile(
        r"lock(?:ed|out)?|too many|banned|blocked|try again|exceed|throttl",
        re.I,
    )

    def _ftp_brute_hit(self, output, cred: Creds) -> None:
        line = out_if(
            f"user: {cred.user}, password: {shown_password(cred.passw)}",
            "VULN",
            True,
            colortext=True,
            indent=0,
        )
        if line and output is not None:
            output.add_string_to_output(line.rstrip("\n"))

    def _ftp_brute_kind(self, raw: str) -> str:
        code, _line = self._ftp_parse_reply_line(raw)
        if code == 421 or self._FTP_BRUTE_LOCK_RE.search(raw or ""):
            return "blocked"
        if "cannot change directory" in (raw or "").lower():
            return "ok"
        return "fail"

    def _ftp_brute_cmd(self, ftp, command: str) -> tuple[int | None, str, str]:
        """Send one command. Returns code, reply line, and ok|fail|blocked|down."""
        try:
            resp = ftp.sendcmd(command)
        except (ftplib.error_perm, ftplib.error_temp) as e:
            raw = str(e.args[0]) if e.args else str(e)
            code, line = self._ftp_parse_reply_line(raw)
            return code, line, self._ftp_brute_kind(raw)
        except (OSError, EOFError, ftplib.Error) as e:
            raw = str(e)
            kind = "blocked" if self._ftp_brute_kind(raw) == "blocked" else "down"
            return None, raw, kind
        code, line = self._ftp_parse_reply_line(resp)
        if code is not None and 200 <= code < 300:
            return code, line, "ok"
        return code, line, self._ftp_brute_kind(line)

    def _ftp_brute_one(self, cred: Creds, output) -> str:
        """One USER/PASS. ok, fail, blocked, or down."""
        if self._brute_stop.is_set():
            return "skip"
        shown = cred.user if len(cred.user) <= 32 else cred.user[:29] + "..."
        try:
            ftp = self.connect()
        except OSError as e:
            raw = str(e)
            self._user_enum_trace(f"{shown!r}: connect failed {self._snip(raw)}", output)
            if self._FTP_BRUTE_LOCK_RE.search(raw) or "421" in raw:
                return "limited"
            return "down"
        try:
            ucode, uline, ukind = self._ftp_brute_cmd(ftp, "USER " + cred.user)
            if ukind in ("blocked", "down") or ucode not in (331, 332):
                self._user_enum_trace(
                    f"{shown!r}: USER {self._user_enum_dbg_reply(ucode, uline)}",
                    output,
                )
                if ukind == "ok":
                    self._ftp_brute_hit(output, cred)
                return ukind
            pcode, pline, pkind = self._ftp_brute_cmd(ftp, "PASS " + cred.passw)
            pass_label = 'PASS ""' if cred.passw == "" else "PASS"
            self._user_enum_trace(
                f"{shown!r}: USER {self._user_enum_dbg_reply(ucode, uline)}; "
                f"{pass_label} {self._user_enum_dbg_reply(pcode, pline)}",
                output,
            )
            if pkind == "ok":
                self._ftp_brute_hit(output, cred)
            return pkind
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def _ftp_auth_catch_all(self) -> str:
        """One USER/PASS with a random user and password (RFC 959)."""
        fake_user = "".join(random.choices(string.ascii_letters + string.digits, k=24))
        fake_pass = "".join(random.choices(string.ascii_letters + string.digits, k=24))
        try:
            ftp = self.connect()
        except OSError as e:
            raw = str(e)
            self._dbg(f"Catch-all: connect failed: {self._snip(raw)}")
            if self._FTP_BRUTE_LOCK_RE.search(raw) or "421" in raw:
                return "limited"
            return "unreachable"
        try:
            self._dbg(f"Catch-all USER {fake_user!r}")
            ucode, uline, ukind = self._ftp_brute_cmd(ftp, "USER " + fake_user)
            if ukind == "ok":
                self._dbg("Catch-all USER → accepted (indeterminate)")
                return "indeterminate"
            if ukind == "down" or ucode not in (331, 332):
                self._dbg(f"Catch-all rejected (not configured): {self._user_enum_dbg_reply(ucode, uline)}")
                return "unreachable" if ukind == "down" else "not_configured"
            self._dbg("Catch-all USER → accepted, trying PASS")
            pcode, pline, pkind = self._ftp_brute_cmd(ftp, "PASS " + fake_pass)
            if pkind == "ok":
                self._dbg("Catch-all PASS → accepted (indeterminate)")
                return "indeterminate"
            if pkind == "down":
                self._dbg(f"Catch-all: PASS failed {self._snip(pline)}")
                return "unreachable"
            self._dbg(f"Catch-all rejected (not configured): {self._user_enum_dbg_reply(pcode, pline)}")
            return "not_configured"
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def _ftp_brute_label(self, cred: Creds) -> str:
        name = cred.user
        if len(name) > 24:
            return name[:21] + "..."
        return name

    def login_bruteforce(self) -> set[Creds]:
        """Try the supplied passwords. Gray progress like user enumeration. -vv is USER/PASS per attempt."""
        users = text_or_file(self.args.user, self.args.users)
        passwords = brute_passwords(self.args.password, self.args.passwords)
        if self.args.spray:
            creds = [Creds(u, p) for p in passwords for u in users]
        else:
            creds = [Creds(u, p) for u in users for p in passwords]
        threads = self.args.threads if self.args.threads is not None else 10
        threads = max(1, int(threads))
        self._brute_stop = threading.Event()
        self._brute_guessing = None
        found: set[Creds] = set()
        if not creds:
            self._tprint("No usernames or passwords to try.", "WARNING")
            return found

        progress = ThreadedProgress(
            len(creds),
            enabled=not self.use_json,
            indent=4,
            bar_indent=4,
        )
        progress.kickoff(self._ftp_brute_label(creds[0]))
        state = {"downs": 0, "saw_reply": False, "blocked": False, "note": None}
        lock = threading.Lock()

        def work(cred: Creds, output) -> str:
            kind = self._ftp_brute_one(cred, output)
            with lock:
                if kind == "ok":
                    found.add(cred)
                    state["saw_reply"] = True
                    state["downs"] = 0
                elif kind == "fail":
                    state["saw_reply"] = True
                    state["downs"] = 0
                elif kind == "blocked":
                    state["blocked"] = True
                    state["saw_reply"] = True
                    self._brute_stop.set()
                elif kind == "limited":
                    if state["saw_reply"]:
                        state["blocked"] = True
                    else:
                        state["note"] = (
                            "Connection rate limit. Password guessing was not tested."
                        )
                    self._brute_stop.set()
                elif kind == "down":
                    state["downs"] += 1
                    if state["saw_reply"] and state["downs"] >= 3:
                        state["blocked"] = True
                        self._brute_stop.set()
            return self._ftp_brute_label(cred)

        try:
            progress.run(creds, work, threads)
        finally:
            progress.finalize()

        if state["blocked"]:
            self._brute_guessing = "stopped"
        elif state["saw_reply"]:
            self._brute_guessing = "not_limited"
        else:
            self._brute_guessing = "not_tested"
            self._brute_guessing_detail = state["note"]
        self.results.creds = found
        return found

    def _try_login(self, creds: Creds) -> Creds | None:
        """Login attempt function for bruteforce

        Args:
            creds (Creds): Creds to use for login

        Returns:
            Creds | None: Creds if success, None if failed
        """
        try:
            ftp = self.connect()
        except OSError as e:
            self._dbg(f"Login {creds.user!r}: connect failed: {e}")
            return None
        try:
            self._dbg(f"USER {creds.user!r}")
            ftp.login(creds.user, creds.passw)
            self._dbg(f"PASS → OK (valid: {creds.user!r})")
            result = creds
        except Exception as e:
            # Valid creds but server-side error?
            if e.args and len(e.args) > 0:
                if "cannot change directory" in str(e.args[0]).lower():
                    self._dbg(
                        f"PASS → OK (valid: {creds.user!r}, cannot change directory)"
                    )
                    result = creds
                else:
                    self._dbg(f"PASS → failed for {creds.user!r}: {self._snip(str(e))}")
                    result = None
            else:
                self._dbg(f"PASS → failed for {creds.user!r}: {self._snip(str(e))}")
                result = None
        finally:
            ftp.close()
            return result

    def bounce(self) -> BounceResult:
        """
        Attempts to login (anonymous or valid bruteforce creds) and
        perform an FTP bounce attack, either for port scan or
        request via file upload.

        Returns:
            BounceResult: results
        """

        creds: Creds | None = None
        write_path: str | None = None

        # Choose valid creds (any for --bounce, write-permitted for --bounce-file)
        if not self.args.bounce_file:
            # Any creds for port scan
            if self.results.anonymous:
                creds = Creds("anonymous", "")
            elif self.results.creds is not None and len(self.results.creds) > 0:
                for c in self.results.creds:
                    creds = c
                    break
        elif (access := self.results.access) is not None and access.results:
            # Write & Read creds for bounced request
            for p in access.results:
                if p.write is None or p.read is None:
                    continue
                else:
                    creds = p.creds
                    write_path = p.write

        if creds is None:
            return BounceResult(self.args.bounce, None, None, None, None)

        # Use the appropriate creds to connect to the service
        ftp = self.connect()
        ftp.login(creds.user, creds.passw)

        # Bounce setup attempt
        if not self._bounce_setup(ftp, self.args.bounce):
            return BounceResult(self.args.bounce, creds, False, None, None)

        if self.args.bounce_file and write_path is not None:
            # Full bounced request
            stored, uploaded, cleaned = False, False, False
            filename = write_path + ".txt"

            try:
                # Upload request file onto FTP server
                with open(self.args.bounce_file, "rb") as f:
                    # reusing previous filename, with doubled .txt extension
                    p = ftp.storbinary("STOR " + filename, f)
                    stored = True

                # Refresh bounce setup after STOR
                self._bounce_setup(ftp, self.args.bounce)

                # Upload request to bounce target
                # TODO timeout for unreachable ports?
                ftp.sendcmd("RETR " + filename)
                uploaded = True
            except FileNotFoundError:
                raise argparse.ArgumentError(None, f"File not found: '{self.args.bounce_file}'")
            except PermissionError:
                raise argparse.ArgumentError(
                    None, f"Cannot read file (permission denied): '{self.args.bounce_file}'"
                )
            except OSError as e:
                raise argparse.ArgumentError(None, f"Cannot read file '{self.args.bounce_file}': {e}")
            except ftplib.Error:
                pass
            finally:
                if stored:
                    # Cleanup the uploaded request file
                    try:
                        ftp.delete(filename)
                        cleaned = True
                    except ftplib.Error as e:
                        # 226 is success, but ftplib does not account for that
                        if e.args and len(e.args) > 0 and len(str(e.args[0])) >= 3:
                            if str(e.args[0])[:3] == "226":
                                cleaned = True

            return BounceResult(
                self.args.bounce,
                creds,
                True,
                None,
                BounceRequestResult(
                    filename,
                    stored,
                    uploaded,
                    cleaned,
                ),
            )
        else:
            # Just port scan
            try:
                ftp.sendcmd("LIST")

                port_ok = True
            except:
                port_ok = False

            return BounceResult(self.args.bounce, creds, True, port_ok, None)

    def _bounce_setup(self, ftp: ftplib.FTP, target: Target) -> bool:
        """Attempts to negotiate an FTP bounce configuration

        Args:
            ftp (ftplib.FTP): FTP connection
            target (Target): bounce target

        Returns:
            bool: negotiation result
        """
        try:
            ftp.sendport(target.ip, target.port)
            self._dbg(f"PORT {target.ip}:{target.port} → OK")
        except Exception as e:
            self._dbg(f"PORT {target.ip}:{target.port} → {self._snip(str(e))}")
            try:
                ftp.sendeprt(target.ip, target.port)
                self._dbg(f"EPRT {target.ip}:{target.port} → OK")
            except Exception as e2:
                self._dbg(f"EPRT {target.ip}:{target.port} → {self._snip(str(e2))}")
                return False

        return True

    def _user_enum_probe_signature(self, r: FtpUserEnumProbeRow) -> tuple[int | None, int | None, str]:
        """Comparable outcome. The echoed username is removed before the text is compared."""
        if r.error:
            return (None, None, "")
        if r.user_reply_code in (331, 332):
            user_text = self._user_enum_reply_template(r.user_reply_line or "", r.username)
            pass_text = self._user_enum_reply_template(r.pass_reply_line or "", r.username)
            return (r.user_reply_code, r.pass_reply_code, f"{user_text}|{pass_text}")
        return (
            r.user_reply_code,
            None,
            self._user_enum_reply_template(r.user_reply_line or "", r.username),
        )

    @staticmethod
    def _user_enum_format_probe_reply(r: FtpUserEnumProbeRow) -> str:
        if r.error:
            return f"(probe error: {r.error[:100]})"
        if r.user_reply_code in (331, 332):
            c = r.pass_reply_code
            line = (r.pass_reply_line or "").strip()
        else:
            c = r.user_reply_code
            line = (r.user_reply_line or "").strip()
        line = re.sub(r"\s+", " ", line)
        if c is not None and (line == str(c) or line.startswith(f"{c} ")):
            return line[:160]
        return f"{c} {line}"[:160].strip()

    def _print_user_enum_terminal(self, ue: FtpUserEnumResult) -> None:
        """One line per wordlist name, then one verdict."""
        wl = [r for r in ue.probes if r.probe_kind == "wordlist" and r.error is None]
        ctrl = [r for r in ue.probes if r.probe_kind.startswith("control") and r.error is None]
        n_err = sum(1 for p in ue.probes if p.error)
        n_all = len(ue.probes)

        if n_all and n_err == n_all:
            self._tprint(
                "Could not connect. Username enumeration was not tested.",
                "WARNING",
                indent=4,
            )
            return
        if (
            n_err
            and n_err * 2 >= n_all
            and not ue.enumeration_suspected
            and not ue.timing_anomaly_suspected
        ):
            self._tprint(
                f"{n_err} of {n_all} probes failed. Could not tell whether usernames exist.",
                "WARNING",
                indent=4,
            )
            return

        accepted = [
            r
            for r in wl + ctrl
            if r.user_reply_code in (331, 332)
            and r.pass_reply_code is not None
            and 200 <= r.pass_reply_code < 300
        ]
        compared = [r for r in wl + ctrl if r.error is None]
        if accepted and compared and len(accepted) == len(compared):
            self._tprint(
                "Wrong password was accepted for every name, including controls.",
                "WARNING",
                indent=4,
            )

        if ue.enumeration_suspected:
            self._tprint("User enumeration is possible. Replies are not the same.", "VULN", indent=4)
            base = next(
                (
                    self._user_enum_probe_signature(r)
                    for r in ctrl
                    if r.probe_kind == "control_invalid_random"
                ),
                None,
            )
            for r in wl:
                if base is None or self._user_enum_probe_signature(r) != base:
                    self._tprint(
                        f"{r.username}: {self._user_enum_format_probe_reply(r)}",
                        "TEXT",
                        indent=4,
                    )
        elif ue.timing_anomaly_suspected:
            self._tprint("User enumeration may be possible from response time.", "WARNING", indent=4)
        else:
            self._tprint(
                "User enumeration is not possible. All names got the same reply.",
                "NOTVULN",
                indent=4,
            )

    def _print_ftp_dos_audit_terminal(self, da: FtpDosAuditResult) -> None:
        """Login or replay only. Probe lines are printed next to their -vv trace."""
        if getattr(self, "_dos_probes_emitted", False):
            return
        if not da.probes:
            msg = (da.detail or "").strip() or "Processing probes were not run."
            self._tprint(self._snip(msg), "WARNING")
            return
        for r in da.probes:
            self._ftp_dos_print_probe(r, debug=False)

    def _eicar_lines(self, r: FtpEicarRow) -> list[tuple[str, str]]:
        who = f"{r.creds.user}: " if r.creds and r.creds.user else ""
        if not r.stor_ok:
            if self._ftp_text_is_unconfirmed(r.stor_error):
                return [("WARNING", f"{who}EICAR was not confirmed")]
            return [("NOTVULN", f"{who}EICAR upload was refused")]
        uploaded = ("VULN", f"{who}EICAR was uploaded")
        if r.vanished_after_stor_suspected:
            return [uploaded, ("NOTVULN", f"{who}EICAR was deleted")]
        if r.retr_ok and r.retr_payload_match:
            return [uploaded, ("VULN", f"{who}EICAR was not deleted")]
        return [uploaded, ("WARNING", f"{who}Deletion was not confirmed")]

    def _print_eicar_audit_terminal(self, ea: FtpEicarAuditResult) -> None:
        if not ea.rows:
            self._tprint(ea.detail, "WARNING")
            return
        many = len(ea.rows) > 1
        for r in ea.rows:
            for bullet, text in self._eicar_lines(r):
                if not many:
                    text = text.split(": ", 1)[-1]
                self._tprint(text, bullet)

    # region output


    def build_json(self, ptjsonlib) -> None:
        """Formats and outputs module results. Skips streamed sections in text mode; JSON always complete."""
        properties = {
            "software_type": None,
            "name": "ftp",
            "version": None,
            "vendor": None,
            "description": None,
        }
        deferred_vulns = []

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
        if self.results.commands_requested:
            if (info := self.results.info) and (
                info.help_response is not None or info.syst is not None or info.stat is not None
            ):
                if info.help_response is not None:
                    properties.update({"helpCommand": info.help_response})
                if info.syst is not None:
                    properties.update({"systCommand": info.syst})
                if info.stat is not None:
                    properties.update({"statCommand": info.stat})

        # Encryption (skip terminal if streamed; always add to properties for JSON)
        if (encryption_error := self.results.encryption_error) is not None:
            properties.update({"encryptionError": encryption_error})
        elif (enc := self.results.encryption) is not None:
            properties.update(
                {
                    "encryption": {
                        "plaintext": enc.plaintext_ok,
                        "authTls": enc.auth_tls_ok,
                        "tls": enc.tls_ok,
                    }
                }
            )
        # Anonymous authentication and access permissions (skip terminal if streamed)
        if (anonymous_error := self.results.anonymous_error) is not None:
            properties.update({"anonymousError": anonymous_error})
        elif (access_error := self.results.access_error) is not None:
            properties.update({"accessError": access_error})
        elif (anon := self.results.anonymous) is not None:
            if anon:
                response_str = ""
                if (access := self.results.access) is not None:
                    if access.errors is None and access.results is not None:
                        try:
                            anon_p = next(p for p in access.results if p.creds.user == "anonymous")
                            response_str = (
                                f"(Directory listing: {anon_p.dirlist is not None}, "
                                + f"Write: {anon_p.write}, "
                                + f"Read: {anon_p.read}, "
                                + f"Delete: {anon_p.delete})"
                            )
                        except StopIteration:
                            pass
                    else:
                        response_str = "Encountered errors during access enumeration:"
                        if access.errors:
                            response_str += "\n" + "\n".join(access.errors)

                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.Anonymous.value,
                        "vuln_request": "anonymous login",
                        "vuln_response": response_str,
                    }
                )

        # --access without working anonymous: access_check still ran but UI above skipped (anonymous unset or False)
        if (
            self.args.access
            and (access := self.results.access) is not None
            and access.errors
            and self.results.anonymous is not True
        ):
            properties.update({"accessCheckErrors": list(access.errors)})

        guessing = getattr(self, "_brute_guessing", None)
        if guessing is not None:
            properties.update({"ftpPasswordGuessing": guessing})
        if getattr(self, "_auth_catch_all", None) == "indeterminate":
            properties.update({"catchAll": "indeterminate"})

        # Bruteforced credentials and their access permissions (skip terminal if streamed)
        if (creds := self.results.creds) is not None:
            if len(creds) > 0:
                json_lines: list[str] = []
                for cred in creds:
                    cred_str = f"user: {cred.user}, password: {shown_password(cred.passw)}"

                    if (access := self.results.access) is not None:
                        if access.errors is None and access.results is not None:
                            try:
                                cred_p = next(p for p in access.results if p.creds == cred)
                                perm_str = (
                                    f" (Directory listing: {cred_p.dirlist is not None}, "
                                    + f"Write: {cred_p.write}, "
                                    + f"Read: {cred_p.read}, "
                                    + f"Delete: {cred_p.delete})"
                                )
                            except StopIteration:
                                perm_str = ""
                        else:
                            perm_str = " Encountered errors during access enumeration:"
                            for e in access.errors or []:
                                pass
                                perm_str += f"\n{e}"
                    else:
                        perm_str = ""

                    show_perm_terminal = ""

                    json_lines.append(cred_str + perm_str)

                names = text_or_file(self.args.user, None)
                if names:
                    user_str = "username: " + ", ".join(names)
                else:
                    user_str = f"usernames: {self.args.users}"

                if self.args.password is not None:
                    passw_str = f"password: {shown_password(self.args.password)}"
                else:
                    passw_str = f"passwords: {self.args.passwords}"

                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.WeakCreds.value,
                        "vuln_request": f"{user_str}\n{passw_str}",
                        "vuln_response": "\n".join(json_lines),
                    }
                )

        # Directory listing
        if (
            self.args.access_list
            and (access := self.results.access) is not None
            and access.results is not None
        ):
            try:
                p = next(p for p in access.results if p.dirlist is not None and len(p.dirlist) > 0)
                out_str = "\n".join(p.dirlist)
                properties.update({"directoryListing": out_str})
            except StopIteration:
                properties.update({"directoryListing": "no access or empty"})

        # Path enumeration (dictionary attack results)
        if path_enum_error := getattr(self.results, "path_enum_error", None):
            properties.update({"pathEnumError": path_enum_error})
        elif (path_list := getattr(self.results, "path_enum", None)) is not None:
            path_enum_json = [
                {
                    "path": p.path,
                    "exists": p.exists,
                    "isDirectory": p.is_directory,
                    "size": p.size,
                    "mtime": p.mtime,
                    "readable": p.readable,
                    "writable": p.writable,
                    "deletable": p.deletable,
                    "cleanupFailed": p.cleanup_failed,
                    "loginDirectory": p.login_directory,
                }
                for p in path_list
            ]
            properties.update({"pathEnum": path_enum_json})

        # Data mode (passive/active)
        if modes_error := getattr(self.results, "modes_error", None):
            properties.update({"dataModesError": modes_error})
        elif (modes := getattr(self.results, "modes", None)) is not None:
            modes_json: dict = {"passive": modes.passive_ok, "active": modes.active_ok}
            if modes.pasv_ip_leak:
                modes_json["pasvIpLeak"] = modes.pasv_ip_leak
            properties.update({"dataModes": modes_json})

        # Passive data port spread (PTL-SVC-FTP-PASIVE)
        if ppr_err := getattr(self.results, "pasv_port_range_error", None):
            properties.update({"ftpPasvPortRangeError": ppr_err})
        elif (ppr := getattr(self.results, "pasv_port_range", None)) is not None:
            ppr_json = {
                "sampleCount": len(ppr.probes),
                "successfulSamples": len(ppr.successful_ports),
                "dataPorts": list(ppr.successful_ports),
                "minPort": ppr.min_port,
                "maxPort": ppr.max_port,
                "observedSpan": ppr.observed_span,
                "maxSpanThreshold": ppr.max_span_threshold,
                "minSamplesForVerdict": ppr.min_samples_for_verdict,
                "widePassiveRange": ppr.wide_passive_range,
                "inconclusive": ppr.inconclusive,
                "detail": ppr.detail,
                "probes": [
                    {
                        "sampleIndex": pr.sample_index,
                        "dataPort": pr.data_port,
                        "error": pr.error,
                    }
                    for pr in ppr.probes
                ],
            }
            properties.update({"ftpPasvPortRange": ppr_json})
            if ppr.wide_passive_range and not ppr.inconclusive:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpPassivePortRange.value,
                        "vuln_request": "Repeated PASV + LIST (--pasv-port-audit / -R)",
                        "vuln_response": ppr.detail,
                    }
                )

        # Connection limits audit (PTL-SVC-FTP-CONN)
        if cl_err := getattr(self.results, "conn_limits_error", None):
            properties.update({"ftpConnLimitsError": cl_err})
        elif (cl := getattr(self.results, "conn_limits", None)) is not None:
            pp = cl.pasv_pre_auth
            po = cl.pasv_post_auth
            cl_json: dict = {
                "cryptoMode": cl.crypto_mode,
                "parallel": {
                    "attempted": cl.parallel.attempted,
                    "succeeded": cl.parallel.succeeded,
                    "failed": cl.parallel.failed,
                    "errorSamples": list(cl.parallel.error_samples),
                },
                "sequential": {
                    "attempts": cl.sequential.attempts,
                    "succeeded": cl.sequential.succeeded,
                    "failed": cl.sequential.failed,
                    "interConnectDelayMs": cl.sequential.inter_connect_delay_ms,
                    "errorSamples": list(cl.sequential.error_samples),
                },
                "pasvPreAuth": {
                    "attempts": pp.attempts,
                    "reply227": pp.reply227,
                    "reply530": pp.reply530,
                    "replyOther": pp.reply_other,
                    "lastReplySnippet": pp.last_reply_snippet,
                    "error": pp.error,
                },
                "pasvPostAuth": None
                if po is None
                else {
                    "attempts": po.attempts,
                    "reply227": po.reply227,
                    "reply530": po.reply530,
                    "replyOther": po.reply_other,
                    "lastReplySnippet": po.last_reply_snippet,
                    "error": po.error,
                },
                "idlePreAuth": {
                    "performed": cl.idle_pre_auth.performed,
                    "waitSeconds": cl.idle_pre_auth.wait_seconds,
                    "kickObserved": cl.idle_pre_auth.kick_observed,
                    "note": cl.idle_pre_auth.note,
                },
                "slowAuth": {
                    "performed": cl.slow_auth.performed,
                    "gapSeconds": cl.slow_auth.gap_seconds,
                    "stillConnectedAfterPass": cl.slow_auth.still_connected_after_pass,
                    "passReplySnippet": cl.slow_auth.pass_reply_snippet,
                    "note": cl.slow_auth.note,
                },
                "idlePostAuth": None
                if cl.idle_post_auth is None
                else {
                    "performed": cl.idle_post_auth.performed,
                    "waitSeconds": cl.idle_post_auth.wait_seconds,
                    "kickObserved": cl.idle_post_auth.kick_observed,
                    "note": cl.idle_post_auth.note,
                },
                "limitsInsufficientSuspected": cl.limits_insufficient_suspected,
                "riskFactors": list(cl.risk_factors),
                "detail": cl.detail,
            }
            properties.update({"ftpConnLimitsAudit": cl_json})
            if cl.limits_insufficient_suspected:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpConnectionLimits.value,
                        "vuln_request": "Connection / idle / PASV probes (--count / --duration)",
                        "vuln_response": "; ".join(cl.risk_factors) if cl.risk_factors else cl.detail,
                    }
                )

        # Chroot / user isolation audit (PTL-SVC-FTP-CHROOT)
        if ch_err := getattr(self.results, "chroot_audit_error", None):
            properties.update({"ftpChrootAuditError": ch_err})
        elif (ch := getattr(self.results, "chroot_audit", None)) is not None:
            dd = ch.dotdot
            ch_json = {
                "pwdInitial": ch.pwd_initial,
                "cwdProbes": [
                    {
                        "probeId": r.probe_id,
                        "path": r.path,
                        "success": r.success,
                        "pwdAfter": r.pwd_after,
                        "errorOrReply": r.error_or_reply,
                    }
                    for r in ch.cwd_probes
                ],
                "dotdot": {
                    "stepsOk": dd.steps_ok,
                    "pwdInitial": dd.pwd_initial,
                    "pwdFinal": dd.pwd_final,
                    "stoppedReason": dd.stopped_reason,
                },
                "homeParentAccessible": ch.home_parent_accessible,
                "systemPathsAccessible": list(ch.system_paths_accessible),
                "passwdSizeOk": ch.passwd_size_ok,
                "shadowSizeOk": ch.shadow_size_ok,
                "dotdotParentEscapeSuspected": ch.dotdot_parent_escape_suspected,
                "isolationBrokenSuspected": ch.isolation_broken_suspected,
                "detail": ch.detail,
                "passwdSizeBytes": ch.passwd_size_bytes,
                "shadowSizeBytes": ch.shadow_size_bytes,
                "passwdRetrOk": ch.passwd_retr_ok,
                "shadowRetrOk": ch.shadow_retr_ok,
                "passwdRetrRelativeOk": ch.passwd_retr_relative_ok,
                "shadowRetrRelativeOk": ch.shadow_retr_relative_ok,
                "writeEscapeOk": ch.write_escape_ok,
            }
            properties.update({"ftpChrootAudit": ch_json})
            if ch.isolation_broken_suspected:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpChrootIsolation.value,
                        "vuln_request": "CWD / .. / RETR / MKD probes (--chroot-audit / -J)",
                        "vuln_response": ch.detail,
                    }
                )

        # Active mode policy audit (PTL-SVC-FTP-ACTIVE)
        if active_audit_error := getattr(self.results, "active_audit_error", None):
            properties.update({"activeAuditError": active_audit_error})
        elif (aa := getattr(self.results, "active_audit", None)) is not None:
            doc_net_ip = "192.0.2.1"
            steps_json = [
                {
                    "phase": s.phase,
                    "name": s.name,
                    "command": s.command,
                    "reply": s.reply,
                    "code": s.code,
                    "note": s.note,
                    "interpretation": s.interpretation,
                    "listReply": s.list_reply,
                    "listCode": s.list_code,
                }
                for s in aa.steps
            ]
            audit_props: dict = {
                "steps": steps_json,
                "postAuthComplete": aa.post_auth_ran,
                "foreignIpPortAccepted": aa.foreign_ip_accepted,
                "lowPortAccepted": aa.low_port_accepted,
                "listActiveOk": aa.list_after_own_port_ok,
                "fullAudit": aa.full_audit,
            }
            if aa.low_ports_accepted:
                audit_props["lowPortsAccepted"] = list(aa.low_ports_accepted)
            properties.update({"activeAudit": audit_props})

            if aa.foreign_ip_accepted or aa.low_port_accepted:
                parts = []
                if aa.foreign_ip_accepted:
                    parts.append(
                        f"Server returned 200 for PORT to documentation address {doc_net_ip} (FTP bounce / third-party data connection risk per RFC 2577)."
                    )
                if aa.low_port_accepted:
                    lp = ", ".join(str(p) for p in aa.low_ports_accepted) if aa.low_ports_accepted else ""
                    parts.append(
                        "Server returned 200 for PORT with data port < 1000"
                        + (f" (ports: {lp})" if lp else "")
                        + " (RFC 2577 recommends rejecting < 1024, often 504)."
                    )
                req = "PASV/PORT policy audit (--active-audit-full)" if aa.full_audit else "PASV/PORT policy audit (-M / --active-audit)"
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpActivePolicy.value,
                        "vuln_request": req,
                        "vuln_response": " ".join(parts),
                    }
                )

        # Command surface audit (PTL-SVC-FTP-CMD)
        if cmd_audit_error := getattr(self.results, "cmd_audit_error", None):
            properties.update({"ftpCommandAuditError": cmd_audit_error})
        elif (ca := getattr(self.results, "cmd_audit", None)) is not None:
            audit_json = {
                "helpPreAuth": ca.help_pre_auth,
                "featResponse": ca.feat_response,
                "siteHelpPreAuth": ca.site_help_pre,
                "siteHelpAllPreAuth": ca.site_help_all_pre,
                "siteHelpPostAuth": ca.site_help_post,
                "siteHelpAllPostAuth": ca.site_help_all_post,
                "siteHelpAllPreAuthError": ca.site_help_all_pre_error,
                "siteHelpAllPostAuthError": ca.site_help_all_post_error,
                "featFeatures": list(ca.feat_features),
                "matchedRisks": [
                    {"tier": r.tier, "token": r.token, "source": r.source} for r in ca.matched_risks
                ],
                "responseTruncated": ca.response_truncated,
            }
            properties.update({"ftpCommandAudit": audit_json})
            vuln_risks = [r for r in ca.matched_risks if r.tier in ("critical", "high")]
            if vuln_risks:
                parts = [f"{r.tier}: {r.token} ({r.source})" for r in vuln_risks]
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpCmdSurface.value,
                        "vuln_request": "HELP/FEAT/SITE HELP (cmd audit -C)",
                        "vuln_response": (
                            "Server advertises risky capabilities: "
                            + "; ".join(parts)
                            + ". Listing in HELP/SITE does not prove unprivileged execution; use --cmd-audit-active for safe SITE probes after login."
                        ),
                    }
                )

        # Active SITE probes (--cmd-audit-active)
        if cmd_audit_active_error := getattr(self.results, "cmd_audit_active_error", None):
            properties.update({"ftpCommandAuditActiveError": cmd_audit_active_error})
        elif (caa := getattr(self.results, "cmd_audit_active", None)) is not None:
            active_json = {
                "probeTimeoutSeconds": caa.probe_timeout_seconds,
                "probeFile": caa.probe_file,
                "cleanupOk": caa.cleanup_ok,
                "cleanupError": caa.cleanup_error,
                "setupError": caa.setup_error,
                "probes": [
                    {
                        "probeId": p.probe_id,
                        "commandSent": p.command_sent,
                        "replyCode": p.reply_code,
                        "replyLine": p.reply_line,
                        "classification": p.classification,
                        "advertisedInPassiveAudit": p.advertised_in_passive_audit,
                        "error": p.error,
                    }
                    for p in caa.probes
                ],
            }
            properties.update({"ftpCommandAuditActive": active_json})

        # Invalid / non-standard command audit (PTL-SVC-FTP-INVCOMM)
        if inv_err := getattr(self.results, "invalid_cmd_audit_error", None):
            properties.update({"ftpInvalidCommandAuditError": inv_err})
        elif (inv := getattr(self.results, "invalid_cmd_audit", None)) is not None:
            def _inv_session_to_json(sess: InvalidCmdSessionResult | None) -> dict | None:
                if sess is None:
                    return None
                return {
                    "phase": sess.phase,
                    "resilienceRating": sess.resilience_rating,
                    "nullByteTruncationSuspected": sess.null_byte_truncation_suspected,
                    "hadConnectionDrop": sess.had_connection_drop,
                    "probes": [
                        {
                            "probeId": p.probe_id,
                            "intentLabel": p.intent_label,
                            "bytesLineHex": p.bytes_line_hex,
                            "lineSentPreview": p.line_sent_preview,
                            "replyCode": p.reply_code,
                            "replyText": p.reply_text,
                            "classification": p.classification,
                            "connectionOkAfter": p.connection_ok_after,
                            "error": p.error,
                            "followUpCommand": p.follow_up_command,
                            "followUpReplyCode": p.follow_up_reply_code,
                            "followUpReplySnippet": p.follow_up_reply_snippet,
                            "nullByteOutcome": p.null_byte_outcome,
                        }
                        for p in sess.probes
                    ],
                }

            def _inv_null_byte_critical(inv_a: InvalidCmdAuditResult) -> bool:
                for s in (inv_a.pre_auth, inv_a.post_auth):
                    if s is None:
                        continue
                    for p in s.probes:
                        if p.null_byte_outcome and "critical_suspected" in p.null_byte_outcome:
                            return True
                return False

            inv_json = {
                "probeTimeoutSeconds": inv.probe_timeout_seconds,
                "overallResilienceRating": inv.overall_resilience_rating,
                "nullByteTruncationSuspected": inv.null_byte_truncation_suspected,
                "nullByteCriticalContextSuspected": _inv_null_byte_critical(inv),
                "setupError": inv.setup_error,
                "postAuthLoginError": inv.post_auth_login_error,
                "tlsHandshakeHint": inv.tls_handshake_hint,
                "obsoleteTlsSuspected": inv.obsolete_tls_suspected,
                "preAuth": _inv_session_to_json(inv.pre_auth),
                "postAuth": _inv_session_to_json(inv.post_auth),
            }
            properties.update({"ftpInvalidCommandAudit": inv_json})
            if inv.overall_resilience_rating == "Vulnerable":
                vuln_extra = ""
                if _inv_null_byte_critical(inv):
                    vuln_extra = (
                        " Null-byte USER returned 230 and PWD suggests root/high-privilege context — "
                        "treat as possible auth-bypass / truncation; verify manually."
                    )
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpInvalidCommandHandling.value,
                        "vuln_request": "Invalid / malformed FTP control lines (-iv / --invalid-cmd-audit)",
                        "vuln_response": (
                            "overallResilienceRating=Vulnerable: unexpected 2xx on garbage command, "
                            "null-byte USER may have logged in (230), or service did not recover after probe."
                            + vuln_extra
                            + " See ftpInvalidCommandAudit in JSON (intentLabel, nullByteOutcome)."
                        ),
                    }
                )
            if inv.obsolete_tls_suspected:
                hint = inv.tls_handshake_hint or ""
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpObsoleteTls.value,
                        "vuln_request": "Invalid-command audit (-iv) TLS handshake (implicit or AUTH TLS)",
                        "vuln_response": (
                            "Critical (protocol hygiene): Python SSL (create_default_context) refused to complete "
                            "handshake — typical when the server offers only TLS 1.0/1.1 or otherwise incompatible "
                            "legacy TLS. INVCOMM over encrypted channel could not run; treat as obsolete "
                            "infrastructure / protocol downgrade risk. "
                            + (hint if hint else "See ftpInvalidCommandAudit.setupError and tlsHandshakeHint in JSON.")
                        ),
                    }
                )

        # Username enumeration (PTL-SVC-FTP-USRENUM)
        if ue_err := getattr(self.results, "user_enum_error", None):
            properties.update({"ftpUserEnumerationError": ue_err})
        elif (ue := getattr(self.results, "user_enum", None)) is not None:
            ue_json = {
                "fixedPasswordMarker": ue.fixed_password_marker,
                "wordlistMaxApplied": int(getattr(self.args, "user_enum_max", 0) or 0),
                "distinctUserReplyCodes": list(ue.distinct_user_reply_codes),
                "distinctPassReplyNorms": list(ue.distinct_pass_reply_norms),
                "enumerationSuspected": ue.enumeration_suspected,
                "timingAnomalySuspected": ue.timing_anomaly_suspected,
                "timingNotes": list(ue.timing_notes),
                "timingControlMedianMs": ue.timing_control_median_ms,
                "timingWordlistMedianMs": ue.timing_wordlist_median_ms,
                "timingSlowUsernamesMs": [{"username": u, "passElapsedMs": ms} for u, ms in ue.timing_slow_usernames_ms],
                "passTextSimilarityMin": ue.pass_text_similarity_min,
                "detail": ue.detail,
                "probes": [
                    {
                        "probeIndex": p.probe_index,
                        "username": p.username,
                        "probeKind": p.probe_kind,
                        "userReplyCode": p.user_reply_code,
                        "userReplyLine": p.user_reply_line,
                        "passReplyCode": p.pass_reply_code,
                        "passReplyLine": p.pass_reply_line,
                        "passElapsedMs": p.pass_elapsed_ms,
                        "connectionOkAfter": p.connection_ok_after,
                        "error": p.error,
                    }
                    for p in ue.probes
                ],
            }
            properties.update({"ftpUserEnumeration": ue_json})
            if ue.enumeration_suspected or ue.timing_anomaly_suspected:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpUserEnumeration.value,
                        "vuln_request": "USER/PASS with fixed wrong password (-eu / --user-enum)",
                        "vuln_response": (
                            ue.detail
                            + " See ftpUserEnumeration in JSON (per-probe codes, lines, passElapsedMs, connectionOkAfter)."
                        ),
                    }
                )

        # EICAR / on-access antivirus probe (PTL-SVC-FTP-ANTIVIRUS)
        if ea_err := getattr(self.results, "eicar_audit_error", None):
            properties.update({"ftpEicarError": ea_err})
        elif (ea := getattr(self.results, "eicar_audit", None)) is not None:
            ea_json = {
                "postStorDelaySeconds": ea.post_stor_delay_seconds,
                "detail": ea.detail,
                "riskyContentReachable": ea.risky_content_reachable,
                "uploadBlockedAllAccounts": ea.upload_blocked_all,
                "rows": [
                    {
                        "username": r.creds.user,
                        "password": r.creds.passw,
                        "remotePath": r.remote_path,
                        "storOk": r.stor_ok,
                        "storError": r.stor_error,
                        "sizeBytes": r.size_bytes,
                        "sizeError": r.size_error,
                        "retrOk": r.retr_ok,
                        "retrPayloadMatch": r.retr_payload_match,
                        "retrError": r.retr_error,
                        "vanishedAfterStorSuspected": r.vanished_after_stor_suspected,
                        "onAccessScanSuspected": r.on_access_scan_suspected,
                        "deleteOk": r.delete_ok,
                        "deleteError": r.delete_error,
                        "deleteNote": r.delete_note,
                    }
                    for r in ea.rows
                ],
            }
            properties.update({"ftpEicar": ea_json})
            if ea.risky_content_reachable:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpAntivirusEicar.value,
                        "vuln_request": "FTP STOR of EICAR test file + delayed SIZE/RETR (--eicar)",
                        "vuln_response": (
                            ea.detail
                            + " EICAR remained retrievable after post-STOR delay — treat as missing or weak "
                            "on-access/content filtering on the FTP storage path unless policy explicitly allows."
                        ),
                    }
                )

        # FTP processing resilience / STOR timing (PTL-SVC-FTP-PROC-DOS)
        if d_err := getattr(self.results, "dos_audit_error", None):
            properties.update({"ftpProcessingResilienceError": d_err})
        elif (dos := getattr(self.results, "dos_audit", None)) is not None:
            dos_json = {
                "timeoutSeconds": dos.timeout_seconds,
                "zipMode": dos.zip_mode,
                "credsUser": dos.creds_user,
                "detail": dos.detail,
                "postProcessingDosSuspected": dos.post_processing_dos_suspected,
                "allBlockedByPolicy": dos.all_blocked_by_policy,
                "probes": [
                    {
                        "probeLabel": p.probe_label,
                        "remoteFilename": p.remote_filename,
                        "payloadBytes": p.payload_bytes,
                        "storOk": p.stor_ok,
                        "storError": p.stor_error,
                        "storReplySnippet": p.stor_reply_snippet,
                        "replyCode": p.reply_code,
                        "totalTransferSeconds": p.total_transfer_seconds,
                        "deltaLastByteTo226Seconds": p.delta_last_byte_to_226_seconds,
                        "noopOk": p.noop_ok,
                        "noopError": p.noop_error,
                        "noopElapsedSeconds": p.noop_elapsed_seconds,
                        "blockedByPolicy": p.blocked_by_policy,
                        "backgroundProcessingSuspected": p.background_processing_suspected,
                        "timedOut": p.timed_out,
                        "deleteOk": p.delete_ok,
                        "deleteError": p.delete_error,
                    }
                    for p in dos.probes
                ],
            }
            properties.update({"ftpProcessingResilience": dos_json})
            if dos.post_processing_dos_suspected:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpProcessingResilience.value,
                        "vuln_request": (
                            "FTP STOR of billion-laughs XML + ZIP bomb in one session (--ftp-dos-probes); "
                            "timing last-byte→226 + NOOP/PWD stability"
                        ),
                        "vuln_response": dos.detail
                        + " Elevated control latency, timeout, or unstable session after STOR hints at synchronous "
                        "or heavyweight backend processing (AV/EDR decompression, XML parse, indexer). "
                        "See ftpProcessingResilience JSON for per-probe deltas.",
                    }
                )

        # Bounce attack
        if bounce := self.results.bounce:
            if (creds := bounce.used_creds) is None:
                properties.update({"bounceStatus": "no valid credentials"})
            else:
                if not bounce.bounce_accepted:
                    properties.update({"bounceStatus": "rejected"})
                else:
                    properties.update({"bounceStatus": "ok"})

                    if (r := bounce.request) is None:
                        out_str = f"Target port reachable: {bounce.port_accessible}"
                        deferred_vulns.append(
                            {
                                "vuln_code": VULNS.Bounce.value,
                                "vuln_request": f"Bounce port scan target: {bounce.target.ip}:{bounce.target.port}\nCreds used: {creds.user}:{creds.passw}",
                                "vuln_response": out_str,
                            }
                        )
                    else:
                        res = f"Yes ({r.ftpserver_filepath})" if r.stored else "No"
                        stored_str = "Stored on FTP server: " + res
                        res = "Yes" if r.uploaded else "No"
                        sent_str = "Sent to bounce target: " + res
                        res = "Yes" if r.cleaned else "No"
                        clean_str = "Cleaned up: " + res

                        deferred_vulns.append(
                            {
                                "vuln_code": VULNS.Bounce.value,
                                "vuln_request": f"Bounce request target: {bounce.target.ip}:{bounce.target.port}\nCreds used: {creds.user}:{creds.passw}\nRequest file: {self.args.bounce_file}",
                                "vuln_response": "\n".join([stored_str, sent_str, clean_str]),
                            }
                        )

        # Create node at the end with all collected properties and bind vulnerabilities
        ftp_node = ptjsonlib.create_node_object(
            "software",
            None,
            None,
            properties,
        )
        ptjsonlib.add_node(ftp_node)
        node_key = ftp_node["key"]
        for v in deferred_vulns:
            ptjsonlib.add_vulnerability(node_key=node_key, **v)

        ptjsonlib.set_status("finished", "")
        self._ptprint(ptjsonlib.get_result_json(), json=True)


# endregion
