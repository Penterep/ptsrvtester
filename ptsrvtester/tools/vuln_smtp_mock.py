#!/usr/bin/env python3
"""
Vulnerable SMTP mock server for local ptsrvtester testing.

Accepts (almost) everything at the SMTP layer: open relay style RCPT, any DATA payload,
no SIZE enforcement, optional AUTH that always succeeds. Does not deliver mail anywhere.

Typical use (from another terminal):

  python3 ptsrvtester/tools/vuln_smtp_mock.py --port 2525

  ptsrvtester smtp -av -r victim@mock.local -m tester@mock.local 127.0.0.1:2525
  ptsrvtester smtp -bomb -r victim@mock.local 127.0.0.1:2525
  ptsrvtester smtp -ssrf -r victim@mock.local --ssrf-canary-url http://127.0.0.1:9999/ 127.0.0.1:2525
  ptsrvtester smtp -flood -r victim@mock.local 127.0.0.1:2525
  ptsrvtester smtp -zipxxe -r victim@mock.local 127.0.0.1:2525
  ptsrvtester smtp -br -m bounce@mock.local -r victim@mock.local 127.0.0.1:2525
  ptsrvtester smtp -sh -r victim@mock.local 127.0.0.1:2525

With Submission-style AUTH (any username/password accepted when --auth is set):

  python3 ptsrvtester/tools/vuln_smtp_mock.py --port 2587 --auth
  ptsrvtester smtp -av -r victim@mock.local -u user -p pass 127.0.0.1:2587
"""

from __future__ import annotations

import argparse
import base64
import re
import socket
import socketserver
import sys
import threading
import time
from datetime import datetime, timezone


CRLF = b"\r\n"
DOT = b"."


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class VulnSMTPSession:
    """One client connection — intentionally permissive."""

    def __init__(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        *,
        require_auth: bool,
        advertise_auth: bool,
        size_limit: int,
        enforce_size: bool,
        log_payload: bool,
        max_logged_bytes: int,
        stats: dict[str, int],
        stats_lock: threading.Lock,
        banner_host: str,
    ) -> None:
        self.conn = conn
        self.addr = addr
        self.require_auth = require_auth
        self.advertise_auth = advertise_auth
        self.size_limit = size_limit
        self.enforce_size = enforce_size
        self.log_payload = log_payload
        self.max_logged_bytes = max_logged_bytes
        self.stats = stats
        self.stats_lock = stats_lock
        self.banner_host = banner_host

        self.authed = not require_auth
        self.mail_from: str | None = None
        self.rcpt_to: list[str] = []
        self._recv_buf = b""

    def run(self) -> None:
        try:
            self.conn.settimeout(120.0)
            self._send_line(f"220 {self.banner_host} ESMTP vuln-mock ready")
            while True:
                line = self._read_line()
                if line is None:
                    break
                if not line:
                    continue
                cmd, arg = self._split_command(line)
                if cmd in ("QUIT", "CLOSE"):
                    self._send_line("221 2.0.0 Bye")
                    break
                if cmd == "NOOP":
                    self._send_line("250 2.0.0 OK")
                elif cmd == "RSET":
                    self.mail_from = None
                    self.rcpt_to.clear()
                    self._send_line("250 2.0.0 Reset OK")
                elif cmd in ("HELO", "EHLO"):
                    self._handle_helo(cmd == "EHLO")
                elif cmd == "STARTTLS":
                    # Tester may use plain mock; politely decline so session continues.
                    self._send_line("502 5.5.1 STARTTLS not implemented on mock (use plain port)")
                elif cmd == "AUTH":
                    self._handle_auth(arg)
                elif cmd == "MAIL":
                    self._handle_mail(arg)
                elif cmd == "RCPT":
                    self._handle_rcpt(arg)
                elif cmd == "DATA":
                    self._handle_data()
                elif cmd in ("VRFY", "EXPN"):
                    self._send_line(f"250 2.0.0 <probe@{self.banner_host}>")
                elif cmd == "HELP":
                    self._send_line("214 2.0.0 This is a vulnerable SMTP mock for local testing")
                else:
                    self._send_line("500 5.5.2 Command not recognized (mock)")
        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            pass
        finally:
            try:
                self.conn.close()
            except OSError:
                pass

    def _split_command(self, line: str) -> tuple[str, str]:
        line = line.strip()
        if not line:
            return "", ""
        parts = line.split(None, 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""
        return cmd, arg

    def _read_line(self) -> str | None:
        while True:
            if b"\n" in self._recv_buf:
                raw, self._recv_buf = self._recv_buf.split(b"\n", 1)
                return raw.decode("utf-8", errors="replace").rstrip("\r")
            try:
                chunk = self.conn.recv(4096)
            except TimeoutError:
                return None
            if not chunk:
                return None
            self._recv_buf += chunk

    def _send_line(self, text: str) -> None:
        self.conn.sendall(text.encode("utf-8", errors="replace") + CRLF)

    def _handle_helo(self, is_ehlo: bool) -> None:
        if not is_ehlo:
            self._send_line(f"250 {self.banner_host}")
            return
        lines = [
            f"250-{self.banner_host} greets {self.addr[0]}",
            f"250-SIZE {self.size_limit}",
            "250-8BITMIME",
            "250-ENHANCEDSTATUSCODES",
            "250-PIPELINING",
        ]
        if self.advertise_auth:
            lines.append("250-AUTH LOGIN PLAIN")
        lines.append("250 OK")
        for i, ln in enumerate(lines):
            self._send_line(ln)

    def _handle_auth(self, arg: str) -> None:
        if not self.advertise_auth:
            self._send_line("502 5.5.4 AUTH not available")
            return
        mechanism, _, initial = arg.partition(" ")
        mechanism = mechanism.upper()
        if mechanism == "LOGIN":
            if initial:
                self._auth_login_fast(initial)
                return
            self._send_line("334 " + base64.b64encode(b"Username:").decode())
            user_b64 = self._read_line()
            if user_b64 is None:
                return
            self._send_line("334 " + base64.b64encode(b"Password:").decode())
            pass_b64 = self._read_line()
            if pass_b64 is None:
                return
            self._finish_auth_ok()
            return
        if mechanism == "PLAIN":
            blob = initial or ""
            if not blob:
                self._send_line("334 ")
                line = self._read_line()
                if line is None:
                    return
                blob = line.strip()
            self._finish_auth_ok()
            return
        self._send_line("504 5.5.4 Unrecognized AUTH type")

    def _auth_login_fast(self, _initial: str) -> None:
        self._finish_auth_ok()

    def _finish_auth_ok(self) -> None:
        self.authed = True
        self._send_line("235 2.0.0 Authentication successful")
        self._inc("auth_ok")

    def _handle_mail(self, arg: str) -> None:
        if self.require_auth and not self.authed:
            self._send_line("530 5.7.0 Authentication required")
            return
        self.mail_from = arg
        self.rcpt_to.clear()
        if self.enforce_size:
            m = re.search(r"SIZE=(\d+)", arg, re.I)
            if m and int(m.group(1)) > self.size_limit:
                self._send_line("552 5.3.4 Message size exceeds fixed maximum message size")
                self._inc("mail_rejected_size")
                return
        self._send_line("250 2.1.0 Sender OK")
        self._inc("mail_ok")

    def _handle_rcpt(self, arg: str) -> None:
        if self.require_auth and not self.authed:
            self._send_line("530 5.7.0 Authentication required")
            return
        if not self.mail_from:
            self._send_line("503 5.5.1 Need MAIL before RCPT")
            return
        self.rcpt_to.append(arg)
        self._send_line("250 2.1.5 Recipient OK")
        self._inc("rcpt_ok")

    def _handle_data(self) -> None:
        if self.require_auth and not self.authed:
            self._send_line("530 5.7.0 Authentication required")
            return
        if not self.mail_from or not self.rcpt_to:
            self._send_line("503 5.5.1 Need MAIL and RCPT before DATA")
            return
        self._send_line("354 Start mail input; end with <CRLF>.<CRLF>")
        data = self._read_data()
        if data is None:
            return
        nbytes = len(data)
        self._inc("data_ok")
        self._inc_bytes(nbytes)
        if self.log_payload:
            preview = data[: self.max_logged_bytes]
            suffix = "..." if len(data) > len(preview) else ""
            print(
                f"[{_now()}] DATA {nbytes} B from {self.addr[0]} "
                f"MAIL {self.mail_from!r} RCPT {len(self.rcpt_to)} "
                f"preview={preview!r}{suffix}",
                flush=True,
            )
        self.mail_from = None
        self.rcpt_to.clear()
        self._send_line("250 2.0.0 Message accepted for delivery (mock — not sent)")

    def _read_data(self) -> bytes | None:
        out = bytearray()
        while True:
            if b"\n" in self._recv_buf:
                raw, self._recv_buf = self._recv_buf.split(b"\n", 1)
                line = raw.rstrip(b"\r")
                if line == DOT:
                    return bytes(out)
                if line.startswith(DOT + DOT):
                    line = line[1:]
                out.extend(line)
                out.extend(CRLF)
                continue
            try:
                chunk = self.conn.recv(65536)
            except TimeoutError:
                return None
            if not chunk:
                return None
            self._recv_buf += chunk

    def _inc(self, key: str) -> None:
        with self.stats_lock:
            self.stats[key] = self.stats.get(key, 0) + 1

    def _inc_bytes(self, n: int) -> None:
        with self.stats_lock:
            self.stats["data_bytes"] = self.stats.get("data_bytes", 0) + n


class ThreadedSMTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class VulnSMTPHandler(socketserver.BaseRequestHandler):
    server: ThreadedSMTPServer  # type: ignore[assignment]

    def handle(self) -> None:
        session = VulnSMTPSession(
            self.request,
            self.client_address,
            require_auth=self.server.require_auth,
            advertise_auth=self.server.advertise_auth,
            size_limit=self.server.size_limit,
            enforce_size=self.server.enforce_size,
            log_payload=self.server.log_payload,
            max_logged_bytes=self.server.max_logged_bytes,
            stats=self.server.stats,
            stats_lock=self.server.stats_lock,
            banner_host=self.server.banner_host,
        )
        session.run()


def _stats_printer(stats: dict[str, int], stats_lock: threading.Lock, interval: float) -> None:
    while True:
        time.sleep(interval)
        with stats_lock:
            if not stats:
                continue
            parts = ", ".join(f"{k}={v}" for k, v in sorted(stats.items()))
        print(f"[{_now()}] stats: {parts}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Vulnerable SMTP mock for local ptsrvtester tests (accept-all, no delivery).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=2525, help="Bind port (default: 2525)")
    parser.add_argument(
        "--banner-host",
        default="vuln-mock.local",
        help="Hostname in banner/EHLO (default: vuln-mock.local)",
    )
    parser.add_argument(
        "--auth",
        action="store_true",
        help="Advertise AUTH LOGIN PLAIN and accept any credentials",
    )
    parser.add_argument(
        "--require-auth",
        action="store_true",
        help="Require successful AUTH before MAIL/RCPT/DATA (implies --auth)",
    )
    parser.add_argument(
        "--size-limit",
        type=int,
        default=52_428_800,
        help="SIZE value advertised in EHLO (default: 50 MiB)",
    )
    parser.add_argument(
        "--enforce-size",
        action="store_true",
        help="Reject MAIL FROM SIZE larger than --size-limit (default: off = vulnerable)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Do not log DATA payload previews",
    )
    parser.add_argument(
        "--stats-interval",
        type=float,
        default=30.0,
        metavar="SEC",
        help="Print counters every SEC seconds (0 = disable, default: 30)",
    )
    args = parser.parse_args()

    if args.require_auth:
        args.auth = True

    stats: dict[str, int] = {}
    stats_lock = threading.Lock()

    server = ThreadedSMTPServer((args.host, args.port), VulnSMTPHandler)
    server.require_auth = args.require_auth
    server.advertise_auth = args.auth
    server.size_limit = args.size_limit
    server.enforce_size = args.enforce_size
    server.log_payload = not args.quiet
    server.max_logged_bytes = 200
    server.stats = stats
    server.stats_lock = stats_lock
    server.banner_host = args.banner_host

    mode = []
    if args.require_auth:
        mode.append("require-auth")
    elif args.auth:
        mode.append("auth-optional")
    else:
        mode.append("no-auth")
    if args.enforce_size:
        mode.append("size-enforced")
    else:
        mode.append("size-ignored")

    print(
        f"vuln-smtp-mock listening on {args.host}:{args.port} "
        f"({', '.join(mode)}) — Ctrl+C to stop",
        flush=True,
    )
    print(
        "Example: ptsrvtester smtp -av -r victim@mock.local 127.0.0.1:"
        f"{args.port}",
        flush=True,
    )

    if args.stats_interval > 0:
        t = threading.Thread(
            target=_stats_printer,
            args=(stats, stats_lock, args.stats_interval),
            daemon=True,
        )
        t.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.", flush=True)
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
