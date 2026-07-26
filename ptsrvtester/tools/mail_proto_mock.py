#!/usr/bin/env python3
"""
Combined POP3 / IMAP / FTP mock servers for local ptsrvtester testing.

Two profiles:
  vuln   — permissive, information-disclosing, cleartext-friendly (findings expected)
  secure — hardened surface, valid creds only, TLS where advertised

Default ports (no root required):
  POP3 plain 1110   IMAP plain 1143   FTP plain 2121
  POP3 TLS   1995   IMAP TLS   1993   FTP TLS   2990  (implicit TLS listeners)

Valid credentials (secure profile only): test / test

Examples:
  python3 ptsrvtester/tools/vuln_mail_proto_mock.py
  python3 ptsrvtester/tools/secure_mail_proto_mock.py

  ptsrvtester pop3 -ts ALL 127.0.0.1:1110
  ptsrvtester imap -ts ALL 127.0.0.1:1143
  ptsrvtester ftp  -ts ALL 127.0.0.1:2121
"""

from __future__ import annotations

import argparse
import base64
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


CRLF = b"\r\n"
VALID_USER = "test"
VALID_PASS = "test"


class Profile(str, Enum):
    VULN = "vuln"
    SECURE = "secure"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_line(sock: socket.socket, buf: bytearray) -> bytes | None:
    while True:
        if b"\n" in buf:
            raw, rest = buf.split(b"\n", 1)
            buf.clear()
            buf.extend(rest)
            return raw.rstrip(b"\r")
        try:
            chunk = sock.recv(4096)
        except (TimeoutError, OSError):
            return None
        if not chunk:
            return None
        buf.extend(chunk)


def _send(sock: socket.socket, text: str | bytes) -> None:
    if isinstance(text, str):
        text = text.encode("utf-8", errors="replace")
    sock.sendall(text + CRLF)


_TLS_LOCK = threading.Lock()
_TLS_CTX: ssl.SSLContext | None = None


def _tls_server_context() -> ssl.SSLContext:
    global _TLS_CTX
    with _TLS_LOCK:
        if _TLS_CTX is not None:
            return _TLS_CTX
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tmp = Path(tempfile.gettempdir()) / "ptsrvtester_mail_proto_mock_tls"
        tmp.mkdir(parents=True, exist_ok=True)
        cert = tmp / "cert.pem"
        key = tmp / "key.pem"
        if not cert.exists() or not key.exists():
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(key), "-out", str(cert),
                    "-days", "3650", "-nodes", "-subj", "/CN=localhost",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        _TLS_CTX = ctx
        return ctx


def _wrap_tls(sock: socket.socket) -> ssl.SSLSocket:
    return _tls_server_context().wrap_socket(sock, server_side=True)


def _creds_ok(user: str, password: str, profile: Profile) -> bool:
    if profile is Profile.VULN:
        return True
    return user.lower() == VALID_USER and password == VALID_PASS


# ---------------------------------------------------------------------------
# POP3
# ---------------------------------------------------------------------------


@dataclass
class Pop3Profile:
    banner: str
    capa_lines: list[str]
    help_text: str
    allow_anonymous: bool
    accept_any_login: bool
    advertise_stls: bool
    implementation: str | None


def _pop3_profile(p: Profile) -> Pop3Profile:
    if p is Profile.VULN:
        return Pop3Profile(
            banner="+OK vuln-mock.local POP3 mock ready",
            capa_lines=[
                "TOP", "UIDL", "USER", "PIPELINING", "RESP-CODES", "EXPIRE 60",
                "IMPLEMENTATION vuln-mock-pop3/1.0.3",
                "SASL PLAIN LOGIN ANONYMOUS NTLM",
            ],
            help_text="USER PASS CAPA STLS AUTH LIST RETR DELE — vuln-mock POP3 help",
            allow_anonymous=True,
            accept_any_login=True,
            advertise_stls=False,
            implementation="vuln-mock-pop3/1.0.3",
        )
    return Pop3Profile(
        banner="+OK secure-mock.local POP3 ready",
        capa_lines=[
            "TOP", "UIDL", "PIPELINING", "RESP-CODES", "STLS",
            "SASL SCRAM-SHA-256 SCRAM-SHA-1",
        ],
        help_text="",
        allow_anonymous=False,
        accept_any_login=False,
        advertise_stls=True,
        implementation=None,
    )


class Pop3Session:
    def __init__(self, conn: socket.socket, addr: tuple[str, int], profile: Pop3Profile) -> None:
        self.conn = conn
        self.addr = addr
        self.p = profile
        self.buf = bytearray()
        self.authed = False
        self.user: str | None = None
        self.tls = False

    def run(self) -> None:
        try:
            self.conn.settimeout(120.0)
            _send(self.conn, self.p.banner)
            while True:
                line = _read_line(self.conn, self.buf)
                if line is None:
                    break
                if not line:
                    continue
                try:
                    text = line.decode("utf-8", errors="replace").strip()
                except Exception:
                    _send(self.conn, "-ERR bad encoding")
                    continue
                if not self._dispatch(text):
                    break
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                self.conn.close()
            except OSError:
                pass

    def _dispatch(self, line: str) -> bool:
        parts = line.split(None, 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "QUIT":
            _send(self.conn, "+OK Bye")
            return False
        if cmd == "NOOP":
            _send(self.conn, "+OK")
            return True
        if cmd == "CAPA":
            _send(self.conn, "+OK Capability list follows")
            for ln in self.p.capa_lines:
                _send(self.conn, ln)
            _send(self.conn, ".")
            return True
        if cmd == "HELP":
            if self.p.help_text:
                _send(self.conn, f"+OK {self.p.help_text}")
            else:
                _send(self.conn, "-ERR HELP not supported")
            return True
        if cmd == "STLS":
            if not self.p.advertise_stls:
                _send(self.conn, "-ERR STLS not allowed")
                return True
            _send(self.conn, "+OK Begin TLS negotiation")
            try:
                self.conn = _wrap_tls(self.conn)
                self.tls = True
                self.buf.clear()
            except OSError:
                return False
            return True
        if cmd == "AUTH":
            return self._auth(arg)
        if cmd == "USER":
            self.user = arg
            _send(self.conn, "+OK User accepted")
            return True
        if cmd == "PASS":
            if self._login(self.user or "", arg):
                _send(self.conn, "+OK Mailbox open")
                self.authed = True
            else:
                _send(self.conn, "-ERR Invalid login")
            return True
        if cmd in ("STAT", "LIST", "UIDL", "RETR", "DELE", "TOP"):
            if not self.authed:
                _send(self.conn, "-ERR Authentication required")
                return True
            if cmd == "STAT":
                _send(self.conn, "+OK 0 0")
            elif cmd == "LIST":
                _send(self.conn, "+OK 0 messages")
                _send(self.conn, ".")
            elif cmd == "UIDL":
                _send(self.conn, "+OK")
                _send(self.conn, ".")
            else:
                _send(self.conn, "-ERR no such message")
            return True
        _send(self.conn, "-ERR Unknown command")
        return True

    def _auth(self, arg: str) -> bool:
        mech, _, blob = arg.partition(" ")
        mech = mech.upper()
        if mech == "ANONYMOUS":
            if not self.p.allow_anonymous:
                _send(self.conn, "-ERR Anonymous not allowed")
                return True
            if not blob:
                _send(self.conn, "+ ")
                line = _read_line(self.conn, self.buf)
                if line is None:
                    return False
            self.authed = True
            _send(self.conn, "+OK Auth successful")
            return True
        if mech in ("PLAIN", "LOGIN", "NTLM"):
            if mech == "NTLM" and not blob:
                _send(self.conn, "+ ")
                line = _read_line(self.conn, self.buf)
                if line is None:
                    return False
                blob = line.decode("utf-8", errors="replace").strip()
            if mech == "NTLM" and blob:
                # Minimal fake challenge for NTLM info probe
                _send(self.conn, "+ " + base64.b64encode(b"NTLMSSP\x00\x02\x00\x00\x00").decode())
                line = _read_line(self.conn, self.buf)
                if line is None:
                    return False
            if self.p.accept_any_login:
                self.authed = True
                _send(self.conn, "+OK Auth successful")
            else:
                _send(self.conn, "-ERR Authentication failed")
            return True
        _send(self.conn, "-ERR Unsupported AUTH mechanism")
        return True

    def _login(self, user: str, password: str) -> bool:
        if self.p.accept_any_login:
            return True
        return _creds_ok(user, password, Profile.SECURE)


class Pop3Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        Pop3Session(self.request, self.client_address, self.server.pop3_profile).run()  # type: ignore[attr-defined]


class Pop3Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------


@dataclass
class ImapProfile:
    banner_caps: list[str]
    allow_anonymous: bool
    accept_any_login: bool
    advertise_starttls: bool
    id_software: str | None


def _imap_profile(p: Profile) -> ImapProfile:
    if p is Profile.VULN:
        return ImapProfile(
            banner_caps=[
                "IMAP4rev1", "AUTH=PLAIN", "AUTH=LOGIN", "AUTH=ANONYMOUS", "AUTH=NTLM",
                "IDLE", "NAMESPACE", "UIDPLUS", "LITERAL+",
            ],
            allow_anonymous=True,
            accept_any_login=True,
            advertise_starttls=False,
            id_software="vuln-mock-imap 1.0.3",
        )
    return ImapProfile(
        banner_caps=[
            "IMAP4rev1", "STARTTLS", "LOGINDISABLED",
            "AUTH=SCRAM-SHA-256", "AUTH=SCRAM-SHA-1", "UIDPLUS",
        ],
        allow_anonymous=False,
        accept_any_login=False,
        advertise_starttls=True,
        id_software="secure-mock-imap 1.0",
    )


class ImapSession:
    def __init__(self, conn: socket.socket, addr: tuple[str, int], profile: ImapProfile) -> None:
        self.conn = conn
        self.addr = addr
        self.p = profile
        self.buf = bytearray()
        self.authed = False
        self.tls = False
        self.tag_counter = 0

    def run(self) -> None:
        try:
            self.conn.settimeout(120.0)
            caps = " ".join(self.p.banner_caps)
            host = "secure-mock.local" if not self.p.accept_any_login else "vuln-mock.local"
            _send(self.conn, f"* OK [{caps}] {host} IMAP4rev1 mock ready")
            while True:
                line = _read_line(self.conn, self.buf)
                if line is None:
                    break
                if not line:
                    continue
                try:
                    text = line.decode("utf-8", errors="replace").strip()
                except Exception:
                    continue
                if not self._dispatch(text):
                    break
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                self.conn.close()
            except OSError:
                pass

    def _caps(self) -> str:
        return " ".join(self.p.banner_caps)

    def _dispatch(self, line: str) -> bool:
        m = re.match(r"^(\S+)\s+(\S+)(?:\s+(.*))?$", line, re.I)
        if not m:
            return True
        tag, cmd, arg = m.group(1), m.group(2).upper(), (m.group(3) or "").strip()

        if cmd == "LOGOUT":
            _send(self.conn, f"* BYE Logging out")
            _send(self.conn, f"{tag} OK LOGOUT completed")
            return False
        if cmd == "NOOP":
            _send(self.conn, f"{tag} OK NOOP completed")
            return True
        if cmd == "CAPABILITY":
            _send(self.conn, f"* CAPABILITY {_caps()}")
            _send(self.conn, f"{tag} OK CAPABILITY completed")
            return True
        if cmd == "STARTTLS":
            if not self.p.advertise_starttls:
                _send(self.conn, f"{tag} NO STARTTLS not available")
                return True
            _send(self.conn, f"{tag} OK Begin TLS negotiation now")
            try:
                self.conn = _wrap_tls(self.conn)
                self.tls = True
                self.buf.clear()
            except OSError:
                return False
            return True
        if cmd == "ID":
            if self.p.id_software:
                _send(self.conn, f'* ID ("name" "{self.p.id_software}" "version" "1.0.3")')
            else:
                _send(self.conn, f"* ID NIL")
            _send(self.conn, f"{tag} OK ID completed")
            return True
        if cmd == "LOGIN":
            parts = arg.split(None, 1)
            if len(parts) < 2:
                _send(self.conn, f"{tag} BAD LOGIN needs user and password")
                return True
            user = parts[0].strip('"')
            passwd = parts[1].strip('"')
            if self.p.accept_any_login or _creds_ok(user, passwd, Profile.SECURE):
                self.authed = True
                _send(self.conn, f"{tag} OK LOGIN completed")
            else:
                _send(self.conn, f"{tag} NO LOGIN failed")
            return True
        if cmd == "AUTHENTICATE":
            mech, _, initial = arg.partition(" ")
            mech = mech.upper()
            if mech == "ANONYMOUS":
                if not self.p.allow_anonymous:
                    _send(self.conn, f"{tag} NO Anonymous auth disabled")
                    return True
                if not initial:
                    _send(self.conn, "+ ")
                    line = _read_line(self.conn, self.buf)
                    if line is None:
                        return False
                self.authed = True
                _send(self.conn, f"{tag} OK AUTHENTICATE completed")
                return True
            if mech == "NTLM":
                _send(self.conn, "+ " + base64.b64encode(b"NTLMSSP\x00\x02\x00\x00\x00").decode())
                line = _read_line(self.conn, self.buf)
                if line is None:
                    return False
                if self.p.accept_any_login:
                    self.authed = True
                    _send(self.conn, f"{tag} OK AUTHENTICATE completed")
                else:
                    _send(self.conn, f"{tag} NO AUTHENTICATE failed")
                return True
            if mech in ("PLAIN", "LOGIN"):
                if not initial:
                    _send(self.conn, "+ ")
                    line = _read_line(self.conn, self.buf)
                    if line is None:
                        return False
                if self.p.accept_any_login:
                    self.authed = True
                    _send(self.conn, f"{tag} OK AUTHENTICATE completed")
                else:
                    _send(self.conn, f"{tag} NO AUTHENTICATE failed")
                return True
            _send(self.conn, f"{tag} NO AUTHENTICATE mechanism not supported")
            return True
        if cmd in ("SELECT", "EXAMINE", "LIST", "LSUB", "STATUS", "NAMESPACE"):
            if not self.authed:
                _send(self.conn, f"{tag} NO Not authenticated")
                return True
            if cmd == "NAMESPACE":
                _send(self.conn, f'* NAMESPACE (("" "/")) NIL NIL')
            elif cmd == "LIST":
                _send(self.conn, f'* LIST () "/" "INBOX"')
            elif cmd in ("SELECT", "EXAMINE"):
                _send(self.conn, f"* 0 EXISTS")
                _send(self.conn, f"* 0 RECENT")
                _send(self.conn, f"* OK [{cmd}] completed")
            else:
                _send(self.conn, f"* STATUS INBOX (MESSAGES 0)")
            _send(self.conn, f"{tag} OK {cmd} completed")
            return True
        if cmd == "APPEND":
            if not self.authed:
                _send(self.conn, f"{tag} NO Not authenticated")
                return True
            _send(self.conn, "+ Ready for literal data")
            while True:
                line = _read_line(self.conn, self.buf)
                if line is None:
                    return False
                if line == b".":
                    break
            _send(self.conn, f"{tag} OK APPEND completed")
            return True
        _send(self.conn, f"{tag} BAD Command not recognized (mock)")
        return True


class ImapHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        ImapSession(self.request, self.client_address, self.server.imap_profile).run()  # type: ignore[attr-defined]


class ImapServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# FTP
# ---------------------------------------------------------------------------


@dataclass
class FtpProfile:
    banner: str
    syst: str
    help_lines: list[str]
    feat_lines: list[str]
    allow_anonymous: bool
    accept_any_login: bool
    auth_tls: bool


def _ftp_profile(p: Profile) -> FtpProfile:
    if p is Profile.VULN:
        return FtpProfile(
            banner="220 vuln-mock.local FTP mock ready",
            syst="215 UNIX Type: L8 Version: vuln-mock-ftp/1.0.3",
            help_lines=[
                "214-The following commands are recognized.",
                " USER PASS ACCT CWD CDUP SMNT QUIT REIN PORT PASV TYPE STRU MODE RETR STOR",
                " STOU APPE RNFR RNTO ABOR DELE MDIR RMD MLST MLSD STAT HELP NOOP SYST FEAT",
                "214 End of HELP",
            ],
            feat_lines=[
                "211-Features:",
                " AUTH TLS;TLS-C;SSL;PROT;PBSZ;UTF8;MDTM;SIZE;REST STREAM;EPSV;EPRT",
                "211 End",
            ],
            allow_anonymous=True,
            accept_any_login=True,
            auth_tls=False,
        )
    return FtpProfile(
        banner="220 secure-mock.local FTP ready",
        syst="215 UNIX Type: L8",
        help_lines=[],
        feat_lines=[
            "211-Features:",
            " AUTH TLS;TLS-C;SSL;PROT;PBSZ;UTF8",
            "211 End",
        ],
        allow_anonymous=False,
        accept_any_login=False,
        auth_tls=True,
    )


class FtpSession:
    def __init__(self, conn: socket.socket, addr: tuple[str, int], profile: FtpProfile) -> None:
        self.conn = conn
        self.addr = addr
        self.p = profile
        self.buf = bytearray()
        self.user: str | None = None
        self.logged_in = False
        self.tls = False
        self._data_port: int | None = None
        self._data_server: socket.socket | None = None

    def run(self) -> None:
        try:
            self.conn.settimeout(120.0)
            _send(self.conn, self.p.banner)
            while True:
                line = _read_line(self.conn, self.buf)
                if line is None:
                    break
                if not line:
                    continue
                try:
                    text = line.decode("utf-8", errors="replace").strip()
                except Exception:
                    _send(self.conn, "500 Invalid encoding")
                    continue
                if not self._dispatch(text):
                    break
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            self._close_data()
            try:
                self.conn.close()
            except OSError:
                pass

    def _close_data(self) -> None:
        if self._data_server:
            try:
                self._data_server.close()
            except OSError:
                pass
            self._data_server = None

    def _open_pasv(self) -> tuple[int, socket.socket]:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        return port, srv

    def _send_listing(self, data_sock: socket.socket) -> None:
        listing = "drwxr-xr-x 1 mock mock 4096 Jan  1 00:00 pub\r\n"
        try:
            data_sock.sendall(listing.encode("ascii"))
        except OSError:
            pass
        finally:
            try:
                data_sock.close()
            except OSError:
                pass

    def _dispatch(self, line: str) -> bool:
        parts = line.split(None, 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "QUIT":
            _send(self.conn, "221 Goodbye")
            return False
        if cmd == "NOOP":
            _send(self.conn, "200 OK")
            return True
        if cmd == "SYST":
            _send(self.conn, self.p.syst)
            return True
        if cmd == "HELP":
            if self.p.help_lines:
                for ln in self.p.help_lines:
                    _send(self.conn, ln)
            else:
                _send(self.conn, "502 HELP not implemented")
            return True
        if cmd == "FEAT":
            for ln in self.p.feat_lines:
                _send(self.conn, ln)
            return True
        if cmd == "STAT":
            _send(self.conn, "211-FTP mock status")
            _send(self.conn, "211 End of status")
            return True
        if cmd == "AUTH" and arg.upper() == "TLS":
            if not self.p.auth_tls:
                _send(self.conn, "502 AUTH TLS not available")
                return True
            _send(self.conn, "234 Proceed with negotiation")
            try:
                self.conn = _wrap_tls(self.conn)
                self.tls = True
                self.buf.clear()
            except OSError:
                return False
            return True
        if cmd == "USER":
            self.user = arg
            if arg.lower() == "anonymous" and self.p.allow_anonymous:
                _send(self.conn, "331 Anonymous login OK, send email as password")
            elif self.p.accept_any_login:
                _send(self.conn, "331 Password required")
            else:
                _send(self.conn, "331 Password required")
            return True
        if cmd == "PASS":
            user = self.user or ""
            if user.lower() == "anonymous" and not self.p.allow_anonymous:
                _send(self.conn, "530 Login incorrect")
                return True
            if self.p.accept_any_login or _creds_ok(user, arg, Profile.SECURE):
                self.logged_in = True
                _send(self.conn, "230 User logged in")
            else:
                _send(self.conn, "530 Login incorrect")
            return True
        if cmd == "TYPE":
            _send(self.conn, "200 Type set")
            return True
        if cmd == "PASV":
            if not self.logged_in:
                _send(self.conn, "530 Please login with USER and PASS")
                return True
            self._close_data()
            port, srv = self._open_pasv()
            self._data_server = srv
            self._data_port = port
            p1, p2 = divmod(port, 256)
            _send(self.conn, f"227 Entering Passive Mode (127,0,0,1,{p1},{p2})")
            return True
        if cmd in ("LIST", "NLST"):
            if not self.logged_in:
                _send(self.conn, "530 Please login with USER and PASS")
                return True
            if self._data_server is None:
                _send(self.conn, "425 Use PASV first")
                return True
            _send(self.conn, "150 Opening ASCII mode data connection")
            try:
                self._data_server.settimeout(10.0)
                data_sock, _ = self._data_server.accept()
                self._send_listing(data_sock)
            except OSError:
                pass
            self._close_data()
            _send(self.conn, "226 Transfer complete")
            return True
        if cmd == "STOR":
            if not self.logged_in:
                _send(self.conn, "530 Please login with USER and PASS")
                return True
            if self._data_server is None:
                _send(self.conn, "425 Use PASV first")
                return True
            _send(self.conn, "150 Opening BINARY mode data connection")
            try:
                self._data_server.settimeout(10.0)
                data_sock, _ = self._data_server.accept()
                try:
                    while True:
                        chunk = data_sock.recv(65536)
                        if not chunk:
                            break
                except OSError:
                    pass
                finally:
                    data_sock.close()
            except OSError:
                pass
            self._close_data()
            _send(self.conn, "226 Transfer complete")
            return True
        if cmd == "SIZE":
            _send(self.conn, "213 0")
            return True
        if cmd == "DELE":
            _send(self.conn, "250 DELE command successful")
            return True
        if cmd == "PWD":
            _send(self.conn, '257 "/" is current directory')
            return True
        if cmd == "CWD":
            _send(self.conn, "250 Directory changed")
            return True
        if cmd in ("PORT", "EPRT"):
            _send(self.conn, "200 OK")
            return True
        _send(self.conn, "500 Command not recognized (mock)")
        return True


class FtpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        FtpSession(self.request, self.client_address, self.server.ftp_profile).run()  # type: ignore[attr-defined]


class FtpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# Implicit TLS wrappers (POP3 1995, IMAP 1993, FTP 2990)
# ---------------------------------------------------------------------------


class _TlsFirstHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            tls_sock = _wrap_tls(self.request)
            tls_sock.settimeout(120.0)
            factory = getattr(self.server, "session_factory", None)
            if factory is not None:
                factory(tls_sock, self.client_address)
        except OSError:
            pass


class TlsFirstServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# Launcher
# ---------------------------------------------------------------------------


@dataclass
class Listener:
    name: str
    server: socketserver.BaseServer
    thread: threading.Thread = field(repr=False)


def run_mock(profile: Profile, host: str = "127.0.0.1", *, enable_tls_ports: bool = True) -> int:
    pop3_p = _pop3_profile(profile)
    imap_p = _imap_profile(profile)
    ftp_p = _ftp_profile(profile)

    ports = {
        "pop3": 1110,
        "imap": 1143,
        "ftp": 2121,
    }
    tls_ports = {
        "pop3_tls": 1995,
        "imap_tls": 1993,
        "ftp_tls": 2990,
    }

    listeners: list[Listener] = []

    pop3_srv = Pop3Server((host, ports["pop3"]), Pop3Handler)
    pop3_srv.pop3_profile = pop3_p
    pop3_th = threading.Thread(target=pop3_srv.serve_forever, daemon=True, name="mock-pop3")
    pop3_th.start()
    listeners.append(Listener("pop3", pop3_srv, pop3_th))

    imap_srv = ImapServer((host, ports["imap"]), ImapHandler)
    imap_srv.imap_profile = imap_p
    imap_th = threading.Thread(target=imap_srv.serve_forever, daemon=True, name="mock-imap")
    imap_th.start()
    listeners.append(Listener("imap", imap_srv, imap_th))

    ftp_srv = FtpServer((host, ports["ftp"]), FtpHandler)
    ftp_srv.ftp_profile = ftp_p
    ftp_th = threading.Thread(target=ftp_srv.serve_forever, daemon=True, name="mock-ftp")
    ftp_th.start()
    listeners.append(Listener("ftp", ftp_srv, ftp_th))

    if enable_tls_ports:
        def _pop3_tls_factory(sock: socket.socket, addr: tuple[str, int]) -> None:
            sess = Pop3Session(sock, addr, pop3_p)
            sess.tls = True
            sess.run()

        tls_pop = TlsFirstServer((host, tls_ports["pop3_tls"]), _TlsFirstHandler)
        tls_pop.session_factory = _pop3_tls_factory
        t1 = threading.Thread(target=tls_pop.serve_forever, daemon=True, name="mock-pop3-tls")
        t1.start()
        listeners.append(Listener("pop3_tls", tls_pop, t1))

        def _imap_tls_factory(sock: socket.socket, addr: tuple[str, int]) -> None:
            sess = ImapSession(sock, addr, imap_p)
            sess.tls = True
            sess.run()

        tls_imap = TlsFirstServer((host, tls_ports["imap_tls"]), _TlsFirstHandler)
        tls_imap.session_factory = _imap_tls_factory
        t2 = threading.Thread(target=tls_imap.serve_forever, daemon=True, name="mock-imap-tls")
        t2.start()
        listeners.append(Listener("imap_tls", tls_imap, t2))

        def _ftp_tls_factory(sock: socket.socket, addr: tuple[str, int]) -> None:
            sess = FtpSession(sock, addr, ftp_p)
            sess.tls = True
            sess.run()

        tls_ftp = TlsFirstServer((host, tls_ports["ftp_tls"]), _TlsFirstHandler)
        tls_ftp.session_factory = _ftp_tls_factory
        t3 = threading.Thread(target=tls_ftp.serve_forever, daemon=True, name="mock-ftp-tls")
        t3.start()
        listeners.append(Listener("ftp_tls", tls_ftp, t3))

    label = "VULNERABLE" if profile is Profile.VULN else "SECURE"
    print(f"[{_now()}] mail-proto-mock ({label}) on {host}", flush=True)
    print(f"  POP3 plain :{ports['pop3']}   IMAP plain :{ports['imap']}   FTP plain :{ports['ftp']}", flush=True)
    if enable_tls_ports:
        print(
            f"  POP3 TLS   :{tls_ports['pop3_tls']}   IMAP TLS   :{tls_ports['imap_tls']}   "
            f"FTP TLS   :{tls_ports['ftp_tls']}",
            flush=True,
        )
    if profile is Profile.SECURE:
        print(f"  Valid credentials: {VALID_USER!r} / {VALID_PASS!r}", flush=True)
    print("Examples:", flush=True)
    print(f"  ptsrvtester pop3 -ts ALL {host}:{ports['pop3']}", flush=True)
    print(f"  ptsrvtester imap -ts ALL {host}:{ports['imap']}", flush=True)
    print(f"  ptsrvtester ftp  -ts ALL {host}:{ports['ftp']}", flush=True)
    print("Ctrl+C to stop.", flush=True)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print(f"\n[{_now()}] Shutting down.", flush=True)
    finally:
        for ln in listeners:
            ln.server.shutdown()
            ln.server.server_close()
    return 0


def main(argv: list[str] | None = None, *, default_profile: Profile | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Combined POP3/IMAP/FTP mock for ptsrvtester (-ts modules).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument(
        "--profile",
        choices=[p.value for p in Profile],
        default=(default_profile.value if default_profile else Profile.VULN.value),
        help="vuln = findings expected; secure = hardened (default: vuln)",
    )
    parser.add_argument(
        "--no-tls-ports",
        action="store_true",
        help="Do not bind implicit-TLS ports 1995/1993/2990",
    )
    args = parser.parse_args(argv)
    return run_mock(Profile(args.profile), args.host, enable_tls_ports=not args.no_tls_ports)


if __name__ == "__main__":
    sys.exit(main())
