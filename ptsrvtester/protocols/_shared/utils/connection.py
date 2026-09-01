"""Connection adapters the rate-limit engine drives.

:class:`TcpConnectionAdapter` is the protocol-agnostic default: a bare TCP
connect (optionally reading a greeting banner) is enough to exercise the
connection limiting most services enforce at the transport / pre-auth layer
(e.g. sshd ``MaxStartups`` + ``LoginGraceTime``, connection-per-IP caps in
mail/LDAP servers, firewall/conntrack rate limits).

A protocol that wants a more precise "the service really accepted me" signal
(a full handshake rather than a raw SYN-ACK) can subclass this or provide its
own object with the same ``probe()`` / ``open_held()`` methods and expose it as
``ctx.rate_limit_adapter``.
"""

from __future__ import annotations

import socket
import time
from typing import Optional

from .rate_limit import (
    ConnectionHandle,
    ProbeOutcome,
    ProbeResult,
    classify_exception,
)


class SocketHandle:
    """A held TCP socket with a non-consuming peer-liveness snapshot."""

    __slots__ = ("_sock",)

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def is_alive(self) -> Optional[bool]:
        """Peek without consuming: idle == alive, EOF/error == closed.

        Pending bytes are reported as unknown (``None``): a non-consuming peek
        cannot tell whether a FIN follows them, so we do not overstate liveness.
        """
        try:
            self._sock.setblocking(False)
        except OSError:
            return False
        try:
            pending = self._sock.recv(1, socket.MSG_PEEK)
            return False if pending == b"" else None
        except (BlockingIOError, InterruptedError):
            return True
        except OSError:
            return False
        finally:
            try:
                self._sock.setblocking(True)
            except OSError:
                pass


class TcpConnectionAdapter:
    """Default adapter: TCP connect (+ optional banner read) and hold."""

    def __init__(
        self,
        host: str,
        port: int,
        timeout_seconds: float = 5.0,
        *,
        expect_banner: bool = False,
        banner_bytes: int = 64,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = float(timeout_seconds)
        self.expect_banner = expect_banner
        self.banner_bytes = banner_bytes

    def _connect(self) -> tuple[ProbeResult, Optional[socket.socket]]:
        started = time.perf_counter()
        sock: Optional[socket.socket] = None
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            sock.settimeout(self.timeout)
            if self.expect_banner:
                data = sock.recv(self.banner_bytes)
                if not data:
                    duration = max(0.0, (time.perf_counter() - started) * 1000.0)
                    try:
                        sock.close()
                    except OSError:
                        pass
                    return ProbeResult(
                        ProbeOutcome.REJECTED,
                        duration_ms=duration,
                        error="server closed without sending a banner",
                    ), None
            duration = max(0.0, (time.perf_counter() - started) * 1000.0)
            return ProbeResult(ProbeOutcome.ACCEPTED, duration_ms=duration), sock
        except Exception as exc:
            duration = max(0.0, (time.perf_counter() - started) * 1000.0)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            return ProbeResult(
                classify_exception(exc), duration_ms=duration, error=str(exc)
            ), None

    def probe(self) -> ProbeResult:
        result, sock = self._connect()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        return result

    def open_held(self) -> tuple[ProbeResult, Optional[ConnectionHandle]]:
        result, sock = self._connect()
        if sock is None:
            return result, None
        return result, SocketHandle(sock)


class SSHBannerAdapter(TcpConnectionAdapter):
    """SSH adapter: a connection counts as accepted only once sshd sends its
    ``SSH-2.0-...`` identification banner.  This distinguishes a real SSH slot
    (``MaxStartups`` not exhausted) from a bare TCP SYN-ACK, and holding the
    socket without completing key exchange exercises ``LoginGraceTime``.
    """

    def __init__(self, host: str, port: int, timeout_seconds: float = 5.0) -> None:
        super().__init__(
            host, port, timeout_seconds, expect_banner=True, banner_bytes=255
        )


__all__ = ["SocketHandle", "TcpConnectionAdapter", "SSHBannerAdapter"]