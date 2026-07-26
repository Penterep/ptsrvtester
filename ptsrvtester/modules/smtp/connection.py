import ipaddress, smtplib, socket, ssl, time


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..utils.helpers import get_mode

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from .helpers import *
from .results import *
from .registry import *


class ConnectionMixin:

    def connect(self, timeout: float = 15.0, *, fatal: bool = True) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, int, bytes]:
        """Port 465 is implicit TLS only (SMTPS), so we use TLS even without --tls.
        For IP targets we connect manually with server_hostname=None so SNI does not break.

        timeout controls the socket read/write deadline for all operations on the
        returned SMTP object.  Callers that need a non-default value (e.g. enumeration
        uses 30 s; retry after server silence uses 10 s) pass it explicitly.

        When ``fatal`` is False the caller receives :class:`ConnectionError` instead of
        ``end_error`` / process exit — used by threaded AUTH-ENUM probes."""
        try:
            if self.args.tls or self.args.target.port == 465:
                ctx = ssl._create_unverified_context()
                host, port = self.args.target.ip, self.args.target.port
                try:
                    ipaddress.ip_address(host)
                    server_hostname = None
                except ValueError:
                    server_hostname = host
                sock = socket.create_connection((host, port), timeout=timeout)
                sock_ssl = ctx.wrap_socket(sock, server_hostname=server_hostname)
                smtp = smtplib.SMTP(timeout=timeout)
                smtp.sock = sock_ssl
                smtp.file = None
                status, reply = smtp.getreply()
            else:
                smtp = smtplib.SMTP(timeout=timeout)
                status, reply = smtp.connect(self.args.target.ip, self.args.target.port)
                if self.args.starttls and status == 220:
                    status_stls, _ = smtp.docmd("STARTTLS")
                    if status_stls == 220:
                        ctx = ssl._create_unverified_context()
                        try:
                            _is_ip = ipaddress.ip_address(self.args.target.ip)
                            server_hostname = None
                        except ValueError:
                            server_hostname = self.args.target.ip
                        sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=server_hostname)
                        smtp.sock = sock_ssl
                        smtp.file = None
                        smtp.helo_resp = None
                        smtp.ehlo_resp = None
                        smtp.esmtp_features = {}
                        smtp.does_esmtp = False

            self._smtp_sock_set_tcp_nodelay(smtp)
            return smtp, status, reply
        except Exception as e:
            mode = "TLS" if (self.args.tls or self.args.target.port == 465) else get_mode(self.args)
            msg = (
                f"Could not connect to the target server "
                f"{self.args.target.ip}:{self.args.target.port} ({mode}): {e}"
            )
            if self.args.target.port == 587 and not self.args.starttls and "refused" in str(e).lower():
                msg += " (port 587 typically requires --starttls)"
            if fatal:
                self._fail(msg)
            raise ConnectionError(msg) from e

    def _connect_silent(self, timeout: float = 15.0, send_ehlo: bool = True) -> smtplib.SMTP:
        """Like connect() but NEVER calls _fail() – raises plain Exception on failure.
        Used exclusively by rate_limit_test so no error is printed for failed attempts.

        When ``send_ehlo`` is False, the function returns immediately after reading the 220
        banner so the caller can measure the server's pre-EHLO (banner) idle timeout.
        """
        try:
            if self.args.tls or self.args.target.port == 465:
                ctx = ssl._create_unverified_context()
                host, port = self.args.target.ip, self.args.target.port
                try:
                    ipaddress.ip_address(host)
                    server_hostname = None
                except ValueError:
                    server_hostname = host
                sock = socket.create_connection((host, port), timeout=timeout)
                sock_ssl = ctx.wrap_socket(sock, server_hostname=server_hostname)
                smtp = smtplib.SMTP(timeout=timeout)
                smtp.sock = sock_ssl
                smtp.file = None
                status, reply = smtp.getreply()
            else:
                smtp = smtplib.SMTP(timeout=timeout)
                status, reply = smtp.connect(self.args.target.ip, self.args.target.port)
            if status != 220:
                try:
                    smtp.close()
                except Exception:
                    pass
                raise Exception(
                    f"Could not connect to the target server "
                    f"{self.args.target.ip}:{self.args.target.port}: server responded {status}"
                )
            self._smtp_sock_set_tcp_nodelay(smtp)
            if send_ehlo:
                smtp.docmd("EHLO", self.fqdn)
            return smtp
        except Exception:
            raise

    @staticmethod
    def _smtp_sock_set_tcp_nodelay(smtp) -> None:
        """Disable Nagle on the SMTP TCP socket so small segments (e.g. multi-line replies) arrive sooner."""
        sk = getattr(smtp, "sock", None)
        if sk is None:
            return
        try:
            sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, ValueError, AttributeError):
            pass

    def get_smtp_handler(self, timeout: float = 15.0) -> smtplib.SMTP:
        smtp_handler, status, reply = self.connect(timeout=timeout)
        if status == 220:
            return smtp_handler
        else:
            self.ptjsonlib.end_error(
                f"SMTP Info - [{status}] {self.bytes_to_str(reply)}", self.use_json
            )
            raise SystemExit

    def _get_smtp_connection(self):
        smtp, status, reply = self.connect()

        if status == 220:
            status, reply = smtp.docmd("EHLO", f"{self.fqdn}")
            if status == 250:
                return smtp
            else:
                raise Exception("Error when EHLOing")
        else:
            # Include actual server response (e.g. 421 = too many connections, try later)
            raise Exception(f"Server responded {status}: {self.bytes_to_str(reply)}")

    def wait_for_unban(self, seconds, ban_duration=0, retries_left=12):
        """Wait for server to unban, then try to reconnect. Returns (ban_seconds, reconnected)."""
        self.noop_smtp_connections()
        ban_duration += seconds
        time.sleep(seconds)
        try:
            self.ptdebug(f">", end="")
            self._get_smtp_connection()
            self.ptdebug(f"\r", end="")
            return (ban_duration, True)
        except Exception as e:
            if retries_left <= 0:
                return (ban_duration, False)
            return self.wait_for_unban(5, ban_duration, retries_left - 1)

    def noop_smtp_connections(self):
        for smtp in self.smtp_list:
            status, reply = smtp.docmd("noop")
            if status != 250:
                return True
        return False

    def close_smtp_connections(
        self,
    ):
        for smtp in self.smtp_list:
            try:
                smtp.quit()
            except Exception:
                continue
        del self.smtp_list

    def bytes_to_str(self, text):
        return text.decode("utf-8")
