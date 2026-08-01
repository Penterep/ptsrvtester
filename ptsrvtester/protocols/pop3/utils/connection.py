"""POP3 connection factory, shared server-info probe, and encryption probes."""
from __future__ import annotations

import ipaddress
import poplib
import random
import socket
import ssl
import string
from base64 import b64decode, b64encode

from .capa import bytes_to_text
from .helpers import get_mode
from .results import EncryptionResult, HelpInfoResult, InfoResult, NTLMResult
from .ptntlmauth.ptntlmauth import decode_ChallengeMessage_blob, get_NegotiateMessage_data


def connect_pop3(args, *, timeout: float = 10.0) -> poplib.POP3 | poplib.POP3_SSL:
    """Open a fresh POP3 connection according to ``args.tls`` / ``--starttls`` / port 995."""
    try:
        if args.tls or args.target.port == 995:
            ctx = ssl._create_unverified_context()
            pop3 = poplib.POP3_SSL(
                args.target.ip, args.target.port, context=ctx, timeout=timeout,
            )
        else:
            pop3 = poplib.POP3(args.target.ip, args.target.port, timeout=timeout)
            if args.starttls:
                pop3.stls()
    except Exception as e:
        mode = "TLS" if (args.tls or args.target.port == 995) else get_mode(args)
        raise OSError(
            f"Could not connect to the target server "
            f"{args.target.ip}:{args.target.port} ({mode}): {e}"
        ) from e
    return pop3


def fetch_info(pop3: poplib.POP3 | poplib.POP3_SSL, args, *, get_capa: bool = True) -> InfoResult:
    """Banner + optional CAPA (and CAPA after STLS upgrade when applicable)."""
    banner = bytes_to_text(pop3.welcome)
    capability = None
    capability_stls = None
    if get_capa:
        try:
            capability = pop3.capa()
        except poplib.error_proto:
            capability = None
        if (
            capability
            and "STLS" in capability
            and args.target.port != 995
            and not args.tls
            and not isinstance(pop3, poplib.POP3_SSL)
        ):
            try:
                pop3.stls()
                capability_stls = pop3.capa()
            except Exception:
                pass
    return InfoResult(banner, capability, capability_stls)


def probe_server_info(args) -> InfoResult:
    """One-shot connect used to populate shared ``ctx.server_info``."""
    pop3 = connect_pop3(args)
    try:
        return fetch_info(pop3, args, get_capa=True)
    finally:
        try:
            pop3.close()
        except Exception:
            pass


class ServerInfoCache:
    """Lazy shared banner/CAPA snapshot — probed once on first access."""

    def __init__(self, args):
        self._args = args
        self._info: InfoResult | None = None
        self._error: str | None = None
        self._loaded = False
        self._error_emitted = False

    def get(self) -> tuple[InfoResult | None, str | None]:
        if not self._loaded:
            try:
                self._info = probe_server_info(self._args)
            except Exception as e:
                self._error = str(e)
            self._loaded = True
        return self._info, self._error


def require_server_info(ctx) -> InfoResult | None:
    """Return cached banner/CAPA or report the connect error once and return None."""
    info, err = ctx.server_info.get()
    if err:
        if not ctx.server_info._error_emitted:
            ctx.server_info._error_emitted = True
            ctx.report.set_connect_error(err)
            ctx.out(err, "ERROR", indent=4)
        return None
    return info


def fetch_help_info(pop3: poplib.POP3 | poplib.POP3_SSL, capa: dict | None) -> HelpInfoResult:
    help_response = None
    try:
        resp = pop3._shortcmd("HELP")
        help_response = bytes_to_text(resp)
    except Exception:
        help_response = None

    implementation = None
    if capa and "IMPLEMENTATION" in capa:
        vals = capa.get("IMPLEMENTATION") or []
        implementation = " ".join(str(v) for v in vals) if vals else "IMPLEMENTATION"
    return HelpInfoResult(help_response, implementation)


def test_encryption(args, *, debug=None) -> EncryptionResult:
    """Probe plaintext / STLS / implicit TLS with fresh connections."""
    host = args.target.ip
    port = args.target.port
    timeout = 10.0
    plaintext_ok = stls_ok = tls_ok = False
    _ssl_ctx = ssl._create_unverified_context()
    tls_only_port = port == 995

    def _dbg(msg: str) -> None:
        if debug:
            debug(msg)

    if not tls_only_port:
        try:
            pop3 = poplib.POP3(host, port, timeout=timeout)
            try:
                _ = pop3.welcome
                plaintext_ok = True
            finally:
                pop3.close()
        except Exception as e:
            _dbg(f"Plaintext test failed: {e}")

        try:
            pop3 = poplib.POP3(host, port, timeout=timeout)
            try:
                _ = pop3.welcome
                caps = pop3.capa()
                if "STLS" in caps:
                    resp = pop3._shortcmd("STLS")
                    if resp.startswith(b"+OK"):
                        try:
                            ipaddress.ip_address(host)
                            sni = None
                        except ValueError:
                            sni = host
                        sock_ssl = _ssl_ctx.wrap_socket(pop3.sock, server_hostname=sni)
                        pop3.sock = sock_ssl
                        pop3.file = sock_ssl.makefile("rb")
                        pop3._tls_established = True
                        pop3.capa()
                        stls_ok = True
            finally:
                pop3.close()
        except Exception as e:
            _dbg(f"STLS test failed: {e}")

    connect_timeout = 15.0 if tls_only_port else timeout

    def _try_implicit_tls(sni):
        sock = socket.create_connection((host, port), timeout=connect_timeout)
        sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=sni)
        sock_ssl.settimeout(connect_timeout)
        try:
            f = sock_ssl.makefile("rb")
            try:
                line = f.readline()
            finally:
                f.close()
            return bool(line and line.strip().startswith(b"+OK"))
        finally:
            sock_ssl.close()

    try:
        try:
            ipaddress.ip_address(host)
            sni_first, sni_fallback = None, host
        except ValueError:
            sni_first, sni_fallback = host, None
        for sni in (sni_first, sni_fallback):
            if sni is None and sni_fallback is None:
                continue
            try:
                if _try_implicit_tls(sni):
                    tls_ok = True
                    break
            except Exception as e:
                _dbg(f"Implicit TLS test failed (SNI={sni!r}): {e}")
    except Exception as e:
        _dbg(f"Implicit TLS test failed: {e}")

    return EncryptionResult(plaintext_ok, stls_ok, tls_ok)


def auth_anonymous(pop3: poplib.POP3 | poplib.POP3_SSL) -> bool:
    try:
        res: bytes = pop3._shortcmd("AUTH ANONYMOUS")
        if len(res.strip()) == 1:
            pop3._shortcmd(b64encode(b"HELLO").decode())
        return True
    except Exception:
        return False


def auth_ntlm(args) -> NTLMResult:
    try:
        pop3 = connect_pop3(args)
        try:
            res: bytes = pop3._shortcmd("AUTH NTLM")
            if res.strip().startswith(b"+"):
                b64_neg = b64encode(get_NegotiateMessage_data()).decode()
                res = pop3._shortcmd(b64_neg).strip()
                b64_chal = b"+".join(res.split(b"+")[1:])
                info = decode_ChallengeMessage_blob(b64decode(b64_chal))
                return NTLMResult(True, info)
            return NTLMResult(False, None)
        finally:
            pop3.close()
    except Exception:
        return NTLMResult(False, None)


def test_catch_all(args) -> str:
    """Return ``indeterminate``, ``not_configured``, or ``unreachable``."""
    try:
        pop3 = connect_pop3(args)
    except Exception:
        return "unreachable"
    try:
        fake_user = "".join(random.choices(string.ascii_letters + string.digits, k=24))
        fake_pass = "".join(random.choices(string.ascii_letters + string.digits, k=24))
        try:
            pop3.user(fake_user)
            pop3.pass_(fake_pass)
            return "indeterminate"
        except Exception:
            return "not_configured"
    finally:
        try:
            pop3.close()
        except Exception:
            pass


def try_login(args, creds) -> object | None:
    try:
        pop3 = connect_pop3(args)
    except OSError:
        return None
    try:
        pop3.user(creds.user)
        pop3.pass_(creds.passw)
        return creds
    except Exception:
        return None
    finally:
        try:
            pop3.close()
        except Exception:
            pass
