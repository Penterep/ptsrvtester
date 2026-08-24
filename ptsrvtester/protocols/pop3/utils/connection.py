"""POP3 connection factory, shared server-info probe, and encryption probes."""
from __future__ import annotations

import ipaddress
import poplib
import random
import socket
import ssl
import string
from base64 import b64decode, b64encode
from typing import Callable

from .capa import bytes_to_text
from .helpers import get_mode
from .results import EncryptionResult, HelpInfoResult, InfoResult, NTLMResult
from .ptntlmauth.ptntlmauth import decode_ChallengeMessage_blob, get_NegotiateMessage_data

DebugFn = Callable[..., None]


def _snip(text: str | bytes | None, limit: int = 160) -> str:
    """One-line reply snippet for -vv traces (avoid dumping huge blobs)."""
    if text is None:
        return ""
    if isinstance(text, bytes):
        text = bytes_to_text(text)
    text = (text or "").replace("\r", "").replace("\n", " ").strip()
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _capa_lines(capa: dict | None) -> list[str]:
    if not capa:
        return ["(none)"]
    lines = []
    for key in sorted(capa):
        vals = capa.get(key) or []
        if vals:
            lines.append(f"{key} {' '.join(str(v) for v in vals)}")
        else:
            lines.append(str(key))
    return lines or ["(empty)"]


def connect_pop3(args, *, timeout: float = 10.0, debug: DebugFn | None = None) -> poplib.POP3 | poplib.POP3_SSL:
    """Open a fresh POP3 connection according to ``args.tls`` / ``--starttls`` / port 995."""
    mode = "TLS" if (args.tls or args.target.port == 995) else get_mode(args)
    if debug:
        debug(f"Connecting to {args.target.ip}:{args.target.port} ({mode})")
    try:
        if args.tls or args.target.port == 995:
            ctx = ssl._create_unverified_context()
            pop3 = poplib.POP3_SSL(
                args.target.ip, args.target.port, context=ctx, timeout=timeout,
            )
        else:
            pop3 = poplib.POP3(args.target.ip, args.target.port, timeout=timeout)
            if args.starttls:
                if debug:
                    debug("Sending STLS (explicit upgrade)")
                pop3.stls()
                if debug:
                    debug("STLS upgrade OK")
    except Exception as e:
        if debug:
            debug(f"Connect failed: {e}")
        raise OSError(
            f"Could not connect to the target server "
            f"{args.target.ip}:{args.target.port} ({mode}): {e}"
        ) from e
    if debug:
        debug(f"Banner: {_snip(pop3.welcome)}")
    return pop3


def fetch_info(
    pop3: poplib.POP3 | poplib.POP3_SSL,
    args,
    *,
    get_capa: bool = True,
    debug: DebugFn | None = None,
) -> InfoResult:
    """Banner + optional CAPA (and CAPA after STLS upgrade when applicable)."""
    banner = bytes_to_text(pop3.welcome)
    capability = None
    capability_stls = None
    if get_capa:
        try:
            capability = pop3.capa()
            if debug:
                debug("CAPA response:")
                for line in _capa_lines(capability):
                    debug(line, indent=8)
        except poplib.error_proto as e:
            capability = None
            if debug:
                debug(f"CAPA failed: {e}")
        if (
            capability
            and "STLS" in capability
            and args.target.port != 995
            and not args.tls
            and not isinstance(pop3, poplib.POP3_SSL)
        ):
            try:
                if debug:
                    debug("STLS available — upgrading for post-STLS CAPA")
                pop3.stls()
                capability_stls = pop3.capa()
                if debug:
                    debug("CAPA after STLS:")
                    for line in _capa_lines(capability_stls):
                        debug(line, indent=8)
            except Exception as e:
                if debug:
                    debug(f"STLS / CAPA after STLS failed: {e}")
    return InfoResult(banner, capability, capability_stls)


def probe_server_info(args, *, debug: DebugFn | None = None) -> InfoResult:
    """One-shot connect used to populate shared ``ctx.server_info``."""
    if debug:
        debug("Initial server information")
    pop3 = connect_pop3(args, debug=debug)
    try:
        return fetch_info(pop3, args, get_capa=True, debug=debug)
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

    def get(self, *, debug: DebugFn | None = None) -> tuple[InfoResult | None, str | None]:
        if not self._loaded:
            try:
                self._info = probe_server_info(self._args, debug=debug)
            except Exception as e:
                self._error = str(e)
                if debug:
                    debug(f"Initial server probe failed: {e}")
            self._loaded = True
        return self._info, self._error


def require_server_info(ctx) -> InfoResult | None:
    """Return cached banner/CAPA or report the connect error once and return None."""
    info, err = ctx.server_info.get(debug=ctx.debug)
    if err:
        if not ctx.server_info._error_emitted:
            ctx.server_info._error_emitted = True
            ctx.report.set_connect_error(err)
            ctx.out(err, "ERROR", indent=4)
        return None
    return info


def fetch_help_info(
    pop3: poplib.POP3 | poplib.POP3_SSL,
    capa: dict | None,
    *,
    debug: DebugFn | None = None,
) -> HelpInfoResult:
    help_response = None
    try:
        resp = pop3._shortcmd("HELP")
        help_response = bytes_to_text(resp)
        if debug:
            debug(f"HELP → {_snip(help_response)}")
            for line in (help_response or "").replace("\r", "").splitlines()[1:12]:
                if line.strip():
                    debug(line, indent=8)
    except Exception as e:
        help_response = None
        if debug:
            debug(f"HELP failed: {e}")

    implementation = None
    if capa and "IMPLEMENTATION" in capa:
        vals = capa.get("IMPLEMENTATION") or []
        implementation = " ".join(str(v) for v in vals) if vals else "IMPLEMENTATION"
        if debug:
            debug(f"IMPLEMENTATION (from CAPA): {implementation}")
    elif debug:
        debug("IMPLEMENTATION not advertised in CAPA")
    return HelpInfoResult(help_response, implementation)


def test_encryption(args, *, debug: DebugFn | None = None) -> EncryptionResult:
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
                welcome = bytes_to_text(pop3.welcome)
                plaintext_ok = True
                _dbg(f"Plaintext welcome: {_snip(welcome)}")
            finally:
                pop3.close()
        except Exception as e:
            _dbg(f"Plaintext test failed: {e}")

        try:
            pop3 = poplib.POP3(host, port, timeout=timeout)
            try:
                _dbg(f"STLS probe welcome: {_snip(pop3.welcome)}")
                caps = pop3.capa()
                _dbg("STLS probe CAPA: " + ", ".join(_capa_lines(caps)[:12]))
                if "STLS" in caps:
                    resp = pop3._shortcmd("STLS")
                    _dbg(f"STLS → {_snip(resp)}")
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
                        post = pop3.capa()
                        _dbg("CAPA after STLS wrap: " + ", ".join(_capa_lines(post)[:12]))
                        stls_ok = True
                else:
                    _dbg("STLS not advertised in CAPA")
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
            ok = bool(line and line.strip().startswith(b"+OK"))
            _dbg(f"Implicit TLS (SNI={sni!r}) welcome: {_snip(line)} → {'OK' if ok else 'FAIL'}")
            return ok
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


def auth_anonymous(
    pop3: poplib.POP3 | poplib.POP3_SSL,
    *,
    debug: DebugFn | None = None,
) -> bool:
    try:
        res: bytes = pop3._shortcmd("AUTH ANONYMOUS")
        if debug:
            debug(f"AUTH ANONYMOUS → {_snip(res)}")
        if len(res.strip()) == 1:
            cont = b64encode(b"HELLO").decode()
            res2 = pop3._shortcmd(cont)
            if debug:
                debug(f"AUTH ANONYMOUS continuation → {_snip(res2)}")
        return True
    except Exception as e:
        if debug:
            debug(f"AUTH ANONYMOUS failed: {e}")
        return False


def auth_ntlm(args, *, debug: DebugFn | None = None) -> NTLMResult:
    try:
        pop3 = connect_pop3(args, debug=debug)
        try:
            res: bytes = pop3._shortcmd("AUTH NTLM")
            if debug:
                debug(f"AUTH NTLM → {_snip(res)}")
            if res.strip().startswith(b"+"):
                b64_neg = b64encode(get_NegotiateMessage_data()).decode()
                res = pop3._shortcmd(b64_neg).strip()
                if debug:
                    debug(f"AUTH NTLM after negotiate → {_snip(res)}")
                b64_chal = b"+".join(res.split(b"+")[1:])
                info = decode_ChallengeMessage_blob(b64decode(b64_chal))
                if debug:
                    debug("NTLM challenge decoded OK")
                return NTLMResult(True, info)
            if debug:
                debug("AUTH NTLM: server did not return challenge (+)")
            return NTLMResult(False, None)
        finally:
            pop3.close()
    except Exception as e:
        if debug:
            debug(f"AUTH NTLM failed: {e}")
        return NTLMResult(False, None)


def test_catch_all(args, *, debug: DebugFn | None = None) -> str:
    """Return ``indeterminate``, ``not_configured``, or ``unreachable``."""
    try:
        pop3 = connect_pop3(args, debug=debug)
    except Exception as e:
        if debug:
            debug(f"Catch-all: connect failed: {e}")
        return "unreachable"
    try:
        fake_user = "".join(random.choices(string.ascii_letters + string.digits, k=24))
        fake_pass = "".join(random.choices(string.ascii_letters + string.digits, k=24))
        if debug:
            debug(f"Catch-all USER {fake_user!r}")
        try:
            pop3.user(fake_user)
            if debug:
                debug(f"Catch-all USER → accepted, trying PASS")
            pop3.pass_(fake_pass)
            if debug:
                debug("Catch-all PASS → accepted (indeterminate)")
            return "indeterminate"
        except Exception as e:
            if debug:
                debug(f"Catch-all rejected (not configured): {e}")
            return "not_configured"
    finally:
        try:
            pop3.close()
        except Exception:
            pass


def try_login(args, creds, *, debug: DebugFn | None = None) -> object | None:
    try:
        pop3 = connect_pop3(args)
    except OSError as e:
        if debug:
            debug(f"Login {creds.user!r}: connect failed: {e}")
        return None
    try:
        if debug:
            debug(f"USER {creds.user!r}")
        pop3.user(creds.user)
        pop3.pass_(creds.passw)
        if debug:
            debug(f"PASS → +OK (valid: {creds.user!r})")
        return creds
    except Exception as e:
        if debug:
            debug(f"PASS → failed for {creds.user!r}: {_snip(str(e))}")
        return None
    finally:
        try:
            pop3.close()
        except Exception:
            pass
