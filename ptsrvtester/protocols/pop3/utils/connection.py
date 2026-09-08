"""POP3 connection factory, shared server-info probe, and encryption probes."""
from __future__ import annotations

import ipaddress
import poplib
import random
import select
import socket
import ssl
import string
import sys
import threading
import time
from base64 import b64decode, b64encode
from typing import Callable

from .capa import bytes_to_text
from .helpers import get_mode
from .ptprinthelper import get_colored_text
from .results import (
    EncryptionResult,
    HelpInfoResult,
    InfoResult,
    NOOP2_DEFAULT_CONNECTIONS,
    NTLMResult,
    NoopConnectionCountResult,
    NoopDurationResult,
    NOOP1_PROGRESS_EVERY,
    noop1_stats_from_rtts,
    noop2_count_from_args,
    conn_limit_count_verdict,
    POP3_NOOP_POSTAUTH_CONN_ACCT_HIGH_MIN,
    POP3_NOOP_POSTAUTH_CONN_ACCT_INCREASED_MIN,
    POP3_NOOP_POSTAUTH_CONN_ACCT_SIGNIFICANT_MIN,
    POP3_NOOP_POSTAUTH_CONN_INTERVAL_SECONDS,
    POP3_NOOP_POSTAUTH_CONN_IP_HIGH_MIN,
    POP3_NOOP_POSTAUTH_CONN_IP_INCREASED_MIN,
    POP3_NOOP_POSTAUTH_CONN_IP_SIGNIFICANT_MIN,
    POP3_NOOP_POSTAUTH_CONN_MAX_ATTEMPTS,
    POP3_NOOP_POSTAUTH_CONN_TEST_SECONDS,
    POP3_NOOP_POSTAUTH_CONN_TIMEOUT_SECONDS,
    POP3_NOOP_POSTAUTH_DUR_HIGH_MIN,
    POP3_NOOP_POSTAUTH_DUR_INCREASED_MIN,
    POP3_NOOP_POSTAUTH_DUR_INTERVAL_SECONDS,
    POP3_NOOP_POSTAUTH_DUR_SIGNIFICANT_MIN,
    POP3_NOOP_POSTAUTH_DUR_TEST_SECONDS,
    POP3_NOOP_POSTAUTH_DUR_TIMEOUT_SECONDS,
    POP3_NOOP_PREAUTH_CONN_HIGH_MIN,
    POP3_NOOP_PREAUTH_CONN_INCREASED_MIN,
    POP3_NOOP_PREAUTH_CONN_INTERVAL_SECONDS,
    POP3_NOOP_PREAUTH_CONN_MAX_ATTEMPTS,
    POP3_NOOP_PREAUTH_CONN_SIGNIFICANT_MIN,
    POP3_NOOP_PREAUTH_CONN_TEST_SECONDS,
    POP3_NOOP_PREAUTH_CONN_TIMEOUT_SECONDS,
    POP3_NOOP_PREAUTH_DUR_HIGH_MIN,
    POP3_NOOP_PREAUTH_DUR_INCREASED_MIN,
    POP3_NOOP_PREAUTH_DUR_INTERVAL_SECONDS,
    POP3_NOOP_PREAUTH_DUR_SIGNIFICANT_MIN,
    POP3_NOOP_PREAUTH_DUR_TEST_SECONDS,
    POP3_NOOP_PREAUTH_DUR_TIMEOUT_SECONDS,
)
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
    """Banner + optional CAPA (post-STLS CAPA is fetched later by the CAPA module)."""
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
    return InfoResult(banner, capability, capability_stls)


def fetch_capa_after_stls(args, *, debug: DebugFn | None = None) -> dict | None:
    """Reconnect, STLS-upgrade, and return post-STLS CAPA (None if unavailable)."""
    if args.tls or args.target.port == 995:
        return None
    pop3 = connect_pop3(args)
    try:
        try:
            caps = pop3.capa()
        except poplib.error_proto:
            caps = None
        if not caps or "STLS" not in caps:
            if debug:
                debug("STLS not advertised in CAPA")
            return None
        if debug:
            debug("STLS available — upgrading for post-STLS CAPA")
        pop3.stls()
        capability_stls = pop3.capa()
        if debug:
            debug("CAPA after STLS:")
            for line in _capa_lines(capability_stls):
                debug(line, indent=8)
        return capability_stls
    except Exception as e:
        if debug:
            debug(f"STLS / CAPA after STLS failed: {e}")
        return None
    finally:
        try:
            pop3.close()
        except Exception:
            pass


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


# ─── NOOP Connection Limit Tests ──────────────────────────────────────────────


def _pop3_noop_safe(pop3: poplib.POP3 | poplib.POP3_SSL) -> tuple[bool, str | None]:
    """Send NOOP and return (success, error_msg)."""
    try:
        pop3._shortcmd("NOOP")  # Sends NOOP and expects +OK
        return (True, None)
    except Exception as e:
        return (False, _noop2_failure_detail(e))


def _noop1_duration_delay(args, default_duration: float, default_delay: float) -> tuple[float, float]:
    dur = getattr(args, "noop1_duration", None)
    delay = getattr(args, "noop1_delay", None)
    duration = float(dur) if dur is not None else float(default_duration)
    delay_s = float(delay) if delay is not None else float(default_delay)
    if duration <= 0:
        duration = float(default_duration)
    if delay_s < 0:
        delay_s = 0.0
    return duration, delay_s


def _noop1_error_result(*, authenticated: bool, duration: float, delay: float, error: str) -> NoopDurationResult:
    return NoopDurationResult(
        authenticated=authenticated,
        test_duration_seconds=duration,
        maintained_seconds=0.0,
        noops_sent=0,
        noops_ok=0,
        noops_error=0,
        disconnected=True,
        disconnect_after_seconds=None,
        hit_test_cap=False,
        error_message=error,
        delay_seconds=delay,
    )


def _noop1_wait_idle(sock, delay: float, start_time: float, duration: float, *, write_live=None) -> str:
    """Wait ``delay`` seconds; watch for peer close. Return ok / duration_cap / disconnected."""
    if duration > 0 and (time.perf_counter() - start_time) >= duration:
        return "duration_cap"
    if delay <= 0:
        return "ok"
    deadline = time.perf_counter() + delay
    orig_timeout = None
    try:
        orig_timeout = sock.gettimeout()
    except Exception:
        pass
    try:
        while True:
            now = time.perf_counter()
            elapsed = now - start_time
            if elapsed >= duration:
                return "duration_cap"
            remaining_delay = deadline - now
            if remaining_delay <= 0:
                return "ok"
            if write_live:
                wait_s = int(remaining_delay)
                elapsed_min = int(elapsed / 60)
                elapsed_sec = int(elapsed % 60)
                write_live(
                    f"Waiting {wait_s}s until next NOOP ({elapsed_min}m {elapsed_sec}s elapsed)"
                )
            wait = min(1.0, remaining_delay)
            try:
                ready, _, _ = select.select([sock], [], [], wait)
            except (ValueError, OSError, TypeError):
                return "disconnected"
            if not ready:
                continue
            try:
                data = sock.recv(1, socket.MSG_PEEK)
            except BlockingIOError:
                continue
            except Exception:
                return "disconnected"
            if not data:
                return "disconnected"
            return "disconnected"
    finally:
        try:
            if orig_timeout is not None:
                sock.settimeout(orig_timeout)
        except Exception:
            pass


def _run_noop_duration_loop(
    pop3, args, *, authenticated: bool, duration: float, delay: float,
    debug: DebugFn | None = None, flush=None,
) -> NoopDurationResult:
    start_time = time.perf_counter()
    noops_sent = 0
    noops_ok = 0
    noops_error = 0
    disconnected = False
    disconnect_after_seconds = None
    hit_test_cap = False
    idle_disconnect = False
    rtts: list[float] = []

    show_progress = not getattr(args, "json", False)
    verbose = bool(getattr(args, "debug", False))
    live_line_dirty = False

    def write_live(text: str):
        nonlocal live_line_dirty
        if not show_progress or verbose:
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

    def emit_vv(msg: str) -> None:
        """Print a -vv snapshot as its own line (never onto the live \\r row)."""
        if not verbose or not debug:
            return
        clear_live()
        debug(msg)
        if flush:
            flush()

    if show_progress and not verbose:
        write_live("Test started, sending first NOOP...")

    try:
        while True:
            elapsed = time.perf_counter() - start_time
            if elapsed >= duration:
                hit_test_cap = True
                break

            noops_sent += 1
            t0 = time.perf_counter()
            success, error = _pop3_noop_safe(pop3)
            rt = time.perf_counter() - t0
            if success:
                noops_ok += 1
                rtts.append(rt)
                if show_progress and not verbose and (
                    delay > 0 or noops_sent == 1 or noops_sent % NOOP1_PROGRESS_EVERY == 0
                ):
                    elapsed_now = time.perf_counter() - start_time
                    elapsed_min = int(elapsed_now / 60)
                    elapsed_sec = int(elapsed_now % 60)
                    write_live(f"NOOPs sent: {noops_sent} ({elapsed_min}m {elapsed_sec}s elapsed)")
                if noops_sent % NOOP1_PROGRESS_EVERY == 0:
                    emit_vv(
                        f"NOOP #{noops_sent}: +OK rt={rt:.3f}s "
                        f"(elapsed: {int(time.perf_counter() - start_time)}s)"
                    )
            else:
                noops_error += 1
                disconnected = True
                disconnect_after_seconds = time.perf_counter() - start_time
                emit_vv(f"NOOP #{noops_sent}: failed — {error}")
                break

            wait_state = _noop1_wait_idle(
                pop3.sock, delay, start_time, duration,
                write_live=write_live if not verbose else None,
            )
            if wait_state == "duration_cap":
                hit_test_cap = True
                break
            if wait_state == "disconnected":
                disconnected = True
                idle_disconnect = True
                disconnect_after_seconds = time.perf_counter() - start_time
                emit_vv(
                    f"Idle disconnect after {disconnect_after_seconds:.1f}s "
                    f"(no NOOP for {delay:.0f}s interval)"
                )
                break
    finally:
        clear_live()
        try:
            pop3.close()
        except Exception:
            pass

    maintained_seconds = time.perf_counter() - start_time
    stats = noop1_stats_from_rtts(rtts, noops_sent, noops_error)
    return NoopDurationResult(
        authenticated=authenticated,
        test_duration_seconds=duration,
        maintained_seconds=maintained_seconds,
        noops_sent=noops_sent,
        noops_ok=noops_ok,
        noops_error=noops_error,
        disconnected=disconnected,
        disconnect_after_seconds=disconnect_after_seconds,
        hit_test_cap=hit_test_cap,
        error_message=None,
        delay_seconds=delay,
        idle_disconnect=idle_disconnect,
        **stats,
    )


def test_noop_duration_preauth(args, *, debug: DebugFn | None = None, flush=None) -> NoopDurationResult:
    """NOOP1: Keep a pre-auth connection alive with periodic NOOP."""
    duration, delay = _noop1_duration_delay(
        args, POP3_NOOP_PREAUTH_DUR_TEST_SECONDS, POP3_NOOP_PREAUTH_DUR_INTERVAL_SECONDS,
    )
    if debug:
        debug(f"NOOP duration test (pre-auth): connecting... (duration={duration:.0f}s, delay={delay:.0f}s)")
        if flush:
            flush()

    try:
        pop3 = connect_pop3(args, timeout=POP3_NOOP_PREAUTH_DUR_TIMEOUT_SECONDS, debug=debug)
        pop3.sock.settimeout(POP3_NOOP_PREAUTH_DUR_TIMEOUT_SECONDS)
    except Exception as e:
        return _noop1_error_result(
            authenticated=False, duration=duration, delay=delay,
            error=f"Connection failed: {e}",
        )
    return _run_noop_duration_loop(
        pop3, args, authenticated=False, duration=duration, delay=delay,
        debug=debug, flush=flush,
    )


def test_noop_duration_postauth(
    args, username: str, password: str, *, debug: DebugFn | None = None, flush=None,
) -> NoopDurationResult:
    """NOOP1: Keep a post-auth connection alive with periodic NOOP."""
    duration, delay = _noop1_duration_delay(
        args, POP3_NOOP_POSTAUTH_DUR_TEST_SECONDS, POP3_NOOP_POSTAUTH_DUR_INTERVAL_SECONDS,
    )
    if debug:
        debug(
            f"NOOP duration test (post-auth): connecting and logging in as {username!r}... "
            f"(duration={duration:.0f}s, delay={delay:.0f}s)"
        )
        if flush:
            flush()

    try:
        pop3 = connect_pop3(args, timeout=POP3_NOOP_POSTAUTH_DUR_TIMEOUT_SECONDS, debug=debug)
        pop3.sock.settimeout(POP3_NOOP_POSTAUTH_DUR_TIMEOUT_SECONDS)
        pop3.user(username)
        pop3.pass_(password)
    except Exception as e:
        return _noop1_error_result(
            authenticated=True, duration=duration, delay=delay,
            error=f"Connection/login failed: {e}",
        )
    return _run_noop_duration_loop(
        pop3, args, authenticated=True, duration=duration, delay=delay,
        debug=debug, flush=flush,
    )


def _noop2_ramp_threads(args) -> int:
    return max(1, int(getattr(args, "noop2_threads", None) or 1))


def _noop2_failure_detail(exc: BaseException) -> str:
    """Prefer the original socket/server text when connect_pop3 wraps OSError."""
    if exc.__cause__ is not None:
        inner = str(exc.__cause__).strip()
        if inner:
            return inner
    return str(exc).strip() or type(exc).__name__


def _noop2_classify_conn_failure(exc: BaseException) -> tuple[str, str]:
    """Return ``(reason, detail)`` for -vv, matching SMTP/IMAP NOOP2 wording."""
    detail = _noop2_failure_detail(exc)
    root = exc.__cause__ if exc.__cause__ is not None else exc
    if isinstance(root, (socket.timeout, TimeoutError)):
        return "timeout", detail
    if isinstance(root, (
        ConnectionRefusedError,
        ConnectionResetError,
        ConnectionAbortedError,
        BrokenPipeError,
    )):
        return "disconnect", detail
    msg = detail.lower()
    if "timed out" in msg or "timeout" in msg:
        return "timeout", detail
    if any(k in msg for k in (
        "refused", "reset", "disconnect", "closed", "broken pipe",
        "aborted", "eof", "-err", "inactivity",
    )):
        return "disconnect", detail
    return "error", detail


def _noop2_reason_from_text(text: str) -> str:
    msg = (text or "").lower()
    if "timed out" in msg or "timeout" in msg:
        return "timeout"
    if any(k in msg for k in (
        "refused", "reset", "disconnect", "closed", "broken pipe",
        "aborted", "eof", "-err", "inactivity",
    )):
        return "disconnect"
    return "error"


def _noop2_format_close_cause(error: str | None) -> str:
    """Human-readable close cause. POP3 -ERR body is tagged like IMAP BYE."""
    text = (error or "").strip()
    if not text:
        return "peer closed connection"
    low = text.lower()
    body = text
    if low.startswith("-err"):
        body = text[4:].strip()
        low = body.lower()
    if "errno" in low or "error:" in low or low.startswith(("connection", "socket", "ssl", "timeout")):
        return body or text
    if low.startswith("server "):
        return body
    return f"server: {body}" if body else "peer closed connection"


def _noop2_drop_conn(pop3) -> None:
    """Tear down a storm socket without QUIT (avoids hangs on dead peers)."""
    sock = getattr(pop3, "sock", None)
    try:
        if sock is not None:
            try:
                sock.settimeout(0.2)
            except Exception:
                pass
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
    except Exception:
        pass
    fh = getattr(pop3, "file", None)
    if fh is not None:
        try:
            fh.close()
        except Exception:
            pass


def _noop2_socket_already_closed(sock) -> bool:
    """True if the peer has already closed the socket (FIN/RST); stray data = still alive."""
    if sock is None:
        return True
    try:
        ready, _, _ = select.select([sock], [], [], 0)
    except (ValueError, OSError, TypeError):
        return True
    if not ready:
        return False
    try:
        data = sock.recv(1, socket.MSG_PEEK)
    except BlockingIOError:
        return False
    except Exception:
        return True
    return not data


def _noop2_print_ramp(out, flush, established, est_err, est_disc, est_timeout, reaped, *, json_mode=False) -> None:
    if json_mode or out is None:
        return
    out(f"Established {established} connections", "TITLE", indent=4)
    out(f"Errors {est_err} connections", "TITLE", indent=4)
    out(f"Refused at connect {est_disc} connections", "TITLE", indent=4)
    out(f"Timeouts during connecting {est_timeout}", "TITLE", indent=4)
    out(f"Dropped while idle {reaped} connections", "TITLE", indent=4)
    if flush:
        flush()


def _noop2_wait_delay(sock, delay: float, stop_event: threading.Event) -> str:
    """Wait ``delay`` seconds between NOOPs. Return ok / disconnected / stopped."""
    if delay <= 0:
        return "ok"
    deadline = time.perf_counter() + delay
    while not stop_event.is_set():
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return "ok"
        if _noop2_socket_already_closed(sock):
            return "disconnected"
        try:
            ready, _, _ = select.select([sock], [], [], min(0.25, remaining))
        except (ValueError, OSError, TypeError):
            return "disconnected"
        if ready and _noop2_socket_already_closed(sock):
            return "disconnected"
        if ready:
            time.sleep(min(0.25, remaining))
    return "stopped"


def _noop2_make_count_result(
    *,
    authenticated: bool,
    requested: int,
    established: int,
    maintained: int,
    duration: float,
    sent: int,
    ok: int,
    err: int,
    disconnected: int,
    est_err: int,
    est_disc: int,
    est_timeout: int,
    reaped: int,
    storm_pool: int,
    min_rt,
    max_rt,
    avg_rt,
    error_rate_pct: float,
    early_exit: bool,
    terminated,
    delay: float,
    error_message=None,
) -> NoopConnectionCountResult:
    return NoopConnectionCountResult(
        authenticated=authenticated,
        max_connections_attempted=requested,
        connections_established=established,
        connections_maintained=maintained,
        test_duration_seconds=duration,
        total_noops_sent=sent,
        total_noops_ok=ok,
        total_noops_error=err,
        early_disconnect_count=disconnected,
        error_message=error_message,
        establish_errors=est_err,
        establish_disconnected=est_disc,
        establish_timeouts=est_timeout,
        reaped_before_storm=reaped,
        storm_pool_connections=storm_pool,
        min_rt_seconds=min_rt,
        max_rt_seconds=max_rt,
        avg_rt_seconds=avg_rt,
        error_rate_pct=error_rate_pct,
        early_exit_no_connections=early_exit,
        terminated_connections=tuple(terminated),
        delay_seconds=delay,
    )


def _noop2_establish_pool(
    max_connections: int,
    opener,
    *,
    write_live,
    show_progress,
    debug: DebugFn | None = None,
    ramp_threads: int = 1,
    clear_live=None,
):
    """Open connections sequentially or with ``-t`` worker threads.

    Every requested slot is attempted. Failures are logged at -vv with
    classified reason and the server/socket text.
    """
    connections: list = []
    fail_count = 0
    est_err = 0
    est_disc = 0
    est_timeout = 0
    ramp_threads = min(max(1, ramp_threads), max_connections)
    lock = threading.Lock()
    next_index = 0

    def progress_text() -> str:
        extra = f" ({fail_count} failed)" if fail_count else ""
        return f"Establishing connections: {len(connections)}/{max_connections}{extra}"

    def emit_fail(idx: int, exc: BaseException) -> None:
        nonlocal fail_count, est_err, est_disc, est_timeout
        fail_count += 1
        reason, detail = _noop2_classify_conn_failure(exc)
        if reason == "timeout":
            est_timeout += 1
        elif reason == "disconnect":
            est_disc += 1
        else:
            est_err += 1
        if clear_live:
            clear_live()
        if debug:
            debug(f"Connection #{idx + 1} failed — {reason} ({detail})")
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
        return connections, est_err, est_disc, est_timeout

    def worker() -> None:
        nonlocal next_index
        while True:
            with lock:
                if next_index >= max_connections:
                    return
                idx = next_index
                next_index += 1
            try_one(idx)

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(ramp_threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    return connections, est_err, est_disc, est_timeout


def _noop2_conn_count_test(
    args,
    *,
    opener,
    authenticated: bool,
    max_connections: int,
    duration: float,
    delay: float,
    timeout_seconds: float,
    closer,
    label: str,
    debug: DebugFn | None = None,
    out=None,
    flush=None,
) -> NoopConnectionCountResult:
    """Ramp up connections, then hold them with NOOP for ``duration`` seconds."""
    ramp_threads = _noop2_ramp_threads(args)
    json_mode = bool(getattr(args, "json", False))
    if debug:
        extra = f" ({ramp_threads} threads)" if ramp_threads > 1 else ""
        debug(
            f"NOOP connection count test ({label}): attempting up to {max_connections} "
            f"connections{extra}, duration={duration:.0f}s, delay={delay:.0f}s..."
        )

    show_progress = not json_mode
    live_line_dirty = False

    def write_live(text: str):
        nonlocal live_line_dirty
        if not show_progress:
            return
        line = get_colored_text(text, "ADDITIONS")
        sys.stdout.write(f"\033[2K\r{line}")
        sys.stdout.flush()
        live_line_dirty = True

    def clear_live():
        nonlocal live_line_dirty
        if not show_progress or not live_line_dirty:
            return
        sys.stdout.write("\033[2K\r")
        sys.stdout.flush()
        live_line_dirty = False

    connections, est_err, est_disc, est_timeout = _noop2_establish_pool(
        max_connections,
        opener,
        write_live=write_live,
        show_progress=show_progress,
        debug=debug,
        ramp_threads=ramp_threads,
        clear_live=clear_live,
    )
    established = len(connections)
    clear_live()

    live_connections = []
    reaped = 0
    for pop3, idx in connections:
        sock = getattr(pop3, "sock", None)
        if _noop2_socket_already_closed(sock):
            reaped += 1
            _noop2_drop_conn(pop3)
        else:
            live_connections.append((pop3, idx))
    connections = live_connections
    storm_pool = len(connections)

    _noop2_print_ramp(
        out, flush, established, est_err, est_disc, est_timeout, reaped, json_mode=json_mode,
    )
    if show_progress and out is not None:
        kind, text = conn_limit_count_verdict(established, max_connections)
        out(text, kind, indent=4)
        if flush:
            flush()

    if storm_pool == 0:
        if debug:
            debug(
                f"NOOP2 ({label}): all {established} established sockets were closed before "
                f"the storm (reaped={reaped}); skipping NOOP phase."
            )
        return _noop2_make_count_result(
            authenticated=authenticated,
            requested=max_connections,
            established=established,
            maintained=0,
            duration=0.0,
            sent=0, ok=0, err=0, disconnected=0,
            est_err=est_err, est_disc=est_disc, est_timeout=est_timeout,
            reaped=reaped, storm_pool=0,
            min_rt=None, max_rt=None, avg_rt=None,
            error_rate_pct=0.0, early_exit=True, terminated=(),
            delay=delay,
        )

    if debug:
        debug(
            f"NOOP2 ({label}): {storm_pool}/{established} sockets alive after sweep "
            f"(reaped={reaped}); starting NOOP storm for {duration:.0f}s (delay={delay:.0f}s)."
        )

    stop_event = threading.Event()
    results_lock = threading.Lock()
    agg_sent = 0
    agg_ok = 0
    agg_err = 0
    agg_rtts: list[float] = []
    terminated_info: list[tuple[int, str, str]] = []
    active_count = storm_pool
    FLUSH_EVERY = 32

    def _flush(local_sent, local_ok, local_err, local_rtts) -> None:
        nonlocal agg_sent, agg_ok, agg_err
        with results_lock:
            agg_sent += local_sent
            agg_ok += local_ok
            agg_err += local_err
            if local_rtts:
                agg_rtts.extend(local_rtts)

    def _worker(display_idx: int, pop3) -> None:
        nonlocal active_count
        sock = getattr(pop3, "sock", None)
        local_sent = 0
        local_ok = 0
        local_err = 0
        local_rtts: list[float] = []
        total_ok = 0
        died_reason: str | None = None
        died_cause = ""
        try:
            while not stop_event.is_set():
                if _noop2_socket_already_closed(sock):
                    died_reason = "disconnect"
                    died_cause = "peer closed connection"
                    break
                t0 = time.perf_counter()
                success, error = _pop3_noop_safe(pop3)
                rt = time.perf_counter() - t0
                local_sent += 1
                if success:
                    local_ok += 1
                    total_ok += 1
                    local_rtts.append(rt)
                else:
                    local_err += 1
                    closed = _noop2_socket_already_closed(sock)
                    reason = _noop2_reason_from_text(error or "")
                    if closed or reason == "disconnect":
                        died_reason = reason if error else "disconnect"
                        died_cause = _noop2_format_close_cause(error)
                        break
                if local_sent % FLUSH_EVERY == 0:
                    _flush(local_sent, local_ok, local_err, local_rtts)
                    local_sent = local_ok = local_err = 0
                    local_rtts = []
                if delay > 0:
                    wait = _noop2_wait_delay(sock, delay, stop_event)
                    if wait == "disconnected":
                        died_reason = "disconnect"
                        died_cause = "peer closed connection"
                        break
                    if wait == "stopped":
                        break
        except Exception as exc:
            local_sent += 1
            local_err += 1
            died_reason, died_cause = _noop2_classify_conn_failure(exc)
            died_cause = _noop2_format_close_cause(died_cause)
        finally:
            _flush(local_sent, local_ok, local_err, local_rtts)
            if died_reason is not None:
                t_rel = time.perf_counter() - run_start
                if total_ok == 0:
                    timing = f"no successful reply, t={t_rel:.1f}s"
                else:
                    timing = f"after {total_ok} OK NOOPs, t={t_rel:.1f}s"
                detail = f"{died_cause}; {timing}" if died_cause else timing
                with results_lock:
                    active_count -= 1
                    terminated_info.append((display_idx, died_reason, detail))

    threads: list[threading.Thread] = []
    run_start = time.perf_counter()
    for display_idx, (pop3, _orig_idx) in enumerate(connections, start=1):
        t = threading.Thread(target=_worker, args=(display_idx, pop3), daemon=True)
        threads.append(t)
        t.start()

    deadline = run_start + duration
    early_exit_no_conns = False
    while time.perf_counter() < deadline:
        with results_lock:
            cs, co, ce = agg_sent, agg_ok, agg_err
            active_now = active_count
        if active_now == 0:
            early_exit_no_conns = True
            break
        if show_progress:
            remaining = int(max(0, deadline - time.perf_counter()))
            write_live(
                f"NOOP storm (active {active_now}/{storm_pool}): {cs} sent "
                f"(ok={co}, err={ce}) — {remaining:02d}s left"
            )
        time.sleep(0.1)
    stop_event.set()
    if early_exit_no_conns:
        for pop3, _ in connections:
            _noop2_drop_conn(pop3)
        join_s = 2.0
    else:
        join_s = min(5.0, timeout_seconds + 2.0)
    for t in threads:
        t.join(timeout=join_s)
    run_duration = time.perf_counter() - run_start
    clear_live()

    for pop3, _ in connections:
        _noop2_drop_conn(pop3)

    min_rt = min(agg_rtts) if agg_rtts else None
    max_rt = max(agg_rtts) if agg_rtts else None
    avg_rt = (sum(agg_rtts) / len(agg_rtts)) if agg_rtts else None
    error_rate_pct = (100.0 * agg_err / agg_sent) if agg_sent else 0.0
    with results_lock:
        active_end = max(active_count, 0)
        terminated_sorted = tuple(sorted(terminated_info, key=lambda t: t[0]))
    disconnected_during = max(storm_pool - active_end, 0)

    if debug:
        debug(
            f"NOOP2 ({label}) summary: established={established}/{max_connections} "
            f"(err={est_err}, disc={est_disc}, timeout={est_timeout}, reaped={reaped}), "
            f"storm_pool={storm_pool}, active_end={active_end}, "
            f"dropped_during_test={disconnected_during}, "
            f"early_exit={early_exit_no_conns}, duration={run_duration:.1f}s, "
            f"sent={agg_sent}, ok={agg_ok}, error={agg_err} ({error_rate_pct:.1f}%), "
            f"avg_rt={avg_rt}."
        )

    return _noop2_make_count_result(
        authenticated=authenticated,
        requested=max_connections,
        established=established,
        maintained=active_end,
        duration=run_duration,
        sent=agg_sent, ok=agg_ok, err=agg_err,
        disconnected=disconnected_during,
        est_err=est_err, est_disc=est_disc, est_timeout=est_timeout,
        reaped=reaped, storm_pool=storm_pool,
        min_rt=min_rt, max_rt=max_rt, avg_rt=avg_rt,
        error_rate_pct=error_rate_pct,
        early_exit=early_exit_no_conns,
        terminated=terminated_sorted,
        delay=delay,
    )


def test_noop_conn_count_preauth(
    args, *, debug: DebugFn | None = None, out=None, flush=None,
) -> NoopConnectionCountResult:
    """NOOP2: How many pre-auth connections can be maintained with NOOP."""
    max_connections = noop2_count_from_args(args, NOOP2_DEFAULT_CONNECTIONS)
    duration, delay = _noop1_duration_delay(
        args,
        POP3_NOOP_PREAUTH_CONN_TEST_SECONDS,
        POP3_NOOP_PREAUTH_CONN_INTERVAL_SECONDS,
    )

    def opener(_idx: int):
        pop3 = connect_pop3(args, timeout=POP3_NOOP_PREAUTH_CONN_TIMEOUT_SECONDS, debug=None)
        pop3.sock.settimeout(POP3_NOOP_PREAUTH_CONN_TIMEOUT_SECONDS)
        return pop3

    return _noop2_conn_count_test(
        args,
        opener=opener,
        authenticated=False,
        max_connections=max_connections,
        duration=duration,
        delay=delay,
        timeout_seconds=POP3_NOOP_PREAUTH_CONN_TIMEOUT_SECONDS,
        closer=lambda pop3: pop3.close(),
        label="pre-auth",
        debug=debug,
        out=out,
        flush=flush,
    )


def test_noop_conn_count_postauth(
    args, username: str, password: str, *, debug: DebugFn | None = None, out=None, flush=None,
) -> NoopConnectionCountResult:
    """NOOP2: How many post-auth connections can be maintained with NOOP."""
    raw = noop2_count_from_args(args, NOOP2_DEFAULT_CONNECTIONS)
    max_connections = min(raw * 4, POP3_NOOP_POSTAUTH_CONN_MAX_ATTEMPTS)
    duration, delay = _noop1_duration_delay(
        args,
        POP3_NOOP_POSTAUTH_CONN_TEST_SECONDS,
        POP3_NOOP_POSTAUTH_CONN_INTERVAL_SECONDS,
    )

    def opener(_idx: int):
        pop3 = connect_pop3(args, timeout=POP3_NOOP_POSTAUTH_CONN_TIMEOUT_SECONDS, debug=None)
        pop3.sock.settimeout(POP3_NOOP_POSTAUTH_CONN_TIMEOUT_SECONDS)
        pop3.user(username)
        pop3.pass_(password)
        return pop3

    return _noop2_conn_count_test(
        args,
        opener=opener,
        authenticated=True,
        max_connections=max_connections,
        duration=duration,
        delay=delay,
        timeout_seconds=POP3_NOOP_POSTAUTH_CONN_TIMEOUT_SECONDS,
        closer=lambda pop3: pop3.close(),
        label="post-auth",
        debug=debug,
        out=out,
        flush=flush,
    )
