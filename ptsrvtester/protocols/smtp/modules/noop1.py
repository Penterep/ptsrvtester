"""NOOP1 — NOOP connection duration."""
import select
import socket
import sys
import time

from ._common import eng
from ._noop import (
    _noop1_duration_delay,
    _noop_progress_line,
    _smtp_noop_close,
    _smtp_noop_open,
    _smtp_noop_safe,
)
from ..utils.results import *

def _noop1_wait_idle(sock, delay: float, start_time: float, duration: float, *, tick=None) -> str:
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
            if tick:
                tick()
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

def _noop1_error_result(e, *, authenticated: bool, duration: float, delay: float, error: str) -> NoopDurationResult:
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

def _run_noop_duration_loop(e, smtp, *, authenticated: bool, duration: float, delay: float) -> NoopDurationResult:
    start_time = time.perf_counter()
    noops_sent = 0
    noops_ok = 0
    noops_error = 0
    disconnected = False
    disconnect_after_seconds = None
    hit_test_cap = False
    idle_disconnect = False
    tag_counter = 0
    rtts: list[float] = []

    show_progress = not e.use_json
    verbose = bool(getattr(e.args, "debug", False))
    live_line_dirty = False

    def write_live(text: str):
        nonlocal live_line_dirty
        if not show_progress:
            return
        sys.stdout.write(f"\033[2K\r{text}")
        sys.stdout.flush()
        live_line_dirty = True

    def paint() -> None:
        elapsed = time.perf_counter() - start_time
        write_live(_noop_progress_line(elapsed, duration, f"NOOPs: {noops_sent}"))

    def clear_live():
        nonlocal live_line_dirty
        if not show_progress or not live_line_dirty:
            return
        sys.stdout.write("\033[2K\r")
        sys.stdout.flush()
        live_line_dirty = False

    def emit_vv(msg: str) -> None:
        """Print a -vv snapshot as its own line (never onto the live \\r row)."""
        if not verbose:
            return
        clear_live()
        e.debug(msg)
        e._flush_terminal()

    paint()

    try:
        while True:
            elapsed = time.perf_counter() - start_time
            if elapsed >= duration:
                hit_test_cap = True
                break

            tag_counter += 1
            noops_sent += 1
            tag = f"a{tag_counter:04d}"
            t0 = time.perf_counter()
            success, error = _smtp_noop_safe(e, smtp, tag)
            rt = time.perf_counter() - t0
            if success:
                noops_ok += 1
                rtts.append(rt)
                paint()
                if noops_sent % NOOP1_PROGRESS_EVERY == 0:
                    emit_vv(
                        f"NOOP #{noops_sent}: 250 ({rt:.2f}s, elapsed {int(time.perf_counter() - start_time)}s)"
                    )
                    paint()
            else:
                noops_error += 1
                disconnected = True
                disconnect_after_seconds = time.perf_counter() - start_time
                emit_vv(f"NOOP #{noops_sent}: failed — {error}")
                break

            wait_state = _noop1_wait_idle(
                smtp.sock, delay, start_time, duration,
                tick=paint,
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
            _smtp_noop_close(smtp)
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

def test_noop_duration_preauth(e) -> NoopDurationResult:
    """NOOP1: Keep a pre-auth connection alive with periodic NOOP."""
    duration, delay = _noop1_duration_delay(e, 
        SMTP_NOOP_PREAUTH_DUR_TEST_SECONDS, SMTP_NOOP_PREAUTH_DUR_INTERVAL_SECONDS,
    )
    e.debug(
        f"NOOP duration test: connecting... "
        f"(duration={duration:.0f}s, delay={delay:.0f}s)"
    )
    e._flush_terminal()
    try:
        smtp = _smtp_noop_open(e)
        smtp.sock.settimeout(SMTP_NOOP_PREAUTH_DUR_TIMEOUT_SECONDS)
    except Exception as ex:
        return _noop1_error_result(e, 
            authenticated=False, duration=duration, delay=delay,
            error=f"Connection failed: {ex}",
        )
    return _run_noop_duration_loop(e, 
        smtp, authenticated=False, duration=duration, delay=delay,
    )


__MODULELABEL__ = "NOOP connection duration"
__MODULECODE__ = "NOOP1"
__ORDER__ = 85


def _fmt_held(seconds: float | None) -> str:
    if seconds is None:
        return "N/A"
    if seconds >= 60:
        return f"{seconds / 60.0:.1f} min"
    return f"{seconds:.1f}s"


def _evaluate_duration(result, thresholds):
    """Evaluate duration result and return (vulnerable, rating)."""
    maintained_min = result.maintained_seconds / 60.0
    vulnerable = False
    rating = "OK"

    high_min, significant_min, increased_min = thresholds
    held = result.disconnect_after_seconds if result.disconnected else result.maintained_seconds
    held = held or 0.0

    if result.hit_test_cap or result.disconnected:
        if held >= high_min:
            rating = "high"
            vulnerable = True
        elif held >= significant_min:
            rating = "significant"
            vulnerable = True
        elif held >= increased_min:
            rating = "increased"
            vulnerable = True

    return vulnerable, rating, maintained_min


def _emit_timing(ctx, result, indent=8):
    from ..utils.results import NOOP1_ERROR_RATE_OK_MAX_PCT, noop1_rt_display

    if result.min_rt_seconds is not None:
        ctx.out(
            f"Time between two commands ({noop1_rt_display(result.min_rt_seconds)} - "
            f"{noop1_rt_display(result.max_rt_seconds)}, avg {noop1_rt_display(result.avg_rt_seconds)})",
            "NOTVULN",
            indent=indent,
        )
        if result.slowdown_detected:
            ctx.out(
                f"Time trolting is configured "
                f"(baseline {noop1_rt_display(result.baseline_avg_seconds)} → "
                f"last {noop1_rt_display(result.last_window_avg_seconds)})",
                "NOTVULN",
                indent=indent,
            )
        else:
            ctx.out("No time trolting is configured", "VULN", indent=indent)
    else:
        ctx.out("No time trolting is configured (not enough samples)", "VULN", indent=indent)

    err_rate = result.error_rate_pct
    if err_rate <= NOOP1_ERROR_RATE_OK_MAX_PCT:
        ctx.out(f"Error rate: {err_rate:.0f}%", "NOTVULN", indent=indent)
    else:
        ctx.out(
            f"Error rate: {err_rate:.0f}% (over {NOOP1_ERROR_RATE_OK_MAX_PCT:.0f}%)",
            "VULN",
            indent=indent,
        )


def _emit_duration(ctx, result, vulnerable):
    held = result.disconnect_after_seconds if result.disconnected else result.maintained_seconds
    bullet = "VULN" if vulnerable else "NOTVULN"
    if result.idle_disconnect:
        ctx.out(
            f"Idle disconnect: connection closed after {_fmt_held(held)} without NOOP",
            bullet,
            indent=8,
        )
    elif result.disconnected:
        ctx.out(f"Connection dropped after {_fmt_held(held)}", bullet, indent=8)
    elif result.hit_test_cap:
        ctx.out(f"No disconnect within {_fmt_held(result.maintained_seconds)}", bullet, indent=8)
    _emit_timing(ctx, result, indent=8)
    ctx.out(
        f"NOOPs: {result.noops_sent} sent, {result.noops_ok} OK, {result.noops_error} errors",
        "INFO",
        indent=8,
    )


def run(ctx):
    e = eng(ctx)

    from ..utils.results import (
        SMTP_NOOP_PREAUTH_DUR_HIGH_MIN,
        SMTP_NOOP_PREAUTH_DUR_INCREASED_MIN,
        SMTP_NOOP_PREAUTH_DUR_SIGNIFICANT_MIN,
        VULNS,
    )

    try:
        result_preauth = test_noop_duration_preauth(e)
    except Exception as ex:
        ctx.out(f"Test failed: {ex}", "ERROR", indent=8)
        result_preauth = None

    if result_preauth and not result_preauth.error_message:
        e.results.noop_duration_preauth = result_preauth
        thresholds = (
            SMTP_NOOP_PREAUTH_DUR_HIGH_MIN,
            SMTP_NOOP_PREAUTH_DUR_SIGNIFICANT_MIN,
            SMTP_NOOP_PREAUTH_DUR_INCREASED_MIN,
        )
        vulnerable, rating, _maintained_min = _evaluate_duration(result_preauth, thresholds)
        _emit_duration(ctx, result_preauth, vulnerable)
        if vulnerable:
            ctx.report.add_vulnerability(
                vuln_code=VULNS.NoopDurationPreauth.value,
                vuln_request=f"NOOP duration ({rating})",
            )
    elif result_preauth:
        ctx.out(f"Test error: {result_preauth.error_message}", "ERROR", indent=8)
