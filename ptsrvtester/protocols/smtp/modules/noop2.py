"""NOOP2 — NOOP connection count."""
import select
import smtplib
import socket
import sys
import threading
import time

from ..utils.ptprinthelper import get_colored_text
from ..utils.results import conn_limit_count_verdict
from ._common import eng
from ._noop import (
    _noop1_duration_delay,
    _noop_progress_line,
    _smtp_noop_close,
    _smtp_noop_open,
    _smtp_noop_safe,
    _unwrap_smtp_error,
)
from ..utils.results import *

def _noop2_ramp_threads(e) -> int:
    raw = getattr(e.args, "noop2_threads", None)
    if raw is None:
        raw = getattr(e.args, "enum_threads", None)
    return max(1, int(raw or 1))

def _noop2_classify_conn_failure(exc: BaseException) -> tuple[str, str]:
    """Return ``(reason, detail)`` for -vv, matching SMTP NOOP2 wording."""
    detail = _unwrap_smtp_error(str(exc).strip() or type(exc).__name__)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout", detail
    if isinstance(exc, (
        ConnectionRefusedError,
        ConnectionResetError,
        ConnectionAbortedError,
        BrokenPipeError,
        smtplib.SMTPServerDisconnected,
    )):
        return "disconnect", detail
    msg = detail.lower()
    if "timed out" in msg or "timeout" in msg:
        return "timeout", detail
    if any(k in msg for k in ("refused", "reset", "disconnect", "closed", "broken pipe", "aborted", " bye")):
        return "disconnect", detail
    return "error", detail

def _noop2_reason_from_text(text: str) -> str:
    msg = (text or "").lower()
    if "timed out" in msg or "timeout" in msg:
        return "timeout"
    if any(k in msg for k in ("refused", "reset", "disconnect", "closed", "broken pipe", "aborted", "eof", "bye")):
        return "disconnect"
    return "error"

def _noop2_format_close_cause(error: str | None) -> str:
    """Human-readable close cause. IMAP BYE body is tagged so it is not our idle verdict."""
    text = (error or "").strip()
    if not text:
        return "peer closed connection"
    low = text.lower()
    if "errno" in low or "error:" in low or low.startswith(("connection", "socket", "ssl", "timeout")):
        return text
    if low.startswith("server bye"):
        return text
    return f"server BYE: {text}"

def _noop2_drop_conn(imap) -> None:
    """Tear down a storm socket without IMAP LOGOUT (avoids 30s hangs on dead peers)."""
    sock = getattr(imap, "sock", None)
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
    for attr in ("file",):
        fh = getattr(imap, attr, None)
        if fh is None:
            continue
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

def _noop2_print_ramp(e, established, est_err, est_disc, est_timeout, reaped) -> None:
    if e.use_json:
        return
    e.out(f"Established {established} connections", "TITLE", indent=4)
    e.out(f"Errors {est_err} connections", "TITLE", indent=4)
    e.out(f"Refused at connect {est_disc} connections", "TITLE", indent=4)
    e.out(f"Timeouts during connecting {est_timeout}", "TITLE", indent=4)
    e.out(f"Dropped while idle {reaped} connections", "TITLE", indent=4)
    e._flush_terminal()

def _noop2_wait_delay(e, sock, delay: float, stop_event: threading.Event) -> str:
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
    e,
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

def _noop2_establish_pool(e, max_connections: int, opener, *, write_live, show_progress, clear_live=None):
    """Open connections sequentially or with ``-t`` worker threads.

    Every requested slot is attempted (SMTP NOOP2 behaviour). Failures are
    logged at -vv with classified reason and the server/socket text.
    """
    connections: list = []
    fail_count = 0
    est_err = 0
    est_disc = 0
    est_timeout = 0
    ramp_threads = min(_noop2_ramp_threads(e), max_connections)
    lock = threading.Lock()
    next_index = 0
    ramp_start = time.perf_counter()

    def progress_text() -> str:
        done = len(connections) + fail_count
        extra = f" ({fail_count} failed)" if fail_count else ""
        eta = None
        if done > 0:
            elapsed = time.perf_counter() - ramp_start
            eta = max(0.0, (max_connections - done) * elapsed / done)
        return _noop_progress_line(
            done, max_connections, f"Establishing{extra}", eta=eta, count=True,
        )

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
        e.debug(f"Connection #{idx + 1} failed — {reason} ({detail})")
        if show_progress:
            write_live(progress_text())

    def record(conn, idx: int) -> None:
        connections.append((conn, idx))
        if show_progress:
            write_live(progress_text())

    def try_one(idx: int) -> None:
        try:
            conn = opener(idx)
        except Exception as ex:
            with lock:
                emit_fail(idx, ex)
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

    workers = [
        threading.Thread(target=worker, daemon=True)
        for _ in range(ramp_threads)
    ]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    return connections, est_err, est_disc, est_timeout

def _noop2_conn_count_test(
    e,
    *,
    opener,
    authenticated: bool,
    max_connections: int,
    duration: float,
    delay: float,
    timeout_seconds: float,
    closer,
    tag_prefix: str,
) -> NoopConnectionCountResult:
    """Ramp up connections, then hold them with NOOP for ``duration`` seconds."""
    ramp_threads = _noop2_ramp_threads(e)
    e.debug(
        f"NOOP connection count test: attempting up to {max_connections} connections"
        + (f" ({ramp_threads} threads)" if ramp_threads > 1 else "")
        + f", duration={duration:.0f}s, delay={delay:.0f}s..."
    )

    show_progress = not e.use_json
    live_line_dirty = False

    def write_live(text: str):
        nonlocal live_line_dirty
        if not show_progress:
            return
        line = text
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

    connections, est_err, est_disc, est_timeout = _noop2_establish_pool(e, 
        max_connections, opener, write_live=write_live, show_progress=show_progress,
        clear_live=clear_live,
    )
    established = len(connections)
    clear_live()

    live_connections = []
    reaped = 0
    for imap, idx in connections:
        sock = getattr(imap, "sock", None)
        if _noop2_socket_already_closed(sock):
            reaped += 1
            _noop2_drop_conn(imap)
        else:
            live_connections.append((imap, idx))
    connections = live_connections
    storm_pool = len(connections)

    _noop2_print_ramp(e, established, est_err, est_disc, est_timeout, reaped)
    if show_progress:
        kind, text = conn_limit_count_verdict(established, max_connections)
        e.out(text, kind, indent=4)
        e._flush_terminal()

    if storm_pool == 0:
        e.debug(
            f"NOOP2: all {established} established sockets were closed before "
            f"the storm (reaped={reaped}); skipping NOOP phase."
        )
        return _noop2_make_count_result(e, 
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

    e.debug(
        f"NOOP2: {storm_pool}/{established} sockets alive after sweep "
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

    def _worker(display_idx: int, imap, orig_idx: int) -> None:
        nonlocal active_count
        sock = getattr(imap, "sock", None)
        local_sent = 0
        local_ok = 0
        local_err = 0
        local_rtts: list[float] = []
        total_ok = 0
        tag_counter = 0
        died_reason: str | None = None
        died_cause = ""
        try:
            while not stop_event.is_set():
                if _noop2_socket_already_closed(sock):
                    died_reason = "disconnect"
                    died_cause = "peer closed connection"
                    break
                tag_counter += 1
                t0 = time.perf_counter()
                success, error = _smtp_noop_safe(e, 
                    imap, f"{tag_prefix}{orig_idx:04d}{tag_counter:04d}",
                )
                rt = time.perf_counter() - t0
                local_sent += 1
                if success:
                    local_ok += 1
                    total_ok += 1
                    local_rtts.append(rt)
                else:
                    local_err += 1
                    # BYE / abort ends the socket even if TCP is still half-open.
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
                    wait = _noop2_wait_delay(e, sock, delay, stop_event)
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
    for display_idx, (imap, orig_idx) in enumerate(connections, start=1):
        t = threading.Thread(
            target=_worker, args=(display_idx, imap, orig_idx), daemon=True,
        )
        threads.append(t)
        t.start()

    deadline = run_start + duration
    early_exit_no_conns = False
    verbose = bool(getattr(e.args, "debug", False))
    next_vv = NOOP1_PROGRESS_EVERY
    while time.perf_counter() < deadline:
        with results_lock:
            cs, co, ce = agg_sent, agg_ok, agg_err
            active_now = active_count
        if active_now == 0:
            early_exit_no_conns = True
            break
        if verbose and cs >= next_vv:
            clear_live()
            elapsed = int(time.perf_counter() - run_start)
            e.debug(f"NOOP #{cs}: ok={co}, err={ce} (elapsed {elapsed}s)")
            next_vv = ((cs // NOOP1_PROGRESS_EVERY) + 1) * NOOP1_PROGRESS_EVERY
        if show_progress:
            elapsed = time.perf_counter() - run_start
            write_live(
                _noop_progress_line(
                    elapsed,
                    duration,
                    f"NOOP storm {active_now}/{storm_pool} sent={cs} ok={co} err={ce}",
                )
            )
        time.sleep(0.1)
    stop_event.set()
    if early_exit_no_conns:
        # Unblock any recv() still sitting on a BYE'd socket, then leave.
        for imap, _ in connections:
            _noop2_drop_conn(imap)
        join_s = 2.0
    else:
        join_s = min(5.0, timeout_seconds + 2.0)
    for t in threads:
        t.join(timeout=join_s)
    run_duration = time.perf_counter() - run_start
    clear_live()

    for imap, _ in connections:
        _noop2_drop_conn(imap)

    min_rt = min(agg_rtts) if agg_rtts else None
    max_rt = max(agg_rtts) if agg_rtts else None
    avg_rt = (sum(agg_rtts) / len(agg_rtts)) if agg_rtts else None
    error_rate_pct = (100.0 * agg_err / agg_sent) if agg_sent else 0.0
    with results_lock:
        active_end = max(active_count, 0)
        terminated_sorted = tuple(sorted(terminated_info, key=lambda t: t[0]))
    disconnected_during = max(storm_pool - active_end, 0)

    e.debug(
        f"NOOP2 summary: established={established}/{max_connections} "
        f"(err={est_err}, disc={est_disc}, timeout={est_timeout}, reaped={reaped}), "
        f"storm_pool={storm_pool}, active_end={active_end}, "
        f"dropped_during_test={disconnected_during}, "
        f"early_exit={early_exit_no_conns}, duration={run_duration:.1f}s, "
        f"sent={agg_sent}, ok={agg_ok}, error={agg_err} ({error_rate_pct:.1f}%), "
        f"avg_rt={avg_rt}."
    )

    return _noop2_make_count_result(e, 
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

def test_noop_conn_count_preauth(e) -> NoopConnectionCountResult:
    """NOOP2: How many pre-auth connections can be maintained with NOOP."""
    max_connections = noop2_count_from_args(e.args, NOOP2_DEFAULT_CONNECTIONS)
    duration, delay = _noop1_duration_delay(e, 
        SMTP_NOOP_PREAUTH_CONN_TEST_SECONDS,
        SMTP_NOOP_PREAUTH_CONN_INTERVAL_SECONDS,
    )

    def opener(_idx: int):
        smtp = _smtp_noop_open(e)
        smtp.sock.settimeout(SMTP_NOOP_PREAUTH_CONN_TIMEOUT_SECONDS)
        return smtp

    return _noop2_conn_count_test(e, 
        opener=opener,
        authenticated=False,
        max_connections=max_connections,
        duration=duration,
        delay=delay,
        timeout_seconds=SMTP_NOOP_PREAUTH_CONN_TIMEOUT_SECONDS,
        closer=lambda conn: _smtp_noop_close(conn),
        tag_prefix="b",
    )

__MODULELABEL__ = "NOOP connection count"
__MODULECODE__ = "NOOP2"
__ORDER__ = 86


def _flush_ctx(ctx) -> None:
    if getattr(ctx, "json", False):
        return
    lock = getattr(ctx, "print_lock", None)
    if lock is None:
        return
    chunk = lock.get_output_string()
    if chunk:
        import sys
        sys.stdout.write(chunk)
        sys.stdout.flush()
        lock.output_string = ""


def _emit_noop2_result(ctx, result) -> None:
    from ..utils.results import (
        NOOP2_AVG_TIME_OK_MAX_SECONDS,
        NOOP2_ERROR_RATE_OK_MAX_PCT,
        noop1_rt_display,
    )

    verbose = bool(getattr(ctx.args, "debug", False))
    if result.min_rt_seconds is not None:
        min_d = noop1_rt_display(result.min_rt_seconds)
        max_d = noop1_rt_display(result.max_rt_seconds)
        avg_d = noop1_rt_display(result.avg_rt_seconds)
        if (result.avg_rt_seconds or 0) > NOOP2_AVG_TIME_OK_MAX_SECONDS:
            ctx.out(
                f"Time between two commands ({min_d} - {max_d}, avg {avg_d}) "
                f"— over {NOOP2_AVG_TIME_OK_MAX_SECONDS:.0f}s avg under load",
                "VULN",
                indent=4,
            )
        else:
            ctx.out(
                f"Time between two commands ({min_d} - {max_d}, avg {avg_d})",
                "NOTVULN",
                indent=4,
            )
    else:
        ctx.out(
            f"Time between two commands: no successful replies "
            f"({result.total_noops_sent} sent)",
            "VULN",
            indent=4,
        )

    err_rate = result.error_rate_pct
    if err_rate <= NOOP2_ERROR_RATE_OK_MAX_PCT:
        ctx.out(f"Error rate: {err_rate:.0f}%", "NOTVULN", indent=4)
    else:
        ctx.out(
            f"Error rate: {err_rate:.0f}% (over {NOOP2_ERROR_RATE_OK_MAX_PCT:.0f}%)",
            "VULN",
            indent=4,
        )

    storm_base = result.storm_pool_connections or result.connections_established
    disconnected = result.early_disconnect_count
    if storm_base > 0 and disconnected > 0:
        pct = 100.0 * disconnected / storm_base
        ctx.out(
            f"Disconnected connections during test: {disconnected} from {storm_base} ({pct:.0f}%)",
            "TITLE",
            indent=4,
        )
        if verbose:
            for idx, reason, detail in result.terminated_connections:
                ctx.out(
                    get_colored_text(f"Connection #{idx} terminated — {reason} ({detail})", "ADDITIONS"),
                    "TEXT",
                    indent=8,
                )
    _flush_ctx(ctx)


def _maybe_add_conn_limit_vuln(ctx, result, vuln_code: str, phase: str) -> None:
    kind, _ = conn_limit_count_verdict(
        result.connections_established, result.max_connections_attempted,
    )
    if kind != "VULN":
        return
    ctx.report.add_vulnerability(
        vuln_code=vuln_code,
        vuln_request=(
            f"{phase} NOOP connection count "
            f"({result.connections_established}/{result.max_connections_attempted})"
        ),
    )


def run(ctx):
    e = eng(ctx)

    from ..utils.results import VULNS

    try:
        result_preauth = test_noop_conn_count_preauth(e)
    except Exception as ex:
        ctx.out(f"Test failed: {ex}", "ERROR", indent=4)
        result_preauth = None

    if result_preauth and not result_preauth.error_message:
        e.results.noop_conn_count_preauth = result_preauth
        if result_preauth.connections_established > 0:
            _emit_noop2_result(ctx, result_preauth)
            _maybe_add_conn_limit_vuln(ctx, result_preauth, VULNS.NoopConnCountPreauth.value, "SMTP")
    elif result_preauth:
        ctx.out(f"Test error: {result_preauth.error_message}", "ERROR", indent=4)
