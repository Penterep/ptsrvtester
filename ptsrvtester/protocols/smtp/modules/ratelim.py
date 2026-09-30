"""RATELIM — simultaneous connection rate limiting."""
import ipaddress, queue, shutil, smtplib, socket, ssl, statistics, sys, threading, time

from ..._base import Out
from ..utils.ptprinthelper import get_colored_text

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "Rate limiting"
__MODULECODE__ = "RATELIM"
__ORDER__ = 200


def rate_limit_test(e) -> RateLimitResult:
    """Rate limiting test – parallel connection flood with two timeout probes.

        Flow:
          1. Connection A: connect + read 220 banner only (no EHLO). Start a watcher
             thread that waits for the server to close the idle banner-only session and
             records the elapsed "Initial response timeout".
          2. Connection B: connect + EHLO. Watcher thread records the "Idle timeout".
          3. Ramp-up: keep opening additional banner-only connections (sequential,
             small delay) until the server refuses (ban) or the attempt budget is hit.
          4. Ban-duration probe (only if banned): retry a new connection every 5 s
             until one is accepted (or the 5 min cap is hit).
          5. Wait for A and B watchers (or their 5 min caps) and emit verdicts.

        A and B run concurrently with steps 3–4; their results are reported as soon
        as they are available (or after the ban-duration step, whichever is later).
        """
    _show_progress = not e.args.json
    max_attempts = getattr(e.args, 'rate_limit', None) or RATE_LIMIT_DEFAULT_ATTEMPTS
    return _rate_limit_test_impl(e, _show_progress, max_attempts)


def _rate_limit_test_impl(e, _show_progress: bool, max_attempts: int) -> RateLimitResult:
    MAX_TIMEOUT = RATE_LIMIT_TIMEOUT_CAP_SECONDS
    MAX_BAN_WAIT = RATE_LIMIT_TIMEOUT_CAP_SECONDS
    RETRY_INTERVAL = 5
    PHASE1_DELAY = 0.15
    _print_lock = threading.Lock()
    e.ptdebug('Rate limiting test', title=True)
    e.ptdebug(f'Target {e.args.target.ip}:{e.args.target.port} — up to {max_attempts} parallel sessions (ramp {PHASE1_DELAY}s), ban duration probe max {MAX_BAN_WAIT}s, banner/idle timeout cap {MAX_TIMEOUT}s.')

    live_open = False

    def _write_live(label: str, value: str) -> None:
        nonlocal live_open
        line = f'    {label} {value}'
        with _print_lock:
            sys.stdout.write(f'\033[2K\r{line}')
            sys.stdout.flush()
            live_open = True

    def _finalize_line(label: str, value: str) -> None:
        nonlocal live_open
        line = f'    {label} {value}'
        with _print_lock:
            sys.stdout.write(f'\033[2K\r{line}\n')
            sys.stdout.flush()
            live_open = False

    def _clear_live() -> None:
        nonlocal live_open
        if not live_open:
            return
        with _print_lock:
            sys.stdout.write('\033[2K\r')
            sys.stdout.flush()
            live_open = False

    def _fmt_mmss(seconds: float) -> str:
        return f'{int(seconds // 60):02d}:{int(seconds % 60):02d}'

    def _print_verdict(is_vuln: bool, text: str) -> None:
        e._ptprint_raw(text, bullet_type='VULN' if is_vuln else 'NOTVULN', condition=not e.use_json, indent=8)

    def _print_info(text: str) -> None:
        e._ptprint_raw(text, bullet_type='TITLE', condition=not e.use_json, indent=8)

    def _watch_disconnect(smtp, start_time: float, cap_seconds: float, result_cell: list, stop_event: threading.Event) -> None:
        sock = getattr(smtp, 'sock', None)
        if sock is None:
            return
        try:
            sock.settimeout(1.0)
        except Exception:
            pass
        while not stop_event.is_set():
            elapsed = time.perf_counter() - start_time
            if elapsed >= cap_seconds:
                if not result_cell:
                    result_cell.append((cap_seconds, True))
                return
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            except Exception:
                if not result_cell and (not stop_event.is_set()):
                    result_cell.append((time.perf_counter() - start_time, False))
                return
            if not result_cell and (not stop_event.is_set()):
                result_cell.append((time.perf_counter() - start_time, False))
            return
    connections: list = []
    _first_error: list[str | None] = [None]
    watcher_stop = threading.Event()
    a_start_time: float | None = None
    b_start_time: float | None = None
    a_result: list = []
    b_result: list = []
    if _show_progress:
        _write_live('Connected:', '0')
    try:
        smtp_a = e._connect_silent(send_ehlo=False)
        a_start_time = time.perf_counter()
        connections.append(smtp_a)
        threading.Thread(target=_watch_disconnect, args=(smtp_a, a_start_time, MAX_TIMEOUT, a_result, watcher_stop), daemon=True).start()
        e.ptdebug('Session A (banner-only, no EHLO): TCP open after 220; watcher thread measures idle disconnect / initial-response timeout.', Out.INFO)
        if _show_progress:
            _write_live('Connected:', str(len(connections)))
    except Exception as exc:
        e.ptdebug(f'Session A (banner-only): connect failed — {exc}', Out.INFO)
        _first_error[0] = str(exc)
    time.sleep(PHASE1_DELAY)
    try:
        smtp_b = e._connect_silent(send_ehlo=True)
        b_start_time = time.perf_counter()
        connections.append(smtp_b)
        threading.Thread(target=_watch_disconnect, args=(smtp_b, b_start_time, MAX_TIMEOUT, b_result, watcher_stop), daemon=True).start()
        e.ptdebug('Session B (banner + EHLO): established; watcher thread measures idle timeout after EHLO.', Out.INFO)
        if _show_progress:
            _write_live('Connected:', str(len(connections)))
    except Exception as exc:
        e.ptdebug(f'Session B (EHLO): connect failed — {exc}', Out.INFO)
        if _first_error[0] is None:
            _first_error[0] = str(exc)
    if not connections:
        if _show_progress:
            _finalize_line('Connected:', '0')
        raise TestFailedError(_first_error[0] or 'Could not establish any connection')
    banned = False
    remaining = max_attempts - len(connections)
    for _ in range(max(remaining, 0)):
        time.sleep(PHASE1_DELAY)
        try:
            smtp_extra = e._connect_silent(send_ehlo=False)
        except Exception as exc:
            e.ptdebug(f'Ramp-up: next banner-only connection refused or failed — {exc}', Out.INFO)
            if _first_error[0] is None:
                _first_error[0] = str(exc)
            banned = True
            break
        connections.append(smtp_extra)
        e.ptdebug(f'Ramp-up [{len(connections)}/{max_attempts}]: banner-only session established.', Out.INFO)
        if _show_progress:
            _write_live('Connected:', str(len(connections)))
    connected = len(connections)
    if _show_progress:
        _finalize_line('Connected:', str(connected))
    e.ptdebug(f'Ramp-up: {connected}/{max_attempts} connections established.')
    if banned:
        e.ptdebug(f'Ramp-up stopped: {_first_error[0]}')
    if banned and connected >= RATE_LIMIT_CONN_VULN_THRESHOLD:
        _print_info(f'You are banned when {connected} threads was connected')
    elif not banned:
        e._ptprint_raw(f'No blocking occurred despite a large number of established connections ({connected} connections are active)', bullet_type='VULN', condition=not e.use_json, indent=8)
    if connected >= RATE_LIMIT_CONN_VULN_THRESHOLD:
        _print_verdict(True, f'More then {RATE_LIMIT_CONN_VULN_THRESHOLD} simultaneous SMTP connections from one IP accepted is too much')
    elif banned:
        _print_verdict(False, f'You are banned when {connected} threads was connected')
    ban_duration_seconds: float | None = None
    ban_duration_exceeded = False
    ban_duration_probe_ran = False
    if banned:
        ban_duration_probe_ran = True
        start_rl = time.perf_counter()
        _rl_stop = threading.Event()
        e.ptdebug(f'Ban duration probe: retry every {RETRY_INTERVAL}s until reconnect or {MAX_BAN_WAIT}s cap.', Out.INFO)
        if _show_progress:
            _write_live('Ban duration:', '00:00')

            def _rl_ticker() -> None:
                while not _rl_stop.wait(0.5):
                    elapsed = time.perf_counter() - start_rl
                    _write_live('Ban duration:', _fmt_mmss(elapsed))
            threading.Thread(target=_rl_ticker, daemon=True).start()
        _ban_try = 0
        while True:
            elapsed = time.perf_counter() - start_rl
            if elapsed >= MAX_BAN_WAIT:
                ban_duration_exceeded = True
                ban_duration_seconds = elapsed
                break
            try:
                probe = e._connect_silent(send_ehlo=False)
                ban_duration_seconds = time.perf_counter() - start_rl
                e.ptdebug(f'Ban probe: reconnect succeeded after {ban_duration_seconds:.2f}s (attempt #{_ban_try + 1}).', Out.INFO)
                try:
                    probe.close()
                except Exception:
                    pass
                break
            except Exception as exc:
                _ban_try += 1
                e.ptdebug(f'Ban probe attempt #{_ban_try}: connect failed — {exc}', Out.INFO)
            wait_end = time.perf_counter() + RETRY_INTERVAL
            while time.perf_counter() < wait_end:
                time.sleep(0.2)
        _rl_stop.set()
        if _show_progress:
            _finalize_line('Ban duration:', _rate_limit_duration_display(ban_duration_seconds, ban_duration_exceeded))
        if ban_duration_exceeded:
            e.ptdebug(f'Ban duration: no new connection within {MAX_BAN_WAIT}s (cap).')
            _print_verdict(False, 'Ban is bigger then 30s')
        else:
            if ban_duration_seconds is not None:
                e.ptdebug(f'Ban duration summary: reconnect accepted after {ban_duration_seconds:.2f}s.', Out.INFO)
            if ban_duration_seconds is not None and ban_duration_seconds < RATE_LIMIT_BAN_MIN_SECONDS:
                _print_verdict(True, 'Ban duration is too low')
            else:
                _print_verdict(False, 'Ban is bigger then 30s')

    def _await_and_report(start_time: float | None, result_cell: list, label: str, cap: float, threshold: float, bad_msg: str, ok_msg: str) -> tuple[float | None, bool]:
        if start_time is None:
            if _show_progress:
                _finalize_line(label, 'N/A')
            return (None, False)
        deadline = start_time + cap + 2.0
        if _show_progress and (not result_cell):
            _write_live(label, _fmt_mmss(time.perf_counter() - start_time))
            live_stop = threading.Event()

            def _tick() -> None:
                while not live_stop.wait(0.5):
                    if result_cell:
                        return
                    _write_live(label, _fmt_mmss(time.perf_counter() - start_time))
            threading.Thread(target=_tick, daemon=True).start()
            while not result_cell and time.perf_counter() < deadline:
                time.sleep(0.2)
            live_stop.set()
        else:
            while not result_cell and time.perf_counter() < deadline:
                time.sleep(0.2)
        if not result_cell:
            result_cell.append((cap, True))
        elapsed, exceeded = result_cell[0]
        disp = _rate_limit_duration_display(elapsed, exceeded)
        e.ptdebug(f'{label.strip()} measured {disp}' + (' (hit hard cap)' if exceeded else ' (peer closed or replied)'), Out.INFO)
        if _show_progress:
            _finalize_line(label, disp)
        if exceeded or elapsed > threshold:
            _print_verdict(True, bad_msg)
        else:
            _print_verdict(False, ok_msg)
        return (elapsed, exceeded)
    initial_seconds, initial_exceeded = _await_and_report(a_start_time, a_result, 'Initial response timeout (without EHLO):', MAX_TIMEOUT, RATE_LIMIT_INITIAL_TIMEOUT_MAX_SECONDS, f'Timeout is too long (more then {RATE_LIMIT_INITIAL_TIMEOUT_MAX_SECONDS}s)', f'Timeout is lower then {RATE_LIMIT_INITIAL_TIMEOUT_MAX_SECONDS}s')
    idle_seconds, idle_exceeded = _await_and_report(b_start_time, b_result, 'Idle timeout (after EHLO):', MAX_TIMEOUT, RATE_LIMIT_IDLE_TIMEOUT_MAX_SECONDS, f'Timeout is too long (more then {RATE_LIMIT_IDLE_TIMEOUT_MAX_SECONDS}s)', f'Timeout is lower then {RATE_LIMIT_IDLE_TIMEOUT_MAX_SECONDS}s')
    watcher_stop.set()
    for conn in connections:
        try:
            conn.close()
        except Exception:
            pass
    e.ptdebug(f'Summary: connected={connected}, banned={banned}, ban_duration_seconds={ban_duration_seconds!s}, initial_timeout_seconds={initial_seconds!s}, idle_timeout_seconds={idle_seconds!s}.')
    _clear_live()
    return RateLimitResult(connected=connected, max_attempts=max_attempts, banned=banned, ban_duration_probe_ran=ban_duration_probe_ran, ban_duration_seconds=ban_duration_seconds, ban_duration_exceeded=ban_duration_exceeded, initial_timeout_seconds=initial_seconds, initial_timeout_exceeded=initial_exceeded, idle_timeout_seconds=idle_seconds, idle_timeout_exceeded=idle_exceeded)


def _stream_rate_limit_result(e) -> None:
    if (err := e.results.rate_limit_error) is not None:
        e._ptprint_raw(f'Rate limiting test failed: {err}', bullet_type='VULN', condition=not e.use_json, indent=4)


def run(ctx):
    e = eng(ctx)
    try:
        e.results.rate_limit = rate_limit_test(e)
    except Exception as ex:
        e.results.rate_limit_error = str(ex)
        # Drop a live \\r progress row so the error starts on its own line.
        sys.stdout.write('\033[2K\r')
        sys.stdout.flush()
        ctx.out(f"RATELIM failed: {ex}", "ERROR", indent=4)
        return
    _stream_rate_limit_result(e)
