"""RATELIMIT — cross-protocol connection rate-limiting test.

Discovered for every protocol (see ``_shared`` package docstring), so
``<protocol> -ts RATELIMIT <target>`` works the same way for SSH, FTP, LDAP,
DNS, SMB, … It answers four questions:

  1. Is rate limiting deployed?
  2. How many concurrent connections can I hold open?
  3. How fast can I connect and disconnect (connections/second)?
  4. How long does an idle connection survive before the server drops it?

By default it drives a bare-TCP adapter (enough to exercise the pre-auth
connection limiting most services enforce). A protocol can inject a
protocol-aware adapter as ``ctx.rate_limit_adapter`` for a sharper signal.
"""

import itertools
import sys
import threading
import time

from ptlibs.ptprinthelper import ptprint, clear_line

from ptsrvtester.protocols._shared.utils.connection import TcpConnectionAdapter
from ptsrvtester.protocols._shared.utils.rate_limit import (
    RateLimitConfig,
    RateLimitTester,
    Verdict,
)

__MODULELABEL__ = "Connection rate limiting"
__MODULECODE__ = "RATELIMIT"
__ORDER__ = 900
__RUN_IN_ALL__ = False


class _Progress:
    """Live spinner + elapsed counter written straight to the terminal.

    Same mechanism as SSH's DHEAT progress line: a self-updating ``\\r`` line
    (spinner + current phase + elapsed seconds) that is erased when the run
    finishes, before the buffered verdict/statistics are printed. The engine
    drives the phase text via the :meth:`set` callback.
    """

    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port
        self._phase = "starting…"
        self._start = time.time()
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def set(self, phase: str) -> None:
        with self._lock:
            self._phase = phase

    def _current(self) -> str:
        with self._lock:
            return self._phase

    def run(self) -> None:
        frames = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        sys.stdout.write("\033[?25l")  # hide cursor
        sys.stdout.flush()
        try:
            while not self._stop.is_set():
                elapsed = time.time() - self._start
                ptprint(
                    f"    {next(frames)} Connection rate limiting {self.ip}:{self.port} "
                    f"— {self._current()} ({elapsed:0.0f}s)",
                    "TEXT", end="\r", flush=True, clear_to_eol=True, colortext="TITLE",
                )
                time.sleep(0.1)
        finally:
            clear_line(end="\r")           # erase the temporary line
            sys.stdout.write("\033[?25h")  # restore cursor
            sys.stdout.flush()

    def stop(self) -> None:
        self._stop.set()


def _fmt_seconds(value):
    return "unknown" if value is None else f"{value:.1f}s"


def _fmt_ms(value):
    return "unknown" if value is None else f"{value:.0f} ms"


def run(ctx):
    args = ctx.args

    ip, port = ctx.target
    adapter = getattr(ctx, "rate_limit_adapter", None)
    if adapter is None:
        timeout = getattr(args, "rate_timeout", 5.0)
        adapter = TcpConnectionAdapter(ip, port, timeout_seconds=timeout)

    config = RateLimitConfig.from_args(args)
    ctx.debug(
        f"config: count={config.count} concurrency={config.concurrency} "
        f"timeout={config.timeout_seconds:g}s idle_max={config.idle_max_seconds:g}s"
    )

    show_progress = not getattr(ctx, "json", False) and sys.stdout.isatty()
    progress = None
    spinner = None
    if show_progress:
        progress = _Progress(ip, port)
        spinner = threading.Thread(target=progress.run, daemon=True)
        spinner.start()

    try:
        report = RateLimitTester(
            adapter, config,
            log=ctx.debug,
            progress=(progress.set if progress is not None else None),
        ).run()
    finally:
        if spinner is not None:
            progress.stop()
            spinner.join()

    _render_text(ctx, report)
    _render_json(ctx, report)


_VERDICT_CATEGORY = {
    Verdict.LIMITING_OBSERVED: "OK",
    Verdict.NOT_OBSERVED: "VULN",
    Verdict.INCONCLUSIVE: "WARNING",
    Verdict.IMPACT_PERSISTED: "WARNING",
    Verdict.ERROR: "ERROR",
}

_VERDICT_TEXT = {
    Verdict.LIMITING_OBSERVED: "Rate limiting: DEPLOYED (connection limiting observed)",
    Verdict.NOT_OBSERVED: "Rate limiting: NOT observed within the tested sample",
    Verdict.INCONCLUSIVE: "Rate limiting: inconclusive",
    Verdict.IMPACT_PERSISTED: "Rate limiting: target stopped answering (possible block/impact)",
    Verdict.ERROR: "Rate limiting: test error",
}


def _render_text(ctx, report):
    det = report.detection
    ctx.out(_VERDICT_TEXT[det.verdict], _VERDICT_CATEGORY[det.verdict], indent=4)

    if report.aborted_reason:
        for note in det.notes:
            ctx.out(note, "TEXT", indent=8)
        return

    if report.concurrency is not None:
        c = report.concurrency
        if c.accepted == 0:
            msg = f"Concurrent connections held: 0/{c.requested} (could not hold any open)"
            cat = "WARNING"
        elif c.capped:
            msg = f"Concurrent connections held: {c.accepted}/{c.requested} (server capped)"
            cat = "OK"
        else:
            msg = f"Concurrent connections held: {c.accepted}/{c.requested} (no cap seen)"
            cat = "TEXT"
        ctx.out(msg, cat, indent=4)
        if c.alive_after_hold and c.alive_after_hold != c.accepted:
            ctx.out(
                f"still alive after {report.config.hold_seconds:g}s hold: {c.alive_after_hold}",
                "TEXT", indent=8,
            )

    if report.connect_rate is not None:
        r = report.connect_rate
        rate = "unknown" if r.rate_per_second is None else f"{r.rate_per_second:.1f} conn/s"
        ctx.out(
            f"Connect/disconnect rate: {r.accepted}/{r.attempted} in "
            f"{r.elapsed_seconds:.2f}s ({rate})",
            "TEXT", indent=4,
        )

    if report.idle_timeout is not None:
        i = report.idle_timeout
        if i.measured and i.seconds is not None:
            ctx.out(f"Idle connection dropped after: {_fmt_seconds(i.seconds)}", "TEXT", indent=4)
        elif i.measured and i.still_open:
            ctx.out(
                f"Idle connection survived the full {_fmt_seconds(i.limit_seconds)} window "
                "(raise --rate-idle-max to probe further)",
                "TEXT", indent=4,
            )
        else:
            for note in i.notes:
                ctx.out(f"Idle timeout: {note}", "TEXT", indent=4)

    if det.baseline_median_ms is not None:
        ctx.debug(f"baseline median latency: {_fmt_ms(det.baseline_median_ms)}")
    for note in det.notes:
        ctx.out(note, "TEXT", indent=8)


def _render_json(ctx, report):
    if not getattr(ctx, "json", False):
        return
    try:
        det = report.detection
        cfg = report.config
        properties = {
            "rateLimitingDeployed": det.deployed,
            "verdict": det.verdict.value,
            "burstAttempted": det.burst_attempted,
            "burstAccepted": det.burst_accepted,
            "recoveryAttempted": det.recovery_attempted,
            "recoveryAccepted": det.recovery_accepted,
            "baselineMedianMs": det.baseline_median_ms,
            "config": {
                "count": cfg.count,
                "concurrency": cfg.concurrency,
                "timeoutSeconds": cfg.timeout_seconds,
                "holdSeconds": cfg.hold_seconds,
                "cooldownSeconds": cfg.cooldown_seconds,
                "idleMaxSeconds": cfg.idle_max_seconds,
            },
        }
        if report.concurrency is not None:
            properties["maxConcurrentObserved"] = report.concurrency.accepted
            properties["concurrentCapped"] = report.concurrency.capped
        if report.connect_rate is not None:
            properties["connectRatePerSecond"] = report.connect_rate.rate_per_second
        if report.idle_timeout is not None:
            i = report.idle_timeout
            properties["idleTimeoutSeconds"] = i.seconds
            properties["idleStillOpen"] = i.still_open
        if det.notes:
            properties["notes"] = list(det.notes)

        node = ctx.ptjsonlib.create_node_object(
            "connection-rate-limit", None, None, properties
        )
        ctx.ptjsonlib.add_node(node)
    except Exception as exc:
        ctx.debug(f"RATELIMIT JSON output skipped: {exc}")