"""Protocol-agnostic connection rate-limiting probe engine.

This module contains **no** protocol packet code.  It drives a caller-supplied
:class:`ConnectionAdapter` (see :mod:`.connection`) that knows how to open one
connection to the target far enough to tell "the service accepted me" from "the
service refused/limited me", and how to keep that connection open (a held
handle) so we can watch it.

It answers four questions a pentester asks about connection rate limiting:

1. **Is rate limiting deployed?** — burst a batch of connect+close attempts and
   see whether the server starts refusing, then whether it recovers after a
   cooldown (a repeatable-failure-then-recovery pattern is the signal).
2. **How many concurrent connections can I hold?** — open connections and keep
   them open, counting how many the server lets live simultaneously.
3. **How fast can I connect and disconnect?** — measure achievable
   connect+teardown throughput (connections per second) under the burst.
4. **How long does an idle connection survive?** — open one connection, send
   nothing, and time how long until the server tears it down.

Everything is bounded: hard caps protect both the target and the scanner from
descriptor/thread exhaustion, verdicts are conservative (a negative result only
means "not observed within the configured sample"), and every held handle is
closed in a ``finally`` block.
"""

from __future__ import annotations

import socket
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Protocol

MAX_COUNT = 200
MAX_CONCURRENCY = 50
MAX_TIMEOUT_SECONDS = 60.0
MAX_HOLD_SECONDS = 60.0
MAX_COOLDOWN_SECONDS = 120.0
MAX_IDLE_SECONDS = 600.0
MAX_ERROR_LENGTH = 300


class ProbeOutcome(str, Enum):
    """Outcome of one connection attempt as classified by the adapter/engine."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    RESET = "reset"
    TRANSPORT_ERROR = "transport"
    INTERNAL_ERROR = "internal"

    @property
    def is_failure(self) -> bool:
        return self is not ProbeOutcome.ACCEPTED


@dataclass(frozen=True)
class ProbeResult:
    outcome: ProbeOutcome
    duration_ms: Optional[float] = None
    error: Optional[str] = None

    @property
    def accepted(self) -> bool:
        return self.outcome is ProbeOutcome.ACCEPTED


class ConnectionHandle(Protocol):
    """A live connection the engine can watch and must be able to close."""

    def close(self) -> object: ...

    def is_alive(self) -> Optional[bool]:
        """``True`` still open, ``False`` peer closed, ``None`` unknown."""


class ConnectionAdapter(Protocol):
    """What each protocol supplies so the engine can pressure-test it."""

    def probe(self) -> ProbeResult:
        """Open one connection, classify it, and close it."""

    def open_held(self) -> tuple[ProbeResult, Optional[ConnectionHandle]]:
        """Open one connection and return it still open (or ``None`` on failure)."""


def _clamp_int(value: object, lo: int, hi: int, default: int) -> int:
    try:
        v = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def _clamp_float(value: object, lo: float, hi: float, default: float) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    if v != v:  # NaN
        return default
    return max(lo, min(hi, v))


@dataclass(frozen=True)
class RateLimitConfig:
    """Bounded run configuration.  Values are clamped into the safe caps."""

    count: int = 30
    concurrency: int = 10
    timeout_seconds: float = 5.0
    hold_seconds: float = 2.0
    cooldown_seconds: float = 3.0
    idle_max_seconds: float = 30.0
    idle_poll_seconds: float = 1.0
    baseline_probes: int = 3
    recovery_probes: int = 3
    failure_threshold: int = 2

    @classmethod
    def from_args(cls, args) -> "RateLimitConfig":
        """Build a clamped config from an argparse namespace (missing = default)."""
        g = lambda name, d: getattr(args, name, d)
        return cls(
            count=_clamp_int(g("rate_count", 30), 5, MAX_COUNT, 30),
            concurrency=_clamp_int(g("rate_concurrency", 10), 1, MAX_CONCURRENCY, 10),
            timeout_seconds=_clamp_float(g("rate_timeout", 5.0), 0.5, MAX_TIMEOUT_SECONDS, 5.0),
            hold_seconds=_clamp_float(g("rate_hold_seconds", 2.0), 0.0, MAX_HOLD_SECONDS, 2.0),
            cooldown_seconds=_clamp_float(g("rate_cooldown_seconds", 3.0), 0.0, MAX_COOLDOWN_SECONDS, 3.0),
            idle_max_seconds=_clamp_float(g("rate_idle_max", 30.0), 0.0, MAX_IDLE_SECONDS, 30.0),
            idle_poll_seconds=_clamp_float(g("rate_idle_poll", 1.0), 0.2, 30.0, 1.0),
        )


class Verdict(str, Enum):
    LIMITING_OBSERVED = "limiting_observed"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"
    IMPACT_PERSISTED = "impact_persisted"
    ERROR = "error"


@dataclass(frozen=True)
class DetectionResult:
    verdict: Verdict
    deployed: Optional[bool]
    baseline_ok: bool
    baseline_median_ms: Optional[float]
    burst_attempted: int
    burst_accepted: int
    recovery_attempted: int
    recovery_accepted: int
    notes: tuple[str, ...] = ()

    @property
    def burst_failures(self) -> int:
        return self.burst_attempted - self.burst_accepted


@dataclass(frozen=True)
class ConcurrencyResult:
    requested: int
    accepted: int
    alive_after_hold: int
    capped: bool
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConnectRateResult:
    attempted: int
    accepted: int
    elapsed_seconds: float
    rate_per_second: Optional[float]
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class IdleTimeoutResult:
    measured: bool
    seconds: Optional[float]
    still_open: bool
    limit_seconds: float
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RateLimitReport:
    config: RateLimitConfig
    detection: DetectionResult
    concurrency: Optional[ConcurrencyResult] = None
    connect_rate: Optional[ConnectRateResult] = None
    idle_timeout: Optional[IdleTimeoutResult] = None
    aborted_reason: Optional[str] = None


def _error_text(error: object) -> str:
    message = str(error).strip() or error.__class__.__name__
    if len(message) > MAX_ERROR_LENGTH:
        message = message[: MAX_ERROR_LENGTH - 3] + "..."
    return message


def classify_exception(exc: BaseException) -> ProbeOutcome:
    """Map a raised exception to a :class:`ProbeOutcome` (shared by adapters)."""
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return ProbeOutcome.TIMEOUT
    if isinstance(exc, ConnectionRefusedError):
        return ProbeOutcome.REFUSED
    if isinstance(exc, ConnectionResetError):
        return ProbeOutcome.RESET
    if isinstance(exc, OSError):
        return ProbeOutcome.TRANSPORT_ERROR
    return ProbeOutcome.INTERNAL_ERROR


class RateLimitTester:
    """Run the bounded connection-pressure scenarios through an adapter."""

    def __init__(
        self,
        adapter: ConnectionAdapter,
        config: Optional[RateLimitConfig] = None,
        *,
        log: Optional[Callable[[str], None]] = None,
        progress: Optional[Callable[[str], None]] = None,
        clock: Callable[[], float] = time.perf_counter,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.adapter = adapter
        self.config = config or RateLimitConfig()
        self._log = log or (lambda _msg: None)
        self._progress = progress or (lambda _phase: None)
        self._clock = clock
        self._sleep = sleeper

    def _phase(self, label: str) -> None:
        try:
            self._progress(label)
        except Exception:
            pass


    def _probe(self) -> ProbeResult:
        started = self._clock()
        try:
            result = self.adapter.probe()
            if not isinstance(result, ProbeResult):
                raise TypeError("adapter.probe() must return ProbeResult")
        except Exception as exc:
            return ProbeResult(
                classify_exception(exc),
                duration_ms=max(0.0, (self._clock() - started) * 1000.0),
                error=_error_text(exc),
            )
        if result.duration_ms is None:
            result = ProbeResult(
                result.outcome,
                duration_ms=max(0.0, (self._clock() - started) * 1000.0),
                error=result.error,
            )
        return result

    def _open(self) -> tuple[ProbeResult, Optional[ConnectionHandle]]:
        try:
            result, handle = self.adapter.open_held()
            if not isinstance(result, ProbeResult):
                raise TypeError("adapter.open_held() must return (ProbeResult, handle)")
        except Exception as exc:
            return ProbeResult(classify_exception(exc), error=_error_text(exc)), None
        if result.accepted and handle is None:
            return ProbeResult(
                ProbeOutcome.INTERNAL_ERROR,
                error="accepted open returned no handle",
            ), None
        return result, handle


    def _serial(self, n: int) -> list[ProbeResult]:
        return [self._probe() for _ in range(max(0, n))]

    def _concurrent_probes(self, n: int) -> tuple[list[ProbeResult], float]:
        """Fire ``n`` connect+close probes, at most ``concurrency`` at a time."""
        n = max(0, n)
        if n == 0:
            return [], 0.0
        workers = max(1, min(self.config.concurrency, n))
        started = self._clock()
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ratelimit") as ex:
            results = list(ex.map(lambda _i: self._probe(), range(n)))
        elapsed = max(0.0, self._clock() - started)
        return results, elapsed

    def _open_many(self, n: int) -> tuple[list[ProbeResult], list[ConnectionHandle]]:
        """Open up to ``n`` held connections concurrently; return probes + handles."""
        n = max(0, n)
        if n == 0:
            return [], []
        workers = max(1, min(self.config.concurrency, n))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ratelimit-hold") as ex:
            opened = list(ex.map(lambda _i: self._open(), range(n)))
        probes = [p for p, _ in opened]
        handles = [h for _, h in opened if h is not None]
        return probes, handles

    @staticmethod
    def _median_ms(results: list[ProbeResult]) -> Optional[float]:
        durations = [r.duration_ms for r in results if r.accepted and r.duration_ms is not None]
        return statistics.median(durations) if durations else None

    @staticmethod
    def _accepted(results: list[ProbeResult]) -> int:
        return sum(1 for r in results if r.accepted)


    def run(self) -> RateLimitReport:
        cfg = self.config

        self._log(f"baseline: {cfg.baseline_probes} probe(s)")
        self._phase("measuring baseline")
        baseline = self._serial(cfg.baseline_probes)
        baseline_accepted = self._accepted(baseline)
        baseline_ok = baseline_accepted >= max(1, cfg.baseline_probes - 1)
        baseline_median = self._median_ms(baseline)
        if not baseline_ok:
            reason = "baseline could not establish a healthy connection to the target"
            self._log(reason)
            return RateLimitReport(
                config=cfg,
                detection=DetectionResult(
                    verdict=Verdict.INCONCLUSIVE,
                    deployed=None,
                    baseline_ok=False,
                    baseline_median_ms=baseline_median,
                    burst_attempted=0,
                    burst_accepted=0,
                    recovery_attempted=0,
                    recovery_accepted=0,
                    notes=(reason,),
                ),
                aborted_reason=reason,
            )

        self._log(f"burst: {cfg.count} connect/close, concurrency {cfg.concurrency}")
        self._phase(f"connect/disconnect burst ({cfg.count})")
        burst, elapsed = self._concurrent_probes(cfg.count)
        burst_accepted = self._accepted(burst)
        internal = any(r.outcome is ProbeOutcome.INTERNAL_ERROR for r in burst)
        connect_rate = ConnectRateResult(
            attempted=len(burst),
            accepted=burst_accepted,
            elapsed_seconds=elapsed,
            rate_per_second=(burst_accepted / elapsed if elapsed > 0 else None),
            notes=(),
        )

        concurrency = self._run_concurrency()

        if cfg.cooldown_seconds > 0:
            self._log(f"cooldown: {cfg.cooldown_seconds:g}s")
            self._phase("cooldown")
            try:
                self._sleep(cfg.cooldown_seconds)
            except Exception:
                pass

        self._log(f"recovery: {cfg.recovery_probes} probe(s)")
        self._phase("checking recovery")
        recovery = self._serial(cfg.recovery_probes)
        recovery_accepted = self._accepted(recovery)
        recovery_ok = recovery_accepted >= max(1, cfg.recovery_probes - 1)

        idle = self._run_idle_timeout()

        detection = self._assess(
            baseline_ok=baseline_ok,
            baseline_median=baseline_median,
            burst=burst,
            burst_accepted=burst_accepted,
            recovery=recovery,
            recovery_accepted=recovery_accepted,
            recovery_ok=recovery_ok,
            concurrency=concurrency,
            internal=internal,
        )
        return RateLimitReport(
            config=cfg,
            detection=detection,
            concurrency=concurrency,
            connect_rate=connect_rate,
            idle_timeout=idle,
        )

    def _run_concurrency(self) -> ConcurrencyResult:
        cfg = self.config
        self._log(f"concurrency: open up to {cfg.count} held connections")
        self._phase(f"holding up to {cfg.count} concurrent connections")
        probes, handles = self._open_many(cfg.count)
        accepted = self._accepted(probes)
        alive_after_hold = 0
        try:
            if handles and cfg.hold_seconds > 0:
                try:
                    self._sleep(cfg.hold_seconds)
                except Exception:
                    pass
            for h in handles:
                check = getattr(h, "is_alive", None)
                if not callable(check):
                    continue
                try:
                    if check() is True:
                        alive_after_hold += 1
                except Exception:
                    pass
        finally:
            for h in handles:
                try:
                    h.close()
                except Exception:
                    pass
        capped = accepted < cfg.count and accepted > 0
        notes: tuple[str, ...] = ()
        if accepted == 0:
            notes = ("no connection could be held open",)
        return ConcurrencyResult(
            requested=cfg.count,
            accepted=accepted,
            alive_after_hold=alive_after_hold,
            capped=capped,
            notes=notes,
        )

    def _run_idle_timeout(self) -> IdleTimeoutResult:
        cfg = self.config
        if cfg.idle_max_seconds <= 0:
            return IdleTimeoutResult(
                measured=False, seconds=None, still_open=False,
                limit_seconds=0.0, notes=("idle-timeout check disabled",),
            )
        self._log(f"idle: hold one connection up to {cfg.idle_max_seconds:g}s")
        self._phase("waiting for idle connection to drop")
        probe, handle = self._open()
        if not probe.accepted or handle is None:
            return IdleTimeoutResult(
                measured=False, seconds=None, still_open=False,
                limit_seconds=cfg.idle_max_seconds,
                notes=("could not open a connection to measure idle timeout",),
            )
        check = getattr(handle, "is_alive", None)
        started = self._clock()
        try:
            if not callable(check):
                return IdleTimeoutResult(
                    measured=False, seconds=None, still_open=True,
                    limit_seconds=cfg.idle_max_seconds,
                    notes=("adapter handle cannot report liveness",),
                )
            deadline = started + cfg.idle_max_seconds
            while self._clock() < deadline:
                try:
                    alive = check()
                except Exception:
                    alive = False
                if alive is False:
                    elapsed = max(0.0, self._clock() - started)
                    return IdleTimeoutResult(
                        measured=True, seconds=elapsed, still_open=False,
                        limit_seconds=cfg.idle_max_seconds,
                    )
                remaining = deadline - self._clock()
                if remaining <= 0:
                    break
                try:
                    self._sleep(min(cfg.idle_poll_seconds, remaining))
                except Exception:
                    break
            return IdleTimeoutResult(
                measured=True, seconds=None, still_open=True,
                limit_seconds=cfg.idle_max_seconds,
                notes=(f"connection still open after {cfg.idle_max_seconds:g}s",),
            )
        finally:
            try:
                handle.close()
            except Exception:
                pass

    def _assess(
        self,
        *,
        baseline_ok: bool,
        baseline_median: Optional[float],
        burst: list[ProbeResult],
        burst_accepted: int,
        recovery: list[ProbeResult],
        recovery_accepted: int,
        recovery_ok: bool,
        concurrency: ConcurrencyResult,
        internal: bool,
    ) -> DetectionResult:
        cfg = self.config
        notes: list[str] = []
        burst_failures = len(burst) - burst_accepted

        if internal:
            notes.append("internal probe errors occurred; results are unreliable")
            verdict, deployed = Verdict.ERROR, None
        elif not recovery_ok and recovery_accepted == 0:
            notes.append(
                "the target stopped answering after the burst and had not recovered "
                "after the cooldown — possible IP block or service impact"
            )
            verdict, deployed = Verdict.IMPACT_PERSISTED, True
        else:
            limiting = (
                burst_failures >= cfg.failure_threshold
                or concurrency.capped
            )
            if limiting and recovery_ok:
                if burst_failures >= cfg.failure_threshold:
                    notes.append(
                        f"{burst_failures}/{len(burst)} burst connections were refused "
                        "or dropped, and the service recovered after cooldown"
                    )
                if concurrency.capped:
                    notes.append(
                        f"only {concurrency.accepted}/{concurrency.requested} "
                        "connections could be held open at once"
                    )
                verdict, deployed = Verdict.LIMITING_OBSERVED, True
            elif limiting and not recovery_ok:
                notes.append("failures occurred during load and recovery was only partial")
                verdict, deployed = Verdict.INCONCLUSIVE, None
            else:
                notes.append(
                    "no connection limiting was observed within the configured sample"
                )
                verdict, deployed = Verdict.NOT_OBSERVED, False

        return DetectionResult(
            verdict=verdict,
            deployed=deployed,
            baseline_ok=baseline_ok,
            baseline_median_ms=baseline_median,
            burst_attempted=len(burst),
            burst_accepted=burst_accepted,
            recovery_attempted=len(recovery),
            recovery_accepted=recovery_accepted,
            notes=tuple(notes),
        )


__all__ = [
    "MAX_CONCURRENCY",
    "MAX_COUNT",
    "ConcurrencyResult",
    "ConnectRateResult",
    "ConnectionAdapter",
    "ConnectionHandle",
    "DetectionResult",
    "IdleTimeoutResult",
    "ProbeOutcome",
    "ProbeResult",
    "RateLimitConfig",
    "RateLimitReport",
    "RateLimitTester",
    "Verdict",
    "classify_exception",
]