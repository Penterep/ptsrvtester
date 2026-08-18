"""Safety-bounded core for active RDP connection limiting checks.

The module deliberately contains no RDP packet implementation.  Callers inject
callbacks which establish a connection far enough to receive and validate the
server's X.224 Connection Confirm PDU.  This keeps the load-control policy easy
to unit test while allowing :mod:`ptsrvtester.protocols.rdp.utils.engine` to
reuse its existing packet builder and parser.

Two scenarios are supported:

``completed``
    Establish X.224 negotiations concurrently and close each connection from
    inside the injected probe callback.

``held``
    Establish negotiated connections concurrently, retain their closeable
    handles, revalidate peer-side TCP liveness, run control probes, and close
    every returned handle in a ``finally`` block before checking recovery.

Verdicts are intentionally conservative.  A negative result means only that no
limiting was observed within the configured sample.  A limiting verdict needs
repeatable failures followed by a healthy recovery; a single failure is
reported as inconclusive.  Persistent recovery failures are surfaced
separately so a caller can stop all further active tests.
"""

from __future__ import annotations

import math
import socket
import statistics
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Protocol

MAX_CONNECTIONS = 200
MAX_CONCURRENCY = 50
MAX_PHASE_PROBES = 10
MAX_HOLD_SECONDS = 30.0
MAX_COOLDOWN_SECONDS = 60.0
MAX_SLOWDOWN_ABSOLUTE_MS = 60_000.0
MAX_ERROR_LENGTH = 500


class Scenario(str, Enum):
    COMPLETED = "completed"
    HELD = "held"


class ProbePhase(str, Enum):
    BASELINE = "baseline"
    LOAD = "load"
    CONTROL = "control"
    RECOVERY = "recovery"


class ProbeOutcome(str, Enum):
    """Outcome of one complete X.224 negotiation attempt."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    RESET = "reset"
    PROTOCOL_ERROR = "protocol_error"
    TRANSPORT_ERROR = "transport_error"
    INTERNAL_ERROR = "internal_error"


class RateLimitVerdict(str, Enum):
    LIMITING_OBSERVED = "limiting_observed"
    SLOWDOWN_OBSERVED = "slowdown_observed"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"
    IMPACT_PERSISTED = "impact_persisted"
    ERROR = "error"


class Closeable(Protocol):
    def close(self) -> object:
        """Release the connection handle."""


class LivenessCheckable(Closeable, Protocol):
    def is_alive(self) -> bool | None:
        """Return whether the peer still keeps the negotiated socket open.

        ``None`` means that liveness cannot be determined without consuming or
        otherwise changing the protocol stream.
        """


class SocketConnectionHandle:
    """Closeable TCP socket with a non-consuming peer-liveness snapshot."""

    __slots__ = ("_socket",)

    def __init__(self, sock: socket.socket) -> None:
        if not isinstance(sock, socket.socket):
            raise TypeError("sock must be a socket.socket")
        self._socket = sock

    def close(self) -> None:
        self._socket.close()

    def is_alive(self) -> bool | None:
        """Peek without blocking: idle means alive and EOF/error means closed.

        Pending bytes are reported as unknown.  A non-consuming peek cannot
        tell whether a FIN follows those bytes, so treating them as definitely
        alive would overstate the evidence.
        """

        try:
            previous_timeout = self._socket.gettimeout()
        except OSError:
            return False
        try:
            self._socket.setblocking(False)
            try:
                pending = self._socket.recv(1, socket.MSG_PEEK)
                return False if pending == b"" else None
            except (BlockingIOError, InterruptedError):
                return True
            except OSError:
                return False
        finally:
            try:
                self._socket.settimeout(previous_timeout)
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    scenario: Scenario
    phase: ProbePhase
    attempt: int

    def __post_init__(self) -> None:
        if isinstance(self.attempt, bool) or self.attempt < 1:
            raise ValueError("attempt must be a positive integer")


@dataclass(frozen=True, slots=True)
class ProbeResult:
    outcome: ProbeOutcome
    duration_ms: float | None = None
    selected_protocol: int | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, ProbeOutcome):
            raise TypeError("outcome must be ProbeOutcome")
        if self.duration_ms is not None:
            if (
                isinstance(self.duration_ms, bool)
                or not math.isfinite(self.duration_ms)
                or self.duration_ms < 0
            ):
                raise ValueError("duration_ms must be a finite non-negative number")

    @property
    def accepted(self) -> bool:
        return self.outcome is ProbeOutcome.ACCEPTED


@dataclass(frozen=True, slots=True)
class OpenConnectionResult:
    """Result returned by a held-connection factory.

    A successful negotiation must return a closeable handle.  A failed attempt
    may still return one; the runner tracks and closes it defensively.
    """

    probe: ProbeResult
    connection: Closeable | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.probe, ProbeResult):
            raise TypeError("probe must be ProbeResult")
        if self.connection is not None and not callable(
            getattr(self.connection, "close", None)
        ):
            raise TypeError("connection must provide close()")
        liveness_check = getattr(self.connection, "is_alive", None)
        if liveness_check is not None and not callable(liveness_check):
            raise TypeError("connection is_alive attribute must be callable")
        if self.probe.accepted and self.connection is None:
            raise ValueError("an accepted held connection must return a handle")


@dataclass(frozen=True, slots=True)
class RateLimitConfig:
    """Bounded active-test configuration.

    Defaults are deliberately moderate.  The hard caps protect both the target
    and the scanner from accidental descriptor/thread exhaustion; callers must
    not silently bypass them.
    """

    completed_connections: int = 30
    held_connections: int = 30
    concurrency: int = 10
    baseline_probes: int = 3
    control_probes: int = 3
    recovery_probes: int = 3
    hold_seconds: float = 1.0
    cooldown_seconds: float = 2.0
    failure_threshold: int = 2
    min_attempts_before_stop: int = 5
    slowdown_factor: float = 2.0
    slowdown_absolute_ms: float = 500.0
    min_timing_samples: int = 3

    def __post_init__(self) -> None:
        _bounded_int(
            "completed_connections", self.completed_connections, 1, MAX_CONNECTIONS
        )
        _bounded_int("held_connections", self.held_connections, 1, MAX_CONNECTIONS)
        _bounded_int("concurrency", self.concurrency, 1, MAX_CONCURRENCY)
        _bounded_int("baseline_probes", self.baseline_probes, 1, MAX_PHASE_PROBES)
        _bounded_int("control_probes", self.control_probes, 1, MAX_PHASE_PROBES)
        _bounded_int("recovery_probes", self.recovery_probes, 1, MAX_PHASE_PROBES)
        _bounded_float("hold_seconds", self.hold_seconds, 0, MAX_HOLD_SECONDS)
        _bounded_float(
            "cooldown_seconds", self.cooldown_seconds, 0, MAX_COOLDOWN_SECONDS
        )
        _bounded_int(
            "failure_threshold",
            self.failure_threshold,
            1,
            min(
                self.completed_connections,
                self.held_connections + self.control_probes,
                self.recovery_probes,
            ),
        )
        _bounded_int(
            "min_attempts_before_stop",
            self.min_attempts_before_stop,
            1,
            min(self.completed_connections, self.held_connections),
        )
        _bounded_float("slowdown_factor", self.slowdown_factor, 1.0, 10.0)
        _bounded_float(
            "slowdown_absolute_ms",
            self.slowdown_absolute_ms,
            0,
            MAX_SLOWDOWN_ABSOLUTE_MS,
        )
        _bounded_int(
            "min_timing_samples",
            self.min_timing_samples,
            1,
            min(
                self.completed_connections,
                self.control_probes,
                self.baseline_probes,
            ),
        )


@dataclass(frozen=True, slots=True)
class ProbeMetrics:
    requested: int
    attempted: int
    accepted: int
    outcome_counts: dict[str, int]
    median_ms: float | None = None
    p95_ms: float | None = None
    first_failure_attempt: int | None = None

    @property
    def failures(self) -> int:
        return self.attempted - self.accepted

    @property
    def internal_errors(self) -> int:
        return self.outcome_counts.get(ProbeOutcome.INTERNAL_ERROR.value, 0)

    @property
    def complete(self) -> bool:
        return self.attempted == self.requested

    @property
    def healthy(self) -> bool:
        return self.complete and self.attempted > 0 and self.accepted == self.attempted


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    scenario: Scenario
    verdict: RateLimitVerdict
    baseline: ProbeMetrics
    load: ProbeMetrics
    recovery: ProbeMetrics
    control: ProbeMetrics | None = None
    held_open_count: int = 0
    held_alive_count: int = 0
    held_closed_count: int = 0
    held_liveness_unknown_count: int = 0
    early_stopped: bool = False
    slowdown_observed: bool = False
    slowdown_ratio: float | None = None
    cleanup_errors: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def safe_to_continue(self) -> bool:
        return self.verdict not in {
            RateLimitVerdict.IMPACT_PERSISTED,
            RateLimitVerdict.ERROR,
        }

    @property
    def server_liveness_revalidated_during_hold(self) -> bool:
        """Whether every initially accepted held socket got a peer-liveness check."""

        return (
            self.held_open_count > 0
            and self.held_liveness_unknown_count == 0
            and self.held_alive_count + self.held_closed_count
            == self.held_open_count
        )


@dataclass(frozen=True, slots=True)
class RateLimitReport:
    completed: ScenarioResult
    held: ScenarioResult | None
    stopped_after_completed: bool = False


ProbeCallback = Callable[[ProbeRequest], ProbeResult]
HeldConnectionFactory = Callable[[ProbeRequest], OpenConnectionResult]
Clock = Callable[[], float]
Sleeper = Callable[[float], None]


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")


def _bounded_float(
    name: str,
    value: float,
    minimum: float,
    maximum: float,
) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number")
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum:g} and {maximum:g}")


def _error_text(error: object) -> str:
    message = str(error).strip() or error.__class__.__name__
    if len(message) > MAX_ERROR_LENGTH:
        message = f"{message[: MAX_ERROR_LENGTH - 3]}..."
    return message


def _exception_probe(error: Exception, duration_ms: float) -> ProbeResult:
    if isinstance(error, (TimeoutError, socket.timeout)):
        outcome = ProbeOutcome.TIMEOUT
    elif isinstance(error, ConnectionRefusedError):
        outcome = ProbeOutcome.REFUSED
    elif isinstance(error, ConnectionResetError):
        outcome = ProbeOutcome.RESET
    elif isinstance(error, OSError):
        outcome = ProbeOutcome.TRANSPORT_ERROR
    else:
        outcome = ProbeOutcome.INTERNAL_ERROR
    return ProbeResult(
        outcome=outcome,
        duration_ms=duration_ms,
        error=_error_text(error),
    )


def _percentile_95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[index]


def _metrics(requested: int, results: dict[int, ProbeResult]) -> ProbeMetrics:
    counts = {outcome.value: 0 for outcome in ProbeOutcome}
    accepted_durations: list[float] = []
    first_failure: int | None = None
    accepted = 0

    for attempt in sorted(results):
        result = results[attempt]
        counts[result.outcome.value] += 1
        if result.accepted:
            accepted += 1
            if result.duration_ms is not None:
                accepted_durations.append(result.duration_ms)
        elif first_failure is None:
            first_failure = attempt

    return ProbeMetrics(
        requested=requested,
        attempted=len(results),
        accepted=accepted,
        outcome_counts=counts,
        median_ms=(statistics.median(accepted_durations) if accepted_durations else None),
        p95_ms=_percentile_95(accepted_durations),
        first_failure_attempt=first_failure,
    )


def _empty_metrics() -> ProbeMetrics:
    return _metrics(0, {})


class RateLimitRunner:
    """Execute bounded connection-pressure scenarios through injected callbacks."""

    def __init__(
        self,
        probe: ProbeCallback,
        held_connection_factory: HeldConnectionFactory | None = None,
        *,
        config: RateLimitConfig | None = None,
        clock: Clock = time.perf_counter,
        sleeper: Sleeper = time.sleep,
    ) -> None:
        if not callable(probe):
            raise TypeError("probe must be callable")
        if held_connection_factory is not None and not callable(held_connection_factory):
            raise TypeError("held_connection_factory must be callable")
        if not callable(clock) or not callable(sleeper):
            raise TypeError("clock and sleeper must be callable")

        self.probe = probe
        self.held_connection_factory = held_connection_factory
        self.config = config or RateLimitConfig()
        self.clock = clock
        self.sleeper = sleeper

    def _invoke_probe(self, request: ProbeRequest) -> ProbeResult:
        started = self.clock()
        try:
            result = self.probe(request)
            if not isinstance(result, ProbeResult):
                raise TypeError("probe callback must return ProbeResult")
        except Exception as exc:
            return _exception_probe(exc, max(0.0, (self.clock() - started) * 1000.0))

        if result.duration_ms is None:
            result = replace(
                result,
                duration_ms=max(0.0, (self.clock() - started) * 1000.0),
            )
        if result.error is not None:
            result = replace(result, error=_error_text(result.error))
        return result

    def _invoke_open(self, request: ProbeRequest) -> OpenConnectionResult:
        if self.held_connection_factory is None:
            return OpenConnectionResult(
                ProbeResult(
                    ProbeOutcome.INTERNAL_ERROR,
                    duration_ms=0.0,
                    error="held connection factory is not configured",
                )
            )

        started = self.clock()
        try:
            result = self.held_connection_factory(request)
            if not isinstance(result, OpenConnectionResult):
                raise TypeError(
                    "held connection factory must return OpenConnectionResult"
                )
        except Exception as exc:
            return OpenConnectionResult(
                _exception_probe(exc, max(0.0, (self.clock() - started) * 1000.0))
            )

        probe = result.probe
        if probe.duration_ms is None:
            probe = replace(
                probe,
                duration_ms=max(0.0, (self.clock() - started) * 1000.0),
            )
        if probe.error is not None:
            probe = replace(probe, error=_error_text(probe.error))
        return replace(result, probe=probe)

    def _series(
        self,
        scenario: Scenario,
        phase: ProbePhase,
        count: int,
        *,
        stop_at_impact: bool = False,
    ) -> tuple[dict[int, ProbeResult], bool]:
        results: dict[int, ProbeResult] = {}
        failures = 0
        for attempt in range(1, count + 1):
            result = self._invoke_probe(ProbeRequest(scenario, phase, attempt))
            results[attempt] = result
            if result.outcome is ProbeOutcome.INTERNAL_ERROR:
                return results, True
            if not result.accepted:
                failures += 1
            if stop_at_impact and failures >= self.config.failure_threshold:
                return results, True
        return results, False

    def _concurrent(
        self,
        scenario: Scenario,
        count: int,
        invoke: Callable[[ProbeRequest], ProbeResult],
    ) -> tuple[dict[int, ProbeResult], bool]:
        """Run at most ``concurrency`` callbacks and stop scheduling on impact."""

        results: dict[int, ProbeResult] = {}
        next_attempt = 1
        early_stopped = False
        failures = 0
        workers = min(self.config.concurrency, count)
        executor = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix=f"rdp-rate-{scenario.value}",
        )
        pending: dict[Future[ProbeResult], int] = {}

        def submit_one() -> None:
            nonlocal next_attempt
            attempt = next_attempt
            next_attempt += 1
            request = ProbeRequest(scenario, ProbePhase.LOAD, attempt)
            pending[executor.submit(invoke, request)] = attempt

        try:
            for _ in range(workers):
                submit_one()

            while pending:
                completed, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
                for future in completed:
                    attempt = pending.pop(future)
                    # ``invoke`` catches ordinary callback errors.  This fallback
                    # protects against a bug in an injected wrapper itself.
                    try:
                        result = future.result()
                    except Exception as exc:  # pragma: no cover - defensive only
                        result = _exception_probe(exc, 0.0)
                    results[attempt] = result
                    if result.outcome is ProbeOutcome.INTERNAL_ERROR:
                        early_stopped = True
                    elif not result.accepted:
                        failures += 1

                if (
                    any(
                        result.outcome is ProbeOutcome.INTERNAL_ERROR
                        for result in results.values()
                    )
                    or (
                        len(results) >= self.config.min_attempts_before_stop
                        and failures >= self.config.failure_threshold
                    )
                ):
                    early_stopped = True

                while (
                    not early_stopped
                    and next_attempt <= count
                    and len(pending) < workers
                ):
                    submit_one()
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

        return results, early_stopped

    def _sleep_safely(self, seconds: float) -> str | None:
        if seconds <= 0:
            return None
        try:
            self.sleeper(seconds)
        except Exception as exc:
            return f"sleep failed: {_error_text(exc)}"
        return None

    def _slowdown(
        self,
        baseline: ProbeMetrics,
        comparison: ProbeMetrics,
    ) -> tuple[bool, float | None]:
        if (
            baseline.accepted < self.config.min_timing_samples
            or comparison.accepted < self.config.min_timing_samples
            or baseline.median_ms is None
            or comparison.median_ms is None
        ):
            return False, None

        threshold = max(
            baseline.median_ms * self.config.slowdown_factor,
            baseline.median_ms + self.config.slowdown_absolute_ms,
        )
        ratio = (
            comparison.median_ms / baseline.median_ms
            if baseline.median_ms > 0
            else None
        )
        return comparison.median_ms >= threshold, ratio

    def _assess(
        self,
        *,
        scenario: Scenario,
        baseline: ProbeMetrics,
        load: ProbeMetrics,
        recovery: ProbeMetrics,
        control: ProbeMetrics | None,
        early_stopped: bool,
        held_closed_count: int = 0,
        held_liveness_unknown_count: int = 0,
        cleanup_errors: tuple[str, ...] = (),
        operational_errors: tuple[str, ...] = (),
    ) -> tuple[RateLimitVerdict, bool, float | None, tuple[str, ...]]:
        notes = list(operational_errors)
        if cleanup_errors:
            notes.append("one or more held connections could not be closed cleanly")

        all_metrics = [baseline, load, recovery]
        if control is not None:
            all_metrics.append(control)
        if operational_errors or cleanup_errors or any(
            metrics.internal_errors for metrics in all_metrics
        ):
            return RateLimitVerdict.ERROR, False, None, tuple(notes)

        if not baseline.healthy:
            notes.append("healthy X.224 baseline was not established; load was skipped")
            return RateLimitVerdict.INCONCLUSIVE, False, None, tuple(notes)

        recovery_failures = recovery.failures
        if recovery_failures >= self.config.failure_threshold:
            notes.append("RDP negotiation failures persisted after load and cooldown")
            return RateLimitVerdict.IMPACT_PERSISTED, False, None, tuple(notes)
        if not recovery.healthy:
            notes.append("recovery was not completely healthy")
            return RateLimitVerdict.INCONCLUSIVE, False, None, tuple(notes)

        signal_metrics = [load]
        if control is not None:
            signal_metrics.append(control)
        observed_failures = (
            sum(metrics.failures for metrics in signal_metrics)
            + held_closed_count
        )
        if observed_failures >= self.config.failure_threshold:
            if held_closed_count:
                notes.append(
                    "repeatable negotiation failures or peer-closed held sockets "
                    "occurred during load and recovery succeeded"
                )
            else:
                notes.append(
                    "repeatable negotiation failures occurred during load and "
                    "recovery succeeded"
                )
            return RateLimitVerdict.LIMITING_OBSERVED, False, None, tuple(notes)

        timing_comparison = control if scenario is Scenario.HELD else load
        slowdown, ratio = self._slowdown(baseline, timing_comparison or load)
        if slowdown:
            notes.append(
                "X.224 connection-attempt slowdown crossed both the relative and "
                "absolute thresholds"
            )
            return RateLimitVerdict.SLOWDOWN_OBSERVED, True, ratio, tuple(notes)

        if early_stopped or any(not metrics.complete for metrics in signal_metrics):
            notes.append("the configured sample was not completed")
            return RateLimitVerdict.INCONCLUSIVE, False, ratio, tuple(notes)
        if observed_failures:
            notes.append("isolated failures did not meet the limiting threshold")
            return RateLimitVerdict.INCONCLUSIVE, False, ratio, tuple(notes)
        if held_liveness_unknown_count:
            notes.append(
                "server-side liveness could not be revalidated for every held socket"
            )
            return RateLimitVerdict.INCONCLUSIVE, False, ratio, tuple(notes)

        notes.append(
            "no connection limiting was observed within the configured sample"
        )
        return RateLimitVerdict.NOT_OBSERVED, False, ratio, tuple(notes)

    def _baseline_failure_result(
        self,
        scenario: Scenario,
        baseline_results: dict[int, ProbeResult],
    ) -> ScenarioResult:
        baseline = _metrics(self.config.baseline_probes, baseline_results)
        verdict = (
            RateLimitVerdict.ERROR
            if baseline.internal_errors
            else RateLimitVerdict.INCONCLUSIVE
        )
        note = (
            "baseline probe callback failed"
            if baseline.internal_errors
            else "healthy X.224 baseline was not established; load was skipped"
        )
        return ScenarioResult(
            scenario=scenario,
            verdict=verdict,
            baseline=baseline,
            load=_empty_metrics(),
            recovery=_empty_metrics(),
            control=_empty_metrics() if scenario is Scenario.HELD else None,
            notes=(note,),
        )

    def run_completed(self) -> ScenarioResult:
        scenario = Scenario.COMPLETED
        baseline_results, _ = self._series(
            scenario, ProbePhase.BASELINE, self.config.baseline_probes
        )
        baseline = _metrics(self.config.baseline_probes, baseline_results)
        if not baseline.healthy:
            return self._baseline_failure_result(scenario, baseline_results)

        load_results, early_stopped = self._concurrent(
            scenario,
            self.config.completed_connections,
            self._invoke_probe,
        )
        load = _metrics(self.config.completed_connections, load_results)
        operational_errors: list[str] = []
        if error := self._sleep_safely(self.config.cooldown_seconds):
            operational_errors.append(error)
        recovery_results, _ = self._series(
            scenario, ProbePhase.RECOVERY, self.config.recovery_probes
        )
        recovery = _metrics(self.config.recovery_probes, recovery_results)
        verdict, slowdown, ratio, notes = self._assess(
            scenario=scenario,
            baseline=baseline,
            load=load,
            recovery=recovery,
            control=None,
            early_stopped=early_stopped,
            operational_errors=tuple(operational_errors),
        )
        return ScenarioResult(
            scenario=scenario,
            verdict=verdict,
            baseline=baseline,
            load=load,
            recovery=recovery,
            early_stopped=early_stopped,
            slowdown_observed=slowdown,
            slowdown_ratio=ratio,
            notes=notes,
        )

    def run_held(self) -> ScenarioResult:
        scenario = Scenario.HELD
        if self.held_connection_factory is None:
            return ScenarioResult(
                scenario=scenario,
                verdict=RateLimitVerdict.ERROR,
                baseline=_empty_metrics(),
                load=_empty_metrics(),
                recovery=_empty_metrics(),
                control=_empty_metrics(),
                notes=("held connection factory is not configured",),
            )

        baseline_results, _ = self._series(
            scenario, ProbePhase.BASELINE, self.config.baseline_probes
        )
        baseline = _metrics(self.config.baseline_probes, baseline_results)
        if not baseline.healthy:
            return self._baseline_failure_result(scenario, baseline_results)

        handles: list[Closeable] = []
        accepted_handles: list[Closeable] = []
        handle_ids: set[int] = set()
        handles_lock = threading.Lock()
        cleanup_errors: list[str] = []
        operational_errors: list[str] = []

        def open_and_track(request: ProbeRequest) -> ProbeResult:
            opened = self._invoke_open(request)
            if opened.connection is not None:
                with handles_lock:
                    handle_id = id(opened.connection)
                    if handle_id not in handle_ids:
                        handle_ids.add(handle_id)
                        handles.append(opened.connection)
                        if opened.probe.accepted:
                            accepted_handles.append(opened.connection)
            return opened.probe

        control_results: dict[int, ProbeResult] = {}
        early_stopped = False
        load_results: dict[int, ProbeResult] = {}
        held_alive_count = 0
        held_closed_count = 0
        held_liveness_unknown_count = 0
        held_follow_up_skipped = False
        try:
            load_results, early_stopped = self._concurrent(
                scenario,
                self.config.held_connections,
                open_and_track,
            )
            if early_stopped:
                # An early stop deliberately avoids extending the load with a
                # hold period or control probes.  Accepted handles still need
                # an explicit liveness classification in the report: no
                # snapshot was taken, so they are unknown rather than zero.
                held_liveness_unknown_count = len(accepted_handles)
                held_follow_up_skipped = True
            elif handles:
                if error := self._sleep_safely(self.config.hold_seconds):
                    operational_errors.append(error)
                for handle in accepted_handles:
                    liveness_check = getattr(handle, "is_alive", None)
                    if not callable(liveness_check):
                        held_liveness_unknown_count += 1
                        continue
                    try:
                        alive = liveness_check()
                    except Exception as exc:
                        held_liveness_unknown_count += 1
                        operational_errors.append(
                            f"held-socket liveness check failed: {_error_text(exc)}"
                        )
                        continue
                    if alive is True:
                        held_alive_count += 1
                    elif alive is False:
                        held_closed_count += 1
                    else:
                        held_liveness_unknown_count += 1
                control_results, control_stopped = self._series(
                    scenario,
                    ProbePhase.CONTROL,
                    self.config.control_probes,
                    stop_at_impact=True,
                )
                early_stopped = early_stopped or control_stopped
        finally:
            for handle in reversed(handles):
                try:
                    handle.close()
                except Exception as exc:
                    cleanup_errors.append(_error_text(exc))

        if error := self._sleep_safely(self.config.cooldown_seconds):
            operational_errors.append(error)
        recovery_results, _ = self._series(
            scenario, ProbePhase.RECOVERY, self.config.recovery_probes
        )

        load = _metrics(self.config.held_connections, load_results)
        control = _metrics(self.config.control_probes, control_results)
        recovery = _metrics(self.config.recovery_probes, recovery_results)
        verdict, slowdown, ratio, notes = self._assess(
            scenario=scenario,
            baseline=baseline,
            load=load,
            recovery=recovery,
            control=control,
            early_stopped=early_stopped,
            held_closed_count=held_closed_count,
            held_liveness_unknown_count=held_liveness_unknown_count,
            cleanup_errors=tuple(cleanup_errors),
            operational_errors=tuple(operational_errors),
        )
        if held_follow_up_skipped:
            notes = (
                *notes,
                (
                    "held-socket hold/liveness checks and control probes were "
                    "skipped after the held-open load stopped early; retained "
                    "handles, if any, were closed before recovery"
                ),
            )
        return ScenarioResult(
            scenario=scenario,
            verdict=verdict,
            baseline=baseline,
            load=load,
            recovery=recovery,
            control=control,
            held_open_count=len(accepted_handles),
            held_alive_count=held_alive_count,
            held_closed_count=held_closed_count,
            held_liveness_unknown_count=held_liveness_unknown_count,
            early_stopped=early_stopped,
            slowdown_observed=slowdown,
            slowdown_ratio=ratio,
            cleanup_errors=tuple(cleanup_errors),
            notes=notes,
        )

    def run_both(self) -> RateLimitReport:
        completed = self.run_completed()
        if not completed.safe_to_continue:
            return RateLimitReport(
                completed=completed,
                held=None,
                stopped_after_completed=True,
            )
        return RateLimitReport(completed=completed, held=self.run_held())


__all__ = [
    "MAX_CONCURRENCY",
    "MAX_CONNECTIONS",
    "Closeable",
    "HeldConnectionFactory",
    "LivenessCheckable",
    "OpenConnectionResult",
    "ProbeCallback",
    "ProbeMetrics",
    "ProbeOutcome",
    "ProbePhase",
    "ProbeRequest",
    "ProbeResult",
    "RateLimitConfig",
    "RateLimitReport",
    "RateLimitRunner",
    "RateLimitVerdict",
    "Scenario",
    "ScenarioResult",
    "SocketConnectionHandle",
]
