from __future__ import annotations

import socket
import threading
import time
import unittest

from ptsrvtester.protocols.rdp.utils.rate_limit import (
    MAX_CONCURRENCY,
    MAX_CONNECTIONS,
    OpenConnectionResult,
    ProbeOutcome,
    ProbePhase,
    ProbeRequest,
    ProbeResult,
    RateLimitConfig,
    RateLimitRunner,
    RateLimitVerdict,
    Scenario,
    SocketConnectionHandle,
)


def accepted(duration_ms: float = 10.0) -> ProbeResult:
    return ProbeResult(ProbeOutcome.ACCEPTED, duration_ms=duration_ms)


def rejected(duration_ms: float = 10.0) -> ProbeResult:
    return ProbeResult(ProbeOutcome.REJECTED, duration_ms=duration_ms)


def test_config(**overrides) -> RateLimitConfig:
    values = {
        "completed_connections": 6,
        "held_connections": 6,
        "concurrency": 2,
        "baseline_probes": 3,
        "control_probes": 3,
        "recovery_probes": 3,
        "hold_seconds": 0.0,
        "cooldown_seconds": 0.0,
        "failure_threshold": 2,
        "min_attempts_before_stop": 2,
        "slowdown_factor": 2.0,
        "slowdown_absolute_ms": 100.0,
        "min_timing_samples": 3,
    }
    values.update(overrides)
    return RateLimitConfig(**values)


class FakeConnection:
    def __init__(
        self,
        *,
        close_error: Exception | None = None,
        peer_alive: bool | None = True,
    ) -> None:
        self.closed = False
        self.close_calls = 0
        self.close_error = close_error
        self.peer_alive = peer_alive

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.close_error is not None:
            raise self.close_error

    def is_alive(self) -> bool | None:
        if self.closed:
            return False
        return self.peer_alive


class RateLimitConfigTests(unittest.TestCase):
    def test_defaults_are_valid_and_bounded(self):
        config = RateLimitConfig()

        self.assertLessEqual(config.completed_connections, MAX_CONNECTIONS)
        self.assertLessEqual(config.held_connections, MAX_CONNECTIONS)
        self.assertLessEqual(config.concurrency, MAX_CONCURRENCY)

    def test_connection_and_concurrency_hard_caps_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "completed_connections"):
            RateLimitConfig(completed_connections=MAX_CONNECTIONS + 1)
        with self.assertRaisesRegex(ValueError, "held_connections"):
            RateLimitConfig(held_connections=MAX_CONNECTIONS + 1)
        with self.assertRaisesRegex(ValueError, "concurrency"):
            RateLimitConfig(concurrency=MAX_CONCURRENCY + 1)

    def test_boolean_and_non_finite_values_are_rejected(self):
        with self.assertRaisesRegex(TypeError, "completed_connections"):
            RateLimitConfig(completed_connections=True)
        with self.assertRaisesRegex(ValueError, "hold_seconds"):
            RateLimitConfig(hold_seconds=float("inf"))
        with self.assertRaisesRegex(ValueError, "cooldown_seconds"):
            RateLimitConfig(cooldown_seconds=-1)

    def test_thresholds_must_be_reachable_in_every_relevant_phase(self):
        with self.assertRaisesRegex(ValueError, "failure_threshold"):
            test_config(recovery_probes=1, failure_threshold=2)
        with self.assertRaisesRegex(ValueError, "min_attempts_before_stop"):
            test_config(held_connections=1, min_attempts_before_stop=2)
        with self.assertRaisesRegex(ValueError, "min_timing_samples"):
            test_config(baseline_probes=2, min_timing_samples=3)

    def test_probe_and_held_result_contracts_are_validated(self):
        with self.assertRaisesRegex(ValueError, "duration_ms"):
            ProbeResult(ProbeOutcome.ACCEPTED, duration_ms=-0.1)
        with self.assertRaisesRegex(ValueError, "must return a handle"):
            OpenConnectionResult(accepted())
        with self.assertRaisesRegex(ValueError, "positive integer"):
            ProbeRequest(Scenario.COMPLETED, ProbePhase.LOAD, 0)

    def test_socket_handle_revalidates_peer_liveness_without_consuming_data(self):
        client, peer = socket.socketpair()
        handle = SocketConnectionHandle(client)
        try:
            self.assertTrue(handle.is_alive())
            peer.sendall(b"x")
            self.assertIsNone(handle.is_alive())
            self.assertEqual(client.recv(1), b"x")
            peer.shutdown(socket.SHUT_RDWR)
            peer.close()
            self.assertFalse(handle.is_alive())
        finally:
            handle.close()
            try:
                peer.close()
            except OSError:
                pass


class CompletedConnectionScenarioTests(unittest.TestCase):
    def test_unhealthy_baseline_skips_all_active_load(self):
        requests: list[ProbeRequest] = []

        def probe(request: ProbeRequest) -> ProbeResult:
            requests.append(request)
            if request.phase is ProbePhase.BASELINE and request.attempt == 1:
                return rejected()
            return accepted()

        result = RateLimitRunner(
            probe,
            config=test_config(),
            sleeper=lambda _seconds: None,
        ).run_completed()

        self.assertEqual(result.verdict, RateLimitVerdict.INCONCLUSIVE)
        self.assertEqual(result.load.attempted, 0)
        self.assertEqual(result.recovery.attempted, 0)
        self.assertEqual({request.phase for request in requests}, {ProbePhase.BASELINE})

    def test_complete_healthy_sample_reports_only_not_observed(self):
        def probe(request: ProbeRequest) -> ProbeResult:
            duration = {
                ProbePhase.BASELINE: 20.0,
                ProbePhase.LOAD: 30.0,
                ProbePhase.RECOVERY: 20.0,
            }[request.phase]
            return accepted(duration)

        result = RateLimitRunner(
            probe,
            config=test_config(),
            sleeper=lambda _seconds: None,
        ).run_completed()

        self.assertEqual(result.verdict, RateLimitVerdict.NOT_OBSERVED)
        self.assertEqual(result.load.attempted, 6)
        self.assertEqual(result.load.accepted, 6)
        self.assertEqual(result.load.median_ms, 30.0)
        self.assertEqual(result.load.p95_ms, 30.0)
        self.assertFalse(result.early_stopped)
        self.assertIn("within the configured sample", result.notes[-1])

    def test_slowdown_requires_relative_and_absolute_threshold(self):
        def probe(request: ProbeRequest) -> ProbeResult:
            if request.phase is ProbePhase.LOAD:
                return accepted(250.0)
            return accepted(50.0)

        result = RateLimitRunner(
            probe,
            config=test_config(
                slowdown_factor=2.0,
                slowdown_absolute_ms=100.0,
            ),
            sleeper=lambda _seconds: None,
        ).run_completed()

        self.assertEqual(result.verdict, RateLimitVerdict.SLOWDOWN_OBSERVED)
        self.assertTrue(result.slowdown_observed)
        self.assertEqual(result.slowdown_ratio, 5.0)

    def test_relative_growth_alone_is_not_called_slowdown(self):
        def probe(request: ProbeRequest) -> ProbeResult:
            return accepted(3.0 if request.phase is ProbePhase.LOAD else 1.0)

        result = RateLimitRunner(
            probe,
            config=test_config(
                slowdown_factor=2.0,
                slowdown_absolute_ms=100.0,
            ),
            sleeper=lambda _seconds: None,
        ).run_completed()

        self.assertEqual(result.verdict, RateLimitVerdict.NOT_OBSERVED)
        self.assertFalse(result.slowdown_observed)

    def test_isolated_load_failure_is_inconclusive(self):
        def probe(request: ProbeRequest) -> ProbeResult:
            if request.phase is ProbePhase.LOAD and request.attempt == 1:
                return rejected()
            return accepted()

        result = RateLimitRunner(
            probe,
            config=test_config(failure_threshold=2),
            sleeper=lambda _seconds: None,
        ).run_completed()

        self.assertEqual(result.verdict, RateLimitVerdict.INCONCLUSIVE)
        self.assertEqual(result.load.attempted, 6)
        self.assertEqual(result.load.failures, 1)
        self.assertFalse(result.early_stopped)

    def test_repeatable_failures_stop_new_work_and_recovery_confirms_limiting(self):
        config = test_config(
            completed_connections=20,
            held_connections=20,
            concurrency=2,
            failure_threshold=2,
            min_attempts_before_stop=2,
        )

        def probe(request: ProbeRequest) -> ProbeResult:
            if request.phase is ProbePhase.LOAD and request.attempt <= 2:
                return ProbeResult(ProbeOutcome.REFUSED, duration_ms=5.0)
            return accepted()

        result = RateLimitRunner(
            probe,
            config=config,
            sleeper=lambda _seconds: None,
        ).run_completed()

        self.assertEqual(result.verdict, RateLimitVerdict.LIMITING_OBSERVED)
        self.assertTrue(result.early_stopped)
        self.assertGreaterEqual(result.load.attempted, 2)
        self.assertLess(result.load.attempted, config.completed_connections)
        self.assertTrue(result.recovery.healthy)

    def test_persistent_recovery_impact_has_priority_over_load_verdict(self):
        def probe(request: ProbeRequest) -> ProbeResult:
            if request.phase in {ProbePhase.LOAD, ProbePhase.RECOVERY}:
                return ProbeResult(ProbeOutcome.TIMEOUT, duration_ms=1000.0)
            return accepted()

        result = RateLimitRunner(
            probe,
            config=test_config(),
            sleeper=lambda _seconds: None,
        ).run_completed()

        self.assertEqual(result.verdict, RateLimitVerdict.IMPACT_PERSISTED)
        self.assertFalse(result.safe_to_continue)

    def test_one_recovery_failure_is_conservative_inconclusive(self):
        def probe(request: ProbeRequest) -> ProbeResult:
            if request.phase is ProbePhase.LOAD and request.attempt <= 2:
                return rejected()
            if request.phase is ProbePhase.RECOVERY and request.attempt == 1:
                return rejected()
            return accepted()

        result = RateLimitRunner(
            probe,
            config=test_config(failure_threshold=2),
            sleeper=lambda _seconds: None,
        ).run_completed()

        self.assertEqual(result.verdict, RateLimitVerdict.INCONCLUSIVE)
        self.assertNotEqual(result.verdict, RateLimitVerdict.LIMITING_OBSERVED)

    def test_unexpected_callback_failure_is_error_and_is_truncated(self):
        long_message = "x" * 1000

        def probe(_request: ProbeRequest):
            raise RuntimeError(long_message)

        runner = RateLimitRunner(
            probe,
            config=test_config(),
            sleeper=lambda _seconds: None,
        )
        sample = runner._invoke_probe(
            ProbeRequest(Scenario.COMPLETED, ProbePhase.BASELINE, 1)
        )
        result = runner.run_completed()

        self.assertEqual(sample.outcome, ProbeOutcome.INTERNAL_ERROR)
        self.assertLessEqual(len(sample.error or ""), 500)
        self.assertEqual(result.verdict, RateLimitVerdict.ERROR)
        self.assertFalse(result.safe_to_continue)

    def test_common_transport_exceptions_are_classified_without_string_matching(self):
        exceptions = (
            (TimeoutError("late"), ProbeOutcome.TIMEOUT),
            (ConnectionRefusedError("no"), ProbeOutcome.REFUSED),
            (ConnectionResetError("reset"), ProbeOutcome.RESET),
            (OSError("network"), ProbeOutcome.TRANSPORT_ERROR),
        )
        for error, expected in exceptions:
            with self.subTest(expected=expected):
                runner = RateLimitRunner(
                    lambda _request, error=error: (_ for _ in ()).throw(error),
                    config=test_config(),
                    sleeper=lambda _seconds: None,
                )
                sample = runner._invoke_probe(
                    ProbeRequest(Scenario.COMPLETED, ProbePhase.LOAD, 1)
                )
                self.assertEqual(sample.outcome, expected)

    def test_callback_duration_is_measured_when_not_supplied(self):
        readings = iter((10.0, 10.125))
        runner = RateLimitRunner(
            lambda _request: ProbeResult(ProbeOutcome.ACCEPTED),
            config=test_config(),
            clock=lambda: next(readings),
            sleeper=lambda _seconds: None,
        )

        result = runner._invoke_probe(
            ProbeRequest(Scenario.COMPLETED, ProbePhase.LOAD, 1)
        )

        self.assertEqual(result.duration_ms, 125.0)

    def test_load_uses_bounded_concurrency(self):
        active = 0
        maximum_active = 0
        lock = threading.Lock()

        def probe(request: ProbeRequest) -> ProbeResult:
            nonlocal active, maximum_active
            if request.phase is not ProbePhase.LOAD:
                return accepted()
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.02)
            with lock:
                active -= 1
            return accepted()

        config = test_config(concurrency=3)
        result = RateLimitRunner(
            probe,
            config=config,
            sleeper=lambda _seconds: None,
        ).run_completed()

        self.assertEqual(result.verdict, RateLimitVerdict.NOT_OBSERVED)
        self.assertGreater(maximum_active, 1)
        self.assertLessEqual(maximum_active, config.concurrency)


class HeldConnectionScenarioTests(unittest.TestCase):
    def test_factory_is_required(self):
        calls = 0

        def probe(_request: ProbeRequest) -> ProbeResult:
            nonlocal calls
            calls += 1
            return accepted()

        result = RateLimitRunner(
            probe,
            config=test_config(),
            sleeper=lambda _seconds: None,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.ERROR)
        self.assertEqual(calls, 0)

    def test_connections_remain_open_for_controls_and_all_close_afterwards(self):
        connections: list[FakeConnection] = []
        sleep_calls: list[float] = []

        def factory(_request: ProbeRequest) -> OpenConnectionResult:
            connection = FakeConnection()
            connections.append(connection)
            return OpenConnectionResult(accepted(15.0), connection)

        def probe(request: ProbeRequest) -> ProbeResult:
            if request.phase is ProbePhase.CONTROL:
                self.assertTrue(connections)
                self.assertTrue(all(not connection.closed for connection in connections))
            return accepted(10.0)

        config = test_config(hold_seconds=0.5, cooldown_seconds=0.25)
        result = RateLimitRunner(
            probe,
            factory,
            config=config,
            sleeper=sleep_calls.append,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.NOT_OBSERVED)
        self.assertEqual(result.held_open_count, config.held_connections)
        self.assertEqual(result.held_alive_count, config.held_connections)
        self.assertEqual(result.held_closed_count, 0)
        self.assertEqual(result.held_liveness_unknown_count, 0)
        self.assertTrue(result.server_liveness_revalidated_during_hold)
        self.assertEqual(result.control.attempted, config.control_probes)
        self.assertTrue(all(connection.closed for connection in connections))
        self.assertTrue(all(connection.close_calls == 1 for connection in connections))
        self.assertEqual(sleep_calls, [0.5, 0.25])

    def test_control_failures_close_handles_immediately_then_verify_recovery(self):
        connections: list[FakeConnection] = []

        def factory(_request: ProbeRequest) -> OpenConnectionResult:
            connection = FakeConnection()
            connections.append(connection)
            return OpenConnectionResult(accepted(), connection)

        def probe(request: ProbeRequest) -> ProbeResult:
            if request.phase is ProbePhase.CONTROL:
                return ProbeResult(ProbeOutcome.TIMEOUT, duration_ms=1000.0)
            if request.phase is ProbePhase.RECOVERY:
                self.assertTrue(all(connection.closed for connection in connections))
            return accepted()

        result = RateLimitRunner(
            probe,
            factory,
            config=test_config(failure_threshold=2),
            sleeper=lambda _seconds: None,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.LIMITING_OBSERVED)
        self.assertEqual(result.control.attempted, 2)
        self.assertTrue(result.early_stopped)
        self.assertTrue(all(connection.closed for connection in connections))
        self.assertTrue(result.recovery.healthy)

    def test_peer_closed_held_sockets_are_counted_as_a_repeatable_signal(self):
        def factory(request: ProbeRequest) -> OpenConnectionResult:
            return OpenConnectionResult(
                accepted(),
                FakeConnection(peer_alive=request.attempt > 2),
            )

        result = RateLimitRunner(
            lambda _request: accepted(),
            factory,
            config=test_config(failure_threshold=2),
            sleeper=lambda _seconds: None,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.LIMITING_OBSERVED)
        self.assertEqual(result.held_closed_count, 2)
        self.assertEqual(result.held_alive_count, 4)
        self.assertTrue(result.server_liveness_revalidated_during_hold)

    def test_unknown_held_socket_liveness_makes_negative_verdict_inconclusive(self):
        class CloseOnlyConnection:
            def close(self) -> None:
                pass

        result = RateLimitRunner(
            lambda _request: accepted(),
            lambda _request: OpenConnectionResult(
                accepted(),
                CloseOnlyConnection(),
            ),
            config=test_config(),
            sleeper=lambda _seconds: None,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.INCONCLUSIVE)
        self.assertEqual(
            result.held_liveness_unknown_count,
            result.held_open_count,
        )
        self.assertFalse(result.server_liveness_revalidated_during_hold)

    def test_failed_open_attempt_handles_are_also_closed(self):
        connections: list[FakeConnection] = []

        def factory(request: ProbeRequest) -> OpenConnectionResult:
            connection = FakeConnection()
            connections.append(connection)
            result = rejected() if request.attempt <= 2 else accepted()
            return OpenConnectionResult(result, connection)

        result = RateLimitRunner(
            lambda _request: accepted(),
            factory,
            config=test_config(failure_threshold=2),
            sleeper=lambda _seconds: None,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.LIMITING_OBSERVED)
        self.assertGreaterEqual(len(connections), 2)
        self.assertTrue(all(connection.closed for connection in connections))

    def test_early_load_stop_accounts_for_unchecked_retained_handles(self):
        connections: list[FakeConnection] = []
        phases: list[ProbePhase] = []
        sleep_calls: list[float] = []

        def factory(request: ProbeRequest) -> OpenConnectionResult:
            if request.attempt == 1:
                connection = FakeConnection()
                connections.append(connection)
                return OpenConnectionResult(accepted(), connection)
            return OpenConnectionResult(rejected())

        def probe(request: ProbeRequest) -> ProbeResult:
            phases.append(request.phase)
            if request.phase is ProbePhase.RECOVERY:
                self.assertTrue(all(connection.closed for connection in connections))
            return accepted()

        config = test_config(
            held_connections=5,
            concurrency=1,
            min_attempts_before_stop=5,
            hold_seconds=0.5,
        )
        result = RateLimitRunner(
            probe,
            factory,
            config=config,
            sleeper=sleep_calls.append,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.LIMITING_OBSERVED)
        self.assertTrue(result.early_stopped)
        self.assertEqual(result.load.attempted, 5)
        self.assertEqual(result.load.accepted, 1)
        self.assertEqual(result.held_open_count, 1)
        self.assertEqual(result.held_alive_count, 0)
        self.assertEqual(result.held_closed_count, 0)
        self.assertEqual(result.held_liveness_unknown_count, 1)
        self.assertFalse(result.server_liveness_revalidated_during_hold)
        self.assertEqual(result.control.attempted, 0)
        self.assertNotIn(ProbePhase.CONTROL, phases)
        self.assertEqual(sleep_calls, [])
        self.assertIn("control probes were skipped", result.notes[-1])
        self.assertTrue(all(connection.closed for connection in connections))

    def test_cleanup_failure_is_an_error_not_a_successful_verdict(self):
        connections: list[FakeConnection] = []

        def factory(request: ProbeRequest) -> OpenConnectionResult:
            connection = FakeConnection(
                close_error=OSError("close failed") if request.attempt == 1 else None
            )
            connections.append(connection)
            return OpenConnectionResult(accepted(), connection)

        result = RateLimitRunner(
            lambda _request: accepted(),
            factory,
            config=test_config(),
            sleeper=lambda _seconds: None,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.ERROR)
        self.assertEqual(result.cleanup_errors, ("close failed",))
        self.assertTrue(all(connection.closed for connection in connections))

    def test_factory_transport_failures_are_counted_and_stop_opening(self):
        def factory(request: ProbeRequest) -> OpenConnectionResult:
            if request.attempt <= 2:
                raise ConnectionRefusedError("busy")
            return OpenConnectionResult(accepted(), FakeConnection())

        result = RateLimitRunner(
            lambda _request: accepted(),
            factory,
            config=test_config(failure_threshold=2),
            sleeper=lambda _seconds: None,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.LIMITING_OBSERVED)
        self.assertEqual(
            result.load.outcome_counts[ProbeOutcome.REFUSED.value],
            2,
        )
        self.assertTrue(result.early_stopped)

    def test_control_callback_error_still_closes_every_connection(self):
        connections: list[FakeConnection] = []

        def factory(_request: ProbeRequest) -> OpenConnectionResult:
            connection = FakeConnection()
            connections.append(connection)
            return OpenConnectionResult(accepted(), connection)

        def probe(request: ProbeRequest):
            if request.phase is ProbePhase.CONTROL:
                raise RuntimeError("probe implementation failed")
            return accepted()

        result = RateLimitRunner(
            probe,
            factory,
            config=test_config(),
            sleeper=lambda _seconds: None,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.ERROR)
        self.assertTrue(all(connection.closed for connection in connections))

    def test_held_slowdown_uses_control_probes_not_parallel_open_timings(self):
        def factory(_request: ProbeRequest) -> OpenConnectionResult:
            return OpenConnectionResult(accepted(5000.0), FakeConnection())

        def probe(request: ProbeRequest) -> ProbeResult:
            if request.phase is ProbePhase.CONTROL:
                return accepted(250.0)
            return accepted(50.0)

        result = RateLimitRunner(
            probe,
            factory,
            config=test_config(),
            sleeper=lambda _seconds: None,
        ).run_held()

        self.assertEqual(result.verdict, RateLimitVerdict.SLOWDOWN_OBSERVED)
        self.assertEqual(result.slowdown_ratio, 5.0)


class CombinedScenarioTests(unittest.TestCase):
    def test_persistent_completed_impact_prevents_held_scenario(self):
        factory_calls = 0

        def probe(request: ProbeRequest) -> ProbeResult:
            if (
                request.scenario is Scenario.COMPLETED
                and request.phase in {ProbePhase.LOAD, ProbePhase.RECOVERY}
            ):
                return rejected()
            return accepted()

        def factory(_request: ProbeRequest) -> OpenConnectionResult:
            nonlocal factory_calls
            factory_calls += 1
            return OpenConnectionResult(accepted(), FakeConnection())

        report = RateLimitRunner(
            probe,
            factory,
            config=test_config(),
            sleeper=lambda _seconds: None,
        ).run_both()

        self.assertEqual(
            report.completed.verdict,
            RateLimitVerdict.IMPACT_PERSISTED,
        )
        self.assertIsNone(report.held)
        self.assertTrue(report.stopped_after_completed)
        self.assertEqual(factory_calls, 0)

    def test_recovered_completed_limiting_allows_distinct_held_scenario(self):
        def probe(request: ProbeRequest) -> ProbeResult:
            if (
                request.scenario is Scenario.COMPLETED
                and request.phase is ProbePhase.LOAD
                and request.attempt <= 2
            ):
                return rejected()
            return accepted()

        report = RateLimitRunner(
            probe,
            lambda _request: OpenConnectionResult(accepted(), FakeConnection()),
            config=test_config(),
            sleeper=lambda _seconds: None,
        ).run_both()

        self.assertEqual(
            report.completed.verdict,
            RateLimitVerdict.LIMITING_OBSERVED,
        )
        self.assertIsNotNone(report.held)
        self.assertEqual(report.held.verdict, RateLimitVerdict.NOT_OBSERVED)
        self.assertFalse(report.stopped_after_completed)


if __name__ == "__main__":
    unittest.main()
