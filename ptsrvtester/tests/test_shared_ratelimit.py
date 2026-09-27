"""Unit tests for the shared cross-protocol RATELIMIT engine and adapters.

These use in-process fake adapters (deterministic, no network) plus one real
localhost TCP server for the TcpConnectionAdapter / SocketHandle path.
"""

from __future__ import annotations

import socket
import threading
import unittest

from ptsrvtester.protocols._shared.utils.rate_limit import (
    ProbeOutcome,
    ProbeResult,
    RateLimitConfig,
    RateLimitTester,
    Verdict,
)
from ptsrvtester.protocols._shared.utils.connection import (
    SocketHandle,
    TcpConnectionAdapter,
)


# --- fake adapters ---------------------------------------------------------


class _Handle:
    def __init__(self, alive=True):
        self._alive = alive

    def close(self):
        self._alive = False

    def is_alive(self):
        return self._alive


class HealthyAdapter:
    """Always accepts; hands out live handles."""

    def probe(self):
        return ProbeResult(ProbeOutcome.ACCEPTED, 5.0)

    def open_held(self):
        return ProbeResult(ProbeOutcome.ACCEPTED, 5.0), _Handle()


class ConcurrentCapAdapter:
    """Refuses while more than ``cap`` connections are held open concurrently.

    Serial phases (baseline/recovery) open+close instantly so they always see
    zero held and accept; the concurrent burst/hold climbs past the cap and gets
    refused for the excess — modelling a server that limits concurrency but
    recovers immediately.
    """

    def __init__(self, cap):
        self.cap = cap
        self._open = 0
        self._lock = threading.Lock()

    def probe(self):
        with self._lock:
            if self._open >= self.cap:
                return ProbeResult(ProbeOutcome.REFUSED, 1.0, error="refused")
        return ProbeResult(ProbeOutcome.ACCEPTED, 5.0)

    def open_held(self):
        with self._lock:
            if self._open >= self.cap:
                return ProbeResult(ProbeOutcome.REFUSED, 1.0, error="refused"), None
            self._open += 1
        adapter = self

        class _Tracked(_Handle):
            def close(self):
                super().close()
                with adapter._lock:
                    adapter._open -= 1

        return ProbeResult(ProbeOutcome.ACCEPTED, 5.0), _Tracked()


class DeadAdapter:
    """Baseline works, then everything fails and never recovers."""

    def __init__(self):
        self.calls = 0

    def probe(self):
        self.calls += 1
        if self.calls <= 2:  # let the 2 baseline probes through
            return ProbeResult(ProbeOutcome.ACCEPTED, 5.0)
        return ProbeResult(ProbeOutcome.RESET, 1.0, error="reset")

    def open_held(self):
        return ProbeResult(ProbeOutcome.RESET, 1.0, error="reset"), None


class UnreachableAdapter:
    def probe(self):
        return ProbeResult(ProbeOutcome.REFUSED, 1.0, error="refused")

    def open_held(self):
        return ProbeResult(ProbeOutcome.REFUSED, 1.0, error="refused"), None


def _cfg(**kw):
    base = dict(
        count=8, concurrency=4, baseline_probes=2, recovery_probes=2,
        hold_seconds=0.0, cooldown_seconds=0.0, idle_max_seconds=0.0,
    )
    base.update(kw)
    return RateLimitConfig(**base)


def _tester(adapter, cfg):
    return RateLimitTester(adapter, cfg, sleeper=lambda s: None)


class VerdictTests(unittest.TestCase):
    def test_healthy_not_observed(self):
        rep = _tester(HealthyAdapter(), _cfg()).run()
        self.assertIs(rep.detection.verdict, Verdict.NOT_OBSERVED)
        self.assertIs(rep.detection.deployed, False)
        self.assertEqual(rep.concurrency.accepted, 8)
        self.assertEqual(rep.concurrency.requested, 8)
        self.assertFalse(rep.concurrency.capped)
        self.assertEqual(rep.connect_rate.accepted, 8)

    def test_concurrency_cap_recovers_is_limiting(self):
        rep = _tester(ConcurrentCapAdapter(cap=3), _cfg(count=10, concurrency=10)).run()
        self.assertIs(rep.detection.verdict, Verdict.LIMITING_OBSERVED)
        self.assertIs(rep.detection.deployed, True)
        self.assertTrue(rep.concurrency.capped)
        self.assertLessEqual(rep.concurrency.accepted, 3)

    def test_persistent_failure_is_impact_persisted(self):
        rep = _tester(DeadAdapter(), _cfg()).run()
        self.assertIs(rep.detection.verdict, Verdict.IMPACT_PERSISTED)
        self.assertIs(rep.detection.deployed, True)

    def test_unreachable_baseline_is_inconclusive(self):
        rep = _tester(UnreachableAdapter(), _cfg()).run()
        self.assertIs(rep.detection.verdict, Verdict.INCONCLUSIVE)
        self.assertIsNone(rep.detection.deployed)
        self.assertIsNotNone(rep.aborted_reason)


class IdleTimeoutTests(unittest.TestCase):
    def test_idle_timeout_measured(self):
        class DyingAdapter(HealthyAdapter):
            def open_held(self):
                h = _Handle()
                state = {"polls": 0}

                def is_alive():
                    state["polls"] += 1
                    return state["polls"] < 3  # dies on the 3rd poll

                h.is_alive = is_alive
                return ProbeResult(ProbeOutcome.ACCEPTED, 5.0), h

        cfg = _cfg(idle_max_seconds=10.0, idle_poll_seconds=0.01)
        rep = _tester(DyingAdapter(), cfg).run()
        self.assertTrue(rep.idle_timeout.measured)
        self.assertFalse(rep.idle_timeout.still_open)
        self.assertIsNotNone(rep.idle_timeout.seconds)

    def test_idle_timeout_still_open(self):
        cfg = _cfg(idle_max_seconds=0.05, idle_poll_seconds=0.01)
        rep = RateLimitTester(HealthyAdapter(), cfg).run()
        self.assertTrue(rep.idle_timeout.measured)
        self.assertTrue(rep.idle_timeout.still_open)
        self.assertIsNone(rep.idle_timeout.seconds)


class ConfigTests(unittest.TestCase):
    def test_config_from_args_clamps(self):
        class Args:
            rate_count = 100000       # -> MAX_COUNT
            rate_concurrency = 0      # -> min 1
            rate_timeout = -5         # -> min 0.5
            rate_idle_max = 999999    # -> MAX_IDLE_SECONDS

        cfg = RateLimitConfig.from_args(Args())
        self.assertEqual(cfg.count, 200)
        self.assertEqual(cfg.concurrency, 1)
        self.assertEqual(cfg.timeout_seconds, 0.5)
        self.assertEqual(cfg.idle_max_seconds, 600.0)

    def test_config_from_args_defaults_when_missing(self):
        class Args:
            pass

        cfg = RateLimitConfig.from_args(Args())
        self.assertEqual(cfg.count, 30)
        self.assertEqual(cfg.concurrency, 10)


class TcpAdapterTests(unittest.TestCase):
    def setUp(self):
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(50)
        self.port = self._srv.getsockname()[1]
        self._conns = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        self._srv.settimeout(0.2)
        while not self._stop.is_set():
            try:
                c, _ = self._srv.accept()
                self._conns.append(c)
            except socket.timeout:
                continue
            except OSError:
                break

    def tearDown(self):
        self._stop.set()
        self._thread.join(timeout=1)
        for c in self._conns:
            try:
                c.close()
            except OSError:
                pass
        self._srv.close()

    def test_probe_and_hold(self):
        adapter = TcpConnectionAdapter("127.0.0.1", self.port, timeout_seconds=2.0)
        self.assertTrue(adapter.probe().accepted)
        probe, handle = adapter.open_held()
        self.assertTrue(probe.accepted)
        self.assertIsInstance(handle, SocketHandle)
        self.assertIs(handle.is_alive(), True)
        handle.close()

    def test_full_run_against_real_server(self):
        adapter = TcpConnectionAdapter("127.0.0.1", self.port, timeout_seconds=2.0)
        cfg = _cfg(count=6, concurrency=3, idle_max_seconds=0.0)
        rep = RateLimitTester(adapter, cfg).run()
        self.assertTrue(rep.detection.baseline_ok)
        self.assertEqual(rep.connect_rate.accepted, 6)
        self.assertEqual(rep.concurrency.accepted, 6)


class TcpAdapterRefusedTest(unittest.TestCase):
    def test_refused_on_closed_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        adapter = TcpConnectionAdapter("127.0.0.1", port, timeout_seconds=1.0)
        result = adapter.probe()
        self.assertFalse(result.accepted)
        self.assertIn(
            result.outcome,
            (ProbeOutcome.REFUSED, ProbeOutcome.TIMEOUT, ProbeOutcome.TRANSPORT_ERROR),
        )


if __name__ == "__main__":
    unittest.main()