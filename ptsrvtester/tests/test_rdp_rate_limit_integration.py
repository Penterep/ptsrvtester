import socket
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ptsrvtester.protocols.rdp.utils.cli import RDP_EXPLICIT_ONLY_TESTS, RDPArgs
from ptsrvtester.protocols.rdp.utils.engine import (
    IMPLEMENTED_TESTS,
    PROTOCOL_HYBRID,
    RDP,
    RDP_TEST_ORDER,
    RDPConnectionLimitResult,
)
from ptsrvtester.protocols.rdp.utils.rate_limit import (
    ProbeMetrics,
    ProbeOutcome,
    RateLimitConfig,
    RateLimitVerdict,
    Scenario,
    ScenarioResult,
)


def rate_args(**overrides) -> RDPArgs:
    values = {
        "module": "rdp",
        "target": SimpleNamespace(ip="192.0.2.10", port=3389),
        "tests": None,
        "login": None,
        "password": None,
        "insecure_auth": False,
        "allow_load_test": False,
        "rate_mode": "both",
        "rate_count": 30,
        "rate_concurrency": 10,
        "rate_hold_seconds": 0.0,
        "rate_cooldown_seconds": 0.0,
        "timeout": 10000,
        "json": False,
        "debug": False,
    }
    values.update(overrides)
    return RDPArgs(**values)


def healthy_metrics(count: int = 3) -> ProbeMetrics:
    return ProbeMetrics(
        requested=count,
        attempted=count,
        accepted=count,
        outcome_counts={"accepted": count},
        median_ms=10.0,
        p95_ms=12.0,
    )


class RDPRateLimitIntegrationTests(unittest.TestCase):
    def test_legacy_engine_default_never_runs_explicit_only_tests(self):
        engine = RDP(rate_args(), Mock())
        engine.run_test = Mock()

        engine.run()

        selected = [call.args[0] for call in engine.run_test.call_args_list]
        expected = [
            code
            for code in RDP_TEST_ORDER
            if code in IMPLEMENTED_TESTS
            and code != "AUTH"
            and code not in RDP_EXPLICIT_ONLY_TESTS
        ]
        self.assertEqual(selected, expected)

    def test_rate_limit_is_guarded_before_network_activity(self):
        engine = RDP(rate_args(), Mock())
        engine._rate_probe = Mock(
            side_effect=AssertionError("network must not be reached")
        )

        result = engine._run_rate_limit_test()

        self.assertEqual(result.status, "blocked")
        self.assertIn("--allow-load-test", result.error)
        engine._rate_probe.assert_not_called()

    def test_held_connection_exposes_non_consuming_peer_liveness(self):
        client, peer = socket.socketpair()
        engine = RDP(rate_args(), Mock())
        reply = SimpleNamespace(
            selected_protocol=PROTOCOL_HYBRID,
            failure_code=None,
        )
        try:
            with (
                patch(
                    "ptsrvtester.protocols.rdp.utils.engine.socket.create_connection",
                    return_value=client,
                ),
                patch(
                    "ptsrvtester.protocols.rdp.utils.engine._read_tpkt",
                    return_value=b"reply",
                ),
                patch(
                    "ptsrvtester.protocols.rdp.utils.engine._parse_negotiation_reply_details",
                    return_value=reply,
                ),
            ):
                opened = engine._rate_open_held(Mock())

            self.assertEqual(opened.probe.outcome, ProbeOutcome.ACCEPTED)
            self.assertTrue(opened.connection.is_alive())
            peer.shutdown(socket.SHUT_RDWR)
            peer.close()
            self.assertFalse(opened.connection.is_alive())
            opened.connection.close()
        finally:
            try:
                client.close()
            except OSError:
                pass
            try:
                peer.close()
            except OSError:
                pass

    @patch("ptsrvtester.protocols.rdp.utils.engine.RateLimitRunner")
    def test_rate_limit_adapter_preserves_scenario_metrics(self, runner_class):
        scenario = ScenarioResult(
            scenario=Scenario.COMPLETED,
            verdict=RateLimitVerdict.NOT_OBSERVED,
            baseline=healthy_metrics(),
            load=healthy_metrics(5),
            recovery=healthy_metrics(),
        )
        runner_class.return_value.run_completed.return_value = scenario
        engine = RDP(
            rate_args(
                allow_load_test=True,
                rate_mode="completed",
                rate_count=5,
                rate_concurrency=2,
            ),
            Mock(),
        )

        result = engine._run_rate_limit_test()

        self.assertEqual(result.status, "not_observed")
        self.assertEqual(result.scenarios, (scenario,))
        self.assertEqual(result.probe_layer, "RDP X.224 negotiation")

    @patch("ptsrvtester.protocols.rdp.utils.engine.RateLimitRunner")
    def test_rate_limit_rejects_weak_opt_in_and_single_sample(self, runner_class):
        weak_opt_in = RDP(rate_args(allow_load_test="false"), Mock())
        too_small = RDP(rate_args(allow_load_test=True, rate_count=1), Mock())

        self.assertEqual(weak_opt_in._run_rate_limit_test().status, "blocked")
        invalid = too_small._run_rate_limit_test()
        self.assertEqual(invalid.status, "error")
        self.assertIn("between 5 and 200", invalid.error)
        runner_class.assert_not_called()

    @patch("ptsrvtester.protocols.rdp.utils.engine.RateLimitRunner")
    def test_observed_failures_are_not_claimed_as_protection(self, runner_class):
        scenario = ScenarioResult(
            scenario=Scenario.COMPLETED,
            verdict=RateLimitVerdict.LIMITING_OBSERVED,
            baseline=healthy_metrics(),
            load=ProbeMetrics(
                requested=5,
                attempted=5,
                accepted=3,
                outcome_counts={"accepted": 3, "reset": 2},
            ),
            recovery=healthy_metrics(),
        )
        runner_class.return_value.run_completed.return_value = scenario
        engine = RDP(
            rate_args(
                allow_load_test=True,
                rate_mode="completed",
                rate_count=5,
            ),
            Mock(),
        )

        result = engine._run_rate_limit_test()

        self.assertEqual(result.status, "limiting_observed")
        self.assertNotEqual(result.status, "protection_observed")

    def test_rate_metrics_summary_labels_a_skipped_phase(self):
        metrics = ProbeMetrics(
            requested=3,
            attempted=0,
            accepted=0,
            outcome_counts={},
        )

        self.assertEqual(
            RDP._rate_metrics_summary(metrics),
            "not attempted (3 configured)",
        )

    def test_json_output_contains_actionable_rate_limit_results(self):
        ptjsonlib = Mock()
        ptjsonlib.create_node_object.return_value = {"key": "rdp-node"}
        ptjsonlib.get_result_json.return_value = {}
        engine = RDP(rate_args(), ptjsonlib)
        scenario = ScenarioResult(
            scenario=Scenario.COMPLETED,
            verdict=RateLimitVerdict.NOT_OBSERVED,
            baseline=healthy_metrics(),
            load=healthy_metrics(5),
            recovery=healthy_metrics(),
        )
        engine.results.connection_limit = RDPConnectionLimitResult(
            status="not_observed",
            scenarios=(scenario,),
            mode="completed",
            config=RateLimitConfig(
                completed_connections=5,
                held_connections=5,
                concurrency=2,
                failure_threshold=2,
                min_attempts_before_stop=5,
                min_timing_samples=3,
                hold_seconds=0,
                cooldown_seconds=0,
            ),
        )

        engine.output(emit_text=False)

        properties = ptjsonlib.create_node_object.call_args.args[3]
        connection_limiting = properties["connectionLimiting"]
        self.assertEqual(connection_limiting["scenarios"][0]["load"]["accepted"], 5)
        self.assertEqual(connection_limiting["probeLayer"], "RDP X.224 negotiation")
        self.assertEqual(connection_limiting["config"]["failureThreshold"], 2)


if __name__ == "__main__":
    unittest.main()
