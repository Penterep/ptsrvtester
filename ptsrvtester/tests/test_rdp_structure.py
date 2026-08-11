import argparse
import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from ptsrvtester.protocols.rdp import RDP
from ptsrvtester.protocols.rdp.main import RDP as RDPMain
from ptsrvtester.protocols.rdp.utils.cli import RDP_EXPLICIT_ONLY_TESTS, RDPArgs
from ptsrvtester.protocols.rdp.utils.engine import RDP_TEST_ORDER, NLAResult
from ptsrvtester.ptsrvtester import MODULES


def structure_args(**overrides) -> RDPArgs:
    values = {
        "module": "rdp",
        "target": SimpleNamespace(ip="192.0.2.10", port=0),
        "tests": None,
        "login": None,
        "password": None,
        "insecure_auth": False,
        "allow_load_test": False,
        "rate_mode": "both",
        "rate_count": 30,
        "rate_concurrency": 10,
        "rate_hold_seconds": 3.0,
        "rate_cooldown_seconds": 2.0,
        "timeout": 10000,
        "module_threads": 8,
        "json": False,
        "debug": False,
    }
    values.update(overrides)
    return RDPArgs(**values)


def structure_main(**overrides) -> RDP:
    return RDP(structure_args(**overrides), Mock())


def parse_rdp_args(*arguments: str) -> RDPArgs:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="module", required=True)
    RDPArgs().add_subparser("rdp", subparsers)
    return parser.parse_args(
        ["rdp", "192.0.2.10", *arguments],
        namespace=RDPArgs(),
    )


class RDPRateLimitCLIParserTests(unittest.TestCase):
    def assert_parse_rejected(self, *arguments: str) -> None:
        with (
            patch("sys.stderr", new=io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            parse_rdp_args(*arguments)
        self.assertNotEqual(raised.exception.code, 0)

    def test_rate_options_have_safe_defaults_and_no_implicit_opt_in(self):
        args = parse_rdp_args()

        self.assertIsNone(args.tests)
        self.assertFalse(args.allow_load_test)
        self.assertEqual(args.rate_mode, "both")
        self.assertEqual(args.rate_count, 30)
        self.assertEqual(args.rate_concurrency, 10)
        self.assertEqual(args.rate_hold_seconds, 3.0)
        self.assertEqual(args.rate_cooldown_seconds, 2.0)

    def test_rate_options_parse_at_upper_safety_boundaries(self):
        args = parse_rdp_args(
            "-ts",
            "RATELIMIT",
            "--allow-load-test",
            "--rate-mode",
            "held",
            "--rate-count",
            "200",
            "--rate-concurrency",
            "50",
            "--rate-hold-seconds",
            "30",
            "--rate-cooldown-seconds",
            "60",
        )

        self.assertEqual(args.tests, ["RATELIMIT"])
        self.assertTrue(args.allow_load_test)
        self.assertEqual(args.rate_mode, "held")
        self.assertEqual(args.rate_count, 200)
        self.assertEqual(args.rate_concurrency, 50)
        self.assertEqual(args.rate_hold_seconds, 30.0)
        self.assertEqual(args.rate_cooldown_seconds, 60.0)

    def test_rate_options_accept_lower_safety_boundaries(self):
        args = parse_rdp_args(
            "--rate-count",
            "5",
            "--rate-concurrency",
            "1",
            "--rate-hold-seconds",
            "0",
            "--rate-cooldown-seconds",
            "0",
        )

        self.assertEqual(args.rate_count, 5)
        self.assertEqual(args.rate_concurrency, 1)
        self.assertEqual(args.rate_hold_seconds, 0.0)
        self.assertEqual(args.rate_cooldown_seconds, 0.0)

    def test_invalid_rate_choices_and_ranges_are_rejected(self):
        invalid_values = (
            ("--rate-mode", "burst"),
            ("--rate-count", "4"),
            ("--rate-count", "201"),
            ("--rate-concurrency", "0"),
            ("--rate-concurrency", "51"),
            ("--rate-hold-seconds", "-0.1"),
            ("--rate-hold-seconds", "30.1"),
            ("--rate-hold-seconds", "nan"),
            ("--rate-cooldown-seconds", "-0.1"),
            ("--rate-cooldown-seconds", "60.1"),
            ("--rate-cooldown-seconds", "inf"),
        )
        for option, value in invalid_values:
            with self.subTest(option=option, value=value):
                self.assert_parse_rejected(option, value)

    def test_load_opt_in_does_not_accept_a_boolean_value(self):
        self.assert_parse_rejected("--allow-load-test=false")


class RDPStructureTests(unittest.TestCase):
    def test_public_entrypoint_and_discovery_expose_all_ten_tests(self):
        self.assertIs(RDP, RDPMain)
        self.assertEqual(MODULES["rdp"][0], "ptsrvtester.protocols.rdp:RDP")

        module = structure_main()
        discovered = module._discover_modules()

        self.assertEqual(set(discovered), set(RDP_TEST_ORDER))
        self.assertEqual(
            sorted(discovered, key=lambda code: (discovered[code].order, code)),
            list(RDP_TEST_ORDER),
        )
        self.assertEqual(len({entry.order for entry in discovered.values()}), 10)

    def test_selection_accepts_list_and_comma_forms_with_alias_and_deduplication(self):
        expected = ["SSL", "NTLMINFO", "NLA"]
        for selected in (
            ["ssl", "INFO", "ssl", "NLA"],
            "ssl,INFO,ssl,NLA",
        ):
            with self.subTest(selected=selected):
                module = structure_main(tests=selected)
                self.assertEqual(
                    module._select_codes(module._discover_modules()),
                    expected,
                )

    def test_default_selection_keeps_auth_behind_complete_credentials(self):
        pre_auth = [
            code
            for code in RDP_TEST_ORDER
            if code != "AUTH" and code not in RDP_EXPLICIT_ONLY_TESTS
        ]
        with_auth = [
            code for code in RDP_TEST_ORDER if code not in RDP_EXPLICIT_ONLY_TESTS
        ]
        cases = (
            ({}, pre_auth),
            ({"login": "EXAMPLE\\tester"}, pre_auth),
            ({"password": "secret"}, pre_auth),
            (
                {"login": "EXAMPLE\\tester", "password": "secret"},
                with_auth,
            ),
        )

        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                module = structure_main(**overrides)
                self.assertEqual(
                    module._select_codes(module._discover_modules()),
                    expected,
                )

    def test_all_excludes_ratelimit_and_remembers_full_selection(self):
        module = structure_main(tests="ALL")

        selected = module._select_codes(module._discover_modules())

        expected = [
            code for code in RDP_TEST_ORDER if code not in RDP_EXPLICIT_ONLY_TESTS
        ]
        self.assertEqual(selected, expected)
        self.assertEqual(
            module.args._rdp_selected_tests,
            frozenset(expected),
        )

    def test_ratelimit_named_alongside_all_remains_explicit(self):
        module = structure_main(tests="ALL,RATELIMIT")

        selected = module._select_codes(module._discover_modules())

        self.assertEqual(selected[-1], "RATELIMIT")
        self.assertEqual(selected.count("RATELIMIT"), 1)

    def test_ratelimit_is_forced_last_and_engine_uses_one_resolved_ip(self):
        module = structure_main(tests="RATELIMIT,NLA")

        self.assertEqual(
            module._select_codes(module._discover_modules()),
            ["NLA", "RATELIMIT"],
        )
        self.assertEqual(module.rdp_engine.connect_host, module.target[0])

    def test_context_reuses_one_engine_and_execution_is_serial(self):
        module = structure_main()

        first = module.build_context()
        second = module.build_context()

        self.assertIs(first["rdp_engine"], second["rdp_engine"])
        self.assertIs(first["rdp_engine"], module.rdp_engine)
        self.assertEqual(module._thread_count(), 1)

    def test_each_discovered_adapter_dispatches_its_own_code(self):
        module = structure_main()
        discovered = module._discover_modules()
        engine = Mock()
        context = SimpleNamespace(rdp_engine=engine)

        for code in RDP_TEST_ORDER:
            with self.subTest(code=code):
                engine.reset_mock()
                discovered[code].module.run(context)
                engine.run_module.assert_called_once_with(code, context)

    def test_basemain_run_dispatches_selected_adapters_in_legacy_order(self):
        module = structure_main(tests="SSL,NLA")
        engine = Mock()
        module.rdp_engine = engine

        with patch("sys.stdout", new=io.StringIO()):
            module.run()

        self.assertEqual(
            engine.run_module.call_args_list,
            [call("SSL", unittest.mock.ANY), call("NLA", unittest.mock.ANY)],
        )

    def test_unexpected_adapter_error_is_structured_and_marks_output_failed(self):
        ptjsonlib = Mock()
        ptjsonlib.create_node_object.return_value = {"key": "rdp-test-node"}
        login = "EXAMPLE\\sensitive-user"
        password = "SuperSecretPassword"
        module = RDP(
            structure_args(tests="NLA", login=login, password=password),
            ptjsonlib,
        )
        module.rdp_engine.run_test = Mock(
            side_effect=RuntimeError(
                f"probe exploded for {login} using {password}"
            )
        )

        text_output = io.StringIO()
        with patch("sys.stdout", new=text_output):
            module.run()
            module.output()

        self.assertEqual(
            module.rdp_engine.results.module_errors,
            {
                "NLA": (
                    "RuntimeError: probe exploded for <redacted> "
                    "using <redacted>"
                )
            },
        )
        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(
            properties["moduleErrors"],
            [
                {
                    "test": "NLA",
                    "error": (
                        "RuntimeError: probe exploded for <redacted> "
                        "using <redacted>"
                    ),
                }
            ],
        )
        self.assertNotIn(login, text_output.getvalue())
        self.assertNotIn(password, text_output.getvalue())
        self.assertNotIn(login, str(properties))
        self.assertNotIn(password, str(properties))
        ptjsonlib.set_status.assert_called_once_with(
            "error", "RDP module failure(s): NLA"
        )

    def test_output_is_finalized_once_by_the_shared_engine(self):
        module = structure_main()
        engine = module.build_context()["rdp_engine"]
        engine.output = Mock()

        module.output()

        engine.output.assert_called_once_with(emit_text=False)

    def test_adapter_reporting_suppresses_the_duplicate_engine_heading(self):
        module = structure_main()
        engine = module.rdp_engine
        engine.results.nla = NLAResult("required", [])
        context = Mock()

        engine.emit_test_output("NLA", context)

        messages = [call.args[0] for call in context.out.call_args_list]
        self.assertNotIn("Network Level Authentication (NLA) test", messages)
        self.assertTrue(any("NLA required" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
