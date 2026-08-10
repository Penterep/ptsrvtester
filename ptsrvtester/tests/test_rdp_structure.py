import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from ptsrvtester.protocols.rdp import RDP
from ptsrvtester.protocols.rdp.main import RDP as RDPMain
from ptsrvtester.protocols.rdp.utils.cli import RDPArgs
from ptsrvtester.protocols.rdp.utils.engine import NLAResult, RDP_TEST_ORDER


def structure_args(**overrides) -> RDPArgs:
    values = {
        "module": "rdp",
        "target": SimpleNamespace(ip="192.0.2.10", port=0),
        "tests": None,
        "login": None,
        "password": None,
        "insecure_auth": False,
        "timeout": 10000,
        "module_threads": 8,
        "json": False,
        "debug": False,
    }
    values.update(overrides)
    return RDPArgs(**values)


def structure_main(**overrides) -> RDP:
    return RDP(structure_args(**overrides), Mock())


class RDPStructureTests(unittest.TestCase):
    def test_public_entrypoint_and_discovery_expose_all_nine_tests(self):
        self.assertIs(RDP, RDPMain)

        module = structure_main()
        discovered = module._discover_modules()

        self.assertEqual(set(discovered), set(RDP_TEST_ORDER))
        self.assertEqual(
            sorted(discovered, key=lambda code: (discovered[code].order, code)),
            list(RDP_TEST_ORDER),
        )
        self.assertEqual(len({entry.order for entry in discovered.values()}), 9)

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
        pre_auth = [code for code in RDP_TEST_ORDER if code != "AUTH"]
        cases = (
            ({}, pre_auth),
            ({"login": "EXAMPLE\\tester"}, pre_auth),
            ({"password": "secret"}, pre_auth),
            (
                {"login": "EXAMPLE\\tester", "password": "secret"},
                list(RDP_TEST_ORDER),
            ),
        )

        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                module = structure_main(**overrides)
                self.assertEqual(
                    module._select_codes(module._discover_modules()),
                    expected,
                )

    def test_all_selects_every_module_and_remembers_full_selection(self):
        module = structure_main(tests="ALL")

        selected = module._select_codes(module._discover_modules())

        self.assertEqual(selected, list(RDP_TEST_ORDER))
        self.assertEqual(
            module.args._rdp_selected_tests,
            frozenset(RDP_TEST_ORDER),
        )

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
