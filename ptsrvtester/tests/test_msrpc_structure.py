import argparse
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from setuptools import find_packages

from ptsrvtester.protocols.msrpc import MSRPC
from ptsrvtester.protocols.msrpc.main import MSRPC as MSRPCMain
from ptsrvtester.protocols.msrpc.utils.cli import MSRPCArgs
from ptsrvtester.protocols.msrpc.utils.registry import (
    MSRPC_DEFAULT_SUITE,
    MSRPC_EXPLICIT_ONLY_TESTS,
    MSRPC_TEST_ORDER,
)
from ptsrvtester.ptsrvtester import MODULES


EXPECTED_TEST_ORDER = (
    "ENUMEPM",
    "ENUMMGMT",
    "ENUMPIPES",
    "ANONSMB",
    "BRUTEPIPE",
    "BRUTESMB",
    "BRUTETCP",
    "BRUTEHTTP",
)
EXPECTED_SAFE_SUITE = (
    "ENUMEPM",
    "ENUMMGMT",
    "ENUMPIPES",
    "ANONSMB",
)
EXPECTED_BRUTE_TESTS = frozenset(
    {"BRUTEPIPE", "BRUTESMB", "BRUTETCP", "BRUTEHTTP"}
)


def structure_args(**overrides) -> MSRPCArgs:
    values = {
        "module": "msrpc",
        "target": SimpleNamespace(ip="192.0.2.10", port=0),
        "tests": None,
        "pipes": None,
        "username": None,
        "password": None,
        "username_file": None,
        "password_file": None,
        "pipe": None,
        "domain": None,
        "uuid": None,
        "output": None,
        "threads": 10,
        "max_attempts": 1000,
        "timeout_seconds": 5.0,
        "module_threads": 8,
        "json": False,
        "debug": False,
    }
    values.update(overrides)
    return MSRPCArgs(**values)


def structure_main(**overrides) -> MSRPC:
    engine = Mock(name="shared_msrpc_engine")
    with patch(
        "ptsrvtester.protocols.msrpc.main.MsrpcEngine",
        return_value=engine,
    ):
        module = MSRPC(structure_args(**overrides), Mock())
    return module


class MSRPCStructureTests(unittest.TestCase):
    def test_public_entrypoint_and_registry_expose_exactly_eight_tests(self):
        self.assertIs(MSRPC, MSRPCMain)
        self.assertEqual(
            MODULES["msrpc"][0],
            "ptsrvtester.protocols.msrpc:MSRPC",
        )
        self.assertEqual(MSRPC_TEST_ORDER, EXPECTED_TEST_ORDER)
        self.assertEqual(MSRPC_DEFAULT_SUITE, EXPECTED_SAFE_SUITE)
        self.assertEqual(MSRPC_EXPLICIT_ONLY_TESTS, EXPECTED_BRUTE_TESTS)

        module = structure_main()
        discovered = module._discover_modules()
        discovered_in_order = tuple(
            sorted(discovered, key=lambda code: (discovered[code].order, code))
        )

        self.assertEqual(discovered_in_order, EXPECTED_TEST_ORDER)
        self.assertEqual(set(discovered), set(EXPECTED_TEST_ORDER))
        self.assertEqual(len(discovered), 8)
        self.assertEqual(len({entry.order for entry in discovered.values()}), 8)

    def test_modules_package_is_included_by_setuptools_discovery(self):
        self.assertIn("ptsrvtester.protocols.msrpc.modules", find_packages())

    def test_omitted_tests_and_all_select_only_the_safe_suite(self):
        for selected in (None, "ALL", "all"):
            with self.subTest(selected=selected):
                module = structure_main(tests=selected)
                self.assertEqual(
                    module._select_codes(module._discover_modules()),
                    list(EXPECTED_SAFE_SUITE),
                )

    def test_all_plus_named_brute_expands_safe_suite_and_keeps_the_brute(self):
        module = structure_main(
            tests="ALL,BRUTESMB",
            username="audit-user",
            password="audit-password",
        )

        self.assertEqual(
            module._select_codes(module._discover_modules()),
            [*EXPECTED_SAFE_SUITE, "BRUTESMB"],
        )

    def test_brute_tests_are_never_implicitly_selected(self):
        module = structure_main(tests="ALL")
        selected = module._select_codes(module._discover_modules())

        self.assertTrue(MSRPC_EXPLICIT_ONLY_TESTS.isdisjoint(selected))

    def test_shared_engine_is_reused_and_module_execution_is_forced_serial(self):
        module = structure_main(module_threads=100)

        first = module.build_context()
        second = module.build_context()

        self.assertIs(first["engine"], second["engine"])
        self.assertIs(first["engine"], module.engine)
        self.assertEqual(module._thread_count(), 1)

    def test_main_rejects_invalid_brute_selection_before_any_probe_can_run(self):
        with patch("ptsrvtester.protocols.msrpc.main.MsrpcEngine") as engine_class:
            with self.assertRaises(argparse.ArgumentError):
                MSRPC(structure_args(tests="BRUTESMB"), Mock())

        engine_class.assert_not_called()

    def test_selected_adapter_import_failure_is_reported_not_silently_skipped(self):
        module = structure_main(tests="ENUMEPM")
        discovered = module._discover_modules()
        del discovered["ENUMEPM"]

        self.assertEqual(module._select_codes(discovered), [])
        module.engine.record_module_error.assert_called_once_with(
            "DISCOVERY", "Selected MSRPC adapter(s) could not be loaded: ENUMEPM"
        )
        module.ptjsonlib.end_error.assert_called_once_with(
            "Selected MSRPC adapter(s) could not be loaded: ENUMEPM", False
        )


if __name__ == "__main__":
    unittest.main()
