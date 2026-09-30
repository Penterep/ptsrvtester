import argparse
import io
import json
import unittest
from unittest.mock import patch

from ptsrvtester.tests.test_msrpc_cli import validated_args, parse_msrpc_args
from ptsrvtester.tests.test_msrpc_engine import msrpc_main


class InventoryIntegrationTests(unittest.TestCase):
    def test_new_adapters_execute_and_publish_data_without_new_ptv(self):
        module, report = msrpc_main(tests="SAMRGROUPS,SAMRUSERINFO")
        groups = {"status": "partial", "domains": [{"name": "BUILTIN", "groups": []}]}
        user_info = {"status": "denied", "reason": "access_denied", "domains": []}
        with patch("ptsrvtester.protocols.msrpc.utils.samr_groups.enumerate_samr_groups", return_value=groups) as group_call, \
                patch("ptsrvtester.protocols.msrpc.utils.samr_userinfo.query_samr_user_info", return_value=user_info) as info_call, \
                patch("sys.stdout", new=io.StringIO()):
            module.run()
            module.output()
        group_call.assert_called_once_with(module.engine)
        info_call.assert_called_once_with(module.engine)
        properties = report.create_node_object.call_args.args[3]
        self.assertEqual(properties["samrGroups"], groups)
        self.assertEqual(properties["samrUserInfo"], user_info)
        self.assertNotIn("secret", json.dumps(properties))
        report.add_vulnerability.assert_not_called()

    def test_new_selection_remains_explicit_and_direct_credentials_only(self):
        for code in ("SAMRGROUPS", "SAMRUSERINFO"):
            with self.subTest(code=code):
                with self.assertRaises(argparse.ArgumentError):
                    validated_args("-tg", "192.0.2.20", "-ts", f"ALL,{code}")
                args = validated_args("-tg", "192.0.2.20:1445", "-ts", code, "-u", "auditor", "-pw", "secret")
                self.assertEqual(args.target.port, 1445)
        module, _ = msrpc_main(tests="ALL")
        self.assertNotIn("SAMRGROUPS", module.selected_tests)
        self.assertNotIn("SAMRUSERINFO", module.selected_tests)

    def test_inventory_limits_and_name_filters_are_validated(self):
        for flag in ("--samr-max-groups", "--samr-max-members", "--samr-max-users"):
            for value in ("0", "10001", "bad"):
                with self.subTest(flag=flag, value=value), patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
                    parse_msrpc_args("-tg", "192.0.2.20", flag, value)
        for flag in ("--samr-user", "--samr-domain"):
            with self.subTest(flag=flag), self.assertRaises(argparse.ArgumentError):
                validated_args("-tg", "192.0.2.20", "-ts", "ENUMEPM", flag, "alice")
        args = validated_args("-tg", "192.0.2.20", "-ts", "SAMRUSERINFO", "-u", "auditor", "-pw", "secret",
                              "--samr-user", "alice", "--samr-domain", "SERVER", "--domain", "AUTHDOMAIN")
        self.assertEqual(args.samr_domain, "SERVER")
        self.assertEqual(args.domain, "AUTHDOMAIN")

    def test_unsupported_rpc_uuid_fails_before_target_resolution(self):
        with patch("ptsrvtester.protocols.msrpc.main.socket.gethostbyname") as dns:
            with self.assertRaisesRegex(argparse.ArgumentError, "no read-only confirmation"):
                validated_args("-tg", "unresolved.test:135", "-ts", "BRUTETCP", "-u", "auditor", "-pw", "secret",
                               "--uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:1.0")
        dns.assert_not_called()
