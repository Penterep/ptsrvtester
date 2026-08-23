import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ptsrvtester.protocols.msrpc.utils.cli import MSRPCArgs
from ptsrvtester.protocols.msrpc.utils.engine import (
    Credential,
    MsrpcEngine,
    MSRPCResult,
)

LEGACY_VULNERABILITY_CODES = [
    "PTV-MSRCP-SMBNULLSESSION",
    "PTV-MSRPC-WEAKPIPECREDS",
    "PTV-MSRPC-WEAKSMBCREDS",
    "PTV-MSRPC-WEAKRPCCREDS",
    "PTV-MSRPC-WEAKHTTPCREDS",
]


def complete_samr_policy() -> dict:
    return {
        "status": "complete",
        "reason": None,
        "domains": [
            {
                "status": "complete",
                "name": "LAB",
                "sid": "S-1-5-21-1-2-3",
                "passwordPolicy": {
                    "minimumPasswordLength": 12,
                    "passwordHistoryLength": 24,
                    "passwordProperties": 17,
                    "unknownPasswordPropertyBits": 0,
                    "passwordPropertyFlags": [
                        "DOMAIN_PASSWORD_COMPLEX",
                        "DOMAIN_PASSWORD_STORE_CLEARTEXT",
                    ],
                    "passwordComplexityRequired": True,
                    "reversibleEncryptionEnabled": True,
                    "minimumPasswordAge": {
                        "raw100ns": -864000000000,
                        "seconds": 86400,
                        "unlimited": False,
                    },
                    "maximumPasswordAge": {
                        "raw100ns": -36288000000000,
                        "seconds": 3628800,
                        "unlimited": False,
                    },
                },
                "lockoutPolicy": {
                    "lockoutEnabled": True,
                    "lockoutThreshold": 5,
                    "lockoutDuration": {
                        "raw100ns": -6000000000,
                        "seconds": 600,
                        "unlimited": False,
                    },
                    "lockoutObservationWindow": {
                        "raw100ns": -3000000000,
                        "seconds": 300,
                        "unlimited": False,
                    },
                },
                "errors": [],
            }
        ],
    }


def complete_samr_users() -> dict:
    return {
        "status": "complete",
        "reason": None,
        "limit": 1000,
        "returned": 2,
        "truncated": False,
        "domains": [
            {
                "status": "complete",
                "reason": None,
                "name": "LAB",
                "sid": "S-1-5-21-1-2-3",
                "returned": 2,
                "truncated": False,
                "users": [
                    {
                        "name": "Administrator",
                        "rid": 500,
                        "sid": "S-1-5-21-1-2-3-500",
                    },
                    {
                        "name": "EvidenceAccount",
                        "rid": 1101,
                        "sid": "S-1-5-21-1-2-3-1101",
                    },
                ],
            }
        ],
    }


def output_args(
    *,
    json: bool = False,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
) -> MSRPCArgs:
    return MSRPCArgs(
        module="msrpc",
        target=SimpleNamespace(ip="192.0.2.25", port=0),
        tests="ALL",
        pipes=None,
        username=username,
        password=password,
        username_file=None,
        password_file=None,
        pipe=None,
        domain=domain,
        uuid=None,
        output=None,
        threads=1,
        samr_max_users=1000,
        module_threads=1,
        ip="192.0.2.25",
        port=135,
        verbose=False,
        json=json,
        debug=False,
    )


def populated_results() -> MSRPCResult:
    results = MSRPCResult(
        EpmapEndpoints={
            "12345678-1234-abcd-ef00-0123456789ab v1.0": {
                "Protocol": "Example RPC protocol",
                "EXE": "example.exe",
                "annotation": "Example service",
                "Bindings": ["ncacn_ip_tcp:192.0.2.25[49152]"],
            }
        },
        MgmtEndpoints=["12345778-1234-abcd-ef00-0123456789ab"],
        Pipes=["samr", "svcctl"],
        PipesCreds=[Credential("pipe-user", "pipe-pass")],
        Anonymous=["True", "False"],
        SMB_Brute=[Credential("smb-user", "smb-pass")],
        TCP_Brute=[Credential("rpc-user", "rpc-pass")],
        HTTP_Brute=[
            Credential("http-user", "http-pass"),
            Credential("second-user", "second-pass"),
        ],
    )
    results.module_errors = {}
    return results


def output_engine(
    *,
    json: bool = False,
    results: MSRPCResult | None = None,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
) -> tuple[MsrpcEngine, Mock]:
    ptjsonlib = Mock()
    ptjsonlib.create_node_object.return_value = {"key": "msrpc-node"}
    ptjsonlib.get_result_json.return_value = '{"status":"finished"}'
    engine = MsrpcEngine(
        output_args(
            json=json,
            username=username,
            password=password,
            domain=domain,
        ),
        ptjsonlib,
    )
    engine.results = populated_results() if results is None else results
    return engine, ptjsonlib


def vulnerability_codes(ptjsonlib: Mock) -> list[str]:
    return [
        recorded.kwargs["vuln_code"]
        for recorded in ptjsonlib.add_vulnerability.call_args_list
    ]


class MSRPCOutputTests(unittest.TestCase):
    def test_output_preserves_enum_data_credentials_and_legacy_vulnerability_codes(self):
        engine, ptjsonlib = output_engine(json=False)

        stdout = io.StringIO()
        with patch("sys.stdout", new=stdout):
            engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(properties["epmapEndpoints"], engine.results.EpmapEndpoints)
        self.assertEqual(properties["mgmtEndpoints"], engine.results.MgmtEndpoints)
        self.assertEqual(properties["pipes"], ["samr", "svcctl"])
        self.assertEqual(properties["anonymous"], "True,False")
        self.assertEqual(properties["pipesCreds"], "pipe-user:pipe-pass")
        self.assertEqual(properties["smbBrute"], "smb-user:smb-pass")
        self.assertEqual(properties["tcpBrute"], "rpc-user:rpc-pass")
        self.assertEqual(
            properties["httpBrute"],
            "http-user:http-pass, second-user:second-pass",
        )
        self.assertEqual(
            vulnerability_codes(ptjsonlib),
            LEGACY_VULNERABILITY_CODES,
        )
        responses = [
            recorded.kwargs["vuln_response"]
            for recorded in ptjsonlib.add_vulnerability.call_args_list
        ]
        self.assertEqual(
            responses,
            [
                "True,False",
                "pipe-user:pipe-pass",
                "smb-user:smb-pass",
                "rpc-user:rpc-pass",
                "http-user:http-pass, second-user:second-pass",
            ],
        )
        requests = [
            recorded.kwargs["vuln_request"]
            for recorded in ptjsonlib.add_vulnerability.call_args_list
        ]
        self.assertEqual(
            requests,
            [
                "Testing anonymous SMB access and IPC$ share.",
                "Bruteforcing credentials for specific pipes",
                "Bruteforcing SMB credentials",
                "Bruteforcing RPC credentials for specific UUID",
                "Bruteforcing HTTP credentials",
            ],
        )
        ptjsonlib.set_status.assert_called_once_with("finished", "")
        self.assertEqual(stdout.getvalue(), "")

    def test_json_is_printed_only_in_json_mode(self):
        text_engine, _ = output_engine(json=False)
        text_stdout = io.StringIO()
        with patch("sys.stdout", new=text_stdout):
            text_engine.output()
        self.assertEqual(text_stdout.getvalue(), "")

        json_engine, jsonlib = output_engine(json=True)
        json_stdout = io.StringIO()
        with patch("sys.stdout", new=json_stdout):
            json_engine.output()
        self.assertEqual(json_stdout.getvalue(), '{"status":"finished"}\n')
        jsonlib.get_result_json.assert_called_once_with()

    def test_module_errors_set_error_status_and_are_serialized(self):
        engine, ptjsonlib = output_engine(json=False)
        engine.results.module_errors = {
            "ANONSMB": "OSError: connection refused",
            "ENUMMGMT": "TimeoutError: timed out",
        }

        engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(
            properties["moduleErrors"],
            [
                {"test": "ANONSMB", "error": "OSError: connection refused"},
                {"test": "ENUMMGMT", "error": "TimeoutError: timed out"},
            ],
        )
        ptjsonlib.set_status.assert_called_once_with(
            "error", "MSRPC module failure(s): ANONSMB, ENUMMGMT"
        )

    def test_samr_policy_not_run_is_preserved_as_none(self):
        engine, ptjsonlib = output_engine(results=MSRPCResult())

        engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertIsNone(properties["samrPolicy"])
        self.assertNotIn("moduleErrors", properties)
        ptjsonlib.add_vulnerability.assert_not_called()
        ptjsonlib.set_status.assert_called_once_with("finished", "")

    def test_complete_samr_policy_is_preserved_without_a_new_vulnerability(self):
        results = populated_results()
        results.SamrPolicy = complete_samr_policy()
        engine, ptjsonlib = output_engine(results=results)

        engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(properties["samrPolicy"], results.SamrPolicy)
        self.assertEqual(vulnerability_codes(ptjsonlib), LEGACY_VULNERABILITY_CODES)
        self.assertEqual(len(ptjsonlib.add_vulnerability.call_args_list), 5)
        ptjsonlib.set_status.assert_called_once_with("finished", "")

    def test_denied_samr_policy_is_preserved_as_a_clean_result(self):
        denied = {
            "status": "denied",
            "reason": "samr_access_denied",
            "domains": [],
        }
        engine, ptjsonlib = output_engine(
            results=MSRPCResult(SamrPolicy=denied)
        )

        engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(properties["samrPolicy"], denied)
        self.assertNotIn("moduleErrors", properties)
        ptjsonlib.add_vulnerability.assert_not_called()
        ptjsonlib.set_status.assert_called_once_with("finished", "")

    def test_error_samr_policy_and_module_error_are_preserved(self):
        error_result = {
            "status": "error",
            "reason": "operational_error",
            "domains": [],
        }
        results = MSRPCResult(SamrPolicy=error_result)
        results.module_errors = {
            "SAMRPOLICY": "OSError: SAMR transport failed"
        }
        engine, ptjsonlib = output_engine(results=results)

        engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(properties["samrPolicy"], error_result)
        self.assertEqual(
            properties["moduleErrors"],
            [
                {
                    "test": "SAMRPOLICY",
                    "error": "OSError: SAMR transport failed",
                }
            ],
        )
        ptjsonlib.add_vulnerability.assert_not_called()
        ptjsonlib.set_status.assert_called_once_with(
            "error", "MSRPC module failure(s): SAMRPOLICY"
        )

    def test_samr_policy_json_does_not_serialize_supplied_credentials(self):
        username = "SensitiveAuditUser"
        password = "NeverPrint-7f9!"
        results = MSRPCResult(SamrPolicy=complete_samr_policy())
        engine, ptjsonlib = output_engine(
            json=True,
            results=results,
            username=username,
            password=password,
        )

        def serialized_result() -> str:
            properties = ptjsonlib.create_node_object.call_args.args[3]
            return json.dumps({"properties": properties}, sort_keys=True)

        ptjsonlib.get_result_json.side_effect = serialized_result
        stdout = io.StringIO()
        with patch("sys.stdout", new=stdout):
            engine.output()

        serialized = stdout.getvalue()
        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(properties["samrPolicy"], results.SamrPolicy)
        self.assertNotIn(username, serialized)
        self.assertNotIn(password, serialized)
        self.assertNotIn(username, json.dumps(properties, sort_keys=True))
        self.assertNotIn(password, json.dumps(properties, sort_keys=True))
        ptjsonlib.add_vulnerability.assert_not_called()
        ptjsonlib.get_result_json.assert_called_once_with()

    def test_samr_users_not_run_is_preserved_as_none(self):
        engine, ptjsonlib = output_engine(results=MSRPCResult())

        engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertIsNone(properties["samrUsers"])
        self.assertNotIn("moduleErrors", properties)
        ptjsonlib.add_vulnerability.assert_not_called()
        ptjsonlib.set_status.assert_called_once_with("finished", "")

    def test_complete_samr_users_is_preserved_without_a_new_vulnerability(self):
        results = populated_results()
        results.SamrUsers = complete_samr_users()
        engine, ptjsonlib = output_engine(results=results)

        engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(properties["samrUsers"], results.SamrUsers)
        self.assertEqual(vulnerability_codes(ptjsonlib), LEGACY_VULNERABILITY_CODES)
        self.assertEqual(len(ptjsonlib.add_vulnerability.call_args_list), 5)
        ptjsonlib.set_status.assert_called_once_with("finished", "")

    def test_limit_partial_samr_users_is_a_clean_finished_result(self):
        partial = {
            "status": "partial",
            "reason": "limit_reached",
            "limit": 1,
            "returned": 1,
            "truncated": True,
            "domains": [
                {
                    "status": "partial",
                    "reason": "limit_reached",
                    "name": "LAB",
                    "sid": "S-1-5-21-1-2-3",
                    "returned": 1,
                    "truncated": True,
                    "users": [
                        {
                            "name": "Administrator",
                            "rid": 500,
                            "sid": "S-1-5-21-1-2-3-500",
                        }
                    ],
                }
            ],
        }
        engine, ptjsonlib = output_engine(
            results=MSRPCResult(SamrUsers=partial)
        )

        engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(properties["samrUsers"], partial)
        self.assertNotIn("moduleErrors", properties)
        ptjsonlib.add_vulnerability.assert_not_called()
        ptjsonlib.set_status.assert_called_once_with("finished", "")

    def test_denied_samr_users_is_preserved_as_a_clean_result(self):
        denied = {
            "status": "denied",
            "reason": "authentication_denied",
            "limit": 1000,
            "returned": 0,
            "truncated": False,
            "domains": [],
        }
        engine, ptjsonlib = output_engine(
            results=MSRPCResult(SamrUsers=denied)
        )

        engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(properties["samrUsers"], denied)
        self.assertNotIn("moduleErrors", properties)
        ptjsonlib.add_vulnerability.assert_not_called()
        ptjsonlib.set_status.assert_called_once_with("finished", "")

    def test_error_samr_users_and_module_error_are_preserved(self):
        error_result = {
            "status": "error",
            "reason": "operational_error",
            "limit": 1000,
            "returned": 0,
            "truncated": False,
            "domains": [],
        }
        results = MSRPCResult(SamrUsers=error_result)
        results.module_errors = {
            "SAMRUSERS": "OSError: SAMR transport failed"
        }
        engine, ptjsonlib = output_engine(results=results)

        engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(properties["samrUsers"], error_result)
        self.assertEqual(
            properties["moduleErrors"],
            [
                {
                    "test": "SAMRUSERS",
                    "error": "OSError: SAMR transport failed",
                }
            ],
        )
        ptjsonlib.add_vulnerability.assert_not_called()
        ptjsonlib.set_status.assert_called_once_with(
            "error", "MSRPC module failure(s): SAMRUSERS"
        )

    def test_samr_users_error_redacts_auth_secrets_but_keeps_user_evidence(self):
        username = "SensitiveAuditUser"
        password = "NeverPrint-7f9!"
        domain = "SensitiveAuthDomain"
        result = complete_samr_users()
        result.update(status="error", reason="operational_error")
        results = MSRPCResult(SamrUsers=result)
        engine, ptjsonlib = output_engine(
            json=True,
            results=results,
            username=username,
            password=password,
            domain=domain,
        )
        raw_error = RuntimeError(
            f"SAMR failed for {domain}\\{username} with {password}"
        )
        results.module_errors = {
            "SAMRUSERS": engine._sanitized_samr_error(raw_error)
        }

        def serialized_result() -> str:
            properties = ptjsonlib.create_node_object.call_args.args[3]
            return json.dumps({"properties": properties}, sort_keys=True)

        ptjsonlib.get_result_json.side_effect = serialized_result
        stdout = io.StringIO()
        with patch("sys.stdout", new=stdout):
            engine.output()

        properties = ptjsonlib.create_node_object.call_args.args[3]
        serialized_properties = json.dumps(properties, sort_keys=True)
        serialized_stdout = stdout.getvalue()
        error_text = properties["moduleErrors"][0]["error"]
        for secret in (username, password, domain):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, error_text)
                self.assertNotIn(secret, serialized_properties)
                self.assertNotIn(secret, serialized_stdout)
        self.assertIn("[redacted]", error_text)
        self.assertIn("EvidenceAccount", serialized_properties)
        self.assertIn("EvidenceAccount", serialized_stdout)
        self.assertEqual(properties["samrUsers"], result)
        ptjsonlib.add_vulnerability.assert_not_called()
        ptjsonlib.set_status.assert_called_once_with(
            "error", "MSRPC module failure(s): SAMRUSERS"
        )
        ptjsonlib.get_result_json.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
