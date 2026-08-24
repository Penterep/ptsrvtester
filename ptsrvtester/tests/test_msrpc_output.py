import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ptsrvtester.protocols.msrpc.utils.cli import MSRPCArgs
from ptsrvtester.protocols.msrpc.utils.engine import (
    Credential,
    MSRPCResult,
    MsrpcEngine,
)


def output_args(*, json: bool = False) -> MSRPCArgs:
    return MSRPCArgs(
        module="msrpc",
        target=SimpleNamespace(ip="192.0.2.25", port=0),
        tests="ALL",
        pipes=None,
        username=None,
        password=None,
        username_file=None,
        password_file=None,
        pipe=None,
        domain=None,
        uuid=None,
        output=None,
        threads=1,
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


def output_engine(*, json: bool = False) -> tuple[MsrpcEngine, Mock]:
    ptjsonlib = Mock()
    ptjsonlib.create_node_object.return_value = {"key": "msrpc-node"}
    ptjsonlib.get_result_json.return_value = '{"status":"finished"}'
    engine = MsrpcEngine(output_args(json=json), ptjsonlib)
    engine.results = populated_results()
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
            [
                "PTV-MSRCP-SMBNULLSESSION",
                "PTV-MSRPC-WEAKPIPECREDS",
                "PTV-MSRPC-WEAKSMBCREDS",
                "PTV-MSRPC-WEAKRPCCREDS",
                "PTV-MSRPC-WEAKHTTPCREDS",
            ],
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


if __name__ == "__main__":
    unittest.main()
