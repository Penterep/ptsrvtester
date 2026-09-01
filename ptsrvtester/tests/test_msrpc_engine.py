import argparse
import io
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from impacket import uuid as impacket_uuid
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT
from impacket.dcerpc.v5.rpch import RPCProxyClientException
from impacket.http import AUTH_NTLM
from impacket.nt_errors import (
    STATUS_ACCESS_DENIED,
    STATUS_LOGON_FAILURE,
    STATUS_OBJECT_NAME_NOT_FOUND,
)
from impacket.smbconnection import SessionError

from ptsrvtester.protocols.msrpc.main import MSRPC
from ptsrvtester.protocols.msrpc.utils.cli import MSRPCArgs
from ptsrvtester.protocols.msrpc.utils.engine import (
    Credential,
    MsrpcEngine,
    _AttemptResult,
)


TEST_IP = "192.0.2.25"
TEST_INTERFACE_UUID = "12345778-1234-abcd-ef00-0123456789ab"
TEST_INTERFACE = f"{TEST_INTERFACE_UUID}:1.0"


def msrpc_args(**overrides) -> MSRPCArgs:
    values = {
        "module": "msrpc",
        "target": SimpleNamespace(ip=TEST_IP, port=0),
        "tests": None,
        "pipes": None,
        "username": "alice",
        "password": "secret",
        "username_file": None,
        "password_file": None,
        "pipe": "samr",
        "domain": "EXAMPLE",
        "uuid": TEST_INTERFACE,
        "output": None,
        "threads": 1,
        "max_attempts": 1000,
        "timeout_seconds": 5.0,
        "module_threads": 1,
        "ip": TEST_IP,
        "port": 0,
        "verbose": False,
        "json": False,
        "debug": False,
    }
    values.update(overrides)
    return MSRPCArgs(**values)


def msrpc_main(**overrides) -> tuple[MSRPC, Mock]:
    ptjsonlib = Mock()
    ptjsonlib.create_node_object.return_value = {"key": "msrpc-node"}
    ptjsonlib.get_result_json.return_value = '{"status":"finished"}'
    module = MSRPC(msrpc_args(**overrides), ptjsonlib)
    return module, ptjsonlib


def rpc_transport() -> tuple[Mock, Mock]:
    rpc_transport_mock = Mock()
    dce = Mock()
    rpc_transport_mock.get_dce_rpc.return_value = dce
    return rpc_transport_mock, dce


class MSRPCPortRoutingTests(unittest.TestCase):
    def test_mixed_default_families_use_rpc_135_smb_445_and_http_443(self):
        module, _ = msrpc_main(tests="ENUMEPM,ANONSMB,BRUTEHTTP")
        engine = module.engine

        epm_transport, epm_dce = rpc_transport()
        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=epm_transport,
            ) as factory,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.epm.hept_lookup",
                return_value=[],
            ),
        ):
            self.assertEqual(engine.enumerate_epm(), {})
        factory.assert_called_once_with(f"ncacn_ip_tcp:{TEST_IP}[135]")
        epm_transport.set_connect_timeout.assert_called_once_with(5.0)
        epm_dce.disconnect.assert_called_once_with()

        smb = Mock()
        smb.listShares.return_value = []
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=smb,
        ) as connection:
            self.assertEqual(engine.Anonymous_smb(), ["True", "True"])
        self.assertEqual(connection.call_args.kwargs["sess_port"], 445)
        smb.logoff.assert_called_once_with()

        http_transport, http_dce = rpc_transport()
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
            return_value=http_transport,
        ) as factory:
            self.assertEqual(
                engine.http_brute(),
                [("alice", "secret")],
            )
        factory.assert_called_once_with(
            f"ncacn_http:[593,RpcProxy={TEST_IP}:443]"
        )
        http_transport.set_credentials.assert_called_once_with(
            "alice", "secret", "EXAMPLE"
        )
        http_transport.set_auth_type.assert_called_once_with(AUTH_NTLM)
        http_transport.set_connect_timeout.assert_called_once_with(5.0)
        http_dce.set_credentials.assert_called_once_with(
            "alice", "secret", "EXAMPLE"
        )
        http_dce.set_auth_type.assert_called_once_with(RPC_C_AUTHN_WINNT)
        http_dce.disconnect.assert_called_once_with()

    def test_single_family_honours_custom_target_port(self):
        rpc_module, _ = msrpc_main(
            tests="ENUMEPM",
            target=SimpleNamespace(ip=TEST_IP, port=1135),
        )
        rpc_mock, _ = rpc_transport()
        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ) as rpc_factory,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.epm.hept_lookup",
                return_value=[],
            ),
        ):
            rpc_module.engine.enumerate_epm()
        rpc_factory.assert_called_once_with(f"ncacn_ip_tcp:{TEST_IP}[1135]")

        smb_module, _ = msrpc_main(
            tests="ANONSMB",
            target=SimpleNamespace(ip=TEST_IP, port=1445),
        )
        smb = Mock()
        smb.listShares.return_value = []
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=smb,
        ) as smb_connection:
            smb_module.engine.Anonymous_smb()
        self.assertEqual(smb_connection.call_args.kwargs["sess_port"], 1445)

        http_module, _ = msrpc_main(
            tests="BRUTEHTTP",
            target=SimpleNamespace(ip=TEST_IP, port=80),
        )
        http_transport, _ = rpc_transport()
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
            return_value=http_transport,
        ) as http_factory:
            http_module.engine.http_brute()
        http_factory.assert_called_once_with(
            f"ncacn_http:[593,RpcProxy={TEST_IP}:80]"
        )

    def test_custom_port_with_mixed_transport_families_is_rejected(self):
        with self.assertRaises(argparse.ArgumentError):
            msrpc_main(
                tests="ENUMEPM,ANONSMB",
                target=SimpleNamespace(ip=TEST_IP, port=31337),
            )


class MSRPCStructuredProbeTests(unittest.TestCase):
    def test_epm_returns_structured_endpoint_data(self):
        module, _ = msrpc_main(tests="ENUMEPM")
        rpc_mock, dce = rpc_transport()
        endpoint = "12345678-1234-abcd-ef00-0123456789ab v1.0"
        floor = MagicMock()
        floor.__str__ = Mock(return_value=endpoint)
        entry = {
            "tower": {"Floors": [floor]},
            "annotation": b"Example service\x00",
        }

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.epm.hept_lookup",
                return_value=[entry],
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.epm.PrintStringBinding",
                return_value="ncacn_ip_tcp:192.0.2.25[49152]",
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.uuid.string_to_uuidtup",
                return_value=(endpoint[:36], "1.0"),
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.uuid.uuidtup_to_bin",
                return_value=b"unknown-interface!!",
            ),
            patch.dict(
                "ptsrvtester.protocols.msrpc.utils.engine.epm.KNOWN_PROTOCOLS",
                {endpoint[:36]: "Example RPC protocol"},
                clear=True,
            ),
            patch.dict(
                "ptsrvtester.protocols.msrpc.utils.engine.epm.KNOWN_UUIDS",
                {},
                clear=True,
            ),
        ):
            result = module.engine.enumerate_epm()

        self.assertEqual(
            result,
            {
                endpoint: {
                    "Bindings": ["ncacn_ip_tcp:192.0.2.25[49152]"],
                    "EXE": "N/A",
                    "annotation": "Example service",
                    "Protocol": "Example RPC protocol",
                }
            },
        )
        dce.disconnect.assert_called_once_with()

    def test_mgmt_pipes_and_anonymous_return_structured_results(self):
        module, _ = msrpc_main(tests="ENUMMGMT,ENUMPIPES,ANONSMB")
        engine = module.engine

        rpc_mock, dce = rpc_transport()
        interface_data = Mock()
        interface_data.getData.return_value = b"interface"
        ifids = {
            "if_id_vector": {
                "count": 1,
                "if_id": [{"Data": interface_data}],
            }
        }
        dangerous_uuid = "12345778-1234-abcd-ef00-0123456789ab"
        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.mgmt.hinq_if_ids",
                return_value=ifids,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.uuid.bin_to_uuidtup",
                return_value=(dangerous_uuid.upper(), "1.0"),
            ),
        ):
            self.assertEqual(engine.enumerate_mgmt(), [dangerous_uuid])
        dce.disconnect.assert_called_once_with()

        engine.args.pipes = ["samr", "svcctl"]
        engine.try_authenticated_pipe_bind = Mock(side_effect=[True, False])
        self.assertEqual(engine.enumerate_pipes(), ["samr"])

        smb = Mock()
        smb.listShares.return_value = [{"shi1_netname": "IPC$\x00"}]
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=smb,
        ):
            self.assertEqual(engine.Anonymous_smb(), ["True", "True"])


class MSRPCAnonymousClassificationTests(unittest.TestCase):
    def test_authentication_denial_is_a_clean_non_vulnerable_result(self):
        module, _ = msrpc_main(tests="ANONSMB")
        module.engine.ptprint = Mock()
        smb = Mock()
        smb.login.side_effect = SessionError(STATUS_LOGON_FAILURE)

        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=smb,
        ):
            self.assertEqual(module.engine.Anonymous_smb(), [])

        categories = [
            recorded.kwargs["out"].value
            for recorded in module.engine.ptprint.call_args_list
            if "out" in recorded.kwargs
        ]
        self.assertIn("NOTVULN", categories)

    def test_network_failure_becomes_module_error_and_never_notvuln(self):
        module, ptjsonlib = msrpc_main(tests="ANONSMB")

        text_output = io.StringIO()
        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                side_effect=OSError("connection refused"),
            ),
            patch("sys.stdout", new=text_output),
        ):
            module.run()
            module.output()

        self.assertEqual(
            module.engine.results.module_errors,
            {"ANONSMB": "OSError: connection refused"},
        )
        self.assertNotIn("Anonymous SMB login is denied", text_output.getvalue())
        self.assertNotIn("NOTVULN", text_output.getvalue())
        ptjsonlib.set_status.assert_called_once_with(
            "error", "MSRPC module failure(s): ANONSMB"
        )


class MSRPCBindingAndCleanupTests(unittest.TestCase):
    def test_named_pipe_uses_custom_smb_port_and_disconnects(self):
        module, _ = msrpc_main(
            tests="BRUTEPIPE",
            target=SimpleNamespace(ip=TEST_IP, port=1445),
        )
        rpc_mock, dce = rpc_transport()
        smb = Mock()
        smb.isGuestSession.return_value = False

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ) as factory,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=smb,
            ) as smb_connection,
        ):
            self.assertTrue(
                module.engine.try_authenticated_pipe_bind(
                    "samr", "alice", "secret", "EXAMPLE"
                )
            )

        factory.assert_called_once_with(f"ncacn_np:{TEST_IP}[\\pipe\\samr]")
        self.assertEqual(smb_connection.call_args.kwargs["timeout"], 5.0)
        smb.login.assert_called_once_with("alice", "secret", "EXAMPLE")
        rpc_mock.set_dport.assert_called_once_with(1445)
        rpc_mock.set_smb_connection.assert_called_once_with(smb)
        dce.disconnect.assert_called_once_with()
        smb.logoff.assert_called_once_with()
        smb.close.assert_called_once_with()

    def test_tcp_uuid_is_validated_and_converted_before_bind(self):
        module, _ = msrpc_main(
            tests="BRUTETCP",
            target=SimpleNamespace(ip=TEST_IP, port=49152),
        )
        rpc_mock, dce = rpc_transport()
        expected = impacket_uuid.uuidtup_to_bin(
            (TEST_INTERFACE_UUID, "1.0")
        )

        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
            return_value=rpc_mock,
        ) as factory:
            self.assertTrue(
                module.engine.try_authenticated_bind(
                    TEST_IP,
                    49152,
                    "alice",
                    "secret",
                    TEST_INTERFACE,
                    "EXAMPLE",
                )
            )

        dce.bind.assert_called_once_with(expected)
        dce.set_credentials.assert_called_once_with(
            "alice", "secret", "EXAMPLE"
        )
        dce.set_auth_type.assert_called_once_with(RPC_C_AUTHN_WINNT)
        dce.disconnect.assert_called_once_with()

        factory.reset_mock()
        with self.assertRaises(argparse.ArgumentError):
            module.engine.try_authenticated_bind(
                TEST_IP,
                49152,
                "alice",
                "secret",
                "not-a-valid-interface",
                "EXAMPLE",
            )
        factory.assert_not_called()


class MSRPCCredentialSafetyTests(unittest.TestCase):
    def test_smb_guest_mapping_is_rejected_but_non_guest_is_accepted(self):
        guest_module, _ = msrpc_main(tests="BRUTESMB")
        guest = Mock()
        guest.isGuestSession.return_value = True
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=guest,
        ):
            self.assertEqual(guest_module.engine.smb_brute(), [])
        self.assertEqual(guest_module.engine.results.module_errors, {})

        user_module, _ = msrpc_main(tests="BRUTESMB")
        user = Mock()
        user.isGuestSession.return_value = False
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=user,
        ):
            self.assertEqual(
                user_module.engine.smb_brute(),
                [Credential("alice", "secret")],
            )

    def test_smb_auth_rejection_and_operational_error_are_distinguished(self):
        rejected_module, _ = msrpc_main(tests="BRUTESMB")
        rejected = Mock()
        rejected.login.side_effect = SessionError(STATUS_LOGON_FAILURE)
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=rejected,
        ):
            self.assertEqual(rejected_module.engine.smb_brute(), [])
        self.assertEqual(rejected_module.engine.results.module_errors, {})

        error_module, _ = msrpc_main(tests="BRUTESMB")
        error = Mock()
        error.login.side_effect = SessionError(STATUS_ACCESS_DENIED)
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=error,
        ):
            self.assertEqual(error_module.engine.smb_brute(), [])
        self.assertIn("BRUTESMB", error_module.engine.results.module_errors)

    def test_brutepipe_rejects_guest_and_reports_pipe_errors(self):
        guest_module, _ = msrpc_main(tests="BRUTEPIPE")
        guest = Mock()
        guest.isGuestSession.return_value = True
        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=guest,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory"
            ) as factory,
        ):
            self.assertEqual(guest_module.engine.pipe_dictionary_attack(), [])
        factory.assert_not_called()
        self.assertEqual(guest_module.engine.results.module_errors, {})

        error_module, _ = msrpc_main(tests="BRUTEPIPE")
        user = Mock()
        user.isGuestSession.return_value = False
        rpc_mock, dce = rpc_transport()
        dce.connect.side_effect = SessionError(STATUS_OBJECT_NAME_NOT_FOUND)
        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=user,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
        ):
            self.assertEqual(error_module.engine.pipe_dictionary_attack(), [])
        self.assertIn("BRUTEPIPE", error_module.engine.results.module_errors)

    def test_enumpipes_retains_guest_or_null_reachability(self):
        module, _ = msrpc_main(tests="ENUMPIPES")
        guest = Mock()
        guest.isGuestSession.return_value = True
        rpc_mock, _ = rpc_transport()
        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=guest,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
        ):
            self.assertTrue(
                module.engine.try_authenticated_pipe_bind("samr", "", "", "")
            )

    def test_http_401_is_a_clean_credential_rejection(self):
        module, _ = msrpc_main(tests="BRUTEHTTP")
        rpc_mock, dce = rpc_transport()
        dce.connect.side_effect = RPCProxyClientException(
            "RPC Proxy Client: NTLM authentication failed",
            proxy_error="HTTP/1.1 401 Unauthorized",
        )
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
            return_value=rpc_mock,
        ):
            self.assertEqual(module.engine.http_brute(), [])
        self.assertEqual(module.engine.results.module_errors, {})

    def test_http_proxy_connect_timeout_is_active_and_restored(self):
        module, _ = msrpc_main(
            tests="BRUTEHTTP",
            timeout_seconds=2.5,
        )
        rpc_mock, dce = rpc_transport()
        observed = []
        dce.connect.side_effect = lambda: observed.append(socket.getdefaulttimeout())
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(17.0)
        try:
            with patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ):
                self.assertEqual(
                    module.engine.http_brute(),
                    [Credential("alice", "secret")],
                )
            self.assertEqual(observed, [2.5])
            self.assertEqual(socket.getdefaulttimeout(), 17.0)
        finally:
            socket.setdefaulttimeout(original_timeout)


class MSRPCCredentialSchedulerTests(unittest.TestCase):
    def test_compatibility_generator_preserves_username_major_order(self):
        module, _ = msrpc_main(tests="BRUTESMB")
        with patch.object(
            module.engine,
            "_credential_sources",
            return_value=(["u1", "u2"], ["p1", "p2"]),
        ):
            self.assertEqual(
                module.engine._generate_credentials(),
                [
                    Credential("u1", "p1"),
                    Credential("u1", "p2"),
                    Credential("u2", "p1"),
                    Credential("u2", "p2"),
                ],
            )

    def test_attempt_cap_rejects_before_any_worker_runs(self):
        module, _ = msrpc_main(tests="BRUTESMB", max_attempts=3)
        attempt = Mock()
        with patch.object(
            module.engine,
            "_credential_sources",
            return_value=(["u1", "u2"], ["p1", "p2"]),
        ):
            with self.assertRaises(argparse.ArgumentError):
                module.engine._run_credential_attempts("BRUTESMB", attempt)
        attempt.assert_not_called()

    def test_scheduler_bounds_pending_work_and_preserves_result_order(self):
        module, _ = msrpc_main(tests="BRUTESMB", threads=2, max_attempts=20)
        usernames = [f"u{index}" for index in range(10)]
        consumed = 0
        consumed_window = threading.Event()
        release = threading.Event()
        lock = threading.Lock()

        def generated(_usernames, _passwords):
            nonlocal consumed
            for username in usernames:
                with lock:
                    consumed += 1
                    if consumed == 4:
                        consumed_window.set()
                yield Credential(username, "p")

        def attempt(credential):
            release.wait(5)
            return _AttemptResult(credential, accepted=True)

        result = []
        errors = []

        def run_scheduler():
            try:
                result.extend(
                    module.engine._run_credential_attempts("BRUTESMB", attempt)
                )
            except Exception as exc:  # surfaced in the assertion thread below
                errors.append(exc)

        with (
            patch.object(
                module.engine,
                "_credential_sources",
                return_value=(usernames, ["p"]),
            ),
            patch.object(module.engine, "_iter_credentials", side_effect=generated),
        ):
            worker = threading.Thread(target=run_scheduler, daemon=True)
            worker.start()
            try:
                self.assertTrue(consumed_window.wait(2))
                with lock:
                    self.assertEqual(consumed, 4)
            finally:
                release.set()
                worker.join(5)

        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(result, [Credential(username, "p") for username in usernames])


class MSRPCResourceCleanupTests(unittest.TestCase):
    def test_dce_connections_are_disconnected_when_probe_fails(self):
        module, _ = msrpc_main(tests="ENUMEPM")
        rpc_mock, dce = rpc_transport()
        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.epm.hept_lookup",
                side_effect=OSError("lookup failed"),
            ),
        ):
            self.assertEqual(module.engine.enumerate_epm(), {})
        dce.disconnect.assert_called_once_with()

        rpc_mock, dce = rpc_transport()
        dce.bind.side_effect = OSError("bind failed")
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
            return_value=rpc_mock,
        ):
            self.assertFalse(
                module.engine.try_authenticated_bind(
                    TEST_IP,
                    135,
                    "alice",
                    "secret",
                    TEST_INTERFACE,
                    "EXAMPLE",
                )
            )
        dce.disconnect.assert_called_once_with()

    def test_smb_and_http_sessions_are_cleaned_up_on_inner_failure(self):
        smb_module, _ = msrpc_main(tests="ANONSMB")
        smb = Mock()
        smb.connectTree.side_effect = SessionError(STATUS_ACCESS_DENIED)
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=smb,
        ):
            self.assertEqual(smb_module.engine.Anonymous_smb(), ["True", "False"])
        smb.logoff.assert_called_once_with()

        no_share_list = Mock()
        no_share_list.listShares.side_effect = SessionError(STATUS_ACCESS_DENIED)
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=no_share_list,
        ):
            self.assertEqual(
                smb_module.engine.Anonymous_smb(), ["True", "True"]
            )
        no_share_list.logoff.assert_called_once_with()

        broken_smb = Mock()
        broken_smb.listShares.side_effect = OSError("connection reset")
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
            return_value=broken_smb,
        ):
            with self.assertRaises(OSError):
                smb_module.engine.Anonymous_smb()
        broken_smb.logoff.assert_called_once_with()

        http_module, _ = msrpc_main(tests="BRUTEHTTP")
        rpc_mock, dce = rpc_transport()
        dce.bind.side_effect = OSError("bind failed")
        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
            return_value=rpc_mock,
        ):
            self.assertEqual(http_module.engine.http_brute(), [])
        dce.disconnect.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
