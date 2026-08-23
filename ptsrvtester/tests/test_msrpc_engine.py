import argparse
import io
import socket
import threading
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, call, patch

from impacket import uuid as impacket_uuid
from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT
from impacket.dcerpc.v5.rpch import RPCProxyClientException
from impacket.http import AUTH_NTLM
from impacket.nt_errors import (
    STATUS_ACCESS_DENIED,
    STATUS_INVALID_INFO_CLASS,
    STATUS_LOGON_FAILURE,
    STATUS_MORE_ENTRIES,
    STATUS_NOT_SUPPORTED,
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
from ptsrvtester.protocols.msrpc.utils.samr_policy import (
    UNLIMITED_RELATIVE_INTERVAL,
    format_interval,
    old_large_integer_value,
    parse_lockout_policy,
    parse_password_policy,
    relative_interval,
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
        "samr_max_users": 1000,
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


def old_relative_interval(raw_100ns: int) -> dict[str, int]:
    """Build the split form returned by SAMR for password-age intervals."""
    unsigned = raw_100ns & ((1 << 64) - 1)
    high = (unsigned >> 32) & 0xFFFFFFFF
    if high & 0x80000000:
        high -= 1 << 32
    return {
        "LowPart": unsigned & 0xFFFFFFFF,
        "HighPart": high,
    }


def password_policy_fixture(*, maximum_age: int = -86400 * 10_000_000):
    return {
        "MinPasswordLength": 14,
        "PasswordHistoryLength": 24,
        "PasswordProperties": (
            samr.DOMAIN_PASSWORD_COMPLEX
            | samr.DOMAIN_LOCKOUT_ADMINS
            | samr.DOMAIN_PASSWORD_STORE_CLEARTEXT
            | 0x80
        ),
        "MinPasswordAge": old_relative_interval(-3600 * 10_000_000),
        "MaxPasswordAge": old_relative_interval(maximum_age),
    }


def lockout_policy_fixture(
    *, duration: int = -1800 * 10_000_000, threshold: int = 5
):
    return {
        "LockoutDuration": duration,
        "LockoutObservationWindow": -900 * 10_000_000,
        "LockoutThreshold": threshold,
    }


def canonical_sid(value: str) -> Mock:
    sid = Mock(name=f"sid-{value}")
    sid.formatCanonical.return_value = value
    return sid


def samr_enum_user(name: str, rid: int) -> dict[str, object]:
    return {
        "RelativeId": rid,
        "Name": name,
    }


def samr_enum_page(
    entries: list[dict[str, object]],
    *,
    context: int = 0,
    status: int = 0,
) -> dict[str, object]:
    return {
        "EnumerationContext": context,
        "Buffer": {
            "EntriesRead": len(entries),
            "Buffer": entries,
        },
        "CountReturned": len(entries),
        "ErrorCode": status,
    }


def samr_user_control(account_control: int) -> dict[str, object]:
    return {
        "Buffer": {
            "Control": {
                "UserAccountControl": account_control,
            }
        },
        "ErrorCode": 0,
    }


def samr_more_users(
    entries: list[dict[str, object]], context: int
) -> samr.DCERPCSessionError:
    return samr.DCERPCSessionError(
        error_code=STATUS_MORE_ENTRIES,
        packet=samr_enum_page(
            entries,
            context=context,
            status=STATUS_MORE_ENTRIES,
        ),
    )


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


class MSRPCSamrPolicyConversionTests(unittest.TestCase):
    def test_password_policy_decodes_signed_ages_flags_and_unknown_bits(self):
        raw_maximum = -42 * 86400 * 10_000_000
        fixture = password_policy_fixture(maximum_age=raw_maximum)

        self.assertEqual(
            old_large_integer_value(fixture["MaxPasswordAge"]), raw_maximum
        )
        policy = parse_password_policy(fixture)

        self.assertEqual(policy["minimumPasswordLength"], 14)
        self.assertEqual(policy["passwordHistoryLength"], 24)
        self.assertTrue(policy["passwordComplexityRequired"])
        self.assertTrue(policy["reversibleEncryptionEnabled"])
        self.assertNotIn("administratorLockoutEnabled", policy)
        self.assertTrue(
            policy["passwordProperties"] & samr.DOMAIN_LOCKOUT_ADMINS
        )
        self.assertEqual(policy["unknownPasswordPropertyBits"], 0x80)
        self.assertEqual(
            policy["passwordPropertyFlags"],
            [
                "DOMAIN_PASSWORD_COMPLEX",
                "DOMAIN_LOCKOUT_ADMINS",
                "DOMAIN_PASSWORD_STORE_CLEARTEXT",
            ],
        )
        self.assertEqual(policy["minimumPasswordAge"]["seconds"], 3600)
        self.assertEqual(policy["maximumPasswordAge"]["seconds"], 42 * 86400)
        self.assertFalse(policy["maximumPasswordAge"]["unlimited"])

    def test_int64_min_is_preserved_as_the_no_automatic_expiry_sentinel(self):
        interval = relative_interval(UNLIMITED_RELATIVE_INTERVAL)

        self.assertEqual(
            interval,
            {
                "raw100ns": UNLIMITED_RELATIVE_INTERVAL,
                "seconds": None,
                "unlimited": True,
            },
        )
        self.assertEqual(format_interval(interval), "unlimited")

        password = parse_password_policy(
            password_policy_fixture(maximum_age=UNLIMITED_RELATIVE_INTERVAL)
        )
        self.assertTrue(password["maximumPasswordAge"]["unlimited"])

        lockout = parse_lockout_policy(
            lockout_policy_fixture(duration=UNLIMITED_RELATIVE_INTERVAL)
        )
        self.assertTrue(lockout["lockoutEnabled"])
        self.assertTrue(lockout["lockoutDuration"]["unlimited"])
        self.assertTrue(lockout["lockoutDuration"]["untilAdministratorUnlock"])
        self.assertIsNone(lockout["lockoutDuration"]["seconds"])

        disabled = parse_lockout_policy(
            lockout_policy_fixture(
                duration=UNLIMITED_RELATIVE_INTERVAL,
                threshold=0,
            )
        )
        self.assertFalse(disabled["lockoutEnabled"])
        self.assertFalse(
            disabled["lockoutDuration"]["untilAdministratorUnlock"]
        )

    def test_manual_unlock_duration_is_described_without_calling_it_unlimited(self):
        module, _ = msrpc_main(tests="SAMRPOLICY")
        module.engine.ptprint = Mock()
        lockout = parse_lockout_policy(
            lockout_policy_fixture(duration=UNLIMITED_RELATIVE_INTERVAL)
        )
        result = {
            "status": "complete",
            "reason": None,
            "domains": [
                {
                    "status": "complete",
                    "name": "EXAMPLE",
                    "sid": "S-1-5-21-1-2-3",
                    "passwordPolicy": None,
                    "lockoutPolicy": lockout,
                    "errors": [],
                }
            ],
        }

        lines = module.engine._print_samr_policy(result)
        printed = "\n".join(str(item) for item in lines)

        self.assertIn("Lockout duration: until administrator unlocks", printed)
        self.assertNotIn("Lockout duration: unlimited", printed)

    def test_positive_relative_interval_is_rejected_instead_of_abs_converted(self):
        with self.assertRaisesRegex(
            ValueError, "relative SAM interval must not be positive"
        ):
            relative_interval(1)

        with self.assertRaises(ValueError):
            parse_password_policy(password_policy_fixture(maximum_age=10_000_000))


class MSRPCSamrPolicyEngineTests(unittest.TestCase):
    def test_complete_query_uses_one_smb_login_and_minimal_samr_access(self):
        module, _ = msrpc_main(
            tests="SAMRPOLICY",
            target=SimpleNamespace(ip=TEST_IP, port=1445),
        )
        smb = Mock()
        smb.isGuestSession.return_value = False
        rpc_mock, dce = rpc_transport()
        server_handle = "server-handle"
        domain_handle = "domain-handle"
        builtin_sid = canonical_sid("S-1-5-32")
        account_sid = canonical_sid("S-1-5-21-1-2-3")

        enumeration = {
            "Buffer": {
                "Buffer": [
                    {"Name": "localized-builtin\x00"},
                    {"Name": "EXAMPLE\x00"},
                ]
            },
            "EnumerationContext": 0,
            "ErrorCode": 0,
        }

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=smb,
            ) as connection,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ) as factory,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrConnect5",
                return_value={"ServerHandle": server_handle},
            ) as connect5,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrEnumerateDomainsInSamServer",
                return_value=enumeration,
            ) as enumerate_domains,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrLookupDomainInSamServer",
                side_effect=[
                    {"DomainId": builtin_sid},
                    {"DomainId": account_sid},
                ],
            ) as lookup_domain,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrOpenDomain",
                return_value={"DomainHandle": domain_handle},
            ) as open_domain,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrQueryInformationDomain",
                side_effect=[
                    {"Buffer": {"Password": password_policy_fixture()}},
                    {"Buffer": {"Lockout": lockout_policy_fixture()}},
                ],
            ) as query_information,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrCloseHandle"
            ) as close_handle,
        ):
            result = module.engine.query_samr_policy()

        self.assertEqual(result["status"], "complete")
        self.assertIsNone(result["reason"])
        self.assertEqual(len(result["domains"]), 1)
        self.assertEqual(result["domains"][0]["name"], "EXAMPLE")
        self.assertEqual(result["domains"][0]["sid"], "S-1-5-21-1-2-3")
        self.assertEqual(
            result["domains"][0]["passwordPolicy"]["minimumPasswordLength"], 14
        )
        self.assertEqual(
            result["domains"][0]["lockoutPolicy"]["lockoutThreshold"], 5
        )

        connection.assert_called_once_with(
            TEST_IP,
            TEST_IP,
            sess_port=1445,
            timeout=5.0,
        )
        smb.login.assert_called_once_with(
            "alice", "secret", "EXAMPLE", ntlmFallback=False
        )
        smb.isGuestSession.assert_called_once_with()
        factory.assert_called_once_with(f"ncacn_np:{TEST_IP}[\\pipe\\samr]")
        rpc_mock.set_dport.assert_called_once_with(1445)
        rpc_mock.set_connect_timeout.assert_called_once_with(5.0)
        rpc_mock.setRemoteHost.assert_called_once_with(TEST_IP)
        rpc_mock.set_smb_connection.assert_called_once_with(smb)
        dce.connect.assert_called_once_with()
        dce.bind.assert_called_once_with(samr.MSRPC_UUID_SAMR)

        connect5.assert_called_once_with(
            dce,
            desiredAccess=(
                samr.SAM_SERVER_ENUMERATE_DOMAINS
                | samr.SAM_SERVER_LOOKUP_DOMAIN
            ),
        )
        enumerate_domains.assert_called_once_with(
            dce, server_handle, enumerationContext=0
        )
        self.assertEqual(
            lookup_domain.call_args_list,
            [
                call(dce, server_handle, "localized-builtin"),
                call(dce, server_handle, "EXAMPLE"),
            ],
        )
        open_domain.assert_called_once_with(
            dce,
            server_handle,
            desiredAccess=samr.DOMAIN_READ_PASSWORD_PARAMETERS,
            domainId=account_sid,
        )
        self.assertEqual(
            query_information.call_args_list,
            [
                call(
                    dce,
                    domain_handle,
                    samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation,
                ),
                call(
                    dce,
                    domain_handle,
                    samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation,
                ),
            ],
        )
        self.assertEqual(
            close_handle.call_args_list,
            [call(dce, domain_handle), call(dce, server_handle)],
        )
        dce.disconnect.assert_called_once_with()
        smb.logoff.assert_called_once_with()
        smb.close.assert_called_once_with()

    def test_domain_enumeration_follows_more_entries_without_duplicates(self):
        module, _ = msrpc_main(tests="SAMRPOLICY")
        dce = Mock()
        server_handle = "server-handle"
        first_page = {
            "Buffer": {"Buffer": [{"Name": "EXAMPLE\x00"}]},
            "EnumerationContext": 7,
            "ErrorCode": STATUS_MORE_ENTRIES,
        }
        second_page = {
            "Buffer": {
                "Buffer": [
                    {"Name": "example"},
                    {"Name": "TRUSTED\x00"},
                ]
            },
            "EnumerationContext": 7,
            "ErrorCode": 0,
        }
        more_entries = samr.DCERPCSessionError(
            error_code=STATUS_MORE_ENTRIES,
            packet=first_page,
        )

        with patch(
            "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrEnumerateDomainsInSamServer",
            side_effect=[more_entries, second_page],
        ) as enumerate_domains:
            names = module.engine._enumerate_samr_domain_names(dce, server_handle)

        self.assertEqual(names, ["EXAMPLE", "TRUSTED"])
        self.assertEqual(
            enumerate_domains.call_args_list,
            [
                call(dce, server_handle, enumerationContext=0),
                call(dce, server_handle, enumerationContext=7),
            ],
        )

    def test_authentication_denial_does_not_start_rpc_and_closes_socket(self):
        module, _ = msrpc_main(tests="SAMRPOLICY")
        smb = Mock()
        smb.login.side_effect = SessionError(STATUS_LOGON_FAILURE)

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=smb,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory"
            ) as factory,
        ):
            result = module.engine.query_samr_policy()

        self.assertEqual(
            result,
            {
                "status": "denied",
                "reason": "authentication_denied",
                "domains": [],
            },
        )
        smb.login.assert_called_once_with(
            "alice", "secret", "EXAMPLE", ntlmFallback=False
        )
        smb.isGuestSession.assert_not_called()
        factory.assert_not_called()
        smb.logoff.assert_not_called()
        smb.close.assert_called_once_with()
        self.assertEqual(module.engine.results.module_errors, {})

    def test_guest_mapping_is_denied_before_samr_binding(self):
        module, _ = msrpc_main(tests="SAMRPOLICY")
        smb = Mock()
        smb.isGuestSession.return_value = True

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=smb,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory"
            ) as factory,
        ):
            result = module.engine.query_samr_policy()

        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["reason"], "guest_session")
        self.assertEqual(result["domains"], [])
        factory.assert_not_called()
        smb.logoff.assert_called_once_with()
        smb.close.assert_called_once_with()
        self.assertEqual(module.engine.results.module_errors, {})

    def test_sam_server_access_denial_is_not_an_operational_error(self):
        module, _ = msrpc_main(tests="SAMRPOLICY")
        smb = Mock()
        smb.isGuestSession.return_value = False
        rpc_mock, dce = rpc_transport()
        denied = samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED)

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=smb,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrConnect5",
                side_effect=denied,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrCloseHandle"
            ) as close_handle,
        ):
            result = module.engine.query_samr_policy()

        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["reason"], "sam_server_access_denied")
        self.assertEqual(result["domains"], [])
        self.assertEqual(module.engine.results.module_errors, {})
        close_handle.assert_not_called()
        dce.disconnect.assert_called_once_with()
        smb.logoff.assert_called_once_with()
        smb.close.assert_called_once_with()

    def test_rpc_access_denied_string_is_clean_denied_and_cleans_sessions(self):
        module, _ = msrpc_main(tests="SAMRPOLICY")
        smb = Mock()
        smb.isGuestSession.return_value = False
        rpc_mock, dce = rpc_transport()
        dce.bind.side_effect = DCERPCException(
            error_string="rpc_s_access_denied",
            error_code=None,
        )

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=smb,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrConnect5"
            ) as connect5,
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrCloseHandle"
            ) as close_handle,
        ):
            result = module.engine.query_samr_policy()

        self.assertEqual(
            result,
            {
                "status": "denied",
                "reason": "samr_access_denied",
                "domains": [],
            },
        )
        self.assertEqual(module.engine.results.module_errors, {})
        dce.connect.assert_called_once_with()
        dce.bind.assert_called_once_with(samr.MSRPC_UUID_SAMR)
        connect5.assert_not_called()
        close_handle.assert_not_called()
        dce.disconnect.assert_called_once_with()
        smb.logoff.assert_called_once_with()
        smb.close.assert_called_once_with()

    def test_one_unavailable_policy_section_retains_data_as_partial(self):
        module, _ = msrpc_main(tests="SAMRPOLICY")
        smb = Mock()
        smb.isGuestSession.return_value = False
        rpc_mock, dce = rpc_transport()
        server_handle = "server-handle"
        domain_handle = "domain-handle"
        account_sid = canonical_sid("S-1-5-21-1-2-3")
        denied = samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED)

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=smb,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrConnect5",
                return_value={"ServerHandle": server_handle},
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrEnumerateDomainsInSamServer",
                return_value={
                    "Buffer": {"Buffer": [{"Name": "EXAMPLE"}]},
                    "EnumerationContext": 0,
                    "ErrorCode": 0,
                },
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrLookupDomainInSamServer",
                return_value={"DomainId": account_sid},
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrOpenDomain",
                return_value={"DomainHandle": domain_handle},
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrQueryInformationDomain",
                side_effect=[
                    {"Buffer": {"Password": password_policy_fixture()}},
                    denied,
                ],
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrCloseHandle"
            ) as close_handle,
        ):
            result = module.engine.query_samr_policy()

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["reason"], "some_policy_data_unavailable")
        domain = result["domains"][0]
        self.assertEqual(domain["status"], "partial")
        self.assertIsNotNone(domain["passwordPolicy"])
        self.assertIsNone(domain["lockoutPolicy"])
        self.assertEqual(
            domain["errors"],
            [{"section": "lockoutPolicy", "reason": "access_denied"}],
        )
        self.assertEqual(
            close_handle.call_args_list,
            [call(dce, domain_handle), call(dce, server_handle)],
        )
        dce.disconnect.assert_called_once_with()
        smb.logoff.assert_called_once_with()
        smb.close.assert_called_once_with()

    def test_two_unsupported_policy_sections_are_partial_not_denied(self):
        module, _ = msrpc_main(tests="SAMRPOLICY")
        smb = Mock()
        smb.isGuestSession.return_value = False
        rpc_mock, dce = rpc_transport()
        server_handle = "server-handle"
        domain_handle = "domain-handle"
        account_sid = canonical_sid("S-1-5-21-1-2-3")
        unsupported = samr.DCERPCSessionError(error_code=STATUS_NOT_SUPPORTED)
        invalid_class = samr.DCERPCSessionError(
            error_code=STATUS_INVALID_INFO_CLASS
        )

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=smb,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrConnect5",
                return_value={"ServerHandle": server_handle},
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrEnumerateDomainsInSamServer",
                return_value={
                    "Buffer": {"Buffer": [{"Name": "EXAMPLE"}]},
                    "EnumerationContext": 0,
                    "ErrorCode": 0,
                },
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrLookupDomainInSamServer",
                return_value={"DomainId": account_sid},
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrOpenDomain",
                return_value={"DomainHandle": domain_handle},
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrQueryInformationDomain",
                side_effect=[unsupported, invalid_class],
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrCloseHandle"
            ) as close_handle,
        ):
            result = module.engine.query_samr_policy()

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["reason"], "some_policy_data_unavailable")
        domain = result["domains"][0]
        self.assertEqual(domain["status"], "partial")
        self.assertIsNone(domain["passwordPolicy"])
        self.assertIsNone(domain["lockoutPolicy"])
        self.assertEqual(
            domain["errors"],
            [
                {"section": "passwordPolicy", "reason": "not_supported"},
                {"section": "lockoutPolicy", "reason": "not_supported"},
            ],
        )
        self.assertEqual(module.engine.results.module_errors, {})
        self.assertEqual(
            close_handle.call_args_list,
            [call(dce, domain_handle), call(dce, server_handle)],
        )
        dce.disconnect.assert_called_once_with()
        smb.logoff.assert_called_once_with()
        smb.close.assert_called_once_with()

    def test_operational_error_redacts_credentials_and_cleans_every_session(self):
        username = "user-leak-marker"
        password = "password-leak-marker"
        domain = "domain-leak-marker"
        module, _ = msrpc_main(
            tests="SAMRPOLICY",
            username=username,
            password=password,
            domain=domain,
        )
        module.engine.ptprint = Mock()
        smb = Mock()
        smb.isGuestSession.return_value = False
        rpc_mock, dce = rpc_transport()
        dce.connect.side_effect = OSError(f"{username} {password} {domain}")

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=smb,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrCloseHandle"
            ) as close_handle,
        ):
            result = module.engine.query_samr_policy()

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "operational_error")
        recorded_error = module.engine.results.module_errors["SAMRPOLICY"]
        printed = " ".join(
            str(argument)
            for recorded_call in module.engine.ptprint.call_args_list
            for argument in recorded_call.args
        )
        observable = f"{result!r} {recorded_error} {printed}"
        for secret in (username, password, domain):
            self.assertNotIn(secret, observable)
        self.assertIn("[redacted]", recorded_error)

        close_handle.assert_not_called()
        dce.disconnect.assert_called_once_with()
        smb.logoff.assert_called_once_with()
        smb.close.assert_called_once_with()


class MSRPCSamrUsersEngineTests(unittest.TestCase):
    def _run_enumeration(
        self,
        enumeration_side_effect,
        *,
        user_controls=None,
        open_user_errors=None,
        domain_names=("EXAMPLE",),
        domain_sids=("S-1-5-21-1-2-3",),
        max_users=1000,
        target_port=0,
    ):
        module, _ = msrpc_main(
            tests="SAMRUSERS",
            samr_max_users=max_users,
            target=SimpleNamespace(ip=TEST_IP, port=target_port),
        )
        module.engine.ptprint = Mock()
        smb = Mock()
        smb.isGuestSession.return_value = False
        rpc_mock, dce = rpc_transport()
        server_handle = "server-handle"
        sid_objects = [canonical_sid(value) for value in domain_sids]
        domain_handles = [f"domain-handle-{index}" for index in range(len(domain_names))]
        domain_enumeration = {
            "Buffer": {
                "Buffer": [{"Name": f"{name}\x00"} for name in domain_names]
            },
            "EnumerationContext": 0,
            "ErrorCode": 0,
        }
        user_controls = user_controls or {}
        open_user_errors = open_user_errors or {}

        def open_user_result(_dce, _domain_handle, *, desiredAccess, userId):
            outcome = open_user_errors.get(userId)
            if isinstance(outcome, BaseException):
                raise outcome
            return {"UserHandle": f"user-handle-{userId}"}

        def query_user_result(_dce, user_handle, *, userInformationClass):
            rid = int(str(user_handle).rsplit("-", 1)[1])
            outcome = user_controls.get(rid, samr.USER_NORMAL_ACCOUNT)
            if isinstance(outcome, BaseException):
                raise outcome
            if isinstance(outcome, dict):
                return outcome
            return samr_user_control(int(outcome))

        with ExitStack() as stack:
            connection = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                    return_value=smb,
                )
            )
            factory = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                    return_value=rpc_mock,
                )
            )
            connect5 = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrConnect5",
                    return_value={"ServerHandle": server_handle},
                )
            )
            enumerate_domains = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrEnumerateDomainsInSamServer",
                    return_value=domain_enumeration,
                )
            )
            lookup_domain = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrLookupDomainInSamServer",
                    side_effect=[{"DomainId": sid} for sid in sid_objects],
                )
            )
            open_domain = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrOpenDomain",
                    side_effect=[
                        {"DomainHandle": handle} for handle in domain_handles
                    ],
                )
            )
            enumerate_users = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrEnumerateUsersInDomain",
                    side_effect=enumeration_side_effect,
                )
            )
            open_user = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrOpenUser",
                    side_effect=open_user_result,
                )
            )
            query_user = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrQueryInformationUser",
                    side_effect=query_user_result,
                )
            )
            close_handle = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrCloseHandle"
                )
            )
            set_user = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrSetInformationUser"
                )
            )
            set_user2 = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrSetInformationUser2"
                )
            )
            delete_user = stack.enter_context(
                patch(
                    "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrDeleteUser"
                )
            )
            result = module.engine.enumerate_samr_users()

        return SimpleNamespace(
            module=module,
            result=result,
            smb=smb,
            rpc=rpc_mock,
            dce=dce,
            server_handle=server_handle,
            sid_objects=sid_objects,
            domain_handles=domain_handles,
            connection=connection,
            factory=factory,
            connect5=connect5,
            enumerate_domains=enumerate_domains,
            lookup_domain=lookup_domain,
            open_domain=open_domain,
            enumerate_users=enumerate_users,
            open_user=open_user,
            query_user=query_user,
            close_handle=close_handle,
            set_user=set_user,
            set_user2=set_user2,
            delete_user=delete_user,
        )

    def test_complete_query_uses_normal_account_filter_and_minimal_read_access(self):
        guest_control = samr.USER_ACCOUNT_DISABLED | samr.USER_NORMAL_ACCOUNT
        admin_control = (
            samr.USER_NORMAL_ACCOUNT
            | samr.USER_DONT_EXPIRE_PASSWORD
            | samr.USER_ACCOUNT_AUTO_LOCKED
            | 0x80000000
        )
        run = self._run_enumeration(
            [
                samr_enum_page(
                    [
                        samr_enum_user("Administrator\x00", 500),
                        samr_enum_user("Guest", 501),
                    ]
                )
            ],
            user_controls={500: admin_control, 501: guest_control},
            domain_names=("localized-builtin", "EXAMPLE"),
            domain_sids=("S-1-5-32", "S-1-5-21-1-2-3"),
            target_port=1445,
        )

        self.assertEqual(run.result["status"], "complete")
        self.assertIsNone(run.result["reason"])
        self.assertEqual(run.result["limit"], 1000)
        self.assertEqual(run.result["returned"], 2)
        self.assertFalse(run.result["truncated"])
        self.assertEqual(len(run.result["domains"]), 1)
        domain = run.result["domains"][0]
        self.assertEqual(domain["name"], "EXAMPLE")
        self.assertEqual(domain["sid"], "S-1-5-21-1-2-3")
        self.assertEqual(domain["status"], "complete")
        self.assertEqual(domain["returned"], 2)
        self.assertFalse(domain["truncated"])

        administrator, guest = domain["users"]
        self.assertEqual(
            administrator,
            {
                "name": "Administrator",
                "rid": 500,
                "sid": "S-1-5-21-1-2-3-500",
                "stateStatus": "complete",
                "stateReason": None,
                "accountControl": admin_control,
                "accountControlFlags": [
                    "USER_NORMAL_ACCOUNT",
                    "USER_DONT_EXPIRE_PASSWORD",
                    "USER_ACCOUNT_AUTO_LOCKED",
                ],
                "unknownAccountControlBits": 0x80000000,
                "disabled": False,
                "lockedOut": True,
            },
        )
        self.assertTrue(guest["disabled"])
        self.assertFalse(guest["lockedOut"])

        run.connection.assert_called_once_with(
            TEST_IP, TEST_IP, sess_port=1445, timeout=5.0
        )
        run.smb.login.assert_called_once_with(
            "alice", "secret", "EXAMPLE", ntlmFallback=False
        )
        run.smb.isGuestSession.assert_called_once_with()
        run.factory.assert_called_once_with(f"ncacn_np:{TEST_IP}[\\pipe\\samr]")
        run.rpc.set_dport.assert_called_once_with(1445)
        run.rpc.set_connect_timeout.assert_called_once_with(5.0)
        run.rpc.setRemoteHost.assert_called_once_with(TEST_IP)
        run.rpc.set_smb_connection.assert_called_once_with(run.smb)
        run.dce.connect.assert_called_once_with()
        run.dce.bind.assert_called_once_with(samr.MSRPC_UUID_SAMR)
        run.connect5.assert_called_once_with(
            run.dce,
            desiredAccess=(
                samr.SAM_SERVER_ENUMERATE_DOMAINS
                | samr.SAM_SERVER_LOOKUP_DOMAIN
            ),
        )
        run.open_domain.assert_called_once_with(
            run.dce,
            run.server_handle,
            desiredAccess=(samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_LOOKUP),
            domainId=run.sid_objects[1],
        )
        run.enumerate_users.assert_called_once()
        enumeration_call = run.enumerate_users.call_args
        self.assertEqual(enumeration_call.args, (run.dce, run.domain_handles[0]))
        self.assertEqual(
            enumeration_call.kwargs["userAccountControl"],
            samr.USER_NORMAL_ACCOUNT,
        )
        self.assertEqual(enumeration_call.kwargs["enumerationContext"], 0)
        self.assertGreater(enumeration_call.kwargs["preferedMaximumLength"], 0)
        self.assertLess(
            enumeration_call.kwargs["preferedMaximumLength"], 0xFFFFFFFF
        )
        self.assertEqual(
            run.open_user.call_args_list,
            [
                call(
                    run.dce,
                    run.domain_handles[0],
                    desiredAccess=samr.USER_READ_ACCOUNT,
                    userId=500,
                ),
                call(
                    run.dce,
                    run.domain_handles[0],
                    desiredAccess=samr.USER_READ_ACCOUNT,
                    userId=501,
                ),
            ],
        )
        self.assertEqual(
            run.query_user.call_args_list,
            [
                call(
                    run.dce,
                    "user-handle-500",
                    userInformationClass=(
                        samr.USER_INFORMATION_CLASS.UserControlInformation
                    ),
                ),
                call(
                    run.dce,
                    "user-handle-501",
                    userInformationClass=(
                        samr.USER_INFORMATION_CLASS.UserControlInformation
                    ),
                ),
            ],
        )
        self.assertEqual(
            run.close_handle.call_args_list,
            [
                call(run.dce, "user-handle-500"),
                call(run.dce, "user-handle-501"),
                call(run.dce, run.domain_handles[0]),
                call(run.dce, run.server_handle),
            ],
        )
        run.dce.disconnect.assert_called_once_with()
        run.smb.logoff.assert_called_once_with()
        run.smb.close.assert_called_once_with()
        for forbidden in (run.set_user, run.set_user2, run.delete_user):
            forbidden.assert_not_called()

    def test_paging_uses_enumeration_context_and_deduplicates_users(self):
        run = self._run_enumeration(
            [
                samr_more_users(
                    [samr_enum_user("alice", 1000), samr_enum_user("bob", 1001)],
                    7,
                ),
                samr_enum_page(
                    [samr_enum_user("bob", 1001), samr_enum_user("carol", 1002)],
                    context=9,
                ),
            ]
        )

        self.assertEqual(run.result["status"], "complete")
        self.assertEqual(run.result["returned"], 3)
        self.assertEqual(
            [user["name"] for user in run.result["domains"][0]["users"]],
            ["alice", "bob", "carol"],
        )
        self.assertEqual(
            [
                item.kwargs["enumerationContext"]
                for item in run.enumerate_users.call_args_list
            ],
            [0, 7],
        )
        self.assertEqual(
            [item.kwargs["userId"] for item in run.open_user.call_args_list],
            [1000, 1001, 1002],
        )

    def test_global_limit_stops_before_an_additional_account_domain(self):
        run = self._run_enumeration(
            [
                samr_enum_page(
                    [samr_enum_user("one", 1000), samr_enum_user("two", 1001)]
                )
            ],
            domain_names=("FIRST", "localized-builtin", "SECOND"),
            domain_sids=("S-1-5-21-1", "S-1-5-32", "S-1-5-21-2"),
            max_users=2,
        )

        self.assertEqual(run.result["status"], "partial")
        self.assertEqual(run.result["reason"], "limit_reached")
        self.assertEqual(run.result["limit"], 2)
        self.assertEqual(run.result["returned"], 2)
        self.assertTrue(run.result["truncated"])
        self.assertEqual(len(run.result["domains"]), 1)
        self.assertEqual(
            [user["name"] for user in run.result["domains"][0]["users"]],
            ["one", "two"],
        )
        self.assertEqual(run.lookup_domain.call_count, 3)
        run.enumerate_users.assert_called_once()
        run.open_domain.assert_called_once()

    def test_exact_limit_ignores_a_later_builtin_domain(self):
        run = self._run_enumeration(
            [samr_enum_page([samr_enum_user("one", 1000)])],
            domain_names=("EXAMPLE", "localized-builtin"),
            domain_sids=("S-1-5-21-1", "S-1-5-32"),
            max_users=1,
        )

        self.assertEqual(run.result["status"], "complete")
        self.assertIsNone(run.result["reason"])
        self.assertEqual(run.result["returned"], 1)
        self.assertFalse(run.result["truncated"])
        self.assertEqual(len(run.result["domains"]), 1)
        self.assertEqual(run.lookup_domain.call_count, 2)
        run.open_domain.assert_called_once()
        run.enumerate_users.assert_called_once()

    def test_limit_boundary_uses_terminal_status_and_more_entries_signal(self):
        exact = self._run_enumeration(
            [
                samr_enum_page(
                    [samr_enum_user("one", 1000), samr_enum_user("two", 1001)],
                )
            ],
            max_users=2,
        )
        self.assertEqual(exact.result["status"], "complete")
        self.assertIsNone(exact.result["reason"])
        self.assertEqual(exact.result["returned"], 2)
        self.assertFalse(exact.result["truncated"])
        exact.enumerate_users.assert_called_once()

        continued = self._run_enumeration(
            [
                samr_more_users(
                    [samr_enum_user("one", 1000), samr_enum_user("two", 1001)],
                    2,
                )
            ],
            max_users=2,
        )
        self.assertEqual(continued.result["status"], "partial")
        self.assertEqual(continued.result["reason"], "limit_reached")
        self.assertEqual(continued.result["returned"], 2)
        self.assertTrue(continued.result["truncated"])
        continued.enumerate_users.assert_called_once()
        self.assertIn(
            "Reason: limit reached",
            [item.args[0] for item in continued.module.engine.ptprint.call_args_list],
        )

        overflow = self._run_enumeration(
            [
                samr_enum_page(
                    [
                        samr_enum_user("one", 1000),
                        samr_enum_user("two", 1001),
                        samr_enum_user("three", 1002),
                    ]
                )
            ],
            max_users=2,
        )
        self.assertEqual(overflow.result["status"], "partial")
        self.assertEqual(overflow.result["reason"], "limit_reached")
        self.assertEqual(overflow.result["returned"], 2)
        self.assertTrue(overflow.result["truncated"])
        self.assertEqual(
            [user["name"] for user in overflow.result["domains"][0]["users"]],
            ["one", "two"],
        )
        self.assertEqual(
            [item.kwargs["userId"] for item in overflow.open_user.call_args_list],
            [1000, 1001],
        )
        self.assertEqual(overflow.query_user.call_count, 2)

    def test_domain_access_denial_is_clean_denied_and_not_module_error(self):
        denied = samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED)
        run = self._run_enumeration([denied])

        self.assertEqual(run.result["status"], "denied")
        self.assertEqual(run.result["returned"], 0)
        self.assertFalse(run.result["truncated"])
        domain = run.result["domains"][0]
        self.assertEqual(domain["status"], "denied")
        self.assertEqual(domain["users"], [])
        self.assertEqual(run.module.engine.results.module_errors, {})
        run.open_user.assert_not_called()
        run.query_user.assert_not_called()
        self.assertEqual(
            run.close_handle.call_args_list,
            [
                call(run.dce, run.domain_handles[0]),
                call(run.dce, run.server_handle),
            ],
        )
        run.dce.disconnect.assert_called_once_with()
        run.smb.logoff.assert_called_once_with()
        run.smb.close.assert_called_once_with()

    def test_user_query_denial_preserves_identity_and_closes_user_handle(self):
        denied = samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED)
        run = self._run_enumeration(
            [
                samr_enum_page(
                    [samr_enum_user("alice", 1000), samr_enum_user("bob", 1001)]
                )
            ],
            user_controls={1001: denied},
        )

        self.assertEqual(run.result["status"], "partial")
        self.assertEqual(run.result["reason"], "some_account_data_unavailable")
        self.assertEqual(run.result["returned"], 2)
        self.assertEqual(run.result["domains"][0]["status"], "partial")
        self.assertEqual(
            run.result["domains"][0]["reason"], "some_account_state_unavailable"
        )
        self.assertEqual(
            [user["name"] for user in run.result["domains"][0]["users"]],
            ["alice", "bob"],
        )
        self.assertEqual(
            run.result["domains"][0]["users"][1],
            {
                "name": "bob",
                "rid": 1001,
                "sid": "S-1-5-21-1-2-3-1001",
                "stateStatus": "denied",
                "stateReason": "access_denied",
                "accountControl": None,
                "accountControlFlags": [],
                "unknownAccountControlBits": None,
                "disabled": None,
                "lockedOut": None,
            },
        )
        self.assertEqual(run.module.engine.results.module_errors, {})
        self.assertEqual(
            run.close_handle.call_args_list,
            [
                call(run.dce, "user-handle-1000"),
                call(run.dce, "user-handle-1001"),
                call(run.dce, run.domain_handles[0]),
                call(run.dce, run.server_handle),
            ],
        )

    def test_repeated_enumeration_context_is_operational_error_and_cleans_handles(self):
        run = self._run_enumeration(
            [
                samr_more_users([samr_enum_user("alice", 1000)], 7),
                samr_more_users([samr_enum_user("bob", 1001)], 7),
            ]
        )

        self.assertEqual(run.result["status"], "error")
        self.assertEqual(run.result["reason"], "operational_error")
        self.assertIn("SAMRUSERS", run.module.engine.results.module_errors)
        self.assertEqual(
            [
                item.kwargs["enumerationContext"]
                for item in run.enumerate_users.call_args_list
            ],
            [0, 7],
        )
        self.assertEqual(run.close_handle.call_args_list[-2:], [
            call(run.dce, run.domain_handles[0]),
            call(run.dce, run.server_handle),
        ])
        run.dce.disconnect.assert_called_once_with()
        run.smb.logoff.assert_called_once_with()
        run.smb.close.assert_called_once_with()

    def test_duplicate_only_page_is_rejected_as_no_progress(self):
        run = self._run_enumeration(
            [
                samr_more_users([samr_enum_user("alice", 1000)], 7),
                samr_more_users([samr_enum_user("alice", 1000)], 8),
            ]
        )

        self.assertEqual(run.result["status"], "error")
        self.assertEqual(run.result["reason"], "operational_error")
        self.assertEqual(run.result["returned"], 1)
        self.assertIn("SAMRUSERS", run.module.engine.results.module_errors)
        self.assertEqual(run.open_user.call_count, 1)
        self.assertEqual(
            [
                item.kwargs["enumerationContext"]
                for item in run.enumerate_users.call_args_list
            ],
            [0, 7],
        )

    def test_malformed_enumeration_response_is_error_not_empty_success(self):
        malformed = {
            "EnumerationContext": 0,
            "Buffer": {},
            "CountReturned": 1,
            "ErrorCode": 0,
        }
        run = self._run_enumeration([malformed])

        self.assertEqual(run.result["status"], "error")
        self.assertEqual(run.result["reason"], "operational_error")
        self.assertEqual(run.result["returned"], 0)
        self.assertFalse(run.result["truncated"])
        self.assertIn("SAMRUSERS", run.module.engine.results.module_errors)

    def test_malformed_control_response_closes_user_and_parent_handles(self):
        run = self._run_enumeration(
            [samr_enum_page([samr_enum_user("alice", 1000)])],
            user_controls={1000: {"Buffer": {}, "ErrorCode": 0}},
        )

        self.assertEqual(run.result["status"], "error")
        self.assertEqual(run.result["reason"], "operational_error")
        self.assertEqual(run.result["returned"], 0)
        self.assertIn("SAMRUSERS", run.module.engine.results.module_errors)
        self.assertEqual(
            run.close_handle.call_args_list,
            [
                call(run.dce, "user-handle-1000"),
                call(run.dce, run.domain_handles[0]),
                call(run.dce, run.server_handle),
            ],
        )

    def test_operational_error_redacts_secrets_from_result_log_and_module_error(self):
        username = "samr-user-leak-marker"
        password = "samr-password-leak-marker"
        domain = "samr-domain-leak-marker"
        module, _ = msrpc_main(
            tests="SAMRUSERS",
            username=username,
            password=password,
            domain=domain,
            samr_max_users=1000,
        )
        module.engine.ptprint = Mock()
        smb = Mock()
        smb.isGuestSession.return_value = False
        rpc_mock, dce = rpc_transport()
        dce.connect.side_effect = OSError(f"{username} {password} {domain}")

        with (
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.SMBConnection",
                return_value=smb,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.transport.DCERPCTransportFactory",
                return_value=rpc_mock,
            ),
            patch(
                "ptsrvtester.protocols.msrpc.utils.engine.samr.hSamrCloseHandle"
            ) as close_handle,
        ):
            result = module.engine.enumerate_samr_users()

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "operational_error")
        recorded_error = module.engine.results.module_errors["SAMRUSERS"]
        printed = " ".join(
            str(argument)
            for recorded_call in module.engine.ptprint.call_args_list
            for argument in recorded_call.args
        )
        observable = f"{result!r} {recorded_error} {printed}"
        for secret in (username, password, domain):
            self.assertNotIn(secret, observable)
        self.assertIn("[redacted]", recorded_error)
        close_handle.assert_not_called()
        dce.disconnect.assert_called_once_with()
        smb.logoff.assert_called_once_with()
        smb.close.assert_called_once_with()


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
