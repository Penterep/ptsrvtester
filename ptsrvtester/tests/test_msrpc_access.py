"""Access evidence and credential confirmation integration; all I/O is mocked."""
import json
import unittest
from unittest.mock import Mock, patch

from impacket.dcerpc.v5 import mgmt, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from impacket.dcerpc.v5.rpch import RPCProxyClient, RPCProxyClientException
from impacket.nt_errors import (
    STATUS_ACCESS_DENIED, STATUS_ACCOUNT_LOCKED_OUT, STATUS_LOGON_FAILURE, STATUS_OBJECT_NAME_NOT_FOUND,
)
from impacket.smbconnection import SessionError

from ptsrvtester.protocols.msrpc.utils.engine import Credential, _AttemptResult
from ptsrvtester.protocols.msrpc.utils.epm_inventory import iter_epm_entries
from ptsrvtester.protocols.msrpc.utils.rpc_auth import RpcAuthenticationUnconfirmed
from ptsrvtester.protocols.msrpc.utils.rpc_proxy import ObservedRPCProxyTransport
from ptsrvtester.tests.test_msrpc_engine import msrpc_main, TEST_IP, share_inventory_fixture


ENGINE = "ptsrvtester.protocols.msrpc.utils.engine"


class AnonymousAccessTests(unittest.TestCase):
    def check(self, smb, inventory=None):
        module, report = msrpc_main(tests="ANONSMB")
        with (
            patch(f"{ENGINE}.SMBConnection", return_value=smb),
            patch(f"{ENGINE}.enumerate_shares", return_value=inventory or share_inventory_fixture()) as shares,
        ):
            module.engine.results.Anonymous = module.engine.Anonymous_smb()
        self.shares = shares
        module.engine.output()
        return module.engine, report

    def test_guest_access_is_retained_without_null_session_vulnerability(self):
        smb = Mock()
        smb.isGuestSession.return_value = True
        inventory = share_inventory_fixture([{"name": "Public", "type": 0, "remark": "Files"}])
        engine, report = self.check(smb, inventory)
        self.assertEqual(engine.results.Anonymous, [])
        self.assertEqual(engine.results.AnonymousAccess, {
            "status": "complete", "reason": None, "sessionType": "guest", "login": "accepted",
            "ipcAccess": "allowed", "shareEnumeration": "complete",
            "shares": [{"name": "Public", "type": 0, "remark": "Files"}],
            "shareEnumerationDetails": {key: value for key, value in inventory.items() if key not in {"shares", "error"}},
        })
        report.add_vulnerability.assert_not_called()
        smb.close.assert_called_once()

    def test_null_session_and_ipc_denial_are_separate_results(self):
        smb = Mock()
        smb.isGuestSession.return_value = False
        smb.connectTree.side_effect = SessionError(STATUS_ACCESS_DENIED)
        engine, report = self.check(smb)
        self.assertEqual(engine.results.Anonymous, ["True", "False"])
        self.assertEqual(engine.results.AnonymousAccess["sessionType"], "null")
        self.assertEqual(engine.results.AnonymousAccess["ipcAccess"], "denied")
        self.assertEqual(engine.results.module_errors, {})
        self.shares.assert_not_called()
        self.assertEqual(report.add_vulnerability.call_args.kwargs["vuln_code"], "PTV-MSRCP-SMBNULLSESSION")

    def test_login_operational_failure_is_not_a_clean_denial(self):
        for code, expected in ((STATUS_LOGON_FAILURE, "denied"), (STATUS_OBJECT_NAME_NOT_FOUND, "error")):
            with self.subTest(code=code):
                smb = Mock()
                smb.login.side_effect = SessionError(code)
                engine, report = self.check(smb)
                self.assertEqual(engine.results.AnonymousAccess["status"], expected)
                self.assertEqual(bool(engine.results.module_errors), expected == "error")
                report.add_vulnerability.assert_not_called()
                smb.close.assert_called_once()

    def test_later_share_failure_keeps_null_session_evidence(self):
        smb = Mock()
        smb.isGuestSession.return_value = False
        engine, _ = self.check(smb, share_inventory_fixture(
            status="error", reason="operational_error", error=OSError("reset"),
        ))
        self.assertEqual(engine.results.Anonymous, ["True", "True"])
        self.assertEqual(engine.results.AnonymousAccess["shareEnumeration"], "error")
        self.assertIn("ANONSMB", engine.results.module_errors)

    def test_srvsvc_share_denial_is_not_an_operational_failure(self):
        smb = Mock()
        smb.isGuestSession.return_value = False
        engine, _ = self.check(smb, share_inventory_fixture(
            status="denied", reason="share_enumeration_denied",
        ))
        self.assertEqual(engine.results.Anonymous, ["True", "True"])
        self.assertEqual(engine.results.AnonymousAccess["shareEnumeration"], "denied")
        self.assertEqual(engine.results.module_errors, {})

    def test_partial_share_inventory_survives_limits_and_errors_in_json(self):
        for operational in (False, True):
            with self.subTest(operational=operational):
                smb = Mock()
                smb.isGuestSession.return_value = False
                inventory = share_inventory_fixture(
                    [{"name": "Public", "type": 0, "remark": "Files"}],
                    status="partial",
                    reason="operational_error" if operational else "share_limit_reached",
                    error=TimeoutError("offline timeout") if operational else None,
                    truncated=not operational,
                )
                engine, report = self.check(smb, inventory)
                properties = report.create_node_object.call_args.args[3]
                self.assertEqual(engine.results.Anonymous, ["True", "True"])
                self.assertEqual(properties["anonymousAccess"]["status"], "partial")
                self.assertEqual(properties["anonymousAccess"]["shares"], inventory["shares"])
                self.assertEqual(
                    properties["anonymousAccess"]["shareEnumerationDetails"]["truncated"], not operational,
                )
                self.assertEqual(bool(engine.results.module_errors), operational)
                json.dumps(properties)  # Raw exceptions must not leak into the JSON object.
                smb.login.assert_called_once()


class EpmPagingIntegrationTests(unittest.TestCase):
    def test_completed_pages_survive_timeout_or_limit_in_engine_output(self):
        from ptsrvtester.tests.test_msrpc_epm import epm_page, epm_dce

        for limited in (False, True):
            with self.subTest(limited=limited):
                module, report = msrpc_main(tests="ENUMEPM", output="unused.txt")
                module.engine.ptprint = Mock()
                module.engine.write_to_file = Mock()
                dce = epm_dce(epm_page((135,), continued=True), TimeoutError("second page"))
                transport = Mock()
                transport.get_dce_rpc.return_value = dce
                with (
                    patch(f"{ENGINE}.transport.DCERPCTransportFactory", return_value=transport),
                    patch(f"{ENGINE}.iter_epm_entries",
                          side_effect=lambda connection: iter_epm_entries(connection, max_entries=1 if limited else 10000)),
                ):
                    module.engine.results.EpmapEndpoints = module.engine.enumerate_epm()
                printed = "\n".join(call.args[0] for call in module.engine.ptprint.call_args_list)
                module.engine.write_to_file.assert_called_once()
                saved = "\n".join(module.engine.write_to_file.call_args.args[0])
                for output in (printed, saved):
                    self.assertIn("UUID: E1AF8308-5D1F-11C9-91A4-08002B14A0FA v3.0", output)
                    self.assertIn("ncacn_ip_tcp:192.0.2.20[135]", output)
                    self.assertIn("Enumeration partial:", output)
                module.engine.output()
                properties = report.create_node_object.call_args.args[3]
                self.assertEqual(len(properties["epmapEndpoints"]), 1)
                self.assertEqual(properties["epmapEnumeration"]["status"], "partial")
                self.assertEqual(properties["epmapEnumeration"]["entriesReturned"], 1)
                self.assertEqual(properties["epmapEnumeration"]["truncated"], limited)
                self.assertEqual(bool(module.engine.results.module_errors), not limited)
                dce.disconnect.assert_called_once()
                report.add_vulnerability.assert_not_called()


class LockoutIntegrationTests(unittest.TestCase):
    def test_smb_and_pipe_lockout_stop_pending_passwords_and_later_modules(self):
        for first_code in ("BRUTESMB", "BRUTEPIPE"):
            with self.subTest(first_code=first_code):
                module, _ = msrpc_main(tests=first_code, threads=10)
                smb = Mock()
                smb.login.side_effect = SessionError(STATUS_ACCOUNT_LOCKED_OUT)
                with (
                    patch(f"{ENGINE}.SMBConnection", return_value=smb),
                    patch.object(module.engine, "_credential_sources", return_value=(["alice", "ALICE"], ["a", "b", "c"])),
                ):
                    if first_code == "BRUTESMB":
                        found = module.engine.smb_brute()
                    else:
                        found = module.engine.pipe_dictionary_attack()
                    self.assertEqual(found, [])
                    smb.login.assert_called_once_with("alice", "a", "EXAMPLE", ntlmFallback=False)
                    checks = module.engine.results.credential_checks[first_code]
                    self.assertEqual([check["status"] for check in checks], ["rejected"] + ["skipped"] * 5)
                    next_attempt = Mock()
                    module.engine._run_credential_attempts("BRUTEHTTP", next_attempt)
                    next_attempt.assert_not_called()
                self.assertEqual(module.engine.results.module_errors, {})

    def test_wrong_password_does_not_skip_remaining_passwords_or_other_accounts(self):
        module, _ = msrpc_main(tests="BRUTESMB")
        called = []

        def attempt(credential):
            called.append(credential)
            if credential.username == "alice":
                return _AttemptResult(credential, rejected=True)
            return _AttemptResult(credential, accepted=True)

        with patch.object(module.engine, "_credential_sources", return_value=(["alice", "bob"], ["a", "b"])):
            found = module.engine._run_credential_attempts("BRUTESMB", attempt)
        self.assertEqual(len(called), 4)
        self.assertEqual(found, [Credential("bob", "a"), Credential("bob", "b")])
        self.assertEqual(module.engine._locked_accounts, set())

    def test_rpc_and_proxy_propagate_confirmed_lockout_but_not_unsigned_fault_text(self):
        from ptsrvtester.tests.test_msrpc_engine import TEST_INTERFACE

        for failure, expected in (
            (DCERPCException(error_code=STATUS_ACCOUNT_LOCKED_OUT), True),
            (RpcAuthenticationUnconfirmed("Unverified RPC fault 0xc0000234"), False),
        ):
            with self.subTest(expected=expected):
                module, _ = msrpc_main(tests="BRUTEHTTP")
                rpc = Mock()
                rpc.channel_status = {"in": "opened", "out": "opened"}
                dce = Mock()
                dce.bind.side_effect = failure
                with (
                    patch(f"{ENGINE}.transport.DCERPCTransportFactory", return_value=rpc),
                    patch(f"{ENGINE}.ObservedRPCProxyTransport", return_value=rpc),
                    patch(f"{ENGINE}.VerifiedDCERPC", return_value=dce),
                ):
                    tcp = module.engine._tcp_attempt(TEST_IP, 135, Credential("alice", "secret"), TEST_INTERFACE, "EXAMPLE")
                    http = module.engine._http_attempt(Credential("alice", "secret"))
                self.assertEqual(tcp.stop_account, expected)
                self.assertEqual(http.stop_account, expected)


class RpcCredentialEvidenceTests(unittest.TestCase):
    def test_bind_only_or_denied_method_never_produces_valid_credentials(self):
        for failure in (RpcAuthenticationUnconfirmed("bad signature"), DCERPCException(error_code=5)):
            with self.subTest(failure=type(failure).__name__):
                module, _ = msrpc_main(tests="ENUMEPM")
                dce = Mock()
                with patch(f"{ENGINE}.transport.DCERPCTransportFactory"), \
                        patch(f"{ENGINE}.VerifiedDCERPC", return_value=dce), \
                        patch(f"{ENGINE}.confirm_rpc_access", side_effect=failure):
                    result = module.engine._tcp_attempt(TEST_IP, 135, Credential("alice", "secret"),
                                                        "12345778-1234-abcd-ef00-0123456789ac:1.0", "EXAMPLE")
                self.assertFalse(result.accepted)
                self.assertFalse(result.rejected)
                self.assertIs(result.error, failure)
                self.assertEqual(result.evidence["rpcBind"], "accepted")
                self.assertEqual(result.evidence["rpcCall"], "unconfirmed")
                dce.disconnect.assert_called_once()

    def test_supported_rpc_requires_integrity_and_confirmed_call(self):
        module, _ = msrpc_main(tests="ENUMEPM")
        dce = Mock()
        with patch(f"{ENGINE}.transport.DCERPCTransportFactory"), \
                patch(f"{ENGINE}.VerifiedDCERPC", return_value=dce), \
                patch(f"{ENGINE}.confirm_rpc_access") as confirm:
            result = module.engine._tcp_attempt(TEST_IP, 135, Credential("alice", "secret"),
                                                "12345778-1234-abcd-ef00-0123456789ac:1.0", "EXAMPLE")
        self.assertTrue(result.accepted)
        dce.set_auth_level.assert_called_once_with(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        confirm.assert_called_once_with(dce, samr.MSRPC_UUID_SAMR)
        self.assertEqual(result.evidence["rpcCall"], "confirmed")

    def test_unsupported_interface_issues_no_network_request(self):
        module, _ = msrpc_main(tests="ENUMEPM")
        with patch(f"{ENGINE}.transport.DCERPCTransportFactory") as factory:
            result = module.engine._tcp_attempt(TEST_IP, 135, Credential("alice", "secret"),
                                                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee:1.0", "")
        factory.assert_not_called()
        self.assertFalse(result.accepted)
        self.assertEqual(result.evidence["reason"], "unsupported_interface")

    def test_proxy_tunnel_can_succeed_while_backend_call_is_denied(self):
        module, report = msrpc_main(tests="BRUTEHTTP")
        dce = Mock()
        rpc = Mock(channel_status={"in": "opened", "out": "opened"})
        with patch(f"{ENGINE}.ObservedRPCProxyTransport", return_value=rpc), \
                patch(f"{ENGINE}.VerifiedDCERPC", return_value=dce), \
                patch(f"{ENGINE}.confirm_rpc_access", side_effect=DCERPCException(error_code=5)):
            module.engine.results.HTTP_Brute = module.engine.http_brute()
        module.engine.output()
        checks = module.engine.results.credential_checks["BRUTEHTTP"]
        self.assertEqual(checks[0]["rpcTunnel"], "established")
        self.assertEqual(checks[0]["rpcBind"], "accepted")
        self.assertEqual(checks[0]["rpcCall"], "unconfirmed")
        self.assertEqual(checks[0]["status"], "inconclusive")
        self.assertNotIn("secret", json.dumps(checks))
        report.add_vulnerability.assert_not_called()


class ProxyChannelTests(unittest.TestCase):
    def test_channel_open_does_not_imply_backend_access(self):
        proxy = ObservedRPCProxyTransport("ncacn_http:[593,RpcProxy=example.test:443]")
        with patch.object(RPCProxyClient, "create_rpc_in_channel"), \
                patch.object(RPCProxyClient, "create_rpc_out_channel"), \
                patch.object(RPCProxyClient, "create_tunnel", side_effect=OSError("backend unavailable")):
            with self.assertRaises(OSError):
                proxy.connect()
        self.assertEqual(proxy.channel_status, {"in": "opened", "out": "opened"})
        self.assertEqual(proxy.tunnel_status, "error")

    def test_localized_http_401_is_classified_without_matching_reason_phrase(self):
        proxy = ObservedRPCProxyTransport("ncacn_http:[593,RpcProxy=example.test:80]")
        error = RPCProxyClientException("failed", proxy_error="HTTP/1.1 401 Nicht autorisiert")
        with patch.object(RPCProxyClient, "create_rpc_in_channel", side_effect=error):
            with self.assertRaises(RPCProxyClientException):
                proxy.connect()
        self.assertEqual(proxy.channel_status, {"in": "denied", "out": "not_tested"})
        self.assertEqual(proxy.tunnel_status, "not_tested")

    def test_cleanup_attempts_both_channels_after_partial_setup(self):
        proxy = ObservedRPCProxyTransport("ncacn_http:[593,RpcProxy=example.test:443]")
        with patch.object(proxy, "close_rpc_in_channel", side_effect=KeyError("missing")), \
                patch.object(proxy, "close_rpc_out_channel") as close_out:
            proxy.disconnect()
        close_out.assert_called_once()


class ManagementInventoryTests(unittest.TestCase):
    def test_unrecognized_interfaces_and_versions_are_retained(self):
        module, _ = msrpc_main(tests="ENUMMGMT")
        unknown = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        response = {"if_id_vector": {"count": 2, "if_id": [{"Data": Mock()}, {"Data": Mock()}]}}
        with patch(f"{ENGINE}.transport.DCERPCTransportFactory"), \
                patch.object(mgmt, "hinq_if_ids", return_value=response), \
                patch(f"{ENGINE}.uuid.bin_to_uuidtup", side_effect=[(unknown, "1.0"), (unknown, "2.0")]):
            result = module.engine.enumerate_mgmt()
        self.assertEqual(result, [unknown.lower()])
        self.assertEqual([item["version"] for item in module.engine.results.MgmtInterfaces], ["1.0", "2.0"])
        self.assertTrue(all(item["knownPipe"] is None for item in module.engine.results.MgmtInterfaces))
