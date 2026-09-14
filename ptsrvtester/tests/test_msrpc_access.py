"""Access evidence and credential confirmation integration; all I/O is mocked."""
import json
import unittest
from unittest.mock import Mock, patch

from impacket.dcerpc.v5 import mgmt, samr, srvs
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from impacket.dcerpc.v5.rpch import RPCProxyClient, RPCProxyClientException
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE, STATUS_OBJECT_NAME_NOT_FOUND
from impacket.smbconnection import SessionError

from ptsrvtester.protocols.msrpc.utils.engine import Credential
from ptsrvtester.protocols.msrpc.utils.rpc_auth import RpcAuthenticationUnconfirmed
from ptsrvtester.protocols.msrpc.utils.rpc_proxy import ObservedRPCProxyTransport
from ptsrvtester.tests.test_msrpc_engine import msrpc_main, TEST_IP


ENGINE = "ptsrvtester.protocols.msrpc.utils.engine"


class AnonymousAccessTests(unittest.TestCase):
    def check(self, smb):
        module, report = msrpc_main(tests="ANONSMB")
        with patch(f"{ENGINE}.SMBConnection", return_value=smb):
            module.engine.results.Anonymous = module.engine.Anonymous_smb()
        module.engine.output()
        return module.engine, report

    def test_guest_access_is_retained_without_null_session_vulnerability(self):
        smb = Mock()
        smb.isGuestSession.return_value = True
        smb.listShares.return_value = [{"shi1_netname": "Public\x00", "shi1_type": 0, "shi1_remark": "Files\x00"}]
        engine, report = self.check(smb)
        self.assertEqual(engine.results.Anonymous, [])
        self.assertEqual(engine.results.AnonymousAccess, {
            "status": "complete", "reason": None, "sessionType": "guest", "login": "accepted",
            "ipcAccess": "allowed", "shareEnumeration": "complete",
            "shares": [{"name": "Public", "type": 0, "remark": "Files"}],
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
        smb.listShares.assert_not_called()
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
        smb.listShares.side_effect = OSError("reset")
        engine, _ = self.check(smb)
        self.assertEqual(engine.results.Anonymous, ["True", "True"])
        self.assertEqual(engine.results.AnonymousAccess["shareEnumeration"], "error")
        self.assertIn("ANONSMB", engine.results.module_errors)

    def test_srvsvc_share_denial_is_not_an_operational_failure(self):
        smb = Mock()
        smb.isGuestSession.return_value = False
        smb.listShares.side_effect = srvs.DCERPCSessionError(error_code=5)
        engine, _ = self.check(smb)
        self.assertEqual(engine.results.Anonymous, ["True", "True"])
        self.assertEqual(engine.results.AnonymousAccess["shareEnumeration"], "denied")
        self.assertEqual(engine.results.module_errors, {})


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
