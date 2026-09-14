import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.ndr import NULL
from impacket.nt_errors import (
    STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE, STATUS_MORE_ENTRIES,
    STATUS_OBJECT_NAME_NOT_FOUND,
)
from impacket.smbconnection import SessionError

from ptsrvtester.protocols.msrpc.utils.engine import MsrpcEngine
from ptsrvtester.protocols.msrpc.utils.samr_session import (
    SamrDenied, enumeration_page, iter_samr_domains, samr_session,
)


SESSION = "ptsrvtester.protocols.msrpc.utils.samr_session"


def engine_fixture(**overrides):
    values = dict(
        ip="192.0.2.20", username="audit-user", password="audit-secret",
        domain="AUDIT", output=None, samr_max_groups=1000, samr_max_members=1000,
        smb_port=1445, timeout_seconds=3.0,
    )
    values.update(overrides)
    return MsrpcEngine(SimpleNamespace(**values), Mock())


def enumeration_fixture(entries=(), context=0, status=0, response_class=None):
    response = (response_class or samr.SamrEnumerateDomainsInSamServerResponse)()
    response["EnumerationContext"] = context
    response["CountReturned"] = len(entries)
    response["ErrorCode"] = status
    if not entries:
        response["Buffer"] = NULL
    else:
        response["Buffer"]["EntriesRead"] = len(entries)
        for name, rid in entries:
            entry = samr.SAMPR_RID_ENUMERATION()
            entry["Name"] = name
            entry["RelativeId"] = rid
            response["Buffer"]["Buffer"].append(entry)
    return type(response)(response.getData())


class SamrSessionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.engine = engine_fixture()
        self.smb = Mock()
        self.smb.isGuestSession.return_value = False
        self.stack.enter_context(patch(f"{SESSION}.SMBConnection", return_value=self.smb))
        self.factory = self.stack.enter_context(patch(f"{SESSION}.transport.DCERPCTransportFactory"))
        self.rpc_transport = self.factory.return_value
        self.dce = self.rpc_transport.get_dce_rpc.return_value
        self.connect = self.stack.enter_context(patch(
            f"{SESSION}.samr.hSamrConnect5", return_value={"ServerHandle": "server"},
        ))
        self.close_handle = self.stack.enter_context(patch(f"{SESSION}.samr.hSamrCloseHandle"))

    def test_minimal_rights_no_ntlm_fallback_and_cleanup(self):
        with samr_session(self.engine) as pair:
            self.assertEqual(pair, (self.dce, "server"))
        self.smb.login.assert_called_once_with(
            "audit-user", "audit-secret", "AUDIT", ntlmFallback=False,
        )
        self.rpc_transport.set_dport.assert_called_once_with(1445)
        self.rpc_transport.set_connect_timeout.assert_called_once_with(3.0)
        self.rpc_transport.set_smb_connection.assert_called_once_with(self.smb)
        self.dce.bind.assert_called_once_with(samr.MSRPC_UUID_SAMR)
        self.connect.assert_called_once_with(
            self.dce, desiredAccess=samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN,
        )
        self.close_handle.assert_called_once_with(self.dce, "server")
        self.dce.disconnect.assert_called_once()
        self.smb.logoff.assert_called_once()
        self.smb.close.assert_called_once()

    def test_guest_mapping_stops_before_rpc(self):
        self.smb.isGuestSession.return_value = True
        with self.assertRaises(SamrDenied) as raised:
            with samr_session(self.engine):
                self.fail("Guest session must not yield")
        self.assertEqual(raised.exception.reason, "guest_session")
        self.factory.assert_not_called()
        self.smb.logoff.assert_called_once()
        self.smb.close.assert_called_once()

    def test_authentication_refusal_closes_unlogged_session(self):
        self.smb.login.side_effect = SessionError(STATUS_LOGON_FAILURE)
        with self.assertRaises(SamrDenied) as raised:
            with samr_session(self.engine):
                pass
        self.assertEqual(raised.exception.reason, "authentication_denied")
        self.smb.logoff.assert_not_called()
        self.smb.close.assert_called_once()
        self.factory.assert_not_called()

    def test_operational_login_error_is_not_denied(self):
        self.smb.login.side_effect = SessionError(STATUS_OBJECT_NAME_NOT_FOUND)
        with self.assertRaises(SessionError):
            with samr_session(self.engine):
                pass
        self.smb.close.assert_called_once()
        self.factory.assert_not_called()

    def test_bind_access_refusal_cleans_up(self):
        self.dce.bind.side_effect = samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED)
        with self.assertRaises(SamrDenied) as raised:
            with samr_session(self.engine):
                pass
        self.assertEqual(raised.exception.reason, "samr_access_denied")
        self.connect.assert_not_called()
        self.dce.disconnect.assert_called_once()
        self.smb.close.assert_called_once()

    def test_caller_error_closes_server_and_connections(self):
        with self.assertRaisesRegex(RuntimeError, "operation failed"):
            with samr_session(self.engine):
                raise RuntimeError("operation failed")
        self.close_handle.assert_called_once_with(self.dce, "server")
        self.dce.disconnect.assert_called_once()
        self.smb.close.assert_called_once()


class SamrEnumerationTests(unittest.TestCase):
    def test_ndr_pages_and_null_terminal_buffer(self):
        first = enumeration_fixture((("BUILTIN", 0),), context=7, status=STATUS_MORE_ENTRIES)
        more = samr.DCERPCSessionError(error_code=STATUS_MORE_ENTRIES, packet=first)
        with patch(f"{SESSION}.samr.hSamrEnumerateDomainsInSamServer", side_effect=[
            more, enumeration_fixture((("SERVER", 0),)),
        ]) as enumerate_rpc:
            self.assertEqual(list(iter_samr_domains(engine_fixture(), "dce", "server")), ["BUILTIN", "SERVER"])
        self.assertEqual(enumerate_rpc.call_args_list[1].kwargs["enumerationContext"], 7)
        entries, _, more = enumeration_page(enumeration_fixture())
        self.assertEqual(entries, [])
        self.assertFalse(more)

    def test_inconsistent_counts_are_not_empty_success(self):
        response = enumeration_fixture((("SERVER", 0),))
        response["CountReturned"] = 2
        with self.assertRaises(ValueError):
            enumeration_page(response)

    def test_status_failure_is_not_empty_success(self):
        response = enumeration_fixture()
        response["ErrorCode"] = STATUS_ACCESS_DENIED
        with self.assertRaises(samr.DCERPCSessionError):
            enumeration_page(response)

    def test_stalled_context_preserves_yielded_domain(self):
        page = enumeration_fixture((("SERVER", 0),), context=0, status=STATUS_MORE_ENTRIES)
        with patch(f"{SESSION}.samr.hSamrEnumerateDomainsInSamServer", return_value=page) as call_rpc:
            domains = iter_samr_domains(engine_fixture(), "dce", "server")
            self.assertEqual(next(domains), "SERVER")
            with self.assertRaisesRegex(RuntimeError, "did not advance"):
                next(domains)
        call_rpc.assert_called_once()

    def test_page_safety_cap_bounds_changing_context(self):
        page = enumeration_fixture((("SERVER", 0),), context=1, status=STATUS_MORE_ENTRIES)
        with patch(f"{SESSION}.MAX_ENUMERATION_PAGES", 1), patch(
            f"{SESSION}.samr.hSamrEnumerateDomainsInSamServer", return_value=page,
        ) as call_rpc:
            domains = iter_samr_domains(engine_fixture(), "dce", "server")
            self.assertEqual(next(domains), "SERVER")
            with self.assertRaisesRegex(RuntimeError, "page limit"):
                next(domains)
        call_rpc.assert_called_once()

    def test_empty_continuation_and_duplicate_domains_fail(self):
        response = enumeration_fixture(context=1, status=STATUS_MORE_ENTRIES)
        with self.assertRaisesRegex(ValueError, "empty continuation"):
            enumeration_page(response)
        duplicate = enumeration_fixture((("SERVER", 0), ("server", 0)))
        with patch(f"{SESSION}.samr.hSamrEnumerateDomainsInSamServer", return_value=duplicate):
            domains = iter_samr_domains(engine_fixture(), "dce", "server")
            self.assertEqual(next(domains), "SERVER")
            with self.assertRaisesRegex(ValueError, "repeated a domain"):
                next(domains)
