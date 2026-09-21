"""Offline SRVS paging, partial evidence, and caller-owned session checks."""
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from impacket.dcerpc.v5 import srvs
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.smbconnection import SessionError
from impacket.system_errors import ERROR_MORE_DATA

from ptsrvtester.protocols.msrpc.utils.shares import (
    SHARE_PAGE_BYTES, enumerate_shares,
)


SHARES = "ptsrvtester.protocols.msrpc.utils.shares"


def share_page(names=(), context=0, status=0, *, null_remark=False):
    response = srvs.NetrShareEnumResponse()
    response["ErrorCode"] = status
    response["ResumeHandle"] = context
    response["TotalEntries"] = len(names)
    response["InfoStruct"]["Level"] = 1
    response["InfoStruct"]["ShareInfo"]["tag"] = 1
    container = response["InfoStruct"]["ShareInfo"]["Level1"]
    container["EntriesRead"] = len(names)
    if not names:
        container["Buffer"] = NULL
    for name in names:
        item = srvs.SHARE_INFO_1()
        item["shi1_netname"] = name + "\x00"
        item["shi1_type"] = 0
        item["shi1_remark"] = NULL if null_remark else "Files\x00"
        container["Buffer"].append(item)
    return type(response)(response.getData())


class ShareEnumerationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.smb = Mock()
        self.smb.getRemoteName.return_value = "LAB"
        self.smb.getRemoteHost.return_value = "192.0.2.20"
        self.factory = self.stack.enter_context(patch(f"{SHARES}.transport.SMBTransport"))
        self.dce = self.factory.return_value.get_dce_rpc.return_value
        self.query = self.stack.enter_context(patch(f"{SHARES}.srvs.hNetrShareEnum"))

    def test_more_data_exception_is_followed_and_shares_are_retained(self):
        self.query.side_effect = [
            srvs.DCERPCSessionError(
                error_code=ERROR_MORE_DATA,
                packet=share_page(["Public"], context=47, status=ERROR_MORE_DATA),
            ),
            share_page(["Other"]),
        ]
        result = enumerate_shares(self.smb)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["returned"], 2)
        self.assertEqual(result["shares"], [
            {"name": "Public", "type": 0, "remark": "Files"},
            {"name": "Other", "type": 0, "remark": "Files"},
        ])
        self.assertEqual([call.kwargs["resumeHandle"] for call in self.query.call_args_list], [0, 47])
        self.assertEqual(self.query.call_args.kwargs["preferedMaximumLength"], SHARE_PAGE_BYTES)
        self.assertEqual(self.query.call_args.kwargs["serverName"], "\\\\192.0.2.20")
        self.factory.assert_called_once_with(
            "LAB", remote_host="192.0.2.20", filename=r"\srvsvc", smb_connection=self.smb,
        )
        self.dce.bind.assert_called_once_with(srvs.MSRPC_UUID_SRVS)
        self.dce.disconnect.assert_called_once()
        self.smb.login.assert_not_called()
        self.smb.close.assert_not_called()
        self.smb.logoff.assert_not_called()

    def test_empty_null_buffer_is_complete(self):
        self.query.return_value = share_page()
        result = enumerate_shares(self.smb)
        self.assertEqual((result["status"], result["returned"]), ("complete", 0))

    def test_null_remark_is_not_a_stringified_pointer(self):
        self.query.return_value = share_page(["Public"], null_remark=True)
        result = enumerate_shares(self.smb)
        self.assertEqual(result["status"], "complete")
        self.assertIsNone(result["shares"][0]["remark"])

    def test_high_bit_resume_handle_preserves_impacket_signed_long(self):
        self.query.side_effect = [
            share_page(["First"], context=-2147483647, status=ERROR_MORE_DATA),
            share_page(["Second"]),
        ]
        result = enumerate_shares(self.smb)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.query.call_args.kwargs["resumeHandle"], -2147483647)

    def test_later_timeout_retains_partial_inventory_and_error(self):
        failure = TimeoutError("share page timed out")
        self.query.side_effect = [share_page(["Public"], 1, ERROR_MORE_DATA), failure]
        result = enumerate_shares(self.smb)
        self.assertEqual((result["status"], result["reason"]), ("partial", "operational_error"))
        self.assertEqual(result["returned"], 1)
        self.assertIs(result["error"], failure)
        self.dce.disconnect.assert_called_once()

    def test_denials_have_no_operational_error_and_keep_prior_pages(self):
        for first_page in (False, True):
            with self.subTest(first_page=first_page):
                self.query.side_effect = (
                    [share_page(["Public"], 1, ERROR_MORE_DATA)] if first_page else []
                ) + [srvs.DCERPCSessionError(error_code=5)]
                result = enumerate_shares(self.smb)
                self.assertEqual(result["status"], "partial" if first_page else "denied")
                self.assertEqual(result["reason"], "share_enumeration_denied")
                self.assertEqual(result["returned"], int(first_page))
                self.assertIsNone(result["error"])

    def test_smb_pipe_denial_and_bind_failure_disconnect(self):
        for failure, expected in (
            (SessionError(STATUS_ACCESS_DENIED), "denied"),
            (OSError("bind transport reset"), "error"),
        ):
            with self.subTest(expected=expected):
                self.dce.reset_mock()
                self.dce.bind.side_effect = failure
                result = enumerate_shares(self.smb)
                self.assertEqual(result["status"], expected)
                self.dce.disconnect.assert_called_once()
        self.query.assert_not_called()

    def test_entry_limit_retains_only_allowed_entries(self):
        self.query.return_value = share_page(["One", "Two", "Three"])
        result = enumerate_shares(self.smb, limit=2)
        self.assertEqual(result["reason"], "share_limit_reached")
        self.assertEqual(result["returned"], 2)
        self.assertTrue(result["truncated"])
        self.assertIsNone(result["error"])
        self.query.assert_called_once()

    def test_exact_limit_is_complete_only_on_terminal_page(self):
        for status, expected in ((0, "complete"), (ERROR_MORE_DATA, "partial")):
            with self.subTest(status=status):
                self.query.return_value = share_page(["One"], context=1, status=status)
                result = enumerate_shares(self.smb, limit=1)
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["truncated"], status == ERROR_MORE_DATA)

    def test_page_limit_stops_without_an_extra_request(self):
        self.query.side_effect = [
            share_page(["One"], 1, ERROR_MORE_DATA),
            share_page(["Two"], 2, ERROR_MORE_DATA),
        ]
        result = enumerate_shares(self.smb, max_pages=2)
        self.assertEqual(result["reason"], "share_page_limit_reached")
        self.assertEqual(result["returned"], 2)
        self.assertTrue(result["truncated"])
        self.assertEqual(self.query.call_count, 2)

    def test_repeated_share_or_handle_stops_and_preserves_evidence(self):
        for second in (
            share_page(["PUBLIC"], 2, ERROR_MORE_DATA),
            share_page(["Other"], 1, ERROR_MORE_DATA),
            share_page(["Other"], 0, ERROR_MORE_DATA),
        ):
            with self.subTest(second=second["ResumeHandle"]):
                self.query.side_effect = [share_page(["Public"], 1, ERROR_MORE_DATA), second]
                result = enumerate_shares(self.smb)
                self.assertEqual(result["status"], "partial")
                self.assertIsInstance(result["error"], ValueError)
                self.assertEqual(result["shares"][0]["name"], "Public")

    def test_empty_continuation_and_inconsistent_count_are_errors(self):
        bad_count = share_page(["One"])
        bad_count["InfoStruct"]["ShareInfo"]["Level1"]["EntriesRead"] = 2
        for page in (share_page(context=1, status=ERROR_MORE_DATA), bad_count):
            with self.subTest(page=page["ErrorCode"]):
                self.query.return_value = page
                result = enumerate_shares(self.smb)
                self.assertEqual(result["status"], "error")
                self.assertIsInstance(result["error"], ValueError)
                self.assertEqual(result["shares"], [])

    def test_malformed_entry_preserves_prior_entries_on_same_page(self):
        self.query.return_value = share_page(["One", ""])
        result = enumerate_shares(self.smb)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["returned"], 1)
        self.assertIsInstance(result["error"], ValueError)

    def test_invalid_limits_fail_before_connecting(self):
        for kwargs in ({"limit": 0}, {"limit": True}, {"limit": 10001}, {"max_pages": 257}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    enumerate_shares(self.smb, **kwargs)
        self.factory.assert_not_called()


class ShareTransportOwnershipTests(unittest.TestCase):
    def test_real_transport_reuses_session_and_releases_only_its_tree(self):
        smb = Mock()
        smb.getRemoteName.return_value = "LAB"
        smb.getRemoteHost.return_value = "192.0.2.20"
        smb.getCredentials.return_value = ("audit", "secret", "LAB", "", "", "", None, None)
        smb.connectTree.return_value = 17
        with patch.object(DCERPC_v5, "bind"), patch.object(
            DCERPC_v5, "request", return_value=share_page(["Public"]),
        ) as request:
            result = enumerate_shares(smb)
        self.assertEqual(result["status"], "complete")
        smb.connectTree.assert_called_once_with("IPC$")
        smb.openFile.assert_called_once_with(17, r"\srvsvc")
        smb.disconnectTree.assert_called_once_with(17)
        smb.login.assert_not_called()
        smb.logoff.assert_not_called()
        smb.close.assert_not_called()
        request_data = request.call_args.args[0]
        self.assertEqual(request_data["ResumeHandle"], 0)
        self.assertEqual(request_data["PreferedMaximumLength"], SHARE_PAGE_BYTES)


if __name__ == "__main__":
    unittest.main()
