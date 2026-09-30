import json
import unittest
from contextlib import ExitStack, nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.dtypes import RPC_SID
from impacket.nt_errors import (
    STATUS_ACCESS_DENIED,
    STATUS_INVALID_INFO_CLASS,
    STATUS_MORE_ENTRIES,
    STATUS_NONE_MAPPED,
)

from ptsrvtester.protocols.msrpc.modules import samruserinfo
from ptsrvtester.protocols.msrpc.utils import samr_userinfo as userinfo
from ptsrvtester.protocols.msrpc.utils.engine import MsrpcEngine
from ptsrvtester.protocols.msrpc.utils.samr_session import SamrDenied


TEST_HOST = "192.0.2.41"
TEST_SID = "S-1-5-21-1-2-3"
TEST_TICKS = 133485408001234567  # 2024-01-01T00:00:00.1234567Z


def timestamp(raw):
    value = samr.OLD_LARGE_INTEGER()
    value["LowPart"] = raw & 0xFFFFFFFF
    high = (raw >> 32) & 0xFFFFFFFF
    value["HighPart"] = high - (1 << 32) if high & (1 << 31) else high
    return value


def details_response(*, mask=None, last_logon=TEST_TICKS, password_set=0, expiry=(1 << 63) - 1):
    response = samr.SamrQueryInformationUserResponse()
    response["Buffer"]["tag"] = samr.USER_INFORMATION_CLASS.UserAllInformation
    info = response["Buffer"]["All"]
    if mask is None:
        mask = sum(field[2] for field in userinfo._ACCOUNT_FIELDS + userinfo._LOGON_FIELDS)
    info["WhichFields"] = mask
    for key, raw in (
        ("LastLogon", last_logon), ("LastLogoff", 0),
        ("PasswordLastSet", password_set), ("AccountExpires", expiry),
    ):
        info[key] = timestamp(raw)
    info["BadPasswordCount"] = 0
    info["LogonCount"] = 7
    info["UserAccountControl"] = samr.USER_NORMAL_ACCOUNT
    # Exercise the actual NDR union, pointers, ULONG/USHORT and split timestamps.
    return samr.SamrQueryInformationUserResponse(response.getData())


def enumeration(entries, *, status=0, context=0):
    response = samr.SamrEnumerateUsersInDomainResponse()
    response["EnumerationContext"] = context
    response["CountReturned"] = len(entries)
    response["Buffer"]["EntriesRead"] = len(entries)
    for name, rid in entries:
        entry = samr.SAMPR_RID_ENUMERATION()
        entry["Name"] = name
        entry["RelativeId"] = rid
        response["Buffer"]["Buffer"].append(entry)
    response["ErrorCode"] = status
    return samr.SamrEnumerateUsersInDomainResponse(response.getData())


def lookup_response(*, kind=samr.SID_NAME_USE.SidTypeUser, rid=1001):
    response = samr.SamrLookupNamesInDomainResponse()
    for key, number in (("RelativeIds", rid), ("Use", kind)):
        response[key]["Count"] = 1
        item = samr.ULONG()
        item["Data"] = number
        response[key]["Element"].append(item)
    return samr.SamrLookupNamesInDomainResponse(response.getData())


class TimestampTests(unittest.TestCase):
    def test_exact_ticks_and_utc_fraction(self):
        value = userinfo.parse_samr_timestamp(timestamp(TEST_TICKS), zero_meaning="unknown")
        self.assertEqual(value["raw100ns"], str(TEST_TICKS))
        self.assertEqual(value["utc"], "2024-01-01T00:00:00.1234567Z")
        self.assertEqual(value["meaning"], "timestamp")
        self.assertEqual(json.loads(json.dumps(value))["raw100ns"], str(TEST_TICKS))

    def test_zero_and_expiry_sentinels_have_field_specific_meaning(self):
        for raw, zero, expiry, expected in (
            (0, "unknown", False, "unknown"),
            (0, "not_set", False, "not_set"),
            (0, "never", True, "never"),
            ((1 << 63) - 1, "never", True, "never"),
        ):
            with self.subTest(raw=raw, zero=zero, expiry=expiry):
                value = userinfo.parse_samr_timestamp(timestamp(raw), zero_meaning=zero, expiry=expiry)
                self.assertEqual(value["status"], "complete")
                self.assertEqual(value["meaning"], expected)
                self.assertIsNone(value["utc"])

    def test_invalid_or_unrenderable_timestamps_keep_raw_value(self):
        for raw in (-1, (1 << 63) - 1):
            value = userinfo.parse_samr_timestamp(timestamp(raw), zero_meaning="not_set")
            self.assertEqual(value["status"], "error")
            self.assertEqual(value["meaning"], "unknown")
            self.assertEqual(value["raw100ns"], str(raw))
            self.assertIsNone(value["utc"])

    def test_unreturned_zero_is_unknown_and_returned_zero_is_measured(self):
        info = details_response(mask=samr.USER_ALL_BADPASSWORDCOUNT)["Buffer"]["All"]
        parsed = userinfo.parse_user_information(info, userinfo._LOGON_FIELDS)
        self.assertEqual(parsed["status"], "partial")
        self.assertEqual(parsed["badPasswordCount"]["value"], 0)
        self.assertEqual(parsed["badPasswordCount"]["status"], "complete")
        self.assertIsNone(parsed["lastLogon"]["raw100ns"])
        self.assertEqual(parsed["lastLogon"]["meaning"], "unknown")
        self.assertEqual(parsed["lastLogon"]["reason"], "not_returned")

    def test_one_malformed_field_preserves_other_fields(self):
        info = {"WhichFields": samr.USER_ALL_LOGONCOUNT | samr.USER_ALL_BADPASSWORDCOUNT,
                "LogonCount": 3, "BadPasswordCount": -1}
        parsed = userinfo.parse_user_information(info, userinfo._LOGON_FIELDS)
        self.assertEqual(parsed["logonCount"]["value"], 3)
        self.assertEqual(parsed["badPasswordCount"]["status"], "error")
        self.assertEqual(parsed["status"], "partial")


class UserInfoTests(unittest.TestCase):
    def setUp(self):
        self.engine = MsrpcEngine(SimpleNamespace(
            ip=TEST_HOST, username="audit", password="secret-test-value", domain="AUTH",
            samr_max_users=1000, samr_user=None, samr_domain=None,
            json=False, output=None,
        ), Mock())
        self.engine.ptprint = Mock()
        self.dce = Mock()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.session = self.mock("samr_session", return_value=nullcontext((self.dce, "server")))
        self.domains = self.mock("iter_samr_domains", return_value=["LOCAL"])
        sid = RPC_SID()
        sid.fromCanonical(TEST_SID)
        self.domain_lookup = self.mock("samr.hSamrLookupDomainInSamServer", return_value={"DomainId": sid})
        self.open_domain = self.mock("samr.hSamrOpenDomain", return_value={"DomainHandle": "domain"})
        self.enum = self.mock("samr.hSamrEnumerateUsersInDomain", return_value=enumeration([("alice", 1001)]))
        self.lookup = self.mock("samr.hSamrLookupNamesInDomain", return_value=lookup_response())
        self.open_user = self.mock("samr.hSamrOpenUser", side_effect=lambda dce, domain, **kw: {"UserHandle": f"u-{kw['userId']}-{kw['desiredAccess']}"})
        self.query = self.mock("samr.hSamrQueryInformationUser", side_effect=lambda *a, **kw: details_response())
        self.close = self.mock("samr.hSamrCloseHandle")

    def mock(self, target, **kwargs):
        return self.stack.enter_context(patch.object(userinfo, target, **kwargs)) if "." not in target else self.stack.enter_context(patch(f"{userinfo.__name__}.{target}", **kwargs))

    def run_query(self):
        return userinfo.query_samr_user_info(self.engine)

    def run_module_and_export(self):
        ctx = SimpleNamespace(
            engine=self.engine, ptjsonlib=self.engine.ptjsonlib,
            out=Mock(), debug=Mock(),
        )
        self.engine.ptprint = MsrpcEngine.ptprint.__get__(self.engine, MsrpcEngine)
        samruserinfo.run(ctx)
        self.engine.output()
        properties = self.engine.ptjsonlib.create_node_object.call_args.args[3]
        console = [item.args[0] for item in ctx.out.call_args_list]
        return console, json.loads(json.dumps(properties))["samrUserInfo"]

    def test_returned_zero_last_logon_is_unknown_in_console_and_json(self):
        self.query.side_effect = lambda *a, **kw: details_response(last_logon=0)

        console, exported = self.run_module_and_export()

        self.assertEqual(exported["status"], "complete")
        self.assertEqual(exported["sourceHost"], TEST_HOST)
        self.assertEqual(exported["logonScope"], "queried_server")
        user = exported["domains"][0]["users"][0]
        self.assertEqual(user["logon"]["lastLogon"], {
            "status": "complete", "reason": None, "raw100ns": "0",
            "utc": None, "meaning": "unknown",
        })
        self.assertIn("  lastLogon: unknown", console)
        self.assertNotIn("  lastLogon: never", console)
        self.assertEqual(user["account"]["accountExpires"]["meaning"], "never")
        self.assertIn("  accountExpires: never", console)
        self.engine.ptjsonlib.add_vulnerability.assert_not_called()

    def test_unreturned_last_logon_stays_distinct_from_measured_zero(self):
        mask = sum(field[2] for field in userinfo._ACCOUNT_FIELDS + userinfo._LOGON_FIELDS)
        mask &= ~samr.USER_ALL_LASTLOGON
        self.query.side_effect = lambda *a, **kw: details_response(mask=mask, last_logon=0)

        console, exported = self.run_module_and_export()

        self.assertEqual(exported["status"], "partial")
        user = exported["domains"][0]["users"][0]
        self.assertEqual(user["logon"]["lastLogon"], {
            "status": "unknown", "reason": "not_returned", "raw100ns": None,
            "utc": None, "meaning": "unknown",
        })
        self.assertIn("  lastLogon: unknown (not_returned)", console)
        self.assertNotIn("  lastLogon: unknown", console)
        self.assertNotIn("  lastLogon: never", console)
        self.engine.ptjsonlib.add_vulnerability.assert_not_called()

    def test_complete_query_uses_minimal_separate_read_access_and_cleans_handles(self):
        result = self.run_query()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["returned"], 1)
        self.assertEqual(result["logonScope"], "queried_server")
        user = result["domains"][0]["users"][0]
        self.assertEqual(user["sid"], TEST_SID + "-1001")
        self.assertEqual(user["sourceHost"], TEST_HOST)
        self.assertEqual(user["sourceDomain"], "LOCAL")
        self.assertEqual(user["logon"]["logonCount"]["value"], 7)
        self.assertEqual(user["account"]["accountExpires"]["meaning"], "never")
        self.assertEqual(self.open_user.call_args_list, [
            call(self.dce, "domain", desiredAccess=samr.USER_READ_ACCOUNT, userId=1001),
            call(self.dce, "domain", desiredAccess=samr.USER_READ_LOGON, userId=1001),
        ])
        self.assertTrue(all(item.kwargs["userInformationClass"] == samr.USER_INFORMATION_CLASS.UserAllInformation for item in self.query.call_args_list))
        self.assertEqual(self.enum.call_args.kwargs["userAccountControl"], samr.USER_NORMAL_ACCOUNT)
        self.close.assert_has_calls([call(self.dce, "u-1001-16"), call(self.dce, "u-1001-8"), call(self.dce, "domain")])
        self.assertNotIn("secret-test-value", json.dumps(result))
        self.assertEqual(self.engine.results.module_errors, {})

    def test_logon_denied_preserves_account_details_and_is_not_module_error(self):
        def opened(dce, domain, **kwargs):
            if kwargs["desiredAccess"] == samr.USER_READ_LOGON:
                raise samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED)
            return {"UserHandle": "account"}
        self.open_user.side_effect = opened
        result = self.run_query()
        user = result["domains"][0]["users"][0]
        self.assertEqual(result["status"], "partial")
        self.assertEqual(user["account"]["status"], "complete")
        self.assertEqual(user["logon"]["status"], "denied")
        self.assertIsNone(user["logon"]["logonCount"]["value"])
        self.assertEqual(self.engine.results.module_errors, {})
        self.close.assert_has_calls([call(self.dce, "account"), call(self.dce, "domain")])

    def test_unsupported_account_query_preserves_logon_details_and_closes_handle(self):
        self.query.side_effect = [samr.DCERPCSessionError(error_code=STATUS_INVALID_INFO_CLASS), details_response()]
        result = self.run_query()
        user = result["domains"][0]["users"][0]
        self.assertEqual(user["account"]["status"], "unsupported")
        self.assertEqual(user["logon"]["status"], "complete")
        self.assertEqual(result["status"], "partial")
        self.close.assert_any_call(self.dce, "u-1001-16")
        self.assertEqual(self.engine.results.module_errors, {})

    def test_operational_error_is_sanitized_and_other_section_survives(self):
        self.query.side_effect = [RuntimeError("secret-test-value"), details_response()]
        result = self.run_query()
        self.assertEqual(result["status"], "partial")
        self.assertIn("SAMRUSERINFO", self.engine.results.module_errors)
        self.assertNotIn("secret-test-value", str(self.engine.results.module_errors))
        self.assertEqual(result["domains"][0]["users"][0]["logon"]["status"], "complete")

    def test_selected_user_uses_name_lookup_without_user_enumeration(self):
        self.engine.args.samr_user = "Alice"
        self.engine.args.samr_domain = "local"
        result = self.run_query()
        self.lookup.assert_called_once_with(self.dce, "domain", ["Alice"])
        self.enum.assert_not_called()
        self.assertEqual(self.open_domain.call_args.kwargs["desiredAccess"], samr.DOMAIN_LOOKUP)
        self.assertEqual(result["returned"], 1)

    def test_selected_name_that_is_group_is_not_opened_as_user(self):
        self.engine.args.samr_user = "Administrators"
        self.lookup.return_value = lookup_response(kind=samr.SID_NAME_USE.SidTypeAlias)
        result = self.run_query()
        self.assertEqual(result["reason"], "selected_name_is_not_user")
        self.open_user.assert_not_called()

    def test_unmapped_selected_user_is_complete_empty_inventory(self):
        self.engine.args.samr_user = "missing"
        self.lookup.side_effect = samr.DCERPCSessionError(error_code=STATUS_NONE_MAPPED)
        result = self.run_query()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["reason"], "user_not_found")
        self.assertEqual(result["returned"], 0)
        self.assertEqual(self.engine.results.module_errors, {})

    def test_domain_filter_is_distinct_from_authentication_domain(self):
        self.engine.args.samr_domain = "missing"
        result = self.run_query()
        self.assertEqual(result["reason"], "domain_not_found")
        self.assertEqual(self.engine.args.domain, "AUTH")
        self.domain_lookup.assert_not_called()

    def test_builtin_domain_is_skipped(self):
        sid = RPC_SID()
        sid.fromCanonical("S-1-5-32")
        self.domain_lookup.return_value = {"DomainId": sid}
        result = self.run_query()
        self.assertEqual(result["domains"], [])
        self.assertEqual(result["reason"], "no_account_domains")
        self.open_domain.assert_not_called()

    def test_pagination_preserves_preceding_page_when_next_request_fails(self):
        self.enum.side_effect = [enumeration([("alice", 1001)], status=STATUS_MORE_ENTRIES, context=1), RuntimeError("broken connection")]
        result = self.run_query()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["returned"], 1)
        self.assertEqual(result["domains"][0]["reason"], "operational_error")
        self.close.assert_any_call(self.dce, "domain")

    def test_more_entries_exception_packet_is_processed(self):
        page = enumeration([("alice", 1001)], status=STATUS_MORE_ENTRIES, context=1)
        self.enum.side_effect = [samr.DCERPCSessionError(error_code=STATUS_MORE_ENTRIES, packet=page), enumeration([("bob", 1002)])]
        result = self.run_query()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["returned"], 2)
        self.assertEqual(self.enum.call_args_list[1].kwargs["enumerationContext"], 1)

    def test_limit_stops_queries_inside_page(self):
        self.engine.args.samr_max_users = 1
        self.enum.return_value = enumeration([("alice", 1001), ("bob", 1002)])
        result = self.run_query()
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["returned"], 1)
        self.assertEqual(self.open_user.call_count, 2)

    def test_exact_final_page_limit_is_complete(self):
        self.engine.args.samr_max_users = 1
        result = self.run_query()
        self.assertEqual(result["status"], "complete")
        self.assertFalse(result["truncated"])

    def test_global_limit_applies_across_domains(self):
        self.engine.args.samr_max_users = 1
        self.domains.return_value = ["LOCAL", "OTHER"]
        result = self.run_query()
        self.assertTrue(result["truncated"])
        self.assertEqual(result["returned"], 1)
        self.assertEqual(self.open_domain.call_count, 1)

    def test_stalled_pagination_is_bounded_and_preserves_first_page(self):
        self.enum.return_value = enumeration([("alice", 1001)], status=STATUS_MORE_ENTRIES, context=0)
        result = self.run_query()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["returned"], 1)
        self.assertEqual(self.enum.call_count, 1)
        self.assertIn("SAMRUSERINFO", self.engine.results.module_errors)

    def test_malformed_count_is_rejected_before_querying_users(self):
        page = enumeration([("alice", 1001)])
        page["CountReturned"] = 2
        self.enum.return_value = page
        result = self.run_query()
        self.assertEqual(result["status"], "error")
        self.open_user.assert_not_called()

    def test_denied_domain_does_not_prevent_other_domain(self):
        self.domains.return_value = ["DENIED", "LOCAL"]
        self.open_domain.side_effect = [samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED), {"DomainHandle": "domain"}]
        result = self.run_query()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["domains"][0]["status"], "denied")
        self.assertEqual(result["domains"][1]["returned"], 1)
        self.assertEqual(self.engine.results.module_errors, {})

    def test_guest_session_reports_denied_without_rpc_queries(self):
        self.session.side_effect = SamrDenied("guest_session")
        result = self.run_query()
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["reason"], "guest_session")
        self.enum.assert_not_called()

    def test_invalid_limit_is_rejected_before_connection(self):
        self.engine.args.samr_max_users = 0
        result = self.run_query()
        self.assertEqual(result["reason"], "invalid_user_limit")
        self.session.assert_not_called()

    def test_output_file_contains_details_and_source_scope(self):
        self.engine.args.output = "unused-mocked.txt"
        self.engine.write_to_file = Mock()
        self.run_query()
        output = "\n".join(self.engine.write_to_file.call_args.args[0])
        self.assertIn("queried server only", output)
        self.assertIn("2024-01-01T00:00:00.1234567Z", output)
        self.assertIn("accountExpires: never", output)


if __name__ == "__main__":
    unittest.main()
