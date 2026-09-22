import unittest
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.dtypes import RPC_SID, ULONG
from impacket.dcerpc.v5.ndr import NULL
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_MORE_ENTRIES, STATUS_NOT_SUPPORTED

from ptsrvtester.protocols.msrpc.utils.samr_groups import enumerate_samr_groups
from ptsrvtester.protocols.msrpc.utils.samr_session import SamrDenied
from ptsrvtester.tests.test_msrpc_session import engine_fixture, enumeration_fixture


GROUPS = "ptsrvtester.protocols.msrpc.utils.samr_groups"


def sid_fixture(text):
    sid = RPC_SID()
    sid.fromCanonical(text)
    return sid


def group_page(entries=(), context=0, status=0):
    return enumeration_fixture(entries, context, status, samr.SamrEnumerateGroupsInDomainResponse)


def group_members_fixture(members=()):
    response = samr.SamrGetMembersInGroupResponse()
    response["ErrorCode"] = 0
    response["Members"]["MemberCount"] = len(members)
    if not members:
        response["Members"]["Members"] = NULL
        response["Members"]["Attributes"] = NULL
    for rid, attributes in members:
        rid_value, attr_value = ULONG(), ULONG()
        rid_value["Data"], attr_value["Data"] = rid, attributes
        response["Members"]["Members"].append(rid_value)
        response["Members"]["Attributes"].append(attr_value)
    return type(response)(response.getData())


def alias_members_fixture(sids=()):
    response = samr.SamrGetMembersInAliasResponse()
    response["ErrorCode"] = 0
    response["Members"]["Count"] = len(sids)
    if not sids:
        response["Members"]["Sids"] = NULL
    for text in sids:
        member = samr.PSAMPR_SID_INFORMATION()
        member["SidPointer"] = sid_fixture(text)
        response["Members"]["Sids"].append(member)
    return type(response)(response.getData())


class SamrGroupsTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.engine = engine_fixture()

        @contextmanager
        def session(engine):
            yield "dce", "server"

        self.stack.enter_context(patch(f"{GROUPS}.samr_session", side_effect=session))
        self.domains = self.stack.enter_context(patch(f"{GROUPS}.iter_samr_domains", return_value=["SERVER"]))
        self.lookup = self.stack.enter_context(patch(
            f"{GROUPS}.samr.hSamrLookupDomainInSamServer",
            return_value={"DomainId": sid_fixture("S-1-5-21-1-2-3")},
        ))
        self.open_domain = self.stack.enter_context(patch(
            f"{GROUPS}.samr.hSamrOpenDomain", return_value={"DomainHandle": "domain"},
        ))
        self.groups = self.stack.enter_context(patch(
            f"{GROUPS}.samr.hSamrEnumerateGroupsInDomain", return_value=group_page(),
        ))
        self.aliases = self.stack.enter_context(patch(
            f"{GROUPS}.samr.hSamrEnumerateAliasesInDomain", return_value=group_page(),
        ))
        self.open_group = self.stack.enter_context(patch(
            f"{GROUPS}.samr.hSamrOpenGroup", return_value={"GroupHandle": "group"},
        ))
        self.open_alias = self.stack.enter_context(patch(
            f"{GROUPS}.samr.hSamrOpenAlias", return_value={"AliasHandle": "alias"},
        ))
        self.group_members = self.stack.enter_context(patch(
            f"{GROUPS}.samr.hSamrGetMembersInGroup", return_value=group_members_fixture(),
        ))
        self.alias_members = self.stack.enter_context(patch(
            f"{GROUPS}.samr.hSamrGetMembersInAlias", return_value=alias_members_fixture(),
        ))
        self.close = self.stack.enter_context(patch(f"{GROUPS}.samr.hSamrCloseHandle"))

    def test_ndr_group_alias_members_and_builtin_are_retained(self):
        self.domains.return_value = ["SERVER", "BUILTIN"]
        self.lookup.side_effect = [
            {"DomainId": sid_fixture("S-1-5-21-1-2-3")},
            {"DomainId": sid_fixture("S-1-5-32")},
        ]
        self.groups.side_effect = [group_page((("Operators", 1001),)), group_page()]
        self.aliases.side_effect = [group_page(), group_page((("Administrators", 544),))]
        self.group_members.return_value = group_members_fixture(((1100, 7), (1101, 0)))
        self.alias_members.return_value = alias_members_fixture(("S-1-5-21-1-2-3-500", "S-1-5-21-9-8-7-512"))
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["returned"], 2)
        group = result["domains"][0]["groups"][0]
        self.assertEqual(group["members"][0], {"rid": 1100, "sid": "S-1-5-21-1-2-3-1100", "attributes": 7})
        alias = result["domains"][1]["groups"][0]
        self.assertEqual(alias["sid"], "S-1-5-32-544")
        self.assertEqual(alias["members"][1], {"sid": "S-1-5-21-9-8-7-512"})
        self.open_group.assert_called_once_with("dce", "domain", desiredAccess=samr.GROUP_LIST_MEMBERS, groupId=1001)
        self.open_alias.assert_called_once_with("dce", "domain", desiredAccess=samr.ALIAS_LIST_MEMBERS, aliasId=544)
        self.assertEqual(self.close.call_count, 4)
        self.engine.ptjsonlib.add_vulnerability.assert_not_called()

    def test_pagination_handles_more_entries_exception(self):
        page = group_page((("First", 1001),), 42, STATUS_MORE_ENTRIES)
        self.groups.side_effect = [
            samr.DCERPCSessionError(error_code=STATUS_MORE_ENTRIES, packet=page),
            group_page((("Second", 1002),)),
        ]
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["returned"], 2)
        self.assertEqual(self.groups.call_args_list[1].kwargs["enumerationContext"], 42)

    def test_global_limit_applies_across_groups_and_aliases(self):
        self.engine.args.samr_max_groups = 1
        self.groups.return_value = group_page((("Only", 1001),))
        self.aliases.return_value = group_page((("Skipped", 1002),))
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["reason"], "group_limit_reached")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["returned"], 1)
        self.open_alias.assert_not_called()

    def test_exact_limit_with_no_more_records_is_complete(self):
        self.engine.args.samr_max_groups = 1
        self.groups.return_value = group_page((("Only", 1001),))
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "complete")
        self.assertFalse(result["truncated"])

    def test_member_limit_is_per_group_retained_output(self):
        self.engine.args.samr_max_members = 1
        self.groups.return_value = group_page((("One", 1001), ("Two", 1002)))
        self.group_members.return_value = group_members_fixture(((1100, 7), (1101, 7)))
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "partial")
        for group in result["domains"][0]["groups"]:
            self.assertEqual(group["memberCount"], 2)
            self.assertEqual(group["membersReturned"], 1)
            self.assertTrue(group["membersTruncated"])
        self.assertEqual(self.group_members.call_count, 2)
        self.assertEqual(result["memberLimitScope"], "per_group_output")

    def test_member_access_denied_preserves_raw_group_identifiers(self):
        self.groups.return_value = group_page((("Protected", 1001),))
        self.open_group.side_effect = samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED)
        result = enumerate_samr_groups(self.engine)
        group = result["domains"][0]["groups"][0]
        self.assertEqual(result["status"], "partial")
        self.assertEqual(group["sid"], "S-1-5-21-1-2-3-1001")
        self.assertEqual(group["membersStatus"], "denied")
        self.assertIsNone(group["memberCount"])
        self.assertEqual(self.engine.results.module_errors, {})

    def test_unsupported_members_are_distinguished(self):
        self.aliases.return_value = group_page((("Alias", 1001),))
        self.alias_members.side_effect = samr.DCERPCSessionError(error_code=STATUS_NOT_SUPPORTED)
        group = enumerate_samr_groups(self.engine)["domains"][0]["groups"][0]
        self.assertEqual(group["membersStatus"], "unsupported")
        self.assertEqual(self.engine.results.module_errors, {})

    def test_error_is_sanitized_and_later_groups_survive(self):
        self.groups.return_value = group_page((("Broken", 1001), ("Available", 1002)))
        self.group_members.side_effect = [RuntimeError("audit-user audit-secret AUDIT"), group_members_fixture(((500, 7),))]
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["domains"][0]["groups"][1]["membersReturned"], 1)
        error = self.engine.results.module_errors["SAMRGROUPS"]
        for credential in ("audit-user", "audit-secret", "AUDIT"):
            self.assertNotIn(credential, error)
        self.assertIn("[redacted]", error)
        self.assertEqual(self.close.call_count, 3)

    def test_denied_group_enumeration_still_queries_aliases(self):
        self.groups.side_effect = samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED)
        self.aliases.return_value = group_page((("Available", 1001),))
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["returned"], 1)
        self.assertEqual(result["domains"][0]["enumerations"]["groups"]["status"], "denied")

    def test_all_enumerations_denied(self):
        self.groups.side_effect = samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED)
        self.aliases.side_effect = samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED)
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["returned"], 0)

    def test_invalid_member_counts_preserve_inventory(self):
        self.groups.return_value = group_page((("Broken", 1001),))
        response = group_members_fixture(((500, 7),))
        response["Members"]["MemberCount"] = 2
        self.group_members.return_value = response
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["returned"], 1)
        self.assertEqual(result["domains"][0]["groups"][0]["membersStatus"], "error")
        self.assertIn("SAMRGROUPS", self.engine.results.module_errors)

    def test_malformed_member_retains_valid_prefix(self):
        self.groups.return_value = group_page((("Broken", 1001),))
        self.group_members.return_value = {
            "ErrorCode": 0,
            "Members": {"MemberCount": 2, "Members": [500, -1], "Attributes": [7, 7]},
        }
        group = enumerate_samr_groups(self.engine)["domains"][0]["groups"][0]
        self.assertEqual(group["membersStatus"], "partial")
        self.assertEqual(group["membersReturned"], 1)
        self.assertEqual(group["members"][0]["rid"], 500)

    def test_stalled_pagination_stops_and_preserves_results(self):
        self.groups.return_value = group_page((("First", 1001),), 0, STATUS_MORE_ENTRIES)
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["returned"], 1)
        self.groups.assert_called_once()
        self.assertIn("did not advance", self.engine.results.module_errors["SAMRGROUPS"])

    def test_domain_failure_does_not_discard_other_domain(self):
        self.domains.return_value = ["Denied", "Available"]
        self.lookup.side_effect = [
            samr.DCERPCSessionError(error_code=STATUS_ACCESS_DENIED),
            {"DomainId": sid_fixture("S-1-5-32")},
        ]
        self.aliases.return_value = group_page((("Administrators", 544),))
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["domains"][0]["status"], "denied")
        self.assertEqual(result["domains"][1]["groups"][0]["sid"], "S-1-5-32-544")

    def test_no_domains_and_empty_member_arrays_are_complete(self):
        self.groups.return_value = group_page((("Empty group", 1001),))
        self.aliases.return_value = group_page((("Empty alias", 1002),))
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "complete")
        self.assertTrue(all(g["memberCount"] == 0 for g in result["domains"][0]["groups"]))
        self.domains.return_value = []
        result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["returned"], 0)

    def test_guest_denied_without_module_error(self):
        with patch(f"{GROUPS}.samr_session", side_effect=SamrDenied("guest_session")):
            result = enumerate_samr_groups(self.engine)
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["reason"], "guest_session")
        self.assertEqual(self.engine.results.module_errors, {})
