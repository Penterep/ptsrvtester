import socket
import unittest
from struct import pack
from unittest.mock import Mock

from impacket import uuid
from impacket.dcerpc.v5 import epm
from impacket.dcerpc.v5.rpcrt import DCERPCException

from ptsrvtester.protocols.msrpc.utils.epm_inventory import (
    EpmEnumerationLimit, iter_epm_entries,
)
from ptsrvtester.protocols.msrpc.utils.rpc_auth import (
    ept_lookup_handle_free, ept_lookup_handle_freeResponse,
)


CONTEXT_ID = b"\x12" * 16


def epm_page(ports=(), *, continued=False, status=0):
    """Round-trip real NDR responses, including towers and context handles."""
    response = epm.ept_lookupResponse()
    response["entry_handle"]["context_handle_uuid"] = CONTEXT_ID if continued else b"\x00" * 16
    response["num_ents"] = len(ports)
    response["status"] = status
    for port in ports:
        interface = epm.EPMRPCInterface()
        interface["InterfaceUUID"] = epm.MSRPC_UUID_PORTMAP[:16]
        interface["MajorVersion"] = 3
        data_representation = epm.EPMRPCDataRepresentation()
        data_representation["DataRepUuid"] = uuid.string_to_bin("8a885d04-1ceb-11c9-9fe8-08002b104860")
        data_representation["MajorVersion"] = 2
        protocol = epm.EPMProtocolIdentifier()
        protocol["ProtIdentifier"] = 11
        tcp_port = epm.EPMPortAddr()
        tcp_port["IpPort"] = port
        address = epm.EPMHostAddr()
        address["Ip4addr"] = socket.inet_aton("192.0.2.20")
        raw_tower = pack("<H", 5) + b"".join(
            floor.getData() for floor in (interface, data_representation, protocol, tcp_port, address)
        )
        entry = epm.ept_entry_t()
        entry["object"] = b"\x00" * 16
        entry["annotation"] = b"test endpoint\x00"
        entry["tower"]["tower_length"] = len(raw_tower)
        entry["tower"]["tower_octet_string"] = raw_tower
        response["entries"].append(entry)
    return epm.ept_lookupResponse(response.getData())


def epm_dce(*responses, cleanup_error=None):
    pages = iter(responses)
    dce = Mock()

    def request(value, *, checkError):
        if isinstance(value, ept_lookup_handle_free):
            if cleanup_error is not None:
                raise cleanup_error
            response = ept_lookup_handle_freeResponse()
            response["status"] = 0
            return response
        response = next(pages)
        if isinstance(response, Exception):
            raise response
        return response

    dce.request.side_effect = request
    return dce


class EpmInventoryTests(unittest.TestCase):
    def lookup_requests(self, dce):
        return [call.args[0] for call in dce.request.call_args_list if isinstance(call.args[0], epm.ept_lookup)]

    def close_requests(self, dce):
        return [call.args[0] for call in dce.request.call_args_list if isinstance(call.args[0], ept_lookup_handle_free)]

    def test_pages_can_keep_the_same_context_handle_and_decode_bindings(self):
        dce = epm_dce(
            epm_page((135,), continued=True), epm_page((49667,), continued=True), epm_page((49668,)),
        )
        entries = list(iter_epm_entries(dce))
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0]["annotation"], b"test endpoint\x00")
        self.assertEqual(str(entries[0]["tower"]["Floors"][0]), "E1AF8308-5D1F-11C9-91A4-08002B14A0FA v3.0")
        self.assertEqual(epm.PrintStringBinding(entries[1]["tower"]["Floors"]), "ncacn_ip_tcp:192.0.2.20[49667]")
        requests = self.lookup_requests(dce)
        self.assertTrue(requests[0]["entry_handle"].isNull())
        self.assertEqual(requests[1]["entry_handle"]["context_handle_uuid"], CONTEXT_ID)
        self.assertEqual(requests[2]["entry_handle"]["context_handle_uuid"], CONTEXT_ID)
        self.assertEqual(self.close_requests(dce), [])
        dce.connect.assert_not_called()
        dce.bind.assert_not_called()
        dce.disconnect.assert_not_called()

    def test_empty_terminal_inventory_is_complete(self):
        for status in (0, epm.RPC_NO_MORE_ELEMENTS):
            with self.subTest(status=status):
                dce = epm_dce(epm_page(status=status))
                self.assertEqual(list(iter_epm_entries(dce)), [])
                self.assertEqual(self.close_requests(dce), [])

    def test_terminal_status_releases_a_remaining_handle(self):
        dce = epm_dce(epm_page(continued=True, status=epm.RPC_NO_MORE_ELEMENTS))
        self.assertEqual(list(iter_epm_entries(dce)), [])
        self.assertEqual(len(self.close_requests(dce)), 1)

    def test_later_timeout_keeps_prior_entries_and_releases_handle(self):
        dce = epm_dce(epm_page((135,), continued=True), TimeoutError("RPC timed out"))
        entries = iter_epm_entries(dce)
        self.assertEqual(next(entries)["annotation"], b"test endpoint\x00")
        with self.assertRaises(TimeoutError):
            next(entries)
        self.assertEqual(self.close_requests(dce)[0]["entry_handle"]["context_handle_uuid"], CONTEXT_ID)

    def test_error_status_is_not_an_empty_success(self):
        dce = epm_dce(epm_page(continued=True, status=5))
        with self.assertRaises(DCERPCException) as raised:
            list(iter_epm_entries(dce))
        self.assertEqual(raised.exception.get_error_code(), 5)
        self.assertEqual(len(self.close_requests(dce)), 1)

    def test_empty_continuation_page_is_a_protocol_error(self):
        dce = epm_dce(epm_page(continued=True))
        with self.assertRaisesRegex(RuntimeError, "did not advance"):
            list(iter_epm_entries(dce))
        self.assertEqual(len(self.lookup_requests(dce)), 1)
        self.assertEqual(len(self.close_requests(dce)), 1)

    def test_replayed_continuation_page_is_stopped(self):
        dce = epm_dce(epm_page((135,), continued=True), epm_page((135,), continued=True))
        entries = iter_epm_entries(dce)
        next(entries)
        with self.assertRaisesRegex(RuntimeError, "did not advance"):
            next(entries)
        self.assertEqual(len(self.lookup_requests(dce)), 2)
        self.assertEqual(len(self.close_requests(dce)), 1)

    def test_entry_limit_bounds_wire_request_and_preserves_entries(self):
        dce = epm_dce(epm_page((135,), continued=True), epm_page((49667,), continued=True))
        entries = iter_epm_entries(dce, max_entries=2)
        self.assertIsNotNone(next(entries))
        self.assertIsNotNone(next(entries))
        with self.assertRaises(EpmEnumerationLimit) as raised:
            next(entries)
        self.assertEqual(raised.exception.reason, "endpoint_limit_reached")
        self.assertEqual([request["max_ents"] for request in self.lookup_requests(dce)], [2, 1])
        self.assertEqual(len(self.close_requests(dce)), 1)

    def test_exact_limit_with_null_handle_is_complete(self):
        dce = epm_dce(epm_page((135, 49667)))
        self.assertEqual(len(list(iter_epm_entries(dce, max_entries=2))), 2)
        self.assertEqual(self.close_requests(dce), [])

    def test_page_limit_bounds_requests(self):
        dce = epm_dce(epm_page((135,), continued=True))
        entries = iter_epm_entries(dce, max_pages=1)
        next(entries)
        with self.assertRaises(EpmEnumerationLimit) as raised:
            next(entries)
        self.assertEqual(raised.exception.reason, "page_limit_reached")
        self.assertEqual(len(self.lookup_requests(dce)), 1)
        self.assertEqual(len(self.close_requests(dce)), 1)

    def test_bad_count_is_not_silently_truncated(self):
        for count, limit in ((2, 10), (1, 1)):
            page = epm_page((135, 49667) if limit == 1 else (135,), continued=True)
            page["num_ents"] = count if limit != 1 else 2
            dce = epm_dce(page)
            with self.subTest(count=count, limit=limit), self.assertRaisesRegex(ValueError, "entry count"):
                list(iter_epm_entries(dce, max_entries=limit))
            self.assertEqual(len(self.close_requests(dce)), 1)

    def test_bad_later_tower_keeps_previous_entry(self):
        page = epm_page((135, 49667), continued=True)
        page["entries"][1]["tower"]["tower_length"] += 1
        dce = epm_dce(page)
        entries = iter_epm_entries(dce)
        next(entries)
        with self.assertRaisesRegex(ValueError, "tower length"):
            next(entries)
        self.assertEqual(len(self.close_requests(dce)), 1)

    def test_closing_generator_frees_handle_without_another_lookup(self):
        dce = epm_dce(epm_page((135,), continued=True))
        entries = iter_epm_entries(dce)
        next(entries)
        entries.close()
        self.assertEqual(len(self.lookup_requests(dce)), 1)
        self.assertEqual(len(self.close_requests(dce)), 1)

    def test_cleanup_failure_does_not_mask_enumeration_failure(self):
        dce = epm_dce(
            epm_page((135,), continued=True), TimeoutError("lookup timed out"),
            cleanup_error=ConnectionError("cleanup failed"),
        )
        entries = iter_epm_entries(dce)
        next(entries)
        with self.assertRaisesRegex(TimeoutError, "lookup timed out"):
            next(entries)

    def test_invalid_limits_fail_before_network_access(self):
        for values in ({"max_entries": 0}, {"max_pages": -1}, {"page_size": True}):
            dce = epm_dce()
            with self.subTest(values=values), self.assertRaises(ValueError):
                list(iter_epm_entries(dce, **values))
            dce.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
