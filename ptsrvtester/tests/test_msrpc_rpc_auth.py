"""Offline packet and read-only probe regression tests; no target connections."""
import hashlib
import hmac
import struct
import unittest
from unittest.mock import Mock, patch

from Cryptodome.Cipher import ARC4
from impacket import ntlm, uuid
from impacket.dcerpc.v5 import epm, lsad, mgmt, samr
from impacket.dcerpc.v5.rpcrt import (
    DCERPCException, DCERPC_v5, MSRPC_FAULT, MSRPC_RESPONSE,
    PFC_FIRST_FRAG, PFC_LAST_FRAG, RPC_C_AUTHN_LEVEL_CONNECT,
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_WINNT,
)

from ptsrvtester.protocols.msrpc.utils.rpc_auth import (
    RpcAuthenticationUnconfirmed, UnsupportedRpcProbe, VerifiedDCERPC,
    confirm_rpc_access, ept_lookup_handle_free,
)


SESSION_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
FLAGS = (
    ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | ntlm.NTLMSSP_NEGOTIATE_SIGN | ntlm.NTLMSSP_NEGOTIATE_128
    | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
)


def server_signer(key=SESSION_KEY):
    """Independent MS-NLMP HMAC/RC4 packet fixture, not the production SIGN helper."""
    signing = hashlib.md5(key + b"session key to server-to-client signing key magic constant\x00").digest()
    sealing = hashlib.md5(key + b"session key to server-to-client sealing key magic constant\x00").digest()
    rc4 = ARC4.new(sealing)

    def sign(packet, sequence):
        checksum = hmac.new(signing, struct.pack("<I", sequence) + packet, hashlib.md5).digest()[:8]
        return struct.pack("<I", 1) + rc4.encrypt(checksum) + struct.pack("<I", sequence)

    return sign


def response_packet(
    stub=b"\x00\x00\x00\x00", *, signer=None, sequence=0, call_id=2,
    context=0, auth_context=79231, level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
    packet_type=MSRPC_RESPONSE, flags=PFC_FIRST_FRAG | PFC_LAST_FRAG,
    signed=True,
):
    padding = (-len(stub)) % 4 if signed else 0
    body = stub + b"\xbb" * padding
    trailer = struct.pack("<BBBBI", RPC_C_AUTHN_WINNT, level, padding, 0, auth_context) if signed else b""
    length = 24 + len(body) + len(trailer) + (16 if signed else 0)
    header = struct.pack("<BBBB4sHHIIHBB", 5, 0, packet_type, flags, b"\x10\x00\x00\x00",
                         length, 16 if signed else 0, call_id, len(stub), context, 0, 0)
    packet = header + body + trailer
    return packet + (signer or server_signer())(packet, sequence) if signed else packet


class MemoryTransport:
    def __init__(self, data=b"", chunk_size=None):
        self.data = data
        self.chunk_size = chunk_size
        self.sent = []

    def recv(self, force_recv=0, count=0):
        count = min(count, self.chunk_size) if self.chunk_size else count
        result, self.data = self.data[:count], self.data[count:]
        return result

    def send(self, data, **kwargs):
        self.sent.append(data)

    def doesSupportNTLMv2(self):
        return True


def ready_connection(data=b"", *, chunk_size=None):
    dce = VerifiedDCERPC(MemoryTransport(data, chunk_size))
    dce.set_credentials("alice", "secret", "EXAMPLE")
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

    def bind_fixture(connection, *args, **kwargs):
        connection._DCERPC_v5__flags = FLAGS
        connection.set_session_key(SESSION_KEY)
        connection._DCERPC_v5__max_xmit_size = 4280
        connection._DCERPC_v5__clientSigningKey = ntlm.SIGNKEY(FLAGS, SESSION_KEY, "Client")
        connection._DCERPC_v5__clientSealingHandle = ARC4.new(ntlm.SEALKEY(FLAGS, SESSION_KEY, "Client")).encrypt
        return "bound"

    with patch.object(DCERPC_v5, "bind", autospec=True, side_effect=bind_fixture):
        dce.bind(mgmt.MSRPC_UUID_MGMT)
    dce._expected_call_id = 2
    dce._expected_context_id = 0
    dce._expected_auth_context_id = 79231
    return dce


class RpcVerifierTests(unittest.TestCase):
    def test_real_signed_response_and_short_transport_reads(self):
        dce = ready_connection(response_packet(b"abc"), chunk_size=3)
        self.assertEqual(dce.recv(), b"abc")
        self.assertEqual(dce.verified_responses, 1)

    def test_payload_or_signature_tampering_is_never_accepted(self):
        for position in (24, -1):
            with self.subTest(position=position):
                packet = bytearray(response_packet())
                packet[position] ^= 1
                dce = ready_connection(bytes(packet))
                with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "signature"):
                    dce.recv()
                self.assertEqual(dce.verified_responses, 0)

    def test_wrong_session_key_is_never_accepted(self):
        dce = ready_connection(response_packet(signer=server_signer(b"x" * 16)))
        with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "signature"):
            dce.recv()

    def test_unsigned_success_is_not_credential_proof(self):
        dce = ready_connection(response_packet(signed=False))
        with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "no NTLM"):
            dce.recv()
        self.assertEqual(dce.verified_responses, 0)

    def test_authentication_context_and_level_cannot_change(self):
        for overrides in ({"auth_context": 999}, {"level": RPC_C_AUTHN_LEVEL_CONNECT}):
            with self.subTest(**overrides):
                dce = ready_connection(response_packet(**overrides))
                with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "context changed"):
                    dce.recv()

    def test_call_and_presentation_context_are_correlated(self):
        for overrides in ({"call_id": 1}, {"context": 3}):
            with self.subTest(**overrides):
                dce = ready_connection(response_packet(**overrides))
                with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "pending call"):
                    dce.recv()

    def test_all_response_fragments_are_verified_with_separate_server_sequence(self):
        signer = server_signer()
        packet = response_packet(b"first", signer=signer, flags=PFC_FIRST_FRAG)
        packet += response_packet(b"second", signer=signer, sequence=1, flags=PFC_LAST_FRAG)
        dce = ready_connection(packet)
        self.assertEqual(dce.recv(), b"firstsecond")
        self.assertEqual(dce.verified_responses, 1)

    def test_unsigned_later_fragment_does_not_count_as_verified_response(self):
        packet = response_packet(flags=PFC_FIRST_FRAG)
        packet += response_packet(signed=False, flags=PFC_LAST_FRAG)
        dce = ready_connection(packet)
        with self.assertRaises(RpcAuthenticationUnconfirmed):
            dce.recv()
        self.assertEqual(dce.verified_responses, 0)

    def test_replayed_sequence_is_rejected(self):
        signer = server_signer()
        packet = response_packet(signer=signer, flags=PFC_FIRST_FRAG)
        packet += response_packet(signer=signer, sequence=0, flags=PFC_LAST_FRAG)
        dce = ready_connection(packet)
        with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "signature"):
            dce.recv()

    def test_signed_access_denied_fault_does_not_prove_success(self):
        packet = response_packet(struct.pack("<II", 5, 0), packet_type=MSRPC_FAULT)
        dce = ready_connection(packet)
        with self.assertRaises(DCERPCException) as raised:
            dce.recv()
        self.assertEqual(raised.exception.error_code, 5)
        self.assertEqual(dce.verified_responses, 0)

    def test_unsigned_fault_is_unconfirmed_without_trusted_error_code(self):
        packet = response_packet(struct.pack("<II", 5, 0), packet_type=MSRPC_FAULT, signed=False)
        dce = ready_connection(packet)
        with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "Unverified RPC fault") as raised:
            dce.recv()
        self.assertIsNone(raised.exception.error_code)

    def test_truncated_response_fails_without_hanging(self):
        dce = ready_connection(response_packet()[:-1])
        with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "connection ended"):
            dce.recv()

    def test_confirmation_response_limit(self):
        dce = ready_connection(response_packet(b"more than four bytes"))
        dce.MAX_RESPONSE_BYTES = 8
        with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "size limit"):
            dce.recv()

    def test_bind_requires_explicit_integrity_after_credentials(self):
        dce = VerifiedDCERPC(MemoryTransport())
        dce.set_credentials("alice", "secret")
        with patch.object(DCERPC_v5, "bind") as bind:
            with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "packet integrity"):
                dce.bind(mgmt.MSRPC_UUID_MGMT)
        bind.assert_not_called()

    def test_anonymous_credentials_are_not_promoted_to_user_authentication(self):
        dce = VerifiedDCERPC(MemoryTransport())
        dce.set_credentials("", "")
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "Anonymous"):
            dce.bind(mgmt.MSRPC_UUID_MGMT)

    def test_real_impacket_sender_captures_response_correlation(self):
        dce = ready_connection()
        dce.call(0, b"\x00\x00\x00\x00")
        sent = dce.get_rpc_transport().sent[-1]
        self.assertEqual(dce._expected_call_id, struct.unpack_from("<I", sent, 12)[0])
        self.assertEqual(dce._expected_context_id, 0)
        self.assertEqual(dce._expected_auth_context_id, 79231)


class RpcProbeTests(unittest.TestCase):
    def test_unknown_interface_and_version_never_issue_a_call(self):
        dce = Mock()
        for value in (("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "1.0"),
                      ("12345778-1234-abcd-ef00-0123456789ab", "1.0")):
            with self.subTest(value=value), self.assertRaises(UnsupportedRpcProbe):
                confirm_rpc_access(dce, uuid.uuidtup_to_bin(value))
        dce.request.assert_not_called()

    def test_unverified_impacket_connection_is_rejected(self):
        with self.assertRaises(RpcAuthenticationUnconfirmed):
            confirm_rpc_access(DCERPC_v5(MemoryTransport()), mgmt.MSRPC_UUID_MGMT)

    def test_successful_stub_without_verified_packet_is_not_enough(self):
        dce = ready_connection()
        with patch.object(mgmt, "hinq_if_ids", return_value={}):
            with self.assertRaisesRegex(RpcAuthenticationUnconfirmed, "without a verified"):
                confirm_rpc_access(dce, mgmt.MSRPC_UUID_MGMT)

    def test_epm_lookup_is_bounded_and_closes_continuation_handle(self):
        dce = ready_connection()
        handle = epm.ept_lookup_handle_t()
        handle["context_handle_uuid"] = b"a" * 16
        requests = []

        def request(value, **kwargs):
            requests.append(value)
            dce.verified_responses += 1
            return {"entry_handle": handle, "status": 0}

        with patch.object(dce, "request", side_effect=request):
            confirm_rpc_access(dce, epm.MSRPC_UUID_PORTMAP)
        self.assertIsInstance(requests[0], epm.ept_lookup)
        self.assertEqual(requests[0]["max_ents"], 1)
        self.assertIsInstance(requests[1], ept_lookup_handle_free)
        self.assertEqual(requests[1]["entry_handle"].getData(), handle.getData())

    def test_epm_empty_inventory_is_successful_and_needs_no_cleanup_call(self):
        dce = ready_connection()

        def request(*args, **kwargs):
            dce.verified_responses += 1
            return {"entry_handle": epm.ept_lookup_handle_t(), "status": 0x16C9A0D6}

        with patch.object(dce, "request", side_effect=request) as requested:
            confirm_rpc_access(dce, epm.MSRPC_UUID_PORTMAP)
        requested.assert_called_once()

    def test_samr_connect_uses_minimum_rights_and_closes_handle(self):
        dce = ready_connection()

        def opened(*args, **kwargs):
            dce.verified_responses += 1
            return {"ServerHandle": "server-handle"}

        with patch.object(samr, "hSamrConnect", side_effect=opened) as connect, \
                patch.object(samr, "hSamrCloseHandle") as close:
            confirm_rpc_access(dce, samr.MSRPC_UUID_SAMR)
        connect.assert_called_once_with(dce, desiredAccess=samr.SAM_SERVER_CONNECT)
        close.assert_called_once_with(dce, "server-handle")

    def test_lsa_query_failure_preserves_exception_and_closes_policy(self):
        dce = ready_connection()
        denied = DCERPCException(error_code=5)
        with patch.object(lsad, "hLsarOpenPolicy2", return_value={"PolicyHandle": "policy"}) as opened, \
                patch.object(lsad, "hLsarQueryInformationPolicy2", side_effect=denied), \
                patch.object(lsad, "hLsarClose") as close:
            with self.assertRaises(DCERPCException) as raised:
                confirm_rpc_access(dce, lsad.MSRPC_UUID_LSAD)
        self.assertIs(raised.exception, denied)
        opened.assert_called_once_with(dce, desiredAccess=lsad.POLICY_VIEW_LOCAL_INFORMATION)
        close.assert_called_once_with(dce, "policy")


if __name__ == "__main__":
    unittest.main()
