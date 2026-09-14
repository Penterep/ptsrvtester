"""Bounded read-only calls that confirm an NTLM RPC authentication exchange.

Impacket's NTLM bind finishes by sending AUTH3, without receiving a server
acknowledgement. Its v5 receive path also does not compare NTLM verifiers.
Consequently these probes use a narrow packet-integrity receiver, rather than
treating a bind, an unsigned response, or an RPC fault as credential proof.

The verification follows MS-RPCE 4.2 and MS-NLMP 3.4.2/3.4.4.2. It deliberately
supports NTLM extended session security and packet integrity only.
"""
from __future__ import annotations

from hmac import compare_digest
from struct import unpack_from

from Cryptodome.Cipher import ARC4
from impacket import ntlm, uuid
from impacket.dcerpc.v5 import epm, lsad, mgmt, samr
from impacket.dcerpc.v5.dtypes import NULL, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.rpcrt import (
    DCERPCException,
    DCERPC_v5,
    MSRPC_FAULT,
    MSRPC_RESPONSE,
    MSRPCRespHeader,
    PFC_FIRST_FRAG,
    PFC_LAST_FRAG,
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
    RPC_C_AUTHN_WINNT,
    SEC_TRAILER,
)


SUPPORTED_RPC_PROBES = {
    epm.MSRPC_UUID_PORTMAP: "EPM 3.0 (one endpoint lookup)",
    mgmt.MSRPC_UUID_MGMT: "MGMT 1.0 (interface inventory)",
    samr.MSRPC_UUID_SAMR: "SAMR 1.0 (connect with minimum rights)",
    lsad.MSRPC_UUID_LSAD: "LSAD 0.0 (account domain information)",
}


class UnsupportedRpcProbe(ValueError):
    """No reviewed read-only call is available for this interface/version."""


class RpcAuthenticationUnconfirmed(DCERPCException):
    """The RPC exchange did not provide verifiable authentication evidence."""


class VerifiedDCERPC(DCERPC_v5):
    """Impacket sender with strictly verified NTLM packet-integrity responses.

    Create one instance per connection and call ``set_auth_level`` after
    ``set_credentials`` (Impacket's credential setter resets the auth level).
    Alter-context and concurrent calls are intentionally outside this adapter.
    """

    MAX_RESPONSE_BYTES = 1024 * 1024
    MAX_RESPONSE_FRAGMENTS = 256

    def __init__(self, rpc_transport):
        super().__init__(rpc_transport)
        self._verification_ready = False
        self._receive_buffer = b""
        self._server_sequence = 0
        self._expected_call_id = None
        self._expected_context_id = None
        self._expected_auth_context_id = None
        self.verified_responses = 0

    def bind(self, iface_uuid, *args, **kwargs):
        self._verification_ready = False
        if not self.get_credentials()[0]:
            raise RpcAuthenticationUnconfirmed("Anonymous RPC credentials do not establish a user identity")
        # These negotiated values have no public accessor in Impacket >=0.12.
        # Keep the compatibility dependency in this adapter and fail closed if
        # the upstream representation changes.
        auth_level = getattr(self, "_DCERPC_v5__auth_level", None)
        if (self.get_auth_type() != RPC_C_AUTHN_WINNT
                or auth_level != RPC_C_AUTHN_LEVEL_PKT_INTEGRITY):
            raise RpcAuthenticationUnconfirmed("RPC confirmation requires NTLM packet integrity")
        response = super().bind(iface_uuid, *args, **kwargs)
        flags = getattr(self, "_DCERPC_v5__flags", None)
        required = ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | ntlm.NTLMSSP_NEGOTIATE_SIGN
        if not isinstance(flags, int) or flags & required != required:
            raise RpcAuthenticationUnconfirmed("RPC server did not negotiate NTLM extended session signing")
        session_key = self.get_session_key()
        if not isinstance(session_key, bytes) or len(session_key) != 16:
            raise RpcAuthenticationUnconfirmed("RPC session key is unavailable")
        self._verification_flags = flags
        self._server_signing_key = ntlm.SIGNKEY(flags, session_key, "Server")
        self._server_sealing_handle = ARC4.new(ntlm.SEALKEY(flags, session_key, "Server")).encrypt
        self._server_sequence = 0
        self._receive_buffer = b""
        self.verified_responses = 0
        self._verification_ready = True
        return response

    def _transport_send(self, rpc_packet, forceWriteAndx=0, forceRecv=0):
        if not self._verification_ready:
            raise RpcAuthenticationUnconfirmed("RPC verification context is unavailable")
        super()._transport_send(rpc_packet, forceWriteAndx, forceRecv)
        self._expected_call_id = rpc_packet["call_id"]
        self._expected_context_id = rpc_packet["ctx_id"]
        trailer = SEC_TRAILER(rpc_packet["sec_trailer"])
        self._expected_auth_context_id = trailer["auth_ctx_id"]

    def _read_exact(self, count, force_recv):
        while len(self._receive_buffer) < count:
            chunk = self.get_rpc_transport().recv(force_recv, count=count - len(self._receive_buffer))
            if not chunk:
                raise RpcAuthenticationUnconfirmed("RPC connection ended before a complete response")
            self._receive_buffer += chunk
            if len(self._receive_buffer) > self.MAX_RESPONSE_BYTES:
                raise RpcAuthenticationUnconfirmed("RPC response exceeds the confirmation size limit")
        answer, self._receive_buffer = self._receive_buffer[:count], self._receive_buffer[count:]
        return answer

    def recv(self):
        if not self._verification_ready or self._expected_call_id is None:
            raise RpcAuthenticationUnconfirmed("RPC verification context is unavailable")
        result = bytearray()
        for fragment in range(self.MAX_RESPONSE_FRAGMENTS):
            force_recv = int(fragment > 0)
            header_bytes = self._read_exact(MSRPCRespHeader._SIZE, force_recv)
            if header_bytes[:2] != b"\x05\x00" or header_bytes[4:8] != b"\x10\x00\x00\x00":
                raise RpcAuthenticationUnconfirmed("Unsupported RPC response encoding")
            header = MSRPCRespHeader(header_bytes)
            size = header["frag_len"]
            if size < MSRPCRespHeader._SIZE:
                raise RpcAuthenticationUnconfirmed("Invalid RPC fragment length")
            packet = header_bytes + self._read_exact(size - len(header_bytes), force_recv)
            if (header["call_id"] != self._expected_call_id
                    or header["ctx_id"] != self._expected_context_id
                    or bool(header["flags"] & PFC_FIRST_FRAG) != (fragment == 0)):
                raise RpcAuthenticationUnconfirmed("RPC response does not match the pending call")
            if header["type"] not in (MSRPC_RESPONSE, MSRPC_FAULT):
                raise RpcAuthenticationUnconfirmed("Unexpected RPC response type")
            # Faults may be unsigned, including authentication failures. They
            # are diagnostic only; never promote them to successful credentials.
            if header["auth_len"] != 16 or size < MSRPCRespHeader._SIZE + 24:
                if header["type"] == MSRPC_FAULT and size >= MSRPCRespHeader._SIZE + 4:
                    status = unpack_from("<I", packet, MSRPCRespHeader._SIZE)[0]
                    raise RpcAuthenticationUnconfirmed(f"Unverified RPC fault 0x{status:08x}")
                raise RpcAuthenticationUnconfirmed("RPC response has no NTLM integrity verifier")
            trailer = SEC_TRAILER(packet[-24:-16])
            if (trailer["auth_type"] != RPC_C_AUTHN_WINNT
                    or trailer["auth_level"] != RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
                    or trailer["auth_ctx_id"] != self._expected_auth_context_id):
                raise RpcAuthenticationUnconfirmed("RPC response authentication context changed")
            signature = ntlm.SIGN(
                self._verification_flags, self._server_signing_key, packet[:-16],
                self._server_sequence, self._server_sealing_handle,
            ).getData()
            if not compare_digest(signature, packet[-16:]):
                self._verification_ready = False
                raise RpcAuthenticationUnconfirmed("RPC response NTLM signature verification failed")
            self._server_sequence += 1
            if header["type"] == MSRPC_FAULT:
                if size < MSRPCRespHeader._SIZE + 24 + 4:
                    raise RpcAuthenticationUnconfirmed("Truncated RPC fault")
                status = unpack_from("<I", packet, MSRPCRespHeader._SIZE)[0]
                raise DCERPCException(error_code=status)
            stub = packet[MSRPCRespHeader._SIZE:-24]
            padding = trailer["auth_pad_len"]
            if padding > len(stub):
                raise RpcAuthenticationUnconfirmed("Invalid RPC authentication padding")
            result.extend(stub[:-padding] if padding else stub)
            if len(result) > self.MAX_RESPONSE_BYTES:
                raise RpcAuthenticationUnconfirmed("RPC response exceeds the confirmation size limit")
            if header["flags"] & PFC_LAST_FRAG:
                self.verified_responses += 1
                self._expected_call_id = None
                return bytes(result)
        raise RpcAuthenticationUnconfirmed("RPC response exceeds the confirmation fragment limit")


class ept_lookup_handle_free(NDRCALL):
    """C706 Appendix O, EPM opnum 4; missing from Impacket's EPM helpers."""

    opnum = 4
    structure = (("entry_handle", epm.ept_lookup_handle_t),)


class ept_lookup_handle_freeResponse(NDRCALL):
    structure = (("entry_handle", epm.ept_lookup_handle_t), ("status", ULONG))


def _confirm_epm(dce):
    request = epm.ept_lookup()
    request["inquiry_type"] = epm.RPC_C_EP_ALL_ELTS
    request["object"] = NULL
    request["Ifid"] = NULL
    request["vers_option"] = epm.RPC_C_VERS_ALL
    request["entry_handle"] = epm.ept_lookup_handle_t()
    request["max_ents"] = 1
    # Avoid hept_lookup: it rebinds and enumerates the entire endpoint map.
    response = dce.request(request, checkError=False)
    handle = response["entry_handle"]
    try:
        status = int(response["status"])
        if status not in (0, 0x16C9A0D6):
            raise DCERPCException(error_code=status)
    finally:
        if not handle.isNull():
            close = ept_lookup_handle_free()
            close["entry_handle"] = handle
            closed = dce.request(close, checkError=False)
            if int(closed["status"]):
                raise DCERPCException(error_code=int(closed["status"]))


def confirm_rpc_access(dce: VerifiedDCERPC, interface_binary: bytes) -> None:
    """Confirm one allowlisted call; errors remain rejected/inconclusive upstream.

    The caller owns connect/bind/disconnect. Successful completion establishes
    authenticated RPC access, not that the password is weak.
    """
    if interface_binary not in SUPPORTED_RPC_PROBES:
        interface_uuid, version = uuid.bin_to_uuidtup(interface_binary)
        interface = f"{interface_uuid}:{version}"
        raise UnsupportedRpcProbe(f"No read-only credential confirmation probe for {interface}")
    if not isinstance(dce, VerifiedDCERPC):
        raise RpcAuthenticationUnconfirmed("RPC confirmation requires a verifying connection")
    before = dce.verified_responses
    if interface_binary == epm.MSRPC_UUID_PORTMAP:
        _confirm_epm(dce)
    elif interface_binary == mgmt.MSRPC_UUID_MGMT:
        mgmt.hinq_if_ids(dce)
    elif interface_binary == samr.MSRPC_UUID_SAMR:
        response = samr.hSamrConnect(dce, desiredAccess=samr.SAM_SERVER_CONNECT)
        samr.hSamrCloseHandle(dce, response["ServerHandle"])
    elif interface_binary == lsad.MSRPC_UUID_LSAD:
        response = lsad.hLsarOpenPolicy2(dce, desiredAccess=lsad.POLICY_VIEW_LOCAL_INFORMATION)
        handle = response["PolicyHandle"]
        try:
            lsad.hLsarQueryInformationPolicy2(
                dce, handle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation,
            )
        finally:
            lsad.hLsarClose(dce, handle)
    if dce.verified_responses <= before:
        raise RpcAuthenticationUnconfirmed("RPC call returned without a verified server response")
