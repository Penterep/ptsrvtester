from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import socket
import ssl
import struct
from dataclasses import dataclass, field
from enum import Enum

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.x509.oid import NameOID
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.ptprinthelper import get_colored_text
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, tag, univ

from ._base import BaseArgs, BaseModule, Out
from .utils.helpers import Target, valid_target


PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002
PROTOCOL_RDSTLS = 0x00000004
PROTOCOL_HYBRID_EX = 0x00000008
PROTOCOL_RDSAAD = 0x00000010

NEG_RSP_EXTENDED_CLIENT_DATA_SUPPORTED = 0x01
NEG_RSP_DYNVC_GFX_PROTOCOL_SUPPORTED = 0x02
NEG_RSP_RESTRICTED_ADMIN_MODE_SUPPORTED = 0x08
NEG_RSP_REDIRECTED_AUTH_MODE_SUPPORTED = 0x10

TYPE_RDP_NEG_REQ = 0x01
TYPE_RDP_NEG_RSP = 0x02
TYPE_RDP_NEG_FAILURE = 0x03

X224_TPDU_CONNECTION_CONFIRM = 0xD0
X224_TPDU_DISCONNECT_REQUEST = 0x80

RDP_TEST_ORDER = (
    "NLA",
    "RDPSEC",
    "CREDSSP",
    "RDPENC",
    "SSL",
    "NTLMINFO",
    "AUTH",
)
RDP_TEST_ALIASES = {"INFO": "NTLMINFO"}
RDP_TEST_CHOICES = RDP_TEST_ORDER + tuple(RDP_TEST_ALIASES)
IMPLEMENTED_TESTS = {"NLA", "RDPSEC", "CREDSSP", "RDPENC", "SSL", "NTLMINFO"}

CREDSSP_TSREQUEST_VERSION = 6
MAX_CREDSSP_MESSAGE_SIZE = 256 * 1024
MAX_MCS_MESSAGE_SIZE = 1024 * 1024
NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
NTLM_CHALLENGE_MESSAGE_TYPE = 2
NTLMSSP_NEGOTIATE_VERSION = 0x02000000

PROTOCOL_NAMES = {
    PROTOCOL_RDP: "RDP",
    PROTOCOL_SSL: "SSL",
    PROTOCOL_HYBRID: "HYBRID",
    PROTOCOL_RDSTLS: "RDSTLS",
    PROTOCOL_HYBRID_EX: "HYBRID_EX",
    PROTOCOL_RDSAAD: "RDSAAD",
}

NEGOTIATION_RESPONSE_FLAGS = {
    NEG_RSP_EXTENDED_CLIENT_DATA_SUPPORTED: "Extended Client Data",
    NEG_RSP_DYNVC_GFX_PROTOCOL_SUPPORTED: "Graphics Pipeline",
    NEG_RSP_RESTRICTED_ADMIN_MODE_SUPPORTED: "Restricted Admin Mode",
    NEG_RSP_REDIRECTED_AUTH_MODE_SUPPORTED: "Remote Credential Guard",
}

ENCRYPTION_METHOD_40BIT = 0x00000001
ENCRYPTION_METHOD_128BIT = 0x00000002
ENCRYPTION_METHOD_56BIT = 0x00000008
ENCRYPTION_METHOD_FIPS = 0x00000010

ENCRYPTION_METHOD_NAMES = {
    ENCRYPTION_METHOD_40BIT: "40-bit RC4",
    ENCRYPTION_METHOD_56BIT: "56-bit RC4",
    ENCRYPTION_METHOD_128BIT: "128-bit RC4",
    ENCRYPTION_METHOD_FIPS: "FIPS 140-1",
}

ENCRYPTION_LEVEL_NAMES = {
    0x00000000: "None",
    0x00000001: "Low",
    0x00000002: "Client Compatible",
    0x00000003: "High",
    0x00000004: "FIPS",
}

SERVER_RDP_VERSION_NAMES = {
    0x00080001: "RDP 4.0",
    0x00080004: "RDP 5.x-8.x",
    0x00080005: "RDP 10.0",
    0x00080006: "RDP 10.1",
    0x00080007: "RDP 10.2",
    0x00080008: "RDP 10.3",
    0x00080009: "RDP 10.4",
    0x0008000A: "RDP 10.5",
    0x0008000B: "RDP 10.6",
    0x0008000C: "RDP 10.7",
    0x0008000D: "RDP 10.8",
    0x0008000E: "RDP 10.9",
    0x0008000F: "RDP 10.10",
}

SC_CORE = 0x0C01
SC_SECURITY = 0x0C02

FAILURE_CODES = {
    0x00000001: "SSL required by server",
    0x00000002: "SSL not allowed by server",
    0x00000003: "SSL certificate not on server",
    0x00000004: "inconsistent negotiation flags",
    0x00000005: "CredSSP/NLA required by server",
    0x00000006: "CredSSP with user authentication required by server",
}


class RDPProtocolError(Exception):
    """Raised when the server reply is not a valid pre-auth RDP negotiation reply."""


class _CredSSPNegoData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "negoToken",
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        )
    )


class _CredSSPNegoDataSequence(univ.SequenceOf):
    componentType = _CredSSPNegoData()


class _CredSSPTSRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "version",
            univ.Integer().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
        namedtype.OptionalNamedType(
            "negoTokens",
            _CredSSPNegoDataSequence().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            ),
        ),
        namedtype.OptionalNamedType(
            "authInfo",
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
            ),
        ),
        namedtype.OptionalNamedType(
            "pubKeyAuth",
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
            ),
        ),
        namedtype.OptionalNamedType(
            "errorCode",
            univ.Integer().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)
            ),
        ),
        namedtype.OptionalNamedType(
            "clientNonce",
            univ.OctetString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5)
            ),
        ),
    )


class VULNS(Enum):
    NLA_NOT_REQUIRED = "PTV-RDP-NLA-NOTREQUIRED"
    NLA_NOT_SUPPORTED = "PTV-RDP-NLA-NOTSUPPORTED"
    RDP_SECURITY_ALLOWED = "PTV-RDP-LEGACYSECURITY"
    TLS_WEAK_CONFIG = "PTV-RDP-TLS-WEAKCONFIG"
    NTLM_INFO_DISCLOSURE = "PTV-GENERAL-NTLMINFORMATION"


@dataclass(frozen=True)
class NegotiationReply:
    selected_protocol: int | None = None
    failure_code: int | None = None
    response_flags: int | None = None
    note: str | None = None


@dataclass(frozen=True)
class NegotiationProbe:
    name: str
    requested_protocols: int
    selected_protocol: int | None = None
    failure_code: int | None = None
    response_flags: int | None = None
    error: str | None = None
    note: str | None = None

    @property
    def successful(self) -> bool:
        return self.selected_protocol is not None

    @property
    def failed_by_server(self) -> bool:
        return self.failure_code is not None

    def summary(self) -> str:
        requested = protocol_mask_to_string(self.requested_protocols)
        if self.selected_protocol is not None:
            selected = protocol_name(self.selected_protocol)
            return f"{self.name}: requested {requested}, selected {selected}"
        if self.failure_code is not None:
            reason = FAILURE_CODES.get(
                self.failure_code,
                f"unknown failure code {self.failure_code}",
            )
            return f"{self.name}: requested {requested}, failed ({reason})"
        return f"{self.name}: requested {requested}, error ({self.error or 'unknown error'})"


@dataclass
class NLAResult:
    status: str
    probes: list[NegotiationProbe]
    error: str | None = None


@dataclass
class RDPSecurityResult:
    status: str
    probe: NegotiationProbe


@dataclass
class CredSSPResult:
    status: str
    hybrid_ex_supported: bool
    probes: list[NegotiationProbe]


@dataclass(frozen=True)
class LegacyServerSecurityData:
    encryption_method: int
    encryption_level: int
    server_rdp_version: int | None = None


@dataclass(frozen=True)
class LegacyEncryptionProbe:
    requested_method: int
    accepted: bool | None
    selected_method: int | None = None
    encryption_level: int | None = None
    server_rdp_version: int | None = None
    error: str | None = None


@dataclass
class RDPEncryptionResult:
    status: str
    protocol_probes: list[NegotiationProbe] = field(default_factory=list)
    legacy_status: str = "not_tested"
    legacy_probes: list[LegacyEncryptionProbe] = field(default_factory=list)
    response_flags: int = 0
    error: str | None = None


@dataclass(frozen=True)
class RDPNTLMInfo:
    target_name: str | None = None
    netbios_domain: str | None = None
    netbios_computer: str | None = None
    dns_domain: str | None = None
    dns_computer: str | None = None
    dns_tree: str | None = None
    os_version: str | None = None
    server_time: str | None = None


@dataclass
class NTLMInfoResult:
    status: str
    info: RDPNTLMInfo | None = None
    selected_protocol: str | None = None
    negotiation_probe: NegotiationProbe | None = None
    error: str | None = None


@dataclass(frozen=True)
class TLSVersionProbe:
    version: str
    supported: bool
    selected_cipher: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class CertificateInfo:
    subject: str | None
    issuer: str | None
    serial: str | None
    not_before: str | None
    not_after: str | None
    dns_names: list[str]
    ip_addresses: list[str]
    expired: bool | None
    not_yet_valid: bool | None
    self_signed: bool | None
    parse_error: str | None = None
    common_names: list[str] = field(default_factory=list)
    san_present: bool | None = None
    target_matches_san: bool | None = None
    signature_hash_algorithm: str | None = None


@dataclass
class SSLResult:
    status: str
    negotiation_probe: NegotiationProbe | None = None
    selected_protocol: str | None = None
    selected_tls_version: str | None = None
    selected_cipher: str | None = None
    certificate: CertificateInfo | None = None
    version_probes: list[TLSVersionProbe] = field(default_factory=list)
    weak_findings: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class RDPResults:
    nla: NLAResult | None = None
    rdp_security: RDPSecurityResult | None = None
    credssp: CredSSPResult | None = None
    rdp_encryption: RDPEncryptionResult | None = None
    ntlm_info: NTLMInfoResult | None = None
    ssl: SSLResult | None = None
    not_implemented: list[str] = field(default_factory=list)


def valid_target_rdp(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port."""
    return valid_target(target, domain_allowed=True)


def protocol_name(protocol: int | None) -> str:
    if protocol is None:
        return "n/a"
    return PROTOCOL_NAMES.get(protocol, f"UNKNOWN(0x{protocol:08x})")


def protocol_mask_to_string(mask: int) -> str:
    if mask == PROTOCOL_RDP:
        return "RDP"

    names: list[str] = []
    for bit in (
        PROTOCOL_SSL,
        PROTOCOL_HYBRID,
        PROTOCOL_RDSTLS,
        PROTOCOL_HYBRID_EX,
        PROTOCOL_RDSAAD,
    ):
        if mask & bit:
            names.append(protocol_name(bit))
    return "|".join(names) if names else f"UNKNOWN(0x{mask:08x})"


def _target_is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _dnsname_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.rstrip(".").lower()
    hostname = hostname.rstrip(".").lower()
    if not pattern or not hostname:
        return False
    if not pattern.startswith("*."):
        return pattern == hostname

    suffix = pattern[1:]
    return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")


def _certificate_san_matches_target(
    target: str,
    dns_names: list[str],
    ip_addresses: list[str],
) -> bool:
    try:
        ip = ipaddress.ip_address(target)
        return str(ip) in ip_addresses
    except ValueError:
        return any(_dnsname_matches(name, target) for name in dns_names)


def _certificate_is_self_signed(cert: x509.Certificate) -> bool:
    if cert.subject != cert.issuer:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
        return False
    return True


def _recvall(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RDPProtocolError("connection closed before full response was received")
        data.extend(chunk)
    return bytes(data)


def _build_negotiation_request(protocols: int) -> bytes:
    negotiation = struct.pack("<BBHI", TYPE_RDP_NEG_REQ, 0, 8, protocols)
    x224_cr = b"\x0e\xe0\x00\x00\x00\x00\x00" + negotiation
    tpkt = struct.pack(">BBH", 3, 0, len(x224_cr) + 4)
    return tpkt + x224_cr


def _read_tpkt(sock: socket.socket) -> bytes:
    header = _recvall(sock, 4)
    version, _reserved, length = struct.unpack(">BBH", header)
    if version != 3:
        raise RDPProtocolError(f"invalid TPKT version {version}")
    if length < 7:
        raise RDPProtocolError(f"invalid TPKT length {length}")
    return header + _recvall(sock, length - 4)


def _read_der_message(sock: socket.socket) -> bytes:
    header = _recvall(sock, 2)
    if header[0] != 0x30:
        raise RDPProtocolError(
            f"CredSSP response does not start with an ASN.1 SEQUENCE: 0x{header[0]:02x}"
        )

    length_byte = header[1]
    if length_byte & 0x80:
        length_size = length_byte & 0x7F
        if length_size == 0 or length_size > 4:
            raise RDPProtocolError("CredSSP response uses unsupported ASN.1 length form")
        length_data = _recvall(sock, length_size)
        content_length = int.from_bytes(length_data, "big")
        prefix = header + length_data
    else:
        content_length = length_byte
        prefix = header

    if content_length > MAX_CREDSSP_MESSAGE_SIZE:
        raise RDPProtocolError(
            f"CredSSP response is too large ({content_length} bytes)"
        )
    return prefix + _recvall(sock, content_length)


def _build_spnego_ntlm_init(ntlm_negotiate: bytes) -> bytes:
    spnego = SPNEGO_NegTokenInit()
    spnego["MechTypes"] = [
        TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
    ]
    spnego["MechToken"] = ntlm_negotiate
    return spnego.getData()


def _build_credssp_ts_request(nego_token: bytes) -> bytes:
    request = _CredSSPTSRequest()
    request["version"] = CREDSSP_TSREQUEST_VERSION

    nego_data = _CredSSPNegoData()
    nego_data["negoToken"] = nego_token
    nego_tokens = request.getComponentByName("negoTokens").clone()
    nego_tokens.setComponentByPosition(0, nego_data)
    request.setComponentByName("negoTokens", nego_tokens)
    return der_encoder.encode(request)


def _extract_credssp_nego_token(data: bytes) -> bytes | None:
    request, rest = der_decoder.decode(data, asn1Spec=_CredSSPTSRequest())
    if rest:
        raise RDPProtocolError("CredSSP response contains trailing ASN.1 data")

    nego_tokens = request.getComponentByName("negoTokens")
    if not nego_tokens.hasValue() or len(nego_tokens) == 0:
        return None

    nego_token = nego_tokens[0].getComponentByName("negoToken")
    if not nego_token.hasValue():
        return None
    return bytes(nego_token)


def _slice_ntlm_challenge(data: bytes, offset: int) -> bytes | None:
    message = data[offset:]
    if len(message) < 48:
        return None
    if message[:8] != NTLMSSP_SIGNATURE:
        return None
    message_type = struct.unpack("<I", message[8:12])[0]
    if message_type != NTLM_CHALLENGE_MESSAGE_TYPE:
        return None

    end = 48
    for field_offset in (12, 40):
        field_length = struct.unpack("<H", message[field_offset : field_offset + 2])[0]
        data_offset = struct.unpack("<I", message[field_offset + 4 : field_offset + 8])[0]
        if field_length:
            end = max(end, data_offset + field_length)

    flags = struct.unpack("<I", message[20:24])[0]
    if flags & NTLMSSP_NEGOTIATE_VERSION:
        end = max(end, 56)

    if end > len(message):
        raise RDPProtocolError("CredSSP NTLM challenge is truncated")
    return message[:end]


def _find_ntlm_challenge(data: bytes) -> bytes | None:
    marker = NTLMSSP_SIGNATURE + struct.pack("<I", NTLM_CHALLENGE_MESSAGE_TYPE)
    offset = data.find(marker)
    if offset < 0:
        return None
    return _slice_ntlm_challenge(data, offset)


def _extract_ntlm_challenge(nego_token: bytes) -> bytes:
    candidates = [nego_token]
    try:
        spnego_response = SPNEGO_NegTokenResp(nego_token)
        response_token = spnego_response.fields.get("ResponseToken")
        if response_token:
            candidates.insert(0, response_token)
    except Exception:
        pass

    for candidate in candidates:
        challenge = _find_ntlm_challenge(candidate)
        if challenge is not None:
            return challenge
    raise RDPProtocolError("CredSSP response did not contain an NTLM challenge")


def _ntlm_info_from_details(details) -> RDPNTLMInfo:
    return RDPNTLMInfo(
        target_name=getattr(details, "target_name", None),
        netbios_domain=getattr(details, "netbios_domain", None),
        netbios_computer=getattr(details, "netbios_computer", None),
        dns_domain=getattr(details, "dns_domain", None),
        dns_computer=getattr(details, "dns_computer", None),
        dns_tree=getattr(details, "dns_tree", None),
        os_version=getattr(details, "os_version", None),
        server_time=getattr(details, "server_time", None),
    )


def _ntlm_info_has_values(info: RDPNTLMInfo) -> bool:
    return any(
        (
            info.target_name,
            info.netbios_domain,
            info.netbios_computer,
            info.dns_domain,
            info.dns_computer,
            info.dns_tree,
            info.os_version,
            info.server_time,
        )
    )


def _format_cipher(cipher: tuple | None) -> str | None:
    if not cipher:
        return None
    if len(cipher) >= 3:
        return f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)"
    return str(cipher[0])


def _tls_version_members() -> list[tuple[str, ssl.TLSVersion]]:
    versions: list[tuple[str, ssl.TLSVersion]] = []
    for attr, label in (
        ("TLSv1", "TLSv1.0"),
        ("TLSv1_1", "TLSv1.1"),
        ("TLSv1_2", "TLSv1.2"),
        ("TLSv1_3", "TLSv1.3"),
    ):
        if hasattr(ssl.TLSVersion, attr):
            versions.append((label, getattr(ssl.TLSVersion, attr)))
    return versions


def _create_tls_context(version: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if version is not None:
        context.minimum_version = version
        context.maximum_version = version
    elif hasattr(ssl.TLSVersion, "MINIMUM_SUPPORTED"):
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return context


def _ber_encode_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("BER length cannot be negative")
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if len(encoded) > 4:
        raise ValueError("BER value is too large")
    return bytes((0x80 | len(encoded),)) + encoded


def _ber_wrap(tag_bytes: bytes, value: bytes) -> bytes:
    return tag_bytes + _ber_encode_length(len(value)) + value


def _per_encode_length(length: int) -> bytes:
    if length < 0 or length >= 0x4000:
        raise ValueError("PER length is outside the supported range")
    if length < 0x80:
        return bytes((length,))
    return bytes((0x80 | ((length >> 8) & 0x3F), length & 0xFF))


def _per_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise RDPProtocolError("truncated PER length")
    first = data[offset]
    if not first & 0x80:
        return first, offset + 1
    if offset + 1 >= len(data):
        raise RDPProtocolError("truncated two-byte PER length")
    return ((first & 0x3F) << 8) | data[offset + 1], offset + 2


def _build_client_core_data() -> bytes:
    client_name = "PTSRVTESTER".encode("utf-16-le")[:30]
    client_name += b"\x00" * (32 - len(client_name))
    payload = struct.pack(
        "<IHHHHII",
        0x00080004,
        800,
        600,
        0xCA01,
        0xAA03,
        0x00000409,
        0,
    )
    payload += client_name
    payload += struct.pack("<III", 4, 0, 12)
    payload += b"\x00" * 64
    return struct.pack("<HH", 0xC001, len(payload) + 4) + payload


def _build_client_security_data(encryption_methods: int) -> bytes:
    return struct.pack("<HHII", 0xC002, 12, encryption_methods, 0)


def _build_mcs_connect_initial(encryption_methods: int) -> bytes:
    client_blocks = _build_client_core_data() + _build_client_security_data(
        encryption_methods
    )
    conference_request = (
        b"\x00\x08\x00\x10\x00\x01\xc0\x00Duca"
        + _per_encode_length(len(client_blocks))
        + client_blocks
    )
    gcc_data = (
        b"\x00\x05\x00\x14\x7c\x00\x01"
        + _per_encode_length(len(conference_request))
        + conference_request
    )

    target_parameters = bytes.fromhex(
        "30190201220201020201000201010201000201010202ffff020102"
    )
    minimum_parameters = bytes.fromhex(
        "301902010102010102010102010102010002010102020420020102"
    )
    maximum_parameters = bytes.fromhex(
        "301c0202ffff0202fc170202ffff0201010201000201010202ffff020102"
    )
    mcs_content = (
        b"\x04\x01\x01"
        b"\x04\x01\x01"
        b"\x01\x01\xff"
        + target_parameters
        + minimum_parameters
        + maximum_parameters
        + _ber_wrap(b"\x04", gcc_data)
    )
    mcs = _ber_wrap(b"\x7f\x65", mcs_content)
    x224_data = b"\x02\xf0\x80" + mcs
    if len(x224_data) + 4 > MAX_MCS_MESSAGE_SIZE:
        raise ValueError("MCS Connect Initial is too large")
    return struct.pack(">BBH", 3, 0, len(x224_data) + 4) + x224_data


def _read_ber_tlv(data: bytes, offset: int) -> tuple[bytes, bytes, int]:
    if offset >= len(data):
        raise RDPProtocolError("truncated BER tag")
    tag_start = offset
    first = data[offset]
    offset += 1
    if first & 0x1F == 0x1F:
        for _ in range(4):
            if offset >= len(data):
                raise RDPProtocolError("truncated BER high-tag-number")
            tag_byte = data[offset]
            offset += 1
            if not tag_byte & 0x80:
                break
        else:
            raise RDPProtocolError("BER tag is too long")
    tag_bytes = data[tag_start:offset]

    if offset >= len(data):
        raise RDPProtocolError("truncated BER length")
    first_length = data[offset]
    offset += 1
    if first_length & 0x80:
        length_size = first_length & 0x7F
        if length_size == 0 or length_size > 4 or offset + length_size > len(data):
            raise RDPProtocolError("invalid BER length")
        length = int.from_bytes(data[offset : offset + length_size], "big")
        offset += length_size
    else:
        length = first_length

    end = offset + length
    if length > MAX_MCS_MESSAGE_SIZE or end > len(data):
        raise RDPProtocolError("BER value exceeds response bounds")
    return tag_bytes, data[offset:end], end


def _parse_server_security_data(packet: bytes) -> LegacyServerSecurityData:
    if len(packet) < 8 or packet[0] != 3:
        raise RDPProtocolError("invalid MCS Connect Response TPKT")
    tpkt_length = struct.unpack(">H", packet[2:4])[0]
    if tpkt_length != len(packet) or tpkt_length > MAX_MCS_MESSAGE_SIZE:
        raise RDPProtocolError("invalid MCS Connect Response length")
    if packet[4:7] != b"\x02\xf0\x80":
        raise RDPProtocolError("invalid X.224 Data TPDU in MCS response")

    tag_bytes, mcs_value, end = _read_ber_tlv(packet, 7)
    if tag_bytes != b"\x7f\x66" or end != len(packet):
        raise RDPProtocolError("response is not an MCS Connect Response")

    offset = 0
    tag_bytes, result, offset = _read_ber_tlv(mcs_value, offset)
    if tag_bytes != b"\x0a" or result != b"\x00":
        raise RDPProtocolError("MCS Connect Response was not successful")
    tag_bytes, _called_connect_id, offset = _read_ber_tlv(mcs_value, offset)
    if tag_bytes != b"\x02":
        raise RDPProtocolError("MCS Connect Response has no calledConnectId")
    tag_bytes, _domain_parameters, offset = _read_ber_tlv(mcs_value, offset)
    if tag_bytes != b"\x30":
        raise RDPProtocolError("MCS Connect Response has no domainParameters")
    tag_bytes, gcc_data, offset = _read_ber_tlv(mcs_value, offset)
    if tag_bytes != b"\x04" or offset != len(mcs_value):
        raise RDPProtocolError("MCS Connect Response has invalid GCC userData")

    marker_offset = gcc_data.find(b"McDn")
    if marker_offset < 0:
        raise RDPProtocolError("GCC response does not contain the server H.221 key")
    blocks_length, blocks_offset = _per_decode_length(gcc_data, marker_offset + 4)
    blocks_end = blocks_offset + blocks_length
    if blocks_end > len(gcc_data):
        raise RDPProtocolError("truncated GCC server data blocks")
    blocks = gcc_data[blocks_offset:blocks_end]

    encryption_method = None
    encryption_level = None
    server_rdp_version = None
    offset = 0
    while offset < len(blocks):
        if offset + 4 > len(blocks):
            raise RDPProtocolError("truncated server data block header")
        block_type, block_length = struct.unpack("<HH", blocks[offset : offset + 4])
        if block_length < 4 or offset + block_length > len(blocks):
            raise RDPProtocolError("invalid server data block length")
        block = blocks[offset : offset + block_length]
        if block_type == SC_CORE and block_length >= 8:
            server_rdp_version = struct.unpack("<I", block[4:8])[0]
        elif block_type == SC_SECURITY:
            if block_length < 12:
                raise RDPProtocolError("truncated Server Security Data block")
            encryption_method, encryption_level = struct.unpack("<II", block[4:12])
        offset += block_length

    if encryption_method is None or encryption_level is None:
        raise RDPProtocolError("MCS response has no Server Security Data block")
    return LegacyServerSecurityData(
        encryption_method=encryption_method,
        encryption_level=encryption_level,
        server_rdp_version=server_rdp_version,
    )


def _parse_negotiation_reply_details(packet: bytes) -> NegotiationReply:
    if len(packet) < 7:
        raise RDPProtocolError("RDP negotiation response is too short")
    if packet[0] != 3:
        raise RDPProtocolError(f"invalid TPKT version {packet[0]}")

    tpkt_length = struct.unpack(">H", packet[2:4])[0]
    if tpkt_length != len(packet):
        raise RDPProtocolError(
            f"TPKT length mismatch: header={tpkt_length}, received={len(packet)}"
        )

    x224_li = packet[4]
    if len(packet) < 5 + x224_li:
        raise RDPProtocolError("truncated X.224 response")

    tpdu_type = packet[5] & 0xF0
    if tpdu_type == X224_TPDU_DISCONNECT_REQUEST:
        raise RDPProtocolError("server returned X.224 disconnect request")
    if tpdu_type != X224_TPDU_CONNECTION_CONFIRM:
        raise RDPProtocolError(f"unexpected X.224 TPDU type 0x{packet[5]:02x}")

    # The negotiation structure normally starts after the 7-byte X.224 CC header,
    # but scanning the X.224 variable part makes the parser tolerant of optional data.
    for offset in range(11, max(11, len(packet) - 7)):
        msg_type = packet[offset]
        if msg_type not in (TYPE_RDP_NEG_RSP, TYPE_RDP_NEG_FAILURE):
            continue

        msg_length = struct.unpack("<H", packet[offset + 2 : offset + 4])[0]
        if msg_length < 8 or offset + msg_length > len(packet):
            continue

        value = struct.unpack("<I", packet[offset + 4 : offset + 8])[0]
        if msg_type == TYPE_RDP_NEG_RSP:
            return NegotiationReply(
                selected_protocol=value,
                response_flags=packet[offset + 1],
            )
        return NegotiationReply(failure_code=value)

    return NegotiationReply(
        selected_protocol=PROTOCOL_RDP,
        response_flags=0,
        note="X.224 connection confirmed without negotiation data",
    )


def _parse_negotiation_reply(packet: bytes) -> tuple[int | None, int | None, str | None]:
    reply = _parse_negotiation_reply_details(packet)
    return reply.selected_protocol, reply.failure_code, reply.note


class RDPArgs(BaseArgs):
    target: Target
    tests: list[str] | None
    login: str | None
    password: str | None
    timeout: int

    @staticmethod
    def get_help():
        return [
            {"description": ["RDP Testing Module"]},
            {"usage": ["ptsrvtester rdp <target> <options>"]},
            {"usage_example": [
                "ptsrvtester rdp 192.168.1.10 -ts NLA",
                "ptsrvtester RDP 12.32.43.163 -ts NLA AUTH -l admin -p pass123",
                "ptsrvtester RDP rdp.example.com -ts NLA",
            ]},
            {"options": [
                ["-ts", "--tests", "<test>", "Specify one or more tests to perform"],
                ["", "", "NLA", "Network Level Authentication requirement test"],
                ["", "", "RDPSEC", "Legacy Standard RDP Security negotiation test"],
                ["", "", "CREDSSP", "CredSSP protocol support test"],
                ["", "", "RDPENC", "Security protocols and RDP encryption enumeration"],
                ["", "", "SSL", "TLS/RDP Security configuration test"],
                ["", "", "NTLMINFO", "Pre-auth CredSSP/NTLM server information test"],
                ["", "", "INFO", "Alias for NTLMINFO"],
                ["", "", "AUTH", "Authentication capability test (planned)"],
                ["-l", "--login", "<login>", "Login for account-based tests (planned)"],
                ["-p", "--password", "<password>", "Password for account-based tests (planned)"],
                ["-T", "--timeout", "<milliseconds>", "Socket timeout (default 10000)"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
                ["-vv", "--verbose", "", "Enable verbose mode"],
            ]},
            {"note": [
                "When -ts/--tests is omitted, all currently implemented safe pre-auth tests are executed.",
            ]},
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester rdp 192.168.1.10 -ts NLA
  ptsrvtester rdp 192.168.1.10 -ts NLA NTLMINFO
  ptsrvtester RDP 12.32.43.163 -ts NLA AUTH -l admin -p pass123
  ptsrvtester RDP rdp.example.com -ts NLA
  ptsrvtester rdp 192.168.1.10 -vv"""

        parser = subparsers.add_parser(
            name,
            add_help=True,
            epilog=examples,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError

        parser.add_argument(
            "target",
            type=valid_target_rdp,
            help="IP[:PORT] or HOST[:PORT] (default port: 3389)",
        )
        parser.add_argument(
            "-ts",
            "--tests",
            nargs="+",
            type=str.upper,
            choices=RDP_TEST_CHOICES,
            metavar="TEST",
            help="tests to run: NLA, RDPSEC, CREDSSP, RDPENC, SSL, NTLMINFO, INFO, AUTH",
        )
        parser.add_argument("-l", "--login", help="login for account-based tests")
        parser.add_argument("-p", "--password", help="password for account-based tests")
        parser.add_argument(
            "-T",
            "--timeout",
            type=int,
            default=10000,
            metavar="MILLISECONDS",
            help="socket timeout in milliseconds (default: 10000)",
        )


class RDP(BaseModule):
    @staticmethod
    def module_args() -> RDPArgs:
        return RDPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        if not isinstance(args, RDPArgs):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )
        if args.target.port == 0:
            args.target.port = 3389
        if args.timeout <= 0:
            raise argparse.ArgumentError(None, "--timeout must be a positive integer")

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.use_json = getattr(args, "json", False)
        self.results = RDPResults()
        self.timeout_seconds = args.timeout / 1000.0
        self._security_probes: list[NegotiationProbe] | None = None

    def run(self) -> None:
        selected_tests = self.args.tests or [
            test for test in RDP_TEST_ORDER if test in IMPLEMENTED_TESTS
        ]
        requested_tests = []
        seen_tests = set()
        for test in selected_tests:
            canonical = RDP_TEST_ALIASES.get(test, test)
            if canonical in seen_tests:
                continue
            requested_tests.append(canonical)
            seen_tests.add(canonical)

        for test in requested_tests:
            if test == "NLA":
                self.results.nla = self._run_nla_test()
            elif test == "RDPSEC":
                self.results.rdp_security = self._run_rdp_security_test()
            elif test == "CREDSSP":
                self.results.credssp = self._run_credssp_test()
            elif test == "RDPENC":
                self.results.rdp_encryption = self._run_rdp_encryption_test()
            elif test == "NTLMINFO":
                self.results.ntlm_info = self._run_ntlminfo_test()
            elif test == "SSL":
                self.results.ssl = self._run_ssl_test()
            else:
                self.results.not_implemented.append(test)

    def _get_security_probes(self) -> list[NegotiationProbe]:
        if self._security_probes is not None:
            return self._security_probes
        self._security_probes = [
            self._negotiate(
                "Full negotiation",
                PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX,
            ),
            self._negotiate("CredSSP/NLA only", PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX),
            self._negotiate("TLS without NLA", PROTOCOL_SSL),
            self._negotiate("Standard RDP Security", PROTOCOL_RDP),
        ]
        return self._security_probes

    def _run_nla_test(self) -> NLAResult:
        probes = self._get_security_probes()

        if not any(p.successful or p.failed_by_server for p in probes):
            err = probes[0].error or "RDP negotiation failed"
            return NLAResult("error", probes, err)

        nla_supported = any(
            p.selected_protocol in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX) for p in probes
        )
        non_nla_probes = [
            p
            for p in probes
            if p.name in ("TLS without NLA", "Standard RDP Security")
        ]
        non_nla_allowed = any(
            p.selected_protocol in (PROTOCOL_RDP, PROTOCOL_SSL)
            for p in non_nla_probes
        )
        non_nla_rejected_by_server = (
            len(non_nla_probes) == 2
            and all(p.failed_by_server for p in non_nla_probes)
        )

        if not nla_supported:
            status = "not_supported"
        elif non_nla_allowed:
            status = "allowed_not_required"
        elif non_nla_rejected_by_server:
            status = "required"
        else:
            status = "inconclusive"

        return NLAResult(status, probes)

    def _run_rdp_security_test(self) -> RDPSecurityResult:
        probe = next(
            p for p in self._get_security_probes() if p.name == "Standard RDP Security"
        )
        if probe.selected_protocol == PROTOCOL_RDP:
            status = "allowed"
        elif probe.failed_by_server:
            status = "not_allowed"
        elif probe.error:
            status = "error"
        else:
            status = "inconclusive"
        return RDPSecurityResult(status, probe)

    def _run_credssp_test(self) -> CredSSPResult:
        probes = self._get_security_probes()
        selected = [p.selected_protocol for p in probes if p.selected_protocol is not None]
        supported = any(p in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX) for p in selected)
        hybrid_ex_supported = PROTOCOL_HYBRID_EX in selected
        credssp_only = next(p for p in probes if p.name == "CredSSP/NLA only")

        if supported:
            status = "supported"
        elif credssp_only.failed_by_server:
            status = "not_supported"
        elif credssp_only.error:
            status = "error"
        else:
            status = "inconclusive"

        return CredSSPResult(status, hybrid_ex_supported, probes)

    def _run_rdp_encryption_test(self) -> RDPEncryptionResult:
        protocol_specs = (
            ("Standard RDP Security", PROTOCOL_RDP),
            ("TLS without NLA", PROTOCOL_SSL),
            ("CredSSP", PROTOCOL_HYBRID),
            ("RDSTLS", PROTOCOL_RDSTLS),
            ("CredSSP with Early User Authorization", PROTOCOL_HYBRID_EX),
            ("RDS AAD authentication", PROTOCOL_RDSAAD),
        )
        protocol_probes = [
            self._negotiate(name, protocol) for name, protocol in protocol_specs
        ]
        successful_or_rejected = [
            probe
            for probe in protocol_probes
            if probe.successful or probe.failed_by_server
        ]
        if not successful_or_rejected:
            return RDPEncryptionResult(
                status="error",
                protocol_probes=protocol_probes,
                error=protocol_probes[0].error or "RDP negotiation failed",
            )

        response_flags = 0
        for protocol_probe in protocol_probes:
            response_flags |= protocol_probe.response_flags or 0

        standard_rdp_probe = protocol_probes[0]
        legacy_probes: list[LegacyEncryptionProbe] = []
        if standard_rdp_probe.selected_protocol == PROTOCOL_RDP:
            for encryption_method in ENCRYPTION_METHOD_NAMES:
                legacy_probes.append(
                    self._probe_legacy_encryption(encryption_method)
                )
            if any(probe.accepted is True for probe in legacy_probes):
                legacy_status = "ok"
            elif any(probe.accepted is None for probe in legacy_probes):
                legacy_status = "inconclusive"
            else:
                legacy_status = "not_supported"
        elif standard_rdp_probe.failed_by_server:
            legacy_status = "not_allowed"
        else:
            legacy_status = "error"

        return RDPEncryptionResult(
            status="ok",
            protocol_probes=protocol_probes,
            legacy_status=legacy_status,
            legacy_probes=legacy_probes,
            response_flags=response_flags,
        )

    def _probe_legacy_encryption(self, encryption_method: int) -> LegacyEncryptionProbe:
        try:
            with socket.create_connection(
                (self.args.target.ip, self.args.target.port),
                timeout=self.timeout_seconds,
            ) as sock:
                sock.settimeout(self.timeout_seconds)
                sock.sendall(_build_negotiation_request(PROTOCOL_RDP))
                negotiation = _parse_negotiation_reply_details(_read_tpkt(sock))
                if negotiation.selected_protocol != PROTOCOL_RDP:
                    reason = (
                        FAILURE_CODES.get(
                            negotiation.failure_code,
                            f"failure code {negotiation.failure_code}",
                        )
                        if negotiation.failure_code is not None
                        else f"selected {protocol_name(negotiation.selected_protocol)}"
                    )
                    return LegacyEncryptionProbe(
                        requested_method=encryption_method,
                        accepted=False,
                        error=f"Standard RDP Security not accepted ({reason})",
                    )

                sock.sendall(_build_mcs_connect_initial(encryption_method))
                server_security = _parse_server_security_data(_read_tpkt(sock))
                accepted = bool(server_security.encryption_method & encryption_method)
                return LegacyEncryptionProbe(
                    requested_method=encryption_method,
                    accepted=accepted,
                    selected_method=server_security.encryption_method,
                    encryption_level=server_security.encryption_level,
                    server_rdp_version=server_security.server_rdp_version,
                )
        except (OSError, RDPProtocolError, ValueError) as exc:
            return LegacyEncryptionProbe(
                requested_method=encryption_method,
                accepted=None,
                error=str(exc),
            )

    def _run_ntlminfo_test(self) -> NTLMInfoResult:
        sock: socket.socket | None = None
        probe: NegotiationProbe | None = None
        requested_protocols = PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX

        try:
            from ..ptntlmauth.ptntlmauth import (
                decode_ChallengeMessage_blob,
                get_NegotiateMessage_data,
            )

            sock = socket.create_connection(
                (self.args.target.ip, self.args.target.port),
                timeout=self.timeout_seconds,
            )
            sock.settimeout(self.timeout_seconds)
            sock.sendall(_build_negotiation_request(requested_protocols))
            selected_protocol, failure_code, note = _parse_negotiation_reply(
                _read_tpkt(sock)
            )
            probe = NegotiationProbe(
                name="CredSSP NTLM information",
                requested_protocols=requested_protocols,
                selected_protocol=selected_protocol,
                failure_code=failure_code,
                note=note,
            )

            if selected_protocol not in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX):
                if failure_code is not None:
                    reason = FAILURE_CODES.get(
                        failure_code,
                        f"unknown failure code {failure_code}",
                    )
                    error = f"CredSSP negotiation failed ({reason})"
                else:
                    error = "server did not select CredSSP/NLA"
                return NTLMInfoResult(
                    "not_supported",
                    selected_protocol=protocol_name(selected_protocol),
                    negotiation_probe=probe,
                    error=error,
                )

            server_hostname = (
                None if _target_is_ip(self.args.target.ip) else self.args.target.ip
            )
            context = _create_tls_context()
            with context.wrap_socket(sock, server_hostname=server_hostname) as tls_sock:
                sock = None
                ntlm_negotiate = get_NegotiateMessage_data()
                spnego_init = _build_spnego_ntlm_init(ntlm_negotiate)
                tls_sock.sendall(_build_credssp_ts_request(spnego_init))

                response = _read_der_message(tls_sock)
                nego_token = _extract_credssp_nego_token(response)
                if nego_token is None:
                    raise RDPProtocolError(
                        "CredSSP response did not include a negotiation token"
                    )
                challenge = _extract_ntlm_challenge(nego_token)
                details = decode_ChallengeMessage_blob(challenge)
                ntlm_info = _ntlm_info_from_details(details)

            return NTLMInfoResult(
                "ok" if _ntlm_info_has_values(ntlm_info) else "empty",
                info=ntlm_info,
                selected_protocol=protocol_name(selected_protocol),
                negotiation_probe=probe,
            )
        except ImportError as exc:
            return NTLMInfoResult(
                "error",
                negotiation_probe=probe,
                error=f"NTLMINFO test requires ntlm-auth or impacket ({exc})",
            )
        except (OSError, ssl.SSLError, RDPProtocolError, PyAsn1Error, ValueError) as exc:
            return NTLMInfoResult(
                "error",
                selected_protocol=protocol_name(probe.selected_protocol)
                if probe is not None
                else None,
                negotiation_probe=probe,
                error=str(exc),
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _run_ssl_test(self) -> SSLResult:
        attempts = (
            PROTOCOL_SSL,
            PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX,
        )
        last_result = SSLResult("error", error="TLS handshake was not attempted")
        working_protocols: int | None = None

        for protocols in attempts:
            probe, tls_version, cipher, cert_der, error = self._tls_handshake(protocols)
            if error is None:
                certificate = self._parse_certificate(cert_der, self.args.target.ip)
                result = SSLResult(
                    status="ok",
                    negotiation_probe=probe,
                    selected_protocol=protocol_name(probe.selected_protocol),
                    selected_tls_version=tls_version,
                    selected_cipher=cipher,
                    certificate=certificate,
                )
                working_protocols = protocols
                break
            last_result = SSLResult(
                status="error",
                negotiation_probe=probe,
                error=error,
            )
        else:
            return last_result

        result.version_probes = self._probe_tls_versions(working_protocols)
        result.weak_findings = self._tls_weak_findings(result)
        if result.weak_findings:
            result.status = "weak"
        return result

    def _tls_handshake(
        self,
        requested_protocols: int,
        tls_version: ssl.TLSVersion | None = None,
    ) -> tuple[
        NegotiationProbe | None,
        str | None,
        str | None,
        bytes | None,
        str | None,
    ]:
        sock: socket.socket | None = None
        probe: NegotiationProbe | None = None
        try:
            sock = socket.create_connection(
                (self.args.target.ip, self.args.target.port),
                timeout=self.timeout_seconds,
            )
            sock.settimeout(self.timeout_seconds)
            sock.sendall(_build_negotiation_request(requested_protocols))
            selected_protocol, failure_code, note = _parse_negotiation_reply(
                _read_tpkt(sock)
            )
            probe = NegotiationProbe(
                name=f"TLS handshake via {protocol_mask_to_string(requested_protocols)}",
                requested_protocols=requested_protocols,
                selected_protocol=selected_protocol,
                failure_code=failure_code,
                note=note,
            )

            if selected_protocol not in (PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX):
                return (
                    probe,
                    None,
                    None,
                    None,
                    "server did not select a TLS-capable RDP protocol",
                )

            server_hostname = (
                None if _target_is_ip(self.args.target.ip) else self.args.target.ip
            )
            context = _create_tls_context(tls_version)
            with context.wrap_socket(sock, server_hostname=server_hostname) as tls_sock:
                sock = None
                cert_der = tls_sock.getpeercert(binary_form=True)
                return (
                    probe,
                    tls_sock.version(),
                    _format_cipher(tls_sock.cipher()),
                    cert_der,
                    None,
                )
        except (OSError, ssl.SSLError, RDPProtocolError) as exc:
            return probe, None, None, None, str(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _probe_tls_versions(self, requested_protocols: int) -> list[TLSVersionProbe]:
        probes: list[TLSVersionProbe] = []
        for label, version in _tls_version_members():
            _probe, _selected_version, cipher, _cert_der, error = self._tls_handshake(
                requested_protocols,
                version,
            )
            if error is None:
                probes.append(
                    TLSVersionProbe(
                        label,
                        True,
                        selected_cipher=cipher,
                    )
                )
            else:
                probes.append(TLSVersionProbe(label, False, error=error))
        return probes

    def _parse_certificate(self, cert_der: bytes | None, target: str) -> CertificateInfo:
        if not cert_der:
            return CertificateInfo(
                None,
                None,
                None,
                None,
                None,
                [],
                [],
                None,
                None,
                None,
                "server did not provide a certificate",
            )

        try:
            cert = x509.load_der_x509_certificate(cert_der)
            not_before = getattr(cert, "not_valid_before_utc", None)
            if not_before is None:
                not_before = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
            not_after = getattr(cert, "not_valid_after_utc", None)
            if not_after is None:
                not_after = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)

            dns_names: list[str] = []
            ip_addresses: list[str] = []
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                dns_names = list(san.value.get_values_for_type(x509.DNSName))
                ip_addresses = [
                    str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)
                ]
            except x509.ExtensionNotFound:
                pass
            common_names = [
                attr.value
                for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            ]
            signature_hash_algorithm = (
                cert.signature_hash_algorithm.name
                if cert.signature_hash_algorithm is not None
                else None
            )
            san_present = bool(dns_names or ip_addresses)
            target_matches_san = (
                _certificate_san_matches_target(target, dns_names, ip_addresses)
                if san_present
                else False
            )

            now = dt.datetime.now(dt.timezone.utc)
            return CertificateInfo(
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                serial=f"{cert.serial_number:x}",
                not_before=not_before.isoformat(),
                not_after=not_after.isoformat(),
                dns_names=dns_names,
                ip_addresses=ip_addresses,
                expired=now > not_after,
                not_yet_valid=now < not_before,
                self_signed=_certificate_is_self_signed(cert),
                common_names=common_names,
                san_present=san_present,
                target_matches_san=target_matches_san,
                signature_hash_algorithm=signature_hash_algorithm,
            )
        except Exception as exc:
            return CertificateInfo(
                None,
                None,
                None,
                None,
                None,
                [],
                [],
                None,
                None,
                None,
                str(exc),
            )

    def _tls_weak_findings(self, result: SSLResult) -> list[str]:
        findings: list[str] = []
        for probe in result.version_probes:
            if probe.supported and probe.version in {"TLSv1.0", "TLSv1.1"}:
                findings.append(f"{probe.version} supported")

        weak_cipher_tokens = (
            "RC4",
            "3DES",
            "DES",
            "NULL",
            "EXPORT",
            "MD5",
            "ADH",
            "AECDH",
        )
        checked_ciphers = [result.selected_cipher or ""]
        checked_ciphers.extend(p.selected_cipher or "" for p in result.version_probes)
        for cipher in checked_ciphers:
            upper = cipher.upper()
            if any(token in upper for token in weak_cipher_tokens):
                findings.append(f"weak cipher accepted: {cipher}")

        if result.certificate is not None:
            cert = result.certificate
            if cert.expired:
                findings.append("certificate expired")
            if cert.not_yet_valid:
                findings.append("certificate is not yet valid")
            if cert.self_signed:
                findings.append("certificate is self-signed")
            if cert.san_present is False:
                findings.append("certificate has no subjectAltName extension")
            elif cert.target_matches_san is False:
                findings.append("certificate subjectAltName does not match target")
            if cert.signature_hash_algorithm in {"md5", "sha1"}:
                findings.append(
                    f"certificate signed with weak hash algorithm: {cert.signature_hash_algorithm}"
                )
            if cert.parse_error:
                findings.append(f"certificate parse error: {cert.parse_error}")

        return sorted(set(findings))

    def _negotiate(self, name: str, requested_protocols: int) -> NegotiationProbe:
        try:
            with socket.create_connection(
                (self.args.target.ip, self.args.target.port),
                timeout=self.timeout_seconds,
            ) as sock:
                sock.settimeout(self.timeout_seconds)
                sock.sendall(_build_negotiation_request(requested_protocols))
                reply = _parse_negotiation_reply_details(_read_tpkt(sock))
                return NegotiationProbe(
                    name=name,
                    requested_protocols=requested_protocols,
                    selected_protocol=reply.selected_protocol,
                    failure_code=reply.failure_code,
                    response_flags=reply.response_flags,
                    note=reply.note,
                )
        except (OSError, RDPProtocolError) as exc:
            return NegotiationProbe(
                name=name,
                requested_protocols=requested_protocols,
                error=str(exc),
            )

    def output(self) -> None:
        properties = {
            "software_type": None,
            "name": "rdp",
            "version": None,
            "vendor": None,
            "description": None,
            "target": self.args.target.ip,
            "port": self.args.target.port,
        }
        deferred_vulns = []

        if self.results.nla is not None:
            self._output_nla_text(self.results.nla)
            properties["nla"] = self._nla_json(self.results.nla)

            if self.results.nla.status == "allowed_not_required":
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.NLA_NOT_REQUIRED.value,
                        "vuln_request": "RDP negotiation without CredSSP/NLA",
                        "vuln_response": "Server accepted a non-NLA security protocol",
                    }
                )
            elif self.results.nla.status == "not_supported":
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.NLA_NOT_SUPPORTED.value,
                        "vuln_request": "RDP negotiation with CredSSP/NLA",
                        "vuln_response": "Server did not select CredSSP/NLA",
                    }
                )

        if self.results.rdp_security is not None:
            self._output_rdp_security_text(self.results.rdp_security)
            properties["rdpSecurity"] = self._rdp_security_json(self.results.rdp_security)
            if self.results.rdp_security.status == "allowed":
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.RDP_SECURITY_ALLOWED.value,
                        "vuln_request": "RDP negotiation with PROTOCOL_RDP",
                        "vuln_response": "Server accepted legacy Standard RDP Security",
                    }
                )

        if self.results.credssp is not None:
            self._output_credssp_text(self.results.credssp)
            properties["credssp"] = self._credssp_json(self.results.credssp)

        if self.results.rdp_encryption is not None:
            self._output_rdp_encryption_text(self.results.rdp_encryption)
            properties["rdpEncryption"] = self._rdp_encryption_json(
                self.results.rdp_encryption
            )

        if self.results.ntlm_info is not None:
            self._output_ntlminfo_text(self.results.ntlm_info)
            properties["ntlmInfo"] = self._ntlminfo_json(self.results.ntlm_info)
            if (
                self.results.ntlm_info.status == "ok"
                and self.results.ntlm_info.info is not None
            ):
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.NTLM_INFO_DISCLOSURE.value,
                        "vuln_request": "CredSSP NTLM negotiate challenge",
                        "vuln_response": "\n".join(
                            self._ntlm_info_output_lines(self.results.ntlm_info.info)
                        ),
                    }
                )

        if self.results.ssl is not None:
            self._output_ssl_text(self.results.ssl)
            properties["ssl"] = self._ssl_json(self.results.ssl)
            if self.results.ssl.weak_findings:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.TLS_WEAK_CONFIG.value,
                        "vuln_request": "RDP TLS handshake and TLS version probes",
                        "vuln_response": "\n".join(self.results.ssl.weak_findings),
                    }
                )

        if self.results.not_implemented:
            properties["notImplementedTests"] = self.results.not_implemented
            if not self.use_json:
                for test in self.results.not_implemented:
                    self.ptprint(f"{test} test", Out.INFO)
                    icon = get_colored_text("[!]", color="WARNING")
                    self.ptprint(f"    {icon} Test is not implemented yet", Out.TEXT)

        rdp_node = self.ptjsonlib.create_node_object("software", None, None, properties)
        self.ptjsonlib.add_node(rdp_node)
        node_key = rdp_node["key"]
        for vuln in deferred_vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **vuln)

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)

    def _output_nla_text(self, result: NLAResult) -> None:
        if self.use_json:
            return

        self.ptprint("Network Level Authentication (NLA) test", Out.INFO)
        if result.status == "required":
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} NLA required", Out.TEXT)
        elif result.status == "allowed_not_required":
            icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(f"    {icon} NLA is allowed but not required", Out.TEXT)
        elif result.status == "not_supported":
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} NLA is not supported", Out.TEXT)
        elif result.status == "error":
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} {result.error}", Out.TEXT)
        else:
            icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(f"    {icon} NLA status is inconclusive", Out.TEXT)

        for probe in result.probes:
            self.ptdebug(probe.summary())
            if probe.note:
                self.ptdebug(f"{probe.name}: {probe.note}")

    def _output_rdp_security_text(self, result: RDPSecurityResult) -> None:
        if self.use_json:
            return

        self.ptprint("RDP Security test", Out.INFO)
        if result.status == "allowed":
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Legacy Standard RDP Security is allowed", Out.TEXT)
        elif result.status == "not_allowed":
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} Legacy Standard RDP Security is not allowed", Out.TEXT)
        elif result.status == "error":
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} {result.probe.error}", Out.TEXT)
        else:
            icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(f"    {icon} RDP Security status is inconclusive", Out.TEXT)
        self.ptdebug(result.probe.summary())

    def _output_credssp_text(self, result: CredSSPResult) -> None:
        if self.use_json:
            return

        self.ptprint("CredSSP test", Out.INFO)
        if result.status == "supported":
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(f"    {icon} CredSSP is supported", Out.TEXT)
            if result.hybrid_ex_supported:
                self.ptprint(f"    {icon} CredSSP HYBRID_EX is supported", Out.TEXT)
        elif result.status == "not_supported":
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} CredSSP is not supported", Out.TEXT)
        elif result.status == "error":
            icon = get_colored_text("[✗]", color="VULN")
            probe = next(p for p in result.probes if p.name == "CredSSP/NLA only")
            self.ptprint(f"    {icon} {probe.error}", Out.TEXT)
        else:
            icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(f"    {icon} CredSSP status is inconclusive", Out.TEXT)
        for probe in result.probes:
            self.ptdebug(probe.summary())

    def _output_rdp_encryption_text(self, result: RDPEncryptionResult) -> None:
        if self.use_json:
            return

        self.ptprint("RDP security and encryption enumeration", Out.INFO)
        if result.status == "error":
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} {result.error}", Out.TEXT)
            return

        self.ptprint("    Security protocols", Out.TEXT)
        for probe in result.protocol_probes:
            supported = probe.selected_protocol == probe.requested_protocols
            if supported:
                insecure = probe.requested_protocols == PROTOCOL_RDP
                icon = get_colored_text(
                    "[✗]" if insecure else "[✓]",
                    color="VULN" if insecure else "NOTVULN",
                )
                state = "supported"
            elif probe.failed_by_server:
                icon = get_colored_text("[!]", color="WARNING")
                state = "not supported"
            elif probe.error:
                icon = get_colored_text("[!]", color="WARNING")
                state = f"unknown ({probe.error})"
            else:
                icon = get_colored_text("[!]", color="WARNING")
                state = f"selected {protocol_name(probe.selected_protocol)}"
            self.ptprint(f"        {icon} {probe.name}: {state}", Out.TEXT)

        if result.response_flags:
            self.ptprint("    Negotiation capabilities", Out.TEXT)
            for flag, name in NEGOTIATION_RESPONSE_FLAGS.items():
                if result.response_flags & flag:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"        {icon} {name}", Out.TEXT)

        self.ptprint("    Standard RDP encryption", Out.TEXT)
        if result.legacy_status == "not_allowed":
            icon = get_colored_text("[✓]", color="NOTVULN")
            self.ptprint(
                f"        {icon} Standard RDP Security is not accepted",
                Out.TEXT,
            )
        elif not result.legacy_probes:
            icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(
                f"        {icon} Encryption methods could not be enumerated",
                Out.TEXT,
            )
        else:
            levels = {
                probe.encryption_level
                for probe in result.legacy_probes
                if probe.accepted and probe.encryption_level is not None
            }
            for legacy_probe in result.legacy_probes:
                method_name = ENCRYPTION_METHOD_NAMES[legacy_probe.requested_method]
                if legacy_probe.accepted is True:
                    icon = get_colored_text("[✗]", color="VULN")
                    state = "accepted"
                elif legacy_probe.accepted is False:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    state = "not accepted"
                else:
                    icon = get_colored_text("[!]", color="WARNING")
                    state = f"unknown ({legacy_probe.error})"
                self.ptprint(f"        {icon} {method_name}: {state}", Out.TEXT)
            if levels:
                level_names = ", ".join(
                    ENCRYPTION_LEVEL_NAMES.get(level, f"Unknown ({level})")
                    for level in sorted(levels)
                )
                self.ptprint(f"        Encryption level: {level_names}", Out.TEXT)
            server_versions = {
                probe.server_rdp_version
                for probe in result.legacy_probes
                if probe.server_rdp_version is not None
            }
            if server_versions:
                versions = ", ".join(
                    SERVER_RDP_VERSION_NAMES.get(
                        version,
                        f"Unknown (0x{version:08x})",
                    )
                    for version in sorted(server_versions)
                )
                self.ptprint(f"        Server protocol version: {versions}", Out.TEXT)

        for probe in result.protocol_probes:
            self.ptdebug(probe.summary())

    def _output_ntlminfo_text(self, result: NTLMInfoResult) -> None:
        if self.use_json:
            return

        self.ptprint("RDP NTLM information", Out.INFO)
        if result.status == "ok" and result.info is not None:
            icon = get_colored_text("[!]", color="WARNING")
            protocol = result.selected_protocol or "unknown protocol"
            self.ptprint(
                f"    {icon} NTLM challenge exposes server information via {protocol}",
                Out.TEXT,
            )
            for line in self._ntlm_info_output_lines(result.info):
                self.ptprint(f"        {line}", Out.TEXT)
        elif result.status == "empty":
            icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(
                f"    {icon} NTLM challenge was received but no server fields were decoded",
                Out.TEXT,
            )
        elif result.status == "not_supported":
            icon = get_colored_text("[✓]", color="NOTVULN")
            detail = f": {result.error}" if result.error else ""
            self.ptprint(f"    {icon} NTLM information not available{detail}", Out.TEXT)
        else:
            icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(
                f"    {icon} NTLM information test failed: {result.error}",
                Out.TEXT,
            )

        if result.negotiation_probe is not None:
            self.ptdebug(result.negotiation_probe.summary())

    def _output_ssl_text(self, result: SSLResult) -> None:
        if self.use_json:
            return

        self.ptprint("TLS / SSL configuration test", Out.INFO)
        if result.status in ("ok", "weak"):
            icon = get_colored_text(
                "[!]" if result.status == "weak" else "[✓]",
                color="WARNING" if result.status == "weak" else "NOTVULN",
            )
            detail = result.selected_tls_version or "unknown TLS version"
            if result.selected_cipher:
                detail = f"{detail}, {result.selected_cipher}"
            self.ptprint(f"    {icon} TLS handshake successful ({detail})", Out.TEXT)
            for finding in result.weak_findings:
                finding_icon = get_colored_text("[!]", color="WARNING")
                self.ptprint(f"    {finding_icon} {finding}", Out.TEXT)
        else:
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} TLS handshake failed: {result.error}", Out.TEXT)

        if result.certificate and result.certificate.subject:
            self.ptdebug(f"Certificate subject: {result.certificate.subject}")
            self.ptdebug(f"Certificate issuer: {result.certificate.issuer}")
            self.ptdebug(f"Certificate notAfter: {result.certificate.not_after}")
        for probe in result.version_probes:
            status = "supported" if probe.supported else f"not supported ({probe.error})"
            self.ptdebug(f"{probe.version}: {status}")

    def _nla_json(self, result: NLAResult) -> dict:
        return {
            "status": result.status,
            "error": result.error,
            "probes": [
                {
                    "name": probe.name,
                    "requestedProtocols": protocol_mask_to_string(probe.requested_protocols),
                    "selectedProtocol": protocol_name(probe.selected_protocol),
                    "failureCode": probe.failure_code,
                    "failureReason": FAILURE_CODES.get(probe.failure_code)
                    if probe.failure_code is not None
                    else None,
                    "error": probe.error,
                    "note": probe.note,
                }
                for probe in result.probes
            ],
        }

    def _rdp_security_json(self, result: RDPSecurityResult) -> dict:
        return {
            "status": result.status,
            "probe": self._negotiation_probe_json(result.probe),
        }

    def _credssp_json(self, result: CredSSPResult) -> dict:
        return {
            "status": result.status,
            "hybridExSupported": result.hybrid_ex_supported,
            "probes": [self._negotiation_probe_json(probe) for probe in result.probes],
        }

    def _rdp_encryption_json(self, result: RDPEncryptionResult) -> dict:
        return {
            "status": result.status,
            "error": result.error,
            "securityProtocols": [
                {
                    **self._negotiation_probe_json(probe),
                    "supported": probe.selected_protocol == probe.requested_protocols,
                }
                for probe in result.protocol_probes
            ],
            "negotiationCapabilities": [
                name
                for flag, name in NEGOTIATION_RESPONSE_FLAGS.items()
                if result.response_flags & flag
            ],
            "standardRdpEncryption": {
                "status": result.legacy_status,
                "serverProtocolVersions": sorted(
                    {
                        SERVER_RDP_VERSION_NAMES.get(
                            probe.server_rdp_version,
                            f"Unknown (0x{probe.server_rdp_version:08x})",
                        )
                        for probe in result.legacy_probes
                        if probe.server_rdp_version is not None
                    }
                ),
                "methods": [
                    {
                        "name": ENCRYPTION_METHOD_NAMES[probe.requested_method],
                        "requestedMethod": probe.requested_method,
                        "accepted": probe.accepted,
                        "selectedMethod": probe.selected_method,
                        "encryptionLevel": probe.encryption_level,
                        "encryptionLevelName": ENCRYPTION_LEVEL_NAMES.get(
                            probe.encryption_level
                        ),
                        "serverRdpVersion": probe.server_rdp_version,
                        "error": probe.error,
                    }
                    for probe in result.legacy_probes
                ],
            },
        }

    def _ntlminfo_json(self, result: NTLMInfoResult) -> dict:
        return {
            "status": result.status,
            "selectedProtocol": result.selected_protocol,
            "error": result.error,
            "negotiationProbe": self._negotiation_probe_json(result.negotiation_probe)
            if result.negotiation_probe is not None
            else None,
            "serverInfo": self._ntlm_info_json(result.info)
            if result.info is not None
            else None,
        }

    def _ntlm_info_json(self, info: RDPNTLMInfo) -> dict:
        return {
            "targetName": info.target_name,
            "netbiosDomainName": info.netbios_domain,
            "netbiosComputerName": info.netbios_computer,
            "dnsDomainName": info.dns_domain,
            "dnsComputerName": info.dns_computer,
            "dnsTree": info.dns_tree,
            "osVersion": info.os_version,
            "serverTime": info.server_time,
        }

    def _ntlm_info_output_lines(self, info: RDPNTLMInfo) -> list[str]:
        return [
            f"Target name: {info.target_name}",
            f"NetBios domain name: {info.netbios_domain}",
            f"NetBios computer name: {info.netbios_computer}",
            f"DNS domain name: {info.dns_domain}",
            f"DNS computer name: {info.dns_computer}",
            f"DNS tree: {info.dns_tree}",
            f"OS version: {info.os_version}",
            f"Server time: {info.server_time}",
        ]

    def _ssl_json(self, result: SSLResult) -> dict:
        return {
            "status": result.status,
            "selectedProtocol": result.selected_protocol,
            "selectedTlsVersion": result.selected_tls_version,
            "selectedCipher": result.selected_cipher,
            "weakFindings": result.weak_findings,
            "error": result.error,
            "negotiationProbe": self._negotiation_probe_json(result.negotiation_probe)
            if result.negotiation_probe is not None
            else None,
            "certificate": self._certificate_json(result.certificate)
            if result.certificate is not None
            else None,
            "versionProbes": [
                {
                    "version": probe.version,
                    "supported": probe.supported,
                    "selectedCipher": probe.selected_cipher,
                    "error": probe.error,
                }
                for probe in result.version_probes
            ],
        }

    def _negotiation_probe_json(self, probe: NegotiationProbe) -> dict:
        return {
            "name": probe.name,
            "requestedProtocols": protocol_mask_to_string(probe.requested_protocols),
            "selectedProtocol": protocol_name(probe.selected_protocol),
            "failureCode": probe.failure_code,
            "responseFlags": probe.response_flags,
            "responseFlagNames": [
                name
                for flag, name in NEGOTIATION_RESPONSE_FLAGS.items()
                if probe.response_flags is not None and probe.response_flags & flag
            ],
            "failureReason": FAILURE_CODES.get(probe.failure_code)
            if probe.failure_code is not None
            else None,
            "error": probe.error,
            "note": probe.note,
        }

    def _certificate_json(self, certificate: CertificateInfo) -> dict:
        return {
            "subject": certificate.subject,
            "issuer": certificate.issuer,
            "serial": certificate.serial,
            "notBefore": certificate.not_before,
            "notAfter": certificate.not_after,
            "dnsNames": certificate.dns_names,
            "ipAddresses": certificate.ip_addresses,
            "expired": certificate.expired,
            "notYetValid": certificate.not_yet_valid,
            "selfSigned": certificate.self_signed,
            "parseError": certificate.parse_error,
            "commonNames": certificate.common_names,
            "sanPresent": certificate.san_present,
            "targetMatchesSan": certificate.target_matches_san,
            "signatureHashAlgorithm": certificate.signature_hash_algorithm,
        }
