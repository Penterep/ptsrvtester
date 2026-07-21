from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import hmac
import importlib.metadata
import ipaddress
import logging
import math
import socket
import ssl
import struct
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.x509.oid import NameOID
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib
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
    "CAPABIL",
    "VERSION",
    "SSL",
    "NTLMINFO",
    "AUTH",
)
RDP_TEST_ALIASES = {"INFO": "NTLMINFO"}
RDP_TEST_CHOICES = RDP_TEST_ORDER + tuple(RDP_TEST_ALIASES)
IMPLEMENTED_TESTS = {
    "NLA",
    "RDPSEC",
    "CREDSSP",
    "RDPENC",
    "CAPABIL",
    "VERSION",
    "SSL",
    "NTLMINFO",
    "AUTH",
}

AARDWOLF_VERSION = "0.2.14"
ASYAUTH_VERSION = "0.0.23"
REMOTEFX_CODEC_GUID = "76772f12-bd72-4463-afb3-b73c9c6f7886"
_AARDWOLF_SESSION_LOCK = threading.Lock()
MAX_ACCEPTED_WEAK_CIPHERS = 32

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
LEGACY_ENCRYPTION_METHOD_MASK = (
    ENCRYPTION_METHOD_40BIT
    | ENCRYPTION_METHOD_56BIT
    | ENCRYPTION_METHOD_128BIT
    | ENCRYPTION_METHOD_FIPS
)

ENCRYPTION_LEVEL_NAMES = {
    0x00000000: "None",
    0x00000001: "Low",
    0x00000002: "Client Compatible",
    0x00000003: "High",
    0x00000004: "FIPS",
}

SERVER_RDP_VERSION_NAMES = {
    0x00080001: "RDP 4.0",
    0x00080004: "RDP 5.0-8.1 family",
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
    0x00080010: "RDP 10.11",
    0x00080011: "RDP 10.12",
}

SC_CORE = 0x0C01
SC_SECURITY = 0x0C02
SC_NET = 0x0C03
SC_MCS_MSGCHANNEL = 0x0C04
SC_MULTITRANSPORT = 0x0C08

CS_NET = 0xC003
CS_MCS_MSGCHANNEL = 0xC006
CS_MULTITRANSPORT = 0xC00A

CHANNEL_OPTION_INITIALIZED = 0x80000000
CHANNEL_OPTION_ENCRYPT_RDP = 0x40000000
CHANNEL_OPTION_COMPRESS_RDP = 0x00800000
CHANNEL_OPTION_SHOW_PROTOCOL = 0x00200000
DEFAULT_CHANNEL_OPTIONS = (
    CHANNEL_OPTION_INITIALIZED
    | CHANNEL_OPTION_ENCRYPT_RDP
    | CHANNEL_OPTION_COMPRESS_RDP
    | CHANNEL_OPTION_SHOW_PROTOCOL
)

CAPABILITY_CHANNELS = {
    "Clipboard": "cliprdr",
    "Drive redirection": "rdpdr",
    "Dynamic Virtual Channels": "drdynvc",
    "Audio": "rdpsnd",
}
CAPABILITY_OUTPUT_ORDER = (
    "Bitmap compression",
    "RemoteFX",
    "AVC444",
    "Clipboard",
    "Drive redirection",
    "Dynamic Virtual Channels",
    "Graphics Pipeline",
    "Multi-monitor",
    "Audio",
    "UDP transport",
)

TRANSPORTTYPE_UDPFECR = 0x00000001
TRANSPORTTYPE_UDPFECL = 0x00000004
TRANSPORTTYPE_UDP_PREFERRED = 0x00000100
SOFTSYNC_TCP_TO_UDP = 0x00000200
CLIENT_MULTITRANSPORT_FLAGS = (
    TRANSPORTTYPE_UDPFECR
    | TRANSPORTTYPE_UDPFECL
    | TRANSPORTTYPE_UDP_PREFERRED
    | SOFTSYNC_TCP_TO_UDP
)

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
class ServerCoreData:
    version: int
    client_requested_protocols: int | None = None
    early_capability_flags: int | None = None


@dataclass
class BasicSettingsResult:
    status: str
    selected_protocol: int | None = None
    response_flags: int = 0
    server_core: ServerCoreData | None = None
    channel_ids: dict[str, int] = field(default_factory=dict)
    multitransport_flags: int | None = None
    error: str | None = None


@dataclass(frozen=True)
class CapabilityFinding:
    name: str
    status: str
    evidence: str


@dataclass
class CapabilityResult:
    status: str
    findings: list[CapabilityFinding] = field(default_factory=list)
    error: str | None = None


@dataclass
class RDPVersionResult:
    status: str
    advertised_version: int | None = None
    version_name: str | None = None
    transport: str | None = None
    source: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class AuthTLSValidationResult:
    status: str
    certificate_sha256: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class AuthenticatedSessionResult:
    status: str
    selected_protocol: int | None = None
    session_established: bool = False
    server_core: ServerCoreData | None = None
    channel_ids: dict[str, int] = field(default_factory=dict)
    channel_data_observed: bool = False
    demand_active_observed: bool = False
    capability_types: frozenset[str] = field(default_factory=frozenset)
    bitmap_codec_guids: frozenset[str] = field(default_factory=frozenset)
    capability_error: str | None = None
    tls_verification: str | None = None
    certificate_sha256: str | None = None
    error: str | None = None


@dataclass
class RDPAuthResult:
    status: str
    selected_protocol: int | None = None
    session_established: bool = False
    tls_verification: str | None = None
    certificate_sha256: str | None = None
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
class WeakCipherScanResult:
    status: str
    tested_count: int = 0
    accepted_ciphers: tuple[str, ...] = ()
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
    sha256_fingerprint: str | None = None


@dataclass
class SSLResult:
    status: str
    negotiation_probe: NegotiationProbe | None = None
    selected_protocol: str | None = None
    selected_tls_version: str | None = None
    selected_cipher: str | None = None
    certificate: CertificateInfo | None = None
    version_probes: list[TLSVersionProbe] = field(default_factory=list)
    weak_cipher_scan: WeakCipherScanResult | None = None
    weak_findings: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class RDPResults:
    nla: NLAResult | None = None
    rdp_security: RDPSecurityResult | None = None
    credssp: CredSSPResult | None = None
    rdp_encryption: RDPEncryptionResult | None = None
    capabilities: CapabilityResult | None = None
    version: RDPVersionResult | None = None
    ntlm_info: NTLMInfoResult | None = None
    ssl: SSLResult | None = None
    auth: RDPAuthResult | None = None
    not_implemented: list[str] = field(default_factory=list)


def _split_ntlm_login(login: str) -> tuple[str | None, str]:
    if not login or login != login.strip():
        raise ValueError("login must not be empty or contain leading/trailing whitespace")
    if "\x00" in login:
        raise ValueError("login must not contain NUL characters")
    if len(login) > 512:
        raise ValueError("login is too long")

    if "\\" in login:
        domain, username = login.split("\\", 1)
        if not domain or not username:
            raise ValueError("login must use DOMAIN\\user format")
        return domain, username

    if "@" in login:
        username, domain = login.rsplit("@", 1)
        if not domain or not username:
            raise ValueError("login must use user@domain format")
        return domain, username

    return None, login


def _sanitize_auth_error(error: object, *sensitive_values: str | None) -> str:
    message = str(error).strip() or error.__class__.__name__
    for sensitive_value in sensitive_values:
        if sensitive_value:
            message = message.replace(sensitive_value, "<redacted>")
    if len(message) > 500:
        message = f"{message[:497]}..."
    return message


def _parse_bitmap_codec_guids(data: bytes) -> frozenset[str]:
    if not data:
        raise ValueError("empty RDP bitmap codec data")

    codec_count = data[0]
    offset = 1
    codecs: set[str] = set()
    for _ in range(codec_count):
        if len(data) - offset < 19:
            raise ValueError("truncated RDP bitmap codec entry")

        codec_guid = uuid.UUID(bytes_le=data[offset : offset + 16])
        properties_length = int.from_bytes(
            data[offset + 17 : offset + 19],
            byteorder="little",
        )
        offset += 19
        if len(data) - offset < properties_length:
            raise ValueError("truncated RDP bitmap codec properties")
        offset += properties_length
        codecs.add(str(codec_guid))

    if offset != len(data):
        raise ValueError("unexpected trailing RDP bitmap codec data")
    return frozenset(codecs)


def _certificate_sha256(cert_der: bytes | None) -> str | None:
    if not cert_der:
        return None
    return hashlib.sha256(cert_der).hexdigest()


@contextmanager
def _capture_aardwolf_demand_active(parser_type):
    capture: dict[str, object] = {}
    original_from_bytes = parser_type.from_bytes

    def capture_demand_active(data: bytes):
        parsed = original_from_bytes(data)
        capability_types: set[str] = set()
        bitmap_codec_guids: frozenset[str] = frozenset()
        capability_error: str | None = None

        for capability_set in parsed.capabilitySets:
            capability_type = capability_set.capabilitySetType.name
            capability_types.add(capability_type)
            if capability_type != "BITMAP_CODECS":
                continue

            codec_data = getattr(
                capability_set.capability,
                "supportedBitmapCodecs",
                capability_set.capabilityData,
            )
            try:
                if not isinstance(codec_data, bytes):
                    raise TypeError("RDP bitmap codec data is not a byte string")
                bitmap_codec_guids = _parse_bitmap_codec_guids(codec_data)
            except (TypeError, ValueError) as exc:
                capability_error = str(exc)

        capture["observed"] = True
        capture["capability_types"] = frozenset(capability_types)
        capture["bitmap_codec_guids"] = bitmap_codec_guids
        capture["capability_error"] = capability_error
        return parsed

    parser_type.from_bytes = staticmethod(capture_demand_active)
    try:
        yield capture
    finally:
        parser_type.from_bytes = staticmethod(original_from_bytes)


def _extract_aardwolf_server_core(connection, core_key) -> ServerCoreData | None:
    server_data = getattr(connection, "_RDPConnection__server_connect_pdu", None)
    if server_data is None:
        return None

    try:
        core = server_data[core_key]
        version = int(core.version)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None

    requested_protocols = getattr(core, "clientRequestedProtocols", None)
    early_flags = getattr(core, "earlyCapabilityFlags", None)
    return ServerCoreData(
        version=version,
        client_requested_protocols=(
            int(requested_protocols) if requested_protocols is not None else None
        ),
        early_capability_flags=int(early_flags) if early_flags is not None else None,
    )


def _extract_aardwolf_channel_ids(
    connection,
    network_key,
    requested_channels: tuple[str, ...],
) -> tuple[dict[str, int], bool]:
    server_data = getattr(connection, "_RDPConnection__server_connect_pdu", None)
    if server_data is None:
        return {}, False

    try:
        network = server_data[network_key]
        channel_ids = tuple(int(channel_id) for channel_id in network.channelIdArray)
    except (AttributeError, KeyError, TypeError, ValueError):
        return {}, False

    if len(channel_ids) != len(requested_channels):
        return {}, False
    return dict(zip(requested_channels, channel_ids, strict=True)), True


def _aardwolf_probe_channel_types(
    channel_base: type,
    channel_options_type: type,
) -> tuple[type, ...]:
    def probe_channel_type(channel_name: str) -> type:
        class ProbeChannel(channel_base):
            def __init__(self, _settings):
                channel_base.__init__(
                    self,
                    channel_name,
                    channel_options_type(DEFAULT_CHANNEL_OPTIONS),
                )

            async def process_channel_data(self, _data):
                return None

            async def process_user_data(self, _data):
                return None

        ProbeChannel.name = channel_name
        return ProbeChannel

    return tuple(
        probe_channel_type(channel_name)
        for channel_name in CAPABILITY_CHANNELS.values()
    )


def _aardwolf_peer_certificate_sha256(connection) -> str:
    transport = getattr(connection, "_RDPConnection__connection", None)
    if transport is None:
        raise RuntimeError("aardwolf TLS transport is unavailable")
    fingerprint = _certificate_sha256(transport.get_peer_certificate())
    if fingerprint is None:
        raise RuntimeError("RDP server did not provide a TLS certificate")
    return fingerprint


def _verify_aardwolf_peer_certificate(
    connection,
    expected_certificate_sha256: str,
) -> str:
    actual_fingerprint = _aardwolf_peer_certificate_sha256(connection)
    if not hmac.compare_digest(actual_fingerprint, expected_certificate_sha256):
        raise RuntimeError(
            "RDP TLS certificate changed between validation and authentication"
        )
    return actual_fingerprint


async def _connect_aardwolf_session(
    host: str,
    port: int,
    domain: str | None,
    username: str,
    password: str,
    timeout_seconds: float,
    expected_certificate_sha256: str,
    tls_verification: str,
    request_capability_channels: bool,
) -> AuthenticatedSessionResult:
    from aardwolf.channels import Channel
    from aardwolf.commons.iosettings import RDPIOSettings
    from aardwolf.commons.target import RDPTarget
    from aardwolf.connection import RDPConnection
    from aardwolf.protocol.T128.serverdemandactivepdu import TS_DEMAND_ACTIVE_PDU
    from aardwolf.protocol.T124.userdata.constants import ChannelOption, TS_UD_TYPE
    from aardwolf.protocol.x224.constants import SUPP_PROTOCOLS
    from asyauth.common.constants import asyauthProtocol, asyauthSecret
    from asyauth.common.credentials import UniCredential

    settings = RDPIOSettings()
    requested_channels = (
        tuple(CAPABILITY_CHANNELS.values())
        if request_capability_channels
        else ()
    )
    settings.channels = list(
        _aardwolf_probe_channel_types(Channel, ChannelOption)
        if requested_channels
        else ()
    )
    settings.clipboard_use_pyperclip = False
    settings.supported_protocols = SUPP_PROTOCOLS.HYBRID | SUPP_PROTOCOLS.HYBRID_EX

    credentials = UniCredential(
        secret=password,
        username=username,
        domain=domain,
        stype=asyauthSecret.PASSWORD,
        protocol=asyauthProtocol.NTLM,
    )
    target = RDPTarget(
        ip=host,
        port=port,
        hostname=host,
        timeout=max(1, math.ceil(timeout_seconds)),
        domain=domain,
        unsafe_ssl=False,
    )
    connection = RDPConnection(target, credentials, settings)
    connect_error: object | None = None
    connected = False
    original_credssp_auth = connection.credssp_auth

    async def certificate_guarded_credssp_auth():
        try:
            _verify_aardwolf_peer_certificate(
                connection,
                expected_certificate_sha256,
            )
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            return None, exc
        return await original_credssp_auth()

    connection.credssp_auth = certificate_guarded_credssp_auth
    with _capture_aardwolf_demand_active(TS_DEMAND_ACTIVE_PDU) as capture:
        try:
            try:
                connected, connect_error = await asyncio.wait_for(
                    connection.connect(),
                    timeout=timeout_seconds,
                )
            except TimeoutError:
                connect_error = TimeoutError(
                    f"RDP authentication timed out after {timeout_seconds:g} seconds"
                )
        finally:
            connection.credssp_auth = original_credssp_auth
            try:
                await asyncio.wait_for(
                    connection.terminate(),
                    timeout=min(5.0, max(1.0, timeout_seconds)),
                )
            except (Exception, asyncio.CancelledError):
                pass

    selected_protocol = (
        int(connection.x224_protocol)
        if connection.x224_protocol is not None
        else None
    )
    server_core = _extract_aardwolf_server_core(
        connection,
        TS_UD_TYPE.SC_CORE,
    )
    channel_ids, channel_data_observed = _extract_aardwolf_channel_ids(
        connection,
        TS_UD_TYPE.SC_NET,
        requested_channels,
    )
    if not connected or connect_error is not None:
        return AuthenticatedSessionResult(
            status="failed",
            selected_protocol=selected_protocol,
            server_core=server_core,
            channel_ids=channel_ids,
            channel_data_observed=channel_data_observed,
            demand_active_observed=bool(capture.get("observed")),
            capability_types=capture.get("capability_types", frozenset()),
            bitmap_codec_guids=capture.get("bitmap_codec_guids", frozenset()),
            capability_error=capture.get("capability_error"),
            tls_verification=tls_verification,
            certificate_sha256=expected_certificate_sha256,
            error=_sanitize_auth_error(
                connect_error or "RDP authentication or session setup failed",
                password,
                username,
                domain,
            ),
        )

    return AuthenticatedSessionResult(
        status="authenticated",
        selected_protocol=selected_protocol,
        session_established=True,
        server_core=server_core,
        channel_ids=channel_ids,
        channel_data_observed=channel_data_observed,
        demand_active_observed=bool(capture.get("observed")),
        capability_types=capture.get("capability_types", frozenset()),
        bitmap_codec_guids=capture.get("bitmap_codec_guids", frozenset()),
        capability_error=capture.get("capability_error"),
        tls_verification=tls_verification,
        certificate_sha256=expected_certificate_sha256,
    )


def _run_aardwolf_authenticated_session(
    host: str,
    port: int,
    login: str,
    password: str,
    timeout_seconds: float,
    expected_certificate_sha256: str,
    tls_verification: str,
    request_capability_channels: bool,
) -> AuthenticatedSessionResult:
    try:
        domain, username = _split_ntlm_login(login)
        if "\x00" in password:
            raise ValueError("password must not contain NUL characters")
        if len(password) > 4096:
            raise ValueError("password is too long")
        if tls_verification not in {"verified", "insecure"}:
            raise ValueError("invalid RDP TLS verification state")
        if len(expected_certificate_sha256) != 64:
            raise ValueError("invalid RDP TLS certificate fingerprint")
        try:
            int(expected_certificate_sha256, 16)
        except ValueError as exc:
            raise ValueError("invalid RDP TLS certificate fingerprint") from exc

        for package, expected_version in (
            ("aardwolf", AARDWOLF_VERSION),
            ("asyauth", ASYAUTH_VERSION),
        ):
            installed_version = importlib.metadata.version(package)
            if installed_version != expected_version:
                raise RuntimeError(
                    f"unsupported {package} version {installed_version}; "
                    f"expected {expected_version}"
                )

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError("AUTH cannot run inside an existing asyncio event loop")

        with _AARDWOLF_SESSION_LOCK:
            aardwolf_logger = logging.getLogger("aardwolf")
            logger_was_disabled = aardwolf_logger.disabled
            aardwolf_logger.disabled = True
            try:
                return asyncio.run(
                    _connect_aardwolf_session(
                        host,
                        port,
                        domain,
                        username,
                        password,
                        timeout_seconds,
                        expected_certificate_sha256,
                        tls_verification,
                        request_capability_channels,
                    )
                )
            finally:
                aardwolf_logger.disabled = logger_was_disabled
    except (ImportError, importlib.metadata.PackageNotFoundError) as exc:
        return AuthenticatedSessionResult(
            status="error",
            error=f"RDP authentication dependency is unavailable: {exc}",
        )
    except (RuntimeError, ValueError) as exc:
        return AuthenticatedSessionResult(
            status="error",
            error=_sanitize_auth_error(exc, password, login),
        )
    except Exception as exc:
        return AuthenticatedSessionResult(
            status="error",
            error=_sanitize_auth_error(exc, password, login),
        )


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
        return f"{cipher[0]} ({cipher[2]} bits)"
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


def _available_weak_tls_cipher_names() -> tuple[str, ...]:
    context = _create_tls_context(
        getattr(ssl.TLSVersion, "TLSv1_2", None),
    )
    weak_names: set[str] = set()
    for cipher in context.get_ciphers():
        name = str(cipher.get("name", ""))
        protocol = str(cipher.get("protocol", ""))
        description = str(cipher.get("description", ""))
        upper_name = name.upper()
        upper_description = description.upper()

        if not name or protocol == "TLSv1.3":
            continue
        if any(
            marker in upper_description
            for marker in ("AU=PSK", "KX=PSK", "PSK", "KX=SRP", "AU=SRP")
        ):
            continue

        strength_bits = cipher.get("strength_bits")
        weak = isinstance(strength_bits, int) and strength_bits < 128
        weak = weak or "AU=NONE" in upper_description
        weak = weak or "MAC=SHA1" in upper_description
        weak = weak or any(
            token in upper_name
            for token in (
                "RC4",
                "RC2",
                "3DES",
                "DES",
                "NULL",
                "EXPORT",
                "MD5",
                "IDEA",
                "SEED",
                "ADH",
                "AECDH",
            )
        )
        if weak:
            weak_names.add(name)

    return tuple(sorted(weak_names))


def _cipher_name(formatted_cipher: str | None) -> str | None:
    if not formatted_cipher:
        return None
    return formatted_cipher.split(" (", 1)[0]


def _cipher_scan_error_is_transport_failure(error: str) -> bool:
    normalized = error.lower()
    return any(
        marker in normalized
        for marker in (
            "timed out",
            "connection refused",
            "network is unreachable",
            "no route to host",
            "temporary failure",
        )
    )


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


def _build_client_core_data(
    server_selected_protocol: int = PROTOCOL_RDP,
) -> bytes:
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
    payload += struct.pack(
        "<HHIHHH64sBBI",
        0xCA01,
        1,
        0,
        24,
        0x0007,
        0x0001,
        b"\x00" * 64,
        0,
        0,
        server_selected_protocol,
    )
    return struct.pack("<HH", 0xC001, len(payload) + 4) + payload


def _build_client_security_data(encryption_methods: int) -> bytes:
    return struct.pack("<HHII", 0xC002, 12, encryption_methods, 0)


def _build_client_network_data(channel_names: tuple[str, ...]) -> bytes:
    channel_data = bytearray()
    for channel_name in channel_names:
        encoded_name = channel_name.encode("ascii")
        if not encoded_name or len(encoded_name) > 7:
            raise ValueError(f"invalid static virtual channel name: {channel_name!r}")
        channel_data.extend(encoded_name.ljust(8, b"\x00"))
        channel_data.extend(struct.pack("<I", DEFAULT_CHANNEL_OPTIONS))

    payload = struct.pack("<I", len(channel_names)) + bytes(channel_data)
    return struct.pack("<HH", CS_NET, len(payload) + 4) + payload


def _build_client_message_channel_data() -> bytes:
    return struct.pack("<HHI", CS_MCS_MSGCHANNEL, 8, 0)


def _build_client_multitransport_data(flags: int) -> bytes:
    return struct.pack("<HHI", CS_MULTITRANSPORT, 8, flags)


def _build_mcs_connect_initial(
    encryption_methods: int,
    channel_names: tuple[str, ...] = (),
    multitransport_flags: int | None = None,
    server_selected_protocol: int = PROTOCOL_RDP,
) -> bytes:
    client_blocks = _build_client_core_data(
        server_selected_protocol
    ) + _build_client_security_data(encryption_methods)
    if channel_names:
        client_blocks += _build_client_network_data(channel_names)
    if multitransport_flags is not None:
        client_blocks += _build_client_message_channel_data()
        client_blocks += _build_client_multitransport_data(multitransport_flags)
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


def _parse_server_user_data_blocks(packet: bytes) -> dict[int, bytes]:
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

    parsed_blocks: dict[int, bytes] = {}
    offset = 0
    while offset < len(blocks):
        if offset + 4 > len(blocks):
            raise RDPProtocolError("truncated server data block header")
        block_type, block_length = struct.unpack("<HH", blocks[offset : offset + 4])
        if block_length < 4 or offset + block_length > len(blocks):
            raise RDPProtocolError("invalid server data block length")
        block = blocks[offset : offset + block_length]
        if block_type in parsed_blocks:
            raise RDPProtocolError(
                f"duplicate server data block type 0x{block_type:04x}"
            )
        parsed_blocks[block_type] = block
        offset += block_length

    return parsed_blocks


def _parse_server_core_data(packet: bytes) -> ServerCoreData:
    block = _parse_server_user_data_blocks(packet).get(SC_CORE)
    if block is None:
        raise RDPProtocolError("MCS response has no Server Core Data block")
    if len(block) not in (8, 12, 16):
        raise RDPProtocolError("invalid Server Core Data block length")

    version = struct.unpack("<I", block[4:8])[0]
    client_requested_protocols = (
        struct.unpack("<I", block[8:12])[0] if len(block) >= 12 else None
    )
    early_capability_flags = (
        struct.unpack("<I", block[12:16])[0] if len(block) >= 16 else None
    )
    return ServerCoreData(
        version=version,
        client_requested_protocols=client_requested_protocols,
        early_capability_flags=early_capability_flags,
    )


def _parse_server_network_data(
    packet: bytes,
    requested_channels: tuple[str, ...],
) -> dict[str, int]:
    block = _parse_server_user_data_blocks(packet).get(SC_NET)
    if block is None:
        if requested_channels:
            raise RDPProtocolError("MCS response has no Server Network Data block")
        return {}
    if len(block) < 8:
        raise RDPProtocolError("truncated Server Network Data block")

    channel_count = struct.unpack("<H", block[6:8])[0]
    expected_length = 8 + channel_count * 2 + (2 if channel_count % 2 else 0)
    if len(block) != expected_length:
        raise RDPProtocolError("invalid Server Network Data block length")
    if channel_count != len(requested_channels):
        raise RDPProtocolError(
            "server channel count does not match requested channel count"
        )

    channel_ids = struct.unpack(
        f"<{channel_count}H",
        block[8 : 8 + channel_count * 2],
    ) if channel_count else ()
    return dict(zip(requested_channels, channel_ids, strict=True))


def _parse_server_multitransport_data(packet: bytes) -> int | None:
    block = _parse_server_user_data_blocks(packet).get(SC_MULTITRANSPORT)
    if block is None:
        return None
    if len(block) != 8:
        raise RDPProtocolError("invalid Server Multitransport Data block length")
    return struct.unpack("<I", block[4:8])[0]


def _parse_server_security_data(packet: bytes) -> LegacyServerSecurityData:
    parsed_blocks = _parse_server_user_data_blocks(packet)
    security_block = parsed_blocks.get(SC_SECURITY)
    if security_block is None:
        raise RDPProtocolError("MCS response has no Server Security Data block")
    if len(security_block) < 12:
        raise RDPProtocolError("truncated Server Security Data block")

    encryption_method, encryption_level = struct.unpack(
        "<II", security_block[4:12]
    )
    core_block = parsed_blocks.get(SC_CORE)
    server_rdp_version = (
        struct.unpack("<I", core_block[4:8])[0]
        if core_block is not None and len(core_block) >= 8
        else None
    )

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
    insecure_auth: bool
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
                ["", "", "CAPABIL", "RDP capability negotiation"],
                ["", "", "VERSION", "RDP protocol version reported by the server"],
                ["", "", "SSL", "TLS/RDP Security configuration test"],
                ["", "", "NTLMINFO", "Pre-auth CredSSP/NTLM server information test"],
                ["", "", "INFO", "Alias for NTLMINFO"],
                ["", "", "AUTH", "Single CredSSP/NTLM authentication test"],
                ["-l", "--login", "<login>", "Login for account-based tests"],
                ["-p", "--password", "<password>", "Password for account-based tests"],
                ["", "--insecure-auth", "", "Allow credentials with an untrusted RDP TLS certificate"],
                ["-T", "--timeout", "<milliseconds>", "Network timeout (default 10000)"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
                ["-vv", "--verbose", "", "Enable verbose mode"],
            ]},
            {"note": [
                "When -ts/--tests is omitted, all safe pre-auth tests are executed; "
                "AUTH is also executed when both credentials are supplied.",
                "AUTH performs one CredSSP/NTLM authentication attempt.",
                "Use --insecure-auth only for an explicitly trusted test target "
                "whose RDP certificate cannot be validated.",
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
            help=(
                "tests to run: NLA, RDPSEC, CREDSSP, RDPENC, CAPABIL, "
                "VERSION, SSL, NTLMINFO, INFO, AUTH"
            ),
        )
        parser.add_argument("-l", "--login", help="login for account-based tests")
        parser.add_argument("-p", "--password", help="password for account-based tests")
        parser.add_argument(
            "--insecure-auth",
            action="store_true",
            help="allow credential use when the RDP TLS certificate is untrusted",
        )
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
        self.args.insecure_auth = bool(getattr(args, "insecure_auth", False))
        self.ptjsonlib = ptjsonlib
        self.use_json = getattr(args, "json", False)
        self.results = RDPResults()
        self.timeout_seconds = args.timeout / 1000.0
        self._security_probes: list[NegotiationProbe] | None = None
        self._basic_settings_result: BasicSettingsResult | None = None
        self._auth_tls_validation_result: AuthTLSValidationResult | None = None
        self._authenticated_session_result: AuthenticatedSessionResult | None = None

    def run(self) -> None:
        if self.args.tests is not None:
            selected_tests = self.args.tests
        else:
            selected_tests = [
                test
                for test in RDP_TEST_ORDER
                if test in IMPLEMENTED_TESTS and test != "AUTH"
            ]
            if self.args.login is not None and self.args.password is not None:
                selected_tests.append("AUTH")
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
            elif test == "CAPABIL":
                self.results.capabilities = self._run_capability_test()
            elif test == "VERSION":
                self.results.version = self._run_version_test()
            elif test == "NTLMINFO":
                self.results.ntlm_info = self._run_ntlminfo_test()
            elif test == "SSL":
                self.results.ssl = self._run_ssl_test()
            elif test == "AUTH":
                self.results.auth = self._run_auth_test()
            else:
                self.results.not_implemented.append(test)

    def _get_auth_tls_validation_result(self) -> AuthTLSValidationResult:
        if self._auth_tls_validation_result is not None:
            return self._auth_tls_validation_result

        _probe, _tls_version, _cipher, cert_der, error = self._tls_handshake(
            PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX,
            verify_certificate=not self.args.insecure_auth,
        )
        fingerprint = _certificate_sha256(cert_der)
        if error is not None or fingerprint is None:
            detail = error or "RDP server did not provide a TLS certificate"
            if not self.args.insecure_auth:
                detail = (
                    f"RDP TLS certificate validation failed: {detail}. "
                    "Use --insecure-auth only for an explicitly trusted test target"
                )
            self._auth_tls_validation_result = AuthTLSValidationResult(
                status="error",
                error=detail,
            )
            return self._auth_tls_validation_result

        self._auth_tls_validation_result = AuthTLSValidationResult(
            status="insecure" if self.args.insecure_auth else "verified",
            certificate_sha256=fingerprint,
        )
        return self._auth_tls_validation_result

    def _get_authenticated_session_result(self) -> AuthenticatedSessionResult:
        if self._authenticated_session_result is not None:
            return self._authenticated_session_result

        if self.args.login is None or self.args.password is None:
            self._authenticated_session_result = AuthenticatedSessionResult(
                status="missing_credentials",
                error="both --login and --password are required",
            )
            return self._authenticated_session_result

        tls_validation = self._get_auth_tls_validation_result()
        if (
            tls_validation.status == "error"
            or tls_validation.certificate_sha256 is None
        ):
            self._authenticated_session_result = AuthenticatedSessionResult(
                status="tls_error",
                error=tls_validation.error,
            )
            return self._authenticated_session_result

        self._authenticated_session_result = _run_aardwolf_authenticated_session(
            self.args.target.ip,
            self.args.target.port,
            self.args.login,
            self.args.password,
            self.timeout_seconds,
            tls_validation.certificate_sha256,
            tls_validation.status,
            self.args.tests is None or "CAPABIL" in self.args.tests,
        )
        return self._authenticated_session_result

    def _run_auth_test(self) -> RDPAuthResult:
        if self.args.login is None or self.args.password is None:
            return RDPAuthResult(
                status="missing_credentials",
                error="both --login and --password are required",
            )

        credssp_probe = next(
            (
                probe
                for probe in self._get_security_probes()
                if probe.name == "CredSSP/NLA only"
            ),
            None,
        )
        if credssp_probe is None:
            return RDPAuthResult(
                status="error",
                error="CredSSP negotiation probe was not executed",
            )
        if credssp_probe.selected_protocol not in (
            PROTOCOL_HYBRID,
            PROTOCOL_HYBRID_EX,
        ):
            if credssp_probe.error:
                return RDPAuthResult(status="error", error=credssp_probe.error)
            reason = (
                FAILURE_CODES.get(
                    credssp_probe.failure_code,
                    f"failure code {credssp_probe.failure_code}",
                )
                if credssp_probe.failure_code is not None
                else f"server selected {protocol_name(credssp_probe.selected_protocol)}"
            )
            return RDPAuthResult(
                status="not_supported",
                selected_protocol=credssp_probe.selected_protocol,
                error=f"CredSSP/NLA authentication is not available ({reason})",
            )

        session = self._get_authenticated_session_result()
        if (
            session.status == "authenticated"
            and session.selected_protocol
            not in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX)
        ):
            return RDPAuthResult(
                status="error",
                selected_protocol=session.selected_protocol,
                session_established=session.session_established,
                error="server established a session without selecting CredSSP",
            )

        return RDPAuthResult(
            status=session.status,
            selected_protocol=session.selected_protocol,
            session_established=session.session_established,
            tls_verification=session.tls_verification,
            certificate_sha256=session.certificate_sha256,
            error=session.error,
        )

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

    def _get_basic_settings_result(self) -> BasicSettingsResult:
        if self._basic_settings_result is None:
            self._basic_settings_result = self._probe_basic_settings()
        return self._basic_settings_result

    def _probe_basic_settings(self) -> BasicSettingsResult:
        requested_channels = tuple(CAPABILITY_CHANNELS.values())
        failures: list[str] = []
        transport_errors: list[str] = []

        for requested_protocol in (PROTOCOL_SSL, PROTOCOL_RDP):
            sock: socket.socket | ssl.SSLSocket | None = None
            try:
                sock = socket.create_connection(
                    (self.args.target.ip, self.args.target.port),
                    timeout=self.timeout_seconds,
                )
                sock.settimeout(self.timeout_seconds)
                sock.sendall(_build_negotiation_request(requested_protocol))
                negotiation = _parse_negotiation_reply_details(_read_tpkt(sock))

                if negotiation.selected_protocol != requested_protocol:
                    if negotiation.failure_code is not None:
                        reason = FAILURE_CODES.get(
                            negotiation.failure_code,
                            f"failure code {negotiation.failure_code}",
                        )
                    else:
                        reason = (
                            f"server selected {protocol_name(negotiation.selected_protocol)}"
                        )
                    failures.append(
                        f"{protocol_name(requested_protocol)}: {reason}"
                    )
                    continue

                encryption_methods = LEGACY_ENCRYPTION_METHOD_MASK
                if requested_protocol == PROTOCOL_SSL:
                    server_hostname = (
                        None
                        if _target_is_ip(self.args.target.ip)
                        else self.args.target.ip
                    )
                    sock = _create_tls_context().wrap_socket(
                        sock,
                        server_hostname=server_hostname,
                    )

                response_flags = negotiation.response_flags or 0
                multitransport_flags = (
                    CLIENT_MULTITRANSPORT_FLAGS
                    if response_flags & NEG_RSP_EXTENDED_CLIENT_DATA_SUPPORTED
                    else None
                )
                sock.sendall(
                    _build_mcs_connect_initial(
                        encryption_methods,
                        requested_channels,
                        multitransport_flags,
                        requested_protocol,
                    )
                )
                response = _read_tpkt(sock)

                return BasicSettingsResult(
                    status="ok",
                    selected_protocol=requested_protocol,
                    response_flags=response_flags,
                    server_core=_parse_server_core_data(response),
                    channel_ids=_parse_server_network_data(
                        response,
                        requested_channels,
                    ),
                    multitransport_flags=_parse_server_multitransport_data(
                        response
                    ),
                )
            except (OSError, ssl.SSLError, RDPProtocolError, ValueError) as exc:
                transport_errors.append(
                    f"{protocol_name(requested_protocol)}: {exc}"
                )
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

        details = failures + transport_errors
        detail = "; ".join(details) or "Basic Settings Exchange failed"
        if any("NLA required" in failure for failure in failures):
            return BasicSettingsResult(
                status="unavailable",
                error=f"NLA prevents pre-auth Basic Settings Exchange ({detail})",
            )

        if transport_errors:
            return BasicSettingsResult(status="error", error=detail)

        if failures:
            return BasicSettingsResult(status="unavailable", error=detail)

        return BasicSettingsResult(
            status="error",
            error=detail,
        )

    def _run_version_test(self) -> RDPVersionResult:
        basic_settings = self._get_basic_settings_result()
        if basic_settings.status == "ok" and basic_settings.server_core is not None:
            return self._version_result_from_core(
                basic_settings.server_core,
                protocol_name(basic_settings.selected_protocol),
                "pre_auth",
            )

        if basic_settings.status == "ok":
            return RDPVersionResult(
                status="error",
                source="pre_auth",
                error="Server Core Data was not present in the RDP response",
            )

        if (
            basic_settings.status == "unavailable"
            and self.args.login is not None
            and self.args.password is not None
        ):
            authenticated_session = self._get_authenticated_session_result()
            if (
                authenticated_session.status == "authenticated"
                and authenticated_session.server_core is not None
            ):
                return self._version_result_from_core(
                    authenticated_session.server_core,
                    protocol_name(authenticated_session.selected_protocol),
                    "authenticated",
                )

            auth_error = authenticated_session.error or (
                "authenticated RDP session did not expose Server Core Data"
            )
            pre_auth_error = (
                basic_settings.error or "pre-auth Basic Settings Exchange unavailable"
            )
            return RDPVersionResult(
                status="unavailable",
                source="authenticated",
                error=f"{pre_auth_error}; authenticated fallback failed: {auth_error}",
            )

        return RDPVersionResult(
            status=basic_settings.status,
            source="pre_auth",
            error=basic_settings.error,
        )

    @staticmethod
    def _version_result_from_core(
        server_core: ServerCoreData,
        transport: str,
        source: str,
    ) -> RDPVersionResult:
        advertised_version = server_core.version
        version_name = SERVER_RDP_VERSION_NAMES.get(
            advertised_version,
            f"Unknown (0x{advertised_version:08x})",
        )
        return RDPVersionResult(
            status=(
                "ambiguous"
                if advertised_version == 0x00080004
                else "ok"
                if advertised_version in SERVER_RDP_VERSION_NAMES
                else "unknown"
            ),
            advertised_version=advertised_version,
            version_name=version_name,
            transport=transport,
            source=source,
        )

    def _run_capability_test(self) -> CapabilityResult:
        basic_settings = self._get_basic_settings_result()
        findings: list[CapabilityFinding] = []
        authenticated_session: AuthenticatedSessionResult | None = None
        if self.args.login is not None and self.args.password is not None:
            authenticated_session = self._get_authenticated_session_result()

        channel_ids = basic_settings.channel_ids
        channel_data_observed = basic_settings.status == "ok"
        channel_data_error = basic_settings.error
        if (
            not channel_data_observed
            and authenticated_session is not None
            and authenticated_session.status == "authenticated"
            and authenticated_session.channel_data_observed
        ):
            channel_ids = authenticated_session.channel_ids
            channel_data_observed = True
            channel_data_error = None

        response_flags = basic_settings.response_flags
        negotiation_observed = basic_settings.status == "ok"
        if not negotiation_observed:
            negotiation_probes = self._get_security_probes()
            valid_probes = [probe for probe in negotiation_probes if probe.successful]
            negotiation_observed = bool(valid_probes)
            for probe in valid_probes:
                response_flags |= probe.response_flags or 0

        graphics_supported = bool(
            response_flags & NEG_RSP_DYNVC_GFX_PROTOCOL_SUPPORTED
        )
        if negotiation_observed:
            findings.append(
                CapabilityFinding(
                    "Graphics Pipeline",
                    "supported" if graphics_supported else "not_supported",
                    "RDP_NEG_RSP DYNVC_GFX_PROTOCOL_SUPPORTED flag "
                    + ("present" if graphics_supported else "absent"),
                )
            )
        else:
            findings.append(
                CapabilityFinding(
                    "Graphics Pipeline",
                    "unknown",
                    "no valid RDP negotiation response",
                )
            )

        findings.append(
            CapabilityFinding(
                "Bitmap compression",
                "supported" if negotiation_observed else "unknown",
                (
                    "required by the RDP Bitmap Capability Set"
                    if negotiation_observed
                    else "no valid RDP negotiation response"
                ),
            )
        )

        for capability_name, channel_name in CAPABILITY_CHANNELS.items():
            channel_id = channel_ids.get(channel_name)
            if capability_name == "Dynamic Virtual Channels" and graphics_supported:
                findings.append(
                    CapabilityFinding(
                        capability_name,
                        "supported",
                        "Graphics Pipeline support proves availability of the "
                        "dynamic virtual channel transport",
                    )
                )
            elif channel_id:
                findings.append(
                    CapabilityFinding(
                        capability_name,
                        (
                            "supported"
                            if capability_name == "Dynamic Virtual Channels"
                            else "allocated"
                        ),
                        f"static virtual channel {channel_name} allocated as {channel_id}; "
                        "server policy was not exercised",
                    )
                )
            elif channel_data_observed:
                findings.append(
                    CapabilityFinding(
                        capability_name,
                        "not_supported",
                        f"static virtual channel {channel_name} was not allocated",
                    )
                )
            else:
                findings.append(
                    CapabilityFinding(
                        capability_name,
                        "unknown",
                        channel_data_error
                        or "Basic Settings Exchange did not return valid "
                        "Server Network Data",
                    )
                )

        udp_flags = basic_settings.multitransport_flags
        udp_supported = bool(
            udp_flags is not None
            and udp_flags & (TRANSPORTTYPE_UDPFECR | TRANSPORTTYPE_UDPFECL)
        )
        if basic_settings.status == "ok":
            findings.append(
                CapabilityFinding(
                    "UDP transport",
                    "supported" if udp_supported else "not_supported",
                    (
                        f"Server Multitransport flags: 0x{udp_flags:08x}"
                        if udp_flags is not None
                        else "Server Multitransport Data was not returned"
                    ),
                )
            )
        else:
            udp_error = (
                "requires authenticated multitransport negotiation"
                if authenticated_session is not None
                and authenticated_session.status == "authenticated"
                else basic_settings.error
                or "Basic Settings Exchange was not available"
            )
            findings.append(
                CapabilityFinding(
                    "UDP transport",
                    "unknown",
                    udp_error,
                )
            )

        if (
            authenticated_session is not None
            and authenticated_session.status == "authenticated"
            and authenticated_session.demand_active_observed
        ):
            if authenticated_session.capability_error is not None:
                findings.append(
                    CapabilityFinding(
                        "RemoteFX",
                        "unknown",
                        "Demand Active was received but bitmap codecs could not be "
                        f"decoded ({authenticated_session.capability_error})",
                    )
                )
            else:
                remotefx_supported = (
                    REMOTEFX_CODEC_GUID
                    in authenticated_session.bitmap_codec_guids
                )
                findings.append(
                    CapabilityFinding(
                        "RemoteFX",
                        "supported" if remotefx_supported else "not_supported",
                        "RemoteFX bitmap codec GUID was "
                        + (
                            "advertised in the server Demand Active PDU"
                            if remotefx_supported
                            else "not advertised in the server Demand Active PDU"
                        ),
                    )
                )
        else:
            findings.append(
                CapabilityFinding(
                    "RemoteFX",
                    "unknown",
                    (
                        authenticated_session.error
                        if authenticated_session is not None
                        and authenticated_session.error is not None
                        else "requires authenticated capability exchange"
                    ),
                )
            )

        findings.extend(
            (
                CapabilityFinding(
                    "AVC444",
                    "unknown",
                    "requires RDP Graphics capability exchange",
                ),
                CapabilityFinding(
                    "Multi-monitor",
                    "unknown",
                    "requires monitor-layout negotiation",
                ),
            )
        )

        status = "partial" if any(
            finding.status == "unknown" for finding in findings
        ) else "ok"
        findings.sort(key=lambda finding: CAPABILITY_OUTPUT_ORDER.index(finding.name))
        return CapabilityResult(
            status=status,
            findings=findings,
            error=basic_settings.error if basic_settings.status == "error" else None,
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
        result.weak_cipher_scan = self._probe_weak_tls_ciphers(
            working_protocols,
            result.version_probes,
        )
        result.weak_findings = self._tls_weak_findings(result)
        if result.weak_findings:
            result.status = "weak"
        return result

    def _tls_handshake(
        self,
        requested_protocols: int,
        tls_version: ssl.TLSVersion | None = None,
        *,
        verify_certificate: bool = False,
        cipher_names: tuple[str, ...] = (),
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

            if verify_certificate:
                context = ssl.create_default_context()
                if tls_version is not None:
                    context.minimum_version = tls_version
                    context.maximum_version = tls_version
                server_hostname = self.args.target.ip
            else:
                server_hostname = (
                    None
                    if _target_is_ip(self.args.target.ip)
                    else self.args.target.ip
                )
                context = _create_tls_context(tls_version)
            if cipher_names:
                context.set_ciphers(":".join(cipher_names) + ":@SECLEVEL=0")
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
        except (OSError, ssl.SSLError, RDPProtocolError, ValueError) as exc:
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

    def _probe_weak_tls_ciphers(
        self,
        requested_protocols: int,
        version_probes: list[TLSVersionProbe],
    ) -> WeakCipherScanResult:
        candidates = list(_available_weak_tls_cipher_names())
        if not candidates:
            return WeakCipherScanResult(
                status="unavailable",
                error="local OpenSSL cannot offer any classified weak cipher suites",
            )

        tls12_probe = next(
            (probe for probe in version_probes if probe.version == "TLSv1.2"),
            None,
        )
        if tls12_probe is None or not tls12_probe.supported:
            return WeakCipherScanResult(
                status="not_applicable",
                tested_count=len(candidates),
                error="TLSv1.2 is not supported",
            )

        accepted: list[str] = []
        remaining = candidates.copy()
        while remaining:
            if len(accepted) >= MAX_ACCEPTED_WEAK_CIPHERS:
                return WeakCipherScanResult(
                    status="truncated",
                    tested_count=len(candidates),
                    accepted_ciphers=tuple(accepted),
                    error=(
                        f"stopped after {MAX_ACCEPTED_WEAK_CIPHERS} accepted "
                        "weak cipher suites"
                    ),
                )

            _probe, _version, selected_cipher, _cert_der, error = self._tls_handshake(
                requested_protocols,
                ssl.TLSVersion.TLSv1_2,
                cipher_names=tuple(remaining),
            )
            if error is not None:
                return WeakCipherScanResult(
                    status=(
                        "inconclusive"
                        if _cipher_scan_error_is_transport_failure(error)
                        else "complete"
                    ),
                    tested_count=len(candidates),
                    accepted_ciphers=tuple(accepted),
                    error=(
                        error
                        if _cipher_scan_error_is_transport_failure(error)
                        else None
                    ),
                )

            selected_name = _cipher_name(selected_cipher)
            if selected_name not in remaining:
                return WeakCipherScanResult(
                    status="inconclusive",
                    tested_count=len(candidates),
                    accepted_ciphers=tuple(accepted),
                    error=f"server selected unexpected cipher {selected_name or 'unknown'}",
                )

            accepted.append(selected_name)
            remaining.remove(selected_name)

        return WeakCipherScanResult(
            status="complete",
            tested_count=len(candidates),
            accepted_ciphers=tuple(accepted),
        )

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
                sha256_fingerprint=_certificate_sha256(cert_der),
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

        if result.weak_cipher_scan is not None:
            for cipher in result.weak_cipher_scan.accepted_ciphers:
                findings.append(f"weak TLSv1.2 cipher accepted: {cipher}")

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

    def _print_status(self, message: str, out: Out, *, indent: int = 4) -> None:
        """Print an indented status line using the shared ptlibs bullet mapping."""
        marker = ptprinthelper.bullet(out.value)
        self.ptprint(f"{' ' * indent}{marker}{message}", Out.TEXT)

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

        if self.results.capabilities is not None:
            self._output_capabilities_text(self.results.capabilities)
            properties["capabilities"] = self._capabilities_json(
                self.results.capabilities
            )

        if self.results.version is not None:
            self._output_version_text(self.results.version)
            properties["rdpVersion"] = self._version_json(self.results.version)
            if self.results.version.version_name is not None:
                properties["version"] = self.results.version.version_name

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

        if self.results.auth is not None:
            self._output_auth_text(self.results.auth)
            properties["authentication"] = self._auth_json(self.results.auth)

        if self.results.not_implemented:
            properties["notImplementedTests"] = self.results.not_implemented
            if not self.use_json:
                for test in self.results.not_implemented:
                    self.ptprint(f"{test} test", Out.INFO)
                    self._print_status("Test is not implemented yet", Out.WARNING)

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
            self._print_status("NLA required", Out.NOTVULN)
        elif result.status == "allowed_not_required":
            self._print_status("NLA is allowed but not required", Out.WARNING)
        elif result.status == "not_supported":
            self._print_status("NLA is not supported", Out.VULN)
        elif result.status == "error":
            self._print_status(str(result.error), Out.ERROR)
        else:
            self._print_status("NLA status is inconclusive", Out.WARNING)

        for probe in result.probes:
            self.ptdebug(probe.summary())
            if probe.note:
                self.ptdebug(f"{probe.name}: {probe.note}")

    def _output_rdp_security_text(self, result: RDPSecurityResult) -> None:
        if self.use_json:
            return

        self.ptprint("RDP Security test", Out.INFO)
        if result.status == "allowed":
            self._print_status("Legacy Standard RDP Security is allowed", Out.VULN)
        elif result.status == "not_allowed":
            self._print_status(
                "Legacy Standard RDP Security is not allowed",
                Out.NOTVULN,
            )
        elif result.status == "error":
            self._print_status(str(result.probe.error), Out.ERROR)
        else:
            self._print_status("RDP Security status is inconclusive", Out.WARNING)
        self.ptdebug(result.probe.summary())

    def _output_credssp_text(self, result: CredSSPResult) -> None:
        if self.use_json:
            return

        self.ptprint("CredSSP test", Out.INFO)
        if result.status == "supported":
            self._print_status("CredSSP is supported", Out.NOTVULN)
            if result.hybrid_ex_supported:
                self._print_status("CredSSP HYBRID_EX is supported", Out.NOTVULN)
        elif result.status == "not_supported":
            self._print_status("CredSSP is not supported", Out.VULN)
        elif result.status == "error":
            probe = next(p for p in result.probes if p.name == "CredSSP/NLA only")
            self._print_status(str(probe.error), Out.ERROR)
        else:
            self._print_status("CredSSP status is inconclusive", Out.WARNING)
        for probe in result.probes:
            self.ptdebug(probe.summary())

    def _output_rdp_encryption_text(self, result: RDPEncryptionResult) -> None:
        if self.use_json:
            return

        self.ptprint("RDP security and encryption enumeration", Out.INFO)
        if result.status == "error":
            self._print_status(str(result.error), Out.ERROR)
            return

        self.ptprint("    Security protocols", Out.TEXT)
        for probe in result.protocol_probes:
            supported = probe.selected_protocol == probe.requested_protocols
            if supported:
                insecure = probe.requested_protocols == PROTOCOL_RDP
                status_out = Out.VULN if insecure else Out.NOTVULN
                state = "supported"
            elif probe.failed_by_server:
                status_out = Out.WARNING
                state = "not supported"
            elif probe.error:
                status_out = Out.WARNING
                state = f"unknown ({probe.error})"
            else:
                status_out = Out.WARNING
                state = f"selected {protocol_name(probe.selected_protocol)}"
            self._print_status(
                f"{probe.name}: {state}",
                status_out,
                indent=8,
            )

        if result.response_flags:
            self.ptprint("    Negotiation capabilities", Out.TEXT)
            for flag, name in NEGOTIATION_RESPONSE_FLAGS.items():
                if result.response_flags & flag:
                    self._print_status(name, Out.NOTVULN, indent=8)

        self.ptprint("    Standard RDP encryption", Out.TEXT)
        if result.legacy_status == "not_allowed":
            self._print_status(
                "Standard RDP Security is not accepted",
                Out.NOTVULN,
                indent=8,
            )
        elif not result.legacy_probes:
            self._print_status(
                "Encryption methods could not be enumerated",
                Out.WARNING,
                indent=8,
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
                    status_out = Out.VULN
                    state = "accepted"
                elif legacy_probe.accepted is False:
                    status_out = Out.NOTVULN
                    state = "not accepted"
                else:
                    status_out = Out.WARNING
                    state = f"unknown ({legacy_probe.error})"
                self._print_status(
                    f"{method_name}: {state}",
                    status_out,
                    indent=8,
                )
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

    def _output_capabilities_text(self, result: CapabilityResult) -> None:
        if self.use_json:
            return

        self.ptprint("RDP capabilities", Out.INFO)
        for finding in result.findings:
            if finding.status == "supported":
                status_out = Out.NOTVULN
                state = "supported"
            elif finding.status == "allocated":
                status_out = Out.WARNING
                state = "channel allocated, policy not verified"
            elif finding.status == "not_supported":
                status_out = Out.WARNING
                state = "not supported"
            else:
                status_out = Out.WARNING
                state = (
                    finding.evidence
                    if finding.evidence.startswith("requires")
                    else f"unknown ({finding.evidence})"
                )
            self._print_status(f"{finding.name}: {state}", status_out)
            self.ptdebug(f"{finding.name}: {finding.evidence}")

        if result.error:
            self.ptdebug(f"Capability probe error: {result.error}")

    def _output_version_text(self, result: RDPVersionResult) -> None:
        if self.use_json:
            return

        self.ptprint("RDP protocol version", Out.INFO)
        if result.status == "ok":
            self._print_status(
                f"Server reports: {result.version_name}",
                Out.NOTVULN,
            )
        elif result.status == "ambiguous":
            self._print_status(
                f"Server reports: {result.version_name}",
                Out.WARNING,
            )
            self.ptprint(
                "        Exact version cannot be distinguished by the RDP handshake",
                Out.TEXT,
            )
        elif result.status == "unknown":
            self._print_status(
                f"Unrecognized server version: {result.version_name}",
                Out.WARNING,
            )
        elif result.status == "unavailable":
            self._print_status(
                "Version is not available before authentication: "
                f"{result.error}",
                Out.WARNING,
            )
        else:
            self._print_status(
                f"Version probe failed: {result.error}",
                Out.ERROR,
            )

        if result.transport is not None:
            self.ptdebug(f"Basic Settings Exchange transport: {result.transport}")
        if result.source is not None:
            self.ptdebug(f"Version source: {result.source}")

    def _output_ntlminfo_text(self, result: NTLMInfoResult) -> None:
        if self.use_json:
            return

        self.ptprint("RDP NTLM information", Out.INFO)
        if result.status == "ok" and result.info is not None:
            protocol = result.selected_protocol or "unknown protocol"
            self._print_status(
                f"NTLM challenge exposes server information via {protocol}",
                Out.WARNING,
            )
            for line in self._ntlm_info_output_lines(result.info):
                self.ptprint(f"        {line}", Out.TEXT)
        elif result.status == "empty":
            self._print_status(
                "NTLM challenge was received but no server fields were decoded",
                Out.WARNING,
            )
        elif result.status == "not_supported":
            detail = f": {result.error}" if result.error else ""
            self._print_status(
                f"NTLM information not available{detail}",
                Out.NOTVULN,
            )
        else:
            self._print_status(
                f"NTLM information test failed: {result.error}",
                Out.WARNING,
            )

        if result.negotiation_probe is not None:
            self.ptdebug(result.negotiation_probe.summary())

    def _output_ssl_text(self, result: SSLResult) -> None:
        if self.use_json:
            return

        self.ptprint("TLS / SSL configuration test", Out.INFO)
        if result.status in ("ok", "weak"):
            detail = result.selected_tls_version or "unknown TLS version"
            if result.selected_cipher:
                detail = f"{detail}, {result.selected_cipher}"
            self._print_status(
                f"TLS handshake successful ({detail})",
                Out.WARNING if result.status == "weak" else Out.NOTVULN,
            )
            for finding in result.weak_findings:
                self._print_status(finding, Out.WARNING)
        else:
            self._print_status(
                f"TLS handshake failed: {result.error}",
                Out.ERROR,
            )

        if result.certificate and result.certificate.subject:
            self.ptdebug(f"Certificate subject: {result.certificate.subject}")
            self.ptdebug(f"Certificate issuer: {result.certificate.issuer}")
            self.ptdebug(f"Certificate notAfter: {result.certificate.not_after}")
            self.ptdebug(
                "Certificate SHA-256: "
                f"{result.certificate.sha256_fingerprint or 'unavailable'}"
            )
        if result.weak_cipher_scan is not None:
            scan = result.weak_cipher_scan
            if scan.status == "complete" and not scan.accepted_ciphers:
                self._print_status(
                    "No locally offerable weak TLSv1.2 cipher "
                    f"accepted ({scan.tested_count} tested)",
                    Out.NOTVULN,
                )
            elif scan.status in {"inconclusive", "unavailable", "truncated"}:
                detail = scan.error or "scan did not complete"
                self._print_status(
                    f"Weak TLSv1.2 cipher scan {scan.status}: {detail}",
                    Out.WARNING,
                )
            self.ptdebug(
                f"Weak TLSv1.2 cipher candidates: {scan.tested_count}; "
                f"accepted: {len(scan.accepted_ciphers)}"
            )
        for probe in result.version_probes:
            status = "supported" if probe.supported else f"not supported ({probe.error})"
            self.ptdebug(f"{probe.version}: {status}")

    def _output_auth_text(self, result: RDPAuthResult) -> None:
        if self.use_json:
            return

        self.ptprint("RDP authentication test", Out.INFO)
        if result.status == "authenticated":
            selected_protocol = protocol_name(result.selected_protocol)
            self._print_status(
                "CredSSP/NTLM authentication succeeded "
                f"({selected_protocol})",
                Out.NOTVULN,
            )
        elif result.status == "tls_error":
            self._print_status(
                f"Credentials were not used: {result.error}",
                Out.ERROR,
            )
        elif result.status == "missing_credentials":
            self._print_status(
                "AUTH requires both --login and --password",
                Out.WARNING,
            )
        elif result.status == "not_supported":
            self._print_status(
                "CredSSP/NTLM authentication is not supported",
                Out.WARNING,
            )
            if result.error:
                self.ptdebug(result.error)
        else:
            self._print_status(
                "Authentication or RDP session setup failed",
                Out.WARNING,
            )
            if result.error:
                self.ptdebug(result.error)

        if result.tls_verification == "insecure":
            self._print_status(
                "TLS certificate validation was explicitly disabled",
                Out.WARNING,
            )
        if result.certificate_sha256 is not None:
            self.ptdebug(
                "Authentication TLS certificate SHA-256: "
                f"{result.certificate_sha256}"
            )

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

    def _capabilities_json(self, result: CapabilityResult) -> dict:
        return {
            "status": result.status,
            "error": result.error,
            "findings": [
                {
                    "name": finding.name,
                    "status": finding.status,
                    "evidence": finding.evidence,
                }
                for finding in result.findings
            ],
        }

    def _version_json(self, result: RDPVersionResult) -> dict:
        return {
            "status": result.status,
            "advertisedVersion": result.advertised_version,
            "advertisedVersionHex": (
                f"0x{result.advertised_version:08x}"
                if result.advertised_version is not None
                else None
            ),
            "versionName": result.version_name,
            "transport": result.transport,
            "source": result.source,
            "error": result.error,
            "isSupportedVersionList": False,
        }

    def _auth_json(self, result: RDPAuthResult) -> dict:
        return {
            "status": result.status,
            "selectedProtocol": protocol_name(result.selected_protocol),
            "sessionEstablished": result.session_established,
            "tlsVerification": result.tls_verification,
            "certificateSha256": result.certificate_sha256,
            "error": result.error,
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
            "weakCipherScan": (
                {
                    "status": result.weak_cipher_scan.status,
                    "testedCount": result.weak_cipher_scan.tested_count,
                    "acceptedCiphers": list(
                        result.weak_cipher_scan.accepted_ciphers
                    ),
                    "error": result.weak_cipher_scan.error,
                }
                if result.weak_cipher_scan is not None
                else None
            ),
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
            "sha256Fingerprint": certificate.sha256_fingerprint,
        }
