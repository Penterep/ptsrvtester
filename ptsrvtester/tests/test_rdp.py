import argparse
import datetime as dt
import logging
import struct
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ptsrvtester.modules._base import Out
from ptsrvtester.modules.rdp import (
    AuthTLSValidationResult,
    AuthenticatedSessionResult,
    BasicSettingsResult,
    CapabilityFinding,
    CapabilityResult,
    CredSSPResult,
    ENCRYPTION_METHOD_40BIT,
    ENCRYPTION_METHOD_128BIT,
    ENCRYPTION_METHOD_FIPS,
    ENCRYPTION_LEVEL_NAMES,
    LEGACY_ENCRYPTION_METHOD_MASK,
    LegacyEncryptionProbe,
    NLAResult,
    NTLMInfoResult,
    PROTOCOL_HYBRID,
    PROTOCOL_HYBRID_EX,
    PROTOCOL_RDSTLS,
    PROTOCOL_RDP,
    PROTOCOL_RDSAAD,
    PROTOCOL_SSL,
    NEG_RSP_DYNVC_GFX_PROTOCOL_SUPPORTED,
    NegotiationReply,
    RDP,
    RDPArgs,
    RDPAuthResult,
    RDPProtocolError,
    RDPEncryptionResult,
    RDPVersionResult,
    RDPSecurityResult,
    REMOTEFX_CODEC_GUID,
    ServerCoreData,
    SSLResult,
    TLSVersionProbe,
    TYPE_RDP_NEG_FAILURE,
    TYPE_RDP_NEG_REQ,
    TYPE_RDP_NEG_RSP,
    TRANSPORTTYPE_UDPFECR,
    WeakCipherScanResult,
    NegotiationProbe,
    _aardwolf_probe_channel_types,
    _aardwolf_peer_certificate_sha256,
    _build_client_core_data,
    _build_negotiation_request,
    _build_mcs_connect_initial,
    _ber_wrap,
    _capture_aardwolf_demand_active,
    _certificate_sha256,
    _extract_aardwolf_channel_ids,
    _extract_aardwolf_server_core,
    _format_cipher,
    _parse_negotiation_reply_details,
    _parse_negotiation_reply,
    _parse_bitmap_codec_guids,
    _parse_server_core_data,
    _parse_server_multitransport_data,
    _parse_server_network_data,
    _parse_server_security_data,
    _per_encode_length,
    _sanitize_auth_error,
    _split_ntlm_login,
    _run_aardwolf_authenticated_session,
    _verify_aardwolf_peer_certificate,
)


def connection_confirm(negotiation: bytes = b"") -> bytes:
    x224 = bytes((6 + len(negotiation),)) + b"\xd0\x00\x00\x00\x00\x00"
    payload = x224 + negotiation
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload


def negotiation_response(selected_protocol: int, flags: int = 0) -> bytes:
    return connection_confirm(
        struct.pack("<BBHI", TYPE_RDP_NEG_RSP, flags, 8, selected_protocol)
    )


def negotiation_failure(failure_code: int) -> bytes:
    return connection_confirm(
        struct.pack("<BBHI", TYPE_RDP_NEG_FAILURE, 0, 8, failure_code)
    )


def probe(
    name: str,
    requested: int,
    *,
    selected: int | None = None,
    failure: int | None = None,
    error: str | None = None,
) -> NegotiationProbe:
    return NegotiationProbe(
        name,
        requested,
        selected_protocol=selected,
        failure_code=failure,
        error=error,
    )


def rdp_args(**overrides) -> RDPArgs:
    values = {
        "module": "rdp",
        "target": SimpleNamespace(ip="192.0.2.10", port=0),
        "tests": None,
        "login": None,
        "password": None,
        "insecure_auth": False,
        "timeout": 10000,
        "json": False,
        "debug": False,
    }
    values.update(overrides)
    return RDPArgs(**values)


def certificate_der(subject_key, signing_key) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rdp.example.test")])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(signing_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class NegotiationPacketTests(unittest.TestCase):
    def test_request_contains_valid_tpkt_x224_and_protocol_mask(self):
        requested = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX

        packet = _build_negotiation_request(requested)

        self.assertEqual(packet[:2], b"\x03\x00")
        self.assertEqual(struct.unpack(">H", packet[2:4])[0], len(packet))
        self.assertEqual(packet[5], 0xE0)
        self.assertEqual(packet[11], TYPE_RDP_NEG_REQ)
        self.assertEqual(struct.unpack("<H", packet[13:15])[0], 8)
        self.assertEqual(struct.unpack("<I", packet[15:19])[0], requested)

    def test_parser_returns_selected_protocol(self):
        selected, failure, note = _parse_negotiation_reply(
            negotiation_response(PROTOCOL_HYBRID_EX)
        )

        self.assertEqual(selected, PROTOCOL_HYBRID_EX)
        self.assertIsNone(failure)
        self.assertIsNone(note)

    def test_parser_returns_negotiation_response_flags(self):
        reply = _parse_negotiation_reply_details(
            negotiation_response(PROTOCOL_HYBRID_EX, flags=0x18)
        )

        self.assertEqual(reply.selected_protocol, PROTOCOL_HYBRID_EX)
        self.assertEqual(reply.response_flags, 0x18)

    def test_parser_returns_server_failure(self):
        selected, failure, note = _parse_negotiation_reply(negotiation_failure(5))

        self.assertIsNone(selected)
        self.assertEqual(failure, 5)
        self.assertIsNone(note)

    def test_x224_confirmation_without_negotiation_means_standard_rdp(self):
        selected, failure, note = _parse_negotiation_reply(connection_confirm())

        self.assertEqual(selected, PROTOCOL_RDP)
        self.assertIsNone(failure)
        self.assertIn("without negotiation data", note)

    def test_parser_rejects_tpkt_length_mismatch(self):
        packet = bytearray(negotiation_response(PROTOCOL_SSL))
        packet[3] -= 1

        with self.assertRaises(RDPProtocolError):
            _parse_negotiation_reply(bytes(packet))


class MCSLegacyEncryptionTests(unittest.TestCase):
    @staticmethod
    def server_response(
        encryption_method: int,
        encryption_level: int,
        server_version: int = 0x00080004,
        core_suffix: bytes = b"",
        extra_blocks: bytes = b"",
    ) -> bytes:
        core_payload = struct.pack("<I", server_version) + core_suffix
        blocks = struct.pack("<HH", 0x0C01, len(core_payload) + 4) + core_payload
        blocks += struct.pack(
            "<HHII",
            0x0C02,
            12,
            encryption_method,
            encryption_level,
        )
        blocks += extra_blocks
        gcc = b"\x00McDn" + _per_encode_length(len(blocks)) + blocks
        mcs_value = _ber_wrap(b"\x0a", b"\x00")
        mcs_value += _ber_wrap(b"\x02", b"\x00")
        mcs_value += _ber_wrap(b"\x30", b"")
        mcs_value += _ber_wrap(b"\x04", gcc)
        mcs = _ber_wrap(b"\x7f\x66", mcs_value)
        x224 = b"\x02\xf0\x80" + mcs
        return struct.pack(">BBH", 3, 0, len(x224) + 4) + x224

    def test_client_connect_initial_advertises_requested_method(self):
        packet = _build_mcs_connect_initial(ENCRYPTION_METHOD_FIPS)

        self.assertEqual(struct.unpack(">H", packet[2:4])[0], len(packet))
        self.assertEqual(packet[4:7], b"\x02\xf0\x80")
        security_header = packet.index(b"\x02\xc0\x0c\x00")
        self.assertEqual(
            struct.unpack("<I", packet[security_header + 4 : security_header + 8])[0],
            ENCRYPTION_METHOD_FIPS,
        )

    def test_client_connect_initial_requests_channels_and_multitransport(self):
        packet = _build_mcs_connect_initial(
            LEGACY_ENCRYPTION_METHOD_MASK,
            ("cliprdr", "rdpdr", "rdpsnd", "drdynvc"),
            TRANSPORTTYPE_UDPFECR,
        )

        self.assertIn(
            struct.pack("<HHII", 0xC002, 12, LEGACY_ENCRYPTION_METHOD_MASK, 0),
            packet,
        )
        self.assertIn(b"cliprdr\x00", packet)
        self.assertIn(b"rdpdr\x00\x00\x00", packet)
        self.assertIn(struct.pack("<HH", 0xC006, 8), packet)
        self.assertIn(
            struct.pack("<HHI", 0xC00A, 8, TRANSPORTTYPE_UDPFECR),
            packet,
        )

    def test_client_core_echoes_server_selected_protocol(self):
        block = _build_client_core_data(PROTOCOL_SSL)

        self.assertEqual(struct.unpack("<H", block[2:4])[0], 216)
        self.assertEqual(
            struct.unpack("<I", block[-4:])[0],
            PROTOCOL_SSL,
        )

    def test_server_security_data_is_decoded(self):
        result = _parse_server_security_data(
            self.server_response(ENCRYPTION_METHOD_128BIT, 3)
        )

        self.assertEqual(result.encryption_method, ENCRYPTION_METHOD_128BIT)
        self.assertEqual(result.encryption_level, 3)
        self.assertEqual(ENCRYPTION_LEVEL_NAMES[result.encryption_level], "High")
        self.assertEqual(result.server_rdp_version, 0x00080004)

    def test_server_core_optional_fields_are_decoded(self):
        packet = self.server_response(
            ENCRYPTION_METHOD_128BIT,
            3,
            server_version=0x00080011,
            core_suffix=struct.pack("<II", PROTOCOL_SSL, 0x08),
        )

        result = _parse_server_core_data(packet)

        self.assertEqual(result.version, 0x00080011)
        self.assertEqual(result.client_requested_protocols, PROTOCOL_SSL)
        self.assertEqual(result.early_capability_flags, 0x08)

    def test_server_network_and_multitransport_data_are_decoded(self):
        channels = ("cliprdr", "rdpdr", "rdpsnd", "drdynvc")
        network_block = struct.pack(
            "<HHHHHHHH",
            0x0C03,
            16,
            1003,
            4,
            1004,
            1005,
            1006,
            1007,
        )
        multitransport_block = struct.pack(
            "<HHI",
            0x0C08,
            8,
            TRANSPORTTYPE_UDPFECR,
        )
        packet = self.server_response(
            ENCRYPTION_METHOD_128BIT,
            3,
            extra_blocks=network_block + multitransport_block,
        )

        self.assertEqual(
            _parse_server_network_data(packet, channels),
            dict(zip(channels, (1004, 1005, 1006, 1007), strict=True)),
        )
        self.assertEqual(
            _parse_server_multitransport_data(packet),
            TRANSPORTTYPE_UDPFECR,
        )

    def test_truncated_server_block_is_rejected(self):
        packet = bytearray(self.server_response(ENCRYPTION_METHOD_40BIT, 1))
        packet[-10:-8] = b"\xff\x7f"

        with self.assertRaises(RDPProtocolError):
            _parse_server_security_data(bytes(packet))


class NLAClassificationTests(unittest.TestCase):
    def classify(self, probes: list[NegotiationProbe]) -> NLAResult:
        module = RDP.__new__(RDP)
        module._security_probes = probes
        return module._run_nla_test()

    def test_nla_required(self):
        result = self.classify(
            [
                probe("Full negotiation", 11, selected=PROTOCOL_HYBRID),
                probe("CredSSP/NLA only", 10, selected=PROTOCOL_HYBRID),
                probe("TLS without NLA", 1, failure=5),
                probe("Standard RDP Security", 0, failure=5),
            ]
        )

        self.assertEqual(result.status, "required")

    def test_nla_allowed_but_not_required(self):
        result = self.classify(
            [
                probe("Full negotiation", 11, selected=PROTOCOL_HYBRID),
                probe("CredSSP/NLA only", 10, selected=PROTOCOL_HYBRID),
                probe("TLS without NLA", 1, selected=PROTOCOL_SSL),
                probe("Standard RDP Security", 0, failure=1),
            ]
        )

        self.assertEqual(result.status, "allowed_not_required")

    def test_nla_not_supported(self):
        result = self.classify(
            [
                probe("Full negotiation", 11, selected=PROTOCOL_SSL),
                probe("CredSSP/NLA only", 10, failure=2),
                probe("TLS without NLA", 1, selected=PROTOCOL_SSL),
                probe("Standard RDP Security", 0, selected=PROTOCOL_RDP),
            ]
        )

        self.assertEqual(result.status, "not_supported")

    def test_ambiguous_transport_errors_are_inconclusive(self):
        result = self.classify(
            [
                probe("Full negotiation", 11, selected=PROTOCOL_HYBRID),
                probe("CredSSP/NLA only", 10, selected=PROTOCOL_HYBRID),
                probe("TLS without NLA", 1, error="timeout"),
                probe("Standard RDP Security", 0, error="timeout"),
            ]
        )

        self.assertEqual(result.status, "inconclusive")

    def test_one_rejection_and_one_transport_error_is_inconclusive(self):
        result = self.classify(
            [
                probe("Full negotiation", 11, selected=PROTOCOL_HYBRID),
                probe("CredSSP/NLA only", 10, selected=PROTOCOL_HYBRID),
                probe("TLS without NLA", 1, failure=5),
                probe("Standard RDP Security", 0, error="timeout"),
            ]
        )

        self.assertEqual(result.status, "inconclusive")

    def test_complete_transport_failure_is_error(self):
        result = self.classify(
            [
                probe("Full negotiation", 11, error="connection refused"),
                probe("CredSSP/NLA only", 10, error="connection refused"),
                probe("TLS without NLA", 1, error="connection refused"),
                probe("Standard RDP Security", 0, error="connection refused"),
            ]
        )

        self.assertEqual(result.status, "error")
        self.assertEqual(result.error, "connection refused")


class RDPCommandTests(unittest.TestCase):
    def parse(self, arguments: list[str]) -> RDPArgs:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="module", required=True)
        RDPArgs().add_subparser("rdp", subparsers)
        return parser.parse_args(arguments, namespace=RDPArgs())

    def test_help_contract_contains_jira_options_and_example(self):
        help_data = str(RDPArgs.get_help())

        self.assertIn("-ts", help_data)
        self.assertIn("--tests", help_data)
        self.assertIn("NLA", help_data)
        self.assertIn("AUTH", help_data)
        self.assertIn("SSL", help_data)
        self.assertIn("RDPENC", help_data)
        self.assertIn("CAPABIL", help_data)
        self.assertIn("VERSION", help_data)
        self.assertIn("--login", help_data)
        self.assertIn("--password", help_data)
        self.assertIn(
            "ptsrvtester RDP 12.32.43.163 -ts NLA AUTH -l admin -p pass123",
            help_data,
        )

    def test_parser_accepts_multiple_tests_and_credentials(self):
        args = self.parse(
            [
                "rdp",
                "192.0.2.10:3390",
                "-ts",
                "nla",
                "ssl",
                "-l",
                "admin",
                "-p",
                "pass123",
            ]
        )

        self.assertEqual(args.tests, ["NLA", "SSL"])
        self.assertEqual(args.target.port, 3390)
        self.assertEqual(args.login, "admin")
        self.assertEqual(args.password, "pass123")

    def test_parser_accepts_explicit_insecure_authentication(self):
        args = self.parse(
            [
                "rdp",
                "192.0.2.10",
                "-ts",
                "AUTH",
                "-l",
                "admin",
                "-p",
                "pass123",
                "--insecure-auth",
            ]
        )

        self.assertTrue(args.insecure_auth)

    def test_module_applies_default_port(self):
        module = RDP(rdp_args(), object())

        self.assertEqual(module.args.target.port, 3389)

    def test_no_tests_runs_all_implemented_pre_auth_tests(self):
        module = RDP(rdp_args(), object())
        module._run_nla_test = Mock(return_value=NLAResult("required", []))
        module._run_rdp_security_test = Mock(
            return_value=RDPSecurityResult(
                "not_allowed",
                probe("Standard RDP Security", 0, failure=5),
            )
        )
        module._run_credssp_test = Mock(
            return_value=CredSSPResult("supported", True, [])
        )
        module._run_rdp_encryption_test = Mock(
            return_value=RDPEncryptionResult("ok")
        )
        module._run_capability_test = Mock(
            return_value=CapabilityResult("partial")
        )
        module._run_version_test = Mock(
            return_value=RDPVersionResult("ok")
        )
        module._run_ssl_test = Mock(return_value=SSLResult("ok"))
        module._run_ntlminfo_test = Mock(
            return_value=NTLMInfoResult("not_supported")
        )

        module.run()

        module._run_nla_test.assert_called_once_with()
        module._run_rdp_security_test.assert_called_once_with()
        module._run_credssp_test.assert_called_once_with()
        module._run_rdp_encryption_test.assert_called_once_with()
        module._run_capability_test.assert_called_once_with()
        module._run_version_test.assert_called_once_with()
        module._run_ssl_test.assert_called_once_with()
        module._run_ntlminfo_test.assert_called_once_with()
        self.assertEqual(module.results.not_implemented, [])

    def test_auth_runs_with_credentials(self):
        module = RDP(
            rdp_args(
                tests=["AUTH"],
                login="EXAMPLE\\tester",
                password="secret",
            ),
            object(),
        )
        module._get_security_probes = Mock(
            return_value=[
                probe(
                    "CredSSP/NLA only",
                    PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX,
                    selected=PROTOCOL_HYBRID_EX,
                )
            ]
        )
        module._get_authenticated_session_result = Mock(
            return_value=AuthenticatedSessionResult(
                status="authenticated",
                selected_protocol=PROTOCOL_HYBRID_EX,
                session_established=True,
            )
        )

        module.run()

        self.assertEqual(module.results.auth.status, "authenticated")
        self.assertEqual(module.results.not_implemented, [])

    def test_auth_requires_both_credentials(self):
        module = RDP(rdp_args(tests=["AUTH"], login="tester"), object())

        module.run()

        self.assertEqual(module.results.auth.status, "missing_credentials")

    @patch("ptsrvtester.modules.rdp.IMPLEMENTED_TESTS", {"AUTH"})
    def test_default_run_includes_auth_when_credentials_are_supplied(self):
        module = RDP(
            rdp_args(login="EXAMPLE\\tester", password="secret"),
            object(),
        )
        module._run_auth_test = Mock(return_value=RDPAuthResult("authenticated"))

        module.run()

        module._run_auth_test.assert_called_once_with()


class RDPAuthenticationTests(unittest.TestCase):
    def test_login_parser_supports_domain_and_upn_forms(self):
        self.assertEqual(
            _split_ntlm_login("EXAMPLE\\tester"),
            ("EXAMPLE", "tester"),
        )
        self.assertEqual(
            _split_ntlm_login("tester@example.test"),
            ("example.test", "tester"),
        )
        self.assertEqual(_split_ntlm_login("localuser"), (None, "localuser"))

    def test_secret_is_redacted_from_dependency_errors(self):
        error = _sanitize_auth_error(
            ValueError("authentication failed for password SuperSecret"),
            "SuperSecret",
        )

        self.assertNotIn("SuperSecret", error)
        self.assertIn("<redacted>", error)

    @patch("ptsrvtester.modules.rdp._run_aardwolf_authenticated_session")
    def test_authenticated_session_is_cached(self, run_session):
        run_session.return_value = AuthenticatedSessionResult(
            status="authenticated",
            selected_protocol=PROTOCOL_HYBRID_EX,
            session_established=True,
        )
        module = RDP(
            rdp_args(login="EXAMPLE\\tester", password="secret"),
            object(),
        )
        module._auth_tls_validation_result = AuthTLSValidationResult(
            status="verified",
            certificate_sha256="a" * 64,
        )

        first = module._get_authenticated_session_result()
        second = module._get_authenticated_session_result()

        self.assertIs(first, second)
        run_session.assert_called_once_with(
            "192.0.2.10",
            3389,
            "EXAMPLE\\tester",
            "secret",
            10.0,
            "a" * 64,
            "verified",
            True,
        )

    @patch("ptsrvtester.modules.rdp._run_aardwolf_authenticated_session")
    def test_auth_only_does_not_request_capability_channels(self, run_session):
        run_session.return_value = AuthenticatedSessionResult(
            status="authenticated",
        )
        module = RDP(
            rdp_args(
                tests=["AUTH"],
                login="EXAMPLE\\tester",
                password="secret",
            ),
            object(),
        )
        module._auth_tls_validation_result = AuthTLSValidationResult(
            status="verified",
            certificate_sha256="a" * 64,
        )

        module._get_authenticated_session_result()

        run_session.assert_called_once_with(
            "192.0.2.10",
            3389,
            "EXAMPLE\\tester",
            "secret",
            10.0,
            "a" * 64,
            "verified",
            False,
        )

    def test_auth_output_never_contains_credentials(self):
        module = RDP.__new__(RDP)
        module.use_json = False
        module.args = SimpleNamespace(debug=False, json=False)
        module.ptprint = Mock()

        module._output_auth_text(
            RDPAuthResult(
                status="authenticated",
                selected_protocol=PROTOCOL_HYBRID_EX,
                session_established=True,
            )
        )

        output = "\n".join(
            str(call.args[0]) for call in module.ptprint.call_args_list
        )
        self.assertIn("authentication succeeded", output)
        self.assertNotIn("password", output.lower())

    def test_tls_error_output_says_credentials_were_not_used_once(self):
        module = RDP.__new__(RDP)
        module.use_json = False
        module.args = SimpleNamespace(debug=False, json=False)
        module.ptprint = Mock()

        module._output_auth_text(
            RDPAuthResult(
                status="tls_error",
                error="certificate validation failed",
            )
        )

        output = "\n".join(
            str(call.args[0]) for call in module.ptprint.call_args_list
        )
        self.assertEqual(output.count("Credentials were not used"), 1)
        self.assertNotIn("session setup failed", output)

    def test_failed_authentication_still_reports_insecure_tls_choice(self):
        module = RDP.__new__(RDP)
        module.use_json = False
        module.args = SimpleNamespace(debug=False, json=False)
        module.ptprint = Mock()

        module._output_auth_text(
            RDPAuthResult(
                status="failed",
                tls_verification="insecure",
                error="logon failure",
            )
        )

        output = "\n".join(
            str(call.args[0]) for call in module.ptprint.call_args_list
        )
        self.assertIn("TLS certificate validation was explicitly disabled", output)

    def test_auth_json_contains_no_identity_or_secret(self):
        module = RDP.__new__(RDP)

        result = module._auth_json(
            RDPAuthResult(
                status="authenticated",
                selected_protocol=PROTOCOL_HYBRID,
                session_established=True,
                tls_verification="verified",
                certificate_sha256="a" * 64,
            )
        )

        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["tlsVerification"], "verified")
        self.assertEqual(result["certificateSha256"], "a" * 64)
        self.assertNotIn("login", result)
        self.assertNotIn("password", result)

    @patch("ptsrvtester.modules.rdp._run_aardwolf_authenticated_session")
    def test_untrusted_certificate_blocks_credentials(self, run_session):
        module = RDP(
            rdp_args(login="EXAMPLE\\tester", password="secret"),
            object(),
        )
        module._tls_handshake = Mock(
            return_value=(None, None, None, None, "self-signed certificate")
        )

        result = module._get_authenticated_session_result()

        self.assertEqual(result.status, "tls_error")
        self.assertIn("--insecure-auth", result.error)
        run_session.assert_not_called()
        module._tls_handshake.assert_called_once_with(
            PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX,
            verify_certificate=True,
        )

    @patch("ptsrvtester.modules.rdp._run_aardwolf_authenticated_session")
    def test_explicit_insecure_authentication_pins_preflight_certificate(
        self,
        run_session,
    ):
        cert_der = b"test-certificate"
        run_session.return_value = AuthenticatedSessionResult(
            status="authenticated",
            selected_protocol=PROTOCOL_HYBRID_EX,
            session_established=True,
            tls_verification="insecure",
            certificate_sha256=_certificate_sha256(cert_der),
        )
        module = RDP(
            rdp_args(
                login="EXAMPLE\\tester",
                password="secret",
                insecure_auth=True,
            ),
            object(),
        )
        module._tls_handshake = Mock(
            return_value=(
                None,
                "TLSv1.3",
                "TLS_AES_256_GCM_SHA384",
                cert_der,
                None,
            )
        )

        result = module._get_authenticated_session_result()

        self.assertEqual(result.status, "authenticated")
        module._tls_handshake.assert_called_once_with(
            PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX,
            verify_certificate=False,
        )
        run_session.assert_called_once_with(
            "192.0.2.10",
            3389,
            "EXAMPLE\\tester",
            "secret",
            10.0,
            _certificate_sha256(cert_der),
            "insecure",
            True,
        )

    def test_demand_active_parser_is_restored_after_exception(self):
        class Parser:
            @staticmethod
            def from_bytes(_data):
                return SimpleNamespace(capabilitySets=[])

        original = Parser.from_bytes
        with self.assertRaisesRegex(RuntimeError, "stop"):
            with _capture_aardwolf_demand_active(Parser):
                raise RuntimeError("stop")

        self.assertIs(Parser.from_bytes, original)

    def test_aardwolf_private_state_helpers_extract_expected_values(self):
        core_key = object()
        network_key = object()
        connection = SimpleNamespace()
        setattr(
            connection,
            "_RDPConnection__server_connect_pdu",
            {
                core_key: SimpleNamespace(
                    version=0x00080011,
                    clientRequestedProtocols=PROTOCOL_HYBRID_EX,
                    earlyCapabilityFlags=0x08,
                ),
                network_key: SimpleNamespace(
                    channelIdArray=[1004, 1005, 1006, 1007],
                ),
            },
        )
        setattr(
            connection,
            "_RDPConnection__connection",
            SimpleNamespace(get_peer_certificate=lambda: b"certificate"),
        )

        core = _extract_aardwolf_server_core(connection, core_key)
        channel_ids, channel_data_observed = _extract_aardwolf_channel_ids(
            connection,
            network_key,
            ("cliprdr", "rdpdr", "drdynvc", "rdpsnd"),
        )

        self.assertEqual(core.version, 0x00080011)
        self.assertEqual(core.client_requested_protocols, PROTOCOL_HYBRID_EX)
        self.assertTrue(channel_data_observed)
        self.assertEqual(channel_ids["rdpdr"], 1005)
        self.assertEqual(
            _aardwolf_peer_certificate_sha256(connection),
            _certificate_sha256(b"certificate"),
        )
        with self.assertRaisesRegex(RuntimeError, "certificate changed"):
            _verify_aardwolf_peer_certificate(connection, "0" * 64)

    def test_aardwolf_probe_channels_are_passive_and_ordered(self):
        class FakeChannel:
            def __init__(self, name, options):
                self.name = name
                self.options = options

        channel_types = _aardwolf_probe_channel_types(FakeChannel, int)
        channels = [channel_type(object()) for channel_type in channel_types]

        self.assertEqual(
            [channel.name for channel in channels],
            ["cliprdr", "rdpdr", "drdynvc", "rdpsnd"],
        )

    def test_aardwolf_adapter_runs_without_network_and_restores_logger(self):
        expected_result = AuthenticatedSessionResult(status="authenticated")
        logger = logging.getLogger("aardwolf")
        original_disabled = logger.disabled
        logger.disabled = False
        try:
            with patch(
                "ptsrvtester.modules.rdp.importlib.metadata.version",
                side_effect=lambda package: {
                    "aardwolf": "0.2.14",
                    "asyauth": "0.0.23",
                }[package],
            ), patch(
                "ptsrvtester.modules.rdp._connect_aardwolf_session",
                new_callable=AsyncMock,
                return_value=expected_result,
            ) as connect:
                result = _run_aardwolf_authenticated_session(
                    "192.0.2.10",
                    3389,
                    "EXAMPLE\\tester",
                    "secret",
                    10.0,
                    "a" * 64,
                    "verified",
                    False,
                )

            self.assertIs(result, expected_result)
            connect.assert_awaited_once_with(
                "192.0.2.10",
                3389,
                "EXAMPLE",
                "tester",
                "secret",
                10.0,
                "a" * 64,
                "verified",
                False,
            )
            self.assertFalse(logger.disabled)
        finally:
            logger.disabled = original_disabled

    def test_aardwolf_adapter_restores_logger_after_async_failure(self):
        logger = logging.getLogger("aardwolf")
        original_disabled = logger.disabled
        logger.disabled = False
        try:
            with patch(
                "ptsrvtester.modules.rdp.importlib.metadata.version",
                side_effect=lambda package: {
                    "aardwolf": "0.2.14",
                    "asyauth": "0.0.23",
                }[package],
            ), patch(
                "ptsrvtester.modules.rdp._connect_aardwolf_session",
                new_callable=AsyncMock,
                side_effect=RuntimeError("adapter failure"),
            ):
                result = _run_aardwolf_authenticated_session(
                    "192.0.2.10",
                    3389,
                    "tester",
                    "secret",
                    10.0,
                    "a" * 64,
                    "verified",
                    False,
                )

            self.assertEqual(result.status, "error")
            self.assertIn("adapter failure", result.error)
            self.assertFalse(logger.disabled)
        finally:
            logger.disabled = original_disabled


class NLAOutputTests(unittest.TestCase):
    def output_for(self, status: str) -> str:
        module = RDP.__new__(RDP)
        module.use_json = False
        module.args = SimpleNamespace(debug=False, json=False)
        module.ptprint = Mock()

        module._output_nla_text(NLAResult(status, []))

        return "\n".join(str(call.args[0]) for call in module.ptprint.call_args_list)

    def test_required_output(self):
        self.assertIn("NLA required", self.output_for("required"))

    def test_allowed_output(self):
        self.assertIn(
            "NLA is allowed but not required",
            self.output_for("allowed_not_required"),
        )

    def test_unsupported_output(self):
        self.assertIn("NLA is not supported", self.output_for("not_supported"))

    @patch("ptsrvtester.modules.rdp.ptprinthelper.bullet", return_value="<status> ")
    def test_status_lines_use_ptlibs_bullet_mapping(self, bullet):
        module = RDP.__new__(RDP)
        module.ptprint = Mock()

        module._print_status("message", Out.WARNING)

        bullet.assert_called_once_with("WARNING")
        module.ptprint.assert_called_once_with("    <status> message", Out.TEXT)


class RDPVersionTests(unittest.TestCase):
    @patch("ptsrvtester.modules.rdp._create_tls_context")
    @patch("ptsrvtester.modules.rdp._parse_negotiation_reply_details")
    @patch("ptsrvtester.modules.rdp._read_tpkt", return_value=b"reply")
    @patch("ptsrvtester.modules.rdp.socket.create_connection")
    def test_transport_error_is_not_hidden_by_fallback_rejection(
        self,
        create_connection,
        _read_tpkt_mock,
        parse_reply,
        create_tls_context,
    ):
        create_connection.side_effect = (Mock(), Mock())
        parse_reply.side_effect = (
            NegotiationReply(selected_protocol=PROTOCOL_SSL),
            NegotiationReply(failure_code=1),
        )
        create_tls_context.return_value.wrap_socket.side_effect = OSError(
            "TLS handshake failed"
        )
        module = RDP(rdp_args(), object())

        result = module._probe_basic_settings()

        self.assertEqual(result.status, "error")
        self.assertIn("TLS handshake failed", result.error)
        self.assertIn("SSL required by server", result.error)

    def test_reports_precise_server_advertised_version(self):
        module = RDP(rdp_args(), object())
        module._basic_settings_result = BasicSettingsResult(
            status="ok",
            selected_protocol=PROTOCOL_SSL,
            server_core=ServerCoreData(0x00080011),
        )

        result = module._run_version_test()

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.version_name, "RDP 10.12")
        self.assertEqual(result.transport, "SSL")
        self.assertEqual(result.source, "pre_auth")

    def test_marks_shared_rdp_5_to_8_wire_value_as_ambiguous(self):
        module = RDP(rdp_args(), object())
        module._basic_settings_result = BasicSettingsResult(
            status="ok",
            selected_protocol=PROTOCOL_SSL,
            server_core=ServerCoreData(0x00080004),
        )

        result = module._run_version_test()

        self.assertEqual(result.status, "ambiguous")
        self.assertEqual(result.version_name, "RDP 5.0-8.1 family")

    def test_nla_requirement_is_reported_as_unavailable(self):
        module = RDP(rdp_args(), object())
        module._basic_settings_result = BasicSettingsResult(
            status="unavailable",
            error="NLA prevents pre-auth Basic Settings Exchange",
        )

        result = module._run_version_test()

        self.assertEqual(result.status, "unavailable")
        self.assertIn("NLA", result.error)

    def test_missing_server_core_data_is_an_error(self):
        module = RDP(rdp_args(), object())
        module._basic_settings_result = BasicSettingsResult(
            status="ok",
            selected_protocol=PROTOCOL_SSL,
        )

        result = module._run_version_test()

        self.assertEqual(result.status, "error")
        self.assertIn("Server Core Data", result.error)

    def test_nla_required_server_uses_authenticated_version_fallback(self):
        module = RDP(
            rdp_args(login="EXAMPLE\\tester", password="secret"),
            object(),
        )
        module._basic_settings_result = BasicSettingsResult(
            status="unavailable",
            error="NLA prevents pre-auth Basic Settings Exchange",
        )
        module._authenticated_session_result = AuthenticatedSessionResult(
            status="authenticated",
            selected_protocol=PROTOCOL_HYBRID_EX,
            session_established=True,
            server_core=ServerCoreData(0x00080011),
            tls_verification="verified",
        )

        result = module._run_version_test()

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.version_name, "RDP 10.12")
        self.assertEqual(result.transport, "HYBRID_EX")
        self.assertEqual(result.source, "authenticated")

    def test_version_output_does_not_claim_supported_version_list(self):
        module = RDP.__new__(RDP)
        module.use_json = False
        module.args = SimpleNamespace(debug=False, json=False)
        module.ptprint = Mock()

        module._output_version_text(
            RDPVersionResult(
                status="ok",
                version_name="RDP 10.12",
                source="pre_auth",
            )
        )

        output = "\n".join(
            str(call.args[0]) for call in module.ptprint.call_args_list
        )
        self.assertIn("RDP protocol version", output)
        self.assertIn("Server reports: RDP 10.12", output)
        self.assertNotIn("supported versions", output.lower())

    def test_version_json_identifies_authenticated_source(self):
        module = RDP.__new__(RDP)

        output = module._version_json(
            RDPVersionResult(
                status="ok",
                advertised_version=0x00080011,
                version_name="RDP 10.12",
                source="authenticated",
            )
        )

        self.assertEqual(output["source"], "authenticated")
        self.assertFalse(output["isSupportedVersionList"])


class RDPCapabilityTests(unittest.TestCase):
    @staticmethod
    def finding_map(result: CapabilityResult) -> dict[str, str]:
        return {finding.name: finding.status for finding in result.findings}

    def test_classifies_pre_auth_flags_channels_and_udp(self):
        module = RDP(rdp_args(), object())
        module._basic_settings_result = BasicSettingsResult(
            status="ok",
            selected_protocol=PROTOCOL_SSL,
            response_flags=NEG_RSP_DYNVC_GFX_PROTOCOL_SUPPORTED,
            server_core=ServerCoreData(0x00080011),
            channel_ids={
                "cliprdr": 1004,
                "rdpdr": 1005,
                "rdpsnd": 1006,
                "drdynvc": 1007,
            },
            multitransport_flags=TRANSPORTTYPE_UDPFECR,
        )

        result = module._run_capability_test()
        findings = self.finding_map(result)

        self.assertEqual(findings["Bitmap compression"], "supported")
        self.assertEqual(findings["Graphics Pipeline"], "supported")
        self.assertEqual(findings["Dynamic Virtual Channels"], "supported")
        self.assertEqual(findings["Clipboard"], "allocated")
        self.assertEqual(findings["Drive redirection"], "allocated")
        self.assertEqual(findings["Audio"], "allocated")
        self.assertEqual(findings["UDP transport"], "supported")
        self.assertEqual(findings["RemoteFX"], "unknown")
        self.assertEqual(result.status, "partial")

    def test_nla_still_allows_graphics_flag_classification(self):
        module = RDP(rdp_args(), object())
        module._basic_settings_result = BasicSettingsResult(
            status="unavailable",
            error="NLA prevents pre-auth Basic Settings Exchange",
        )
        module._get_security_probes = Mock(
            return_value=[
                NegotiationProbe(
                    "Full negotiation",
                    PROTOCOL_HYBRID,
                    selected_protocol=PROTOCOL_HYBRID,
                    response_flags=NEG_RSP_DYNVC_GFX_PROTOCOL_SUPPORTED,
                )
            ]
        )

        result = module._run_capability_test()
        findings = self.finding_map(result)

        self.assertEqual(findings["Bitmap compression"], "supported")
        self.assertEqual(findings["Graphics Pipeline"], "supported")
        self.assertEqual(findings["Dynamic Virtual Channels"], "supported")
        self.assertEqual(findings["Clipboard"], "unknown")
        self.assertEqual(findings["UDP transport"], "unknown")

    def test_nla_uses_authenticated_channel_allocations(self):
        module = RDP(
            rdp_args(login="EXAMPLE\\tester", password="secret"),
            object(),
        )
        module._basic_settings_result = BasicSettingsResult(
            status="unavailable",
            error="NLA prevents pre-auth Basic Settings Exchange",
        )
        module._authenticated_session_result = AuthenticatedSessionResult(
            status="authenticated",
            selected_protocol=PROTOCOL_HYBRID_EX,
            session_established=True,
            channel_ids={
                "cliprdr": 1004,
                "rdpdr": 1005,
                "drdynvc": 1006,
                "rdpsnd": 1007,
            },
            channel_data_observed=True,
            demand_active_observed=True,
        )
        module._get_security_probes = Mock(return_value=[])

        result = module._run_capability_test()
        findings = self.finding_map(result)

        self.assertEqual(findings["Clipboard"], "allocated")
        self.assertEqual(findings["Drive redirection"], "allocated")
        self.assertEqual(findings["Dynamic Virtual Channels"], "supported")
        self.assertEqual(findings["Audio"], "allocated")
        self.assertEqual(findings["UDP transport"], "unknown")
        udp_finding = next(
            finding
            for finding in result.findings
            if finding.name == "UDP transport"
        )
        self.assertEqual(
            udp_finding.evidence,
            "requires authenticated multitransport negotiation",
        )

    def test_channel_allocation_output_does_not_claim_policy_is_enabled(self):
        module = RDP.__new__(RDP)
        module.use_json = False
        module.args = SimpleNamespace(debug=False, json=False)
        module.ptprint = Mock()
        result = CapabilityResult(
            status="partial",
            findings=[
                CapabilityFinding(
                    "Clipboard",
                    "allocated",
                    "static virtual channel cliprdr allocated as 1004; "
                    "server policy was not exercised",
                )
            ],
        )

        module._output_capabilities_text(result)

        output = "\n".join(
            str(call.args[0]) for call in module.ptprint.call_args_list
        )
        self.assertIn("RDP capabilities", output)
        self.assertIn("channel allocated, policy not verified", output)

    def test_unknown_capability_output_explains_required_negotiation(self):
        module = RDP.__new__(RDP)
        module.use_json = False
        module.args = SimpleNamespace(debug=False, json=False)
        module.ptprint = Mock()
        result = CapabilityResult(
            status="partial",
            findings=[
                CapabilityFinding(
                    "AVC444",
                    "unknown",
                    "requires RDP Graphics capability exchange",
                )
            ],
        )

        module._output_capabilities_text(result)

        output = "\n".join(
            str(call.args[0]) for call in module.ptprint.call_args_list
        )
        self.assertIn("requires RDP Graphics capability exchange", output)

    def test_bitmap_codec_parser_decodes_wire_guid(self):
        codec_data = (
            b"\x01"
            + uuid.UUID(REMOTEFX_CODEC_GUID).bytes_le
            + b"\x03\x00\x00"
        )

        codecs = _parse_bitmap_codec_guids(codec_data)

        self.assertEqual(codecs, frozenset({REMOTEFX_CODEC_GUID}))

    def test_bitmap_codec_parser_rejects_truncated_data(self):
        with self.assertRaisesRegex(ValueError, "truncated"):
            _parse_bitmap_codec_guids(b"\x01\x00")

    def test_authenticated_demand_active_reports_remotefx(self):
        module = RDP(
            rdp_args(login="EXAMPLE\\tester", password="secret"),
            object(),
        )
        module._basic_settings_result = BasicSettingsResult(
            status="ok",
            selected_protocol=PROTOCOL_SSL,
            server_core=ServerCoreData(0x00080011),
        )
        module._authenticated_session_result = AuthenticatedSessionResult(
            status="authenticated",
            selected_protocol=PROTOCOL_HYBRID_EX,
            session_established=True,
            demand_active_observed=True,
            capability_types=frozenset({"BITMAP", "BITMAP_CODECS"}),
            bitmap_codec_guids=frozenset({REMOTEFX_CODEC_GUID}),
        )

        result = module._run_capability_test()
        findings = self.finding_map(result)

        self.assertEqual(findings["RemoteFX"], "supported")
        self.assertEqual(findings["AVC444"], "unknown")

    def test_authenticated_demand_active_can_reject_remotefx_support(self):
        module = RDP(
            rdp_args(login="EXAMPLE\\tester", password="secret"),
            object(),
        )
        module._basic_settings_result = BasicSettingsResult(
            status="ok",
            selected_protocol=PROTOCOL_SSL,
            server_core=ServerCoreData(0x00080011),
        )
        module._authenticated_session_result = AuthenticatedSessionResult(
            status="authenticated",
            selected_protocol=PROTOCOL_HYBRID,
            session_established=True,
            demand_active_observed=True,
            capability_types=frozenset({"BITMAP"}),
        )

        result = module._run_capability_test()
        findings = self.finding_map(result)

        self.assertEqual(findings["RemoteFX"], "not_supported")


class WeakCipherTests(unittest.TestCase):
    @staticmethod
    def tls12_supported() -> list[TLSVersionProbe]:
        return [TLSVersionProbe("TLSv1.2", True)]

    def test_cipher_format_does_not_repeat_tls_version(self):
        formatted = _format_cipher(
            ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        )

        self.assertEqual(formatted, "TLS_AES_256_GCM_SHA384 (256 bits)")

    @patch(
        "ptsrvtester.modules.rdp._available_weak_tls_cipher_names",
        return_value=("WEAK-A", "WEAK-B"),
    )
    def test_scan_reports_no_accepted_weak_cipher(self, _weak_names):
        module = RDP(rdp_args(), object())
        module._tls_handshake = Mock(
            return_value=(
                None,
                None,
                None,
                None,
                "ssl alert handshake failure",
            )
        )

        result = module._probe_weak_tls_ciphers(
            PROTOCOL_SSL,
            self.tls12_supported(),
        )

        self.assertEqual(result.status, "complete")
        self.assertEqual(result.tested_count, 2)
        self.assertEqual(result.accepted_ciphers, ())

    @patch(
        "ptsrvtester.modules.rdp._available_weak_tls_cipher_names",
        return_value=("WEAK-A", "WEAK-B"),
    )
    def test_scan_enumerates_each_accepted_weak_cipher(self, _weak_names):
        module = RDP(rdp_args(), object())
        module._tls_handshake = Mock(
            side_effect=(
                (None, "TLSv1.2", "WEAK-A (TLSv1.2, 128 bits)", b"cert", None),
                (None, "TLSv1.2", "WEAK-B (TLSv1.2, 128 bits)", b"cert", None),
            )
        )

        result = module._probe_weak_tls_ciphers(
            PROTOCOL_SSL,
            self.tls12_supported(),
        )

        self.assertEqual(result.status, "complete")
        self.assertEqual(result.accepted_ciphers, ("WEAK-A", "WEAK-B"))
        self.assertEqual(module._tls_handshake.call_count, 2)

    @patch(
        "ptsrvtester.modules.rdp._available_weak_tls_cipher_names",
        return_value=("WEAK-A",),
    )
    def test_scan_does_not_treat_timeout_as_cipher_rejection(self, _weak_names):
        module = RDP(rdp_args(), object())
        module._tls_handshake = Mock(
            return_value=(None, None, None, None, "connection timed out")
        )

        result = module._probe_weak_tls_ciphers(
            PROTOCOL_SSL,
            self.tls12_supported(),
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertIn("timed out", result.error)

    def test_accepted_cipher_is_included_in_security_findings(self):
        module = RDP.__new__(RDP)
        result = SSLResult(
            status="ok",
            weak_cipher_scan=WeakCipherScanResult(
                status="complete",
                tested_count=1,
                accepted_ciphers=("WEAK-A",),
            ),
        )

        findings = module._tls_weak_findings(result)

        self.assertIn("weak TLSv1.2 cipher accepted: WEAK-A", findings)

    def test_output_reports_completed_negative_weak_cipher_scan(self):
        module = RDP.__new__(RDP)
        module.use_json = False
        module.args = SimpleNamespace(debug=False, json=False)
        module.ptprint = Mock()
        result = SSLResult(
            status="ok",
            weak_cipher_scan=WeakCipherScanResult(
                status="complete",
                tested_count=12,
            ),
        )

        module._output_ssl_text(result)

        output = "\n".join(
            str(call.args[0]) for call in module.ptprint.call_args_list
        )
        self.assertIn("No locally offerable weak TLSv1.2 cipher accepted", output)

    def test_weak_cipher_scan_is_serialized_for_json(self):
        module = RDP.__new__(RDP)
        result = SSLResult(
            status="weak",
            weak_cipher_scan=WeakCipherScanResult(
                status="complete",
                tested_count=2,
                accepted_ciphers=("WEAK-A",),
            ),
        )

        output = module._ssl_json(result)

        self.assertEqual(output["weakCipherScan"]["testedCount"], 2)
        self.assertEqual(output["weakCipherScan"]["acceptedCiphers"], ["WEAK-A"])


class CertificateParsingTests(unittest.TestCase):
    def setUp(self):
        self.module = RDP.__new__(RDP)

    def test_self_signed_certificate_signature_is_verified(self):
        key = ec.generate_private_key(ec.SECP256R1())
        der = certificate_der(key, key)

        result = self.module._parse_certificate(
            der,
            "rdp.example.test",
        )

        self.assertTrue(result.self_signed)
        self.assertEqual(result.sha256_fingerprint, _certificate_sha256(der))

    def test_self_issued_certificate_signed_by_another_key_is_not_self_signed(self):
        subject_key = ec.generate_private_key(ec.SECP256R1())
        signing_key = ec.generate_private_key(ec.SECP256R1())

        result = self.module._parse_certificate(
            certificate_der(subject_key, signing_key),
            "rdp.example.test",
        )

        self.assertFalse(result.self_signed)


class RDPEncryptionOutputTests(unittest.TestCase):
    @staticmethod
    def sample_result() -> RDPEncryptionResult:
        return RDPEncryptionResult(
            status="ok",
            protocol_probes=[
                probe("Standard RDP Security", PROTOCOL_RDP, selected=PROTOCOL_RDP),
                probe("TLS without NLA", PROTOCOL_SSL, selected=PROTOCOL_SSL),
                probe("RDSTLS", PROTOCOL_RDSTLS, failure=2),
                probe("RDS AAD authentication", PROTOCOL_RDSAAD, failure=2),
            ],
            legacy_status="ok",
            legacy_probes=[
                LegacyEncryptionProbe(
                    ENCRYPTION_METHOD_40BIT,
                    True,
                    selected_method=ENCRYPTION_METHOD_40BIT,
                    encryption_level=1,
                    server_rdp_version=0x00080004,
                ),
                LegacyEncryptionProbe(ENCRYPTION_METHOD_FIPS, False),
            ],
            response_flags=0x18,
        )

    def test_output_lists_protocols_capabilities_and_legacy_methods(self):
        module = RDP.__new__(RDP)
        module.use_json = False
        module.args = SimpleNamespace(debug=False, json=False)
        module.ptprint = Mock()
        result = self.sample_result()

        module._output_rdp_encryption_text(result)

        output = "\n".join(
            str(call.args[0]) for call in module.ptprint.call_args_list
        )
        self.assertIn("TLS without NLA: supported", output)
        self.assertIn("Restricted Admin Mode", output)
        self.assertIn("Remote Credential Guard", output)
        self.assertIn("40-bit RC4: accepted", output)
        self.assertIn("FIPS 140-1: not accepted", output)
        self.assertIn("Server protocol version: RDP 5.0-8.1 family", output)

    def test_output_distinguishes_tls_without_nla_from_tls_transport(self):
        module = RDP.__new__(RDP)
        module.use_json = False
        module.args = SimpleNamespace(debug=False, json=False)
        module.ptprint = Mock()
        module._negotiate = Mock(
            side_effect=lambda name, protocol: probe(name, protocol, failure=5)
        )

        result = module._run_rdp_encryption_test()

        module._output_rdp_encryption_text(result)

        output = "\n".join(
            str(call.args[0]) for call in module.ptprint.call_args_list
        )
        self.assertIn("TLS without NLA: not supported", output)

    def test_json_preserves_evidence_and_capabilities(self):
        module = RDP.__new__(RDP)

        output = module._rdp_encryption_json(self.sample_result())

        self.assertEqual(output["status"], "ok")
        self.assertIn("Restricted Admin Mode", output["negotiationCapabilities"])
        self.assertTrue(output["securityProtocols"][0]["supported"])
        self.assertTrue(
            output["standardRdpEncryption"]["methods"][0]["accepted"]
        )


if __name__ == "__main__":
    unittest.main()
