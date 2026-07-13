import argparse
import datetime as dt
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ptsrvtester.modules.rdp import (
    CredSSPResult,
    ENCRYPTION_METHOD_40BIT,
    ENCRYPTION_METHOD_128BIT,
    ENCRYPTION_METHOD_FIPS,
    ENCRYPTION_LEVEL_NAMES,
    LegacyEncryptionProbe,
    NLAResult,
    NTLMInfoResult,
    PROTOCOL_HYBRID,
    PROTOCOL_HYBRID_EX,
    PROTOCOL_RDSTLS,
    PROTOCOL_RDP,
    PROTOCOL_RDSAAD,
    PROTOCOL_SSL,
    RDP,
    RDPArgs,
    RDPProtocolError,
    RDPEncryptionResult,
    RDPSecurityResult,
    SSLResult,
    TYPE_RDP_NEG_FAILURE,
    TYPE_RDP_NEG_REQ,
    TYPE_RDP_NEG_RSP,
    NegotiationProbe,
    _build_negotiation_request,
    _build_mcs_connect_initial,
    _ber_wrap,
    _parse_negotiation_reply_details,
    _parse_negotiation_reply,
    _parse_server_security_data,
    _per_encode_length,
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
    ) -> bytes:
        blocks = struct.pack("<HHI", 0x0C01, 8, server_version)
        blocks += struct.pack(
            "<HHII",
            0x0C02,
            12,
            encryption_method,
            encryption_level,
        )
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

    def test_server_security_data_is_decoded(self):
        result = _parse_server_security_data(
            self.server_response(ENCRYPTION_METHOD_128BIT, 3)
        )

        self.assertEqual(result.encryption_method, ENCRYPTION_METHOD_128BIT)
        self.assertEqual(result.encryption_level, 3)
        self.assertEqual(ENCRYPTION_LEVEL_NAMES[result.encryption_level], "High")
        self.assertEqual(result.server_rdp_version, 0x00080004)

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
        module._run_ssl_test = Mock(return_value=SSLResult("ok"))
        module._run_ntlminfo_test = Mock(
            return_value=NTLMInfoResult("not_supported")
        )

        module.run()

        module._run_nla_test.assert_called_once_with()
        module._run_rdp_security_test.assert_called_once_with()
        module._run_credssp_test.assert_called_once_with()
        module._run_rdp_encryption_test.assert_called_once_with()
        module._run_ssl_test.assert_called_once_with()
        module._run_ntlminfo_test.assert_called_once_with()
        self.assertEqual(module.results.not_implemented, [])

    def test_auth_is_explicitly_reported_as_planned(self):
        module = RDP(rdp_args(tests=["AUTH"]), object())

        module.run()

        self.assertEqual(module.results.not_implemented, ["AUTH"])


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


class CertificateParsingTests(unittest.TestCase):
    def setUp(self):
        self.module = RDP.__new__(RDP)

    def test_self_signed_certificate_signature_is_verified(self):
        key = ec.generate_private_key(ec.SECP256R1())

        result = self.module._parse_certificate(
            certificate_der(key, key),
            "rdp.example.test",
        )

        self.assertTrue(result.self_signed)

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
        self.assertIn("Server protocol version: RDP 5.x-8.x", output)

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
