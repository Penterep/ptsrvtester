import importlib.metadata
import json
import sys
import unittest
from dataclasses import asdict
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from ptsrvtester.protocols.rdp.utils.auth_attempts import (
    EXPECTED_DEPENDENCY_VERSIONS,
    AardwolfAuthBackend,
    AuthAttemptRequest,
    AuthMechanism,
    AuthOutcome,
    AuthPhase,
    BackendAttemptResult,
    CredentialSource,
    DependencyVersionError,
    TLSFingerprintError,
    TLSVerification,
    _classify_backend_failure,
    certificate_sha256,
    check_dependency_versions,
    ntstatus_name,
    parse_ntstatus,
    run_auth_attempt,
    sanitize_auth_error,
    validate_auth_attempt,
    verify_tls_fingerprint,
)
from ptsrvtester.protocols.rdp.utils.engine import AARDWOLF_VERSION, ASYAUTH_VERSION


def request(**overrides) -> AuthAttemptRequest:
    values = {
        "host": "rdp.example.test",
        "port": 3389,
        "login": "EXAMPLE\\tester",
        "password": "SuperSecretPassword",
        "mechanism": AuthMechanism.NTLM,
        "expected_certificate_sha256": "a" * 64,
        "tls_verification": TLSVerification.VERIFIED,
        "timeout_seconds": 10.0,
        "credential_source": CredentialSource.PROVIDED,
    }
    values.update(overrides)
    return AuthAttemptRequest(**values)


def serialized_sensitive_variants(value: str) -> set[str]:
    rendered = {
        value,
        repr(value),
        ascii(value),
        value.encode("unicode_escape").decode("ascii"),
        json.dumps(value),
        json.dumps(value, ensure_ascii=False),
    }
    for item in tuple(rendered):
        if len(item) >= 2 and item[0] in {'"', "'"} and item[-1] == item[0]:
            rendered.add(item[1:-1])
    return {item for item in rendered if item}


class SequenceClock:
    def __init__(self, *values: float):
        self._values = iter(values)

    def __call__(self) -> float:
        return next(self._values)


class StubBackend:
    def __init__(self, result: BackendAttemptResult):
        self.result = result
        self.requests: list[AuthAttemptRequest] = []

    def run(self, auth_request: AuthAttemptRequest) -> BackendAttemptResult:
        self.requests.append(auth_request)
        return self.result


def fake_module(name: str, **attributes) -> ModuleType:
    module = ModuleType(name)
    for key, value in attributes.items():
        setattr(module, key, value)
    return module


class AuthAttemptValidationTests(unittest.TestCase):
    def test_request_repr_never_contains_login_or_password(self):
        auth_request = request()

        rendered = repr(auth_request)

        self.assertNotIn(auth_request.login, rendered)
        self.assertNotIn(auth_request.password, rendered)

    def test_unicode_password_is_accepted_and_redacted(self):
        auth_request = request(
            login="Správce",
            password="PřílišŽluťoučký+ěš",
        )

        validated = validate_auth_attempt(auth_request)
        message = sanitize_auth_error(
            f"login {auth_request.login} failed with {auth_request.password}",
            validated,
        )

        self.assertEqual(validated.password, auth_request.password)
        self.assertNotIn(auth_request.login, repr(validated))
        self.assertNotIn(auth_request.password, repr(validated))
        self.assertNotIn(auth_request.login, message)
        self.assertNotIn(auth_request.password, message)

    def test_ntlm_request_is_normalized_without_kerberos_prerequisites(self):
        result = validate_auth_attempt(
            request(
                mechanism="NTLM",
                expected_certificate_sha256="AB" * 32,
                credential_source="GENERATED",
                tls_verification="INSECURE",
            )
        )

        self.assertIs(result.mechanism, AuthMechanism.NTLM)
        self.assertIs(result.credential_source, CredentialSource.GENERATED)
        self.assertIs(result.tls_verification, TLSVerification.INSECURE)
        self.assertEqual(result.expected_certificate_sha256, "ab" * 32)
        self.assertIsNone(result.realm)
        self.assertIsNone(result.kdc_ip)
        self.assertIsNone(result.spn_hostname)

    def test_kerberos_requires_explicit_realm_kdc_ip_and_spn_hostname(self):
        complete = {
            "mechanism": AuthMechanism.KERBEROS,
            "login": "tester@example.test",
            "realm": "EXAMPLE.TEST",
            "kdc_ip": "192.0.2.20",
            "spn_hostname": "rdp.example.test",
        }
        for missing in ("realm", "kdc_ip", "spn_hostname"):
            values = complete.copy()
            values[missing] = None
            with self.subTest(missing=missing), self.assertRaises(
                (TypeError, ValueError)
            ):
                validate_auth_attempt(request(**values))

    def test_kerberos_request_normalizes_prerequisites(self):
        result = validate_auth_attempt(
            request(
                mechanism="kerberos",
                login="tester@example.test",
                realm="example.test",
                kdc_ip="192.0.2.20",
                spn_hostname="RDP.EXAMPLE.TEST.",
            )
        )

        self.assertIs(result.mechanism, AuthMechanism.KERBEROS)
        self.assertEqual(result.realm, "EXAMPLE.TEST")
        self.assertEqual(result.kdc_ip, "192.0.2.20")
        self.assertEqual(result.spn_hostname, "rdp.example.test")

    def test_kerberos_rejects_upn_realm_mismatch_and_ip_spn(self):
        with self.assertRaisesRegex(ValueError, "UPN domain"):
            validate_auth_attempt(
                request(
                    mechanism="kerberos",
                    login="tester@other.test",
                    realm="EXAMPLE.TEST",
                    kdc_ip="192.0.2.20",
                    spn_hostname="rdp.example.test",
                )
            )
        with self.assertRaisesRegex(ValueError, "not an IP"):
            validate_auth_attempt(
                request(
                    mechanism="kerberos",
                    login="tester@example.test",
                    realm="EXAMPLE.TEST",
                    kdc_ip="192.0.2.20",
                    spn_hostname="192.0.2.10",
                )
            )

    def test_login_password_port_timeout_and_fingerprint_are_validated(self):
        cases = (
            ({"login": " tester"}, "login"),
            ({"login": "DOMAIN\\user\\extra"}, "DOMAIN\\\\user"),
            ({"password": "bad\x00secret"}, "NUL"),
            ({"port": 0}, "port"),
            ({"timeout_seconds": float("inf")}, "timeout"),
            ({"expected_certificate_sha256": "not-a-hash"}, "64 hexadecimal"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(
                (TypeError, ValueError), message
            ):
                validate_auth_attempt(request(**overrides))


class AuthAttemptUtilityTests(unittest.TestCase):
    def test_dependency_versions_match_runtime_adapters_and_packaging_pins(self):
        self.assertEqual(
            EXPECTED_DEPENDENCY_VERSIONS["aardwolf"], AARDWOLF_VERSION
        )
        self.assertEqual(
            EXPECTED_DEPENDENCY_VERSIONS["asyauth"], ASYAUTH_VERSION
        )
        setup_source = (
            Path(__file__).resolve().parents[2] / "setup.py"
        ).read_text(encoding="utf-8")
        for package, version in EXPECTED_DEPENDENCY_VERSIONS.items():
            with self.subTest(package=package):
                self.assertIn(f'"{package}=={version}"', setup_source)

    def test_dependency_versions_must_match_exact_pins(self):
        installed = check_dependency_versions(
            lambda package: EXPECTED_DEPENDENCY_VERSIONS[package]
        )
        self.assertEqual(installed, EXPECTED_DEPENDENCY_VERSIONS)

        with self.assertRaisesRegex(DependencyVersionError, "unsupported aardwolf"):
            check_dependency_versions(
                lambda package: (
                    "99.0"
                    if package == "aardwolf"
                    else EXPECTED_DEPENDENCY_VERSIONS[package]
                )
            )

    def test_missing_dependency_is_structured(self):
        def missing(_package: str) -> str:
            raise importlib.metadata.PackageNotFoundError("aardwolf")

        with self.assertRaisesRegex(DependencyVersionError, "unavailable: aardwolf"):
            check_dependency_versions(missing)

    def test_ntstatus_parser_handles_signed_hresults_and_names(self):
        self.assertEqual(parse_ntstatus(-1073741715), 0xC000006D)
        self.assertEqual(
            parse_ntstatus("CredSSP failed, Code: 0xc0000418"), 0xC0000418
        )
        self.assertEqual(ntstatus_name(0xD000006D), "STATUS_LOGON_FAILURE")
        self.assertEqual(
            ntstatus_name(0xD000015B),
            "STATUS_LOGON_TYPE_NOT_GRANTED",
        )
        self.assertEqual(ntstatus_name(0xC0000418), "STATUS_NTLM_BLOCKED")
        self.assertIsNone(parse_ntstatus("connection closed without a status"))

    def test_tls_fingerprint_guard_uses_the_live_certificate(self):
        certificate = b"test RDP certificate"
        expected = certificate_sha256(certificate)
        self.assertEqual(
            verify_tls_fingerprint(expected.upper(), certificate),
            expected,
        )

        with self.assertRaisesRegex(TLSFingerprintError, "certificate changed"):
            verify_tls_fingerprint("0" * 64, certificate)
        with self.assertRaisesRegex(TLSFingerprintError, "did not provide"):
            verify_tls_fingerprint(expected, b"")

    def test_error_sanitizer_removes_password_and_identity(self):
        auth_request = request()
        message = sanitize_auth_error(
            "EXAMPLE\\tester used SuperSecretPassword; tester was rejected",
            auth_request,
        )

        self.assertNotIn(auth_request.login, message)
        self.assertNotIn(auth_request.password, message)
        self.assertNotIn("tester", message)
        self.assertIn("<redacted>", message)

    def test_error_sanitizer_removes_raw_and_serialized_credential_forms(self):
        domain = "DömAin"
        username = "UsérName\r\n\tTail"
        login = f"{domain}\\{username}"
        password = "Päss\\word\r\n\tTail!"
        auth_request = request(login=login, password=password)
        sensitive_values = (login, password, domain, username)
        variants = {
            variant
            for value in sensitive_values
            for variant in serialized_sensitive_variants(value)
        }
        message = " | ".join(sorted(variants, key=len, reverse=True))

        sanitized = sanitize_auth_error(message, auth_request)

        for variant in variants:
            with self.subTest(variant=variant):
                self.assertNotIn(variant.casefold(), sanitized.casefold())
        self.assertIn("<redacted>", sanitized)


class AuthAttemptRunnerTests(unittest.TestCase):
    def run_with(
        self,
        backend_result: BackendAttemptResult,
        *,
        auth_request: AuthAttemptRequest | None = None,
        clock: SequenceClock | None = None,
    ):
        backend = StubBackend(backend_result)
        factory = Mock(return_value=backend)
        result = run_auth_attempt(
            auth_request or request(),
            backend_factory=factory,
            clock=clock or SequenceClock(1.0, 1.125),
        )
        return result, backend, factory

    def test_success_reports_protocol_mechanism_authorization_and_duration(self):
        result, backend, factory = self.run_with(
            BackendAttemptResult(
                outcome=AuthOutcome.AUTHENTICATED,
                phase=AuthPhase.COMPLETE,
                selected_protocol=0x08,
                selected_mechanism="NTLMSSP",
                server_response_observed=True,
                connection_duration_ms=80.0,
                credssp_authenticated=True,
                session_established=True,
                rdp_authorized=True,
                evidence=("SPNEGO selected NTLMSSP",),
            )
        )

        factory.assert_called_once_with()
        self.assertEqual(len(backend.requests), 1)
        self.assertEqual(result.outcome, AuthOutcome.AUTHENTICATED)
        self.assertEqual(result.duration_ms, 125.0)
        self.assertEqual(result.connection_duration_ms, 80.0)
        self.assertEqual(result.selected_protocol_name, "HYBRID_EX")
        self.assertEqual(result.selected_mechanism, "NTLMSSP")
        self.assertTrue(result.server_response_observed)
        self.assertTrue(result.credssp_authenticated)
        self.assertTrue(result.session_established)
        self.assertTrue(result.rdp_authorized)

    def test_credssp_success_is_authentication_success_after_session_failure(self):
        outcome, phase, authorized = _classify_backend_failure(
            connected=False,
            error=RuntimeError("later RDP session setup failed"),
            code=None,
            phase=AuthPhase.SESSION,
            mechanism=AuthMechanism.NTLM,
            selected_protocol=0x02,
            credssp_authenticated=True,
        )

        self.assertIs(outcome, AuthOutcome.AUTHENTICATED)
        self.assertIs(phase, AuthPhase.CREDSSP)
        self.assertIsNone(authorized)

        result, _backend, _factory = self.run_with(
            BackendAttemptResult(
                outcome=AuthOutcome.INDETERMINATE,
                phase=phase,
                selected_protocol=0x02,
                connection_duration_ms=75.0,
                credssp_authenticated=True,
                session_established=False,
                rdp_authorized=authorized,
                error="later RDP session setup failed",
            )
        )
        self.assertIs(result.outcome, AuthOutcome.AUTHENTICATED)
        self.assertTrue(result.credssp_authenticated)
        self.assertFalse(result.session_established)
        self.assertIsNone(result.rdp_authorized)

    def test_backend_captures_credssp_success_before_later_session_failure(self):
        certificate = b"live RDP certificate"

        class FakeSettings:
            pass

        class FakeTarget:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        class FakeCredential:
            def __init__(self, *_args, **_kwargs):
                pass

        class FakeAuthContext:
            auth_ctx = None

            async def authenticate(self, *_args, **_kwargs):
                return None, False, None

        class FakeCredSSPCredential:
            def __init__(self, _credentials):
                pass

            def build_context(self):
                return FakeAuthContext()

        class FakeTransport:
            @staticmethod
            def get_peer_certificate():
                return certificate

        class FakeConnection:
            def __init__(self, target, _credential, _settings):
                self.target = target
                self.authapi = None
                self.x224_protocol = 0x02
                self._RDPConnection__connection = FakeTransport()

            async def credssp_auth(self):
                return True, None

            async def connect(self):
                authenticated, error = await self.credssp_auth()
                self.asserted_credssp_result = (authenticated, error)
                return False, RuntimeError("later RDP session setup failed")

            async def terminate(self):
                return True, None

        class FakeProtocols:
            HYBRID = 0x02
            HYBRID_EX = 0x08

        class FakeSecret:
            PASSWORD = object()

        class FakeTSRequest:
            @staticmethod
            def load(_token):
                raise AssertionError("no server token is expected in this fixture")

        modules = {
            "aardwolf.commons.iosettings": fake_module(
                "aardwolf.commons.iosettings", RDPIOSettings=FakeSettings
            ),
            "aardwolf.commons.target": fake_module(
                "aardwolf.commons.target", RDPTarget=FakeTarget
            ),
            "aardwolf.connection": fake_module(
                "aardwolf.connection", RDPConnection=FakeConnection
            ),
            "aardwolf.protocol.x224.constants": fake_module(
                "aardwolf.protocol.x224.constants", SUPP_PROTOCOLS=FakeProtocols
            ),
            "asyauth.common.constants": fake_module(
                "asyauth.common.constants", asyauthSecret=FakeSecret
            ),
            "asyauth.common.credentials.credssp": fake_module(
                "asyauth.common.credentials.credssp",
                CREDSSPCredential=FakeCredSSPCredential,
            ),
            "asyauth.common.credentials.ntlm": fake_module(
                "asyauth.common.credentials.ntlm", NTLMCredential=FakeCredential
            ),
            "asyauth.protocols.credssp.messages.asn1_structs": fake_module(
                "asyauth.protocols.credssp.messages.asn1_structs",
                TSRequest=FakeTSRequest,
            ),
        }

        auth_request = request(
            expected_certificate_sha256=certificate_sha256(certificate)
        )
        backend = AardwolfAuthBackend(
            version_getter=lambda package: EXPECTED_DEPENDENCY_VERSIONS[package]
        )
        with patch.dict(sys.modules, modules):
            result = backend.run(auth_request)

        self.assertIs(result.outcome, AuthOutcome.AUTHENTICATED)
        self.assertIs(result.phase, AuthPhase.CREDSSP)
        self.assertTrue(result.credssp_authenticated)
        self.assertFalse(result.session_established)
        self.assertIsNone(result.rdp_authorized)
        self.assertTrue(
            any("RDP session setup failed" in item for item in result.evidence)
        )

    def test_hybrid_ex_keeps_credential_auth_separate_from_authorization(self):
        certificate = b"live RDP certificate"

        def execute(
            authenticate_result: tuple[bytes | None, bool | None, Exception | None],
            *,
            server_error_code: int | None,
        ):
            auth_context = SimpleNamespace(
                auth_ctx=None,
                authenticate=AsyncMock(return_value=authenticate_result),
            )
            credssp_credential = Mock()
            credssp_credential.return_value.build_context.return_value = auth_context

            class FakeSettings:
                pass

            class FakeTarget:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs

            class FakeCredential:
                def __init__(self, *_args, **_kwargs):
                    pass

            class FakeTransport:
                @staticmethod
                def get_peer_certificate():
                    return certificate

            class FakeConnection:
                def __init__(self, _target, _credential, _settings):
                    self.authapi = None
                    self.x224_protocol = 0x08
                    self._RDPConnection__connection = FakeTransport()

                async def credssp_auth(self):
                    _data, _to_continue, error = await self.authapi.authenticate(
                        b"server CredSSP token"
                    )
                    if error is not None:
                        return None, error
                    return None, RuntimeError(
                        "Authentication failed! (early user auth)"
                    )

                async def connect(self):
                    return await self.credssp_auth()

                async def terminate(self):
                    return True, None

            class FakeProtocols:
                HYBRID = 0x02
                HYBRID_EX = 0x08

            class FakeSecret:
                PASSWORD = object()

            class FakeTSRequest:
                @staticmethod
                def load(_token):
                    return SimpleNamespace(
                        native={"errorCode": server_error_code}
                    )

            modules = {
                "aardwolf.commons.iosettings": fake_module(
                    "aardwolf.commons.iosettings", RDPIOSettings=FakeSettings
                ),
                "aardwolf.commons.target": fake_module(
                    "aardwolf.commons.target", RDPTarget=FakeTarget
                ),
                "aardwolf.connection": fake_module(
                    "aardwolf.connection", RDPConnection=FakeConnection
                ),
                "aardwolf.protocol.x224.constants": fake_module(
                    "aardwolf.protocol.x224.constants", SUPP_PROTOCOLS=FakeProtocols
                ),
                "asyauth.common.constants": fake_module(
                    "asyauth.common.constants", asyauthSecret=FakeSecret
                ),
                "asyauth.common.credentials.credssp": fake_module(
                    "asyauth.common.credentials.credssp",
                    CREDSSPCredential=credssp_credential,
                ),
                "asyauth.common.credentials.ntlm": fake_module(
                    "asyauth.common.credentials.ntlm", NTLMCredential=FakeCredential
                ),
                "asyauth.protocols.credssp.messages.asn1_structs": fake_module(
                    "asyauth.protocols.credssp.messages.asn1_structs",
                    TSRequest=FakeTSRequest,
                ),
            }
            backend = AardwolfAuthBackend(
                version_getter=lambda package: EXPECTED_DEPENDENCY_VERSIONS[package]
            )
            with patch.dict(sys.modules, modules):
                return backend.run(
                    request(
                        expected_certificate_sha256=certificate_sha256(certificate)
                    )
                )

        authorized_context = execute(
            (b"encrypted final credentials", False, None),
            server_error_code=None,
        )
        self.assertIs(authorized_context.outcome, AuthOutcome.AUTHENTICATED)
        self.assertIs(authorized_context.phase, AuthPhase.AUTHORIZATION)
        self.assertTrue(authorized_context.credssp_authenticated)
        self.assertFalse(authorized_context.session_established)
        self.assertIs(authorized_context.rdp_authorized, False)
        self.assertFalse(authorized_context.server_error_from_credssp)
        self.assertIn(
            "RDP authorization was denied after CredSSP authentication",
            authorized_context.evidence,
        )

        credential_rejection = execute(
            (None, None, RuntimeError("CredSSP credential rejection")),
            server_error_code=0xC000006D,
        )
        self.assertIs(credential_rejection.outcome, AuthOutcome.REJECTED)
        self.assertIs(credential_rejection.phase, AuthPhase.CREDSSP)
        self.assertFalse(credential_rejection.credssp_authenticated)
        self.assertIsNone(credential_rejection.rdp_authorized)
        self.assertTrue(credential_rejection.server_error_from_credssp)

    def test_kerberos_kdc_uses_the_configured_attempt_timeout(self):
        certificate = b"live RDP certificate"
        kdc_targets: list[tuple[tuple[object, ...], dict[str, object]]] = []

        class FakeSettings:
            pass

        class FakeRDPTarget:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        class FakeUniTarget:
            def __init__(self, *args, **kwargs):
                kdc_targets.append((args, kwargs))

        class FakeUniProto:
            CLIENT_TCP = object()

        class FakeCredential:
            def __init__(self, *_args, **_kwargs):
                pass

        auth_context = SimpleNamespace(
            auth_ctx=None,
            authenticate=AsyncMock(),
        )
        credssp_credential = Mock()
        credssp_credential.return_value.build_context.return_value = auth_context

        class FakeTransport:
            @staticmethod
            def get_peer_certificate():
                return certificate

        class FakeConnection:
            def __init__(self, _target, _credential, _settings):
                self.authapi = None
                self.x224_protocol = 0x08
                self._RDPConnection__connection = FakeTransport()

            async def credssp_auth(self):
                return True, None

            async def connect(self):
                return await self.credssp_auth()

            async def terminate(self):
                return True, None

        class FakeProtocols:
            HYBRID = 0x02
            HYBRID_EX = 0x08

        class FakeSecret:
            PASSWORD = object()

        modules = {
            "aardwolf.commons.iosettings": fake_module(
                "aardwolf.commons.iosettings", RDPIOSettings=FakeSettings
            ),
            "aardwolf.commons.target": fake_module(
                "aardwolf.commons.target", RDPTarget=FakeRDPTarget
            ),
            "aardwolf.connection": fake_module(
                "aardwolf.connection", RDPConnection=FakeConnection
            ),
            "aardwolf.protocol.x224.constants": fake_module(
                "aardwolf.protocol.x224.constants", SUPP_PROTOCOLS=FakeProtocols
            ),
            "asyauth.common.constants": fake_module(
                "asyauth.common.constants", asyauthSecret=FakeSecret
            ),
            "asyauth.common.credentials.credssp": fake_module(
                "asyauth.common.credentials.credssp",
                CREDSSPCredential=credssp_credential,
            ),
            "asyauth.common.credentials.kerberos": fake_module(
                "asyauth.common.credentials.kerberos",
                KerberosCredential=FakeCredential,
            ),
            "asyauth.protocols.credssp.messages.asn1_structs": fake_module(
                "asyauth.protocols.credssp.messages.asn1_structs",
                TSRequest=Mock(),
            ),
            "asysocks.unicomm.common.target": fake_module(
                "asysocks.unicomm.common.target",
                UniProto=FakeUniProto,
                UniTarget=FakeUniTarget,
            ),
        }
        auth_request = request(
            mechanism=AuthMechanism.KERBEROS,
            login="tester@example.test",
            realm="EXAMPLE.TEST",
            kdc_ip="192.0.2.20",
            spn_hostname="rdp.example.test",
            timeout_seconds=12.25,
            expected_certificate_sha256=certificate_sha256(certificate),
        )
        backend = AardwolfAuthBackend(
            version_getter=lambda package: EXPECTED_DEPENDENCY_VERSIONS[package]
        )

        with patch.dict(sys.modules, modules):
            result = backend.run(auth_request)

        self.assertIs(result.outcome, AuthOutcome.AUTHENTICATED)
        self.assertEqual(len(kdc_targets), 1)
        args, kwargs = kdc_targets[0]
        self.assertEqual(args[:2], ("192.0.2.20", 88))
        self.assertIs(args[2], FakeUniProto.CLIENT_TCP)
        self.assertEqual(kwargs["timeout"], 13)
        self.assertEqual(kwargs["dc_ip"], "192.0.2.20")

    def test_ntstatus_refines_generic_backend_outcomes(self):
        cases = (
            (
                "CredSSP Code: 0xc0000234",
                AuthOutcome.BLOCKED,
                "STATUS_ACCOUNT_LOCKED_OUT",
                AuthPhase.CREDSSP,
            ),
            (
                "CredSSP Code: 0xc0000418",
                AuthOutcome.BLOCKED,
                "STATUS_NTLM_BLOCKED",
                AuthPhase.CREDSSP,
            ),
            (
                "CredSSP Code: 0xd000006d",
                AuthOutcome.REJECTED,
                "STATUS_LOGON_FAILURE",
                AuthPhase.CREDSSP,
            ),
            (
                "CredSSP Code: 0xc0000224",
                AuthOutcome.REJECTED,
                "STATUS_PASSWORD_MUST_CHANGE",
                AuthPhase.CREDSSP,
            ),
            (
                "CredSSP Code: 0x80090311",
                AuthOutcome.PREREQUISITE_ERROR,
                "SEC_E_NO_AUTHENTICATING_AUTHORITY",
                AuthPhase.CREDSSP,
            ),
        )
        for error, outcome, status_name, phase in cases:
            with self.subTest(error=error):
                result, _backend, _factory = self.run_with(
                    BackendAttemptResult(
                        outcome=AuthOutcome.INDETERMINATE,
                        phase=phase,
                        error=error,
                    )
                )
                self.assertEqual(result.outcome, outcome)
                self.assertEqual(result.server_error_name, status_name)
                self.assertFalse(result.server_error_from_credssp)

    def test_access_denied_is_reported_as_authorization_failure(self):
        result, _backend, _factory = self.run_with(
            BackendAttemptResult(
                outcome=AuthOutcome.INDETERMINATE,
                phase=AuthPhase.CREDSSP,
                server_error_code=5,
                error="access denied",
            )
        )

        self.assertEqual(result.outcome, AuthOutcome.REJECTED)
        self.assertEqual(result.phase, AuthPhase.AUTHORIZATION)
        self.assertEqual(result.server_error_hex, "0x00000005")

    def test_logon_type_not_granted_is_a_direct_authorization_rejection(self):
        result, _backend, _factory = self.run_with(
            BackendAttemptResult(
                outcome=AuthOutcome.INDETERMINATE,
                phase=AuthPhase.CREDSSP,
                server_error_code=0xD000015B,
                server_error_from_credssp=True,
                rdp_authorized=False,
                error="CredSSP server rejected the requested logon type",
            )
        )

        self.assertEqual(result.outcome, AuthOutcome.REJECTED)
        self.assertEqual(result.phase, AuthPhase.AUTHORIZATION)
        self.assertEqual(result.server_error_hex, "0xd000015b")
        self.assertEqual(
            result.server_error_name,
            "STATUS_LOGON_TYPE_NOT_GRANTED",
        )
        self.assertTrue(result.server_error_from_credssp)
        self.assertFalse(result.rdp_authorized)

    def test_account_lockout_server_code_is_reported_as_blocked(self):
        result, _backend, _factory = self.run_with(
            BackendAttemptResult(
                outcome=AuthOutcome.REJECTED,
                phase=AuthPhase.CREDSSP,
                server_error_code=0xC0000234,
                server_error_from_credssp=True,
                error="CredSSP server rejected authentication",
            )
        )

        self.assertEqual(result.outcome, AuthOutcome.BLOCKED)
        self.assertEqual(result.server_error_name, "STATUS_ACCOUNT_LOCKED_OUT")
        self.assertEqual(result.server_error_hex, "0xc0000234")
        self.assertTrue(result.server_error_from_credssp)

    def test_exception_fallback_cannot_inherit_server_status_provenance(self):
        result, _backend, _factory = self.run_with(
            BackendAttemptResult(
                outcome=AuthOutcome.INDETERMINATE,
                phase=AuthPhase.CREDSSP,
                server_error_from_credssp=True,
                error="backend exception 0xc0000234",
            )
        )

        self.assertEqual(result.server_error_name, "STATUS_ACCOUNT_LOCKED_OUT")
        self.assertFalse(result.server_error_from_credssp)

    def test_backend_errors_and_evidence_are_sanitized(self):
        auth_request = request()
        result, _backend, _factory = self.run_with(
            BackendAttemptResult(
                outcome=AuthOutcome.REJECTED,
                phase=AuthPhase.CREDSSP,
                selected_mechanism=f"NTLM for {auth_request.login}",
                error=f"{auth_request.login}: {auth_request.password}",
                evidence=(f"attempt for {auth_request.login}",),
            ),
            auth_request=auth_request,
        )

        serialized = str(asdict(result))
        self.assertNotIn(auth_request.login, serialized)
        self.assertNotIn(auth_request.password, serialized)
        self.assertIn("<redacted>", serialized)

    def test_unexpected_backend_exception_is_sanitized(self):
        auth_request = request()

        class ExplodingBackend:
            def run(self, _request):
                raise RuntimeError(
                    f"adapter failed for {auth_request.login} using "
                    f"{auth_request.password}"
                )

        result = run_auth_attempt(
            auth_request,
            backend_factory=ExplodingBackend,
            clock=SequenceClock(5.0, 5.01),
        )

        self.assertEqual(result.outcome, AuthOutcome.ERROR)
        self.assertNotIn(auth_request.login, result.error)
        self.assertNotIn(auth_request.password, result.error)

    def test_invalid_request_never_calls_backend(self):
        factory = Mock()
        result = run_auth_attempt(
            request(port=0),
            backend_factory=factory,
            clock=SequenceClock(1.0, 1.001),
        )

        self.assertEqual(result.outcome, AuthOutcome.PREREQUISITE_ERROR)
        self.assertEqual(result.phase, AuthPhase.VALIDATION)
        factory.assert_not_called()

    def test_default_backend_enforces_dependency_pins_before_network_use(self):
        result = run_auth_attempt(
            request(),
            version_getter=lambda package: (
                "99.0"
                if package == "aardwolf"
                else EXPECTED_DEPENDENCY_VERSIONS[package]
            ),
            clock=SequenceClock(1.0, 1.001),
        )

        self.assertEqual(result.outcome, AuthOutcome.PREREQUISITE_ERROR)
        self.assertEqual(result.phase, AuthPhase.DEPENDENCY)
        self.assertIn("unsupported aardwolf version", result.error)

    def test_non_request_object_is_a_structured_validation_error(self):
        factory = Mock()
        result = run_auth_attempt(
            object(),
            backend_factory=factory,
            clock=SequenceClock(1.0, 1.001),
        )

        self.assertEqual(result.outcome, AuthOutcome.PREREQUISITE_ERROR)
        self.assertEqual(result.phase, AuthPhase.VALIDATION)
        self.assertIn("AuthAttemptRequest", result.error)
        factory.assert_not_called()

    def test_each_call_creates_a_fresh_backend(self):
        backends: list[StubBackend] = []

        def factory() -> StubBackend:
            backend = StubBackend(
                BackendAttemptResult(
                    outcome=AuthOutcome.REJECTED,
                    phase=AuthPhase.CREDSSP,
                )
            )
            backends.append(backend)
            return backend

        for _ in range(2):
            run_auth_attempt(
                request(),
                backend_factory=factory,
                clock=SequenceClock(1.0, 1.1),
            )

        self.assertEqual(len(backends), 2)
        self.assertIsNot(backends[0], backends[1])
        self.assertEqual([len(backend.requests) for backend in backends], [1, 1])

    def test_kerberos_prerequisite_status_is_attributed_to_kdc_phase(self):
        auth_request = request(
            mechanism=AuthMechanism.KERBEROS,
            login="tester@example.test",
            realm="EXAMPLE.TEST",
            kdc_ip="192.0.2.20",
            spn_hostname="rdp.example.test",
        )
        result, _backend, _factory = self.run_with(
            BackendAttemptResult(
                outcome=AuthOutcome.INDETERMINATE,
                phase=AuthPhase.CREDSSP,
                server_error_code=0x80090311,
                error="no authenticating authority",
            ),
            auth_request=auth_request,
        )

        self.assertEqual(result.outcome, AuthOutcome.PREREQUISITE_ERROR)
        self.assertEqual(result.mechanism, AuthMechanism.KERBEROS)
        self.assertEqual(result.phase, AuthPhase.KDC)


if __name__ == "__main__":
    unittest.main()
