"""Fresh, structured RDP CredSSP authentication attempts.

This module deliberately does not share the authenticated-session cache used by
the main RDP engine.  Every call to :func:`run_auth_attempt` creates a new
backend and the default backend creates one new TCP/RDP connection.  That makes
the primitive suitable for authentication-method, username-enumeration and
password-guessing tests, where an attempt's response and duration must be
attributable to one connection.

Only password credentials are supported here.  A certificate used for
Kerberos PKINIT is not equivalent to an RDP smart-card logon; the pinned
aardwolf/asyauth stack does not implement the required smart-card credential
delegation and redirection path.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import importlib.metadata
import ipaddress
import json
import logging
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Protocol

EXPECTED_DEPENDENCY_VERSIONS = {
    "aardwolf": "0.2.13",
    "asyauth": "0.0.23",
    "asysocks": "0.2.18",
}

PROTOCOL_HYBRID = 0x00000002
PROTOCOL_HYBRID_EX = 0x00000008
_AUTH_PROTOCOLS = {PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX}
_MAX_ERROR_LENGTH = 500


class AuthMechanism(str, Enum):
    NTLM = "ntlm"
    KERBEROS = "kerberos"


class CredentialKind(str, Enum):
    PASSWORD = "password"


class CredentialSource(str, Enum):
    PROVIDED = "provided"
    GENERATED = "generated"


class TLSVerification(str, Enum):
    VERIFIED = "verified"
    INSECURE = "insecure"


class AuthPhase(str, Enum):
    VALIDATION = "validation"
    DEPENDENCY = "dependency"
    TCP = "tcp"
    X224 = "x224"
    TLS = "tls"
    KDC = "kdc"
    SPNEGO = "spnego"
    CREDSSP = "credssp"
    AUTHORIZATION = "authorization"
    SESSION = "session"
    COMPLETE = "complete"


class AuthOutcome(str, Enum):
    AUTHENTICATED = "authenticated"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    NOT_SUPPORTED = "not_supported"
    PREREQUISITE_ERROR = "prerequisite_error"
    TLS_ERROR = "tls_error"
    TRANSPORT_ERROR = "transport_error"
    TIMEOUT = "timeout"
    INDETERMINATE = "indeterminate"
    ERROR = "error"


class AuthAttemptError(RuntimeError):
    """Base class for errors local to the attempt adapter."""


class DependencyVersionError(AuthAttemptError):
    """A pinned authentication dependency is absent or has the wrong version."""


class TLSFingerprintError(AuthAttemptError):
    """The live CredSSP TLS peer does not match the validated preflight peer."""


@dataclass(frozen=True)
class AuthAttemptRequest:
    host: str
    port: int
    login: str = field(repr=False)
    password: str = field(repr=False)
    mechanism: AuthMechanism | str
    expected_certificate_sha256: str
    server_hostname: str | None = None
    tls_verification: TLSVerification | str = TLSVerification.VERIFIED
    timeout_seconds: float = 10.0
    credential_source: CredentialSource | str = CredentialSource.PROVIDED
    realm: str | None = None
    kdc_ip: str | None = None
    spn_hostname: str | None = None


@dataclass(frozen=True)
class BackendAttemptResult:
    """Result returned by a backend before common sanitization/classification."""

    outcome: AuthOutcome
    phase: AuthPhase
    selected_protocol: int | None = None
    selected_mechanism: str | None = None
    server_response_observed: bool = False
    connection_duration_ms: float | None = None
    credssp_authenticated: bool = False
    session_established: bool = False
    rdp_authorized: bool | None = None
    server_error_code: int | None = None
    server_error_from_credssp: bool = False
    error: object | None = None
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthAttemptResult:
    mechanism: AuthMechanism
    credential_kind: CredentialKind
    credential_source: CredentialSource
    outcome: AuthOutcome
    phase: AuthPhase
    duration_ms: float
    connection_duration_ms: float | None = None
    selected_protocol: int | None = None
    selected_protocol_name: str | None = None
    selected_mechanism: str | None = None
    server_response_observed: bool = False
    credssp_authenticated: bool = False
    session_established: bool = False
    rdp_authorized: bool | None = None
    tls_verification: TLSVerification | None = None
    certificate_sha256: str | None = None
    server_error_code: int | None = None
    server_error_name: str | None = None
    server_error_from_credssp: bool = False
    error: str | None = None
    evidence: tuple[str, ...] = ()

    @property
    def server_error_hex(self) -> str | None:
        if self.server_error_code is None:
            return None
        return f"0x{self.server_error_code:08x}"


class AuthAttemptBackend(Protocol):
    def run(self, request: AuthAttemptRequest) -> BackendAttemptResult:
        """Execute exactly one fresh authentication attempt."""


BackendFactory = Callable[[], AuthAttemptBackend]
VersionGetter = Callable[[str], str]


_NTSTATUS_NAMES = {
    0x00000005: "AUTHZ_ACCESS_DENIED",
    0x8009030C: "SEC_E_LOGON_DENIED",
    0x80090311: "SEC_E_NO_AUTHENTICATING_AUTHORITY",
    0x8009033D: "SEC_E_PKINIT_NAME_MISMATCH",
    0x8009033E: "SEC_E_SMARTCARD_LOGON_REQUIRED",
    0xC000005E: "STATUS_NO_LOGON_SERVERS",
    0xC0000064: "STATUS_NO_SUCH_USER",
    0xC000006A: "STATUS_WRONG_PASSWORD",
    0xC000006D: "STATUS_LOGON_FAILURE",
    0xC000006E: "STATUS_ACCOUNT_RESTRICTION",
    0xC000006F: "STATUS_INVALID_LOGON_HOURS",
    0xC0000070: "STATUS_INVALID_WORKSTATION",
    0xC0000071: "STATUS_PASSWORD_EXPIRED",
    0xC0000072: "STATUS_ACCOUNT_DISABLED",
    0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
    0xC0000193: "STATUS_ACCOUNT_EXPIRED",
    0xC0000224: "STATUS_PASSWORD_MUST_CHANGE",
    0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
    0xC0000418: "STATUS_NTLM_BLOCKED",
}

_REJECTED_CODES = {
    0x00000005,
    0x8009030C,
    0x8009033D,
    0x8009033E,
    0xC0000064,
    0xC000006A,
    0xC000006D,
    0xC000006E,
    0xC000006F,
    0xC0000070,
    0xC0000071,
    0xC0000072,
    0xC000015B,
    0xC0000193,
    0xC0000224,
}
_PREREQUISITE_CODES = {0x80090311, 0xC000005E}
_BLOCKED_CODES = {
    0xC0000234,  # STATUS_ACCOUNT_LOCKED_OUT
    0xC0000418,  # STATUS_NTLM_BLOCKED
}
_AUTHORIZATION_CODES = {
    0x00000005,  # AUTHZ_ACCESS_DENIED
    0xC000015B,  # STATUS_LOGON_TYPE_NOT_GRANTED
}


def _canonical_ntstatus(code: int) -> int:
    code &= 0xFFFFFFFF
    # Authentication Result PDUs sometimes carry HRESULT_FROM_NT values where
    # the NT bit changes the leading C to D.  Use the underlying NTSTATUS for
    # classification while preserving the original value in result output.
    if code & 0xF0000000 == 0xD0000000:
        return code & ~0x10000000
    return code


def ntstatus_name(code: int | None) -> str | None:
    if code is None:
        return None
    return _NTSTATUS_NAMES.get(_canonical_ntstatus(code))


def parse_ntstatus(value: object) -> int | None:
    """Extract a 32-bit status from an integer or an error containing hex."""

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value & 0xFFFFFFFF
    if value is None:
        return None

    for match in re.finditer(r"(?i)\b0x([0-9a-f]{1,8})\b", str(value)):
        return int(match.group(1), 16) & 0xFFFFFFFF
    return None


def check_dependency_versions(
    version_getter: VersionGetter = importlib.metadata.version,
) -> dict[str, str]:
    """Require the exact authentication-stack versions tested by this adapter."""

    installed: dict[str, str] = {}
    for package, expected in EXPECTED_DEPENDENCY_VERSIONS.items():
        try:
            actual = version_getter(package)
        except importlib.metadata.PackageNotFoundError as exc:
            raise DependencyVersionError(
                f"RDP authentication dependency is unavailable: {package}"
            ) from exc
        if actual != expected:
            raise DependencyVersionError(
                f"unsupported {package} version {actual}; expected {expected}"
            )
        installed[package] = actual
    return installed


def certificate_sha256(certificate_der: bytes) -> str:
    if not isinstance(certificate_der, bytes) or not certificate_der:
        raise TLSFingerprintError("RDP server did not provide a TLS certificate")
    return hashlib.sha256(certificate_der).hexdigest()


def verify_tls_fingerprint(expected_sha256: str, certificate_der: bytes) -> str:
    expected = _validate_fingerprint(expected_sha256)
    actual = certificate_sha256(certificate_der)
    if not hmac.compare_digest(actual, expected):
        raise TLSFingerprintError(
            "RDP TLS certificate changed between validation and authentication"
        )
    return actual


def _enum_value(enum_type, value, field_name: str):
    try:
        return value if isinstance(value, enum_type) else enum_type(str(value).lower())
    except ValueError as exc:
        choices = ", ".join(item.value for item in enum_type)
        raise ValueError(f"{field_name} must be one of: {choices}") from exc


def _validate_text(value: object, field_name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must not be empty or padded with whitespace")
    if "\x00" in value:
        raise ValueError(f"{field_name} must not contain NUL characters")
    if len(value) > maximum:
        raise ValueError(f"{field_name} is too long")
    return value


def _split_login(login: str) -> tuple[str | None, str]:
    login = _validate_text(login, "login", 512)
    if "\\" in login:
        domain, username = login.split("\\", 1)
        if not domain or not username or "\\" in username:
            raise ValueError("login must use DOMAIN\\user format")
        return domain, username
    if "@" in login:
        username, domain = login.rsplit("@", 1)
        if not domain or not username or "@" in username:
            raise ValueError("login must use user@domain format")
        return domain, username
    return None, login


def _validate_password(password: object) -> str:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if "\x00" in password:
        raise ValueError("password must not contain NUL characters")
    if len(password) > 4096:
        raise ValueError("password is too long")
    return password


def _validate_fingerprint(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise ValueError(
            "expected_certificate_sha256 must contain 64 hexadecimal characters"
        )
    return value.lower()


def _validate_spn_hostname(value: object) -> str:
    hostname = _validate_text(value, "spn_hostname", 253)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("spn_hostname must be a DNS hostname, not an IP address")
    if any(character in hostname for character in "/@:\\"):
        raise ValueError("spn_hostname must not contain a port, SPN prefix, or realm")
    labels = hostname.rstrip(".").split(".")
    if any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?", label)
        is None
        for label in labels
    ):
        raise ValueError("spn_hostname is not a valid DNS hostname")
    return hostname.rstrip(".").lower()


def validate_auth_attempt(request: AuthAttemptRequest) -> AuthAttemptRequest:
    """Validate and normalize an attempt without performing network activity."""

    if not isinstance(request, AuthAttemptRequest):
        raise TypeError("request must be an AuthAttemptRequest")
    host = _validate_text(request.host, "host", 253)
    server_hostname = _validate_text(
        request.server_hostname or host,
        "server_hostname",
        253,
    )
    if not isinstance(request.port, int) or isinstance(request.port, bool):
        raise TypeError("port must be an integer")
    if request.port < 1 or request.port > 65535:
        raise ValueError("port must be between 1 and 65535")
    login_domain, _username = _split_login(request.login)
    password = _validate_password(request.password)
    mechanism = _enum_value(AuthMechanism, request.mechanism, "mechanism")
    tls_verification = _enum_value(
        TLSVerification, request.tls_verification, "tls_verification"
    )
    credential_source = _enum_value(
        CredentialSource, request.credential_source, "credential_source"
    )
    if (
        not isinstance(request.timeout_seconds, (int, float))
        or isinstance(request.timeout_seconds, bool)
        or not math.isfinite(float(request.timeout_seconds))
        or request.timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be a positive finite number")

    realm = request.realm
    kdc_ip = request.kdc_ip
    spn_hostname = request.spn_hostname
    if mechanism is AuthMechanism.KERBEROS:
        realm = _validate_text(realm, "realm", 255).upper()
        if login_domain and "@" in request.login and login_domain.upper() != realm:
            raise ValueError("login UPN domain must match the explicit Kerberos realm")
        kdc_ip = str(ipaddress.ip_address(_validate_text(kdc_ip, "kdc_ip", 64)))
        spn_hostname = _validate_spn_hostname(spn_hostname)

    return replace(
        request,
        host=host,
        server_hostname=server_hostname,
        password=password,
        mechanism=mechanism,
        expected_certificate_sha256=_validate_fingerprint(
            request.expected_certificate_sha256
        ),
        tls_verification=tls_verification,
        credential_source=credential_source,
        timeout_seconds=float(request.timeout_seconds),
        realm=realm,
        kdc_ip=kdc_ip,
        spn_hostname=spn_hostname,
    )


def _sensitive_values(request: object) -> tuple[str, ...]:
    password = getattr(request, "password", None)
    login = getattr(request, "login", None)
    values = [value for value in (password, login) if isinstance(value, str)]
    try:
        domain, username = _split_login(login)
    except (TypeError, ValueError):
        return tuple(value for value in values if value)
    values.extend((username, domain))
    return tuple(dict.fromkeys(value for value in values if value))


def _sensitive_variants(values: tuple[str, ...]) -> tuple[str, ...]:
    """Return raw and commonly serialized forms of credential values."""

    variants: set[str] = set()
    for sensitive in values:
        rendered = (
            sensitive,
            repr(sensitive),
            ascii(sensitive),
            sensitive.encode("unicode_escape").decode("ascii"),
            json.dumps(sensitive),
            json.dumps(sensitive, ensure_ascii=False),
        )
        for value in rendered:
            if not value:
                continue
            variants.add(value)
            if (
                len(value) >= 2
                and value[0] in {'"', "'"}
                and value[-1] == value[0]
            ):
                variants.add(value[1:-1])
    return tuple(sorted(variants, key=len, reverse=True))


def sanitize_sensitive_text(error: object, *sensitive_values: str | None) -> str:
    """Redact raw and escaped forms of sensitive strings from diagnostic text."""

    message = str(error).strip() or error.__class__.__name__
    values = tuple(value for value in sensitive_values if value)
    for sensitive in _sensitive_variants(values):
        if len(sensitive) <= 2:
            pattern = rf"(?<![\w@.\\-]){re.escape(sensitive)}(?![\w@.\\-])"
        else:
            pattern = re.escape(sensitive)
        message = re.sub(pattern, "<redacted>", message, flags=re.IGNORECASE)
    if len(message) > _MAX_ERROR_LENGTH:
        message = f"{message[: _MAX_ERROR_LENGTH - 3]}..."
    return message


def sanitize_auth_error(error: object, request: object) -> str:
    return sanitize_sensitive_text(error, *_sensitive_values(request))


def _protocol_name(protocol: int | None) -> str | None:
    return {
        PROTOCOL_HYBRID: "HYBRID",
        PROTOCOL_HYBRID_EX: "HYBRID_EX",
    }.get(protocol, f"UNKNOWN(0x{protocol:08x})" if protocol is not None else None)


def _status_outcome(code: int | None) -> AuthOutcome | None:
    if code is None:
        return None
    canonical = _canonical_ntstatus(code)
    if canonical in _BLOCKED_CODES:
        return AuthOutcome.BLOCKED
    if canonical in _PREREQUISITE_CODES:
        return AuthOutcome.PREREQUISITE_ERROR
    if canonical in _REJECTED_CODES:
        return AuthOutcome.REJECTED
    return None


def _result_for_local_error(
    request: object,
    *,
    outcome: AuthOutcome,
    phase: AuthPhase,
    started: float,
    clock: Callable[[], float],
    error: object,
) -> AuthAttemptResult:
    try:
        mechanism = _enum_value(
            AuthMechanism,
            getattr(request, "mechanism", AuthMechanism.NTLM),
            "mechanism",
        )
    except (TypeError, ValueError):
        mechanism = AuthMechanism.NTLM
    try:
        source = _enum_value(
            CredentialSource,
            getattr(request, "credential_source", CredentialSource.PROVIDED),
            "credential_source",
        )
    except (TypeError, ValueError):
        source = CredentialSource.PROVIDED
    return AuthAttemptResult(
        mechanism=mechanism,
        credential_kind=CredentialKind.PASSWORD,
        credential_source=source,
        outcome=outcome,
        phase=phase,
        duration_ms=max(0.0, (clock() - started) * 1000.0),
        error=sanitize_auth_error(error, request),
    )


def run_auth_attempt(
    request: AuthAttemptRequest,
    *,
    backend_factory: BackendFactory | None = None,
    version_getter: VersionGetter = importlib.metadata.version,
    clock: Callable[[], float] = time.monotonic,
) -> AuthAttemptResult:
    """Run one password authentication attempt on one fresh backend connection."""

    started = clock()
    try:
        validated = validate_auth_attempt(request)
    except (TypeError, ValueError) as exc:
        return _result_for_local_error(
            request,
            outcome=AuthOutcome.PREREQUISITE_ERROR,
            phase=AuthPhase.VALIDATION,
            started=started,
            clock=clock,
            error=exc,
        )

    if backend_factory is None:
        backend_factory = lambda: AardwolfAuthBackend(version_getter=version_getter)

    try:
        backend = backend_factory()
        raw = backend.run(validated)
        if not isinstance(raw, BackendAttemptResult):
            raise TypeError("authentication backend returned an invalid result")
    except DependencyVersionError as exc:
        return _result_for_local_error(
            validated,
            outcome=AuthOutcome.PREREQUISITE_ERROR,
            phase=AuthPhase.DEPENDENCY,
            started=started,
            clock=clock,
            error=exc,
        )
    except TLSFingerprintError as exc:
        return _result_for_local_error(
            validated,
            outcome=AuthOutcome.TLS_ERROR,
            phase=AuthPhase.TLS,
            started=started,
            clock=clock,
            error=exc,
        )
    except TimeoutError as exc:
        return _result_for_local_error(
            validated,
            outcome=AuthOutcome.TIMEOUT,
            phase=AuthPhase.TCP,
            started=started,
            clock=clock,
            error=exc,
        )
    except Exception as exc:  # noqa: BLE001 - backend boundary
        return _result_for_local_error(
            validated,
            outcome=AuthOutcome.ERROR,
            phase=AuthPhase.SESSION,
            started=started,
            clock=clock,
            error=exc,
        )

    code = raw.server_error_code
    server_error_from_credssp = (
        raw.server_error_from_credssp is True
        and isinstance(code, int)
        and not isinstance(code, bool)
    )
    if code is None:
        code = parse_ntstatus(raw.error)
    elif not isinstance(code, int) or isinstance(code, bool):
        code = parse_ntstatus(code)
        server_error_from_credssp = False
    else:
        code &= 0xFFFFFFFF

    # A successful CredSSP exchange proves that the supplied credentials were
    # accepted.  A status discovered during later RDP session setup must not
    # rewrite that authentication result into a credential rejection.
    outcome = (
        AuthOutcome.AUTHENTICATED
        if raw.credssp_authenticated
        else _status_outcome(code) or raw.outcome
    )
    phase = raw.phase
    if (
        not raw.credssp_authenticated
        and code is not None
        and _canonical_ntstatus(code) in _AUTHORIZATION_CODES
    ):
        phase = AuthPhase.AUTHORIZATION
    elif (
        outcome is AuthOutcome.PREREQUISITE_ERROR
        and validated.mechanism is AuthMechanism.KERBEROS
    ):
        phase = AuthPhase.KDC

    evidence = tuple(
        sanitize_auth_error(item, validated) for item in raw.evidence if item
    )
    error = sanitize_auth_error(raw.error, validated) if raw.error is not None else None
    selected_mechanism = (
        sanitize_auth_error(raw.selected_mechanism, validated)
        if raw.selected_mechanism is not None
        else None
    )
    duration_ms = max(0.0, (clock() - started) * 1000.0)
    connection_duration_ms = raw.connection_duration_ms
    if (
        isinstance(connection_duration_ms, bool)
        or (
            connection_duration_ms is not None
            and (
                not isinstance(connection_duration_ms, (int, float))
                or not math.isfinite(float(connection_duration_ms))
                or connection_duration_ms < 0
            )
        )
    ):
        connection_duration_ms = None

    # Keep sensitive values out of the returned object.  Only method metadata,
    # protocol evidence and the already validated public certificate hash remain.
    return AuthAttemptResult(
        mechanism=validated.mechanism,
        credential_kind=CredentialKind.PASSWORD,
        credential_source=validated.credential_source,
        outcome=outcome,
        phase=phase,
        duration_ms=duration_ms,
        connection_duration_ms=(
            float(connection_duration_ms)
            if connection_duration_ms is not None
            else None
        ),
        selected_protocol=raw.selected_protocol,
        selected_protocol_name=_protocol_name(raw.selected_protocol),
        selected_mechanism=selected_mechanism,
        server_response_observed=raw.server_response_observed,
        credssp_authenticated=raw.credssp_authenticated,
        session_established=raw.session_established,
        rdp_authorized=raw.rdp_authorized,
        tls_verification=validated.tls_verification,
        certificate_sha256=validated.expected_certificate_sha256,
        server_error_code=code,
        server_error_name=ntstatus_name(code),
        server_error_from_credssp=server_error_from_credssp,
        error=error,
        evidence=evidence,
    )


_AARDWOLF_ATTEMPT_LOCK = threading.Lock()


class AardwolfAuthBackend:
    """Pinned aardwolf/asyauth adapter that opens one connection per ``run``."""

    def __init__(self, *, version_getter: VersionGetter = importlib.metadata.version):
        self._version_getter = version_getter

    def run(self, request: AuthAttemptRequest) -> BackendAttemptResult:
        check_dependency_versions(self._version_getter)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "synchronous RDP authentication cannot run inside an asyncio event loop"
            )

        with _AARDWOLF_ATTEMPT_LOCK:
            loggers = [logging.getLogger("aardwolf"), logging.getLogger("asyauth")]
            previous = [logger.disabled for logger in loggers]
            for logger in loggers:
                logger.disabled = True
            try:
                return asyncio.run(self._run_once(request))
            finally:
                for logger, disabled in zip(loggers, previous, strict=True):
                    logger.disabled = disabled

    async def _run_once(self, request: AuthAttemptRequest) -> BackendAttemptResult:
        # Imports stay local so help/discovery and unit tests do not eagerly load
        # the comparatively large RDP stack.
        from aardwolf.commons.iosettings import RDPIOSettings
        from aardwolf.commons.target import RDPTarget
        from aardwolf.connection import RDPConnection
        from aardwolf.protocol.x224.constants import SUPP_PROTOCOLS
        from asyauth.common.constants import asyauthSecret
        from asyauth.common.credentials.credssp import CREDSSPCredential
        from asyauth.protocols.credssp.messages.asn1_structs import TSRequest

        login_domain, username = _split_login(request.login)
        if request.mechanism is AuthMechanism.NTLM:
            from asyauth.common.credentials.ntlm import NTLMCredential

            domain = login_domain
            credential = NTLMCredential(
                request.password,
                username,
                domain,
                asyauthSecret.PASSWORD,
            )
            target_hostname = request.server_hostname or request.host
            target_domain = domain
            target_dc_ip = None
        else:
            from asyauth.common.credentials.kerberos import KerberosCredential
            from asysocks.unicomm.common.target import UniProto, UniTarget

            domain = request.realm
            kdc_target = UniTarget(
                request.kdc_ip,
                88,
                UniProto.CLIENT_TCP,
                timeout=max(1, math.ceil(request.timeout_seconds)),
                dc_ip=request.kdc_ip,
            )
            credential = KerberosCredential(
                request.password,
                username,
                request.realm,
                asyauthSecret.PASSWORD,
                target=kdc_target,
            )
            target_hostname = request.spn_hostname
            target_domain = request.realm
            target_dc_ip = request.kdc_ip

        settings = RDPIOSettings()
        settings.channels = []
        settings.clipboard_use_pyperclip = False
        settings.supported_protocols = SUPP_PROTOCOLS.HYBRID | SUPP_PROTOCOLS.HYBRID_EX
        target = RDPTarget(
            ip=request.host,
            port=request.port,
            hostname=target_hostname,
            timeout=max(1, math.ceil(request.timeout_seconds)),
            domain=target_domain,
            dc_ip=target_dc_ip,
            unsafe_ssl=request.tls_verification is TLSVerification.INSECURE,
        )
        connection = RDPConnection(target, credential, settings)
        authapi = CREDSSPCredential([credential]).build_context()
        connection.authapi = authapi

        state: dict[str, object] = {
            "phase": AuthPhase.TCP,
            "fingerprint_verified": False,
            "server_error_code": None,
            "server_error_from_credssp": False,
            "selected_mechanism": None,
            "server_response_observed": False,
            "credssp_authenticated": False,
        }
        original_authenticate = authapi.authenticate
        authenticate_calls = 0

        async def capturing_authenticate(token, *args, **kwargs):
            nonlocal authenticate_calls
            authenticate_calls += 1
            state["phase"] = (
                AuthPhase.KDC
                if request.mechanism is AuthMechanism.KERBEROS
                and authenticate_calls == 1
                else AuthPhase.SPNEGO
            )
            if token:
                state["server_response_observed"] = True
                try:
                    error_code = TSRequest.load(token).native.get("errorCode")
                    if error_code is not None:
                        state["server_error_code"] = int(error_code) & 0xFFFFFFFF
                        state["server_error_from_credssp"] = True
                        state["phase"] = AuthPhase.CREDSSP
                except Exception:  # noqa: BLE001, S110 - parser boundary
                    # A malformed/non-TSRequest token is handled by asyauth.  It
                    # must not hide the original protocol error.
                    pass
            result = await original_authenticate(token, *args, **kwargs)
            selected = getattr(
                getattr(authapi, "auth_ctx", None),
                "selected_authentication_context_name",
                None,
            )
            if selected:
                state["selected_mechanism"] = str(selected)
            if (
                token
                and len(result) >= 3
                and result[0] is not None
                and result[1] is False
                and result[2] is None
            ):
                # asyauth returns ``to_continue=False`` only after the server
                # has accepted the underlying SPNEGO security context and the
                # client has produced its final encrypted credential token.
                # HYBRID_EX can still reject the subsequent RDP authorization,
                # which must not rewrite this credential-authentication fact.
                state["credssp_authenticated"] = True
                state["phase"] = AuthPhase.CREDSSP
            if result[2] is None and state["server_response_observed"]:
                state["phase"] = AuthPhase.CREDSSP
            return result

        authapi.authenticate = capturing_authenticate
        original_credssp_auth = connection.credssp_auth

        async def certificate_guarded_credssp_auth():
            state["phase"] = AuthPhase.TLS
            transport = getattr(connection, "_RDPConnection__connection", None)
            if transport is None or not hasattr(transport, "get_peer_certificate"):
                return None, TLSFingerprintError(
                    "aardwolf TLS transport is unavailable"
                )
            try:
                verify_tls_fingerprint(
                    request.expected_certificate_sha256,
                    transport.get_peer_certificate(),
                )
            except (TLSFingerprintError, TypeError, ValueError) as exc:
                return None, exc
            state["fingerprint_verified"] = True
            state["phase"] = (
                AuthPhase.KDC
                if request.mechanism is AuthMechanism.KERBEROS
                else AuthPhase.SPNEGO
            )
            authenticated, error = await original_credssp_auth()
            if authenticated is True and error is None:
                state["credssp_authenticated"] = True
                state["phase"] = AuthPhase.CREDSSP
            return authenticated, error

        connection.credssp_auth = certificate_guarded_credssp_auth
        connected = False
        connect_error: object | None = None
        response_started = time.perf_counter()
        connection_duration_ms: float | None = None
        try:
            state["phase"] = AuthPhase.X224
            try:
                connected, connect_error = await asyncio.wait_for(
                    connection.connect(), timeout=request.timeout_seconds
                )
            except TimeoutError as exc:
                connect_error = exc
            connection_duration_ms = max(
                0.0,
                (time.perf_counter() - response_started) * 1000.0,
            )
        finally:
            try:
                await asyncio.wait_for(
                    connection.terminate(),
                    timeout=min(5.0, max(1.0, request.timeout_seconds)),
                )
            except (Exception, asyncio.CancelledError):  # noqa: BLE001, S110
                pass

        selected_protocol = (
            int(connection.x224_protocol)
            if getattr(connection, "x224_protocol", None) is not None
            else None
        )
        code = state["server_error_code"]
        if code is None:
            code = parse_ntstatus(connect_error)
        outcome, phase, authorized = _classify_backend_failure(
            connected=bool(connected),
            error=connect_error,
            code=code,
            phase=state["phase"],
            mechanism=request.mechanism,
            selected_protocol=selected_protocol,
            credssp_authenticated=bool(state["credssp_authenticated"]),
        )
        evidence: list[str] = []
        if state["fingerprint_verified"]:
            evidence.append("live TLS certificate matched the preflight SHA-256")
        if state["selected_mechanism"]:
            evidence.append(f"SPNEGO selected {state['selected_mechanism']}")
        if state["server_response_observed"]:
            evidence.append("CredSSP server token received")
        if state["credssp_authenticated"]:
            evidence.append("CredSSP authentication completed")
            if authorized is False:
                evidence.append(
                    "RDP authorization was denied after CredSSP authentication"
                )
            elif not connected or connect_error is not None:
                evidence.append(
                    "RDP session setup failed after CredSSP authentication"
                )

        return BackendAttemptResult(
            outcome=outcome,
            phase=phase,
            selected_protocol=selected_protocol,
            selected_mechanism=state["selected_mechanism"],
            server_response_observed=bool(state["server_response_observed"]),
            connection_duration_ms=connection_duration_ms,
            credssp_authenticated=bool(state["credssp_authenticated"]),
            session_established=bool(connected and connect_error is None),
            rdp_authorized=authorized,
            server_error_code=code,
            server_error_from_credssp=bool(
                state["server_error_from_credssp"]
            ),
            error=connect_error,
            evidence=tuple(evidence),
        )


def _classify_backend_failure(
    *,
    connected: bool,
    error: object | None,
    code: int | None,
    phase: object,
    mechanism: AuthMechanism,
    selected_protocol: int | None,
    credssp_authenticated: bool = False,
) -> tuple[AuthOutcome, AuthPhase, bool | None]:
    current_phase = phase if isinstance(phase, AuthPhase) else AuthPhase.SESSION
    message = str(error or "").lower()
    if selected_protocol is not None and selected_protocol not in _AUTH_PROTOCOLS:
        return AuthOutcome.NOT_SUPPORTED, AuthPhase.X224, None
    if connected and error is None:
        return AuthOutcome.AUTHENTICATED, AuthPhase.COMPLETE, True
    if credssp_authenticated:
        if code is not None and _canonical_ntstatus(code) in _AUTHORIZATION_CODES:
            return AuthOutcome.AUTHENTICATED, AuthPhase.AUTHORIZATION, False
        if (
            selected_protocol == PROTOCOL_HYBRID_EX
            and "early user auth" in message
        ):
            return AuthOutcome.AUTHENTICATED, AuthPhase.AUTHORIZATION, False
        return AuthOutcome.AUTHENTICATED, AuthPhase.CREDSSP, None
    if isinstance(error, TLSFingerprintError):
        return AuthOutcome.TLS_ERROR, AuthPhase.TLS, None
    if isinstance(error, TimeoutError):
        return AuthOutcome.TIMEOUT, current_phase, None

    code_outcome = _status_outcome(code)
    if code_outcome is not None:
        canonical = _canonical_ntstatus(code)
        if canonical in _AUTHORIZATION_CODES:
            return code_outcome, AuthPhase.AUTHORIZATION, False
        if code_outcome is AuthOutcome.PREREQUISITE_ERROR:
            prerequisite_phase = (
                AuthPhase.KDC
                if mechanism is AuthMechanism.KERBEROS
                else current_phase
            )
            return code_outcome, prerequisite_phase, None
        return code_outcome, AuthPhase.CREDSSP, None

    if selected_protocol is not None and selected_protocol not in _AUTH_PROTOCOLS:
        return AuthOutcome.NOT_SUPPORTED, AuthPhase.X224, None

    if "certificate changed" in message or (
        "certificate" in message and "tls" in message
    ):
        return AuthOutcome.TLS_ERROR, AuthPhase.TLS, None
    if any(
        marker in message
        for marker in (
            "connection refused",
            "network is unreachable",
            "no route to host",
        )
    ):
        return AuthOutcome.TRANSPORT_ERROR, AuthPhase.TCP, None
    if mechanism is AuthMechanism.KERBEROS and any(
        marker in message
        for marker in (
            "kdc",
            "kerberos",
            "principal unknown",
            "cannot contact any kdc",
            "name or service not known",
        )
    ):
        return AuthOutcome.PREREQUISITE_ERROR, AuthPhase.KDC, None
    if "ntlm" in message and "block" in message:
        return AuthOutcome.BLOCKED, AuthPhase.CREDSSP, None
    if any(marker in message for marker in ("not supported", "no common mechanism")):
        return AuthOutcome.NOT_SUPPORTED, AuthPhase.SPNEGO, None
    if "early user auth" in message or "access denied" in message:
        return AuthOutcome.REJECTED, AuthPhase.AUTHORIZATION, False
    if any(
        marker in message
        for marker in ("authentication failed", "logon failure", "logon denied")
    ):
        return AuthOutcome.REJECTED, AuthPhase.CREDSSP, None
    if error is None:
        return AuthOutcome.INDETERMINATE, current_phase, None
    return AuthOutcome.INDETERMINATE, current_phase, None


__all__ = [
    "EXPECTED_DEPENDENCY_VERSIONS",
    "AardwolfAuthBackend",
    "AuthAttemptBackend",
    "AuthAttemptRequest",
    "AuthAttemptResult",
    "AuthMechanism",
    "AuthOutcome",
    "AuthPhase",
    "BackendAttemptResult",
    "CredentialKind",
    "CredentialSource",
    "DependencyVersionError",
    "TLSFingerprintError",
    "TLSVerification",
    "certificate_sha256",
    "check_dependency_versions",
    "ntstatus_name",
    "parse_ntstatus",
    "run_auth_attempt",
    "sanitize_auth_error",
    "sanitize_sensitive_text",
    "validate_auth_attempt",
    "verify_tls_fingerprint",
]
