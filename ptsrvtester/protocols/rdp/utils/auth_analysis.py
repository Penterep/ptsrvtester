"""Pure decision logic for active RDP authentication analysis.

The functions in this module deliberately know nothing about aardwolf or the
network.  Their only side effect is calling a supplied ``fresh_attempt``
function.  That function must use a new connection for every call and return a
structured :class:`AuthAttempt` without embedding credentials in its fields.

Two safety rules are central here:

* user enumeration is based only on semantic protocol results; timings are
  retained as diagnostics, never used to classify an account;
* account-lockout probing is disabled unless explicitly enabled and stops
  sending bad passwords as soon as ``STATUS_ACCOUNT_LOCKED_OUT`` is observed.
"""

from __future__ import annotations

import math
import secrets
import statistics
import time
from collections import Counter
from collections.abc import Callable, Iterable, MutableSequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Protocol, TypeAlias

MAX_ENUMERATION_CANDIDATES = 1_000
MAX_USER_WORDLIST_BYTES = 1_048_576
MAX_BRUTE_ATTEMPTS = 100
MAX_ACCOUNT_LOCKOUT_ATTEMPTS = 20

STATUS_NO_SUCH_USER = 0xC0000064
STATUS_WRONG_PASSWORD = 0xC000006A
STATUS_LOGON_FAILURE = 0xC000006D
STATUS_ACCOUNT_RESTRICTION = 0xC000006E
STATUS_INVALID_LOGON_HOURS = 0xC000006F
STATUS_INVALID_WORKSTATION = 0xC0000070
STATUS_PASSWORD_EXPIRED = 0xC0000071
STATUS_ACCOUNT_DISABLED = 0xC0000072
STATUS_LOGON_TYPE_NOT_GRANTED = 0xC000015B
STATUS_ACCOUNT_EXPIRED = 0xC0000193
STATUS_PASSWORD_MUST_CHANGE = 0xC0000224
STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234
STATUS_NTLM_BLOCKED = 0xC0000418

_NTSTATUS_NAMES = {
    STATUS_NO_SUCH_USER: "STATUS_NO_SUCH_USER",
    STATUS_WRONG_PASSWORD: "STATUS_WRONG_PASSWORD",
    STATUS_LOGON_FAILURE: "STATUS_LOGON_FAILURE",
    STATUS_ACCOUNT_RESTRICTION: "STATUS_ACCOUNT_RESTRICTION",
    STATUS_INVALID_LOGON_HOURS: "STATUS_INVALID_LOGON_HOURS",
    STATUS_INVALID_WORKSTATION: "STATUS_INVALID_WORKSTATION",
    STATUS_PASSWORD_EXPIRED: "STATUS_PASSWORD_EXPIRED",
    STATUS_ACCOUNT_DISABLED: "STATUS_ACCOUNT_DISABLED",
    STATUS_LOGON_TYPE_NOT_GRANTED: "STATUS_LOGON_TYPE_NOT_GRANTED",
    STATUS_ACCOUNT_EXPIRED: "STATUS_ACCOUNT_EXPIRED",
    STATUS_PASSWORD_MUST_CHANGE: "STATUS_PASSWORD_MUST_CHANGE",
    STATUS_ACCOUNT_LOCKED_OUT: "STATUS_ACCOUNT_LOCKED_OUT",
    STATUS_NTLM_BLOCKED: "STATUS_NTLM_BLOCKED",
}
_NTSTATUS_VALUES = {name: value for value, name in _NTSTATUS_NAMES.items()}


@dataclass(frozen=True)
class AuthAttempt:
    """Credential-free evidence produced by one fresh authentication attempt."""

    outcome: str
    failure_stage: str | None = None
    ntstatus: int | str | None = None
    selected_protocol: int | str | None = None
    server_error_from_credssp: bool = False
    duration_ms: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, str) or not self.outcome.strip():
            raise ValueError("authentication outcome must not be empty")
        if not isinstance(self.server_error_from_credssp, bool):
            raise TypeError("server_error_from_credssp must be a boolean")
        if self.duration_ms is not None and (
            not math.isfinite(self.duration_ms) or self.duration_ms < 0
        ):
            raise ValueError("authentication duration must be finite and non-negative")


class FreshAuthAttempt(Protocol):
    """Run exactly one authentication attempt over a new connection."""

    def __call__(self, login: str, password: str) -> object: ...


NormalizedStatus: TypeAlias = int | str | None
NormalizedProtocol: TypeAlias = int | str | None
AuthSemanticSignature: TypeAlias = tuple[str, NormalizedStatus]


# Only server statuses that unambiguously describe an existing account are
# accepted as positive evidence.  Generic authentication failures, arbitrary
# backend outcome labels and transport-stage differences are deliberately not
# in this allowlist.
_EXISTING_ACCOUNT_AUTH_STATUSES = {
    "STATUS_WRONG_PASSWORD",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_ACCOUNT_LOCKED_OUT",
}
_NONEXISTING_ACCOUNT_AUTH_STATUSES = {"STATUS_NO_SUCH_USER"}


@dataclass(frozen=True)
class SemanticFingerprint:
    """Comparable authentication semantics, intentionally excluding timing."""

    outcome: str
    failure_stage: str | None
    ntstatus: NormalizedStatus
    selected_protocol: NormalizedProtocol
    server_error_from_credssp: bool


@dataclass(frozen=True)
class UserEnumerationConfig:
    """Configuration for the differential user-enumeration baseline."""

    valid_login: str = field(repr=False)
    candidates: tuple[str, ...] = ()
    allow_auth_failures: bool = False
    inter_attempt_delay_ms: int = 0

    def __post_init__(self) -> None:
        _split_login(self.valid_login)
        if not isinstance(self.allow_auth_failures, bool):
            raise TypeError("allow_auth_failures must be a boolean")
        object.__setattr__(self, "candidates", tuple(self.candidates))
        if len(self.candidates) > MAX_ENUMERATION_CANDIDATES:
            raise ValueError(
                f"at most {MAX_ENUMERATION_CANDIDATES} enumeration candidates "
                "are allowed"
            )
        if (
            isinstance(self.inter_attempt_delay_ms, bool)
            or not isinstance(self.inter_attempt_delay_ms, int)
            or self.inter_attempt_delay_ms < 0
        ):
            raise ValueError("inter_attempt_delay_ms must be a non-negative integer")


@dataclass(frozen=True)
class EnumerationCandidateResult:
    login: str
    classification: str
    fingerprint: SemanticFingerprint
    duration_ms: float | None


@dataclass(frozen=True)
class UserEnumerationResult:
    status: str
    reason: str | None = None
    known_user_fingerprint: SemanticFingerprint | None = None
    invalid_user_fingerprint: SemanticFingerprint | None = None
    invalid_baselines_consistent: bool | None = None
    baseline_attempts: int = 0
    candidate_count_requested: int = 0
    candidates: tuple[EnumerationCandidateResult, ...] = ()

    @property
    def candidate_count_tested(self) -> int:
        return len(self.candidates)

    @property
    def candidate_count_skipped(self) -> int:
        return max(0, self.candidate_count_requested - len(self.candidates))

    @property
    def existing_users(self) -> tuple[str, ...]:
        return tuple(
            item.login for item in self.candidates if item.classification == "existing"
        )

    @property
    def non_existing_users(self) -> tuple[str, ...]:
        return tuple(
            item.login
            for item in self.candidates
            if item.classification == "non_existing"
        )

    @property
    def inconclusive_users(self) -> tuple[str, ...]:
        return tuple(
            item.login
            for item in self.candidates
            if item.classification == "inconclusive"
        )


@dataclass(frozen=True)
class AccountLockoutConfig:
    """Explicitly dangerous real-account probe; disabled by default."""

    enabled: bool = False
    valid_login: str | None = field(default=None, repr=False)
    valid_password: str | None = field(default=None, repr=False)
    bad_attempts: int = 3

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("account-lockout enabled must be a boolean")
        if isinstance(self.bad_attempts, bool) or not isinstance(
            self.bad_attempts, int
        ):
            raise TypeError("account-lockout bad_attempts must be an integer")
        if not 1 <= self.bad_attempts <= MAX_ACCOUNT_LOCKOUT_ATTEMPTS:
            raise ValueError(
                "account-lockout bad_attempts must be between 1 and "
                f"{MAX_ACCOUNT_LOCKOUT_ATTEMPTS}"
            )
        if self.enabled is True:
            if self.valid_login is None or self.valid_password is None:
                raise ValueError(
                    "enabled account-lockout testing requires valid login and password"
                )
            _split_login(self.valid_login)


@dataclass(frozen=True)
class BruteProtectionConfig:
    """Bounded password-guessing protection analysis."""

    namespace_login: str = field(repr=False)
    attempts: int = 12
    comparison_window: int = 3
    allow_auth_failures: bool = False
    inter_attempt_delay_ms: int = 0
    slowdown_factor: float = 3.0
    slowdown_absolute_ms: float = 500.0
    account_lockout: AccountLockoutConfig = field(
        default_factory=AccountLockoutConfig,
        repr=False,
    )

    def __post_init__(self) -> None:
        _split_login(self.namespace_login)
        if not isinstance(self.allow_auth_failures, bool):
            raise TypeError("allow_auth_failures must be a boolean")
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int):
            raise TypeError("brute attempts must be an integer")
        if not 2 <= self.attempts <= MAX_BRUTE_ATTEMPTS:
            raise ValueError(
                f"brute attempts must be between 2 and {MAX_BRUTE_ATTEMPTS}"
            )
        if not 1 <= self.comparison_window <= self.attempts // 2:
            raise ValueError(
                "comparison_window must be positive and fit disjoint first/last windows"
            )
        if (
            isinstance(self.inter_attempt_delay_ms, bool)
            or not isinstance(self.inter_attempt_delay_ms, int)
            or self.inter_attempt_delay_ms < 0
        ):
            raise ValueError("inter_attempt_delay_ms must be a non-negative integer")
        if (
            isinstance(self.slowdown_factor, bool)
            or not isinstance(self.slowdown_factor, (int, float))
            or not math.isfinite(float(self.slowdown_factor))
            or self.slowdown_factor <= 1
        ):
            raise ValueError("slowdown_factor must be a finite number greater than 1")
        if (
            isinstance(self.slowdown_absolute_ms, bool)
            or not isinstance(self.slowdown_absolute_ms, (int, float))
            or not math.isfinite(float(self.slowdown_absolute_ms))
            or self.slowdown_absolute_ms < 0
        ):
            raise ValueError("slowdown_absolute_ms must be finite and non-negative")


@dataclass(frozen=True)
class BruteAttemptObservation:
    index: int
    fingerprint: SemanticFingerprint
    duration_ms: float | None
    timed_out: bool


@dataclass(frozen=True)
class AccountLockoutResult:
    status: str
    reason: str | None = None
    bad_attempts_performed: int = 0
    locked_at_attempt: int | None = None
    baseline_fingerprint: SemanticFingerprint | None = None
    final_fingerprint: SemanticFingerprint | None = None


@dataclass(frozen=True)
class BruteProtectionResult:
    status: str
    reason: str | None = None
    attempts_performed: int = 0
    first_median_ms: float | None = None
    last_median_ms: float | None = None
    median_change_ms: float | None = None
    median_ratio: float | None = None
    outcome_changed: bool = False
    timeout_observed: bool = False
    slowdown_signal: bool = False
    early_stopped: bool = False
    observations: tuple[BruteAttemptObservation, ...] = ()
    account_lockout: AccountLockoutResult = field(
        default_factory=lambda: AccountLockoutResult("not_run")
    )


TokenFactory: TypeAlias = Callable[[int], str]
Shuffle: TypeAlias = Callable[[MutableSequence[object]], None]


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = "_".join(value.strip().lower().replace("-", "_").split())
    return normalized or None


def normalize_ntstatus(value: int | str | None) -> NormalizedStatus:
    """Canonicalize known NTSTATUS values while retaining unknown values."""

    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        number = _canonical_ntstatus(value)
        return _NTSTATUS_NAMES.get(number, number)

    text = value.strip().upper()
    if not text:
        return None
    if text in _NTSTATUS_VALUES:
        return text
    try:
        number = int(text, 0)
    except ValueError:
        return text
    number = _canonical_ntstatus(number)
    return _NTSTATUS_NAMES.get(number, number)


def _canonical_ntstatus(value: int) -> int:
    """Unwrap HRESULT_FROM_NT while retaining other unsigned status values."""

    number = value & 0xFFFFFFFF
    if number & 0xF0000000 == 0xD0000000:
        return number & ~0x10000000
    return number


def semantic_fingerprint(attempt: AuthAttempt) -> SemanticFingerprint:
    """Return fields safe and meaningful for differential comparison."""

    protocol: NormalizedProtocol = attempt.selected_protocol
    if isinstance(protocol, str):
        protocol = protocol.strip().upper() or None
    return SemanticFingerprint(
        outcome=_normalize_text(attempt.outcome) or "invalid_result",
        failure_stage=_normalize_text(attempt.failure_stage),
        ntstatus=normalize_ntstatus(attempt.ntstatus),
        selected_protocol=protocol,
        server_error_from_credssp=attempt.server_error_from_credssp,
    )


def _auth_semantic_signature(
    fingerprint: SemanticFingerprint,
) -> AuthSemanticSignature:
    """Return server-auth semantics suitable for a positive enum verdict.

    ``selected_protocol`` and ``failure_stage`` remain useful diagnostics in
    the full fingerprint, but they are deliberately excluded here.  Either can
    drift because of routing, negotiation or client-side error attribution and
    therefore must never prove that an identity exists.
    """

    return fingerprint.outcome, fingerprint.ntstatus


def _has_identity_specific_status_difference(
    known: SemanticFingerprint,
    invalid: SemanticFingerprint,
) -> bool:
    """Return true for direct, identity-specific CredSSP server statuses."""

    return (
        known.server_error_from_credssp
        and invalid.server_error_from_credssp
        and known.ntstatus in _EXISTING_ACCOUNT_AUTH_STATUSES
        and invalid.ntstatus in _NONEXISTING_ACCOUNT_AUTH_STATUSES
    )


def _classify_account_status(fingerprint: SemanticFingerprint) -> str:
    """Classify only explicit server evidence about account existence."""

    if not fingerprint.server_error_from_credssp:
        return "inconclusive"
    if fingerprint.ntstatus in _EXISTING_ACCOUNT_AUTH_STATUSES:
        return "existing"
    if fingerprint.ntstatus in _NONEXISTING_ACCOUNT_AUTH_STATUSES:
        return "non_existing"
    return "inconclusive"


def _split_login(login: str) -> tuple[str, str | None, str]:
    """Return ``(kind, namespace, username)`` for local/domain/UPN forms."""

    if not isinstance(login, str) or not login or login != login.strip():
        raise ValueError("login must not be empty or have surrounding whitespace")
    if "\x00" in login or "\r" in login or "\n" in login:
        raise ValueError("login contains an invalid control character")
    if len(login) > 512:
        raise ValueError("login is too long")

    if "\\" in login:
        if login.count("\\") != 1:
            raise ValueError("login must use DOMAIN\\user format")
        namespace, username = login.split("\\", 1)
        if not namespace or not username:
            raise ValueError("login must use DOMAIN\\user format")
        return "domain", namespace, username

    if "@" in login:
        username, namespace = login.rsplit("@", 1)
        if not namespace or not username:
            raise ValueError("login must use user@domain format")
        return "upn", namespace, username

    return "local", None, login


def normalize_candidate_login(candidate: str, namespace_login: str) -> str:
    """Apply the baseline namespace to unqualified wordlist identities."""

    candidate = candidate.strip()
    candidate_kind, _candidate_namespace, _candidate_user = _split_login(candidate)
    if candidate_kind != "local":
        return candidate

    namespace_kind, namespace, _known_user = _split_login(namespace_login)
    if namespace_kind == "domain":
        return f"{namespace}\\{candidate}"
    if namespace_kind == "upn":
        return f"{candidate}@{namespace}"
    return candidate


def parse_user_wordlist(
    contents: str | bytes,
    namespace_login: str,
) -> tuple[str, ...]:
    """Parse a strict UTF-8 wordlist, ignoring blank and comment lines.

    Duplicates are removed case-insensitively because Windows account names are
    case-insensitive for this purpose.  Explicitly qualified logins are kept;
    unqualified entries inherit the known login's domain/UPN namespace.
    """

    _split_login(namespace_login)
    if isinstance(contents, bytes):
        text = contents.decode("utf-8-sig", errors="strict")
    elif isinstance(contents, str):
        text = contents.removeprefix("\ufeff")
    else:
        raise TypeError("wordlist contents must be str or bytes")

    users: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        normalized = normalize_candidate_login(line, namespace_login)
        key = normalized.casefold()
        if key in seen:
            continue
        seen.add(key)
        users.append(normalized)
        if len(users) > MAX_ENUMERATION_CANDIDATES:
            raise ValueError(
                f"wordlist contains more than {MAX_ENUMERATION_CANDIDATES} users"
            )
    return tuple(users)


def load_user_wordlist(path: str | Path, namespace_login: str) -> tuple[str, ...]:
    """Load and strictly decode a UTF-8 username wordlist."""

    wordlist_path = Path(path)
    if wordlist_path.stat().st_size > MAX_USER_WORDLIST_BYTES:
        raise ValueError(
            f"wordlist exceeds the {MAX_USER_WORDLIST_BYTES}-byte size limit"
        )

    # The metadata check gives an inexpensive rejection for ordinary files.
    # The bounded read is still required: the path may be replaced or the file
    # may grow between stat() and read().  Reading one byte past the limit lets
    # us detect that race without ever loading an unbounded file into memory.
    with wordlist_path.open("rb") as wordlist:
        contents = wordlist.read(MAX_USER_WORDLIST_BYTES + 1)
    if len(contents) > MAX_USER_WORDLIST_BYTES:
        raise ValueError(
            f"wordlist exceeds the {MAX_USER_WORDLIST_BYTES}-byte size limit"
        )
    return parse_user_wordlist(contents, namespace_login)


def _random_invalid_login(login: str, token: str) -> str:
    kind, namespace, _username = _split_login(login)
    username = f"ptsrv-invalid-{token}"
    if kind == "domain":
        return f"{namespace}\\{username}"
    if kind == "upn":
        return f"{username}@{namespace}"
    return username


def _make_invalid_logins(
    namespace_login: str,
    count: int,
    token_factory: TokenFactory,
) -> tuple[str, ...]:
    logins: list[str] = []
    seen = {namespace_login.casefold()}
    while len(logins) < count:
        candidate = _random_invalid_login(namespace_login, token_factory(16))
        key = candidate.casefold()
        if key in seen:
            continue
        seen.add(key)
        logins.append(candidate)
    return tuple(logins)


def _bad_password(token_factory: TokenFactory) -> str:
    # 256 random bits make an accidental match negligible.  It is never stored
    # in, or returned from, a result object.
    return f"!ptsrv-invalid-{token_factory(32)}!"


def _invoke_fresh(
    fresh_attempt: FreshAuthAttempt,
    login: str,
    password: str,
) -> AuthAttempt:
    """Invoke a probe without propagating exception text that may hold secrets."""

    started = time.perf_counter()
    try:
        result = _coerce_auth_attempt(fresh_attempt(login, password))
    except Exception as exc:  # noqa: BLE001 - isolate backend failures and secrets
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return AuthAttempt(
            outcome="probe_error",
            failure_stage=f"client_exception:{type(exc).__name__}",
            duration_ms=elapsed_ms,
        )
    if result.duration_ms is None:
        result = replace(
            result,
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )
    return result


def _enum_value(value: object) -> object:
    """Unwrap ``Enum``-like values without importing a concrete backend."""

    return getattr(value, "value", value)


def _coerce_auth_attempt(result: object) -> AuthAttempt:
    """Accept this module's evidence or the structured engine adapter result.

    ``utils.auth_attempts.AuthAttemptResult`` uses ``phase`` and
    ``server_error_code`` while this pure layer calls those fields
    ``failure_stage`` and ``ntstatus``.  Duck-typing the small shared surface
    keeps the decision logic independent of the network backend.
    """

    if isinstance(result, AuthAttempt):
        return result

    raw_outcome = getattr(result, "outcome", None)
    if raw_outcome is None:
        raise TypeError("fresh auth callable returned an invalid result")
    raw_stage = getattr(result, "failure_stage", None)
    if raw_stage is None:
        raw_stage = getattr(result, "phase", None)
    ntstatus = getattr(result, "ntstatus", None)
    if ntstatus is None:
        ntstatus = getattr(result, "server_error_code", None)
    duration = getattr(result, "connection_duration_ms", None)
    if duration is None:
        duration = getattr(result, "duration_ms", None)
    server_error_from_credssp = getattr(
        result,
        "server_error_from_credssp",
        False,
    )
    return AuthAttempt(
        outcome=str(_enum_value(raw_outcome)),
        failure_stage=str(_enum_value(raw_stage)) if raw_stage is not None else None,
        ntstatus=ntstatus,
        selected_protocol=getattr(result, "selected_protocol", None),
        server_error_from_credssp=server_error_from_credssp,
        duration_ms=float(duration) if duration is not None else None,
    )


def _is_timeout(attempt: AuthAttempt) -> bool:
    values = (attempt.outcome, attempt.failure_stage or "")
    return any(
        "timeout" in value.lower() or "timed_out" in value.lower()
        for value in values
    )


def _has_account_lockout_signal(attempt: AuthAttempt) -> bool:
    """Return true for any lockout signal, including untrusted client parsing.

    Untrusted signals are sufficient to stop further bad-password attempts for
    safety, but cannot by themselves confirm that the server locked an account.
    """

    if normalize_ntstatus(attempt.ntstatus) == "STATUS_ACCOUNT_LOCKED_OUT":
        return True
    return _normalize_text(attempt.outcome) in {
        "account_locked",
        "account_locked_out",
        "locked_out",
    }


def _is_confirmed_account_locked(attempt: AuthAttempt) -> bool:
    """Return true only for a lockout status decoded from a CredSSP response."""

    return (
        attempt.server_error_from_credssp
        and normalize_ntstatus(attempt.ntstatus) == "STATUS_ACCOUNT_LOCKED_OUT"
    )


def _is_not_applicable(attempt: AuthAttempt) -> bool:
    """Return true when the attempted authentication path is unavailable."""

    return (
        _normalize_text(attempt.outcome) == "not_supported"
        or (
            attempt.server_error_from_credssp
            and normalize_ntstatus(attempt.ntstatus) == "STATUS_NTLM_BLOCKED"
        )
    )


def _is_client_prerequisite_failure(attempt: AuthAttempt) -> bool:
    """Return true when the client could not start a meaningful auth probe.

    Keep this separate from transient transport failures.  Missing or invalid
    local dependencies are deterministic scanner prerequisites, not evidence
    about the target and not something that should be retried for every
    generated identity.
    """

    return (_normalize_text(attempt.outcome) or "") in {
        "dependency_error",
        "prerequisite_error",
    }


def _client_prerequisite_reason(attempt: AuthAttempt) -> str:
    stage = _normalize_text(attempt.failure_stage)
    if stage == "dependency":
        return (
            "the local RDP authentication dependency is unavailable; "
            "no failed login was sent"
        )
    if stage == "validation":
        return (
            "the local RDP authentication prerequisites are invalid; "
            "no failed login was sent"
        )
    return (
        "a local RDP authentication prerequisite prevented the test; "
        "no failed login was sent"
    )


def _is_transient(attempt: AuthAttempt) -> bool:
    outcome = _normalize_text(attempt.outcome) or ""
    if _is_timeout(attempt):
        return True
    return outcome in {
        "blocked",
        "connection_error",
        "connection_refused",
        "dependency_error",
        "error",
        "indeterminate",
        "network_error",
        "not_supported",
        "probe_error",
        "prerequisite_error",
        "rate_limited",
        "tls_error",
        "transport_error",
    }


def _shuffle(values: MutableSequence[object], shuffle: Shuffle | None) -> None:
    if shuffle is not None:
        shuffle(values)
    else:
        secrets.SystemRandom().shuffle(values)


def _tokens(token_factory: TokenFactory | None) -> TokenFactory:
    return token_factory or secrets.token_hex


def run_user_enumeration(
    config: UserEnumerationConfig,
    fresh_attempt: FreshAuthAttempt,
    *,
    token_factory: TokenFactory | None = None,
    shuffle: Shuffle | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> UserEnumerationResult:
    """Run a three-attempt baseline, then classify each candidate at most once."""

    if config.allow_auth_failures is not True:
        return UserEnumerationResult(
            status="blocked",
            reason="active authentication failures require explicit authorization",
            candidate_count_requested=len(config.candidates),
        )

    token = _tokens(token_factory)
    invalid_logins = _make_invalid_logins(config.valid_login, 2, token)
    password = _bad_password(token)
    attempts_started = 0

    def invoke(login: str) -> AuthAttempt:
        nonlocal attempts_started
        if attempts_started and config.inter_attempt_delay_ms:
            sleep(config.inter_attempt_delay_ms / 1000.0)
        attempts_started += 1
        return _invoke_fresh(fresh_attempt, login, password)

    baseline: list[tuple[str, str]] = [
        ("known", config.valid_login),
        ("invalid", invalid_logins[0]),
        ("invalid", invalid_logins[1]),
    ]
    _shuffle(baseline, shuffle)

    observed: list[tuple[str, AuthAttempt]] = []
    for role, login in baseline:
        attempt = invoke(login)
        observed.append((role, attempt))
        if _is_client_prerequisite_failure(attempt):
            return UserEnumerationResult(
                status="blocked",
                reason=_client_prerequisite_reason(attempt),
                baseline_attempts=len(observed),
                candidate_count_requested=len(config.candidates),
            )
        if _has_account_lockout_signal(attempt):
            confirmed = _is_confirmed_account_locked(attempt)
            return UserEnumerationResult(
                status="inconclusive",
                reason=(
                    "account lockout was observed during the baseline"
                    if confirmed
                    else (
                        "an unverified account-lockout signal was returned during "
                        "the baseline; remaining attempts were stopped"
                    )
                ),
                baseline_attempts=len(observed),
                candidate_count_requested=len(config.candidates),
            )

    known_attempt = next(attempt for role, attempt in observed if role == "known")
    invalid_attempts = [attempt for role, attempt in observed if role == "invalid"]
    known_fingerprint = semantic_fingerprint(known_attempt)
    invalid_fingerprints = tuple(map(semantic_fingerprint, invalid_attempts))
    invalid_consistent = invalid_fingerprints[0] == invalid_fingerprints[1]

    common = {
        "known_user_fingerprint": known_fingerprint,
        "invalid_user_fingerprint": invalid_fingerprints[0]
        if invalid_consistent
        else None,
        "invalid_baselines_consistent": invalid_consistent,
        "baseline_attempts": len(observed),
        "candidate_count_requested": len(config.candidates),
    }
    unavailable = [_is_not_applicable(attempt) for _role, attempt in observed]
    if all(unavailable):
        return UserEnumerationResult(
            status="not_applicable",
            reason="the RDP NTLM authentication path is not available",
            **common,
        )
    if any(unavailable):
        return UserEnumerationResult(
            status="inconclusive",
            reason="the authentication path was not consistently available at baseline",
            **common,
        )
    if any(_is_transient(attempt) for _role, attempt in observed):
        return UserEnumerationResult(
            status="inconclusive",
            reason="baseline contained a transient transport/client result",
            **common,
        )
    if any(
        _normalize_text(attempt.outcome) == "authenticated"
        for _role, attempt in observed
    ):
        return UserEnumerationResult(
            status="inconclusive",
            reason="the generated wrong password unexpectedly authenticated",
            **common,
        )
    if not invalid_consistent:
        return UserEnumerationResult(
            status="inconclusive",
            reason="two invalid identities produced different semantic responses",
            **common,
        )
    if known_fingerprint == invalid_fingerprints[0]:
        if (
            known_fingerprint.ntstatus is not None
            and not known_fingerprint.server_error_from_credssp
        ):
            return UserEnumerationResult(
                status="inconclusive",
                reason=(
                    "known and invalid identities produced the same status, but it "
                    "was not decoded directly from a CredSSP server response"
                ),
                **common,
            )
        return UserEnumerationResult(
            status="not_observed",
            reason="known and invalid identities produced the same semantic response",
            **common,
        )

    known_auth_semantics = _auth_semantic_signature(known_fingerprint)
    invalid_auth_semantics = _auth_semantic_signature(invalid_fingerprints[0])
    if known_auth_semantics == invalid_auth_semantics:
        return UserEnumerationResult(
            status="inconclusive",
            reason=(
                "known and invalid identities differed only in diagnostic "
                "transport, protocol, failure-stage, or status-provenance metadata"
            ),
            **common,
        )

    if not _has_identity_specific_status_difference(
        known_fingerprint,
        invalid_fingerprints[0],
    ):
        # The two invalid identities already establish repeatability for the
        # invalid side.  Without a strong identity-specific NTSTATUS, repeat
        # the known side as well before allowing a positive verdict.
        confirmation = invoke(config.valid_login)
        common["baseline_attempts"] = attempts_started
        confirmation_fingerprint = semantic_fingerprint(confirmation)
        if _has_account_lockout_signal(confirmation):
            confirmed = _is_confirmed_account_locked(confirmation)
            return UserEnumerationResult(
                status="inconclusive",
                reason=(
                    "account lockout was observed during baseline confirmation"
                    if confirmed
                    else (
                        "an unverified account-lockout signal was returned during "
                        "baseline confirmation; remaining attempts were stopped"
                    )
                ),
                **common,
            )
        if _is_not_applicable(confirmation) or _is_transient(confirmation):
            return UserEnumerationResult(
                status="inconclusive",
                reason=(
                    "the repeated known-identity baseline returned an unavailable "
                    "or transient result"
                ),
                **common,
            )
        if _normalize_text(confirmation.outcome) == "authenticated":
            return UserEnumerationResult(
                status="inconclusive",
                reason="the generated wrong password unexpectedly authenticated",
                **common,
            )
        if _auth_semantic_signature(confirmation_fingerprint) != known_auth_semantics:
            return UserEnumerationResult(
                status="inconclusive",
                reason=(
                    "the known identity did not produce a repeatable authentication "
                    "response"
                ),
                **common,
            )

        return UserEnumerationResult(
            status="inconclusive",
            reason=(
                "known and invalid identities produced distinct, repeatable "
                "authentication responses, but no account-specific server status "
                "confirmed enumeration; candidate wordlist was not tested"
            ),
            **common,
        )

    normalized_candidates: list[str] = []
    seen = {
        config.valid_login.casefold(),
        *(login.casefold() for login in invalid_logins),
    }
    for candidate in config.candidates:
        normalized = normalize_candidate_login(candidate, config.valid_login)
        key = normalized.casefold()
        if key in seen:
            continue
        seen.add(key)
        normalized_candidates.append(normalized)
    _shuffle(normalized_candidates, shuffle)

    candidate_results: list[EnumerationCandidateResult] = []
    result_status = "enumerable"
    reason = (
        "known and invalid identities produced distinct identity-specific server "
        "statuses"
        if _has_identity_specific_status_difference(
            known_fingerprint,
            invalid_fingerprints[0],
        )
        else (
            "known and invalid identities produced distinct, repeatable "
            "authentication responses"
        )
    )
    for login in normalized_candidates:
        attempt = invoke(login)
        fingerprint = semantic_fingerprint(attempt)
        stop_candidates = False
        if _has_account_lockout_signal(attempt):
            if _is_confirmed_account_locked(attempt):
                classification = "existing"
                result_status = "enumerable_partial"
                reason = (
                    "account lockout was observed; remaining candidates were not "
                    "tested"
                )
            else:
                classification = "inconclusive"
                result_status = "enumerable_partial"
                reason = (
                    "an unverified account-lockout signal was returned; remaining "
                    "candidates were not tested"
                )
            stop_candidates = True
        elif _is_transient(attempt):
            classification = "inconclusive"
            result_status = "enumerable_partial"
            reason = (
                "the baseline showed account enumeration, but a candidate probe "
                "returned a transient or blocked result; remaining candidates were "
                "not tested"
            )
            stop_candidates = True
        else:
            classification = _classify_account_status(fingerprint)
        candidate_results.append(
            EnumerationCandidateResult(
                login=login,
                classification=classification,
                fingerprint=fingerprint,
                duration_ms=attempt.duration_ms,
            )
        )
        if stop_candidates:
            break

    return UserEnumerationResult(
        status=result_status,
        reason=reason,
        candidates=tuple(candidate_results),
        **common,
    )


def _median(values: Iterable[float | None]) -> float | None:
    durations = [value for value in values if value is not None]
    return statistics.median(durations) if durations else None


def _modal_fingerprint(
    observations: Iterable[BruteAttemptObservation],
) -> SemanticFingerprint | None:
    values = [observation.fingerprint for observation in observations]
    if not values:
        return None
    return Counter(values).most_common(1)[0][0]


def _is_blocking_outcome(attempt: AuthAttempt) -> bool:
    outcome = _normalize_text(attempt.outcome) or ""
    return _is_timeout(attempt) or outcome in {
        "blocked",
        "connection_refused",
        "ip_blocked",
        "rate_limited",
        "throttled",
    }


def _run_account_lockout_test(
    config: AccountLockoutConfig,
    fresh_attempt: FreshAuthAttempt,
    token_factory: TokenFactory,
    *,
    inter_attempt_delay_ms: int,
    sleep: Callable[[float], None],
) -> AccountLockoutResult:
    if config.enabled is not True:
        return AccountLockoutResult("not_run")

    # AccountLockoutConfig validation guarantees both are present when enabled.
    login = config.valid_login or ""
    password = config.valid_password or ""
    attempts_started = 0

    def invoke(candidate_password: str) -> AuthAttempt:
        nonlocal attempts_started
        if attempts_started and inter_attempt_delay_ms:
            sleep(inter_attempt_delay_ms / 1000.0)
        attempts_started += 1
        return _invoke_fresh(fresh_attempt, login, candidate_password)

    baseline = invoke(password)
    baseline_fingerprint = semantic_fingerprint(baseline)
    if _has_account_lockout_signal(baseline):
        return AccountLockoutResult(
            status=(
                "blocked" if _is_confirmed_account_locked(baseline) else "inconclusive"
            ),
            reason=(
                "the test account was already locked at baseline"
                if _is_confirmed_account_locked(baseline)
                else (
                    "an unverified account-lockout signal was returned at baseline; "
                    "no bad passwords were sent"
                )
            ),
            baseline_fingerprint=baseline_fingerprint,
        )
    if _normalize_text(baseline.outcome) != "authenticated":
        return AccountLockoutResult(
            status="blocked",
            reason=(
                "valid-credential baseline did not authenticate; no bad passwords sent"
            ),
            baseline_fingerprint=baseline_fingerprint,
        )

    performed = 0
    lockout_signal_at: int | None = None
    confirmed_locked_at: int | None = None
    interrupted = False
    for index in range(1, config.bad_attempts + 1):
        # A fresh wrong password makes each lockout event an independent
        # credential guess and avoids server/client duplicate-attempt handling.
        attempt = invoke(_bad_password(token_factory))
        performed += 1
        if _has_account_lockout_signal(attempt):
            lockout_signal_at = index
            if _is_confirmed_account_locked(attempt):
                confirmed_locked_at = index
            break
        if _is_transient(attempt):
            interrupted = True
            break

    # A final correct-credential probe is always made after a valid baseline.
    # It distinguishes an explicit/implicit lockout from a still-usable account.
    final = invoke(password)
    final_fingerprint = semantic_fingerprint(final)
    final_lockout_signal = _has_account_lockout_signal(final)
    final_lockout_confirmed = _is_confirmed_account_locked(final)
    if confirmed_locked_at is not None or final_lockout_confirmed:
        status = "lockout_observed"
        reason = "the server reported STATUS_ACCOUNT_LOCKED_OUT through CredSSP"
    elif lockout_signal_at is not None or final_lockout_signal:
        status = "inconclusive"
        reason = (
            "an account-lockout signal lacked direct CredSSP server-status provenance"
        )
    elif _normalize_text(final.outcome) == "authenticated" and not interrupted:
        status = "not_observed"
        reason = "the final valid-credential probe still authenticated"
    else:
        status = "inconclusive"
        reason = "the final valid-credential probe did not establish account usability"

    return AccountLockoutResult(
        status=status,
        reason=reason,
        bad_attempts_performed=performed,
        locked_at_attempt=confirmed_locked_at,
        baseline_fingerprint=baseline_fingerprint,
        final_fingerprint=final_fingerprint,
    )


def run_brute_protection(
    config: BruteProtectionConfig,
    fresh_attempt: FreshAuthAttempt,
    *,
    token_factory: TokenFactory | None = None,
    shuffle: Shuffle | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> BruteProtectionResult:
    """Probe semantic blocking with bounded nonexistent-account attempts.

    First/last connection-attempt latency medians are returned for diagnostics.
    They do not by themselves turn the result into ``protection_observed``
    because network timing is too noisy to be a reliable semantic signal.
    """

    if config.allow_auth_failures is not True:
        return BruteProtectionResult(
            status="blocked",
            reason="active authentication failures require explicit authorization",
        )

    token = _tokens(token_factory)
    logins = list(_make_invalid_logins(config.namespace_login, config.attempts, token))
    _shuffle(logins, shuffle)
    password = _bad_password(token)
    observations: list[BruteAttemptObservation] = []
    raw_attempts: list[AuthAttempt] = []
    consecutive_blocking = 0

    for index, login in enumerate(logins, 1):
        attempt = _invoke_fresh(fresh_attempt, login, password)
        raw_attempts.append(attempt)
        observations.append(
            BruteAttemptObservation(
                index=index,
                fingerprint=semantic_fingerprint(attempt),
                duration_ms=attempt.duration_ms,
                timed_out=_is_timeout(attempt),
            )
        )
        if _is_blocking_outcome(attempt):
            consecutive_blocking += 1
        else:
            consecutive_blocking = 0
        if _is_not_applicable(attempt) or (
            _is_transient(attempt) and not _is_blocking_outcome(attempt)
        ):
            break
        if consecutive_blocking >= 2:
            break
        if index < len(logins) and config.inter_attempt_delay_ms:
            sleep(config.inter_attempt_delay_ms / 1000.0)

    width = config.comparison_window
    first = observations[:width]
    last = observations[-width:]
    first_median = _median(item.duration_ms for item in first)
    last_median = _median(item.duration_ms for item in last)
    median_change = (
        last_median - first_median
        if first_median is not None and last_median is not None
        else None
    )
    median_ratio = (
        last_median / first_median
        if first_median not in (None, 0) and last_median is not None
        else None
    )
    first_fingerprint = _modal_fingerprint(first)
    last_fingerprint = _modal_fingerprint(last)
    outcome_changed = (
        first_fingerprint is not None
        and last_fingerprint is not None
        and first_fingerprint != last_fingerprint
    )
    timeout_observed = any(item.timed_out for item in observations)
    first_blocking_count = sum(
        _is_blocking_outcome(item) for item in raw_attempts[:width]
    )
    last_blocking_count = sum(
        _is_blocking_outcome(item) for item in raw_attempts[-width:]
    )
    blocking_transition = (
        first_blocking_count == 0 and last_blocking_count >= 2
    )
    slowdown_signal = (
        width >= 3
        and first_median is not None
        and last_median is not None
        and last_median
        >= max(
            first_median * config.slowdown_factor,
            first_median + config.slowdown_absolute_ms,
        )
    )
    unavailable = [_is_not_applicable(item) for item in raw_attempts]
    prerequisite = next(
        (item for item in raw_attempts if _is_client_prerequisite_failure(item)),
        None,
    )

    if prerequisite is not None:
        status = "blocked"
        reason = _client_prerequisite_reason(prerequisite)
    elif all(unavailable):
        status = "not_applicable"
        reason = "the RDP NTLM authentication path is not available"
    elif any(unavailable):
        status = "inconclusive"
        reason = "the authentication path was not consistently available"
    elif blocking_transition:
        status = "protection_observed"
        reason = "later attempts produced repeated blocking or timeout responses"
    elif any(_is_transient(item) for item in raw_attempts):
        status = "inconclusive"
        reason = "the attempt series contained a transient or blocked result"
    elif outcome_changed:
        status = "response_changed"
        reason = "first and last windows produced different semantic responses"
    elif slowdown_signal:
        status = "slowdown_signal"
        reason = (
            "the last connection-attempt timing window crossed both the relative "
            "and absolute slowdown thresholds; network/server load remains a "
            "possible cause"
        )
    elif width < 3:
        status = "insufficient_samples"
        reason = (
            "slowdown evaluation requires two disjoint three-sample windows; "
            "the configured or completed sample did not provide them"
        )
    else:
        status = "not_observed"
        reason = "no semantic blocking was observed at the configured attempt count"

    if config.account_lockout.enabled is True and status not in {
        "not_observed",
        "insufficient_samples",
    }:
        lockout = AccountLockoutResult(
            status="skipped",
            reason=(
                "the disposable-account lockout probe was skipped because the "
                f"preceding random-identity series ended as {status}"
            ),
        )
    else:
        if (
            config.account_lockout.enabled is True
            and observations
            and config.inter_attempt_delay_ms
        ):
            sleep(config.inter_attempt_delay_ms / 1000.0)
        lockout = _run_account_lockout_test(
            config.account_lockout,
            fresh_attempt,
            token,
            inter_attempt_delay_ms=config.inter_attempt_delay_ms,
            sleep=sleep,
        )
    return BruteProtectionResult(
        status=status,
        reason=reason,
        attempts_performed=len(observations),
        first_median_ms=first_median,
        last_median_ms=last_median,
        median_change_ms=median_change,
        median_ratio=median_ratio,
        outcome_changed=outcome_changed,
        timeout_observed=timeout_observed,
        slowdown_signal=slowdown_signal,
        early_stopped=len(observations) < len(logins),
        observations=tuple(observations),
        account_lockout=lockout,
    )


__all__ = [
    "MAX_ENUMERATION_CANDIDATES",
    "MAX_USER_WORDLIST_BYTES",
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_EXPIRED",
    "STATUS_ACCOUNT_LOCKED_OUT",
    "STATUS_ACCOUNT_RESTRICTION",
    "STATUS_INVALID_LOGON_HOURS",
    "STATUS_INVALID_WORKSTATION",
    "STATUS_LOGON_FAILURE",
    "STATUS_LOGON_TYPE_NOT_GRANTED",
    "STATUS_NO_SUCH_USER",
    "STATUS_NTLM_BLOCKED",
    "STATUS_PASSWORD_EXPIRED",
    "STATUS_PASSWORD_MUST_CHANGE",
    "STATUS_WRONG_PASSWORD",
    "AccountLockoutConfig",
    "AccountLockoutResult",
    "AuthAttempt",
    "BruteAttemptObservation",
    "BruteProtectionConfig",
    "BruteProtectionResult",
    "EnumerationCandidateResult",
    "FreshAuthAttempt",
    "SemanticFingerprint",
    "UserEnumerationConfig",
    "UserEnumerationResult",
    "load_user_wordlist",
    "normalize_candidate_login",
    "normalize_ntstatus",
    "parse_user_wordlist",
    "run_brute_protection",
    "run_user_enumeration",
    "semantic_fingerprint",
]
