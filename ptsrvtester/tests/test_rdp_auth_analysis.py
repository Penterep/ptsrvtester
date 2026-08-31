import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ptsrvtester.protocols.rdp.utils.auth_analysis import (
    MAX_ENUMERATION_CANDIDATES,
    MAX_USER_WORDLIST_BYTES,
    STATUS_ACCOUNT_DISABLED,
    STATUS_ACCOUNT_EXPIRED,
    STATUS_ACCOUNT_LOCKED_OUT,
    STATUS_ACCOUNT_RESTRICTION,
    STATUS_INVALID_LOGON_HOURS,
    STATUS_INVALID_WORKSTATION,
    STATUS_LOGON_FAILURE,
    STATUS_LOGON_TYPE_NOT_GRANTED,
    STATUS_NO_SUCH_USER,
    STATUS_NTLM_BLOCKED,
    STATUS_PASSWORD_EXPIRED,
    STATUS_PASSWORD_MUST_CHANGE,
    STATUS_WRONG_PASSWORD,
    AccountLockoutConfig,
    AuthAttempt,
    BruteProtectionConfig,
    UserEnumerationConfig,
    _coerce_auth_attempt,
    load_user_wordlist,
    normalize_ntstatus,
    parse_user_wordlist,
    run_brute_protection,
    run_user_enumeration,
    semantic_fingerprint,
)


class TokenSequence:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, length: int) -> str:
        self.value += 1
        return f"{self.value:0{length * 2}x}"


def reverse(values) -> None:
    values.reverse()


def rejected(
    status: int,
    *,
    duration_ms: float = 10.0,
    outcome: str = "failed",
    server_error_from_credssp: bool = True,
) -> AuthAttempt:
    return AuthAttempt(
        outcome=outcome,
        failure_stage="credssp_auth",
        ntstatus=status,
        selected_protocol="hybrid_ex",
        server_error_from_credssp=server_error_from_credssp,
        duration_ms=duration_ms,
    )


class SemanticFingerprintTests(unittest.TestCase):
    def test_adapter_uses_connection_attempt_duration(self):
        attempt = _coerce_auth_attempt(
            SimpleNamespace(
                outcome="rejected",
                phase="credssp",
                server_error_code=STATUS_LOGON_FAILURE,
                server_error_from_credssp=True,
                connection_duration_ms=25.0,
                duration_ms=999.0,
            )
        )

        self.assertEqual(attempt.duration_ms, 25.0)
        self.assertTrue(attempt.server_error_from_credssp)

    def test_adapter_defaults_server_error_provenance_to_untrusted(self):
        attempt = _coerce_auth_attempt(
            SimpleNamespace(
                outcome="rejected",
                phase="credssp",
                server_error_code=STATUS_LOGON_FAILURE,
                duration_ms=25.0,
            )
        )

        self.assertFalse(attempt.server_error_from_credssp)
        self.assertFalse(semantic_fingerprint(attempt).server_error_from_credssp)

    def test_server_error_provenance_requires_a_boolean(self):
        with self.assertRaisesRegex(TypeError, "must be a boolean"):
            AuthAttempt(
                outcome="rejected",
                ntstatus=STATUS_LOGON_FAILURE,
                server_error_from_credssp="true",
            )

    def test_timing_is_not_part_of_semantic_fingerprint(self):
        first = rejected(STATUS_WRONG_PASSWORD, duration_ms=10)
        second = rejected(STATUS_WRONG_PASSWORD, duration_ms=10_000)

        self.assertEqual(semantic_fingerprint(first), semantic_fingerprint(second))
        self.assertEqual(
            semantic_fingerprint(first).ntstatus,
            "STATUS_WRONG_PASSWORD",
        )
        self.assertEqual(
            normalize_ntstatus("0xc0000234"),
            "STATUS_ACCOUNT_LOCKED_OUT",
        )
        self.assertEqual(
            normalize_ntstatus(0xD0000234),
            "STATUS_ACCOUNT_LOCKED_OUT",
        )
        self.assertEqual(
            normalize_ntstatus("0xd000006d"),
            "STATUS_LOGON_FAILURE",
        )
        self.assertEqual(
            normalize_ntstatus(0xD000015B),
            "STATUS_LOGON_TYPE_NOT_GRANTED",
        )


class UserWordlistTests(unittest.TestCase):
    def test_utf8_comments_namespace_normalization_and_deduplication(self):
        users = parse_user_wordlist(
            "\ufeff# comment\n alice \nALICE\n; ignored\nbøb\nOTHER\\carol\n",
            "EXAMPLE\\known",
        )

        self.assertEqual(
            users,
            (
                "EXAMPLE\\alice",
                "EXAMPLE\\bøb",
                "OTHER\\carol",
            ),
        )

    def test_upn_namespace_is_applied_to_unqualified_users(self):
        self.assertEqual(
            parse_user_wordlist(b"alice\nbob@example.test\n", "known@example.test"),
            ("alice@example.test", "bob@example.test"),
        )

    def test_loader_uses_strict_utf8(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.txt"
            path.write_bytes(b"alice\n\xff")

            with self.assertRaises(UnicodeDecodeError):
                load_user_wordlist(path, "EXAMPLE\\known")

    def test_parser_enforces_the_candidate_cap(self):
        contents = "\n".join(
            f"user-{index}" for index in range(MAX_ENUMERATION_CANDIDATES + 1)
        )

        with self.assertRaisesRegex(ValueError, "more than 1000"):
            parse_user_wordlist(contents, "EXAMPLE\\known")

    def test_loader_rejects_oversized_file_before_opening_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.txt"
            path.write_bytes(b"a" * (MAX_USER_WORDLIST_BYTES + 1))

            with (
                patch.object(Path, "open") as open_mock,
                self.assertRaisesRegex(ValueError, "byte size limit"),
            ):
                load_user_wordlist(path, "EXAMPLE\\known")

            open_mock.assert_not_called()

    def test_loader_bounded_read_catches_stale_size_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.txt"
            path.write_bytes(b"a" * (MAX_USER_WORDLIST_BYTES + 1))

            stale_stat = SimpleNamespace(st_size=MAX_USER_WORDLIST_BYTES)
            with (
                patch.object(Path, "stat", return_value=stale_stat),
                self.assertRaisesRegex(ValueError, "byte size limit"),
            ):
                load_user_wordlist(path, "EXAMPLE\\known")


class UserEnumerationTests(unittest.TestCase):
    def test_candidate_cap_and_delay_validation(self):
        with self.assertRaisesRegex(ValueError, "at most 1000"):
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=tuple(
                    f"user-{index}" for index in range(MAX_ENUMERATION_CANDIDATES + 1)
                ),
            )
        for delay in (-1, True, 1.5):
            with self.subTest(delay=delay), self.assertRaisesRegex(
                ValueError,
                "non-negative integer",
            ):
                UserEnumerationConfig(
                    valid_login="EXAMPLE\\known",
                    inter_attempt_delay_ms=delay,
                )

    def test_authorization_flag_requires_boolean_and_runtime_exact_true(self):
        with self.assertRaisesRegex(TypeError, "must be a boolean"):
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                allow_auth_failures="false",
            )

        calls = []
        config = UserEnumerationConfig(valid_login="EXAMPLE\\known")
        object.__setattr__(config, "allow_auth_failures", "false")

        result = run_user_enumeration(
            config,
            lambda login, password: calls.append((login, password)),
        )

        self.assertEqual(result.status, "blocked")
        self.assertEqual(calls, [])

    def test_explicit_authorization_is_required_before_any_attempt(self):
        calls = []

        result = run_user_enumeration(
            UserEnumerationConfig(valid_login="EXAMPLE\\known"),
            lambda login, password: calls.append((login, password)),
        )

        self.assertEqual(result.status, "blocked")
        self.assertEqual(calls, [])

    def test_baseline_uses_two_same_namespace_identities_and_one_bad_password(self):
        calls: list[tuple[str, str]] = []

        def attempt(login: str, password: str) -> AuthAttempt:
            calls.append((login, password))
            if login.casefold() in {
                "example\\known",
                "example\\alice",
            }:
                return rejected(STATUS_WRONG_PASSWORD, duration_ms=1000)
            return rejected(STATUS_NO_SUCH_USER, duration_ms=1)

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice", "ALICE", "bob", "known"),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
            shuffle=reverse,
        )

        self.assertEqual(result.status, "enumerable")
        self.assertTrue(result.invalid_baselines_consistent)
        self.assertEqual(result.existing_users, ("EXAMPLE\\alice",))
        self.assertEqual(result.non_existing_users, ("EXAMPLE\\bob",))
        self.assertEqual(len(calls), 5)
        self.assertEqual(len({password for _login, password in calls}), 1)
        baseline_logins = [login for login, _password in calls[:3]]
        invalid_logins = [
            login for login in baseline_logins if login != "EXAMPLE\\known"
        ]
        self.assertEqual(len(invalid_logins), 2)
        self.assertTrue(
            all(login.startswith("EXAMPLE\\ptsrv-invalid-") for login in invalid_logins)
        )
        self.assertEqual(len({login.casefold() for login in invalid_logins}), 2)
        self.assertEqual(
            sum(login.casefold() == "example\\alice" for login, _password in calls),
            1,
        )
        self.assertNotIn(calls[0][1], repr(result))

    def test_delay_is_applied_between_every_attempt_but_not_after_the_last(self):
        events: list[tuple[str, object]] = []

        def attempt(login: str, _password: str) -> AuthAttempt:
            events.append(("attempt", login))
            if login.casefold() in {"example\\known", "example\\alice"}:
                return rejected(STATUS_WRONG_PASSWORD)
            return rejected(STATUS_NO_SUCH_USER)

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice", "bob"),
                allow_auth_failures=True,
                inter_attempt_delay_ms=250,
            ),
            attempt,
            token_factory=TokenSequence(),
            shuffle=reverse,
            sleep=lambda seconds: events.append(("sleep", seconds)),
        )

        self.assertEqual(result.status, "enumerable")
        self.assertEqual(
            [kind for kind, _value in events],
            [
                "attempt",
                "sleep",
                "attempt",
                "sleep",
                "attempt",
                "sleep",
                "attempt",
                "sleep",
                "attempt",
            ],
        )
        self.assertEqual(
            [value for kind, value in events if kind == "sleep"],
            [0.25, 0.25, 0.25, 0.25],
        )

    def test_hresult_and_ntstatus_forms_have_the_same_fingerprint(self):
        def attempt(login: str, _password: str) -> AuthAttempt:
            status = (
                STATUS_LOGON_FAILURE | 0x10000000
                if login == "EXAMPLE\\known"
                else STATUS_LOGON_FAILURE
            )
            return rejected(status)

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "not_observed")

    def test_unavailable_or_invalid_baselines_never_report_not_observed(self):
        cases = (
            ("prerequisite_error", None, "blocked"),
            ("dependency_error", None, "blocked"),
            ("error", None, "inconclusive"),
            ("indeterminate", None, "inconclusive"),
            ("blocked", None, "inconclusive"),
            ("not_supported", None, "not_applicable"),
            ("blocked", STATUS_NTLM_BLOCKED, "not_applicable"),
        )
        for outcome, status_code, expected in cases:
            with self.subTest(outcome=outcome, status_code=status_code):
                calls: list[str] = []

                def attempt(
                    login: str,
                    _password: str,
                    *,
                    current_calls=calls,
                    current_outcome=outcome,
                    current_status_code=status_code,
                ) -> AuthAttempt:
                    current_calls.append(login)
                    return AuthAttempt(
                        outcome=current_outcome,
                        failure_stage="dependency",
                        ntstatus=current_status_code,
                        server_error_from_credssp=current_status_code is not None,
                    )

                result = run_user_enumeration(
                    UserEnumerationConfig(
                        valid_login="EXAMPLE\\known",
                        candidates=("alice",),
                        allow_auth_failures=True,
                    ),
                    attempt,
                    token_factory=TokenSequence(),
                )

                self.assertEqual(result.status, expected)
                self.assertNotEqual(result.status, "not_observed")
                expected_calls = 1 if expected == "blocked" and outcome in {
                    "prerequisite_error",
                    "dependency_error",
                } else 3
                self.assertEqual(len(calls), expected_calls)
                if outcome in {"prerequisite_error", "dependency_error"}:
                    self.assertIn("local RDP authentication", result.reason)

    def test_candidates_are_not_probed_when_semantics_do_not_differ(self):
        calls = []

        def attempt(login: str, password: str) -> AuthAttempt:
            calls.append((login, password))
            duration = 10_000 if login == "EXAMPLE\\known" else 1
            return rejected(STATUS_LOGON_FAILURE, duration_ms=duration)

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice", "bob"),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
            shuffle=reverse,
        )

        self.assertEqual(result.status, "not_observed")
        self.assertEqual(len(calls), 3)
        self.assertEqual(result.candidates, ())

    def test_same_exception_parsed_status_is_inconclusive(self):
        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice",),
                allow_auth_failures=True,
            ),
            lambda _login, _password: rejected(
                STATUS_LOGON_FAILURE,
                server_error_from_credssp=False,
            ),
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertIn("not decoded directly", result.reason)
        self.assertEqual(result.candidates, ())

    def test_selected_protocol_drift_alone_is_inconclusive(self):
        calls = []

        def attempt(login: str, _password: str) -> AuthAttempt:
            calls.append(login)
            return AuthAttempt(
                outcome="failed",
                failure_stage="credssp_auth",
                ntstatus=STATUS_LOGON_FAILURE,
                selected_protocol=(
                    "hybrid_ex" if login == "EXAMPLE\\known" else "hybrid"
                ),
                duration_ms=10,
            )

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice",),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertIn("diagnostic", result.reason)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result.candidates, ())

    def test_generic_failure_stage_drift_alone_is_inconclusive(self):
        def attempt(login: str, _password: str) -> AuthAttempt:
            return AuthAttempt(
                outcome="failed",
                failure_stage=(
                    "credssp_auth" if login == "EXAMPLE\\known" else "session"
                ),
                ntstatus=STATUS_LOGON_FAILURE,
                selected_protocol="hybrid_ex",
                duration_ms=10,
            )

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice",),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertNotEqual(result.status, "enumerable")
        self.assertEqual(result.candidates, ())

    def test_generic_auth_difference_requires_stable_known_confirmation(self):
        calls = []

        def attempt(login: str, _password: str) -> AuthAttempt:
            calls.append(login)
            return AuthAttempt(
                outcome=(
                    "credential_rejected"
                    if login == "EXAMPLE\\known"
                    else "identity_rejected"
                ),
                failure_stage="credssp_auth",
                selected_protocol="hybrid_ex",
                duration_ms=10,
            )

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice",),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertIn("repeatable", result.reason)
        self.assertIn("no account-specific server status", result.reason)
        self.assertEqual(result.baseline_attempts, 4)
        self.assertEqual(calls.count("EXAMPLE\\known"), 2)
        self.assertEqual(result.candidates, ())
        self.assertEqual(result.candidate_count_skipped, 1)

    def test_generic_known_status_against_no_such_user_is_inconclusive(self):
        calls = []

        def attempt(login: str, _password: str) -> AuthAttempt:
            calls.append(login)
            status = (
                STATUS_LOGON_FAILURE
                if login == "EXAMPLE\\known"
                else STATUS_NO_SUCH_USER
            )
            return rejected(status)

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice",),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertNotEqual(result.status, "enumerable")
        self.assertEqual(len(calls), 4)
        self.assertEqual(result.candidates, ())

    def test_exception_parsed_statuses_cannot_confirm_enumeration(self):
        provenance_cases = (
            (False, False),
            (True, False),
            (False, True),
        )
        for known_direct, invalid_direct in provenance_cases:
            with self.subTest(
                known_direct=known_direct,
                invalid_direct=invalid_direct,
            ):
                calls = []

                def attempt(
                    login: str,
                    _password: str,
                    current_calls=calls,
                    current_known_direct=known_direct,
                    current_invalid_direct=invalid_direct,
                ) -> AuthAttempt:
                    current_calls.append(login)
                    if login == "EXAMPLE\\known":
                        return rejected(
                            STATUS_WRONG_PASSWORD,
                            server_error_from_credssp=current_known_direct,
                        )
                    return rejected(
                        STATUS_NO_SUCH_USER,
                        server_error_from_credssp=current_invalid_direct,
                    )

                result = run_user_enumeration(
                    UserEnumerationConfig(
                        valid_login="EXAMPLE\\known",
                        candidates=("alice",),
                        allow_auth_failures=True,
                    ),
                    attempt,
                    token_factory=TokenSequence(),
                )

                self.assertEqual(result.status, "inconclusive")
                self.assertEqual(result.baseline_attempts, 4)
                self.assertEqual(len(calls), 4)
                self.assertEqual(result.candidates, ())

    def test_untrusted_logon_type_not_granted_does_not_confirm_enumeration(self):
        calls = []

        def attempt(login: str, _password: str) -> AuthAttempt:
            calls.append(login)
            if login == "EXAMPLE\\known":
                return rejected(
                    STATUS_LOGON_TYPE_NOT_GRANTED,
                    server_error_from_credssp=False,
                )
            return rejected(STATUS_NO_SUCH_USER)

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice",),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.baseline_attempts, 4)
        self.assertEqual(len(calls), 4)
        self.assertEqual(result.candidates, ())

    def test_same_logon_type_not_granted_status_does_not_confirm_enumeration(self):
        calls = []

        def attempt(login: str, _password: str) -> AuthAttempt:
            calls.append(login)
            return rejected(STATUS_LOGON_TYPE_NOT_GRANTED)

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice",),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "not_observed")
        self.assertEqual(result.baseline_attempts, 3)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result.candidates, ())

    def test_exception_parsed_candidate_statuses_are_inconclusive(self):
        def attempt(login: str, _password: str) -> AuthAttempt:
            if login == "EXAMPLE\\known":
                return rejected(STATUS_WRONG_PASSWORD)
            if login in {"EXAMPLE\\alice", "EXAMPLE\\bob"}:
                status = (
                    STATUS_WRONG_PASSWORD
                    if login == "EXAMPLE\\alice"
                    else STATUS_NO_SUCH_USER
                )
                return rejected(
                    status,
                    server_error_from_credssp=False,
                )
            return rejected(STATUS_NO_SUCH_USER)

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice", "bob"),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
            shuffle=lambda _values: None,
        )

        self.assertEqual(result.status, "enumerable")
        self.assertEqual(result.existing_users, ())
        self.assertEqual(result.non_existing_users, ())
        self.assertEqual(
            result.inconclusive_users,
            ("EXAMPLE\\alice", "EXAMPLE\\bob"),
        )

    def test_allowlisted_existing_account_statuses_confirm_enumeration(self):
        existing_statuses = (
            STATUS_WRONG_PASSWORD,
            STATUS_ACCOUNT_RESTRICTION,
            STATUS_INVALID_LOGON_HOURS,
            STATUS_INVALID_WORKSTATION,
            STATUS_PASSWORD_EXPIRED,
            STATUS_ACCOUNT_DISABLED,
            STATUS_LOGON_TYPE_NOT_GRANTED,
            STATUS_ACCOUNT_EXPIRED,
            STATUS_PASSWORD_MUST_CHANGE,
        )

        for existing_status in existing_statuses:
            with self.subTest(existing_status=existing_status):
                def attempt(
                    login: str,
                    _password: str,
                    current_status: int = existing_status,
                ) -> AuthAttempt:
                    if login.casefold() in {
                        "example\\known",
                        "example\\alice",
                    }:
                        return rejected(current_status)
                    return rejected(STATUS_NO_SUCH_USER)

                result = run_user_enumeration(
                    UserEnumerationConfig(
                        valid_login="EXAMPLE\\known",
                        candidates=("alice", "bob"),
                        allow_auth_failures=True,
                    ),
                    attempt,
                    token_factory=TokenSequence(),
                    shuffle=reverse,
                )

                self.assertEqual(result.status, "enumerable")
                self.assertEqual(result.existing_users, ("EXAMPLE\\alice",))
                self.assertEqual(result.non_existing_users, ("EXAMPLE\\bob",))

    def test_unstable_generic_auth_difference_is_inconclusive(self):
        known_attempts = 0

        def attempt(login: str, _password: str) -> AuthAttempt:
            nonlocal known_attempts
            if login == "EXAMPLE\\known":
                known_attempts += 1
                outcome = (
                    "credential_rejected"
                    if known_attempts == 1
                    else "different_rejection"
                )
            else:
                outcome = "identity_rejected"
            return AuthAttempt(
                outcome=outcome,
                failure_stage="credssp_auth",
                selected_protocol="hybrid_ex",
                duration_ms=10,
            )

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice",),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertIn("repeatable", result.reason)
        self.assertEqual(result.baseline_attempts, 4)
        self.assertEqual(result.candidates, ())

    def test_inconsistent_invalid_baselines_are_inconclusive(self):
        calls = []
        invalid_number = 0

        def attempt(login: str, password: str) -> AuthAttempt:
            nonlocal invalid_number
            calls.append((login, password))
            if login == "EXAMPLE\\known":
                return rejected(STATUS_WRONG_PASSWORD)
            invalid_number += 1
            return rejected(
                STATUS_NO_SUCH_USER if invalid_number == 1 else STATUS_LOGON_FAILURE
            )

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice",),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertFalse(result.invalid_baselines_consistent)
        self.assertEqual(len(calls), 3)

    def test_probe_exception_text_cannot_leak_credentials(self):
        captured = []

        def attempt(login: str, password: str) -> AuthAttempt:
            captured.append((login, password))
            raise RuntimeError(f"failure for {login} using {password}")

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "inconclusive")
        rendered = repr(result)
        self.assertNotIn("EXAMPLE\\known", rendered)
        for login, password in captured:
            self.assertNotIn(login, rendered)
            self.assertNotIn(password, rendered)

    def test_structured_engine_attempt_shape_is_accepted_without_backend_import(self):
        def attempt(login: str, _password: str):
            return SimpleNamespace(
                outcome="rejected",
                phase="credssp",
                server_error_code=(
                    STATUS_WRONG_PASSWORD
                    if login == "EXAMPLE\\known"
                    else STATUS_NO_SUCH_USER
                ),
                server_error_from_credssp=True,
                selected_protocol=8,
                duration_ms=5,
            )

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "enumerable")
        self.assertEqual(
            result.known_user_fingerprint.ntstatus,
            "STATUS_WRONG_PASSWORD",
        )

    def test_candidate_transient_stops_the_remaining_wordlist(self):
        calls = []

        def attempt(login: str, _password: str) -> AuthAttempt:
            calls.append(login)
            if len(calls) <= 3:
                return rejected(
                    STATUS_WRONG_PASSWORD
                    if login == "EXAMPLE\\known"
                    else STATUS_NO_SUCH_USER
                )
            return AuthAttempt(outcome="timeout", failure_stage="transport")

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("first", "second", "third"),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
            shuffle=lambda _values: None,
        )

        self.assertEqual(result.status, "enumerable_partial")
        self.assertEqual(result.candidate_count_requested, 3)
        self.assertEqual(result.candidate_count_tested, 1)
        self.assertEqual(result.candidate_count_skipped, 2)
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(len(calls), 4)

    def test_confirmed_lockout_during_baseline_is_inconclusive_not_blocked(self):
        calls = []

        def attempt(login: str, _password: str) -> AuthAttempt:
            calls.append(login)
            return rejected(STATUS_ACCOUNT_LOCKED_OUT)

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice",),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
            shuffle=lambda _values: None,
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertIn("lockout", result.reason)
        self.assertEqual(result.baseline_attempts, 1)
        self.assertEqual(result.candidate_count_tested, 0)
        self.assertEqual(len(calls), 1)

    def test_confirmed_lockout_during_candidates_preserves_enumeration_result(self):
        calls = []

        def attempt(login: str, _password: str) -> AuthAttempt:
            calls.append(login)
            if len(calls) <= 3:
                return rejected(
                    STATUS_WRONG_PASSWORD
                    if login == "EXAMPLE\\known"
                    else STATUS_NO_SUCH_USER
                )
            return rejected(STATUS_ACCOUNT_LOCKED_OUT)

        result = run_user_enumeration(
            UserEnumerationConfig(
                valid_login="EXAMPLE\\known",
                candidates=("alice", "bob"),
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
            shuffle=lambda _values: None,
        )

        self.assertEqual(result.status, "enumerable_partial")
        self.assertIn("lockout", result.reason)
        self.assertEqual(result.candidate_count_tested, 1)
        self.assertEqual(result.candidate_count_skipped, 1)
        self.assertEqual(result.existing_users, ("EXAMPLE\\alice",))
        self.assertEqual(len(calls), 4)


class BruteProtectionTests(unittest.TestCase):
    def test_safety_flags_require_boolean_and_runtime_exact_true(self):
        with self.assertRaisesRegex(TypeError, "must be a boolean"):
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=4,
                comparison_window=2,
                allow_auth_failures="false",
            )
        with self.assertRaisesRegex(TypeError, "must be a boolean"):
            AccountLockoutConfig(enabled="false")

        calls = []
        config = BruteProtectionConfig(
            namespace_login="EXAMPLE\\known",
            attempts=4,
            comparison_window=2,
        )
        object.__setattr__(config, "allow_auth_failures", "false")

        result = run_brute_protection(
            config,
            lambda login, password: calls.append((login, password)),
        )

        self.assertEqual(result.status, "blocked")
        self.assertEqual(calls, [])

    def test_lockout_runtime_guard_rejects_truthy_non_boolean(self):
        lockout = AccountLockoutConfig(enabled=False)
        object.__setattr__(lockout, "enabled", "false")
        calls = []

        result = run_brute_protection(
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=4,
                comparison_window=2,
                allow_auth_failures=True,
                account_lockout=lockout,
            ),
            lambda login, password: calls.append((login, password))
            or rejected(STATUS_NO_SUCH_USER),
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.account_lockout.status, "not_run")
        self.assertEqual(len(calls), 4)

    def test_authorization_is_required_before_any_attempt(self):
        calls = []
        result = run_brute_protection(
            BruteProtectionConfig(namespace_login="EXAMPLE\\known"),
            lambda login, password: calls.append((login, password)),
        )

        self.assertEqual(result.status, "blocked")
        self.assertEqual(calls, [])

    def test_random_nonexistent_series_reports_medians_and_timeout_transition(self):
        calls: list[tuple[str, str]] = []

        def attempt(login: str, password: str) -> AuthAttempt:
            calls.append((login, password))
            if len(calls) <= 4:
                return rejected(STATUS_NO_SUCH_USER, duration_ms=10)
            return AuthAttempt(
                outcome="timeout",
                failure_stage="transport",
                duration_ms=1000,
            )

        result = run_brute_protection(
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=6,
                comparison_window=2,
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
            shuffle=reverse,
        )

        self.assertEqual(result.status, "protection_observed")
        self.assertEqual(result.attempts_performed, 6)
        self.assertEqual(result.first_median_ms, 10)
        self.assertEqual(result.last_median_ms, 1000)
        self.assertEqual(result.median_change_ms, 990)
        self.assertEqual(result.median_ratio, 100)
        self.assertTrue(result.outcome_changed)
        self.assertTrue(result.timeout_observed)
        self.assertEqual(len({login.casefold() for login, _password in calls}), 6)
        self.assertTrue(
            all(
                login.startswith("EXAMPLE\\ptsrv-invalid-")
                for login, _password in calls
            )
        )
        self.assertEqual(len({password for _login, password in calls}), 1)
        self.assertNotIn(calls[0][1], repr(result))

    def test_repeated_blocking_stops_the_remaining_brute_series(self):
        calls = []

        def attempt(_login: str, _password: str) -> AuthAttempt:
            calls.append(len(calls) + 1)
            if len(calls) <= 3:
                return rejected(STATUS_NO_SUCH_USER, duration_ms=10)
            return AuthAttempt(
                outcome="timeout",
                failure_stage="transport",
                duration_ms=1000,
            )

        result = run_brute_protection(
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=10,
                comparison_window=3,
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "protection_observed")
        self.assertTrue(result.early_stopped)
        self.assertEqual(result.attempts_performed, 5)
        self.assertEqual(len(calls), 5)

    def test_single_timeout_never_proves_blocking(self):
        calls = []

        def attempt(_login: str, _password: str) -> AuthAttempt:
            calls.append(len(calls) + 1)
            if len(calls) == 5:
                return AuthAttempt(
                    outcome="timeout",
                    failure_stage="transport",
                    duration_ms=1000,
                )
            return rejected(STATUS_NO_SUCH_USER, duration_ms=10)

        result = run_brute_protection(
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=8,
                comparison_window=3,
                allow_auth_failures=True,
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertNotEqual(result.status, "protection_observed")

    def test_two_sample_timing_windows_are_reported_as_insufficient(self):
        durations = iter((10, 10, 1000, 1000))

        result = run_brute_protection(
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=4,
                comparison_window=2,
                allow_auth_failures=True,
            ),
            lambda _login, _password: rejected(
                STATUS_NO_SUCH_USER,
                duration_ms=next(durations),
            ),
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "insufficient_samples")
        self.assertIn("three-sample windows", result.reason)
        self.assertEqual(result.first_median_ms, 10)
        self.assertEqual(result.last_median_ms, 1000)
        self.assertFalse(result.outcome_changed)

    def test_three_sample_strong_slowdown_is_reported_as_a_signal_only(self):
        durations = iter((10, 11, 12, 900, 1000, 1100))

        result = run_brute_protection(
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=6,
                comparison_window=3,
                allow_auth_failures=True,
            ),
            lambda _login, _password: rejected(
                STATUS_NO_SUCH_USER,
                duration_ms=next(durations),
            ),
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.status, "slowdown_signal")
        self.assertTrue(result.slowdown_signal)
        self.assertNotEqual(result.status, "protection_observed")

    def test_invalid_or_unavailable_series_never_reports_not_observed(self):
        cases = (
            ("prerequisite_error", None, "blocked"),
            ("dependency_error", None, "blocked"),
            ("error", None, "inconclusive"),
            ("indeterminate", None, "inconclusive"),
            ("blocked", None, "inconclusive"),
            ("not_supported", None, "not_applicable"),
            ("blocked", STATUS_NTLM_BLOCKED, "not_applicable"),
        )
        for outcome, status_code, expected in cases:
            with self.subTest(outcome=outcome, status_code=status_code):
                result = run_brute_protection(
                    BruteProtectionConfig(
                        namespace_login="EXAMPLE\\known",
                        attempts=4,
                        comparison_window=2,
                        allow_auth_failures=True,
                    ),
                    lambda _login, _password, current_outcome=outcome,
                    current_status_code=status_code: AuthAttempt(
                        outcome=current_outcome,
                        failure_stage="dependency",
                        ntstatus=current_status_code,
                        server_error_from_credssp=current_status_code is not None,
                    ),
                    token_factory=TokenSequence(),
                )

                self.assertEqual(result.status, expected)
                self.assertNotEqual(result.status, "not_observed")
                if outcome in {"prerequisite_error", "dependency_error"}:
                    self.assertEqual(result.attempts_performed, 1)
                    self.assertIn("local RDP authentication", result.reason)

    def test_account_lockout_probe_is_opt_in_and_secrets_are_hidden(self):
        calls = []
        lockout = AccountLockoutConfig(
            enabled=False,
            valid_login="EXAMPLE\\known",
            valid_password="SuperSecret",
        )
        config = BruteProtectionConfig(
            namespace_login="EXAMPLE\\known",
            attempts=4,
            comparison_window=2,
            allow_auth_failures=True,
            account_lockout=lockout,
        )

        result = run_brute_protection(
            config,
            lambda login, password: calls.append((login, password))
            or rejected(STATUS_NO_SUCH_USER),
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.account_lockout.status, "not_run")
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(login != "EXAMPLE\\known" for login, _password in calls))
        self.assertNotIn("SuperSecret", repr(config))

    def test_lockout_stops_bad_passwords_and_runs_final_valid_probe(self):
        real_calls: list[tuple[str, str]] = []
        sleep_calls: list[float] = []

        def attempt(login: str, password: str) -> AuthAttempt:
            if login != "EXAMPLE\\known":
                return rejected(STATUS_NO_SUCH_USER)
            real_calls.append((login, password))
            if len(real_calls) == 1:
                return AuthAttempt(outcome="authenticated", duration_ms=10)
            if len(real_calls) == 2:
                return rejected(STATUS_WRONG_PASSWORD)
            return AuthAttempt(
                outcome="failed",
                failure_stage="credssp_auth",
                ntstatus=STATUS_ACCOUNT_LOCKED_OUT | 0x10000000,
                server_error_from_credssp=True,
                duration_ms=10,
            )

        result = run_brute_protection(
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=4,
                comparison_window=2,
                allow_auth_failures=True,
                inter_attempt_delay_ms=250,
                account_lockout=AccountLockoutConfig(
                    enabled=True,
                    valid_login="EXAMPLE\\known",
                    valid_password="CorrectPassword",
                    bad_attempts=5,
                ),
            ),
            attempt,
            token_factory=TokenSequence(),
            sleep=sleep_calls.append,
        )

        self.assertEqual(result.status, "insufficient_samples")
        lockout = result.account_lockout
        self.assertEqual(lockout.status, "lockout_observed")
        self.assertEqual(lockout.bad_attempts_performed, 2)
        self.assertEqual(lockout.locked_at_attempt, 2)
        self.assertEqual(len(real_calls), 4)
        self.assertEqual(real_calls[0][1], "CorrectPassword")
        self.assertNotEqual(real_calls[1][1], "CorrectPassword")
        self.assertNotEqual(real_calls[2][1], "CorrectPassword")
        self.assertNotEqual(real_calls[1][1], real_calls[2][1])
        self.assertEqual(real_calls[3][1], "CorrectPassword")
        self.assertNotIn("CorrectPassword", repr(result))
        # Four random attempts plus baseline, two bad passwords and final valid
        # probe produce one delay between every adjacent authentication attempt.
        self.assertEqual(sleep_calls, [0.25] * 7)

    def test_untrusted_lockout_signal_stops_bad_passwords_but_is_inconclusive(self):
        real_calls: list[tuple[str, str]] = []

        def attempt(login: str, password: str) -> AuthAttempt:
            if login != "EXAMPLE\\known":
                return rejected(STATUS_NO_SUCH_USER)
            real_calls.append((login, password))
            if len(real_calls) in {1, 3}:
                return AuthAttempt(outcome="authenticated", duration_ms=10)
            return rejected(
                STATUS_ACCOUNT_LOCKED_OUT,
                server_error_from_credssp=False,
            )

        result = run_brute_protection(
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=4,
                comparison_window=2,
                allow_auth_failures=True,
                account_lockout=AccountLockoutConfig(
                    enabled=True,
                    valid_login="EXAMPLE\\known",
                    valid_password="CorrectPassword",
                    bad_attempts=5,
                ),
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        lockout = result.account_lockout
        self.assertEqual(lockout.status, "inconclusive")
        self.assertIn("provenance", lockout.reason)
        self.assertEqual(lockout.bad_attempts_performed, 1)
        self.assertIsNone(lockout.locked_at_attempt)
        self.assertEqual(len(real_calls), 3)
        self.assertEqual(real_calls[0][1], "CorrectPassword")
        self.assertNotEqual(real_calls[1][1], "CorrectPassword")
        self.assertEqual(real_calls[2][1], "CorrectPassword")

    def test_lockout_probe_is_skipped_after_random_series_blocking(self):
        real_calls = []

        def attempt(login: str, _password: str) -> AuthAttempt:
            if login == "EXAMPLE\\known":
                real_calls.append(login)
            return AuthAttempt(
                outcome="timeout",
                failure_stage="transport",
                duration_ms=1000,
            )

        result = run_brute_protection(
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=4,
                comparison_window=2,
                allow_auth_failures=True,
                account_lockout=AccountLockoutConfig(
                    enabled=True,
                    valid_login="EXAMPLE\\known",
                    valid_password="CorrectPassword",
                    bad_attempts=3,
                ),
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.account_lockout.status, "skipped")
        self.assertEqual(real_calls, [])

    def test_invalid_valid_credential_baseline_sends_no_bad_account_passwords(self):
        real_calls = []

        def attempt(login: str, password: str) -> AuthAttempt:
            if login == "EXAMPLE\\known":
                real_calls.append((login, password))
                return rejected(STATUS_LOGON_FAILURE)
            return rejected(STATUS_NO_SUCH_USER)

        result = run_brute_protection(
            BruteProtectionConfig(
                namespace_login="EXAMPLE\\known",
                attempts=4,
                comparison_window=2,
                allow_auth_failures=True,
                account_lockout=AccountLockoutConfig(
                    enabled=True,
                    valid_login="EXAMPLE\\known",
                    valid_password="WrongOrUnavailable",
                    bad_attempts=5,
                ),
            ),
            attempt,
            token_factory=TokenSequence(),
        )

        self.assertEqual(result.account_lockout.status, "blocked")
        self.assertEqual(result.account_lockout.bad_attempts_performed, 0)
        self.assertEqual(len(real_calls), 1)

    def test_attempt_caps_are_validated(self):
        with self.assertRaises(ValueError):
            BruteProtectionConfig(
                namespace_login="known",
                attempts=101,
                comparison_window=2,
            )
        with self.assertRaises(ValueError):
            AccountLockoutConfig(
                enabled=True,
                valid_login="known",
                valid_password="secret",
                bad_attempts=21,
            )


if __name__ == "__main__":
    unittest.main()
