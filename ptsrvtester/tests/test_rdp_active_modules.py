import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ptsrvtester.protocols.rdp.utils.auth_analysis import (
    AccountLockoutResult,
    BruteProtectionConfig,
    BruteProtectionResult,
    UserEnumerationResult,
)
from ptsrvtester.protocols.rdp.utils.auth_attempts import (
    AuthAttemptResult,
    AuthMechanism,
    AuthOutcome,
    AuthPhase,
    CredentialKind,
    CredentialSource,
    TLSVerification,
)
from ptsrvtester.protocols.rdp.utils.cli import RDP_EXPLICIT_ONLY_TESTS, RDPArgs
from ptsrvtester.protocols.rdp.utils.engine import (
    IMPLEMENTED_TESTS,
    PROTOCOL_HYBRID,
    PROTOCOL_HYBRID_EX,
    PROTOCOL_SSL,
    RDP,
    RDP_TEST_ORDER,
    AuthMethodObservation,
    AuthTLSValidationResult,
    NegotiationProbe,
    NTLMInfoResult,
    RDPAuthMethodsResult,
    RDPBruteProtectionResult,
)


def active_args(**overrides) -> RDPArgs:
    values = {
        "module": "rdp",
        "target": SimpleNamespace(ip="192.0.2.10", port=3389),
        "tests": None,
        "login": None,
        "password": None,
        "insecure_auth": False,
        "auth_methods": None,
        "realm": None,
        "kdc": None,
        "spn_host": None,
        "users": None,
        "allow_auth_failures": False,
        "guess_attempts": 10,
        "guess_delay_ms": 0,
        "lockout_test": False,
        "lockout_attempts": 3,
        "allow_load_test": False,
        "rate_mode": "both",
        "rate_count": 30,
        "rate_concurrency": 10,
        "rate_hold_seconds": 0.0,
        "rate_cooldown_seconds": 0.0,
        "timeout": 10000,
        "json": False,
        "debug": False,
    }
    values.update(overrides)
    return RDPArgs(**values)


def fresh_result(
    *,
    status: int | None = 0xC000006D,
    outcome: AuthOutcome = AuthOutcome.REJECTED,
    mechanism: AuthMechanism = AuthMechanism.NTLM,
    server_response_observed: bool = True,
    server_error_from_credssp: bool | None = None,
    phase: AuthPhase = AuthPhase.CREDSSP,
    error: str | None = None,
) -> AuthAttemptResult:
    names = {
        0xC0000064: "STATUS_NO_SUCH_USER",
        0xC000006A: "STATUS_WRONG_PASSWORD",
        0xC000006D: "STATUS_LOGON_FAILURE",
        0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
    }
    if server_error_from_credssp is None:
        server_error_from_credssp = (
            status is not None and server_response_observed
        )
    return AuthAttemptResult(
        mechanism=mechanism,
        credential_kind=CredentialKind.PASSWORD,
        credential_source=CredentialSource.GENERATED,
        outcome=outcome,
        phase=phase,
        duration_ms=15.0,
        connection_duration_ms=12.5,
        selected_protocol=PROTOCOL_HYBRID,
        selected_protocol_name="HYBRID",
        selected_mechanism=mechanism.value,
        server_response_observed=server_response_observed,
        tls_verification=TLSVerification.VERIFIED,
        certificate_sha256="ab" * 32,
        server_error_code=status,
        server_error_name=names.get(status),
        server_error_from_credssp=server_error_from_credssp,
        error=error,
        evidence=("CredSSP server token received",),
    )


class RDPActiveModuleIntegrationTests(unittest.TestCase):
    def test_legacy_engine_default_never_runs_explicit_only_tests(self):
        engine = RDP(active_args(), Mock())
        engine.run_test = Mock()

        engine.run()

        selected = [call.args[0] for call in engine.run_test.call_args_list]
        expected = [
            code
            for code in RDP_TEST_ORDER
            if code in IMPLEMENTED_TESTS
            and code != "AUTH"
            and code not in RDP_EXPLICIT_ONLY_TESTS
        ]
        self.assertEqual(selected, expected)

    def test_active_modules_are_guarded_before_network_activity(self):
        engine = RDP(active_args(), Mock())
        engine._get_auth_tls_validation_result = Mock(
            side_effect=AssertionError("network must not be reached")
        )

        self.assertEqual(engine._run_user_enumeration_test().status, "blocked")
        self.assertEqual(
            engine._run_brute_protection_test().analysis.status,
            "blocked",
        )
        engine._get_auth_tls_validation_result.assert_not_called()

    def test_auth_failure_opt_in_requires_the_boolean_true_value(self):
        engine = RDP(
            active_args(
                login="EXAMPLE\\known",
                allow_auth_failures="false",
            ),
            Mock(),
        )
        engine._get_auth_tls_validation_result = Mock(
            side_effect=AssertionError("network must not be reached")
        )

        self.assertEqual(engine._run_user_enumeration_test().status, "blocked")
        self.assertEqual(
            engine._run_brute_protection_test().analysis.status,
            "blocked",
        )
        engine._get_auth_tls_validation_result.assert_not_called()

    def test_kerberos_without_prerequisites_is_explicit_not_unknown(self):
        engine = RDP(active_args(auth_methods=["kerberos"]), Mock())

        result = engine._run_auth_methods_test()

        self.assertEqual(result.status, "partial")
        self.assertEqual(result.methods[0].status, "prerequisite_error")
        self.assertIn("--realm", result.methods[0].reason)

    def test_kerberos_only_with_one_credential_never_claims_ntlm_was_used(self):
        engine = RDP(
            active_args(
                auth_methods=["kerberos"],
                login="tester@example.test",
                realm="EXAMPLE.TEST",
                kdc="192.0.2.20",
                spn_host="rdp.example.test",
            ),
            Mock(),
        )

        result = engine._run_auth_methods_test()

        self.assertEqual(result.methods[0].status, "prerequisite_error")
        self.assertNotIn("NTLM", result.note or "")
        self.assertIn("not used", result.note)

    def test_ntlm_challenge_does_not_hide_a_failed_fresh_attempt(self):
        engine = RDP(active_args(auth_methods=["ntlm"]), Mock())
        engine.results.ntlm_info = NTLMInfoResult("empty")
        engine._run_fresh_auth_attempt = Mock(
            return_value=fresh_result(
                outcome=AuthOutcome.TRANSPORT_ERROR,
                server_response_observed=False,
            )
        )

        result = engine._run_auth_methods_test()

        self.assertEqual(result.status, "partial")
        self.assertEqual(result.methods[0].status, "advertised")
        self.assertIn("fresh credential attempt", result.methods[0].reason)
        self.assertNotIn("credentials were rejected", result.methods[0].reason)

    def test_ntlm_challenge_names_missing_client_dependency(self):
        engine = RDP(active_args(auth_methods=["ntlm"]), Mock())
        engine.results.ntlm_info = NTLMInfoResult("empty")
        engine._run_fresh_auth_attempt = Mock(
            return_value=fresh_result(
                outcome=AuthOutcome.PREREQUISITE_ERROR,
                phase=AuthPhase.DEPENDENCY,
                server_response_observed=False,
                error="RDP authentication dependency is unavailable: aardwolf",
            )
        )

        result = engine._run_auth_methods_test()

        self.assertEqual(result.status, "partial")
        self.assertEqual(result.methods[0].status, "advertised")
        self.assertIn("dependency is unavailable: aardwolf", result.methods[0].reason)

    def test_authmethods_does_not_confirm_exception_parsed_blocking_status(self):
        engine = RDP(active_args(auth_methods=["ntlm"]), Mock())
        engine.results.ntlm_info = NTLMInfoResult("error")
        engine._run_fresh_auth_attempt = Mock(
            return_value=fresh_result(
                status=0xC0000234,
                outcome=AuthOutcome.BLOCKED,
                server_error_from_credssp=False,
                error="backend exception 0xc0000234",
            )
        )

        result = engine._run_auth_methods_test()

        self.assertEqual(result.status, "partial")
        self.assertEqual(result.methods[0].status, "indeterminate")
        self.assertIn("not decoded directly", result.methods[0].reason)
        self.assertNotIn("server returned", result.methods[0].reason.lower())

        engine.ptprint = Mock()
        engine._print_status = Mock()
        engine.ptdebug = Mock()
        engine._output_auth_methods_text(result)
        debug_messages = [call.args[0] for call in engine.ptdebug.call_args_list]
        self.assertTrue(
            any("unverified parsed status=" in message for message in debug_messages)
        )
        self.assertFalse(any("server status=" in message for message in debug_messages))

    def test_authmethods_untrusted_rejection_is_indeterminate_without_preflight(self):
        engine = RDP(active_args(auth_methods=["ntlm"]), Mock())
        engine.results.ntlm_info = NTLMInfoResult("error")
        engine._run_fresh_auth_attempt = Mock(
            return_value=fresh_result(
                status=0xC000006A,
                outcome=AuthOutcome.REJECTED,
                server_error_from_credssp=False,
                error="backend exception 0xc000006a",
            )
        )

        result = engine._run_auth_methods_test()

        self.assertEqual(result.status, "partial")
        self.assertEqual(result.methods[0].status, "indeterminate")
        self.assertIn(
            "unverified status parsed from backend error",
            result.methods[0].reason,
        )

    def test_authmethods_ntlm_preflight_does_not_confirm_parsed_rejection(self):
        engine = RDP(active_args(auth_methods=["ntlm"]), Mock())
        engine.results.ntlm_info = NTLMInfoResult("empty")
        engine._run_fresh_auth_attempt = Mock(
            return_value=fresh_result(
                status=0xC000006A,
                outcome=AuthOutcome.REJECTED,
                server_error_from_credssp=False,
                error="backend exception 0xc000006a",
            )
        )

        result = engine._run_auth_methods_test()

        self.assertEqual(result.methods[0].status, "negotiable")
        self.assertIn("confirmed independently", result.methods[0].reason)
        self.assertIn("unverified rejection status", result.methods[0].reason)
        self.assertNotIn("credentials were rejected", result.methods[0].reason)

    def test_authmethods_account_lockout_is_not_rendered_as_ok(self):
        engine = RDP(active_args(auth_methods=["ntlm"]), Mock())
        engine.results.ntlm_info = NTLMInfoResult("error")
        engine._run_fresh_auth_attempt = Mock(
            return_value=fresh_result(
                status=0xC0000234,
                outcome=AuthOutcome.BLOCKED,
                server_error_from_credssp=True,
            )
        )

        result = engine._run_auth_methods_test()

        method = result.methods[0]
        self.assertEqual(method.status, "blocked")
        self.assertIn(
            "CredSSP server returned STATUS_ACCOUNT_LOCKED_OUT",
            method.reason,
        )
        self.assertEqual(engine._auth_method_output_category(method).value, "WARNING")

    def test_module_error_redacts_domain_login_components(self):
        login = "EXAMPLE\\split-user"
        engine = RDP(
            active_args(login=login, password="SecretPassword"),
            Mock(),
        )
        engine.run_test = Mock(
            side_effect=RuntimeError(
                "backend leaked domain EXAMPLE and user split-user"
            )
        )
        context = SimpleNamespace(out=Mock())

        engine.run_module("AUTHMETHODS", context)

        rendered = engine.results.module_errors["AUTHMETHODS"]
        emitted = str(context.out.call_args)
        for secret in (login, "EXAMPLE", "split-user", "SecretPassword"):
            self.assertNotIn(secret.casefold(), rendered.casefold())
            self.assertNotIn(secret.casefold(), emitted.casefold())
        self.assertIn("<redacted>", rendered)

    def test_active_ntlm_preflight_is_not_published_as_ntlminfo_finding(self):
        ptjsonlib = Mock()
        ptjsonlib.create_node_object.return_value = {"key": "rdp-node"}
        ptjsonlib.get_result_json.return_value = {}
        engine = RDP(active_args(auth_methods=["ntlm"]), ptjsonlib)
        preflight = NTLMInfoResult("empty")
        engine._run_ntlminfo_test = Mock(return_value=preflight)
        engine._run_fresh_auth_attempt = Mock(return_value=fresh_result())

        engine.run_test("AUTHMETHODS")
        engine.output(emit_text=False)

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertNotIn("ntlmInfo", properties)
        ptjsonlib.add_vulnerability.assert_not_called()
        self.assertIsNone(engine.results.ntlm_info)

        engine.run_test("NTLMINFO")
        self.assertIs(engine.results.ntlm_info, preflight)
        engine._run_ntlminfo_test.assert_called_once_with()

    def test_user_enumeration_confirms_identity_specific_ntstatus_difference(self):
        known_login = "EXAMPLE\\known-user"
        engine = RDP(
            active_args(login=known_login, allow_auth_failures=True),
            Mock(),
        )
        engine.results.ntlm_info = NTLMInfoResult("empty")
        engine._get_auth_tls_validation_result = Mock(
            return_value=AuthTLSValidationResult("verified", "ab" * 32)
        )

        def attempt(login, _password, **_kwargs):
            return fresh_result(
                status=0xC000006A if login == known_login else 0xC0000064
            )

        engine._run_fresh_auth_attempt = Mock(side_effect=attempt)

        result = engine._run_user_enumeration_test()

        self.assertEqual(result.status, "enumerable")
        self.assertEqual(result.baseline_attempts, 3)
        self.assertTrue(result.invalid_baselines_consistent)
        self.assertEqual(engine._run_fresh_auth_attempt.call_count, 3)

    @patch(
        "ptsrvtester.protocols.rdp.utils.engine.load_user_wordlist",
        return_value=("EXAMPLE\\candidate",),
    )
    def test_user_enumeration_inconclusive_does_not_probe_candidates(self, _loader):
        known_login = "EXAMPLE\\known-user"
        engine = RDP(
            active_args(
                login=known_login,
                users="users.txt",
                allow_auth_failures=True,
            ),
            Mock(),
        )
        engine.results.ntlm_info = NTLMInfoResult("empty")
        engine._get_auth_tls_validation_result = Mock(
            return_value=AuthTLSValidationResult("verified", "ab" * 32)
        )

        def attempt(login, _password, **_kwargs):
            return fresh_result(
                status=0xC000006D if login == known_login else None
            )

        engine._run_fresh_auth_attempt = Mock(side_effect=attempt)

        result = engine._run_user_enumeration_test()

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.baseline_attempts, 4)
        self.assertEqual(result.candidate_count_requested, 1)
        self.assertEqual(result.candidates, ())
        self.assertEqual(engine._run_fresh_auth_attempt.call_count, 4)

    def test_user_enumeration_rejects_invalid_supplied_credential_baseline(self):
        engine = RDP(
            active_args(
                login="EXAMPLE\\known-user",
                password="claimed-valid",
                allow_auth_failures=True,
            ),
            Mock(),
        )
        engine.results.ntlm_info = NTLMInfoResult("empty")
        engine._get_auth_tls_validation_result = Mock(
            return_value=AuthTLSValidationResult("verified", "ab" * 32)
        )
        engine._run_fresh_auth_attempt = Mock(return_value=fresh_result())

        result = engine._run_user_enumeration_test()

        self.assertEqual(result.status, "blocked")
        self.assertIn("did not authenticate", result.reason)
        self.assertIn("no intentional failed login", result.reason)
        engine._run_fresh_auth_attempt.assert_called_once()
        call = engine._run_fresh_auth_attempt.call_args
        self.assertEqual(call.args, ("EXAMPLE\\known-user", "claimed-valid"))
        self.assertIs(call.kwargs["mechanism"], AuthMechanism.NTLM)
        self.assertIs(
            call.kwargs["credential_source"],
            CredentialSource.PROVIDED,
        )

    @patch("ptsrvtester.protocols.rdp.utils.engine.run_user_enumeration")
    def test_user_enumeration_adapter_passes_the_configured_delay(self, runner):
        runner.return_value = UserEnumerationResult(
            status="not_observed",
            reason="same response",
        )
        engine = RDP(
            active_args(
                login="EXAMPLE\\known-user",
                allow_auth_failures=True,
                guess_delay_ms=125,
            ),
            Mock(),
        )
        engine.results.ntlm_info = NTLMInfoResult("empty")
        engine._get_auth_tls_validation_result = Mock(
            return_value=AuthTLSValidationResult("verified", "ab" * 32)
        )

        engine._run_user_enumeration_test()

        config = runner.call_args.args[0]
        self.assertEqual(config.inter_attempt_delay_ms, 125)

    def test_brute_protection_adapter_reports_bounded_absence_not_unknown(self):
        engine = RDP(
            active_args(allow_auth_failures=True, guess_attempts=6),
            Mock(),
        )
        engine._get_auth_tls_validation_result = Mock(
            return_value=AuthTLSValidationResult("verified", "ab" * 32)
        )
        engine.results.ntlm_info = NTLMInfoResult("empty")
        engine._run_fresh_auth_attempt = Mock(return_value=fresh_result())
        engine._negotiate = Mock(
            return_value=NegotiationProbe(
                "recovery",
                PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX,
                selected_protocol=PROTOCOL_HYBRID,
            )
        )

        result = engine._run_brute_protection_test()

        self.assertEqual(result.analysis.status, "not_observed")
        self.assertEqual(result.analysis.attempts_performed, 6)
        self.assertEqual(result.config.attempts, 6)
        self.assertEqual(result.config.inter_attempt_delay_ms, 0)
        self.assertIsNotNone(result.service_recovery_probe.selected_protocol)

    def test_brute_dependency_block_skips_post_pressure_recovery(self):
        engine = RDP(
            active_args(allow_auth_failures=True, guess_attempts=4),
            Mock(),
        )
        engine._get_auth_tls_validation_result = Mock(
            return_value=AuthTLSValidationResult("verified", "ab" * 32)
        )
        engine.results.ntlm_info = NTLMInfoResult("empty")
        engine._run_fresh_auth_attempt = Mock(
            return_value=fresh_result(
                outcome=AuthOutcome.PREREQUISITE_ERROR,
                phase=AuthPhase.DEPENDENCY,
                server_response_observed=False,
                error="RDP authentication dependency is unavailable: aardwolf",
            )
        )
        engine._negotiate = Mock(
            side_effect=AssertionError("recovery must not run without auth pressure")
        )

        result = engine._run_brute_protection_test()

        self.assertEqual(result.analysis.status, "blocked")
        self.assertIn("no failed login was sent", result.analysis.reason)
        self.assertIsNone(result.service_recovery_probe)
        engine._run_fresh_auth_attempt.assert_called_once()
        engine._negotiate.assert_not_called()

    def test_brute_protection_stops_when_supplied_baseline_is_not_valid(self):
        engine = RDP(
            active_args(
                login="EXAMPLE\\disposable",
                password="claimed-valid",
                allow_auth_failures=True,
                guess_attempts=4,
            ),
            Mock(),
        )
        engine._get_auth_tls_validation_result = Mock(
            return_value=AuthTLSValidationResult("verified", "ab" * 32)
        )
        engine.results.ntlm_info = NTLMInfoResult("empty")
        engine._run_fresh_auth_attempt = Mock(return_value=fresh_result())

        result = engine._run_brute_protection_test()

        self.assertEqual(result.analysis.status, "blocked")
        self.assertIn("no failed-login pressure", result.analysis.reason)
        engine._run_fresh_auth_attempt.assert_called_once()

    def test_brute_protection_never_hides_loss_of_valid_authentication(self):
        engine = RDP(
            active_args(
                login="EXAMPLE\\disposable",
                password="valid",
                allow_auth_failures=True,
                guess_attempts=4,
            ),
            Mock(),
        )
        engine._get_auth_tls_validation_result = Mock(
            return_value=AuthTLSValidationResult("verified", "ab" * 32)
        )
        engine.results.ntlm_info = NTLMInfoResult("empty")
        outcomes = [
            fresh_result(status=0, outcome=AuthOutcome.AUTHENTICATED),
            *(fresh_result() for _ in range(4)),
            fresh_result(),
        ]
        engine._run_fresh_auth_attempt = Mock(side_effect=outcomes)
        engine._negotiate = Mock(
            return_value=NegotiationProbe(
                "recovery",
                PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX,
                selected_protocol=PROTOCOL_HYBRID,
            )
        )

        result = engine._run_brute_protection_test()

        self.assertEqual(result.analysis.status, "inconclusive")
        self.assertIn("final valid-credential probe", result.analysis.reason)

    def test_kerberos_client_side_selection_does_not_prove_server_support(self):
        engine = RDP(
            active_args(
                auth_methods=["kerberos"],
                login="tester@example.test",
                password="secret",
                realm="EXAMPLE.TEST",
                kdc="192.0.2.20",
                spn_host="rdp.example.test",
            ),
            Mock(),
        )
        engine._run_fresh_auth_attempt = Mock(
            return_value=fresh_result(
                mechanism=AuthMechanism.KERBEROS,
                outcome=AuthOutcome.TRANSPORT_ERROR,
                server_response_observed=False,
            )
        )

        result = engine._run_auth_methods_test()

        self.assertNotEqual(result.methods[0].status, "negotiable")
        self.assertEqual(result.methods[0].status, "transport_error")

    def test_json_output_contains_actionable_results_and_no_password(self):
        password = "NeverSerializeThisPassword"
        ptjsonlib = Mock()
        ptjsonlib.create_node_object.return_value = {"key": "rdp-node"}
        ptjsonlib.get_result_json.return_value = {}
        engine = RDP(active_args(password=password), ptjsonlib)
        attempt = fresh_result()
        engine.results.auth_methods = RDPAuthMethodsResult(
            status="ok",
            methods=(
                AuthMethodObservation(
                    mechanism="ntlm",
                    credential_source="generated",
                    status="negotiable",
                    attempt=attempt,
                    reason="NTLM challenge received",
                ),
            ),
        )
        engine.results.user_enumeration = UserEnumerationResult(
            status="not_observed",
            reason="same semantic response",
            baseline_attempts=3,
            invalid_baselines_consistent=True,
            candidate_count_requested=2,
        )
        engine.results.brute_protection = RDPBruteProtectionResult(
            analysis=BruteProtectionResult(
                status="not_observed",
                reason="bounded sample completed",
                attempts_performed=4,
            ),
            config=BruteProtectionConfig(
                namespace_login="EXAMPLE\\baseline",
                attempts=4,
                comparison_window=2,
                allow_auth_failures=True,
                inter_attempt_delay_ms=25,
            ),
        )
        engine.output(emit_text=False)

        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(
            properties["authenticationMethods"]["methods"][0]["status"],
            "negotiable",
        )
        attempt_json = properties["authenticationMethods"]["methods"][0]["attempt"]
        self.assertEqual(attempt_json["connectionDurationMs"], 12.5)
        self.assertTrue(attempt_json["serverErrorFromCredssp"])
        self.assertNotIn("responseDurationMs", attempt_json)
        self.assertEqual(properties["userEnumeration"]["status"], "not_observed")
        self.assertFalse(
            properties["userEnumeration"]["timingUsedForClassification"]
        )
        self.assertEqual(
            properties["userEnumeration"]["mechanism"],
            "credssp_ntlm",
        )
        self.assertEqual(
            properties["userEnumeration"]["candidateCountSkipped"],
            2,
        )
        self.assertEqual(
            properties["passwordGuessingProtection"]["attemptsPerformed"],
            4,
        )
        self.assertEqual(
            properties["passwordGuessingProtection"]["configuredAttempts"],
            4,
        )
        self.assertEqual(
            properties["passwordGuessingProtection"]["interAttemptDelayMs"],
            25,
        )
        self.assertEqual(
            properties["passwordGuessingProtection"]["identityStrategy"],
            "random_nonexistent_identities",
        )
        self.assertNotIn(password, str(properties))

    def test_blocked_active_tests_make_the_module_result_an_error(self):
        ptjsonlib = Mock()
        ptjsonlib.create_node_object.return_value = {"key": "rdp-node"}
        ptjsonlib.get_result_json.return_value = {}
        engine = RDP(active_args(), ptjsonlib)
        engine.results.user_enumeration = UserEnumerationResult(
            status="blocked",
            reason="USERENUM requires a known valid --login",
        )
        engine.results.brute_protection = RDPBruteProtectionResult(
            analysis=BruteProtectionResult(
                status="blocked",
                reason="BRUTEPROT requires --allow-auth-failures",
            )
        )

        engine.output(emit_text=False)

        self.assertEqual(
            set(engine.results.module_errors),
            {"USERENUM", "BRUTEPROT"},
        )
        properties = ptjsonlib.create_node_object.call_args.args[3]
        self.assertEqual(
            {entry["test"] for entry in properties["moduleErrors"]},
            {"USERENUM", "BRUTEPROT"},
        )
        status, reason = ptjsonlib.set_status.call_args.args
        self.assertEqual(status, "error")
        self.assertIn("USERENUM", reason)
        self.assertIn("BRUTEPROT", reason)

    def test_account_lockout_is_reflected_in_the_overall_status(self):
        result = RDPBruteProtectionResult(
            analysis=BruteProtectionResult(
                status="not_observed",
                account_lockout=AccountLockoutResult(
                    status="lockout_observed",
                    reason="STATUS_ACCOUNT_LOCKED_OUT was returned",
                    bad_attempts_performed=2,
                    locked_at_attempt=2,
                ),
            )
        )
        engine = RDP(active_args(), Mock())

        serialized = engine._brute_protection_json(result)

        self.assertEqual(serialized["status"], "account_lockout_observed")
        self.assertEqual(serialized["seriesStatus"], "not_observed")
        self.assertEqual(
            serialized["reason"],
            "STATUS_ACCOUNT_LOCKED_OUT was returned",
        )
        self.assertIsNone(serialized["seriesReason"])

    def test_skipped_requested_lockout_makes_overall_result_partial(self):
        result = RDPBruteProtectionResult(
            analysis=BruteProtectionResult(
                status="protection_observed",
                reason="later attempts were blocked",
                account_lockout=AccountLockoutResult(
                    status="skipped",
                    reason="random-identity series ended early",
                ),
            )
        )
        engine = RDP(active_args(), Mock())

        serialized = engine._brute_protection_json(result)

        self.assertEqual(serialized["status"], "partial")
        self.assertEqual(serialized["seriesStatus"], "protection_observed")
        self.assertIn("account-lockout check", serialized["reason"])


if __name__ == "__main__":
    unittest.main()
