import argparse
import io
import unittest
from unittest.mock import patch

from ptsrvtester.protocols.msrpc.utils.cli import (
    MSRPCArgs,
    validate_msrpc_selection,
)
from ptsrvtester.protocols.msrpc.utils.registry import (
    MSRPC_DEFAULT_SUITE,
    MSRPC_EXPLICIT_ONLY_TESTS,
)


BRUTE_REQUIREMENTS = {
    "BRUTEPIPE": ("--pipe", r"\pipe\samr"),
    "BRUTESMB": (),
    "BRUTETCP": (
        "--uuid",
        "12345778-1234-abcd-ef00-0123456789ab",
    ),
    "BRUTEHTTP": (),
}


def parse_msrpc_args(*arguments: str) -> MSRPCArgs:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="module", required=True)
    MSRPCArgs().add_subparser("msrpc", subparsers)
    return parser.parse_args(
        ["msrpc", *arguments],
        namespace=MSRPCArgs(),
    )


def validated_args(*arguments: str) -> MSRPCArgs:
    args = parse_msrpc_args(*arguments)
    validate_msrpc_selection(args)
    return args


class MSRPCCLIParserTests(unittest.TestCase):
    def assert_parse_rejected(self, *arguments: str) -> None:
        with (
            patch("sys.stderr", new=io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            parse_msrpc_args(*arguments)
        self.assertNotEqual(raised.exception.code, 0)

    def assert_selection_rejected(self, *arguments: str) -> None:
        args = parse_msrpc_args(*arguments)
        with self.assertRaises(argparse.ArgumentError):
            validate_msrpc_selection(args)

    def test_target_is_required(self):
        self.assert_parse_rejected()
        self.assert_parse_rejected("-ts", "ENUMEPM")

    def test_single_and_file_credential_sources_are_mutually_exclusive(self):
        self.assert_parse_rejected(
            "-tg",
            "192.0.2.10",
            "-u",
            "audit-user",
            "-ul",
            "users.txt",
        )
        self.assert_parse_rejected(
            "-tg",
            "192.0.2.10",
            "-pw",
            "audit-password",
            "-pl",
            "passwords.txt",
        )

    def test_threads_accept_only_the_inclusive_safety_range(self):
        for value in (1, 100):
            with self.subTest(value=value):
                args = parse_msrpc_args(
                    "-tg",
                    "192.0.2.10",
                    "--threads",
                    str(value),
                )
                self.assertEqual(args.threads, value)

        for value in ("0", "101", "-1", "not-an-integer"):
            with self.subTest(value=value):
                self.assert_parse_rejected(
                    "-tg",
                    "192.0.2.10",
                    "--threads",
                    value,
                )

    def test_attempt_and_timeout_bounds_are_enforced(self):
        defaults = parse_msrpc_args("-tg", "192.0.2.10")
        self.assertEqual(defaults.max_attempts, 1000)
        self.assertEqual(defaults.timeout_seconds, 5.0)

        for value in ("1", "100000"):
            with self.subTest(max_attempts=value):
                args = parse_msrpc_args(
                    "-tg", "192.0.2.10", "--max-attempts", value
                )
                self.assertEqual(args.max_attempts, int(value))
        for value in ("0", "100001", "not-an-integer"):
            with self.subTest(invalid_max_attempts=value):
                self.assert_parse_rejected(
                    "-tg", "192.0.2.10", "--max-attempts", value
                )

        for value in ("1", "2.5", "60"):
            with self.subTest(timeout=value):
                args = parse_msrpc_args(
                    "-tg", "192.0.2.10", "--timeout-seconds", value
                )
                self.assertEqual(args.timeout_seconds, float(value))
        for value in ("0", "61", "nan", "not-a-number"):
            with self.subTest(invalid_timeout=value):
                self.assert_parse_rejected(
                    "-tg", "192.0.2.10", "--timeout-seconds", value
                )

    def test_every_brute_test_requires_a_user_and_password_source(self):
        for code, extra in BRUTE_REQUIREMENTS.items():
            target = "192.0.2.10:49152" if code == "BRUTETCP" else "192.0.2.10"
            base = ("-tg", target, "-ts", code, *extra)
            with self.subTest(code=code, missing="both"):
                self.assert_selection_rejected(*base)
            with self.subTest(code=code, missing="password"):
                self.assert_selection_rejected(*base, "-u", "audit-user")
            with self.subTest(code=code, missing="username"):
                self.assert_selection_rejected(*base, "-pw", "audit-password")

    def test_each_brute_test_accepts_single_or_file_credential_sources(self):
        credential_forms = (
            ("-u", "audit-user", "-pw", "audit-password"),
            ("-u", "audit-user", "-pl", "passwords.txt"),
            ("-ul", "users.txt", "-pw", "audit-password"),
            ("-ul", "users.txt", "-pl", "passwords.txt"),
        )

        for code, extra in BRUTE_REQUIREMENTS.items():
            target = "192.0.2.10:49152" if code == "BRUTETCP" else "192.0.2.10"
            for credentials in credential_forms:
                with self.subTest(code=code, credentials=credentials):
                    args = validated_args(
                        "-tg",
                        target,
                        "-ts",
                        code,
                        *extra,
                        *credentials,
                    )
                    self.assertEqual(args.tests, code)

    def test_samrpolicy_requires_one_direct_username_and_password(self):
        base = ("-tg", "192.0.2.10", "-ts", "SAMRPOLICY")
        for credentials in (
            (),
            ("-u", "audit-user"),
            ("-pw", "audit-password"),
            ("-u", "", "-pw", "audit-password"),
        ):
            with self.subTest(credentials=credentials):
                self.assert_selection_rejected(*base, *credentials)

        args = validated_args(
            *base,
            "-u",
            "audit-user",
            "-pw",
            "audit-password",
            "-d",
            "EXAMPLE",
        )
        self.assertEqual(args.username, "audit-user")
        self.assertEqual(args.password, "audit-password")
        self.assertEqual(args.domain, "EXAMPLE")

    def test_samrpolicy_accepts_an_explicit_blank_direct_password(self):
        args = validated_args(
            "-tg",
            "192.0.2.10",
            "-ts",
            "SAMRPOLICY",
            "-u",
            "audit-user",
            "-pw",
            "",
        )

        self.assertEqual(args.username, "audit-user")
        self.assertEqual(args.password, "")

    def test_samrpolicy_rejects_wordlists_alone_and_in_mixed_selections(self):
        wordlist_forms = (
            ("-ul", "users.txt", "-pl", "passwords.txt"),
            ("-u", "audit-user", "-pl", "passwords.txt"),
            ("-ul", "users.txt", "-pw", "audit-password"),
        )

        for selection in ("SAMRPOLICY", "SAMRPOLICY,BRUTESMB"):
            for credentials in wordlist_forms:
                with self.subTest(
                    selection=selection,
                    credentials=credentials,
                ):
                    self.assert_selection_rejected(
                        "-tg",
                        "192.0.2.10",
                        "-ts",
                        selection,
                        *credentials,
                    )

    def test_samrpolicy_can_share_one_direct_pair_with_a_brute_test(self):
        args = validated_args(
            "-tg",
            "192.0.2.10",
            "-ts",
            "SAMRPOLICY,BRUTESMB",
            "-u",
            "audit-user",
            "-pw",
            "audit-password",
        )

        self.assertEqual(args.tests, "SAMRPOLICY,BRUTESMB")
        self.assertIsNone(args.username_file)
        self.assertIsNone(args.password_file)

    def test_samrpolicy_custom_port_is_valid_only_for_smb_only_selections(self):
        credentials = ("-u", "audit-user", "-pw", "audit-password")
        for selection in ("SAMRPOLICY", "SAMRPOLICY,ANONSMB"):
            with self.subTest(selection=selection):
                args = validated_args(
                    "-tg",
                    "192.0.2.10:1445",
                    "-ts",
                    selection,
                    *credentials,
                )
                self.assertEqual(args.target.port, 1445)

        self.assert_selection_rejected(
            "-tg",
            "192.0.2.10:1445",
            "-ts",
            "SAMRPOLICY,ENUMEPM",
            *credentials,
        )

    def test_brutepipe_requires_a_pipe_name(self):
        credentials = ("-u", "audit-user", "-pw", "audit-password")
        self.assert_selection_rejected(
            "-tg",
            "192.0.2.10",
            "-ts",
            "BRUTEPIPE",
            *credentials,
        )

        args = validated_args(
            "-tg",
            "192.0.2.10",
            "-ts",
            "BRUTEPIPE",
            "--pipe",
            r"\pipe\samr",
            *credentials,
        )
        self.assertTrue(args.pipe)

    def test_brutetcp_requires_uuid_and_explicit_target_port(self):
        credentials = ("-u", "audit-user", "-pw", "audit-password")
        uuid = "12345778-1234-abcd-ef00-0123456789ab"

        self.assert_selection_rejected(
            "-tg",
            "192.0.2.10:49152",
            "-ts",
            "BRUTETCP",
            *credentials,
        )
        self.assert_selection_rejected(
            "-tg",
            "192.0.2.10",
            "-ts",
            "BRUTETCP",
            "--uuid",
            uuid,
            *credentials,
        )

        args = validated_args(
            "-tg",
            "192.0.2.10:49152",
            "-ts",
            "BRUTETCP",
            "--uuid",
            uuid,
            *credentials,
        )
        self.assertEqual(args.target.port, 49152)
        self.assertTrue(args.uuid)

        self.assert_selection_rejected(
            "-tg",
            "192.0.2.10:49152",
            "-ts",
            "ENUMEPM,BRUTETCP",
            "--uuid",
            uuid,
            *credentials,
        )

    def test_brutehttp_accepts_only_standard_rpc_proxy_ports(self):
        credentials = ("-u", "audit-user", "-pw", "audit-password")
        for target in ("192.0.2.10", "192.0.2.10:80", "192.0.2.10:443"):
            with self.subTest(target=target):
                validated_args(
                    "-tg",
                    target,
                    "-ts",
                    "BRUTEHTTP",
                    *credentials,
                )

        self.assert_selection_rejected(
            "-tg",
            "192.0.2.10:8443",
            "-ts",
            "BRUTEHTTP",
            *credentials,
        )

    def test_enumpipes_accepts_an_optional_comma_separated_pipe_list(self):
        defaults = validated_args(
            "-tg",
            "192.0.2.10",
            "-ts",
            "ENUMPIPES",
        )
        self.assertIsNone(defaults.pipes)

        args = validated_args(
            "-tg",
            "192.0.2.10",
            "-ts",
            "ENUMPIPES",
            "--pipes",
            r"\pipe\samr, \pipe\lsarpc",
        )
        self.assertEqual(args.pipes, ["samr", "lsarpc"])

        self.assert_selection_rejected(
            "-tg",
            "192.0.2.10",
            "-ts",
            "ENUMPIPES",
            "-ul",
            "users.txt",
            "-pl",
            "passwords.txt",
        )

    def test_safe_suite_needs_no_credentials_but_named_brute_with_all_does(self):
        for selection in (None, "ALL", *MSRPC_DEFAULT_SUITE):
            with self.subTest(selection=selection):
                arguments = ["-tg", "192.0.2.10"]
                if selection is not None:
                    arguments.extend(("-ts", selection))
                validated_args(*arguments)

        self.assert_selection_rejected(
            "-tg",
            "192.0.2.10",
            "-ts",
            "ALL,BRUTESMB",
        )
        args = validated_args(
            "-tg",
            "192.0.2.10",
            "-ts",
            "ALL,BRUTESMB",
            "-u",
            "audit-user",
            "-pw",
            "audit-password",
        )
        self.assertEqual(args.tests, "ALL,BRUTESMB")
        self.assertEqual(
            MSRPC_EXPLICIT_ONLY_TESTS,
            frozenset(
                {
                    "SAMRPOLICY",
                    "BRUTEPIPE",
                    "BRUTESMB",
                    "BRUTETCP",
                    "BRUTEHTTP",
                }
            ),
        )

    def test_all_plus_samrpolicy_still_requires_direct_credentials(self):
        self.assert_selection_rejected(
            "-tg",
            "192.0.2.10",
            "-ts",
            "ALL,SAMRPOLICY",
        )
        args = validated_args(
            "-tg",
            "192.0.2.10",
            "-ts",
            "ALL,SAMRPOLICY",
            "-u",
            "audit-user",
            "-pw",
            "audit-password",
        )
        self.assertEqual(args.tests, "ALL,SAMRPOLICY")


if __name__ == "__main__":
    unittest.main()
