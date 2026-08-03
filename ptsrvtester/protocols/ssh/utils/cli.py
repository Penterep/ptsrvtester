"""SSH CLI: the ``SSHArgs`` argparse namespace and its help.

Tests are selected with ``-ts/--tests`` (codes matched against the modules'
``__MODULECODE__`` by :class:`BaseMain`). Value-carrying options
(``--bad-pubkeys``, ``--bad-authkeys``, credentials, ``--privkeys``) stay as
plain options and are consumed by the modules that need them.
"""
import argparse

from ptlibs.ptprinthelper import get_colored_text

from ptsrvtester.protocols.ssh.utils.helpers import (
    Target,
    ArgsWithBruteforce,
    add_bruteforce_args,
    valid_target,
)
from ptsrvtester.protocols.ssh.utils.registry import (
    SSH_TEST_GROUPS,
    SSH_TESTS,
    ssh_test_help,
)

__all__ = ["SSHArgs", "valid_target_ssh"]


def valid_target_ssh(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port."""
    return valid_target(target, domain_allowed=True)


class SSHArgs(ArgsWithBruteforce):
    tests: str | None
    target: Target
    bad_pubkeys: str | None
    bad_authkeys: str | None
    privkeys: str | None

    @staticmethod
    def get_help():
        # Test selection table (-ts): one code + one-line description per test.
        options: list[list[str]] = [
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. BANNER,AUDIT); ALL runs everything:"],
        ]
        for group_title, codes in SSH_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, SSH_TESTS[code]["desc"]])

        options += [
            ["", "", "", ""],
            [get_colored_text("Known static keys", "TITLE")],
            ["-H", "--bad-pubkeys", "<dir>", "Directory of known <name>.pub host keys (used by BADHOSTKEY)"],
            ["-A", "--bad-authkeys", "<dir>", "Directory of known <name>.key user keys (used by BADAUTHKEY)"],
            ["", "", "", ""],
            [get_colored_text("Credentials (BRUTE)", "TITLE")],
            ["-u", "--user", "<username>", "Username for bruteforce"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Password for bruteforce"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
            ["", "--privkeys", "<dir>", "Directory of private keys (pubkey auth)"],
            ["", "--spray", "", "Try one secret across all users (instead of all secrets per user)"],
            ["", "--brute-threads", "<n>", "Threads for bruteforce (default: 10)"],
            ["", "", "", ""],
            [get_colored_text("Output", "TITLE")],
            ["-j", "--json", "", "Output in JSON format"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-v", "--version", "", "Show version and exit"],
            ["-h", "--help", "", "Show this help; 'ssh -ts <TEST> -h' for test options"],
        ]

        return [
            {"description": ["SSH Testing Module"]},
            {"usage": ["ptsrvtester ssh -ts <test>[,<test>...] <options> <target>"]},
            {"usage_example": [
                "ptsrvtester ssh 127.0.0.1",
                "ptsrvtester ssh -ts BANNER,HOSTKEY,AUTHM 127.0.0.1:22",
                "ptsrvtester ssh -ts AUDIT 127.0.0.1",
                "ptsrvtester ssh -ts BADHOSTKEY -H ./hostkeys/ 127.0.0.1",
                "ptsrvtester ssh -ts BRUTE -u admin -P passwords.txt 127.0.0.1:22",
                "ptsrvtester ssh -ts BRUTE -h",
            ]},
            {"options": options},
        ]

    @staticmethod
    def get_test_help(codes):
        """Per-test help object (used by `ssh -ts <TEST> -h`)."""
        return ssh_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester ssh -h
  ptsrvtester ssh 127.0.0.1
  ptsrvtester ssh -ts BANNER,HOSTKEY,AUTHM 127.0.0.1:22
  ptsrvtester ssh -ts AUDIT 127.0.0.1
  ptsrvtester ssh -ts BADHOSTKEY -H ./hostkeys/ 127.0.0.1
  ptsrvtester -j ssh -ts BRUTE -u admin -P passwords.txt --brute-threads 20 127.0.0.1:22
  ptsrvtester ssh -ts BRUTE -h"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument(
            "target",
            type=valid_target_ssh,
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or ssh.example.com:22)",
        )

        direct = parser.add_argument_group(
            "DIRECT SCANNING", "Operations that communicate directly with the target server"
        )
        direct.add_argument(
            "-ts",
            "--tests",
            type=str,
            default=None,
            metavar="<test>",
            dest="tests",
            help="Comma-separated test codes (e.g. BANNER,AUDIT) or ALL; 'ssh -ts <TEST> -h' for test options",
        )
        direct.add_argument(
            "-H",
            "--bad-pubkeys",
            type=str,
            dest="bad_pubkeys",
            help="check if the server host key is static/known: directory of <name>.pub public keys "
                 "(e.g. https://github.com/rapid7/ssh-badkeys/tree/master/host) — used by BADHOSTKEY",
        )

        add_bruteforce_args(parser)

        # Extend the bruteforce group with the SSH-specific key options, mirroring the
        # old flat module: -A alongside the credentials, --privkeys as a brutepass option.
        bruteforce = next(g for g in parser._action_groups if "BRUTEFORCE" in g.title)
        bruteforce.description = "user/users + password/passwords/privkeys"
        bruteforce.add_argument(
            "-A",
            "--bad-authkeys",
            type=str,
            dest="bad_authkeys",
            help="check static user SSH keys: directory of <name>.key private keys + <name>.yml "
                 "(e.g. https://github.com/rapid7/ssh-badkeys/tree/master/authorized) — used by BADAUTHKEY",
        )

        brutepass = next(g for g in bruteforce._mutually_exclusive_groups if g.title == "brutepass")
        brutepass.add_argument(
            "--privkeys",
            type=str,
            help="pubkey authentication: directory of <name>.key private keys "
                 "(add <name>.pass files for passphrase-protected keys)",
        )