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
    dheat: str | None
    dheat_duration: float | None
    lockout_attempts: int
    lockout_cooldown: float
    enum_samples: int
    enum_baseline: int
    enum_sigma: float

    @staticmethod
    def get_help():
        options: list[list[str]] = [
            ["-tg", "--target", "<target>", "IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or ssh.example.com:22)"],
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. BANNER,KEX); ALL runs everything:"],
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
            [get_colored_text("DHEat DoS (DHEAT)", "TITLE")],
            ["", "--dheat", "<N[:kex[:e_len]]>", "DHEat attack params: N concurrent sockets, optional kex + e length (default: 10)"],
            ["", "--dheat-duration", "<seconds>", "How long to run the DHEat attack before stopping (default: 20)"],
            ["", "", "", ""],
            [get_colored_text("Root login policy (ROOTLOGIN)", "TITLE")],
            ["-u", "--user", "<username>", "Account to test (default: root)"],
            ["-p", "--password", "<password>", "Password to confirm root login (optional)"],
            ["-P", "--passwords", "<wordlist>", "Passwords to confirm root login (optional)"],
            ["", "--privkeys", "<dir>", "Private keys to confirm root login (optional)"],
            ["", "", "", ""],
            [get_colored_text("Username enumeration (USERENUM)", "TITLE")],
            ["-u", "--user", "<username>", "Known-valid login used to calibrate the timing oracle (required)"],
            ["-U", "--users", "<wordlist>", "Usernames to enumerate once enumeration is confirmed"],
            ["", "--enum-samples", "<n>", "Timing samples per username (default: 5; range 3-50)"],
            ["", "--enum-baseline", "<n>", "Random invalid names for the baseline (default: 5; range 2-25)"],
            ["", "--enum-sigma", "<f>", "Separation threshold in std devs (default: 3.0)"],
            ["", "", "", ""],
            [get_colored_text("Password-guessing lockout (LOCKOUT)", "TITLE")],
            ["-u", "--user", "<username>", "Target account (required for LOCKOUT)"],
            ["-p", "--password", "<password>", "VALID password of a canary account (enables account-lockout test)"],
            ["", "--lockout-attempts", "<n>", "Failed logins to attempt (default: 8)"],
            ["", "--lockout-cooldown", "<seconds>", "Wait & re-probe to see if a lockout/ban clears (default: 0)"],
            ["", "", "", ""],
            [get_colored_text("Output", "TITLE")],
            ["-j", "--json", "", "Output in JSON format"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-v", "--version", "", "Show version and exit"],
            ["-h", "--help", "", "Show this help; 'ssh -ts <TEST> -h' for test options"],
        ]

        return [
            {"description": ["SSH Testing Module"]},
            {"usage": ["ptsrvtester ssh -tg <target> -ts <test>[,<test>...] <options>"]},
            {"usage_example": [
                "ptsrvtester ssh -tg 127.0.0.1",
                "ptsrvtester ssh -tg 127.0.0.1:22 -ts BANNER,HOSTKEY,AUTHM",
                "ptsrvtester ssh -tg 127.0.0.1 -ts KEX,ENC,MAC",
                "ptsrvtester ssh -tg 127.0.0.1 -ts BADHOSTKEY -H ./hostkeys/",
                "ptsrvtester ssh -tg 127.0.0.1:22 -ts BRUTE -u admin -P passwords.txt",
                "ptsrvtester ssh -tg 127.0.0.1 -ts ROOTLOGIN",
                "ptsrvtester ssh -tg 127.0.0.1 -ts USERENUM -u root -U users.txt",
                "ptsrvtester ssh -tg 127.0.0.1 -ts DHEAT --dheat 10 --dheat-duration 30",
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
  ptsrvtester ssh -tg 127.0.0.1
  ptsrvtester ssh -tg 127.0.0.1:22 -ts BANNER,HOSTKEY,AUTHM
  ptsrvtester ssh -tg 127.0.0.1 -ts KEX,ENC,MAC
  ptsrvtester ssh -tg 127.0.0.1 -ts BADHOSTKEY -H ./hostkeys/
  ptsrvtester -j ssh -tg 127.0.0.1:22 -ts BRUTE -u admin -P passwords.txt --brute-threads 20
  ptsrvtester ssh -tg 127.0.0.1 -ts ROOTLOGIN
  ptsrvtester ssh -tg 127.0.0.1 -ts USERENUM -u root -U users.txt
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
            "-tg",
            "--target",
            required=True,
            type=valid_target_ssh,
            metavar="<target>",
            dest="target",
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
            help="Comma-separated test codes (e.g. BANNER,KEX) or ALL; 'ssh -ts <TEST> -h' for test options",
        )
        direct.add_argument(
            "-H",
            "--bad-pubkeys",
            type=str,
            dest="bad_pubkeys",
            help="check if the server host key is static/known: directory of <name>.pub public keys "
                 "(e.g. https://github.com/rapid7/ssh-badkeys/tree/master/host) — used by BADHOSTKEY",
        )

        dheat = parser.add_argument_group(
            "DHEAT DoS (aggressive)",
            "Active DHEat DoS attack (CVE-2002-20001) — only runs with -ts DHEAT",
        )
        dheat.add_argument(
            "--dheat",
            type=str,
            default=None,
            metavar="<N[:kex[:e_len]]>",
            dest="dheat",
            help="DHEat params passed to ssh-audit --dheat: N concurrent sockets, optional "
                 "key exchange and fake-e length (e.g. 10 or 10:curve25519-sha256:4). Default: 10",
        )
        dheat.add_argument(
            "--dheat-duration",
            type=float,
            default=None,
            metavar="<seconds>",
            dest="dheat_duration",
            help="how long to run the DHEat attack before stopping it and reading the verdict (default: 20)",
        )

        lockout = parser.add_argument_group(
            "LOCKOUT (aggressive)",
            "Password-guessing lockout test — only runs with -ts LOCKOUT. Deliberately "
            "makes failed logins; may lock the target account and/or ban this IP. Uses "
            "-u/--user (target account); add -p/--password (a VALID password for a canary "
            "account) to also test account lockout.",
        )
        lockout.add_argument(
            "--lockout-attempts",
            type=int,
            default=8,
            metavar="<n>",
            dest="lockout_attempts",
            help="number of failed login attempts to make (default: 8; range 1-100)",
        )
        lockout.add_argument(
            "--lockout-cooldown",
            type=float,
            default=0.0,
            metavar="<seconds>",
            dest="lockout_cooldown",
            help="if a lockout/ban is found, wait this long and re-probe to see if it "
                 "clears (0 = skip recovery probe; default: 0)",
        )

        userenum = parser.add_argument_group(
            "USERENUM (aggressive)",
            "Username enumeration via authentication timing — only runs with -ts USERENUM. "
            "Calibrates on a KNOWN-VALID login (-u/--user) and, when enumeration is confirmed, "
            "classifies the names in -U/--users. Makes repeated failed logins.",
        )
        userenum.add_argument(
            "--enum-samples",
            type=int,
            default=5,
            metavar="<n>",
            dest="enum_samples",
            help="timing samples per username; more is more reliable but slower "
                 "(default: 5; range 3-50)",
        )
        userenum.add_argument(
            "--enum-baseline",
            type=int,
            default=5,
            metavar="<n>",
            dest="enum_baseline",
            help="number of random (invalid) names used to build the timing baseline "
                 "(default: 5; range 2-25)",
        )
        userenum.add_argument(
            "--enum-sigma",
            type=float,
            default=3.0,
            metavar="<f>",
            dest="enum_sigma",
            help="how many standard deviations the valid login must be separated from the "
                 "invalid baseline to call enumeration possible (default: 3.0)",
        )

        # -u/--user and -U/--users are NOT mutually exclusive here: USERENUM needs
        # both at once (-u = known-valid calibration login, -U = list to enumerate).
        add_bruteforce_args(parser, mutually_exclusive_user_and_users=False)

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