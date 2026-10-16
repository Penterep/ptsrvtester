import argparse

from ptlibs.ptprinthelper import get_colored_text
from ptsrvtester.protocols.smtp.utils.helpers import Target, ArgsWithBruteforce, add_bruteforce_args, valid_target
from ptsrvtester.protocols.rsync.utils.registry import split_module_list

__all__ = ['RsyncArgs']


RSYNC_TEST_GROUPS = [
    ("Enumeration", ["BANNER", "GRAB_MODULES", "WRITE", "OWNERSHIP"]),
    ("Authentication & Encryption", ["MODULE_AUTH", "USER_ENUM", "PASS_BRUTE", "ENCRYPT"]),
    ("Exploitation", ["PATH_TRAVERSAL", "SYMLINK"]),
    ("Storage stress (explicit opt-in)", ["FILL_SPACE"]),
]

# Per-test definitions:
#   desc      one-line description for the main -ts table
#   long      list of <=3 lines describing what the test does (per-test help)
#   flags     dict dest->value applied to the args namespace when selected
#   value     (dest, default) for tests whose flag carries a value (default set if None)
#   requires  human-readable prerequisite strings (per-test help)
#   common    True -> append common outbound message options to per-test help
#   mods      test-specific option rows [short, long, metavar, help] (per-test help)
RSYNC_TESTS: dict[str, dict] = {
    "BANNER": {
        "desc": "Grab Rsync server banner",
        "long": ["This module grabs the banner of an Rsync server to detect the version of Rsync"],
        "flags": {"banner": True},
        "requires": [
          ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"]
        ],
        "usage": ["-tg 192.168.15.53:387"]
    },
    "GRAB_MODULES": {
        "desc": "Enumerate available Rsync modules",
        "long": ["Lists available modules and their contents using the rsync client."],
        "usage": ["-tg 192.168.15.53:387", "-tg 192.168.15.53:387 -m rsync_module"],
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"],
            ["-m", "--modules", "", "Specific module to enumerate"],
            ["-u", "--user", "<name>", "Rsync module username"],
            ["-p", "--password", "<password>", "Rsync module password"],
        ],
    },
    "WRITE": {
        "desc": "Check module write access",
        "long": ["Attempts to upload a temporary marker to each module and removes it when possible."],
        "usage": ["-tg 192.168.15.53:387", "-tg 192.168.15.53:387 -m rsync_module"],
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"],
            ["-m", "--modules", "", "Specific module to enumerate"],
            ["-u", "--user", "<name>", "Rsync module username"],
            ["-p", "--password", "<password>", "Rsync module password"],
        ],
    },
    "OWNERSHIP": {
        "desc": "Get rsync daemon UID and GID",
        "long": [
            "Uploads a uniquely named probe without preserving ownership to a writable module.",
            "Uses a dry run to read the probe's UID/GID, then removes the probe.",
        ],
        "usage": ["-tg 192.168.15.53:873", "-tg 192.168.15.53:873 -m rsync_module"],
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"],
            ["-m", "--modules", "", "One or more modules to test"],
            ["-u", "--user", "<name>", "Rsync module username"],
            ["-p", "--password", "<password>", "Rsync module password"],
        ],
    },
    "MODULE_AUTH": {
        "desc": "Detect module authentication requirements",
        "long": ["Checks whether each discovered module can be listed without authentication."],
        "usage": ["-tg 192.168.15.53:387", "-tg 192.168.15.53:387 -m rsync_module"],
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"],
            ["-m", "--modules", "", "Specific module to enumerate"],
            ["-u", "--user", "<name>", "Rsync module username"],
            ["-p", "--password", "<password>", "Rsync module password"],
        ],
    },
    "PASS_BRUTE": {
        "desc": "Bruteforce a module password",
        "long": ["Tries a password wordlist against one specified rsync module using a username or username file."],
        "usage": [
            "-tg 192.168.15.53:873 -m private -u backup -P passwords.txt",
            "-tg 192.168.15.53:873 -m private -U users.txt -P passwords.txt",
        ],
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-m", "--modules", "<module>", "Exactly one rsync module to test"],
            ["-u / -U", "--user / --users", "<name|file>", "Rsync username or file containing usernames"],
            ["-P", "--passwords", "<file>", "File containing password candidates"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"],
        ],
    },
    "USER_ENUM": {
        "desc": "Enumerate usernames for an rsync module",
        "long": [
            "Compares authentication responses for candidate usernames against a random, non-existing username."
        ],
        "usage": [
            "-tg 192.168.15.53:873 -m private -u backup",
            "-tg 192.168.15.53:873 -m private -U users.txt",
        ],
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-m", "--modules", "<module>", "Exactly one rsync module to test"],
            ["-u / -U", "--user / --users", "<name|file>", "Rsync username or file containing usernames"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"],
        ],
    },
    "ENCRYPT": {
        "desc": "Check for SSH service",
        "long": ["Checks whether the target accepts SSH connections on TCP port 22."],
        "usage": ["-tg 192.168.15.53:387"],
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"],
        ],
    },
    "PATH_TRAVERSAL": {
        "desc": "Rsync path traversal test",
        "long": ["Checks if the rsync server is vulnerable to path traversal. Tries to access a '../../../../etc/passwd' module"],
        "usage": ["-tg 192.168.15.53:387"],
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"],
            ["-u", "--user", "<name>", "Rsync module username"],
            ["-p", "--password", "<password>", "Rsync module password"],
        ],
    },
    "SYMLINK": {
        "desc": "Rsync symlink upload test",
        "long": [
            "Uploads a symlink pointing to the remote /etc/passwd file to each module.",
            "If the link is accessible, attempts to read and display its contents, then removes the probe.",
        ],
        "usage": ["-tg 192.168.15.53:873", "-tg 192.168.15.53:873 -m rsync_module"],
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"],
            ["-m", "--modules", "", "Specific module to test"],
            ["-u", "--user", "<name>", "Rsync module username"],
            ["-p", "--password", "<password>", "Rsync module password"],
        ],
    },
    "FILL_SPACE": {
        "desc": "Bounded rsync storage upload test",
        "long": [
            "Requires the explicit --dos flag and uploads uniquely named data files.",
            "Stops at the configured size cap (10 MiB by default, 100 MiB maximum) and removes its probe files.",
        ],
        "usage": [
            "-tg 192.168.15.53:873 -d",
            "-tg 192.168.15.53:873 -d --dos-limit 25 -m rsync_module",
        ],
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-d", "--dos", "", "Required explicit opt-in for the bounded storage probe"],
        ],
        "mods": [
            ["-t", "--timeout", "", "Timeout for connections (in seconds)"],
            ["-m", "--modules", "", "One or more modules to test"],
            ["", "--dos-limit", "<MiB>", "Maximum total upload (1-100 MiB; default: 10)"],
            ["-u", "--user", "<name>", "Rsync module username"],
            ["-p", "--password", "<password>", "Rsync module password"],
        ],
    },
}


def _dos_limit_mib(value: str) -> int:
    try:
        limit = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("DOS upload limit must be an integer number of MiB") from exc
    if not 1 <= limit <= 100:
        raise argparse.ArgumentTypeError("DOS upload limit must be between 1 and 100 MiB")
    return limit


def _RSYNC_test_help(codes: list[str]):
    """Build a help object (for ptprinthelper.help_print) describing given test codes."""
    if not codes:
        return None
    valid = [c for c in codes if c in RSYNC_TESTS]
    if not valid:
        available = ", ".join(sorted(RSYNC_TESTS))
        return [
            {"unknown_test": [f"Unknown test: {', '.join(codes)}"]},
            {"available_tests": [f"ALL, {available}"]},
        ]
    out: list[dict] = []
    for code in valid:
        spec = RSYNC_TESTS[code]
        header = f"{code} — {spec.get('desc', '')}"
        out.append({"test": [header, *spec.get("long", [])]})
        req = list(spec.get("requires", []))
        if req:
            out.append({"requires": req})
        rows: list[list[str]] = list(spec.get("mods", []))

        if rows:
            out.append({"test_options": rows})
        has_opts = bool(rows or req)

        usage = [f"ptsrvtester RSYNC -ts {code} " + example + '\n ' for example in spec.get("usage", "")]
        usage[-1] = usage[-1].rstrip("\n ")
        out.append({"usage": [usage]})
    return out

def valid_target_snmp(target: str) -> Target:
    return valid_target(target, domain_allowed=True)

class RsyncArgs(ArgsWithBruteforce):
    ip: str
    port: int
    command: str
    user: str | None
    password: str | None

    @staticmethod
    def get_help():
        options: list[list[str]] = [
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. BANNER,AV); ALL runs everything:"],
        ]

        for group_title, codes in RSYNC_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, RSYNC_TESTS[code]["desc"]])

        options += [
            ["", "", "", ""],
            ["-h", "--help", "", "Show this help message and exit"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-u", "--user", "<name>", "Rsync module username"],
            ["-U", "--users", "<file>", "File containing usernames"],
            ["-p", "--password", "<password>", "Rsync module password"],
            ["-P", "--passwords", "<file>", "File containing password candidates"],
            ["-d", "--dos", "", "Enable the bounded rsync storage upload test"],
            ["", "--dos-limit", "<MiB>", "Maximum storage-test upload (1-100 MiB; default: 10)"],
            ]

        return [
            {"description": ["Rsync Testing Module"]},
            {"usage": ["ptsrvtester rsync <command> <options>"]},
            {"usage_example": [
                "ptsrvtester rsync -ts banner,ssh -tg 192.168.1.1:873",
                "ptsrvtester rsync -ts write --modules home,tmp -tg 192.168.1.1:873",
                "ptsrvtester rsync -ts grab_modules -tg 192.168.1.1 -t 20"
            ]},
            {"options": options}
        ]

    @staticmethod
    def get_test_help(codes):
        return _RSYNC_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of RSYNC arguments"""

        examples = """example usage:
    ptsrvtester rsync -ts banner 
    ptsrvtester rsync -ts grab_modules
    ptsrvtester rsync -ts module_auth -m rsync_module"""

        rsync_subparsers = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(rsync_subparsers, argparse.ArgumentParser):
            raise TypeError

        rsync_subparsers.add_argument("-tg", "--target",
                                     type=valid_target_snmp,
                                     help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:25)"
                                     )

        user_group = rsync_subparsers.add_mutually_exclusive_group()
        user_group.add_argument("-u", "--user", type=str, default=None, help="Rsync module username")
        user_group.add_argument(
            "-U",
            "--users",
            type=str,
            default=None,
            help="File containing usernames for PASS_BRUTE",
        )
        password_group = rsync_subparsers.add_mutually_exclusive_group()
        password_group.add_argument("-p", "--password", type=str, default=None, help="Rsync module password")
        password_group.add_argument(
            "-P",
            "--passwords",
            type=str,
            default=None,
            help="File containing password candidates for PASS_BRUTE",
        )

        rsync_subparsers.add_argument("-w", "--write-to-file", help="File to save the output results.",
                                                                          default=None,
                                                                          type=str)

        rsync_subparsers.add_argument(
            "-ts",
            "--tests",
            type=str,
            #nargs="+",
            default=None,
            metavar="<test>",
            dest="tests",
            help="Comma-separated test codes (e.g. banner,grab_modules) or ALL; 'rsync -ts <TEST> -h' for test options",
        )

        rsync_subparsers.add_argument(
            "-t",
            "--timeout",
            type=int,
            default=5,
            help="Timeout for connections (in seconds)"
        )

        rsync_subparsers.add_argument(
            "-d",
            "--dos",
            action="store_true",
            help="Enable the bounded rsync storage upload test (required by FILL_SPACE)",
        )
        rsync_subparsers.add_argument(
            "--dos-limit",
            type=_dos_limit_mib,
            default=10,
            metavar="<MiB>",
            help="Maximum FILL_SPACE upload in MiB (1-100; default: 10)",
        )

        module_auth_parser = rsync_subparsers.add_argument_group(title="module_auth", description="Rsync module authentication enumeration group")
        module_auth_parser.add_argument("-m", "--modules", type=split_module_list, help="Specify modules to enumerate")
        
        module_enumeration_parser = rsync_subparsers.add_argument_group(title="module_auth", description="Rsync module authentication enumeration group")
        module_enumeration_parser.add_argument("-r", "--recursion", action="store_true", help="List module contents recursively")


# endregion
