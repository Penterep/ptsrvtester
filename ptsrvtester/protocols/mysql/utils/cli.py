import argparse

from ptlibs.ptprinthelper import get_colored_text
from ptsrvtester.protocols.smtp.utils.helpers import Target, ArgsWithBruteforce, valid_target

__all__ = ['MySQLArgs']


MYSQL_TEST_GROUPS = [
    ("Enumeration", ["VERSION"])
]

# Per-test definitions:
#   desc      one-line description for the main -ts table
#   long      list of <=3 lines describing what the test does (per-test help)
#   flags     dict dest->value applied to the args namespace when selected
#   value     (dest, default) for tests whose flag carries a value (default set if None)
#   requires  human-readable prerequisite strings (per-test help)
#   common    True -> append common outbound message options to per-test help
#   mods      test-specific option rows [short, long, metavar, help] (per-test help)
MYSQL_TESTS: dict[str, dict] = {
    "VERSION": {
        "desc": "Grab MySQL version",
        "long": ["Query the MySQL server for its version."],
        "requires": [
          ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
        ],
        "usage": ["-tg 192.168.1.1:3306"],
        "mods": [
            ["-u", "--username", "", "Username to authenticate as"],
            ["-p", "--password", "", "Password to authenticate with"]
        ],
    },
}


def _MYSQL_test_help(codes: list[str]):
    """Build a help object (for ptprinthelper.help_print) describing given test codes."""
    if not codes:
        return None
    valid = [c for c in codes if c in MYSQL_TESTS]
    if not valid:
        available = ", ".join(sorted(MYSQL_TESTS))
        return [
            {"unknown_test": [f"Unknown test: {', '.join(codes)}"]},
            {"available_tests": [f"ALL, {available}"]},
        ]
    out: list[dict] = []
    for code in valid:
        spec = MYSQL_TESTS[code]
        header = f"{code} — {spec.get('desc', '')}"
        out.append({"test": [header, *spec.get("long", [])]})
        req = list(spec.get("requires", []))
        if req:
            out.append({"requires": req})
        rows: list[list[str]] = list(spec.get("mods", []))

        if rows:
            out.append({"test_options": rows})
        usage = [f"ptsrvtester mysql -ts {code} " + example + '\n ' for example in spec.get("usage", "")]
        usage[-1] = usage[-1].rstrip("\n ")
        out.append({"usage": [usage]})
    return out

def valid_target_mysql(target: str) -> Target:
    return valid_target(target, domain_allowed=True)

class MySQLArgs(ArgsWithBruteforce):
    target: Target
    username: str | None
    password: str | None
    tests: str | None

    @staticmethod
    def get_help():
        options: list[list[str]] = [
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. BANNER,AV); ALL runs everything:"],
        ]

        for group_title, codes in MYSQL_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, MYSQL_TESTS[code]["desc"]])

        options += [
            ["", "", "", ""],
            ["-h", "--help", "", "Show this help message and exit"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-u", "--username", "", "Username to authenticate as"],
            ["-p", "--password", "", "Password to authenticate with (no password if none provided)"]
            ]

        return [
            {"description": ["MySQL Testing Module"]},
            {"usage": ["ptsrvtester mysql <command> <options>"]},
            {"usage_example": [
                "ptsrvtester mysql -ts ",
                "ptsrvtester mysql -ts -tg 192.168.1.1:3306",
                "ptsrvtester mysql -ts -tg 192.168.1.1"
            ]},
            {"options": options}
        ]

    @staticmethod
    def get_test_help(codes):
        return _MYSQL_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of MYSQL arguments"""

        examples = """example usage:
    ptsrvtester mysql -ts version -tg 127.0.0.1
    ptsrvtester mysql -ts version -tg 127.0.0.1:3306 -u root -p password
    ptsrvtester mysql -ts version -tg 127.0.0.1 -u root"""

        mysql_subparsers = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(mysql_subparsers, argparse.ArgumentParser):
            raise TypeError

        mysql_subparsers.add_argument("-tg", "--target",
                                     type=valid_target_mysql,
                                     help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:3306)"
                                     )

        mysql_subparsers.add_argument(
            "-ts",
            "--tests",
            type=str,
            #nargs="+",
            default=None,
            metavar="<test>",
            dest="tests",
            help="Comma-separated test codes (e.g. VERSION) or ALL; 'mysql -ts <TEST> -h' for test options",
        )

        mysql_subparsers.add_argument("-u", "--username", type=str, help="Username to authenticate as")
        mysql_subparsers.add_argument("-p", "--password", type=str, help="Password to authenticate with")
# endregion
