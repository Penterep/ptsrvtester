import argparse

from ptlibs.ptprinthelper import get_colored_text
from ptsrvtester.protocols.smtp.utils.helpers import Target, ArgsWithBruteforce, add_bruteforce_args, valid_target
from typing import Optional

__all__ = ['SNMPArgs']


SNMP_TEST_GROUPS = [
    ("General", ["VERSION"]),
    ("SNMPv2", ["V2BRUTE", "V2WRITE", "V2WALK"]),
    ("SNMPv3", ["V3ENUM", "V3BRUTE", "V3WALK", "V3WRITE"])
]

# Per-test definitions:
#   desc      one-line description for the main -ts table
#   long      list of <=3 lines describing what the test does (per-test help)
#   flags     dict dest->value applied to the args namespace when selected
#   value     (dest, default) for tests whose flag carries a value (default set if None)
#   requires  human-readable prerequisite strings (per-test help)
#   common    True -> append common outbound message options to per-test help
#   mods      test-specific option rows [short, long, metavar, help] (per-test help)
SNMP_TESTS: dict[str, dict] = {
    "VERSION": {
        "desc": "Detect SNMP versions",
        "long": "",
        "flags": {"version_detection": True},
        "requires": [
          ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
        ],
        "usage": ["-tg 192.168.15.53:161"]
    },
    "V2BRUTE": {
        "desc": "SNMPv2 dictionary attack",
        "long": "",
        "flags": {"v2_brute_force": True},
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-c", "--single-community", "", "Single community string"],
            ["-cf", "--community-file", "", "File containing community strings"]
        ],
        "mods": [
            ["-w", "--write-to-file", "<file>", "File to write output to"]
        ],
        "usage": [
            "-tg 192.168.15.53:161 -c private",
            "-tg 192.168.15.53:161 -cf c_strings.txt",
            "-tg 192.168.15.53:161 -c private -o creds.txt"
        ]
    },
    "V2WRITE": {
        "desc": "Test SNMPv2 write permission",
        "long": "",
        "flags": {"v2_write": True},
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-c", "--single-community", "", "Single community string"],
            ["-cf", "--community-file", "", "File containing community strings"]
        ],
        "mods": [
            ["-v", "--value", "<value>", "Value to write to the specified OID (default: 'Testvalue123')"]
        ],
        "usage": [
            "-tg 192.168.15.53:161 -c private",
            "-tg 192.168.15.53:161 -cf c_strings.txt",
            "-tg 192.168.15.53:161 -c private -v Value55"
        ]
    },
    "V2WALK": {
        "desc": "SNMPv2 MIB walk",
        "long": "",
        "flags": {"v2_walk": True},
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-c", "--single-community", "", "Single community string"],
            ["-cf", "--community-file", "", "File containing community strings"]
        ],
        "mods": [
            ["-o", "--oid", "<oid>", "OID to start from. Default: 1.3.6"],
            ["-of", "--oid-format", "", "Use human readable OID format"],
            ["-w", "--write-to-file", "<file>", "File to write output to"]
        ],
        "usage": [
            "-tg 192.168.15.53:161 -c private",
            "-tg 192.168.15.53:161 -cf c_strings.txt",
            "-tg 192.168.15.53:161 -c private -o 1.3.8 -of",
        ]
    },
    "V3ENUM": {
        "desc": "SNMPv3 user enumeration",
        "long": "",
        "flags": {"v3_enum": True},
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-u", "--single-username", "", "Single username"],
            ["-uf", "--username-file", "", "File containing usernames"]
        ],
        "mods": [
            ["-w", "--write-to-file", "<file>", "File to write output to"]
        ],
        "usage": [
            "-tg 192.168.15.53:161 -u user123",
            "-tg 192.168.15.53:161 -uf users.txt",
        ]
    },
    "V3BRUTE": {
        "desc": "SNMPv3 credentials bruteforce",
        "long": "",
        "flags": {"v3_brute_force": True},
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-u", "--single-username", "", "Single username"],
            ["-uf", "--username-file", "", "File containing usernames"],
            ["-p", "--single-password", "", "Single password"],
            ["-pf", "--password-file", "", "File containing passwords"]
        ],
        "mods": [
            ["-ap", "--auth-protocols", "", "Authentication protocol"],
            ["-pp", "--priv-protocols", "", "Private protocol"],
            ["-s", "--spray", "", "Enable spray mode"],
            ["-w", "--write-to-file", "<file>", "File to write output to"]
        ],
        "usage": [
            "-tg 192.168.15.53:161 -u user123 -p letm3in",
            "-tg 192.168.15.53:161 -uf users.txtm -pf passwords.txt",
            "-tg 192.168.15.53:161 -u user123 -p letm3in -ap usmHMACSHAAuthProtocol -pp usmAesCfb128Protocol -s",
        ]
    },
    "V3WALK": {
        "desc": "SNMPv3 MIB walk",
        "long": "",
        "flags": {"v3_walk": True},
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-u", "--single-username", "", "Single username"],
            ["-p", "--single-password", "", "Single password"]
        ],
        "mods": [
            ["-ap", "--auth-protocols", "", "Authentication protocol"],
            ["-pp", "--priv-protocols", "", "Private protocol"],
            ["-w", "--write-to-file", "<file>", "File to write output to"],
            ["-o", "--oid", "<oid>", "OID to start from. Default: 1.3.6"],
            ["-of", "--oid-format", "", "Use human readable OID format"],
        ],
        "usage": [
            "-tg 192.168.15.53:161 -u user123 -p letm3in",
            "-tg 192.168.15.53:161 -u user123 -p letm3in -ap usmHMACSHAAuthProtocol -pp usmAesCfb128Protocol",
            "-tg 192.168.15.53:161 -u user123 -p letm3in -o 1.4.5 -of",
        ]
    },
    "V3WRITE": {
        "desc": "Test SNMPv3 write permissions",
        "long": "",
        "flags": {"v3_write": True},
        "requires": [
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["-u", "--single-username", "", "Single username"],
            ["-p", "--single-password", "", "Single password"],
            ["-cred", "--valid-credentials-file",  "", "File containing valid credentials"]
        ],
        "mods": [
            ["-ap", "--auth-protocols", "", "Authentication protocol"],
            ["-pp", "--priv-protocols", "", "Private protocol"],
            ["-v", "--value", "<value>", "Value to write to the specified OID (default: 'Testvalue123')"]
        ]
    }
}

def _SNMP_test_help(codes: list[str]):
    """Build a help object (for ptprinthelper.help_print) describing given test codes."""
    if not codes:
        return None
    valid = [c for c in codes if c in SNMP_TESTS]
    if not valid:
        available = ", ".join(sorted(SNMP_TESTS))
        return [
            {"unknown_test": [f"Unknown test: {', '.join(codes)}"]},
            {"available_tests": [f"ALL, {available}"]},
        ]
    out: list[dict] = []
    for code in valid:
        spec = SNMP_TESTS[code]
        header = f"{code} — {spec.get('desc', '')}"
        out.append({"test": [header, *spec.get("long", [])]})
        req = list(spec.get("requires", []))
        if req:
            out.append({"requires": req})
        rows: list[list[str]] = list(spec.get("mods", []))

        if rows:
            out.append({"test_options": rows})
        has_opts = bool(rows or req)

        usage = [f"ptsrvtester SNMP -ts {code} " + example + '\n ' for example in spec.get("usage", "")]
        usage[-1] = usage[-1].rstrip("\n ")
        out.append({"usage": [usage]})
    return out

def valid_target_snmp(target: str) -> Target:
    return valid_target(target, domain_allowed=True)

class SNMPArgs(ArgsWithBruteforce):
    ip: str
    port: int
    command: str
    output: Optional[str] = None
    single_community: str = None
    single_username: str = None
    single_password: str = None
    community_file: str = None
    username_file: str = None
    password_file: str = None
    valid_credentials_file: str = None
    spray: bool = False
    auth_protocols: str = None
    priv_protocols: str = None
    oid: str = "1.3.6"
    oid_format: bool = False
    value: str = "Testvalue123"

    @staticmethod
    def get_help():
        options: list[list[str]] = [
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. BANNER,AV); ALL runs everything:"],
        ]

        for group_title, codes in SNMP_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, SNMP_TESTS[code]["desc"]])

        options += [
            ["", "", "", ""],
            ["-h", "--help", "", "Show this help message and exit"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ]

        return [
            {"description": ["SNMP Testing Module"]},
            {"usage": ["ptsrvtester snmp <command> <options>"]},
            {"usage_example": [
                "ptsrvtester snmp version -tg 192.168.1.1:161",
                "ptsrvtester snmp v2brute --community-file communities.txt -tg 192.168.1.1:161",
                "ptsrvtester snmp v3brute --username-file users.txt --password-file passwords.txt -tg 192.168.1.1:161"
            ]},
            {"options": options}
        ]

    @staticmethod
    def get_test_help(codes):
        return _SNMP_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of SNMP arguments"""

        examples = """example usage:
    ptsrvtester snmp -ts version -tg 192.168.1.1:161
    ptsrvtester snmp -ts v2brute --community-file communities.txt -tg 192.168.1.1:161
    ptsrvtester snmp -ts v3brute --username-file users.txt --password-file passwords.txt -tg 192.168.1.1:161"""

        snmp_subparsers = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(snmp_subparsers, argparse.ArgumentParser):
            raise TypeError

        snmp_subparsers.add_argument("-tg", "--target",
                                     type=valid_target_snmp,
                                     help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:25)"
                                     )

        snmp_subparsers.add_argument("-w", "--write-to-file", help="File to save the output results.",
                                                                          default=None,
                                                                          type=str)

        snmp_subparsers.add_argument(
            "-ts",
            "--tests",
            type=str,
            #nargs="+",
            default=None,
            metavar="<test>",
            dest="tests",
            help="Comma-separated test codes (e.g. version,v2brute) or ALL; 'smtp -ts <TEST> -h' for test options",
        )

        # SNMPv2 Brute Force
        snmpv2_brute_parser = snmp_subparsers.add_argument_group(title="v2brute",
                                                                 description="SNMPv2 dictionary attack")

        # user_group1 = snmpv2_brute_parser.add_mutually_exclusive_group(required=True)
        snmp_subparsers.add_argument("-c", "--single-community", "--community", help="Single community string")
        snmp_subparsers.add_argument("-cf", "--community-file", help="File containing community strings")

        # SNMPv2 Write Permission
        snmpv2_write_parser = snmp_subparsers.add_argument_group("v2write", description="Test SNMPv2 write permission")
        snmpv2_write_parser.add_argument("-v", "--value", default="Testvalue123",
                                         help="Value to write to the specified OID (default: 'Testvalue123')")

        # SNMPv2 GetBulk (Walk)
        snmpv2_getbulk_parser = snmp_subparsers.add_argument_group("v2walk", description="SNMPv2 MIB walk")
        snmpv2_getbulk_parser.add_argument("-oid", "--oid", default="1.3.6", help="OID to start from")
        snmpv2_getbulk_parser.add_argument("-of", "--oid-format", action="store_true",
                                           help="Use human readable OID format")

        # SNMPv3 User Enumeration
        user_enum_parser = snmp_subparsers.add_argument_group("v3enum", description="SNMPv3 user enumeration")

        # SNMPv3 Brute Force
        snmpv3_brute_parser = snmp_subparsers.add_argument_group("v3brute", description="SNMPv3 credentials bruteforce")
        snmpv3_brute_parser.add_argument("-ap", "--auth-protocols", help="Authentication protocol")
        snmpv3_brute_parser.add_argument("-pp", "--priv-protocols", help="Private protocol")
        snmpv3_brute_parser.add_argument("-s", "--spray", action="store_true", help="Enable spray mode")
        snmpv3_brute_parser.add_argument("-uf", "--username-file", help="Username file")
        snmpv3_brute_parser.add_argument("-pf", "--password-file", help="Password file")

        # SNMPv3 GetBulk (Walk)
        snmpv3_getbulk_parser = snmp_subparsers.add_argument_group("v3walk", description="SNMPv3 MIB walk")
        snmpv3_getbulk_parser.add_argument("-u", "--single-username", help="Single username")
        snmpv3_getbulk_parser.add_argument("-pw", "--single-password", help="Single password")

        # SNMPv3 Write Permission
        snmpv3_write = snmp_subparsers.add_argument_group("v3write", description="Test SNMPv3 write permissions")
        snmpv3_write.add_argument("-cred", "--valid-credentials-file", help="File containing valid credentials")



# endregion
