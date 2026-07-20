from enum import Enum
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from typing import List, NamedTuple
from pysnmp.proto.errind import RequestTimedOut
import argparse
from dataclasses import dataclass
from typing import List, Optional

from ptlibs.ptjsonlib import PtJsonLib
from ptlibs import ptprint

from ._base import BaseModule, BaseArgs, Out
from .utils.helpers import (
    text_or_file,
    valid_target,
    Target
)

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
        "flags": {"version_detection": True}
    },
    "V2BRUTE": {
        "desc": "SNMPv2 dictionary attack",
        "long": "",
        "flags": {"v2_brute_force": True}
    },
    "V2WRITE": {
        "desc": "Test SNMPv2 write permission",
        "long": "",
        "flags": {"v2_write": True}
    },
    "V2WALK": {
        "desc": "SNMPv2 MIB walk",
        "long": "",
        "flags": {"v2_walk": True}
    },
    "V3ENUM": {
        "desc": "SNMPv3 user enumeration",
        "long": "",
        "flags": {"v3_enum": True}
    },
    "V3BRUTE": {
        "desc": "SNMPv3 credentials bruteforce",
        "long": "",
        "flags": {"v3_brute_force": True}
    },
    "V3WALK": {
        "desc": "SNMPv3 MIB walk",
        "long": "",
        "flags": {"v3_walk": True}
    },
    "V3WRITE": {
        "desc": "Test SNMPv3 write permissions",
        "long": "",
        "flags": {"v3_write": True}
    }
}

def _parse_test_codes(raw: str | None) -> list[str]:
    """Split and upper-case a raw -ts value into a list of codes."""
    if not raw:
        return []
    return [c.strip().upper() for c in str(raw).split(",") if c.strip()]

def valid_target_snmp(target: str) -> Target:
    return valid_target(target, domain_allowed=True)

def _apply_SNMP_tests(args) -> None:
    """Translate ``-ts/--tests`` codes into the internal per-test dest flags.

    ``ALL`` (or no ``-ts``) leaves every flag at default -> run-all mode.
    """
    codes = _parse_test_codes(getattr(args, "tests", None))
    if not codes:
        return
    if "ALL" in codes:
        # Explicit full scan: apply nothing so _is_run_all_mode() stays True.
        return
    unknown = [c for c in codes if c not in SNMP_TESTS]
    if unknown:
        available = ", ".join(sorted(SNMP_TESTS))
        raise argparse.ArgumentError(
            None,
            f"Unknown test(s): {', '.join(unknown)}. Available: ALL, {available}",
        )

    for code in codes:
        spec = SNMP_TESTS[code]
        for dest, val in spec.get("flags", {}).items():
            setattr(args, dest, val)
        value = spec.get("value")
        if value is not None:
            dest, default = value
            if getattr(args, dest, None) is None and default is not None:
                setattr(args, dest, default)

    # Every explicitly selected test must actually activate; otherwise report what is
    # missing instead of silently falling back to run-all mode.
    inactive: list[tuple[str, list[str]]] = []
    for code in codes:
        spec = SNMP_TESTS[code]

        if "flags" in spec:
            active = all(getattr(args, dest, None) for dest in spec["flags"])
        elif "value" in spec:
            active = getattr(args, spec["value"][0], None) is not None
        else:
            active = True
        if not active:
            inactive.append((code, list(spec.get("requires", []))))
    if inactive:
        parts = [
            f"{code} requires {'; '.join(req)}" if req else f"{code} could not be activated"
            for code, req in inactive
        ]
        raise argparse.ArgumentError(None, "; ".join(parts))


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
        usage = f"ptsrvtester SNMP -ts {code} " + ("<options> <target>" if has_opts else "<target>")
        out.append({"usage": [usage]})
    return out


class VULNS(Enum):
    WeakCommunityName = "PTV-SNMPv2-WEAKCOMMUNITYNAME"
    WeakUsername = "PTV-SNMPv3-WEAKUSERNAME"
    WeakCredentials = "PTV-SNMPv3-WEAKCREDENTIALS"
    Write_2 = "PTV-SNMPv2-WRITEACCESS"
    Write_3 = "PTV-SNMPv3-WRITEACCESS"
    Readmib_3 = "PTV-SNMPv3-READINGMIB"
    Readmib_2 = "PTV-SNMPv2-READINGMIB"

class Credential(NamedTuple):
    username: str | None
    password: str | None


class SNMPVersion(NamedTuple):
    v1: bool | None
    v2c: bool | None
    v3: bool | None

class WriteTestResult(NamedTuple):
    OID: str | None
    creds: str | None   #community for snmpv2
    value: str | None


class AuthPrivProtocols(NamedTuple):
    auth_protocols: str | None
    priv_protocols: str | None

@dataclass
class SNMPResult:
    version: Optional[SNMPVersion] = None
    communities: Optional[List[str]] = None
    usernames: Optional[List[str]] = None
    credentials: Optional[List[Credential]] = None
    Writetest3: Optional[List[WriteTestResult]] = None
    Writetest2: Optional[List[WriteTestResult]] = None
    Bulk2: Optional[str] = None
    Bulk3: Optional[str] = None

class SNMPArgs(BaseArgs):
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

        options += [
                ["version", "<options>", "", "Detect SNMP versions"],
                ["v2brute", "<options>", "", "SNMPv2 dictionary attack"],
                ["v2write", "<options>", "", "Test SNMPv2 write permission"],
                ["v2walk", "<options>", "", "SNMPv2 MIB walk"],
                ["v3enum", "<options>", "", "SNMPv3 user enumeration"],
                ["v3brute", "<options>", "", "SNMPv3 credentials bruteforce"],
                ["v3walk", "<options>", "", "SNMPv3 MIB walk"],
                ["v3write", "<options>", "", "Test SNMPv3 write permissions"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
                ["-vv", "--verbose", "", "Enable verbose mode"],
            ]

        return [
            {"description": ["SNMP Testing Module"]},
            {"usage": ["ptsrvtester snmp <command> <options>"]},
            {"usage_example": [
                "ptsrvtester snmp version --ip 192.168.1.1",
                "ptsrvtester snmp v2brute --community-file communities.txt --ip 192.168.1.1",
                "ptsrvtester snmp v3brute --username-file users.txt --password-file passwords.txt --ip 192.168.1.1"
            ]},
            {"options": options}
        ]

    @staticmethod
    def get_test_help(codes):
        return _SNMP_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of SNMP arguments"""

        examples = """example usage:
    ptsrvtester snmp version --ip 192.168.1.1 --port 161
    ptsrvtester snmp snmpv2-brute --community-file communities.txt --ip 192.168.1.1 --port 161
    ptsrvtester snmp snmpv3-brute --username-file users.txt --password-file passwords.txt --ip 192.168.1.1 --port 161"""

        snmp_subparsers = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(snmp_subparsers, argparse.ArgumentParser):
            raise TypeError

        snmp_subparsers.add_argument("target",
                                     type=valid_target_snmp,
                                     help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:25)"
                                     )

        snmp_subparsers.add_argument(
            "-ts",
            "--tests",
            type=str,
            default=None,
            metavar="<test>",
            dest="tests",
            help="Comma-separated test codes (e.g. version,v2brute) or ALL; 'smtp -ts <TEST> -h' for test options",
        )

        # SNMPv2 Brute Force
        snmpv2_brute_parser = snmp_subparsers.add_argument_group(title="v2brute",
                                                                 description="SNMPv2 dictionary attack")
        snmpv2_brute_parser.add_argument("-o", "--output", help="File to save the output results.",
                                         default=None,
                                         type=str)

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

        # SNMPv3 GetBulk (Walk)
        snmpv3_getbulk_parser = snmp_subparsers.add_argument_group("v3walk", description="SNMPv3 MIB walk")
        snmpv3_getbulk_parser.add_argument("-u", "--single-username", help="Single username")
        snmpv3_getbulk_parser.add_argument("-pw", "--single-password", help="Single password")

        # SNMPv3 Write Permission
        snmpv3_write = snmp_subparsers.add_argument_group("v3write", description="Test SNMPv3 write permissions")
        snmpv3_write.add_argument("-cred", "--valid-credentials-file", help="File containing valid credentials")


class SNMP(BaseModule):
    @staticmethod
    def module_args():
        return SNMPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        self.args = args  # type: SNMPArgs
        self.ptjsonlib = ptjsonlib
        self.results: SNMPResult | None = None
        _apply_SNMP_tests(args)

    def run(self) -> None:
        """Main SNMP execution logic"""

        self.results = SNMPResult()
        setattr(self.args, "ip", self.args.target.ip)
        setattr(self.args, "port", self.args.target.port)
        c_string_present = getattr(self.args, "single_community", False) or getattr(self.args, "community_file", False)
        username_present = getattr(self.args, "single_username", False) or getattr(self.args, "username_file", False)
        password_present = getattr(self.args, "single_password", False) or getattr(self.args, "password_file", False)

        if getattr(self.args, "version_detection", False):
            ptprint("SNMP version detection test", "TITLE", not self.args.json, colortext=True)
            self.results.version = asyncio.run(self.version_detection())

        if getattr(self.args, "v2_brute_force", False):
            if not c_string_present:
                raise argparse.ArgumentError(None, "SNMPv2 brute-force module requires the -c/--single-community "
                                                   "or -cf/--community-file argument")
            else:
                ptprint("SNMPv2 brute force", "TITLE", not self.args.json, colortext=True)
                self.results.communities = asyncio.run(self.snmpv2_brute())

        if getattr(self.args, "v3_brute_force", False):
            if not username_present and not password_present:
                raise argparse.ArgumentError(None, "SNMPv3 brute-force module requires the -c/--single-community "
                                                   "or -cf/--community-file argument")
            else:
                ptprint("SNMPv3 brute force", "TITLE", not self.args.json, colortext=True)
                self.results.credentials = asyncio.run(self.snmpv3_brute())

        if getattr(self.args, "v3_enum", False):
            if not username_present:
                raise argparse.ArgumentError(None, "SNMPv3 enumeration module requires the -u/--single-username argument")
            else:
                ptprint("SNMPv3 user enumeration test", "TITLE", not self.args.json, colortext=True)
                self.results.usernames = asyncio.run(self.user_enum())

        if getattr(self.args, "v2_write", False):
            if not c_string_present:
                raise argparse.ArgumentError(None, "SNMPv2 write permissions module requires the -c/--single-community "
                                                   "or -cf/--community-file argument")
            else:
                ptprint("SNMPv2 write permissions test", "TITLE", not self.args.json, colortext=True)
                self.results.Writetest2 = asyncio.run(self.test_snmpv2_write_permission())

        if getattr(self.args, "v3_write", False):
            if (not username_present or password_present) or not getattr(self.args, "valid_credentials_file", False):
                raise argparse.ArgumentError(None, "SNMPv3 write permissions module requires the -u/--single-username "
                                                   "and -p/--single-password or -cred/--valid-credentials-file arguments")
            else:
                ptprint("SNMPv3 write permissions test", "TITLE", not self.args.json, colortext=True)
                self.results.Writetest3 = asyncio.run(self.test_snmpv3_write_permissions())

        if getattr(self.args, "v2_walk", False):
            if not c_string_present:
                raise argparse.ArgumentError(None, "Bruteforce module require the -c/--single-community "
                                                   "or -cf/--community-file argument")
            else:
                ptprint("SNMPv2 walk", "TITLE", not self.args.json, colortext=True)
                self.results.Bulk2 = asyncio.run(self.getBulk_SNMPv2())

        if getattr(self.args, "v3_walk", False):
            if not getattr(self.args, "single_password", False) and not getattr(self.args, "single_username", False):
                raise argparse.ArgumentError(None, "SNMPv3 walk module requires the -u/--single-username "
                                                   "and -p/--single-password argument")
            else:
                ptprint("SNMPv3 walk", "TITLE", not self.args.json, colortext=True)
                self.results.Bulk3 = asyncio.run(self.getBulk_SNMPv3())

     # Map protocol OIDs to human-readable names
    PROTOCOL_NAMES = {
        usmHMACMD5AuthProtocol: "usmHMACMD5AuthProtocol",
        usmHMACSHAAuthProtocol: "usmHMACSHAAuthProtocol",
        usmHMAC128SHA224AuthProtocol: "usmHMAC128SHA224AuthProtocol",
        usmHMAC192SHA256AuthProtocol: "usmHMAC192SHA256AuthProtocol",
        usmHMAC256SHA384AuthProtocol: "usmHMAC256SHA384AuthProtocol",
        usmHMAC384SHA512AuthProtocol: "usmHMAC384SHA512AuthProtocol",
        usmDESPrivProtocol: "usmDESPrivProtocol",
        usmAesCfb128Protocol: "usmAesCfb128Protocol",
        usmAesCfb192Protocol: "usmAesCfb192Protocol",
        usmAesCfb256Protocol: "usmAesCfb256Protocol",
        None: "None",
    }

    def drawDoubleLine(self):
        self.ptprint ('=' * 75)

    def write_to_file(self, message_or_messages: str | list[str]):
        """
            File Output.
        """
        try:
            with open(self.args.output, "a") as f:
                if isinstance(message_or_messages, str):
                    f.write(message_or_messages + "\n")
                elif isinstance(message_or_messages, list):
                    for message in message_or_messages:
                        f.write(message + "\n")
        except FileNotFoundError:
            raise argparse.ArgumentError(None, f"File not found: '{self.args.output}'")
        except PermissionError:
            raise argparse.ArgumentError(
                None, f"Cannot write file (permission denied): '{self.args.output}'"
            )
        except OSError as e:
            raise argparse.ArgumentError(None, f"Cannot write file '{self.args.output}': {e}")

    def _text_or_file(self, text: str | None, file_path: str | None) -> List[str]:

        values = text_or_file(text.strip() if text else None, file_path)
        return [v.strip() for v in values if v.strip()]

    # Function for getBulk SNMPv2/SNMPv3
    def format_timeticks(self, value):
        """
            Convert Timeticks to a human-readable string.
        """
        ticks = int(value)
        days, remainder = divmod(ticks, 8640000)  # 1 day = 8640000 timeticks
        hours, remainder = divmod(remainder, 360000)
        minutes, remainder = divmod(remainder, 6000)
        seconds = remainder // 100
        return f"{days} day, {hours}:{minutes:02}:{seconds:02}.{remainder % 100}"

    async def version_detection(self) -> SNMPVersion | None:
        """
           Detects the SNMP version supported by the target device.

           Parameters:
           - self.ip (str): The IP address of the target device.
           - self.port (int): The port number for SNMP communication.

           Returns:
           - SNMPVersion: An object containing three boolean attributes (`v1`, `v2c`, `v3`), each indicating
             whether the corresponding SNMP version is supported by the target device.
        """

        # Struct data
        v1: bool = False
        v2c: bool = False
        v3: bool = False

        ###########################################################################################
        # Detect v1                                                                               #
        ###########################################################################################
        iterator = await get_cmd(
            SnmpEngine(),
            CommunityData("public", mpModel=0),
            await UdpTransportTarget.create((self.args.ip, self.args.port)),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
        )

        errorIndication, errorStatus, errorIndex, varBinds = iterator

        if errorIndication:
            ptprint(f"Error!: {errorIndication}", "ERROR", not self.args.json, indent=4)
        elif errorStatus:
            ptprint(
                "{} at {}".format(
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                ),
                "ERROR", not self.args.json, indent=4
            )

        else:
            v1 = True
            for varBind in varBinds:
                ptprint(f"Success!: {" = ".join([x.prettyPrint() for x in varBind])}", "OK",
                        not self.args.json, indent=4)


        ###########################################################################################
        # Detect v2c                                                                              #
        ###########################################################################################
        iterator = await get_cmd(
            SnmpEngine(),
            CommunityData("public", mpModel=1),
            await UdpTransportTarget.create((self.args.ip, self.args.port)),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
        )

        errorIndication, errorStatus, errorIndex, varBinds = iterator

        if errorIndication:
             ptprint(f"Error!: {errorIndication}", "ERROR", not self.args.json, indent=4)

        elif errorStatus:
            ptprint(f"Error!: {errorIndication}", "ERROR", not self.args.json, indent=4)
            ptprint(
                "{} at {}".format(
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                ),
                "ERROR", not self.args.json, indent=4
            )

        else:
            v2c = True
            for varBind in varBinds:
                ptprint(f'Success!: {" = ".join([x.prettyPrint() for x in varBind])}', "OK",
                not self.args.json, indent=4)


        ###########################################################################################
        # Detect v3                                                                               #
        ###########################################################################################
        iterator = await get_cmd(
            SnmpEngine(),
            UsmUserData("pentest"),
            await UdpTransportTarget.create((self.args.ip, self.args.port)),
            ContextData(),
        )

        errorIndication, errorStatus, errorIndex, varBinds = iterator

        if errorIndication:
            if isinstance(errorIndication, RequestTimedOut):
                ptprint(f"Error!: {errorIndication}", "ERROR", not self.args.json, indent=4)
            else:
                ptprint(f"Success!: {errorIndication}", "OK", not self.args.json, indent=4)
                v3 = True

        elif errorStatus:
            ptprint(
                "{} at {}".format(
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                ),
                "ERROR", not self.args.json, indent=4
            )

        else:
            v3 = True
            for varBind in varBinds:
                ptprint(" = ".join([x.prettyPrint() for x in varBind]), "TEXT", not self.args.json, indent=4)
        v1_str = "v1" if v1 else ""
        v2c_str = "v2" if v2c else ""
        v3_str = "v3" if v3 else ""
        versions = [ver for ver in [v1_str, v2c_str, v3_str] if ver != ""]
        ptprint(f"SNMP version found: {', '.join(versions)}", "INFO", not self.args.json, indent=4)
        return SNMPVersion(v1, v2c, v3)

    async def snmpv2_brute(self) -> List[str]:

        """
           Performs a dictionary attack on SNMPv2/1 to find valid communities.

           Parameters:
           - self.single_community (str): A single community string for SNMPv2/1 authentication.
           - self.community_file (str): Path to a file containing a list of communities for the dictionary attack.
           - self.ip (str): The IP address of the target device.
           - self.port (int): The port number for SNMP communication.
           - self.output (bool): If True, writes valid credentials to a file.

           Returns:
           - list[Credential]: A list of valid communities found during the attack.
           - None: If no credentials are found or required inputs are missing.
        """

        if not self.args.community_file and not self.args.single_community:
            ptprint("Error: Neither a community file nor a single community string was provided.", "WARNING",
                    not self.args.json, indent=4)
            return []
        #self.drawDoubleLine()
        #self.ptprint("Starting a dictionary attack on SNMPv2...", title=True)
        #self.drawDoubleLine()
        communities = self._text_or_file(self.args.single_community, self.args.community_file)
        valid_communities = []

        for community in communities:
            iterator = get_cmd(SnmpEngine(),
                               CommunityData(community),
                               await UdpTransportTarget.create((self.args.ip, self.args.port), timeout=0.1),
                               # Initialize transport target correctly
                               ContextData(),
                               ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)))
            errorIndication, errorStatus, errorIndex, varBinds = await iterator

            if not errorIndication and not errorStatus:
                ptprint(f"Valid community string found: {community}", "VULN", not self.args.json, indent=4)
                valid_communities.append(community)
            else:
                ptprint(f"Error: {errorIndication or errorStatus} for {community}", "ERROR", not self.args.debug, indent=4)

        if valid_communities:
            #self.ptprint("\n")
            ptprint(f"Valid communities:", "INFO", not self.args.json, indent=4)
            for community in valid_communities:
                ptprint(community, "VULN", not self.args.json, indent=8)
            if self.args.output:
                for community in valid_communities:
                    self.write_to_file(community)

        else:
            ptprint("No valid communities found", "OK", not self.args.json, indent=4)
        return valid_communities

    async def user_enum(self) -> list[str]:
        # Users from input
        users: list[str] = self._text_or_file(self.args.single_username, self.args.username_file)

        #self.drawDoubleLine()
        #self.ptprint("Starting username enumeration...", title=True)
        #self.drawDoubleLine()
        valid_usernames = set()

        for username in users:
            try:
                iterator = get_cmd(
                    SnmpEngine(),
                    UsmUserData(username, "userenumeration", authProtocol=None, privProtocol=None),
                    await UdpTransportTarget.create((self.args.ip, self.args.port)),
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
                )
                errorIndication, errorStatus, errorIndex, varBinds = await iterator

                if not errorIndication and not errorStatus:
                    ptprint(f"Valid username found: {username}", "VULN", not self.args.json, indent=4)
                    valid_usernames.add(username)
                elif "Wrong SNMP PDU digest" in str(errorIndication):
                    ptprint(f"Potential valid username: {username}", "WARNING", not self.args.json, indent=4)
                    valid_usernames.add(username)
                else:

                    ptprint(f"Error for username {username}: {errorIndication or errorStatus}", "ERROR",
                                 not self.args.json, indent=4)

            except Exception as e:
                ptprint(f"Error for username {username}: {e}", "ERROR", not self.args.json, indent=4)

        if valid_usernames:
            #self.ptprint("\n")
            ptprint(f"Potential valid usernames:", "INFO", not self.args.json,
                    indent=4)
            for username in valid_usernames:
                ptprint(username, "VULN", not self.args.json, indent=8)
            if self.args.output:
                for username in valid_usernames:
                    self.write_to_file(username)
        else:
            ptprint("No valid usernames found", "OK", not self.args.json, indent=4)

        return list(valid_usernames)

    async def snmpv3_brute(self) -> list[Credential] | None:

        """
            Performs a dictionary attack on SNMPv3 to find valid credentials.

            Parameters:
            - self.single_username (str): A single username for SNMPv3 authentication.
            - self.single_password (str): A single password for SNMPv3 authentication.
            - self.username_file (str): Path to a file containing a list of usernames for the dictionary attack.
            - self.password_file (str): Path to a file containing a list of passwords for the dictionary attack.
            - self.auth_protocols (obj): The authentication protocol to use (e.g., usmHMACSHAAuthProtocol). Defaults to a set of standard protocols if not provided.
            - self.priv_protocols (obj): The encryption protocol to use (e.g., usmDESPrivProtocol). Defaults to a set of standard protocols if not provided.
            - self.spray (bool): Determines whether to try all passwords for each username (False) or all usernames for each password (True).
            - self.ip (str): The IP address of the target device.
            - self.port (int): The port number for SNMP communication.
            - self.output (bool): If True, writes valid credentials to a file.

            Returns:
            - list[Credential]: A list of valid credentials (username and password pairs) found during the attack.
            - None: If no credentials are found or required inputs are missing.
        """

        # Warning
        if not self.args.username_file and not self.args.single_username:
            ptprint("Error: Neither a username file nor a single username was provided.", "WARNING", not self.args.json,
                    indent=4)
            return None

        # Warning
        if not self.args.password_file and not self.args.single_password:
            ptprint("Error: Neither a password file nor a single password was provided.", "WARNING", not self.args.json,
                    indent=4)
            return None

        # Users and passwords from input
        users = self._text_or_file(self.args.single_username, self.args.username_file)
        passwords = self._text_or_file(self.args.single_password, self.args.password_file)
        valid_usernames = set()

        # setting the hash function for bruteforce
        default_auth_protocols = [
            usmHMACSHAAuthProtocol,
            usmHMACMD5AuthProtocol,
            usmHMAC128SHA224AuthProtocol,
            usmHMAC192SHA256AuthProtocol,
            usmHMAC256SHA384AuthProtocol,
            usmHMAC384SHA512AuthProtocol
        ]
        # setting the encryption function for bruteforce
        default_priv_protocols = [
            usmDESPrivProtocol,
            usmAesCfb128Protocol,
            usmAesCfb192Protocol,
            usmAesCfb256Protocol
        ]

        # If protocols are not set, perform username enumeration first
        if (self.args.auth_protocols is None or self.args.priv_protocols is None) and self.args.username_file:
            ptprint("No auth or priv protocols set" , "TITLE", not self.args.json, indent=4)
            users = await self.user_enum()
            valid_usernames = set(users)
            if not users:
                #self.ptprint("\n")
                ptprint("It is not possible to find valid credentials with these usernames", "OK",
                        not self.args.json, indent=4)
                return None

        PROTOCOL_OBJECTS = {v: k for k, v in self.PROTOCOL_NAMES.items()}

        if isinstance(self.args.auth_protocols, str):
            self.args.auth_protocols = PROTOCOL_OBJECTS.get(self.args.auth_protocols, None)
            if self.args.auth_protocols is None:
                ptprint("Warning: Unknown authentication protocol string. Using defaults", "WARNING", not self.args.json,
                        indent=4)


        if isinstance(self.args.priv_protocols, str):
            self.args.priv_protocols = PROTOCOL_OBJECTS.get(self.args.priv_protocols, None)
            if self.args.priv_protocols is None:
                ptprint("Warning: Unknown privacy protocol string. Using defaults", "WARNING", not self.args.json,
                        indent=4)

        auth_protocols = [self.args.auth_protocols] if self.args.auth_protocols else default_auth_protocols
        priv_protocols = [self.args.priv_protocols] if self.args.priv_protocols else default_priv_protocols

        protocols = [AuthPrivProtocols(a, p) for a in auth_protocols for p in priv_protocols]

        # Spray logic
        if self.args.spray:
            creds = [Credential(u, p) for p in passwords for u in users]
        else:
            creds = [Credential(u, p) for u in users for p in passwords]

        found_credentials = []  # store valid found credentials
        successful_protocol = None  # Track the successful protocol combination
        valid_usernames = set()

        # starting the attack
        #self.ptprint("\n")
        #self.drawDoubleLine()
        #self.ptprint("Starting a dictionary attack on SNMPv3...", title=True)
        #self.drawDoubleLine()

        for protocol in protocols:
            if successful_protocol:
                # If a valid protocol was found, skip other combinations
                if protocol != successful_protocol:
                    continue
            for cred in creds:
                try:
                    iterator = get_cmd(SnmpEngine(),
                                       UsmUserData(cred.username, cred.password, authProtocol=protocol.auth_protocols, privProtocol=protocol.priv_protocols),
                                       await UdpTransportTarget.create((self.args.ip, self.args.port)),
                                       ContextData(),
                                       ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)))
                    errorIndication, errorStatus, errorIndex, varBinds = await iterator

                    if not errorIndication and not errorStatus:
                        found_credentials.append(cred)
                        successful_protocol = protocol
                        valid_usernames.add(cred.username)
                        auth_name = self.PROTOCOL_NAMES.get(successful_protocol.auth_protocols, "Unknown Protocol")
                        priv_name = self.PROTOCOL_NAMES.get(successful_protocol.priv_protocols, "Unknown Protocol")
                        ptprint(f"Valid credentials found: Username: {cred.username}, Password: {cred.password}", 
                                "VULN", not self.args.json, indent=4)
                        ptprint(f"Successful Authentication and Private protocols are: {auth_name} and {priv_name}", 
                                "INFO", not self.args.json, indent=4)
                    elif "Wrong SNMP PDU digest" in str(errorIndication):
                        ptprint(f"Digest match (likely valid username - Try different password or protocols): {cred.username}",
                                "INFO", not self.args.json, indent=4)
                        valid_usernames.add(cred.username)
                    elif "Unknown USM user" in str(errorIndication):
                        ptprint(f"Error: Unknown user: {cred.username}", "ERROR", not self.args.json, indent=4)
                    else:
                        ptprint(f"Error: {errorIndication or errorStatus} for {cred.username}/{cred.password}", "ERROR",
                                not self.args.json, indent=4)

                except Exception as e:
                    ptprint(f"Error: {cred.username}/{cred.password}: {e}", "ERROR", not self.args.json, indent=4)

        if valid_usernames:
            #self.ptprint("\n")
            ptprint(f"Potential valid usernames:", "INFO", not self.args.json, indent=4)
            for username in valid_usernames:
                ptprint(username, "VULN", not self.args.json, indent=8)

        if self.args.output and found_credentials:
            results = [f"Username: {cred.username}, Password: {cred.password}" for cred in found_credentials]
            self.write_to_file(results)

        if found_credentials:
            #self.ptprint("\n")
            ptprint("Found credentials:", "INFO", not self.args.json, indent=4)
            for cred in found_credentials:
                ptprint(f"Username: {cred.username}, Password: {cred.password}", "VULN", not self.args.json, indent=8)

        if successful_protocol:
            auth_name = self.PROTOCOL_NAMES.get(successful_protocol.auth_protocols, "Unknown Protocol")
            priv_name = self.PROTOCOL_NAMES.get(successful_protocol.priv_protocols, "Unknown Protocol")
            #self.ptprint("\n")
            ptprint(f"Successful Authentication and Private protocols are: {auth_name} and {priv_name}", "INFO",
                    not self.args.json, indent=4)

        else:
            #self.ptprint("\n")
            ptprint("No valid credentials found", "OK", not self.args.json, indent=4)

        return found_credentials

    async def test_snmpv3_write_permissions(self) -> list[WriteTestResult]:
        """
            Tests SNMPv3 write permissions by attempting to set a value on the target device.

            Parameters:
            - self.single_username (str): A single username for SNMPv3 authentication.
            - self.single_password (str): A single password for SNMPv3 authentication.
            - self.auth_protocols (obj): The authentication protocol (e.g., usmHMACSHAAuthProtocol). Defaults to usmHMACSHAAuthProtocol if not provided.
            - self.priv_protocols (obj): The encryption protocol (e.g., usmDESPrivProtocol). Defaults to usmDESPrivProtocol if not provided.
            - self.valid_credentials_file (str): Path to a file containing multiple valid credentials in the format `username: value, password: value`.
            - self.ip (str): The IP address of the target device.
            - self.port (int): The port number.

            Returns:
            - None: Prints the results of the write test, including success or failure messages.
        """
        results: list[WriteTestResult] = []
        default_auth_protocol = usmHMACSHAAuthProtocol
        default_priv_protocol = usmDESPrivProtocol

        PROTOCOL_OBJECTS = {v: k for k, v in self.PROTOCOL_NAMES.items()}

        if isinstance(self.args.auth_protocols, str):
            self.args.auth_protocols = PROTOCOL_OBJECTS.get(self.args.auth_protocols, None)
            if self.args.auth_protocols is None:
                ptprint("Warning: Unknown authentication protocol string. Using defaults", "WARNING",
                        not self.args.json,
                        indent=4)


        if isinstance(self.args.priv_protocols, str):
            self.args.priv_protocols = PROTOCOL_OBJECTS.get(self.args.priv_protocols, None)
            if self.args.priv_protocols is None:
                ptprint("Warning: Unknown privacy protocol string. Using defaults", "WARNING", not self.args.json,
                        indent=4)

        if not self.args.auth_protocols:
            ptprint("Be aware that authentication protocol was not provided, so it is set as usmHMACSHAAuthProtocol",
                    "INFO", not self.args.json, indent=4)
            self.args.auth_protocols = default_auth_protocol

        if not self.args.priv_protocols:
            ptprint("Be aware that private protocol was not provided, so it is set as usmDESPrivProtocol",
                    "INFO", not self.args.json, indent=4)
            self.args.priv_protocols = default_priv_protocol

        creds = []

        Protocols = AuthPrivProtocols(self.args.auth_protocols, self.args.priv_protocols)

        if self.args.single_username and self.args.single_password:
            creds.append(Credential(self.args.single_username, self.args.single_password))
        elif self.args.valid_credentials_file:
            inputs = self._text_or_file(None, self.args.valid_credentials_file)
            for line in inputs:
                # Parse username and password directly from the line
                parts = line.split(", ")
                if len(parts) == 2:
                    try:
                        username = parts[0].split(": ")[1]
                        password = parts[1].split(": ")[1]
                        creds.append(Credential(username, password))
                    except IndexError:
                        ptprint(f"Invalid line format: {line}", "WARNING", not self.args.json, indent=4)
                else:
                    ptprint(f"Invalid format: {line}", "WARNING", not self.args.json, indent=4)
        else:
            ptprint("Error: Provide either single username/password or a file with credentials.", "WARNING",
                    not self.args.json, indent=4)
            return []
        #self.drawDoubleLine()
        #self.ptprint("Starting SNMPv3 write permission test...", title=True)
        #self.drawDoubleLine()


        for cred in creds:
            try:
                ptprint(f"Testing write permission for user: {cred.username} with password: {cred.password}", "INFO",
                        not self.args.json, indent=4)
                iterator = set_cmd(
                    SnmpEngine(),
                    UsmUserData(cred.username, cred.password, authProtocol=Protocols.auth_protocols, privProtocol=Protocols.priv_protocols),
                    await UdpTransportTarget.create((self.args.ip, self.args.port)),
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0), OctetString(self.args.value))
                )

                errorIndication, errorStatus, errorIndex, varBinds = await iterator

                if not errorIndication and not errorStatus:
                    ptprint("Test was successful!", "VULN", not self.args.json, indent=8)
                    for varBind in varBinds:
                        ptprint(f"OID: {varBind[0]} was set to {varBind[1]}", "INFO", not self.args.json, indent=8)
                        ptprint(f"Note: Attribute was modified for testing purposes. Don't forget to revert it back if necessary.",
                                "INFO", not self.args.json, indent=8)
                        results.append(WriteTestResult(
                        OID=str(varBind[0]),
                        creds=f"{cred.username or 'None'}:{cred.password or 'None'}",
                        value=str(varBind[1])
                        ))
                else:
                    ptprint(f"Test failed: {errorIndication or errorStatus}", "OK", not self.args.json,
                            indent=8)

            except Exception as e:
                ptprint(f"Exception occurred: {e}", "ERROR", not self.args.json, indent=8)

        return results

    async def test_snmpv2_write_permission(self) -> list[WriteTestResult]:
        """
            Tests SNMPv2 write permissions by attempting to set a value on the target device.

            Parameters:
            - self.single_community (str): A single community string for SNMPv2/1 authentication.
            - self.community_file (str): Path to a file containing multiple valid community strings.
            - self.ip (str): The IP address of the target device.
            - self.port (int): The port number.

            Returns:
            - None: Prints the results of the write test, including success or failure messages.
        """
        results: list[WriteTestResult] = []
        if not self.args.community_file and not self.args.single_community:
            ptprint("Error: Neither a community file nor a single community string was provided.", "ERROR", not self.args.json,
                    indent=4)
            return results

        communities = self._text_or_file(self.args.single_community, self.args.community_file)
        #self.drawDoubleLine()
        #self.ptprint("Starting SNMPv2 write permission test...", title=True)
        #self.drawDoubleLine()

        for community in communities:
            try:
                ptprint(f"Testing write permission for community string: {community}", "INFO", not self.args.json,
                        indent=4)
                iterator = set_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    await UdpTransportTarget.create((self.args.ip, self.args.port)),
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0), OctetString(self.args.value))
                )

                errorIndication, errorStatus, errorIndex, varBinds = await iterator

                if not errorIndication and not errorStatus:
                    ptprint("Write was successful!", "VULN", not self.args.json, indent=8)
                    for varBind in varBinds:
                        ptprint(f"OID: {varBind[0]} was set to {varBind[1]}", "INFO", not self.args.json, indent=8)
                        ptprint(f"Note: Attribute was modified for testing purposes. Don't forget to revert it back if necessary.",
                                "INFO", not self.args.json, indent=8)
                        results.append(WriteTestResult(
                        OID=str(varBind[0]),
                        creds=f"{community}",
                        value=str(varBind[1])
                        ))
                else:
                    ptprint(f"Write failed: {errorIndication or errorStatus}", "OK", not self.args.json, indent=8)

            except Exception as e:
                ptprint(f"Exception occurred: {e}", "ERROR", not self.args.json, indent=8)

        return results

    async def getBulk_SNMPv2(self) -> str:

        """
           Executes an SNMPv2 bulk walk on the target device to retrieve MIB object values based on the specified OID.

           Parameters:
           - self.single_community (str): The community string for SNMPv2 authentication.
           - self.oid (str): The starting OID. Default is "1.3.6" if not provided.
           - self.oid_format (bool): Determines if the OID should be converted to a humanreadable format.
           - self.output (bool): Indicates whether the results should be saved to a file.
           - self.ip (str): The IP address of the target device.
           - self.port (int): The port number.

           Returns:
           - results (list): A list of formatted strings containing OID-value pairs retrieved from the target device.
       """

        if not self.args.community_file and not self.args.single_community:
            ptprint("Neither a community file nor a single community string was provided. Defaulting to 'public'.",
                    "WARNING", not self.args.json, indent=4)
            self.args.single_community = "public"

        communities = self._text_or_file(self.args.single_community, self.args.community_file)

        #self.drawDoubleLine()
        #self.ptprint("Starting SNMPv2 bulk walk...", title=True)
        #self.drawDoubleLine()
        results = []
        # for json
        result = None

        for community in communities:
            ptprint(f"Trying community: {community}", "INFO", not self.args.json, indent=4)
            try:
                # Use walk_cmd to traverse the MIB
                objects = walk_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    await UdpTransportTarget.create((self.args.ip, self.args.port)),
                    ContextData(),
                    ObjectType(ObjectIdentity(self.args.oid))
                )

                # Iterate over the returned OID-value pairs
                async for errorIndication, errorStatus, errorIndex, varBinds in objects:
                    if errorIndication:
                        ptprint(f"Error: {errorIndication}", "ERROR", not self.args.json, indent=8)
                        break
                    elif errorStatus:
                        ptprint(f"Error: {errorStatus.prettyPrint()} at {errorIndex}", "ERROR",
                                not self.args.json, indent=8)
                        break
                    else:
                        for oid, value in varBinds:
                            if self.args.oid_format:
                                oid = oid.prettyPrint()  # Convert OID to string
                            value_type = value.__class__.__name__.upper()  # Get the value type
                            value_str = value.prettyPrint()  # Convert value to string

                            # Format the value type and content
                            if value_type == "OCTET STRING":
                                value_output = f'STRING: "{value_str}"'
                            elif value_type == "OBJECT IDENTIFIER":
                                value_output = f'OID: {value}'
                            elif value_type == "TIMETICKS":
                                value_output = f'Timeticks: ({value_str}) {self.format_timeticks(value)}'
                            elif value_type == "INTEGER":
                                value_output = f'INTEGER: {value_str}'
                            else:
                                value_output = value_str  # Default for other types

                            # Construct the final formatted string
                            formatted_output = f"{oid} = {value_output}"
                            ptprint(formatted_output, "TEXT", not self.args.json, indent=8)
                            results.append(formatted_output)

                # Stop the loop if results are found
                if results:
                    ptprint(f"Results found with community '{community}', stopping further attempts.", "VULN",
                            not self.args.json, indent=8)
                    result = "success"
                    break


            except Exception as e:
                ptprint(f"Exception occurred for community '{community}': {e}", "ERROR", not self.args.json, indent=8)
                continue  # Move to the next community in case of errors
        if self.args.output:
            self.write_to_file(results)
        return result

    async def getBulk_SNMPv3(self) -> str:
        """
            Executes an SNMPv3 bulk walk on the target device to retrieve MIB object values based on the specified OID.

            Parameters:
            - self.single_username (str): The username for SNMPv3 authentication.
            - self.single_password (str): The password for SNMPv3 authentication.
            - self.auth_protocols (obj): The authentication protocol (e.g., usmHMACSHAAuthProtocol).
            - self.priv_protocols (obj): The encryption protocol (e.g., usmDESPrivProtocol).
            - self.oid (str): The starting OID. Default is "1.3.6" if not provided.
            - self.oid_format (bool): Determines if the OID should be converted to a humanreadable format.
            - self.output (bool): Indicates whether the results should be saved to a file.
            - self.ip (str): The IP address of the target device.
            - self.port (int): The port number.

            Returns:
            - results (list): A list of formatted strings containing OID-value pairs retrieved from the target device.
        """
        #maps user defined string to oid format of protocol
        PROTOCOL_OBJECTS = {v: k for k, v in self.PROTOCOL_NAMES.items()}

        if not self.args.single_username:
            ptprint("Username was not provided, Set the username to Start the SNMPv3 walk", "ERROR",
                    not self.args.json, indent=4)
            return []

        if not self.args.single_password:
            ptprint("Password was not provided, Set the password to Start the SNMPv3 walk", "WARNING",
                    not self.args.json, indent=4)
            return []

        PROTOCOL_OBJECTS = {v: k for k, v in self.PROTOCOL_NAMES.items()}

        if isinstance(self.args.auth_protocols, str):
            self.args.auth_protocols = PROTOCOL_OBJECTS.get(self.args.auth_protocols, None)
            if self.args.auth_protocols is None:
                ptprint("Warning: Unknown authentication protocol string. Using defaults.", "INFO", not self.args.json,
                        indent=4)


        if isinstance(self.args.priv_protocols, str):
            self.args.priv_protocols = PROTOCOL_OBJECTS.get(self.args.priv_protocols, None)
            if self.args.priv_protocols is None:
                ptprint("Warning: Unknown privacy protocol string. Using defaults.", "INFO", not self.args.json,
                        indent=4)

        if not self.args.auth_protocols:
            ptprint("Be aware that authentication protocol was not provided, so it is set as usmHMACSHAAuthProtocol",
                    "INFO", not self.args.json, indent=4)
            self.args.auth_protocols = usmHMACSHAAuthProtocol

        if not self.args.priv_protocols:
            ptprint("Be aware that private protocol was not provided, so it is set as usmAesCfb128Protocol",
                    "INFO", not self.args.json, indent=4)
            self.args.priv_protocols = usmAesCfb128Protocol

        Protocols = AuthPrivProtocols(self.args.auth_protocols, self.args.priv_protocols)

        if self.args.oid is None:
            self.args.oid = "1.3.6"

        #self.drawDoubleLine()
        #self.ptprint("Starting SNMPv3 bulk walk...", title=True)
        #self.drawDoubleLine()
        results = None

        objects = walk_cmd(
            SnmpEngine(),
            UsmUserData(self.args.single_username, self.args.single_password, authProtocol=Protocols.auth_protocols, privProtocol=Protocols.priv_protocols),
            await UdpTransportTarget.create((self.args.ip, self.args.port)),
            ContextData(),
            ObjectType(ObjectIdentity(self.args.oid))
        )

        # Iterate over the returned OID-value pairs
        async for errorIndication, errorStatus, errorIndex, varBinds in objects:
            if errorIndication:
                ptprint(f"Error: {errorIndication}", "ERROR", not self.args.json, indent=4)
                break
            elif errorStatus:
                ptprint(f"Error: {errorStatus.prettyPrint()} at {errorIndex}", "ERROR", not self.args.json, indent=8)
                break
            else:
                for oid, value in varBinds:
                    if self.args.oid_format:
                        oid = oid.prettyPrint()  # Convert OID to string
                    value_type = value.__class__.__name__.upper()  # Get the value type
                    value_str = value.prettyPrint()  # Convert value to string

                    # Format the value type and content
                    if value_type == "OCTET STRING":
                        value_output = f'STRING: "{value_str}"'
                    elif value_type == "OBJECT-IDENTIFIER":
                        value_output = f'OID: {value}'
                    elif value_type == "TIMETICKS":
                        value_output = f'Timeticks: ({value_str}) {self.format_timeticks(value)}'
                    elif value_type == "INTEGER":
                        value_output = f'INTEGER: {value_str}'
                    else:
                        value_output = value_str  # Default for other types

                    # Construct the final formatted string
                    formatted_output = f"{oid} = {value_output}"
                    ptprint(formatted_output, "TEXT", not self.args.json, indent=8)
                results= "success"

        if self.args.output:
            self.write_to_file(results)
        return results

    def output(self) -> None:
        """
        class SNMPResult:
            version: Optional[SNMPVersion] = None
            communities: Optional[List[str]] = None
            usernames: Optional[List[str]] = None
            credentials: Optional[List[Credential]] = None
            Writetest3: Optional[List[WriteTestResult]] = None
            Writetest2: Optional[List[WriteTestResult]] = None
            Bulk2: Optional[List[str]] = None
            Bulk3: Optional[List[str]] = None
        """
        def credentials_to_string(creds: List[Credential]) -> str:
            return ", ".join(
                f"{c.username or 'None'}:{c.password or 'None'}"
                for c in creds
            )
        def write_results_to_string(results: List[WriteTestResult]) -> str:
            return ", ".join(
                f"{str(r.OID) or 'None'}-{r.value or 'None'}-{r.creds}"
                for r in results
            )

        bulk3_str = None
        if self.results.Bulk3 is not None and len(self.results.Bulk3) != 0:
            bulk3_str = self.results.Bulk3 if isinstance(self.results.Bulk3, str) else "\n".join(self.results.Bulk3)
        bulk2_str = None
        if self.results.Bulk2 is not None and len(self.results.Bulk2) != 0:
            bulk2_str = self.results.Bulk2 if isinstance(self.results.Bulk2, str) else "\n".join(self.results.Bulk2)

        properties = {
            "software_type": None,
            "name": "snmp",
            "version": None,
            "vendor": None,
            "description": None,
            "communities": ",".join(self.results.communities) if self.results.communities is not None and len(self.results.communities) != 0 else None,
            "usernames": ",".join(self.results.usernames) if self.results.usernames is not None and len(self.results.usernames) != 0 else None,
            "credentials": credentials_to_string(self.results.credentials) if self.results.credentials is not None and len(self.results.credentials) != 0 else None,
            "writetest3": write_results_to_string(self.results.Writetest3) if self.results.Writetest3 is not None and len(self.results.Writetest3) != 0 else None,
            "writetest2": write_results_to_string(self.results.Writetest2) if self.results.Writetest2 is not None and len(self.results.Writetest2) != 0 else None,
            "bulk3": bulk3_str,
            "bulk2": bulk2_str,
        }
        deferred_vulns = []

        if self.results.communities is not None and len(self.results.communities) != 0:
            deferred_vulns.append({"vuln_code": VULNS.WeakCommunityName.value, "vuln_request": "Bruteforcing SNMPv1-2 community strings", "vuln_response": ",".join(self.results.communities)})
        if self.results.usernames is not None and len(self.results.usernames) != 0:
            deferred_vulns.append({"vuln_code": VULNS.WeakUsername.value, "vuln_request": "Bruteforcing SNMPv3 usernames", "vuln_response": ",".join(self.results.usernames)})
        if self.results.credentials is not None and len(self.results.credentials) != 0:
            deferred_vulns.append({"vuln_code": VULNS.WeakCredentials.value, "vuln_request": "Bruteforcing SNMPv3 credentials", "vuln_response": credentials_to_string(self.results.credentials)})
        if self.results.Writetest3 is not None and len(self.results.Writetest3) != 0:
            deferred_vulns.append({"vuln_code": VULNS.Write_3.value, "vuln_request": "Testing write access trough SNMPv3", "vuln_response": write_results_to_string(self.results.Writetest3)})
        if self.results.Writetest2 is not None and len(self.results.Writetest2) != 0:
            deferred_vulns.append({"vuln_code": VULNS.Write_2.value, "vuln_request": "Testing write access trough SNMPv2", "vuln_response": write_results_to_string(self.results.Writetest2)})
        if bulk3_str is not None:
            deferred_vulns.append({"vuln_code": VULNS.Readmib_3.value, "vuln_request": "Testing reading MIB database trough SNMPv3", "vuln_response": bulk3_str})
        if bulk2_str is not None:
            deferred_vulns.append({"vuln_code": VULNS.Readmib_2.value, "vuln_request": "Testing reading MIB database trough SNMPv3", "vuln_response": bulk2_str})

        snmp_node = self.ptjsonlib.create_node_object("software", None, None, properties)
        self.ptjsonlib.add_node(snmp_node)
        node_key = snmp_node["key"]
        for v in deferred_vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **v)

        #self.ptprint(self.ptjsonlib.get_result_json(), json=True)