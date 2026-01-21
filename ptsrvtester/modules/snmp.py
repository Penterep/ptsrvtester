from enum import Enum
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from typing import List, NamedTuple
from pysnmp.proto.errind import RequestTimedOut
import argparse
from dataclasses import dataclass
from typing import List, Optional

from ptlibs.ptjsonlib import PtJsonLib

from ._base import BaseModule, BaseArgs, Out

    
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
        return [
            {"description": ["SNMP Testing Module"]},
            {"usage": ["ptsrvtester snmp <command> <options>"]},
            {"usage_example": [
                "ptsrvtester snmp detection --ip 192.168.1.1",
                "ptsrvtester snmp snmpv2-brute --community-file communities.txt --ip 192.168.1.1",
                "ptsrvtester snmp snmpv3-brute --username-file users.txt --password-file passwords.txt --ip 192.168.1.1"
            ]},
            {"options": [
                ["detection", "<options>", "", "Detect SNMP versions"],
                ["snmpv2-brute", "<options>", "", "SNMPv2 dictionary attack"],
                ["snmpv2-write", "<options>", "", "Test SNMPv2 write permission"],
                ["snmpv2-walk", "<options>", "", "SNMPv2 MIB walk"],
                ["snmpv3-enum", "<options>", "", "SNMPv3 user enumeration"],
                ["snmpv3-brute", "<options>", "", "SNMPv3 credentials bruteforce"],
                ["snmpv3-walk", "<options>", "", "SNMPv3 MIB walk"],
                ["snmpv3-write", "<options>", "", "Test SNMPv3 write permissions"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of SNMP arguments"""

        examples = """example usage:
    ptsrvtester snmp detection --ip 192.168.1.1 --port 161
    ptsrvtester snmp snmpv2-brute --community-file communities.txt --ip 192.168.1.1 --port 161
    ptsrvtester snmp snmpv3-brute --username-file users.txt --password-file passwords.txt --ip 192.168.1.1 --port 161"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError

        snmp_subparsers = parser.add_subparsers(dest="command", help="Select SNMP command", required=True)

        # SNMP Version Detection
        detection = snmp_subparsers.add_parser("detection", help="Detect SNMP versions")
        detection.add_argument("-ip", "--ip", required=True, help="Target IP address")
        detection.add_argument("-p", "--port", type=int,default = 161, help="Target port")

        # SNMPv2 Brute Force
        snmpv2_brute_parser = snmp_subparsers.add_parser("snmpv2-brute", help="SNMPv2 dictionary attack")
        snmpv2_brute_parser.add_argument("-ip", "--ip", required=True, help="Target IP address")
        snmpv2_brute_parser.add_argument("-p", "--port", type=int, default = 161, help="Target port")
        snmpv2_brute_parser.add_argument("-o", "--output",  help="File to save the output results.")

        user_group1 = snmpv2_brute_parser.add_mutually_exclusive_group(required=True)
        user_group1.add_argument("-c", "--single-community", "--community", help="Single community string")
        user_group1.add_argument("-cf", "--community-file", help="File containing community strings")

        # SNMPv2 Write Permission
        snmpv2_write_parser = snmp_subparsers.add_parser("snmpv2-write", help="Test SNMPv2 write permission")
        snmpv2_write_parser.add_argument("-ip", "--ip", required=True, help="Target IP address")
        snmpv2_write_parser.add_argument("-p", "--port", type=int, default = 161, help="Target port")
        snmpv2_write_parser.add_argument("-v", "--value", default="Testvalue123", help="Value to write to the specified OID (default: 'Testvalue123')")

        user_group2 = snmpv2_write_parser.add_mutually_exclusive_group(required=True)
        user_group2.add_argument("-c", "--single-community", "--community", help="Single community string")
        user_group2.add_argument("-cf", "--community-file", help="File containing community strings")

        # SNMPv2 GetBulk (Walk)
        snmpv2_getbulk_parser = snmp_subparsers.add_parser("snmpv2-walk", help="SNMPv2 MIB walk")
        snmpv2_getbulk_parser.add_argument("-ip","--ip", required=True, help="Target IP address")
        snmpv2_getbulk_parser.add_argument("-p","--port", type=int, default = 161, help="Target port")
        snmpv2_getbulk_parser.add_argument("-oid","--oid", default="1.3.6", help="OID to start from")
        snmpv2_getbulk_parser.add_argument("-of","--oid-format", action="store_true", help="Use human readable OID format")
        snmpv2_getbulk_parser.add_argument("-o","--output", help="File to save the output results.")

        user_group3 = snmpv2_getbulk_parser.add_mutually_exclusive_group(required=True)
        user_group3.add_argument("-c", "--single-community", "--community", help="Single community string")
        user_group3.add_argument("-cf", "--community-file", help="File containing community strings")

        # SNMPv3 User Enumeration
        user_enum_parser = snmp_subparsers.add_parser("snmpv3-enum", help="SNMPv3 user enumeration")
        user_enum_parser.add_argument("-ip","--ip", required=True, help="Target IP address")
        user_enum_parser.add_argument("-p","--port", type=int, default = 161, help="Target port")
        user_enum_parser.add_argument("-o", "--output", help="File to save the output results.")

        user_group4 = user_enum_parser.add_mutually_exclusive_group(required=True)
        user_group4.add_argument("-u", "--single-username", help="Single username")
        user_group4.add_argument("-ul", "--username-file", help="File containing usernames")

        # SNMPv3 Brute Force
        snmpv3_brute_parser = snmp_subparsers.add_parser("snmpv3-brute", help="SNMPv3 credentials bruteforce")
        snmpv3_brute_parser.add_argument("-ip", "--ip", required=True, help="Target IP address")
        snmpv3_brute_parser.add_argument("-p", "--port", type=int, default = 161, help="Target port")
        snmpv3_brute_parser.add_argument("-ap", "--auth-protocols", help="Authentication protocol")
        snmpv3_brute_parser.add_argument("-pp", "--priv-protocols", help="Private protocol")
        snmpv3_brute_parser.add_argument("-o", "--output", help="File to save the output results.")
        snmpv3_brute_parser.add_argument("-s", "--spray", action="store_true", help="Enable spray mode")
  
        user_group6 = snmpv3_brute_parser.add_mutually_exclusive_group(required=True)
        user_group6.add_argument("-u", "--single-username", help="Single username")
        user_group6.add_argument("-ul", "--username-file", help="File containing usernames")

        user_group7 = snmpv3_brute_parser.add_mutually_exclusive_group(required=True)
        user_group7.add_argument("-pw", "--single-password", help="Single password")
        user_group7.add_argument("-pl", "--password-file", help="File containing passwords")


        # SNMPv3 GetBulk (Walk)
        snmpv3_getbulk_parser = snmp_subparsers.add_parser("snmpv3-walk", help="SNMPv3 MIB walk")
        snmpv3_getbulk_parser.add_argument("-ip", "--ip", required=True, help="Target IP address")
        snmpv3_getbulk_parser.add_argument("-p", "--port", type=int, default = 161, help="Target port")
        snmpv3_getbulk_parser.add_argument("-u", "--single-username", help="Single username")
        snmpv3_getbulk_parser.add_argument("-pw", "--single-password", help="Single password")
        snmpv3_getbulk_parser.add_argument("-ap", "--auth-protocols", help="Authentication protocol")
        snmpv3_getbulk_parser.add_argument("-pp", "--priv-protocols", help="Private protocol")
        snmpv3_getbulk_parser.add_argument("-oid", "--oid", default="1.3.6", help="OID to start from")
        snmpv3_getbulk_parser.add_argument("-of", "--oid-format", action="store_true", help="Use human readable OID format")
        snmpv3_getbulk_parser.add_argument("-o", "--output", help="File to save the output results.")

        # SNMPv3 Write Permission
        snmpv3_write = snmp_subparsers.add_parser("snmpv3-write", help="Test SNMPv3 write permissions")
        snmpv3_write.add_argument("-ip", "--ip", required=True, help="Target IP address")
        snmpv3_write.add_argument("-p", "--port", type=int, default = 161, help="Target port")
        snmpv3_write.add_argument("-u", "--single-username", help="Single username")
        snmpv3_write.add_argument("-pw", "--single-password", help="Single password")
        snmpv3_write.add_argument("-cred", "--valid-credentials-file", help="File containing valid credentials")
        snmpv3_write.add_argument("-ap", "--auth-protocols", help="Authentication protocol")
        snmpv3_write.add_argument("-pp", "--priv-protocols", help="Private protocol")
        snmpv3_write.add_argument("-v", "--value", default="Testvalue123", help="Value to write to the specified OID (default: 'Testvalue123')")


class SNMP(BaseModule):
    @staticmethod
    def module_args():
        return SNMPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        self.args = args  # type: SNMPArgs
        self.ptjsonlib = ptjsonlib
        self.results: SNMPResult | None = None

    def run(self) -> None:
        """Main SNMP execution logic"""

        self.results = SNMPResult()

        if self.args.command == "detection":
            self.results.version = asyncio.run(self.version_detection())

        elif self.args.command == "snmpv2-brute":
            self.results.communities = asyncio.run(self.snmpv2_brute())

        elif self.args.command == "snmpv3-brute":
            self.results.credentials = asyncio.run(self.snmpv3_brute())

        elif self.args.command == "snmpv3-enum":
            self.results.usernames = asyncio.run(self.user_enum())

        elif self.args.command == "snmpv2-write":
            self.results.Writetest2 = asyncio.run(self.test_snmpv2_write_permission())

        elif self.args.command == "snmpv3-write":
            self.results.Writetest3 = asyncio.run(self.test_snmpv3_write_permissions())

        elif self.args.command == "snmpv2-walk":
            self.results.Bulk2 = asyncio.run(self.getBulk_SNMPv2())

        elif self.args.command == "snmpv3-walk":
            self.results.Bulk3 = asyncio.run(self.getBulk_SNMPv3())
        
        else:
            self.ptprint("Unknown command for SNMP module.", out=Out.WARNING)

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
        with open(self.args.output, 'a') as f:
            if isinstance(message_or_messages, str):
                # If it's a single message, write it directly
                f.write(message_or_messages + '\n')
            elif isinstance(message_or_messages, list):
                # If it's a list of messages, iterate and write each one
                for message in message_or_messages:
                    f.write(message + '\n')

    def _text_or_file(self, text: str | None, file_path: str | None) -> List[str]:

        if text:
            return [text.strip()]
        elif file_path:
            try:
                with open(file_path, 'r') as file:
                    return [line.strip() for line in file if line.strip()]
            except Exception as e:
                self.ptprint(f"Error reading file {file_path}: {e}", out=Out.WARNING)
                return []
        else:
            self.ptprint("Error: Neither text nor file input provided.", out=Out.WARNING)
            return []

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
            self.ptprint(f"Error!: {errorIndication}", out=Out.ERROR)
        elif errorStatus:
            self.ptprint(
                "{} at {}".format(
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                ),
                out=Out.ERROR
            )

        else:
            v1 = True
            for varBind in varBinds:
                self.ptprint("Success!: ", end="", out=Out.OK)
                self.ptprint(" = ".join([x.prettyPrint() for x in varBind]))

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
             self.ptprint(f"Error!: {errorIndication}", out=Out.ERROR)

        elif errorStatus:
            self.ptprint("Error!:", out=Out.ERROR)
            self.ptprint(
                "{} at {}".format(
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                ),
                out=Out.ERROR
            )

        else:
            v2c = True
            for varBind in varBinds:
                self.ptprint("Success!: ", end="", out=Out.OK)  # můžeš nastavit `out=Out.SUCCESS` pokud máš definováno
                self.ptprint(" = ".join([x.prettyPrint() for x in varBind]))

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
                self.ptprint(f"Error!: {errorIndication}", out=Out.ERROR)
            else:
                self.ptprint(f"Success!: {errorIndication}", out=Out.OK)
                v3 = True

        elif errorStatus:
            self.ptprint(
                "{} at {}".format(
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                ),
                out=Out.ERROR
            )

        else:
            v3 = True
            for varBind in varBinds:
                self.ptprint(" = ".join([x.prettyPrint() for x in varBind]))

        self.ptprint(str(SNMPVersion(v1, v2c, v3)))
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
            self.ptprint("Error: Neither a community file nor a single community string was provided.", out=Out.WARNING)
            return []
        self.drawDoubleLine()
        self.ptprint("Starting a dictionary attack on SNMPv2...", title=True)
        self.drawDoubleLine()
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
                self.ptprint(f"Valid community string found: {community}", out=Out.OK)
                valid_communities.append(community)
            else:
                self.ptprint(f"Error: {errorIndication or errorStatus} for {community}", out=Out.ERROR)

        if valid_communities:
            self.ptprint("\n")
            self.ptprint("Valid communities:", out=Out.INFO)
            for community in valid_communities:
                self.ptprint(community)
            if self.args.output:
                for community in valid_communities:
                    self.write_to_file(community)

        else:
            self.ptprint("\nNo valid communities found :(", out=Out.INFO)
        return valid_communities

    async def user_enum(self) -> list[str]:


        # Users from input
        users: list[str] = self._text_or_file(self.args.single_username, self.args.username_file)

        self.drawDoubleLine()
        self.ptprint("Starting username enumeration...", title=True)
        self.drawDoubleLine()
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
                    self.ptprint(f"Valid username found: {username}", out=Out.OK)
                    valid_usernames.add(username)
                elif "Wrong SNMP PDU digest" in str(errorIndication):
                    self.ptprint(f"Potential valid username: {username}", out=Out.OK)
                    valid_usernames.add(username)
                else:
                    
                    self.ptprint(f"Error for username {username}: {errorIndication or errorStatus}", out=Out.ERROR)

            except Exception as e:
                self.ptprint(f"Error for username {username}: {e}", out=Out.ERROR)

        if valid_usernames:
            self.ptprint("\n")
            self.ptprint("Potential valid usernames:", out=Out.INFO)
            for username in valid_usernames:
                self.ptprint(username)
                if self.args.output:
                    self.write_to_file(username)
        else:
            self.ptprint("No valid usernames found.", out=Out.INFO)

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
            self.ptprint("Error: Neither a username file nor a single username was provided.", out=Out.WARNING)
            return None

        # Warning
        if not self.args.password_file and not self.args.single_password:
            self.ptprint("Error: Neither a password file nor a single password was provided.", out=Out.WARNING)
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
            self.ptprint("No auth or priv protocols set." , out=Out.TITLE)
            users = await self.user_enum()
            valid_usernames = set(users)
            if not users:
                self.ptprint("\n")
                self.ptprint("Sorry, it is not possible to find valid credentials with these usernames", out=Out.ERROR)
                return None
            
        PROTOCOL_OBJECTS = {v: k for k, v in self.PROTOCOL_NAMES.items()}

        if isinstance(self.args.auth_protocols, str):
            self.args.auth_protocols = PROTOCOL_OBJECTS.get(self.args.auth_protocols, None)
            if self.args.auth_protocols is None:
                self.ptprint("Warning: Unknown authentication protocol string. Using defaults.", out=Out.INFO)


        if isinstance(self.args.priv_protocols, str):
            self.args.priv_protocols = PROTOCOL_OBJECTS.get(self.args.priv_protocols, None)
            if self.args.priv_protocols is None:
                self.ptprint("Warning: Unknown privacy protocol string. Using defaults.", out=Out.INFO)

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
        self.ptprint("\n")
        self.drawDoubleLine()
        self.ptprint("Starting a dictionary attack on SNMPv3...", title=True)
        self.drawDoubleLine()

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
                        self.ptprint(f"Valid credentials found: Username: {cred.username}, Password: {cred.password}", out=Out.OK)
                        self.ptprint(f"Successful Authentication and Private protocols are: {auth_name} and {priv_name}", out=Out.INFO)
                    elif "Wrong SNMP PDU digest" in str(errorIndication):
                        self.ptprint(f"Digest match (likely valid username - Try different password or protocols): {cred.username}", out=Out.INFO)
                        valid_usernames.add(cred.username)
                    elif "Unknown USM user" in str(errorIndication):
                        self.ptprint(f"Error: Unknown user: {cred.username}", out=Out.ERROR)
                    else:
                        self.ptprint(f"Error: {errorIndication or errorStatus} for {cred.username}/{cred.password}", out=Out.ERROR)

                except Exception as e:
                    self.ptprint(f"Error: {cred.username}/{cred.password}: {e}", out=Out.ERROR)

        if valid_usernames:
            self.ptprint("\n")
            self.ptprint("Potential valid usernames:", out=Out.INFO)
            for username in valid_usernames:
                self.ptprint(username)

        if self.args.output and found_credentials:
            results = [f"Username: {cred.username}, Password: {cred.password}" for cred in found_credentials]
            self.write_to_file(results)

        if found_credentials:
            self.ptprint("\n")
            self.ptprint("Found credentials:", out=Out.INFO)
            for cred in found_credentials:
                self.ptprint(f"Username: {cred.username}, Password: {cred.password}")

        if successful_protocol:
            auth_name = self.PROTOCOL_NAMES.get(successful_protocol.auth_protocols, "Unknown Protocol")
            priv_name = self.PROTOCOL_NAMES.get(successful_protocol.priv_protocols, "Unknown Protocol")
            self.ptprint("\n")
            self.ptprint(f"Successful Authentication and Private protocols are: {auth_name} and {priv_name}", out=Out.INFO)

        else:
            self.ptprint("\n")
            self.ptprint("No valid credentials found :(", out=Out.ERROR)

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
                self.ptprint("Warning: Unknown authentication protocol string. Using defaults.", out=Out.INFO)


        if isinstance(self.args.priv_protocols, str):
            self.args.priv_protocols = PROTOCOL_OBJECTS.get(self.args.priv_protocols, None)
            if self.args.priv_protocols is None:
                self.ptprint("Warning: Unknown privacy protocol string. Using defaults.", out=Out.INFO)

        if not self.args.auth_protocols:
            self.ptprint("Be aware that authentication protocol was not provided, so it is set as usmHMACSHAAuthProtocol", out=Out.INFO)
            self.args.auth_protocols = default_auth_protocol

        if not self.args.priv_protocols:
            self.ptprint("Be aware that private protocol was not provided, so it is set as usmDESPrivProtocol", out=Out.INFO)
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
                        self.ptprint(f"Invalid line format: {line}", out=Out.WARNING)
                else:
                    self.ptprint(f"Invalid format: {line}", out=Out.WARNING)
        else:
            self.ptprint("Error: Provide either single username/password or a file with credentials.", out=Out.WARNING)
            return
        self.drawDoubleLine()
        self.ptprint("Starting SNMPv3 write permission test...", title=True)
        self.drawDoubleLine()
        

        for cred in creds:
            try:
                self.ptprint(f"Testing write permission for user: {cred.username} with password: {cred.password}", out=Out.INFO)
                iterator = set_cmd(
                    SnmpEngine(),
                    UsmUserData(cred.username, cred.password, authProtocol=Protocols.auth_protocols, privProtocol=Protocols.priv_protocols),
                    await UdpTransportTarget.create((self.args.ip, self.args.port)),
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0), OctetString(self.args.value))
                )

                errorIndication, errorStatus, errorIndex, varBinds = await iterator

                if not errorIndication and not errorStatus:
                    self.ptprint("Test was successful!", out=Out.OK)
                    for varBind in varBinds:
                        self.ptprint(f"OID: {varBind[0]} was set to {varBind[1]}")
                        self.ptprint(f"Note: Attribute was modified for testing purposes. Don't forget to revert it back if necessary.", out=Out.INFO)
                        results.append(WriteTestResult(
                        OID=str(varBind[0]),
                        creds=f"{cred.username or 'None'}:{cred.password or 'None'}",
                        value=str(varBind[1])
                        ))
                else:
                    self.ptprint(f"Test failed: {errorIndication or errorStatus}", out=Out.ERROR)

            except Exception as e:
                self.ptprint(f"Exception occurred: {e}", out=Out.WARNING)

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
            self.ptprint("Error: Neither a community file nor a single community string was provided.", out=Out.WARNING)
            return results

        communities = self._text_or_file(self.args.single_community, self.args.community_file)
        self.drawDoubleLine()
        self.ptprint("Starting SNMPv2 write permission test...", title=True)
        self.drawDoubleLine()

        for community in communities:
            try:
                self.ptprint(f"Testing write permission for community string: {community}", out=Out.INFO)
                iterator = set_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    await UdpTransportTarget.create((self.args.ip, self.args.port)),
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0), OctetString(self.args.value))
                )

                errorIndication, errorStatus, errorIndex, varBinds = await iterator

                if not errorIndication and not errorStatus:
                    self.ptprint("Write was successful!", out=Out.OK)
                    for varBind in varBinds:
                        self.ptprint(f"OID: {varBind[0]} was set to {varBind[1]}")
                        self.ptprint(f"Note: Attribute was modified for testing purposes. Don't forget to revert it back if necessary.", out=Out.INFO)
                        results.append(WriteTestResult(
                        OID=str(varBind[0]),
                        creds=f"{community}",
                        value=str(varBind[1])
                        ))
                else:
                    self.ptprint(f"Write failed: {errorIndication or errorStatus}", out=Out.ERROR)

            except Exception as e:
                self.ptprint(f"Exception occurred: {e}", out=Out.WARNING)

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
            self.ptprint("Neither a community file nor a single community string was provided. Defaulting to 'public'.", out=Out.WARNING)
            self.args.single_community = "public"

        communities = self._text_or_file(self.args.single_community, self.args.community_file)

        self.drawDoubleLine()
        self.ptprint("Starting SNMPv2 bulk walk...", title=True)
        self.drawDoubleLine()
        results = []
        # for json
        result = None

        for community in communities:
            self.ptprint(f"Trying community: {community}", out=Out.INFO)
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
                        self.ptprint(f"Error: {errorIndication}", out=Out.ERROR)
                        break
                    elif errorStatus:
                        self.ptprint(f"Error: {errorStatus.prettyPrint()} at {errorIndex}", out=Out.ERROR)
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
                            self.ptprint(formatted_output)
                            results.append(formatted_output)

                # Stop the loop if results are found
                if results:
                    self.ptprint(f"Results found with community '{community}', stopping further attempts.", out=Out.OK)
                    result = "success"
                    break
                    

            except Exception as e:
                self.ptprint(f"Exception occurred for community '{community}': {e}", out=Out.WARNING)
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
            self.ptprint("\nUsername was not provided, Set the username to Start the SNMPv3 walk", out=Out.WARNING)
            return []

        if not self.args.single_password:
            self.ptprint("\nPassword was not provided, Set the password to Start the SNMPv3 walk", out=Out.WARNING)
            return []

        PROTOCOL_OBJECTS = {v: k for k, v in self.PROTOCOL_NAMES.items()}

        if isinstance(self.args.auth_protocols, str):
            self.args.auth_protocols = PROTOCOL_OBJECTS.get(self.args.auth_protocols, None)
            if self.args.auth_protocols is None:
                self.ptprint("Warning: Unknown authentication protocol string. Using defaults.", out=Out.INFO)


        if isinstance(self.args.priv_protocols, str):
            self.args.priv_protocols = PROTOCOL_OBJECTS.get(self.args.priv_protocols, None)
            if self.args.priv_protocols is None:
                self.ptprint("Warning: Unknown privacy protocol string. Using defaults.", out=Out.INFO)

        if not self.args.auth_protocols:
            self.ptprint("Be aware that authentication protocol was not provided, so it is set as usmHMACSHAAuthProtocol", out=Out.INFO)
            self.args.auth_protocols = usmHMACSHAAuthProtocol

        if not self.args.priv_protocols:
            self.ptprint("Be aware that private protocol was not provided, so it is set as usmAesCfb128Protocol", out=Out.INFO)
            self.args.priv_protocols = usmAesCfb128Protocol

        Protocols = AuthPrivProtocols(self.args.auth_protocols, self.args.priv_protocols)

        if self.args.oid is None:
            self.args.oid = "1.3.6"

        self.drawDoubleLine()
        self.ptprint("Starting SNMPv3 bulk walk...", title=True)
        self.drawDoubleLine()
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
                self.ptprint(f"Error: {errorIndication}", out=Out.ERROR)
                break
            elif errorStatus:
                self.ptprint(f"Error: {errorStatus.prettyPrint()} at {errorIndex}", out=Out.ERROR)
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
                    self.ptprint(formatted_output)
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

        if (self.results.communities != None):
            if len(self.results.communities) != 0:
                self.ptjsonlib.add_vulnerability(VULNS.WeakCommunityName.value, "Bruteforcing SNMPv1-2 community strings", ",".join(self.results.communities))
        
        if (self.results.usernames != None):
            if len(self.results.usernames) != 0:
                self.ptjsonlib.add_vulnerability(VULNS.WeakUsername.value, "Bruteforcing SNMPv3 usernames", ",".join(self.results.usernames))

        if (self.results.credentials != None):
            if len(self.results.credentials) != 0:
                cred_str = credentials_to_string(self.results.credentials)
                self.ptjsonlib.add_vulnerability(VULNS.WeakCredentials.value, "Bruteforcing SNMPv3 credentials", cred_str) 

        if (self.results.Writetest3 != None):
            if len(self.results.Writetest3) != 0:
                value_str = write_results_to_string(self.results.Writetest3)
                self.ptjsonlib.add_vulnerability(VULNS.Write_3.value, "Testing write access trough SNMPv3", value_str)
        
        if (self.results.Writetest2 != None):
            if len(self.results.Writetest2) != 0:
                value_str = write_results_to_string(self.results.Writetest2)
                self.ptjsonlib.add_vulnerability(VULNS.Write_2.value, "Testing write access trough SNMPv2", value_str)
        
        if (self.results.Bulk3 != None):
            if len(self.results.Bulk3) != 0:
                self.ptjsonlib.add_vulnerability(VULNS.Readmib_3.value, "Testing reading MIB database trough SNMPv3", self.results.Bulk3)

        if (self.results.Bulk2 != None):
            if len(self.results.Bulk2) != 0:
                self.ptjsonlib.add_vulnerability(VULNS.Readmib_2.value, "Testing reading MIB database trough SNMPv3", self.results.Bulk2)

    

        

        self.ptprint(self.ptjsonlib.get_result_json(), json=True)