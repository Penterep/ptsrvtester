from pysnmp.hlapi.v3arch.asyncio import *

import asyncio
from ptsrvtester.protocols.snmp.utils.helpers import write_to_file
from ptsrvtester.protocols.snmp.utils.registry import (PROTOCOL_NAMES, text_or_file,
                                                       AuthPrivProtocols, Credential)
from ptsrvtester.protocols.snmp.modules.v3_enum import user_enum

__MODULELABEL__ = "SNMPv3 Brute Force Test"
__MODULECODE__ = "v3_brute"
__ORDER__ = 100


async def snmpv3_brute(ctx) -> list[Credential] | None:
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
    if not ctx.username_file and not ctx.single_username:
        ctx.out("Error: Neither a username file nor a single username was provided.", "WARNING", 
                indent=4)
        return None

    # Warning
    if not ctx.password_file and not ctx.single_password:
        ctx.out("Error: Neither a password file nor a single password was provided.", "WARNING", 
                indent=4)
        return None

    # Users and passwords from input
    users = text_or_file(ctx.single_username, ctx.username_file)
    passwords = text_or_file(ctx.single_password, ctx.password_file)
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
    if (ctx.auth_protocols is None or ctx.priv_protocols is None) and ctx.username_file:
        ctx.out("No auth or priv protocols set", "TITLE",  indent=4)
        users = await user_enum(ctx)
        valid_usernames = set(users)
        if not users:
            # self.ctx.out("\n")
            ctx.out("It is not possible to find valid credentials with these usernames", "OK",
                     indent=4)
            return None

    PROTOCOL_OBJECTS = {v: k for k, v in PROTOCOL_NAMES.items()}

    if isinstance(ctx.auth_protocols, str):
        ctx.auth_protocols = PROTOCOL_OBJECTS.get(ctx.auth_protocols, None)
        if ctx.auth_protocols is None:
            ctx.out("Warning: Unknown authentication protocol string. Using defaults", "WARNING", 
                    indent=4)

    if isinstance(ctx.priv_protocols, str):
        ctx.priv_protocols = PROTOCOL_OBJECTS.get(ctx.priv_protocols, None)
        if ctx.priv_protocols is None:
            ctx.out("Warning: Unknown privacy protocol string. Using defaults", "WARNING", 
                    indent=4)

    auth_protocols = [ctx.auth_protocols] if ctx.auth_protocols else default_auth_protocols
    priv_protocols = [ctx.priv_protocols] if ctx.priv_protocols else default_priv_protocols

    protocols = [AuthPrivProtocols(a, p) for a in auth_protocols for p in priv_protocols]

    # Spray logic
    if ctx.spray:
        creds = [Credential(u, p) for p in passwords for u in users]
    else:
        creds = [Credential(u, p) for u in users for p in passwords]

    found_credentials = []  # store valid found credentials
    successful_protocol = None  # Track the successful protocol combination
    valid_usernames = set()

    # starting the attack
    # self.ctx.out("\n")
    # self.drawDoubleLine()
    # self.ctx.out("Starting a dictionary attack on SNMPv3...", title=True)
    # self.drawDoubleLine()

    for protocol in protocols:
        if successful_protocol:
            # If a valid protocol was found, skip other combinations
            if protocol != successful_protocol:
                continue
        for cred in creds:
            try:
                iterator = get_cmd(SnmpEngine(),
                                   UsmUserData(cred.username, cred.password, authProtocol=protocol.auth_protocols,
                                               privProtocol=protocol.priv_protocols),
                                   await UdpTransportTarget.create((ctx.ip, ctx.port)),
                                   ContextData(),
                                   ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)))
                errorIndication, errorStatus, errorIndex, varBinds = await iterator

                if not errorIndication and not errorStatus:
                    found_credentials.append(cred)
                    successful_protocol = protocol
                    valid_usernames.add(cred.username)
                    auth_name = PROTOCOL_NAMES.get(successful_protocol.auth_protocols, "Unknown Protocol")
                    priv_name = PROTOCOL_NAMES.get(successful_protocol.priv_protocols, "Unknown Protocol")
                    ctx.out(f"Valid credentials found: Username: {cred.username}, Password: {cred.password}",
                            "VULN",  indent=4)
                    ctx.out(f"Successful Authentication and Private protocols are: {auth_name} and {priv_name}",
                            "INFO",  indent=4)
                elif "Wrong SNMP PDU digest" in str(errorIndication):
                    ctx.out(
                        f"Digest match (likely valid username - Try different password or protocols): {cred.username}",
                        "INFO",  indent=4)
                    valid_usernames.add(cred.username)
                elif "Unknown USM user" in str(errorIndication):
                    ctx.out(f"Error: Unknown user: {cred.username}", "ERROR",  indent=4)
                else:
                    ctx.out(f"Error: {errorIndication or errorStatus} for {cred.username}/{cred.password}", "ERROR",
                             indent=4)

            except Exception as e:
                ctx.out(f"Error: {cred.username}/{cred.password}: {e}", "ERROR",  indent=4)

    if valid_usernames:
        # self.ctx.out("\n")
        ctx.out(f"Potential valid usernames:", "INFO",  indent=4)
        for username in valid_usernames:
            ctx.out(username, "VULN",  indent=8)

    if ctx.write_to_file and found_credentials:
        results = [f"Username: {cred.username}, Password: {cred.password}" for cred in found_credentials]
        write_to_file(ctx.write_to_file, results)

    if found_credentials:
        # self.ctx.out("\n")
        ctx.out("Found credentials:", "INFO",  indent=4)
        creds_dict = {}
        for cred in found_credentials:
            ctx.out(f"Username: {cred.username}, Password: {cred.password}", "VULN",  indent=8)
            creds_dict.update({cred.username: cred.password})
        cred_node = ctx.ptjsonlib.create_node_object("found_v3_credentials", properties=creds_dict)
        ctx.ptjsonlib.add_node(cred_node)

    if successful_protocol:
        auth_name = PROTOCOL_NAMES.get(successful_protocol.auth_protocols, "Unknown Protocol")
        priv_name = PROTOCOL_NAMES.get(successful_protocol.priv_protocols, "Unknown Protocol")
        # self.ctx.out("\n")
        ctx.out(f"Successful Authentication and Private protocols are: {auth_name} and {priv_name}", "INFO",
                 indent=4)
        proto_node = ctx.ptjsonlib.create_node_object("auth_priv_protocols",
                                                      properties={
                                                          "auth_proto": auth_name,
                                                          "priv_proto": priv_name
                                                      })
        ctx.ptjsonlib.add_node(proto_node)

    else:
        # self.ctx.out("\n")
        ctx.out("No valid credentials found", "OK",  indent=4)

    return found_credentials


def run(ctx):
    asyncio.run(snmpv3_brute(ctx))
