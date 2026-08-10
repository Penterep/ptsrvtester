from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
from ptsrvtester.protocols.snmp.utils.registry import (WriteTestResult, PROTOCOL_NAMES, text_or_file,
                                                       AuthPrivProtocols, Credential)

__MODULELABEL__ = "SNMPv3 Write Permission Test"
__MODULECODE__ = "v2_write"
__ORDER__ = 100


async def test_snmpv3_write_permissions(ctx) -> list[WriteTestResult]:
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

    if not ctx.auth_protocols:
        ctx.out("Be aware that authentication protocol was not provided, so it is set as usmHMACSHAAuthProtocol",
                "INFO", indent=4)
        ctx.auth_protocols = default_auth_protocol

    if not ctx.priv_protocols:
        ctx.out("Be aware that private protocol was not provided, so it is set as usmDESPrivProtocol",
                "INFO", indent=4)
        ctx.priv_protocols = default_priv_protocol

    creds = []

    Protocols = AuthPrivProtocols(ctx.auth_protocols, ctx.priv_protocols)

    if ctx.single_username and ctx.single_password:
        creds.append(Credential(ctx.single_username, ctx.single_password))
    elif ctx.valid_credentials_file:
        inputs = text_or_file(None, ctx.valid_credentials_file)
        for line in inputs:
            # Parse username and password directly from the line
            parts = line.split(", ")
            if len(parts) == 2:
                try:
                    username = parts[0].split(": ")[1]
                    password = parts[1].split(": ")[1]
                    creds.append(Credential(username, password))
                except IndexError:
                    ctx.out(f"Invalid line format: {line}", "WARNING", indent=4)
            else:
                ctx.out(f"Invalid format: {line}", "WARNING", indent=4)
    else:
        ctx.out("Error: Provide either single username/password or a file with credentials.", "WARNING",
                indent=4)
        return []
    # self.drawDoubleLine()
    # self.ctx.out("Starting SNMPv3 write permission test...", title=True)
    # self.drawDoubleLine()

    for cred in creds:
        try:
            ctx.out(f"Testing write permission for user: {cred.username} with password: {cred.password}", "INFO",
                    indent=4)
            iterator = set_cmd(
                SnmpEngine(),
                UsmUserData(cred.username, cred.password, authProtocol=Protocols.auth_protocols,
                            privProtocol=Protocols.priv_protocols),
                await UdpTransportTarget.create((ctx.ip, ctx.port)),
                ContextData(),
                ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0), OctetString(ctx.value))
            )

            errorIndication, errorStatus, errorIndex, varBinds = await iterator

            if not errorIndication and not errorStatus:
                ctx.out("Test was successful!", "VULN", indent=8)
                for varBind in varBinds:
                    ctx.out(f"OID: {varBind[0]} was set to {varBind[1]}", "INFO", indent=8)
                    ctx.out(
                        f"Note: Attribute was modified for testing purposes. Don't forget to revert it back if necessary.",
                        "INFO", indent=8)
                    results.append(WriteTestResult(
                        OID=str(varBind[0]),
                        creds=f"{cred.username or 'None'}:{cred.password or 'None'}",
                        value=str(varBind[1])
                    ))
            else:
                ctx.out(f"Test failed: {errorIndication or errorStatus}", "OK",
                        indent=8)

        except Exception as e:
            ctx.out(f"Exception occurred: {e}", "ERROR", indent=8)

    return results


def run(ctx):
    asyncio.run(test_snmpv3_write_permissions(ctx))
