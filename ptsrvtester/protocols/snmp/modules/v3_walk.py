from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
from ptsrvtester.protocols.snmp.utils.helpers import write_to_file, format_timeticks
from ptsrvtester.protocols.snmp.utils.registry import PROTOCOL_NAMES, AuthPrivProtocols


__MODULELABEL__ = "SNMPv3 Walk"
__MODULECODE__ = "v3_walk"
__ORDER__ = 100


async def getBulk_SNMPv3(ctx) -> list:
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
    # maps user defined string to oid format of protocol
    PROTOCOL_OBJECTS = {v: k for k, v in PROTOCOL_NAMES.items()}

    if not ctx.single_username:
        ctx.out("Username was not provided, Set the username to Start the SNMPv3 walk", "ERROR",
                 indent=4)
        return []

    if not ctx.single_password:
        ctx.out("Password was not provided, Set the password to Start the SNMPv3 walk", "WARNING",
                 indent=4)
        return []

    PROTOCOL_OBJECTS = {v: k for k, v in PROTOCOL_NAMES.items()}

    if isinstance(ctx.auth_protocols, str):
        ctx.auth_protocols = PROTOCOL_OBJECTS.get(ctx.auth_protocols, None)
        if ctx.auth_protocols is None:
            ctx.out("Warning: Unknown authentication protocol string. Using defaults.", "INFO", 
                    indent=4)

    if isinstance(ctx.priv_protocols, str):
        ctx.priv_protocols = PROTOCOL_OBJECTS.get(ctx.priv_protocols, None)
        if ctx.priv_protocols is None:
            ctx.out("Warning: Unknown privacy protocol string. Using defaults.", "INFO", 
                    indent=4)

    if not ctx.auth_protocols:
        ctx.out("Be aware that authentication protocol was not provided, so it is set as usmHMACSHAAuthProtocol",
                "INFO",  indent=4)
        ctx.auth_protocols = usmHMACSHAAuthProtocol

    if not ctx.priv_protocols:
        ctx.out("Be aware that private protocol was not provided, so it is set as usmAesCfb128Protocol",
                "INFO",  indent=4)
        ctx.priv_protocols = usmAesCfb128Protocol

    Protocols = AuthPrivProtocols(ctx.auth_protocols, ctx.priv_protocols)

    if ctx.oid is None:
        ctx.oid = "1.3.6"

    # self.drawDoubleLine()
    # self.ctx.out("Starting SNMPv3 bulk walk...", title=True)
    # self.drawDoubleLine()
    results = None
    oids = {}

    objects = walk_cmd(
        SnmpEngine(),
        UsmUserData(ctx.single_username, ctx.single_password, authProtocol=Protocols.auth_protocols,
                    privProtocol=Protocols.priv_protocols),
        await UdpTransportTarget.create((ctx.ip, ctx.port)),
        ContextData(),
        ObjectType(ObjectIdentity(ctx.oid))
    )

    # Iterate over the returned OID-value pairs
    async for errorIndication, errorStatus, errorIndex, varBinds in objects:
        if errorIndication:
            ctx.out(f"Error: {errorIndication}", "ERROR",  indent=4)
            break
        elif errorStatus:
            ctx.out(f"Error: {errorStatus.prettyPrint()} at {errorIndex}", "ERROR",  indent=8)
            break
        else:
            for oid, value in varBinds:
                if ctx.oid_format:
                    oid = oid.prettyPrint()  # Convert OID to string
                value_type = value.__class__.__name__.upper()  # Get the value type
                value_str = value.prettyPrint()  # Convert value to string

                # Format the value type and content
                if value_type == "OCTET STRING":
                    value_output = f'STRING: "{value_str}"'
                elif value_type == "OBJECT-IDENTIFIER":
                    value_output = f'OID: {value}'
                elif value_type == "TIMETICKS":
                    value_output = f'Timeticks: ({value_str}) {format_timeticks(value)}'
                elif value_type == "INTEGER":
                    value_output = f'INTEGER: {value_str}'
                else:
                    value_output = value_str  # Default for other types

                # Construct the final formatted string
                formatted_output = f"{oid} = {value_output}"
                oids.update({str(oid): value_output})
                ctx.out(formatted_output, "TEXT",  indent=8)
            results = "success"

    if ctx.write_to_file and results:
        write_to_file(ctx.write_to_file, results)

    if results:
        node = ctx.ptjsonlib.create_node_object("snmpv3_walk_results", properties=oids)
        ctx.ptjsonlib.add_node(node)
        ctx.ptjsonlib.add_vulnerability("PTV-SNMP-V3-WALK")

    return results


def run(ctx):
    asyncio.run(getBulk_SNMPv3(ctx))