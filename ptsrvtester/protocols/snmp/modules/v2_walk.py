from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
from ptsrvtester.protocols.snmp.utils.helpers import write_to_file, format_timeticks
from ptsrvtester.protocols.snmp.utils.registry import text_or_file

__MODULELABEL__ = "SNMPv2 Walk"
__MODULECODE__ = "v2_walk"
__ORDER__ = 100


async def _getBulk_SNMPv2(ctx) -> str:
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

    if not ctx.community_file and not ctx.single_community:
        ctx.out("Neither a community file nor a single community string was provided. Defaulting to 'public'.",
                "WARNING", indent=4)
        ctx.single_community = "public"

    communities = text_or_file(ctx.single_community, ctx.community_file)

    # self.drawDoubleLine()
    # self.ctx.out("Starting SNMPv2 bulk walk...", title=True)
    # self.drawDoubleLine()
    results = []
    # for json
    result = None

    for community in communities:
        ctx.out(f"Trying community: {community}", "INFO", indent=4)
        try:
            # Use walk_cmd to traverse the MIB
            objects = walk_cmd(
                SnmpEngine(),
                CommunityData(community),
                await UdpTransportTarget.create((ctx.ip, ctx.port)),
                ContextData(),
                ObjectType(ObjectIdentity(ctx.oid))
            )

            # Iterate over the returned OID-value pairs
            async for errorIndication, errorStatus, errorIndex, varBinds in objects:
                if errorIndication:
                    ctx.out(f"Error: {errorIndication}", "ERROR", indent=8)
                    break
                elif errorStatus:
                    ctx.out(f"Error: {errorStatus.prettyPrint()} at {errorIndex}", "ERROR",
                            indent=8)
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
                        elif value_type == "OBJECT IDENTIFIER":
                            value_output = f'OID: {value}'
                        elif value_type == "TIMETICKS":
                            value_output = f'Timeticks: ({value_str}) {format_timeticks(value)}'
                        elif value_type == "INTEGER":
                            value_output = f'INTEGER: {value_str}'
                        else:
                            value_output = value_str  # Default for other types

                        # Construct the final formatted string
                        formatted_output = f"{oid} = {value_output}"
                        ctx.out(formatted_output, "TEXT", indent=8)
                        results.append(formatted_output)

            # Stop the loop if results are found
            if results:
                ctx.out(f"Results found with community '{community}', stopping further attempts.", "VULN",
                        indent=8)
                result = "success"
                break


        except Exception as e:
            ctx.out(f"Exception occurred for community '{community}': {e}", "ERROR", indent=8)
            continue  # Move to the next community in case of errors
    if ctx.write_to_file:
        write_to_file(ctx.write_to_file, results)
    return result


def run(ctx):
    if not ctx.single_community and not ctx.community_file:
        ctx.out("Error: Neither a community file nor a single community string was provided.", "WARNING", indent=4)
        return

    asyncio.run(_getBulk_SNMPv2(ctx))
