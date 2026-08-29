from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
from ptsrvtester.protocols.snmp.utils.helpers import write_to_file
from ptsrvtester.protocols.snmp.utils.registry import text_or_file
from typing import List

__MODULELABEL__ = "SNMPv2 Brute Force Module"
__MODULECODE__ = "v2_brute"
__ORDER__ = 100

async def _snmpv2_brute(ctx: dict) -> List[str]:
    """
    Performs a dictionary attack on SNMPv2/1 to find valid communities.

        Parameters:
       - ctx.single_community (str): A single community string for SNMPv2/1 authentication.
       - ctx.community_file (str): Path to a file containing a list of communities for the dictionary attack.
        - ctx.ip (str): The IP address of the target device.
       - ctx.port (int): The port number for SNMP communication.
       - ctx.output (bool): If True, writes valid credentials to a file.

        Returns:
       - list[Credential]: A list of valid communities found during the attack.
       - None: If no credentials are found or required inputs are missing.
    """

    if not ctx.community_file and not ctx.single_community:
        ctx.out("Error: Neither a community file nor a single community string was provided.", "WARNING",
                indent=4)
        return []
        
    communities = text_or_file(ctx.single_community, ctx.community_file)
    valid_communities = []

    for community in communities:
        iterator = get_cmd(SnmpEngine(),
                            CommunityData(community),
                           await UdpTransportTarget.create((ctx.ip, ctx.port), timeout=0.1),
                           # Initialize transport target correctly
                           ContextData(),
                           ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)))
        errorIndication, errorStatus, errorIndex, varBinds = await iterator

        if not errorIndication and not errorStatus:
            ctx.out(f"Valid community string found: {community}", "VULN", indent=4)
            valid_communities.append(community)
        else:
            ctx.out(f"Error: {errorIndication or errorStatus} for {community}", "ERROR", indent=4)

    if valid_communities:
        #self.ptprint("\n")
        ctx.out(f"Valid communities:", "INFO", indent=4)
        for community in valid_communities:
            ctx.out(community, "VULN", indent=8)
        if ctx.write_to_file:
            for community in valid_communities:
                write_to_file(ctx.write_to_file, community)

        node = ctx.ptjsonlib.create_node_object("valid_community_strings", properties={"valid": valid_communities})
        ctx.ptjsonlib.add_node(node)

    else:
        ctx.out("No valid communities found", "OK", indent=4)

    return valid_communities


def run(ctx):
    if not ctx.single_community and not ctx.community_file:
        ctx.out("Error: Neither a community file nor a single community string was provided.", "WARNING", indent=4)
        return
    
    asyncio.run(_snmpv2_brute(ctx))
