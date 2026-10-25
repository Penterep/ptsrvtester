from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
import os
from ptsrvtester.protocols.snmp.utils.helpers import snmp_debug, write_to_file
from ptsrvtester.protocols.snmp.utils.registry import text_or_file
from ptsrvtester.protocols.snmp.modules.v2_write import test_snmpv2_write_access
from typing import List
from dataclasses import dataclass

__MODULELABEL__ = "SNMPv2 Community Access Brute Force Module"
__MODULECODE__ = "v2brute"
__ORDER__ = 100

@dataclass
class ValidCommunity:
    community: str
    read_access: bool
    read_poc: str
    write_access: bool
    write_poc: str

async def _snmpv2_brute(ctx: dict) -> List[str]:
    """
    Finds SNMPv2/1 communities with read or write access.

        Parameters:
       - ctx.single_community (str): A single community string for SNMPv2/1 authentication.
       - ctx.community_file (str): Path to a file containing a list of communities for the dictionary attack.
        - ctx.ip (str): The IP address of the target device.
       - ctx.port (int): The port number for SNMP communication.
       - ctx.output (bool): If True, writes valid credentials to a file.

        Returns:
       - A list of communities with read or write access.
    """

    if not ctx.single_community and not ctx.community_file:
        ctx.out("No community or wordlist provided. Using the default top-50 community wordlist.",
                "WARNING", indent=4)
        ctx.community_file = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "wordlists",
            "top50wordlist.txt",
        )

    communities = text_or_file(ctx.single_community, ctx.community_file)
    valid_communities = []

    for community in communities:
        obj_type = ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0))
        iterator = get_cmd(SnmpEngine(),
                            CommunityData(community),
                           await UdpTransportTarget.create((ctx.ip, ctx.port), timeout=0.25, retries=0),
                           # Initialize transport target correctly
                           ContextData(),
                           obj_type)
        errorIndication, errorStatus, errorIndex, varBinds = await iterator

        if not errorIndication and not errorStatus:
            read_res = ""
            for varBind in varBinds:
                read_res += " = ".join([x.prettyPrint() for x in varBind])

            snmp_debug(ctx, f"Response for community {community}: {read_res}", indent=4)
            has_write_access, write_var_binds = await test_snmpv2_write_access(ctx, community)

            oid = "1.3.6.1.2.1.1.5.0"  # SNMPv2-MIB::sysName.0
            value = str(ctx.value)

            write_req = f"{oid} = {value!r}"
            write_res = ""
            for varBind in write_var_binds:
                write_res += " = ".join([x.prettyPrint() for x in varBind])
            snmp_debug(
                ctx,
                f"Community {community} has {'write' if has_write_access else 'read-only'} access",
                indent=4,
            )
            valid_communities.append(ValidCommunity(read_access=True,
                                                    read_poc=f"Sent: get-request {obj_type}\r\nReceived: {read_res}",
                                                    write_access=has_write_access,
                                                    write_poc=f"Sent: set-request {write_req}\r\nReceived: {write_res}",
                                                    community=community)
                                                    )
        else:
            snmp_debug(ctx, f"Error: {errorIndication or errorStatus} for {community}", indent=4)

    if valid_communities:
        ctx.out("Valid communities:", "INFO", indent=4)
        for community in valid_communities:
            ctx.out(community.community, "INFO", indent=8)
            if community.read_access:
                ctx.out("Read access", "VULN", indent=12)
                ctx.ptjsonlib.add_vulnerability(
                    vuln_code="PTV-SVC-SNMP-BRUTE",
                    poc=f"Community: {community.community}\r\n{community.read_poc}",
                )
            if community.write_access:
                ctx.out("Write access", "VULN", indent=12)
                ctx.ptjsonlib.add_vulnerability(
                    vuln_code="PTV-SVC-SNMP-WRITE",
                    poc=f"Community: {community.community}\r\n{community.write_poc}",
                )
        if ctx.write_to_file:
            for community in valid_communities:
                write_to_file(ctx.write_to_file, community.community)

    else:
        ctx.out("No valid communities found", "OK", indent=4)

    return valid_communities


def run(ctx):
    asyncio.run(_snmpv2_brute(ctx))
