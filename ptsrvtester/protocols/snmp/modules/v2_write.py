from venv import create

from ptsrvtester.protocols.snmp.utils.registry import text_or_file, WriteTestResult
from pysnmp.hlapi.v3arch.asyncio import *
import asyncio

__MODULELABEL__ = "SNMPv2 Write Permission Test"
__MODULECODE__ = "v2_write"
__ORDER__ = 100


async def test_snmpv2_write_permission(ctx) -> list[WriteTestResult]:
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
    if not ctx.community_file and not ctx.single_community:
        ctx.out("Error: Neither a community file nor a single community string was provided.", "ERROR",
                indent=4)
        return results

    communities = text_or_file(ctx.single_community, ctx.community_file)
    # self.drawDoubleLine()
    # self.ctx.out("Starting SNMPv2 write permission test...", title=True)
    # self.drawDoubleLine()

    for community in communities:
        try:
            ctx.out(f"Testing write permission for community string: {community}", "INFO", 
                    indent=4)
            iterator = set_cmd(
                SnmpEngine(),
                CommunityData(community),
                await UdpTransportTarget.create((ctx.ip, ctx.port)),
                ContextData(),
                ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0), OctetString(ctx.value))
            )

            errorIndication, errorStatus, errorIndex, varBinds = await iterator

            if not errorIndication and not errorStatus:
                ctx.out("Write was successful!", "VULN", indent=8)
                for varBind in varBinds:
                    ctx.out(f"OID: {varBind[0]} was set to {varBind[1]}", "INFO", indent=8)
                    ctx.out(
                        f"Note: Attribute was modified for testing purposes. Don't forget to revert it back if necessary.",
                        "INFO", indent=8)
                    results.append(WriteTestResult(
                        OID=str(varBind[0]),
                        creds=f"{community}",
                        value=str(varBind[1])
                    ))
            else:
                ctx.out(f"Write failed: {errorIndication or errorStatus}", "OK", indent=8)

        except Exception as e:
            ctx.out(f"Exception occurred: {e}", "ERROR", indent=8)

    if results:
        json_results = [{"OID": res.OID, "creds": res.creds, "value": res.value} for res in results]
        node = ctx.ptjsonlib.create_node_object("snmpv2_write_test_results", properties={"results": json_results})
        ctx.ptjsonlib.add_node(node)
        ctx.ptjsonlib.add_vulnerability("PTV-SNMP-V2-WRITE-ACCESS")

    return results

def run(ctx):
    asyncio.run(test_snmpv2_write_permission(ctx))