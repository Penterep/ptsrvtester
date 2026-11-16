import asyncio

from pysnmp.hlapi.v3arch.asyncio import *

from ptsrvtester.protocols.snmp.utils.helpers import format_timeticks, snmp_debug, write_to_file
from ptsrvtester.protocols.snmp.utils.registry import text_or_file

__MODULELABEL__ = "SNMPv1 Walk"
__MODULECODE__ = "V1WALK"
__ORDER__ = 100


async def getBulk_SNMPv1(ctx) -> str | None:
    """Walk the target MIB using SNMPv1 and the supplied community string(s)."""
    if not ctx.community_file and not ctx.single_community:
        ctx.out(
            "Neither a community file nor a single community string was provided.",
            "ERROR",
            indent=4,
        )
        return None

    communities = text_or_file(ctx.single_community, ctx.community_file)
    results = []
    result = None

    for community in communities:
        ctx.out(f"Trying community: {community}", "INFO", indent=4)
        try:
            probe = ObjectType(ObjectIdentity(ctx.oid))
            snmp_debug(ctx, f"Sent: walk starting at OID {ctx.oid}", indent=8)
            objects = walk_cmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0),
                await UdpTransportTarget.create((ctx.ip, ctx.port)),
                ContextData(),
                probe,
            )

            async for error_indication, error_status, error_index, var_binds in objects:
                added_to_json = False
                received = error_indication or (
                    f"{error_status.prettyPrint()} at {error_index}"
                    if error_status
                    else ", ".join(
                        " = ".join(part.prettyPrint() for part in var_bind)
                        for var_bind in var_binds
                    )
                )
                snmp_debug(ctx, f"Received: {received}", indent=8)
                if error_indication:
                    ctx.out(f"Error: {error_indication}", "ERROR", indent=8)
                    break
                if error_status:
                    ctx.out(
                        f"Error: {error_status.prettyPrint()} at {error_index}",
                        "ERROR",
                        indent=8,
                    )
                    break

                for oid, value in var_binds:
                    if ctx.oid_format:
                        oid = oid.prettyPrint()
                    value_type = value.__class__.__name__.upper().replace("-", "")
                    value_str = value.prettyPrint()

                    if value_type == "OCTETSTRING":
                        value_output = f'STRING: "{value_str}"'
                    elif value_type == "OBJECTIDENTIFIER":
                        value_output = f"OID: {value}"
                    elif value_type == "TIMETICKS":
                        value_output = f"Timeticks: ({value_str}) {format_timeticks(value)}"
                    elif value_type in {"INTEGER", "INTEGER32"}:
                        value_output = f"INTEGER: {value_str}"
                    else:
                        value_output = value_str

                    if not added_to_json:
                        poc = f"Sent: get-request {oid}\r\nReceived: {value_output}"
                        ctx.ptjsonlib.add_vulnerability(
                            vuln_code="PTV-SVC-SNMP-WALK", poc=poc
                        )
                        added_to_json = True


                    formatted_output = f"{oid} = {value_output}"
                    ctx.out(formatted_output, "TEXT", indent=8)
                    results.append(formatted_output)

            if results:
                ctx.out(
                    f"Results found with community '{community}', stopping further attempts.",
                    "VULN",
                    indent=8,
                )
                result = "success"
                break
        except Exception as error:
            ctx.out(
                f"Exception occurred for community '{community}': {error}",
                "ERROR",
                indent=8,
            )

    if ctx.write_to_file:
        write_to_file(ctx.write_to_file, results)
    return result


def run(ctx):
    asyncio.run(getBulk_SNMPv1(ctx))
