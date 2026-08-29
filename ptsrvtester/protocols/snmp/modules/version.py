__MODULELABEL__ = "SNMP Version Detection Module"
__MODULECODE__ = "version"
__ORDER__ = 100

from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp.proto.errind import RequestTimedOut
import asyncio
from ptsrvtester.protocols.snmp.utils.registry import SNMPVersion


async def version_detection(ctx: dict) -> SNMPVersion | None:
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
    versions = {
        "v1": False,
        "v2c": False,
        "v3": False
    }

    #v1: bool = False
    #v2c: bool = False
    #v3: bool = False

    ###########################################################################################
    # Detect v1                                                                               #
    ###########################################################################################
    iterator = await get_cmd(
        SnmpEngine(),
        CommunityData("public", mpModel=0),
        await UdpTransportTarget.create((ctx.ip, ctx.port)),
        ContextData(),
        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
    )

    errorIndication, errorStatus, errorIndex, varBinds = iterator

    if errorIndication:
        ctx.out(f"Error!: {errorIndication}", "ERROR", indent=4)
    elif errorStatus:
        ctx.out(
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            ),
            "ERROR",
            indent=4,
        )
    else:
        versions.update({"v1": True})
        for varBind in varBinds:
            ctx.out(
                f"Success!: {' = '.join([x.prettyPrint() for x in varBind])}",
                "OK",
                indent=4,
            )

    ###########################################################################################
    # Detect v2c                                                                              #
    ###########################################################################################
    iterator = await get_cmd(
        SnmpEngine(),
        CommunityData("public", mpModel=1),
        await UdpTransportTarget.create((ctx.ip, ctx.port)),
        ContextData(),
        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
    )

    errorIndication, errorStatus, errorIndex, varBinds = iterator

    if errorIndication:
        ctx.out(f"Error!: {errorIndication}", "ERROR", indent=4)
    elif errorStatus:
        ctx.out(f"Error!: {errorIndication}", "ERROR", indent=4)
        ctx.out(
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            ),
            "ERROR",
            indent=4,
        )
    else:
        versions.update({"v2c": True})
        for varBind in varBinds:
            ctx.out(
                f"Success!: {' = '.join([x.prettyPrint() for x in varBind])}",
                "OK",
                indent=4,
            )

    ###########################################################################################
    # Detect v3                                                                               #
    ###########################################################################################
    iterator = await get_cmd(
        SnmpEngine(),
        UsmUserData("pentest"),
        await UdpTransportTarget.create((ctx.ip, ctx.port)),
        ContextData(),
    )

    errorIndication, errorStatus, errorIndex, varBinds = iterator

    if errorIndication:
        if isinstance(errorIndication, RequestTimedOut):
            ctx.out(f"Error!: {errorIndication}", "ERROR", indent=4)
        else:
            ctx.out(f"Success!: {errorIndication}", "OK", indent=4)
            versions.update({"v3": True})
    elif errorStatus:
        ctx.out(
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            ),
            "ERROR",
            indent=4
        )
    else:
        versions.update({"v3": True})
        for varBind in varBinds:
            ctx.out(
                " = ".join([x.prettyPrint() for x in varBind]),
                "TEXT",
                indent=4
            )

    print(versions.values())
    if not any(versions.values()):
        ctx.out("No SNMP version detected", "OK", indent=4)
        return SNMPVersion(**versions)


    version_strings = [ver for ver, present in versions.items() if present]
    ctx.out(f"SNMP version found: {', '.join(version_strings)}", "INFO", indent=4)
    node = ctx.ptjsonlib.create_node_object("snmp_version", properties=versions)
    ctx.ptjsonlib.add_node(node)
    return SNMPVersion(**versions)


def run(ctx):
    asyncio.run(version_detection(ctx))
