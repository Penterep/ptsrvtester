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
    obj_type = ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0))
    iterator = await get_cmd(
        SnmpEngine(),
        CommunityData("public", mpModel=0),
        await UdpTransportTarget.create((ctx.ip, ctx.port)),
        ContextData(),
        obj_type,
    )

    errorIndication, errorStatus, errorIndex, varBinds = iterator

    if errorIndication:
        ctx.debug(f"SNMPv1 detection error", indent=4)
        ctx.debug(f"Sent: {obj_type}", indent=8)
        ctx.debug(f"Received: {errorIndication}", indent=8)
    elif errorStatus:
        ctx.debug(
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            ),
            indent=8,
        )
    else:
        versions.update({"v1": True})
        res = ""
        ctx.debug(f"SNMPv1 detection success", indent=4)
        
        for varBind in varBinds:
            res += ' = '.join([x.prettyPrint() for x in varBind])
            
        ctx.debug(f"Sent: {obj_type}", indent=8)
        ctx.debug(f"Received: {res}", indent=8)

    ###########################################################################################
    # Detect v2c                                                                              #
    ###########################################################################################
    obj_type = ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0))
    iterator = await get_cmd(
        SnmpEngine(),
        CommunityData("public", mpModel=1),
        await UdpTransportTarget.create((ctx.ip, ctx.port)),
        ContextData(),
        obj_type,
    )

    errorIndication, errorStatus, errorIndex, varBinds = iterator

    if errorIndication:
        ctx.debug(f"SNMPv2c detection error", indent=4)
        ctx.debug(f"Sent: {obj_type}", indent=8)
        ctx.debug(f"Received: {errorIndication}", indent=8)
    elif errorStatus:
        ctx.debug(f"SNMPv2c detection error: {errorIndication}", indent=4)
        ctx.debug(
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            ),
            indent=8,
        )
    else:
        versions.update({"v2c": True})
        res = ""
        ctx.debug(f"SNMPv1 detection success", indent=4)
        for varBind in varBinds:
            res += ' = '.join([x.prettyPrint() for x in varBind])
            
        ctx.debug(f"Sent: {obj_type}", indent=8)
        ctx.debug(f"Received: {res}", indent=8)

    ###########################################################################################
    # Detect v3                                                                               #
    ###########################################################################################
    sent = UsmUserData("pentest")
    iterator = await get_cmd(
        SnmpEngine(),
        sent,
        await UdpTransportTarget.create((ctx.ip, ctx.port)),
        ContextData(),
    )

    errorIndication, errorStatus, errorIndex, varBinds = iterator

    if errorIndication:
        if isinstance(errorIndication, RequestTimedOut):
            ctx.debug(f"SNMPv3 detection error", indent=4)
            ctx.debug(f"Sent: {sent}", indent=8)
            ctx.debug(f"Received: {errorIndication}", indent=8)
        else:
            ctx.debug(f"SNMPv3 detection success", indent=4)
            ctx.debug(f"Sent: {sent}", indent=8)
            ctx.debug(f"Received: {errorIndication}", indent=8)
            versions.update({"v3": True})
    elif errorStatus:
        ctx.debug(
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            ),
            indent=8
        )
    else:
        versions.update({"v3": True})
        for varBind in varBinds:
            ctx.debug(
                " = ".join([x.prettyPrint() for x in varBind]),
                indent=8
            )

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
