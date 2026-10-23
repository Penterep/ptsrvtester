__MODULELABEL__ = "SNMP Version Detection Module"
__MODULECODE__ = "version"
__ORDER__ = 100

from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp.proto.errind import RequestTimedOut
import asyncio
from ptsrvtester.protocols.snmp.utils.registry import SNMPVersion
from ptsrvtester.protocols.snmp.utils.helpers import snmp_debug


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

    poc = {}

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
        ctx.out(f"SNMPv1 (Not supported)", "INFO", indent=4)
        snmp_debug(ctx, f"SNMPv1 detection error", indent=4)
        snmp_debug(ctx, f"Sent: {obj_type}", indent=8)
        snmp_debug(ctx, f"Received: {errorIndication}", indent=8)
    elif errorStatus:
        ctx.out(f"SNMPv1 (Not supported)", "INFO", indent=4)
        snmp_debug(ctx, "SNMPv1 detection error", indent=4)
        snmp_debug(ctx, f"Sent: {obj_type}", indent=8)
        snmp_debug(ctx, f"Received: {errorStatus.prettyPrint()}", indent=8)
        snmp_debug(
            ctx,
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            ),
            indent=8,
        )
    else:
        versions.update({"v1": True})
        res = ""
        snmp_debug(ctx, f"SNMPv1 detection success", indent=4)
        ctx.out(f"SNMPv1 (Supported)", "VULN", indent=4)
        
        for varBind in varBinds:
            res += ' = '.join([x.prettyPrint() for x in varBind])
        
        poc.update({"v1": {"sent": str(obj_type), "received": res}})
        
        snmp_debug(ctx, f"Sent: {obj_type}", indent=8)
        snmp_debug(ctx, f"Received: {res}", indent=8)

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
        ctx.out(f"SNMPv2c (Not supported)", "INFO", indent=4)
        snmp_debug(ctx, f"SNMPv2c detection error", indent=4)
        snmp_debug(ctx, f"Sent: {obj_type}", indent=8)
        snmp_debug(ctx, f"Received: {errorIndication}", indent=8)
    elif errorStatus:
        ctx.out(f"SNMPv2c (Not supported)", "INFO", indent=4)
        snmp_debug(ctx, f"SNMPv2c detection error", indent=4)
        snmp_debug(ctx, f"Sent: {obj_type}", indent=8)
        snmp_debug(ctx, f"Received: {errorStatus.prettyPrint()}", indent=8)
        snmp_debug(ctx, f"SNMPv2c detection error: {errorStatus.prettyPrint()}", indent=4)
        snmp_debug(
            ctx,
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            ),
            indent=8,
        )
    else:
        versions.update({"v2c": True})
        res = ""
        ctx.out(f"SNMPv2c (Supported)", "VULN", indent=4)
        snmp_debug(ctx, f"SNMPv2c detection success", indent=4)
        for varBind in varBinds:
            res += ' = '.join([x.prettyPrint() for x in varBind])
        poc.update({"v2c": {"sent": str(obj_type), "received": res}})
        snmp_debug(ctx, f"Sent: {obj_type}", indent=8)
        snmp_debug(ctx, f"Received: {res}", indent=8)

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
            ctx.out(f"SNMPv3 (Not supported)", "INFO", indent=4)
            snmp_debug(ctx, f"SNMPv3 detection error", indent=4)
            snmp_debug(ctx, f"Sent: {sent}", indent=8)
            snmp_debug(ctx, f"Received: {errorIndication}", indent=8)
        else:
            ctx.out(f"SNMPv3 (Supported)", "OK", indent=4)
            snmp_debug(ctx, f"SNMPv3 detection success", indent=4)
            snmp_debug(ctx, f"Sent: {sent}", indent=8)
            snmp_debug(ctx, f"Received: {errorIndication}", indent=8)
            versions.update({"v3": True})
    elif errorStatus:
        ctx.out(f"SNMPv3 (Not supported)", "INFO", indent=4)
        snmp_debug(ctx, f"SNMPv3 detection error", indent=4)
        snmp_debug(ctx, f"Sent: {sent}", indent=8)
        snmp_debug(ctx, f"Received: {errorStatus.prettyPrint()}", indent=8)
        snmp_debug(
            ctx,
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            ),
            indent=8
        )
    else:
        ctx.out(f"SNMPv3 (Supported)", "OK", indent=4)
        versions.update({"v3": True})
        snmp_debug(
            ctx, f"SNMPv3 detection success", indent=4)
        snmp_debug(ctx, f"Sent: {sent}", indent=8)
        res = ""
        for varBind in varBinds:
            res += " = ".join([x.prettyPrint() for x in varBind])
        snmp_debug(ctx, f"Received: {res}", indent=8)

    if not any(versions.values()):
        ctx.out("No SNMP version detected", "OK", indent=4)
        return SNMPVersion(**versions)

    ctx.ptjsonlib.add_vulnerability(vuln_code="PTV-SVC-SNMP-OLDVER", poc=poc)

    return SNMPVersion(**versions)


def run(ctx):
    asyncio.run(version_detection(ctx))
