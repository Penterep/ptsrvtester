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
    v1: bool = False
    v2c: bool = False
    v3: bool = False

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
        v1 = True
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
        v2c = True
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
            v3 = True
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
        v3 = True
        for varBind in varBinds:
            ctx.out(
                " = ".join([x.prettyPrint() for x in varBind]),
                "TEXT",
                indent=4
            )

    if not any([v1, v2c, v3]):
        ctx.out("No SNMP version detected", "OK", indent=4)
        return SNMPVersion(v1, v2c, v3)

    v1_str = "v1" if v1 else ""
    v2c_str = "v2" if v2c else ""
    v3_str = "v3" if v3 else ""
    versions = [ver for ver in [v1_str, v2c_str, v3_str] if ver != ""]
    ctx.out(f"SNMP version found: {', '.join(versions)}", "INFO", indent=4)
    return SNMPVersion(v1, v2c, v3)


def run(ctx):
    asyncio.run(version_detection(ctx))
