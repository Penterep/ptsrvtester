from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
from ptsrvtester.protocols.snmp.utils.helpers import write_to_file
from ptsrvtester.protocols.snmp.utils.registry import text_or_file

__MODULELABEL__ = "SNMPv3 User Enumeration Test"
__MODULECODE__ = "v3enum"
__ORDER__ = 100


async def user_enum(ctx) -> list[str]:
    # Users from input
    users: list[str] = text_or_file(ctx.single_username, ctx.username_file)

    # self.drawDoubleLine()
    # self.ctx.out("Starting username enumeration...", title=True)
    # self.drawDoubleLine()
    valid_usernames = set()
    potentially_valid_usernames = set()

    for username in users:
        try:
            user_data = UsmUserData(username, "userenumeration", authProtocol=None, privProtocol=None)
            probe = ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0))
            ctx.debug(f"SNMPv3 username enumeration for {username!r}", indent=4)
            ctx.debug(f"Sent: {probe}", indent=8)
            iterator = get_cmd(
                SnmpEngine(),
                user_data,
                await UdpTransportTarget.create((ctx.ip, ctx.port)),
                ContextData(),
                probe,
            )
            errorIndication, errorStatus, errorIndex, varBinds = await iterator
            received = errorIndication or (
                f"{errorStatus.prettyPrint()} at {errorIndex}" if errorStatus else
                ", ".join(" = ".join(part.prettyPrint() for part in varBind) for varBind in varBinds)
            )
            ctx.debug(f"Received: {received}", indent=8)

            if not errorIndication and not errorStatus:
                ctx.out(f"Valid username found: {username}", "VULN",  indent=4)
                valid_usernames.add(username)
            elif "Wrong SNMP PDU digest" in str(errorIndication):
                ctx.out(f"Potential valid username: {username}", "WARNING",  indent=4)
                potentially_valid_usernames.add(username)
            else:

                ctx.out(f"Error for username {username}: {errorIndication or errorStatus}", "ERROR",
                         indent=4)

        except Exception as e:
            ctx.out(f"Error for username {username}: {e}", "ERROR",  indent=4)

    user_dict = {}

    if valid_usernames:
        # self.ctx.out("\n")
        user_dict.update({"valid_usernames": list(valid_usernames)})
        ctx.out(f"Valid usernames:", "INFO",
                indent=4)
        for username in valid_usernames:
            ctx.out(username, "VULN",  indent=8)
        if ctx.write_to_file:
            for username in valid_usernames:
                write_to_file(ctx.write_to_file, username)

    elif potentially_valid_usernames:
        ctx.out(f"Potentially valid usernames:", "INFO",
                indent=4)
        for username in potentially_valid_usernames:
            ctx.out(username, "VULN",  indent=8)
        if ctx.write_to_file:
            for username in potentially_valid_usernames:
                write_to_file(ctx.write_to_file, username)
        user_dict.update({"potentially_valid_usernames": list(potentially_valid_usernames)})

    else:
        ctx.out("No valid usernames found", "OK",  indent=4)

    if valid_usernames or potentially_valid_usernames:
        node = ctx.ptjsonlib.create_node_object("snmpv3_users", properties=user_dict)
        ctx.ptjsonlib.add_node(node)

    return list(valid_usernames)

def run(ctx):
    asyncio.run(user_enum(ctx))