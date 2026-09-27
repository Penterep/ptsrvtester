import time
from ptsrvtester.protocols.dhcp.utils.registry import (
    random_xid,
    random_mac,
    sendp,
    prepare_ack_packet,
)

from icmplib import ping

__MODULELABEL__ = "MAC spoofer"
__MODULECODE__ = "mac_spoofer"
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


def _spoof_mac(ctx):
    """Send a spoofed DHCP ACK to a client to try and change his IP"""
    src_mac = ctx.mac or random_mac()
    transaction_id = ctx.xid or random_xid()




def run(ctx):
    _spoof_mac(ctx)