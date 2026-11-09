import time
from ptsrvtester.protocols.dhcp.utils.registry import (
    random_xid,
    random_mac,
    sendp,
    prepare_discover_packet,
    DHCP,
    BOOTP,
    prepare_discover_packet_unicast,
    get_gateway_mac,
    get_interface_ip,
    get_interface_mac,
    print_dhcp_options,
    get_option,
    debug_packet
)

from scapy.sendrecv import AsyncSniffer
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.all import PacketList


__MODULELABEL__ = "DHCP server information enumeration"
__MODULECODE__ = "info"
__ORDER__ = 100



def _check_broadcast(res: PacketList) -> str:
    if res is None or len(res) == 0:
        return ""
    
    for pkt in res:
        if pkt.haslayer(BOOTP) and pkt[BOOTP].op == 2  and \
            pkt.haslayer(DHCP) and _is_packet_broadcast(pkt) == "UNICAST":
            return pkt[Ether].dst

    return ""

def _is_packet_broadcast(pkt) -> str:
    if pkt.haslayer(BOOTP) and pkt[BOOTP].op == 2:
        eth_dst = pkt[Ether].dst
        ip_dst = pkt[IP].dst
        if eth_dst == "ff:ff:ff:ff:ff:ff":
            return "BROADCAST"
        else:
            return "UNICAST"
    
    return ""
        

def to_int(s):
    a, b, c, d = map(int, s.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d

def same_network(ip1, ip2, mask):
    m = to_int(mask)
    return (to_int(ip1) & m) == (to_int(ip2) & m)

def _is_relay(server_id: str|None, src_ip: str, giaddr: str|None, offered_ip: str|None, subnet_mask: str):
    """Checks if the offered IP address is on the same network as the DHCP server"""
    if server_id is None or giaddr is None:
        return False

    if src_ip != server_id or giaddr != "0.0.0.0" or not same_network(server_id, offered_ip, subnet_mask):
        return True
    
    return False


def _contact_server(ctx, src_mac: str, router_ip: str, server_ip, xid):
    gw_mac = get_gateway_mac(router_ip, ctx.interface)
    if_ip = get_interface_ip(ctx.interface)
    offer_filter = "udp and src port 67"

    if gw_mac is None:
        ctx.out(f"Failed fetching MAC address of gateway", "ERROR", indent=20)
        return
    try:
        def is_offer_packet(packet):
            if packet.haslayer(DHCP) and packet.haslayer(UDP) and packet[UDP].sport == 67:
                debug_packet(ctx, "Received", packet)
                print_dhcp_options(ctx, packet[DHCP].options, 8)
                return True

            return False

        sniffer = AsyncSniffer(
            iface=ctx.interface,
            filter=offer_filter,
            promisc=True,
            stop_filter=is_offer_packet,
            timeout=ctx.timeout
        ) # Use async sniffer to prevent race conditions

        sniffer.start()
        time.sleep(0.05)

        discover = prepare_discover_packet_unicast(src_mac, gw_mac, if_ip, server_ip, xid)
        debug_packet(ctx, "Sent", discover)
        sendp(discover, iface=ctx.interface, verbose=False)

        sniffer.join()
        res = sniffer.results

        if res is None or len(res) == 0:
            ctx.out("Could not contact the DHCP server", "OK", indent=20)

    except Exception as e:
        ctx.out(f"Error sending DHCP discover to server on a different subnet: {e}", "ERROR", indent=12)


def _get_server_info(ctx, src_mac: str, broadcast=False):
    """Retrieve DHCP server information"""

    transaction_id = ctx.xid or random_xid()
    offer_filter = f"udp and src port 67 and (ether dst ff:ff:ff:ff:ff:ff or ether dst {src_mac})"

    try:
        def is_offer_packet(packet):
            if packet.haslayer(DHCP):
                debug_packet(ctx, "Received", packet)
                offered_ip = packet[BOOTP].yiaddr if packet.haslayer(BOOTP) else None
                options = packet[DHCP].options
                delivery_method = _is_packet_broadcast(packet)
                options.insert(1, ("delivery_method", delivery_method))
                options.insert(2, ("offered_ip", offered_ip))
                
                b_type = "INFO"
                if delivery_method == "BROADCAST" and not broadcast:
                    b_type = "VULN"
                    ctx.ptjsonlib.add_vulnerability(vuln_code="PTV-SVC-DHCP-RELAY", 
                                                    poc=f"The broadcast flag was not set and the destination MAC was: ff:ff:ff:ff:ff:ff\r\n")
                    
                
                ctx.out(f"DHCP offer received DHCP Server Information:", b_type, indent=8)
                print_dhcp_options(ctx, options, 8)
                
                if server_ip := get_option(options, "server_id"):   # Check if the server is a relay
                    if _is_relay(server_ip, packet[IP].src, get_option(options, "giaddr"), offered_ip, get_option(options, "subnet_mask")):
                        ctx.out(f"DHCP relay detected", "WARNING", indent=16)
                        ctx.ptjsonlib.add_vulnerability(vuln_code="PTV-SVC-DHCP-RELAY", poc=f"Offered IP {offered_ip} in not on the server network {server_ip}")
                        _contact_server(ctx, src_mac, get_option(options, "router"),
                                        get_option(options, "server_id"), transaction_id)
                
                return True

            return False

        sniffer = AsyncSniffer(
            iface=ctx.interface,
            filter=offer_filter,
            promisc=True,
            stop_filter=is_offer_packet,
            timeout=ctx.timeout
        )  # Use async sniffer to prevent race conditions

        sniffer.start()
        time.sleep(0.05)

        discover = prepare_discover_packet(src_mac, transaction_id, broadcast=broadcast)
        debug_packet(ctx, "Sent", discover)
        sendp(discover, ctx.interface, verbose=False)

        sniffer.join()
        res = sniffer.results or []

        if len(res) == 0:
            ctx.out("No DHCP server information accessible", "OK", indent=8)
        return res

    except Exception as e:
        ctx.out(f"Error retrieving DHCP information: {str(e)}", "ERROR", indent=8)


def run(ctx):
    fake_mac = ctx.mac or random_mac()
    real_iface_mac = get_interface_mac(ctx.interface)

    ctx.out(f"Trying to contact DHCP server using the real MAC address", "INFO", indent=4)
    res = _get_server_info(ctx, real_iface_mac)

    ctx.out(f"Trying to contact DHCP server using the fake/provided MAC address", "INFO", indent=4)
    res.append(_get_server_info(ctx, fake_mac))
    
    if mac := _check_broadcast(res):
        ctx.out(f"Trying to contact DHCP server using the fake/provided MAC address and broadcast flag set", "INFO", indent=4)
        _get_server_info(ctx, mac, True)
    else:
        ctx.ptjsonlib.add_vulnerability(vuln_code="PTV-SVC-DHCP-BROADC")