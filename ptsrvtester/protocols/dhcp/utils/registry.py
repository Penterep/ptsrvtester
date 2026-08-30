from enum import Enum, IntEnum
from dataclasses import dataclass
from typing import Optional
import re
import argparse
import netifaces as ni
from ptlibs.ptjsonlib import PtJsonLib

# DHCP dependencies
try:
    from dhcppython.utils import random_mac
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.l2 import Ether, arping, ARPingResult
    from scapy.layers.inet import IP, UDP
    from scapy.sendrecv import sendp, sniff
    DHCP_AVAILABLE = True
except ImportError:
    DHCP_AVAILABLE = False

#constants
MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
IPv4_TYPE = 0x0800
BROADCAST_FLAG = 0x8000
IP_BROADCAST = "255.255.255.255"
DISCOVER_FILTER = "udp and src port 68 and dst port 67 and ether dst ff:ff:ff:ff:ff:ff"
REQUEST_FILTER = "udp and src port 68 and dst port 67"

class VULNS(Enum):
    DHCP_DOS = "PTV-DHCP-DOS"
    DHCP_STARVATION = "PTV-DHCP-STARVATION"
    DHCP_ROGUE = "PTV-DHCP-ROGUE"

class DHCPTypes(IntEnum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8
    FORCE_RENEW = 9
    LEASE_QUERY = 10
    LEASE_UNASSIGNED = 11
    LEASE_UNKNOWN = 12
    LEASE_ACTIVE = 13

@dataclass
class TargetDHCP:
    i_name: str

def valid_interface(interface: str) -> TargetDHCP:
    return TargetDHCP(interface)

def is_valid_mac_address(mac_a: str) -> str:
    # Regular expression pattern for a MAC address
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'

    # Use re.match to check if the MAC address matches the pattern
    if re.match(pattern, mac_a):
        return mac_a
    else:
        raise argparse.ArgumentError(None, "Invalid MAC address")


def get_interface_ip(interface: str) -> str:
    return ni.ifaddresses(interface)[ni.AF_INET][0]['addr']


def is_valid_xid(xid: str) -> int:
    try:
        xid = int(xid)

        if not 0 <= xid <= 2**32-1:
            raise argparse.ArgumentError(None, "Invalid transaction ID")

        return xid
    except ValueError as e:
        raise argparse.ArgumentError(None, f"Cannot convert XID to int: {e}")


@dataclass
class DHCPResults:
    info: Optional[dict] = None
    starvation: Optional[dict] = None
    denial: Optional[dict] = None
    server: Optional[dict] = None


# Helper functions
def mac_remove_colons(mac: str):
    return mac.replace(":", "")


def random_xid():
    import random
    return random.randint(0, 2**32-1)


def prepare_bootp(src_mac, dst_mac, sport, dport, src_ip, dst_ip, transaction_id):
    eth = Ether(src=src_mac, dst=dst_mac, type=IPv4_TYPE)
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=sport, dport=dport)
    bootp = BOOTP(chaddr=bytes.fromhex(mac_remove_colons(src_mac)), xid=transaction_id)
    return eth / ip / udp / bootp


def prepare_discover_packet(src_mac, transaction_id):
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    return prepare_bootp(src_mac, MAC_BROADCAST, 68, 67, "0.0.0.0", IP_BROADCAST, transaction_id) / dhcp

def prepare_discover_packet_unicast(src_mac, dst_mac, src_ip, dst_ip, transaction_id):
    dhcp = DHCP(options=[("message-type", "discover"), "end"])
    return prepare_bootp(src_mac, dst_mac, 68, 67, src_ip, dst_ip, transaction_id) / dhcp

def get_gateway_mac(ip: str, interface: str) -> str|None:
    res = arping(ip, iface=interface, verbose=0)

    if res[0].res is None or len(res[0].res) == 0:
        return None

    query, answer = res[0].res[0]

    return answer[Ether].src

def is_valid_ip(ip: str) -> str:
    split_ip = [int(octet) for octet in ip.split('.')]

    if len(split_ip) != 4:
        raise argparse.ArgumentError(None, f"{ip} is not a valid IP address")

    if any([not 0 <= octet <= 255 for octet in split_ip]):
        raise argparse.ArgumentError(None, f"{ip} is not a valid IP address")

    return ip

def prepare_request_packet(src_mac, transaction_id, requested_ip):
    dhcp = DHCP(options=[("message-type", "request"), ("requested_addr", requested_ip), "end"])
    return prepare_bootp(src_mac, MAC_BROADCAST, 68, 67, "0.0.0.0", IP_BROADCAST, transaction_id) / dhcp


def prepare_offer_packet(src_mac, dst_mac, transaction_id, offered_ip, netmask, gateway, server_ip, lease, renew, rebind):
    dhcp = DHCP(options=[("message-type", "offer"),
                         ("requested_addr", offered_ip),
                         ("router", gateway),
                         ("subnet_mask", netmask),
                         ("server_id", server_ip),
                         ("lease_time", lease),
                         ("renewal_time", renew),
                         ("rebinding_time", rebind),
                         "end"])
    bootp = prepare_bootp(src_mac, MAC_BROADCAST, 67, 68, server_ip, IP_BROADCAST, transaction_id)
    bootp.getlayer(BOOTP).yiaddr = offered_ip
    bootp.getlayer(BOOTP).op = 2
    bootp.getlayer(BOOTP).flags = BROADCAST_FLAG
    bootp.getlayer(BOOTP).chaddr = bytes.fromhex(mac_remove_colons(dst_mac))
    return bootp / dhcp


def prepare_ack_packet(src_mac, dst_mac, transaction_id, offered_ip, netmask, gateway, server_ip, lease, renew, rebind):
    dhcp = DHCP(options=[("message-type", "ack"),
                         ("requested_addr", offered_ip),
                         ("router", gateway),
                         ("subnet_mask", netmask),
                         ("server_id", server_ip),
                         ("lease_time", lease),
                         ("renewal_time", renew),
                         ("rebinding_time", rebind),
                         "end"])
    bootp = prepare_bootp(src_mac, MAC_BROADCAST, 67, 68, server_ip, IP_BROADCAST, transaction_id)
    bootp.getlayer(BOOTP).yiaddr = offered_ip
    bootp.getlayer(BOOTP).op = 2
    bootp.getlayer(BOOTP).flags = BROADCAST_FLAG
    bootp.getlayer(BOOTP).chaddr = bytes.fromhex(mac_remove_colons(dst_mac))
    return bootp / dhcp

def prepare_nack_packet(src_mac, dst_mac, server_ip, transaction_id):
    dhcp = DHCP(options=[("message-type", "nak"),
                         ("server_id", server_ip),
                         "end"])
    bootp = prepare_bootp(src_mac, MAC_BROADCAST, 67, 68, server_ip, IP_BROADCAST, transaction_id)
    bootp.getlayer(BOOTP).yiaddr = "0.0.0.0"
    bootp.getlayer(BOOTP).op = 2
    bootp.getlayer(BOOTP).flags = BROADCAST_FLAG
    bootp.getlayer(BOOTP).chaddr = bytes.fromhex(mac_remove_colons(dst_mac))
    return bootp / dhcp

def check_lease(lease) -> bool:
    """Checks if lease duration is 30 days or more"""
    return int(lease) >= 2592000


def print_dhcp_options(ctx, options, base_indent) -> None:
    for o in range(1, len(options)):
        b_type = "INFO"
        if options[o] == "end":
            break
        option = options[o]
        if isinstance(option, tuple):
            key, *values = option
            value_str = ", ".join(str(v) for v in values)
        else:
            key, value_str = str(option), ""

        if key == "lease_time" and check_lease(value_str):
            b_type = "WARN"

        ctx.out(f"{key + ':':<24}{value_str}", b_type, indent=base_indent+4)


def get_option(options: list|None, search_term: str) -> str|None:
    """Returns the value of an option from the DHCP OFFER"""
    if options is None:
        return None

    for o in options:
        if isinstance(o, tuple):
            key, value = o
            if key == search_term:
                return value

    return None

def add_options_to_json(options: list|None):
    opt_dict = {}

    if options is None:
        return {}

    for o in range(1, len(options)):
        if options[o] == "end":
            break
        option = options[o]
        if isinstance(option, tuple):
            key, *values = option
            value_str = ", ".join(str(v) for v in values)
        else:
            key, value_str = str(option), ""

        opt_dict.update({key: value_str})

    return opt_dict