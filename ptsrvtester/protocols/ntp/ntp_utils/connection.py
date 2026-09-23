"""Sends packets to NTP server and tries to gather information about it
"""

import socket
import nmap
from scapy.layers.ntp import NTP
from dataclasses import dataclass
from .ntp_classes import NTPResults

# TODO: add IPv6 support
# TODO: add nmap scan to determine if port+ip combo resolve to NTP

def gather_info(ip: str, port: int) -> NTPResults:
    data = None
    results = NTPResults()
    
    # ----------------- First test using regular mode 3 -----------------
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # opens an IPv4 socket for UDP
    try:
        # NTP creates a packet which states it is a query (mode 3)
        sock.settimeout(5)
        sock.sendto(bytes(NTP(version=4, mode=3)), (ip, port))
        data, _ = sock.recvfrom(1024)  # server address and port are discarded
    except Exception as e:
        results.error = True
        results.error_info = str(e)
    finally:
        sock.close()
    
    if results.error:
        return

    # -------------- nmap test to gather more info (mode 6) --------------

    fullver, processor, system_os = "", "", ""
    nm = nmap.PortScanner()
    # first nmap scan sometimes fails, maybe not necessary but seems to help
    for _ in range(2):
        try:
            # TODO: version parsing needs testing (couldn't find server with lower version than 4.2.0)
            # Trying to get better version and system information (mode 6)
            nm.scan(ip, str(port), "-sU --script ntp-info", False, 6)
            nm_out = str(nm[ip]['udp'][port]['script']['ntp-info']).split("\n  ")[2:]

            # string before -o in ver is the upstream revision identity,
            # it's not necessary for vuln evaluation
            fullver = nm_out[0][14:].split(" ")[0]
            if fullver[-2:] == "-o":
                fullver = fullver.split("@")[0]
            else:
                fullver = fullver[:-2]
            processor = nm_out[1][11:]
            system_os = nm_out[2][8:]
            results.accepts_mode_6 = True
            break
        except:
            pass

    # --------------------- Data parsing into results ---------------------

    ntp = NTP(data)
    
    results.kod_sent = ntp.leap == 3 and ntp.stratum == 0
    results.version = fullver if fullver != "" else ntp.version
    results.hostname = nm[ip].hostname() if nm[ip].hostname() != "" else "Unknown"
    results.processor = processor
    results.system_os = system_os
    results.mode = ntp.mode
    results.stratum = ntp.stratum
    results.ref_id = ntp.id
    results.leap = ntp.leap
    results.precision = ntp.precision
    results.ref_time = ntp.ref
    results.transmit_time = ntp.sent
    
    return results
