__MODULELABEL__ = "Information about server"
__MODULECODE__ = "INFO"
__ORDER__ = 10

import socket
import nmap
from datetime import datetime, timezone, timedelta
from scapy.layers.ntp import NTP

_NTP_EPOCH = datetime(1900, 1, 1, tzinfo=timezone.utc)

def _ntp_to_utc(ts) -> str:
    return (_NTP_EPOCH + timedelta(seconds=float(ts))).strftime("%Y-%m-%d %H:%M:%S UTC")


def run(ctx):
    mode_translate = {
        0: "Reserved",
        1: "Symmetric active",
        2: "Symmetric passive",
        3: "Client",
        4: "Server",
        5: "Broadcast",
        6: "Control",
        7: "Private",
    }

    ip, port = ctx.target
    # host = ctx.host

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # opens an IPv4 socket for UDP
    # TODO: add IPv6 support
    sock.settimeout(5)
    data = None
    
    # TODO: add nmap scan to determine if port+ip combo resolve to NTP

    try:
        # NTP creates a packet which states it is a query (mode 3)
        sock.sendto(bytes(NTP(version=4, mode=3)), (ip, port))
        data, _ = sock.recvfrom(1024)  # server address and port are discarded
    except Exception as e:
        ctx.out(f"An error occured while trying to connect to server: {str(e)}", "ERROR", indent=4)
    finally:
        sock.close()
    
    if not data:
        return

    mode_6_scan_success = False
    fullver, processor, system_OS, OS_ver = "", "", "", "" 
    nm = nmap.PortScanner()
    try:
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
        system_OS = nm_out[2][8:]
        mode_6_scan_success = True
    except:
        pass

    ntp = NTP(data)
    ctx.out(f"IP:                   {ip}", "INFO", indent=4)
    ctx.out(f"Port:                 {port}", "INFO", indent=4)
    ctx.out(f"Accepts mode 6:       {mode_6_scan_success}", "INFO", indent=4)

    if mode_6_scan_success:
        ctx.out(f"Server hostname:      {nm[ip].hostname() if nm[ip].hostname() != "" else "Unknown"}", "INFO", indent=4)
        ctx.out(f"NTP version:          {fullver}", "INFO", indent=4)
        ctx.out(f"Processor:            {processor}", "INFO", indent=4)
        ctx.out(f"System OS:            {system_OS}", "INFO", indent=4)
    else:
        ctx.out(f"NTP version:          {ntp.version}", ("INFO" if ntp.version >= 4 else "VULN"), indent=4)

    ctx.out(f"Mode:                 {ntp.mode} ({mode_translate[ntp.mode]})", "INFO", indent=4)
    

    if ntp.leap == 3 and ntp.stratum == 0:
        ctx.out(f"Server sent a KoD (Kiss of Death) packet", "WARNING", indent=4)
        return

    # fake or misconfigured servers can return a weird combination of stratum and refID
    # TODO: check if server is correctly configured or maliciously set up
    stratum_status = "Unsynchronized"
    if ntp.stratum == 0:
        stratum_status = "Invalid"
    elif ntp.stratum == 1:
        stratum_status = "Primary"
    elif ntp.stratum >= 2 and ntp.stratum < 16:
        stratum_status = "Secondary"
    ctx.out(f"Stratum:              {ntp.stratum} ({stratum_status})", "INFO", indent=4)

    ctx.out(f"Reference ID:         {ntp.id}", "INFO", indent=4)

    # leap could be potentially misconfigured or malfunctioning
    # TODO: check if leap seconds coincide with global events (very low priority)
    leap_status = "Unknown (unsynchronized)"
    if ntp.leap == 0:
        leap_status = "No warning"
    elif ntp.leap == 1:
        leap_status = "Last minute had 61s"
    elif ntp.leap == 2:
        leap_status = "Last minute had 59s"
    ctx.out(f"Leap indicator:       {ntp.leap} ({leap_status})", "INFO", indent=4)

    precision_sec = 2 ** int(ntp.precision)
    ctx.out(f"Precision:            2^{ntp.precision} = {precision_sec * 1e6:.3f} µs", "INFO", indent=4)
    ctx.out(f"Reference timestamp:  {_ntp_to_utc(ntp.ref)}", "INFO", indent=4)
    ctx.out(f"Transmit timestamp:   {_ntp_to_utc(ntp.sent)}", "INFO", indent=4)
