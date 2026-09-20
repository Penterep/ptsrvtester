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

    # TODO: add IPv6 support
    # TODO: add nmap scan to determine if port+ip combo resolve to NTP
    data = None
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # opens an IPv4 socket for UDP
    try:
        # NTP creates a packet which states it is a query (mode 3)
        sock.settimeout(5)
        sock.sendto(bytes(NTP(version=4, mode=3)), (ip, port))
        data, _ = sock.recvfrom(1024)  # server address and port are discarded
    except Exception as e:
        ctx.out(f"An error occured while trying to connect to server: {str(e)}", "ERROR", indent=4)
    finally:
        sock.close()
    
    if not data:
        return

    mode_6_scan_success = False
    fullver, processor, system_OS = "", "", ""
    nm = nmap.PortScanner()
    for i in range(2):
        try:
            # TODO: needs testing (couldn't find server with lower version than 4.2.0)
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
            break
        except:
            pass

    ntp = NTP(data)
    version = ntp.version if fullver == "" else fullver

    ctx.out(f"IP:                   {ip}", "INFO", indent=4)
    ctx.out(f"Port:                 {port}", "INFO", indent=4)
    ctx.out(f"Accepts mode 6:       {mode_6_scan_success}", "INFO", indent=4)
    ctx.out(f"NTP version:          {version}", "INFO", indent=4)

    if mode_6_scan_success:
        ctx.out(f"Server hostname:      {nm[ip].hostname() if nm[ip].hostname() != "" else "Unknown"}", "INFO", indent=4)
        ctx.out(f"Processor:            {processor}", "INFO", indent=4)
        ctx.out(f"System OS:            {system_OS}", "INFO", indent=4)

    ctx.out(f"Mode:                 {ntp.mode} ({mode_translate[ntp.mode]})", "INFO", indent=4)

    if ntp.leap == 3 and ntp.stratum == 0:
        ctx.out(f"Server sent a KoD (Kiss of Death) packet", "WARNING", indent=4)
        # return

    # TODO: fake or misconfigured servers can apparently return a weird combination of stratum and refID, try detecting that
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


    # ------- Vulnerabilites (will put into another module once problems are figured out) -------
    
    ctx.out(f"Possible vulnerabilities (temporarily in info)", "INFO", indent=0)
    
    # only 4.2.8p15 - CVE-2023-26551 to CVE-2023-26555 (DoS through errors in code)
    # from 0.3.0 to 0.3.2 - CVE-2023-33192 (DoS through crafted cookies)
    # up to (excluding) 4.2.7p26 - CVE-2013-5211 (traffic amplification through monolist)
    
    if not mode_6_scan_success:
        if ntp.version < 4:
            ctx.out(f"CVE-2013-5211", "VULN", indent=4)
        return
    
    parsed_ver = tuple(int(x) for x in fullver.replace("p", ".").split("."))
    error_DoS_ver = (4, 2, 8, 15)
    cookies_DoS_ver_min = (0, 3, 0)
    cookies_DoS_ver_max = (0, 3, 2)
    monolist_ver = (4, 2, 7, 26)
    
    if parsed_ver == error_DoS_ver:
        ctx.out(f"from CVE-2023-26551 to CVE-2023-26555", "VULN", indent=4)
    if cookies_DoS_ver_min <= parsed_ver <= cookies_DoS_ver_max:
        ctx.out(f"CVE-2023-33192", "VULN", indent=4)
    if parsed_ver < monolist_ver:
        ctx.out(f"CVE-2013-5211", "VULN", indent=4)
