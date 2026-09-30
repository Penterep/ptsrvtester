"""Sends packets to NTP server and tries to gather information about it
"""

import socket
import nmap
from scapy.layers.ntp import NTP
from .ntp_classes import NTPResults
from datetime import datetime, timezone, timedelta

# TODO: add IPv6 support

_NTP_EPOCH = datetime(1900, 1, 1, tzinfo=timezone.utc)

def ntp_to_utc(ts) -> str:
    return (_NTP_EPOCH + timedelta(seconds=float(ts))).strftime("%Y-%m-%d %H:%M:%S UTC")


def sec_to_readable(seconds: float) -> str:
    """Convert seconds to human-readable format (e.g., '2h 15m 30s 102ms')"""
    miliseconds: int = int((seconds - int(seconds))*1000)
    seconds = int(seconds)
    periods = [
        ("d", 86400),
        ("h", 3600),
        ("m", 60),
        ("s", 1)
    ]
    
    parts = []
    for name, count in periods:
        value = seconds // count
        if value != 0:
            seconds %= count
            parts.append(f"{value}{name}")

    if miliseconds != 0:
        parts.append(f"{miliseconds}ms")
    
    return " ".join(parts) if parts else "0s"


def get_ntp_time(server: str = "pool.ntp.org", port: int = 123, timeout: float = 2) -> float:
    """Query a public NTP server and return the timestamp."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(bytes(NTP(version=4, mode=3)), (server, port))
        data, _ = sock.recvfrom(1024)
        ntp_response = NTP(data)
        return ntp_response.sent  # transmit timestamp from server
    except Exception as e:
        raise ValueError(f"Failed to query {server}: {e}")
    finally:
        sock.close()

# TODO: Add variable timeout, retry count, maybe sleep between retries?
def gather_info(ip: str, port: int, results: NTPResults) -> None:
    results.has_ran = True
    data = None
    
    # ------------------------------------------ First test using regular mode 3 ------------------------------------------

    # Sending multiple requests is not ideal, but some servers reply only to repeats
    for _ in range(3):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # opens an IPv4 socket for UDP
        try:
            results.query_attempts += 1
            # NTP creates a packet which states it is a query (mode 3)
            sock.settimeout(3)
            sock.sendto(bytes(NTP(version=4, mode=3)), (ip, port))
            data, _ = sock.recvfrom(1024)  # server address and port are discarded
            break
        except Exception as e:
            results.error_info = str(e)
        finally:
            sock.close()

    if results.query_attempts == 3:
        results.error = True
    else:
        results.error_info = ""


    # -------------------------------------- nmap test to gather more info (mode 6) ---------------------------------------
    # TODO: version parsing needs testing (couldn't find server with lower version than 4.2.0)

    fullver, processor, system_os = "", "", ""
    nmap_worked = False
    nm = nmap.PortScanner()

    # Sending multiple requests is not ideal, but some servers reply only to repeats
    for _ in range(3):
        try:
            results.control_attempts += 1
            # Trying to get better version and system information in control mode (mode 6)
            nm.scan(ip, str(port), "-sU --script ntp-info", False, 3)
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


    # --------------------------------------------- Parsing data into results ---------------------------------------------

    ntp = NTP(data)
    
    results.kod_sent = ntp.leap == 3 and ntp.stratum == 0
    results.version = fullver if fullver != "" else ntp.version
    if nmap_worked:
        results.hostname = nm[ip].hostname() if nm[ip].hostname() != "" else "Unknown"
    else:
        results.hostname = "Unknown"
    results.processor = processor
    results.system_os = system_os
    results.mode = ntp.mode
    results.stratum = ntp.stratum

    if ntp.ref_id is None:
        results.ref_id = ""
    else:
        results.ref_id = ntp.ref_id.decode("ASCII", errors="replace").strip('\x00')

    results.leap = ntp.leap
    results.precision = ntp.precision
    results.ref_time = ntp.ref
    results.transmit_time = ntp.sent
