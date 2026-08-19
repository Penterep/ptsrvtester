"""TEMPLATE — copy this file to modules/<yourmodule>.py to add a module.

The generic main (main.py) discovers every ``modules/*.py`` that is NOT
prefixed with ``_`` and exposes a callable ``run(ctx)``. This file starts with
``_`` on purpose, so it is documentation only and is never executed.

Required / optional module-level attributes
--------------------------------------------
    __MODULELABEL__  (str, required)  one-line label; the main prints it as the
                                    section header before your run() executes.
    __MODULECODE__   (str, optional)  the -ts code; defaults to FILENAME.upper().
    __ORDER__      (int, optional)  run/print order; smaller runs first (default 100).

The run(ctx) entry point
------------------------
``ctx`` carries everything you need — you do NOT manage threads, output ordering
or the section header yourself:

    ctx.args        parsed CLI args (SMTPArgs) — all -m/-r/--tls/... options
    ctx.target      (ip, port) tuple, already resolved
    ctx.ptjsonlib   shared PtJsonLib — add structured results for JSON mode
    ctx.print_lock  this module's output buffer (advanced use)
    ctx.out(text, category="TEXT", colortext=False, indent=0)
                    buffer a line; categories: TEXT/INFO/OK/VULN/NOTVULN/
                    WARNING/ERROR/TITLE/ADDITIONS (text mode only)
    ctx.debug(text) buffer a line shown only with -vv
    ctx.json        True in --json mode  (emit via ctx.ptjsonlib, not ctx.out)
    ctx.verbose     True in -vv mode
    ctx.<extra>     protocol handles from build_context(): ctx.host, ctx.ip,
                    ctx.port, ctx.fqdn, ctx.tls, ctx.starttls, ...

Contract:
  * run() takes exactly one argument (ctx) and returns None.
  * Do NOT print with builtin print()/sys.stdout — use ctx.out()/ctx.debug()
    so output stays isolated per module and ordered by the main.
  * Raising is safe: the main catches it and reports the module as failed without
    aborting the other selected modules.
"""

__MODULELABEL__ = "Information about server:"
__MODULECODE__ = "INFO"
__ORDER__ = 10

import socket
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
    sock.settimeout(4)
    data = None
    try:
        # NTP creates a packet which states it is a query (mode=3)
        sock.sendto(bytes(NTP(version=4, mode=3)), (ip, port))
        data, _ = sock.recvfrom(1024)  # server address and port are discarded
    except:
        ctx.out(f"An error occured while trying to connect to server", "ERROR", indent=4)
    finally:
        sock.close()

    if not data:
        return

    ntp = NTP(data)
    ctx.out(f"IP:                   {ip}", "INFO", indent=4)
    ctx.out(f"Port:                 {port}", "INFO", indent=4)
    ctx.out(f"NTP version:          {ntp.version}", "INFO", indent=4)
    ctx.out(f"Mode:                 {mode_translate[ntp.mode]} ({ntp.mode})", "INFO", indent=4)

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
    ctx.out(f"Stratum:              {stratum_status} ({ntp.stratum})", "INFO", indent=4)

    # leap could be potentially misconfigured or malfunctioning
    # TODO: check if leap seconds coincide with global events (very low priority)
    leap_status = "Unknown (unsynchronized)"
    if ntp.leap == 0:
        leap_status = "No warning"
    elif ntp.leap == 1:
        leap_status = "Last minute had 61s"
    elif ntp.leap == 2:
        leap_status = "Last minute had 59s"
    ctx.out(f"Leap indicator:       {leap_status} ({ntp.leap})", "INFO", indent=4)

    precision_sec = 2 ** int(ntp.precision)
    ctx.out(f"Precision:            2^{ntp.precision} = {precision_sec * 1e6:.3f} µs", "INFO", indent=4)
    ctx.out(f"Reference ID:         {ntp.id}", "INFO", indent=4)
    ctx.out(f"Reference timestamp:  {_ntp_to_utc(ntp.ref)}", "INFO", indent=4)
    ctx.out(f"Transmit timestamp:   {_ntp_to_utc(ntp.sent)}", "INFO", indent=4)
