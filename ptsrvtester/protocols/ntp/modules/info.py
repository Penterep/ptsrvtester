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

__MODULELABEL__ = "Information about server"
__MODULECODE__ = "INFO"
__ORDER__ = 10

import socket
import nmap
from scapy.layers.ntp import NTP
from datetime import datetime, timezone, timedelta
from _common import eng

from ..ntp_utils.ntp_classes import NTPResults
from ..ntp_utils.connection import gather_info

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
    results = NTPResults()
    results = gather_info(ip, port)
    if results.error:
        ctx.out(f"An error occured while trying to connect to server: {results.error_info}", "ERROR", indent=4)

    ctx.out(f"IP:                   {ip}", "INFO", indent=4)
    ctx.out(f"Port:                 {port}", "INFO", indent=4)
    ctx.out(f"Accepts mode 6:       {results.accepts_mode_6}", "INFO", indent=4)
    ctx.out(f"NTP version:          {results.version}", "INFO", indent=4)

    if results.accepts_mode_6:
        ctx.out(f"Server hostname:      {results.hostname}", "INFO", indent=4)
        ctx.out(f"Processor:            {results.processor}", "INFO", indent=4)
        ctx.out(f"System OS:            {results.system_os}", "INFO", indent=4)

    ctx.out(f"Mode:                 {results.mode} ({mode_translate[results.mode]})", "INFO", indent=4)

    if results.leap == 3 and results.stratum == 0:
        ctx.out(f"Server sent a KoD (Kiss of Death) packet", "WARNING", indent=4)
        # return

    # TODO: fake or misconfigured servers can apparently return a weird combination of stratum and refID, try detecting that
    # TODO: check if server is correctly configured or maliciously set up
    stratum_status = "Unsynchronized"
    if results.stratum == 0:
        stratum_status = "Invalid"
    elif results.stratum == 1:
        stratum_status = "Primary"
    elif results.stratum >= 2 and results.stratum < 16:
        stratum_status = "Secondary"
    ctx.out(f"Stratum:              {results.stratum} ({stratum_status})", "INFO", indent=4)

    ctx.out(f"Reference ID:         {results.ref_id}", "INFO", indent=4)

    # leap could be potentially misconfigured or malfunctioning
    # TODO: check if leap seconds coincide with global events (very low priority)
    leap_status = "Unknown (unsynchronized)"
    if results.leap == 0:
        leap_status = "No warning"
    elif results.leap == 1:
        leap_status = "Last minute had 61s"
    elif results.leap == 2:
        leap_status = "Last minute had 59s"
    ctx.out(f"Leap indicator:       {results.leap} ({leap_status})", "INFO", indent=4)

    precision_sec = 2 ** int(results.precision)
    ctx.out(f"Precision:            2^{results.precision} = {precision_sec * 1e6:.3f} µs", "INFO", indent=4)
    ctx.out(f"Reference timestamp:  {_ntp_to_utc(results.ref_time)}", "INFO", indent=4)
    ctx.out(f"Transmit timestamp:   {_ntp_to_utc(results.transmit_time)}", "INFO", indent=4)


    # ------- Vulnerabilites (will put into another module once problems are figured out) -------
    
    ctx.out(f"Possible vulnerabilities (temporarily in info)", "INFO", indent=0)
    
    # only 4.2.8p15 - CVE-2023-26551 to CVE-2023-26555 (DoS through errors in code)
    # from 0.3.0 to 0.3.2 - CVE-2023-33192 (DoS through crafted cookies)
    # up to (excluding) 4.2.7p26 - CVE-2013-5211 (traffic amplification through monolist)
    # TODO: check monolist availability
    
    if not results.accepts_mode_6:
        if not isinstance(results.version, int):
            raise TypeError
        elif results.version < 4:
            ctx.out(f"CVE-2013-5211", "VULN", indent=4)
        return
    
    if not isinstance(results.version, str):
        raise TypeError
    
    parsed_ver = tuple(int(x) for x in results.version.replace("p", ".").split("."))
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
