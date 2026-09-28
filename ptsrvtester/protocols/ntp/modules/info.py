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

from ptsrvtester.protocols.ntp.ntp_utils.ntp_classes import NTPResults
from ptsrvtester.protocols.ntp.ntp_utils.connection import gather_info, ntp_to_utc, get_ntp_time, sec_to_readable


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
    ref_id_translate = {
        "GOES": "Geosynchronous Orbit Environment Satellite",
        "GPS": "Global Position System",
        "GAL": "Galileo Positioning System",
        "PPS": "Generic pulse-per-second",
        "IRIG": "Inter-Range Instrumentation Group",
        "WWVB": "LF Radio WWVB Ft. Collins, CO 60 kHz",
        "DCF": "LF Radio DCF77 Mainflingen, DE 77.5 kHz",
        "HBG": "LF Radio HBG Prangins, HB 75 kHz",
        "MSF": "LF Radio MSF Anthorn, UK 60 kHz",
        "JJY": "LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz",
        "LORC": "MF Radio LORAN C station, 100 kHz",
        "TDF": "MF Radio Allouis, FR 162 kHz",
        "CHU": "HF Radio CHU Ottawa, Ontario",
        "WWV": "HF Radio WWV Ft. Collins, CO",
        "WWVH": "HF Radio WWVH Kauai, HI",
        "NIST": "NIST telephone modem",
        "ACTS": "NIST telephone modem",
        "USNO": "USNO telephone modem",
        "PTB": "European telephone modem",
        "DFM": "UTC(DFM)",
    }
    kod_codes = {
        "ACST": "The association belongs to a unicast server",
        "AUTH": "Server authentication failed",
        "AUTO": "Autokey sequence failed",
        "BCST": "The association belongs to a broadcast server",
        "CRYP": "Cryptographic authentication or identification failed",
        "DENY": "Access denied by remote server",
        "DROP": "Lost peer in symmetric mode",
        "RSTR": "Access denied due to local policy",
        "INIT": "The association has not yet synchronized for the first time",
        "MCST": "The association belongs to a dynamically discovered server",
        "NKEY": "No key found. Either the key was never installed or is not trusted",
        "NTSN": "Network Time Security (NTS) negative-acknowledgment (NAK) 	[RFC 8915, ",
        "RATE": "Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold",
        "RMOT": "Alteration of association from a remote host running ntpdc.",
        "STEP": "A step change in system time has occurred, but the association has not yet resynchronized",
    }
    results: NTPResults
    
    ip, port = ctx.target
    ctx.out(f"IP:                   {ip}", "INFO", indent=4)
    ctx.out(f"Port:                 {port}", "INFO", indent=4)


    # -------------------------------------------- Getting results from server --------------------------------------------

    if not ctx.results.has_ran:
        gather_info(ip, port, ctx.results)
        results = ctx.results
        ctx.results = results
    else:
        results = ctx.results
    if results.error:
        ctx.out(f"An error occured while trying to connect to server: {results.error_info}", "ERROR", indent=4)
        ctx.out(f"It is possible the server accepts only a specific IP range or needs authentication", "ERROR", indent=4)
        return

    ctx.out(f"NTP version:          {results.version}", "INFO", indent=4)


    # ---------------------------------------- Kiss of Death detection and parsing ----------------------------------------

    if results.kod_sent:
        ctx.out(f"Server sent a KoD (Kiss of Death) packet", "WARNING", indent=4)
        
        # KoD code translation
        if results.ref_id != "":
            ref_id: str = str(results.ref_id).upper()
            info = ""
            if ref_id[0] == "X":
                info = ": Experimental"
            elif ref_id in kod_codes.keys():
                info = ": " + kod_codes[ref_id]
            ctx.out(f"KoD code (RefID):     {ref_id}{info}", "WARNING", indent=4)
        else:
            ctx.out(f"Could not determine KoD: RefID is empty", "ERROR", indent=4)
        ctx.out(f"Information in KoD packets is not reliable", "WARNING", indent=4)


    # ------------------------------------------------ System information -------------------------------------------------

    if results.accepts_mode_6:
        ctx.out(f"Server hostname:      {results.hostname}", "INFO", indent=4)
        ctx.out(f"Processor:            {results.processor}", "INFO", indent=4)
        ctx.out(f"System OS:            {results.system_os}", "INFO", indent=4)

    ctx.out(f"Mode:                 {results.mode} ({mode_translate[results.mode]})", "INFO", indent=4)
    ctx.out(f"Accepts mode 6:       {results.accepts_mode_6}", "INFO", indent=4)


    # -------------------------------------------------- Stratum parsing --------------------------------------------------
    # TODO: fake or misconfigured servers can apparently return a weird combination of stratum and refID, should try detecting that

    stratum_status = "Unsynchronized"
    if results.stratum == 0:
        stratum_status = "Invalid"
    elif results.stratum == 1:
        stratum_status = "Primary"
    elif results.stratum >= 2 and results.stratum < 16:
        stratum_status = "Secondary"
    ctx.out(f"Stratum:              {results.stratum} ({stratum_status})", "INFO", indent=4)


    # ----------------------------------------------- Reference ID parsing ------------------------------------------------

    info = ""
    ref_id = str(results.ref_id).upper()
    if ref_id != "":
        if not results.kod_sent and ref_id in ref_id_translate.keys():
            info = ": " + ref_id_translate[ref_id]
        elif ref_id[0] == "X":
            info = ": Experimental"
    else:
        ref_id = "Empty"
    ctx.out(f"Reference ID:         {ref_id}{info}", "INFO", indent=4)


    # --------------------------------------------- Time and sync information ---------------------------------------------
    # TODO: check if leap seconds coincide with global events (very low priority)

    leap_status = "Unsynchronized"
    if results.leap == 0:
        leap_status = "Last minute had 60s"
    elif results.leap == 1:
        leap_status = "Last minute had 61s"
    elif results.leap == 2:
        leap_status = "Last minute had 59s"
    ctx.out(f"Leap indicator:       {results.leap} ({leap_status})", "INFO", indent=4)

    precision_sec = 2 ** int(results.precision)
    ctx.out(f"Precision:            2^{results.precision} = {precision_sec * 1e6:.3f} µs", "INFO", indent=4)
    ctx.out(f"Last upstream sync:   {ntp_to_utc(results.ref_time)}", "INFO", indent=4)
    ctx.out(f"Transmit timestamp:   {ntp_to_utc(results.transmit_time)}", "INFO", indent=4)
    
    acc_time = get_ntp_time()
    acc_diff = abs(acc_time - float(results.transmit_time))
    diff_rating = "Unacceptable"
    if acc_diff <= 0.1:
        diff_rating = "Excellent"      # Better than WAN standard
    elif acc_diff <= 0.5:
        diff_rating = "Good"           # Still safe margin
    elif acc_diff <= 1.5:
        diff_rating = "Acceptable"     # Within MAXDIST threshold
    elif acc_diff <= 3:
        diff_rating = "Poor"           # Beyond safe, but within reason
    else:
        diff_rating = "Unacceptable"  
    
    sync_diff = abs(acc_time - float(results.ref_time))
    if sync_diff <= 120:  # <= 2 minutes
        sync_rating = "Excellent"
    elif sync_diff <= 600:  # <= 10 minutes  
        sync_rating = "Good"
    elif sync_diff <= 3600:  # <= 1 hour
        sync_rating = "Acceptable"
    elif sync_diff <= 86400:  # <= 24 hours
        sync_rating = "Poor"
    else:
        sync_rating = "Unacceptable"

    ctx.out(f"Verified time:        {ntp_to_utc(acc_time)}", "INFO", indent=4)
    ctx.out(f"Diff with verified:   {sec_to_readable(acc_diff)} ({diff_rating})", "INFO", indent=4)
    ctx.out(f"Diff from last sync:  {sec_to_readable(sync_diff)} ({sync_rating})", "INFO", indent=4)
    
    
    # ----------------------------------------------- Response information ------------------------------------------------
    
    ctx.out(f"Server responded to mode 3 in {results.query_attempts} attempt{"s" if results.query_attempts > 1 else ""}", "INFO", indent=4)
    ctx.out(f"Server responded to mode 6 in {results.control_attempts} attempt{"s" if results.control_attempts > 1 else ""}", "INFO", indent=4, condition=results.accepts_mode_6)
