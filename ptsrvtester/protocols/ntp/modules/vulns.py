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

__MODULELABEL__ = "Possible vulnerabilities on the server"
__MODULECODE__ = "VULNS"
__ORDER__ = 11

from ptsrvtester.protocols.ntp.ntp_utils.ntp_classes import NTPResults
from ptsrvtester.protocols.ntp.ntp_utils.connection import gather_info

def run(ctx):
    
    # -------------------------------------------- Getting results from server --------------------------------------------

    ip, port = ctx.target
    if not ctx.results.has_ran:
        gather_info(ip, port, ctx.results)
        results = ctx.results
        ctx.results = results
    else:
        results = ctx.results
    if results.error:
        ctx.out(f"An error occured while trying to connect to server: {results.error_info}", "ERROR", indent=4)
        ctx.out(f"It is possible the server accepts only a specific IP range or needs authentication", "INFO", indent=4)
        return
    
    
    # --------------------------------------------- Vulnerability assessment ----------------------------------------------
    
    # only 4.2.8p15 - CVE-2023-26551 to CVE-2023-26555 (DoS through errors in code)
    # from 0.3.0 to 0.3.2 - CVE-2023-33192 (DoS through crafted cookies)
    # up to (excluding) 4.2.7p26 - CVE-2013-5211 (traffic amplification through monlist)

    # TODO: check monlist availability
    
    
    # ------------------------------------------ Short version format processing ------------------------------------------
    
    if isinstance(results.version, str):
        try:
            results.version = int(results.version)
        except:
            pass

    if isinstance(results.version, int):
        ctx.out(f"Server did not return specific version", "INFO", indent=4)
        ctx.out(f"Detected version:     {results.version}", "INFO", indent=4)
        if results.version == 4:
            ctx.out(f"Version 4 has multiple vulnerabilities, but only on specific versions", "WARNING", indent=4)
        elif results.version == 3:
            ctx.out(f"CVE-2013-5211", "VULN", indent=4)
            ctx.out(f"Possibly CV-2023-33192 (3.0<=ver<=3.2)", "VULN", indent=4)
        else:
            ctx.out(f"Unable to process version: returned in unexpected format ({results.version})", "ERROR", indent=4)
        return


    # ------------------------------------------ Long version format processing -------------------------------------------
    # TODO: figure out what a full ver 0.3.0 response looks like

    try:
        parsed_ver = tuple(int(x) for x in results.version.replace("p", ".").split("."))
    except:
        ctx.out(f"Unable to process version: returned in unexpected format ({results.version})", "ERROR", indent=4)
        return

    ctx.out(f"Detected version:     {str(parsed_ver)[1:-1].replace(", ", ".")}", "INFO", indent=4)
    
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