"""
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

__MODULELABEL__ = "Dialects used by target"
__MODULECODE__ = "DIALECTS"
__ORDER__ = 11

from ..smb_utils.server_connection import ServerConnection
from ..smb_utils.helpers import SMBResults


def run(ctx) -> None:
    output: SMBResults = ctx.output
    sc = ServerConnection(ctx)
    # ip, port = ctx.target

    if not output.has_ran:
        # TODO: add login and password check
        sc.connect()

    if output.had_error:
        ctx.out(f"Could not connect to server: {output.error_info}", "ERROR", indent=4)
        return
    
    for dialect, supported in output.open_dialects.items():
        if not supported:
            continue

        if dialect == "SMBv1":
            cat = "VULN"
        elif dialect in ["SMBv2.0", "SMBv2.1"]:
            cat = "WARNING"
        else:
            cat = "NOTVULN"
        ctx.out(dialect, category=cat, condition=True, indent=4)
