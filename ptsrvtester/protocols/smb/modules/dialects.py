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

__MODULELABEL__ = "The dialects used by the target system"
__MODULECODE__ = "DIALECTS"
__ORDER__ = 11

from ..smb_utils.helpers import SMBContext
from ..smb_utils.server_connection import ServerConnection


def run(ctx: SMBContext) -> None:
    ip, port = ctx.target
    # ctx.out(f"Would check {ip}:{port} here.", "TEXT")
    # For JSON mode, add structured findings instead of text, e.g.:
    #   ctx.ptjsonlib.add_vulnerability("PTV-SMTP-...")

    sc = ServerConnection(ctx)
    out = {}
    for dialect in ctx.mapping.keys():
        if ctx.mapping[dialect]:
            continue
        out = sc.connect(dialect, try_login=False, parse_info=False)
        if out is not None:
            ctx.successful_dialects.append(sc.dial_str_converter(dialect))
    
    for dialect in ctx.successful_dialects:
        ctx.out(dialect, category="VULN" if dialect == "SMBv1" else "NOTVULN",
                condition=True, indent=4)
