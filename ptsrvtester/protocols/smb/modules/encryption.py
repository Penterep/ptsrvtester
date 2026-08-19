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

__MODULELABEL__ = "Encryption status information"
__MODULECODE__ = ""
__ORDER__ = 12

from ..smb_utils.helpers import SMBContext
from ..smb_utils.server_connection import ServerConnection
from impacket.smbconnection import (
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
)


# TODO: add encryption requirement check

def run(ctx: SMBContext) -> None:
    ip, port = ctx.target
    # ctx.out(f"Would check {ip}:{port} here.", "TEXT")
    # For JSON mode, add structured findings instead of text, e.g.:
    #   ctx.ptjsonlib.add_vulnerability("PTV-SMTP-...")
    
    sc = ServerConnection(ctx)
    
    for dialect in [SMB2_DIALECT_30, SMB2_DIALECT_311]:
        out = sc.connect(dialect, try_login=False, parse_info=False, parse_encryption=True)
        if out is not None:
            if dialect == SMB2_DIALECT_30:
                ctx.v30_encryption = out["v30_encryption"]
                ctx.successful_dialects.append("SMBv3.0")
            elif dialect == SMB2_DIALECT_311:
                ctx.v311_encryption = out["v311_encryption"]
                ctx.successful_dialects.append("SMBv3.1.1")
            else:
                assert(False)
    
    if "SMBv3.0" not in ctx.successful_dialects and "SMBv3.1.1" not in ctx.successful_dialects:
        ctx.out("Encryption is only supported on SMBv3 and above. The server doensn't use them", category="INFO", condition=True, indent=4)
    else:
        ctx.out(f"SMBv3.0:    {ctx.v30_encryption if ctx.v30_encryption is not None else "Unknown"}",
                category="INFO", condition="SMBv3.0" in ctx.successful_dialects, indent=4)

        ctx.out(f"SMBv3.1.1:  {ctx.v311_encryption if ctx.v311_encryption is not None else "Unknown"}",
                category="INFO", condition="SMBv3.1.1" in ctx.successful_dialects, indent=4)