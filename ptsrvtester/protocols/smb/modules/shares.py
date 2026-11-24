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

__MODULELABEL__ = "Found shares"
__MODULECODE__ = "SHARES"
__ORDER__ = 13

from ptsrvtester.protocols._base import ModuleContext
from ._common import get_output


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return
    
    if output.shares is None:
        ctx.out("Server doesn't allow share enumeration", "INFO", indent=4)
        return
    
    status = output.shares["status"]
    reason = output.shares["reason"]
    error = output.shares["error"]

    ctx.out("Retrieved all accessible shares", "OK", indent=4,
            condition=(status == "complete"))
    ctx.out(
        f"Could not retrieve all shares: {reason}"
        + (f" ({error})" if error is not None else ""),
        "WARNING", indent=4, condition=(status == "partial"),
    )
    if status in ["error", "denied"]:
        ctx.out(f"Server denied share enumeration: {reason}", "WARNING", indent=4,
                condition=(status == "denied"))
        ctx.out(f"Share enumeration failed: {error}", "ERROR", indent=4,
                condition=(status == "error"))
        return
    
    ctx.out(f"Pages found: {output.shares["pages"]}", "INFO", indent=4)
    
    # Table formatting
    shares = output.shares["shares"]
    numwidth = max(2, len(str(len(shares))))
    namewidth = max((len(share["name"]) for share in shares), default=5)
    typewidth = max((len(share["type_name"]) for share in shares), default=4)

    if shares:
        header = (
            f"{'':<{numwidth + 3}}"
            f"{'SHARE':<{namewidth}}   "
            f"{'TYPE':<{typewidth}}   REMARK"
        )
        ctx.out(header, "INFO", indent=4)

    for num, page in enumerate(shares):
        num = f"{(num+1):0{numwidth}d}"
        name = f"{page['name']:<{namewidth}}"
        share_type = f"{page['type_name']:<{typewidth}}"
        ctx.out(f"[{num}] {name}   {share_type}   {page['remark']}", "INFO", indent=4)