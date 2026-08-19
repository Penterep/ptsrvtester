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

__TESTLABEL__ = "Information about the target system"
__TESTCODE__ = ""
__ORDER__ = 10

from ..smb_utils.server_connection import ServerConnection
from ..smb_utils.helpers import SMBContext


def run(ctx: SMBContext) -> None:
    ip, port = ctx.target
    raw_dialects = ctx.mapping.keys()
    # ctx.out(f"Would check {ip}:{port} here.", "TEXT")
    # For JSON mode, add structured findings instead of text, e.g.:
    #   ctx.ptjsonlib.add_vulnerability("PTV-SMTP-...")
    
    sc = ServerConnection(ctx)
    output = None
    dialect = 0
    for dialect in raw_dialects:
        output = sc.connect(dialect)
        ctx.mapping[dialect] = True
        if output is not None:
            break
    
    if output is None:
        ctx.out("Could not connect to server", "ERROR")
        ctx.error = True
        return
    
    dialect = sc.dial_str_converter(dialect)
    
    ctx.successful_dialects.append(dialect)
    ctx.server_name = output["server_name"]
    ctx.dns_domain_name = output["server_DNS_domain_name"]
    ctx.dns_host_name = output["server_DNS_hostname"]

    # OS version parsing
    os_name = output["server_OS"]
    os_info = [output["server_OS_major"], output["server_OS_minor"], output["server_OS_build"]]
    
    os_version = ""
    for piece in os_info:
        if piece != "unknown":
            os_version += "." + str(piece)
        else:
            break
    
    if os_version == "":
        os_version = "unknown"
    else:
        os_version = os_version[1:]
    
    ctx.os_version = os_version if os_name == "unknown" else f"{os_name} (build: {os_version})"
    
    ctx.ntlmv2_support = output["does_support_NTLMv2"]
    ctx.login_required = output["is_login_required"]
    ctx.signing_required = output["is_signing_required"]
    
    
    # Printing
    # ctx.out("SMB server info:")
    ctx.out(f"Server name:             {ctx.server_name}", "INFO", indent=4)
    ctx.out(f"Server version:          {os_version}", "INFO", indent=4)
    ctx.out(f"DNS domain name:         {ctx.dns_domain_name}", "INFO", indent=4)
    ctx.out(f"DNS host name:           {ctx.dns_host_name}", "INFO", indent=4,
                condition=ctx.dns_host_name != ctx.dns_domain_name)
    ctx.out(f"Lowest dialect version:  {dialect}",
                "VULN" if dialect == "SMBv1" else "NOTVULN", indent=4)
    ctx.out(f"Login required:          {ctx.login_required}",
                "WARNING" if not ctx.login_required else "OK", indent=4)
    ctx.out(f"Signing required:        {ctx.signing_required}",
                "VULN" if not ctx.signing_required else "NOTVULN", indent=4)
    ctx.out(f"NTLMv2 supported:        {ctx.ntlmv2_support}", "INFO", indent=4)
