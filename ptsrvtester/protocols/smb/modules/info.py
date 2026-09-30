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

__MODULELABEL__ = "Information about the target system"
__MODULECODE__ = "INFO"
__ORDER__ = 10

from ..smb_utils.server_connection import ServerConnection
from ..smb_utils.helpers import SMBContext


def win_version_translate(ver: str) -> str:
    output = "Windows "
    version = ver.split(".")
    
    # 5.x = Windows XP
    if version[0] == "5":
        output += "XP"
        if len(version) > 1 and version[1] == "2":
            output += " Professional 64-bit"
        return output
    
    # 6.x = Windows Vista, 7, 8, 8.1
    elif version[0] == "6":
        if version[1] == "0":
            output += "Vista"
            if len(version) > 2:
                if version[2] == "6001":
                    output += " SP1"
                elif version[2] == "6002":
                    output += " SP2"
        elif version[1] == "1":
            output += "7"
            if len(version) > 2 and version[2] == "7601":
                output += " SP1"
        elif version[1] == "2":
            output += "8"
        elif version[1] == "3":
            output += "8.1"
            if len(version) > 2 and version[2] == "9600":
                output += " (Update 1)"
        return output
    
    # 10.x = Windows 10 or 11
    elif version[0] == "10":
        if len(version) > 2:
            build = int(version[2])
            # Windows 11 (build >= 22000)
            if build >= 22000:
                output += "11"
                if build == 22000:
                    output += " (21H2)"
                elif build == 22621:
                    output += " (22H2)"
                elif build == 22631:
                    output += " (23H2)"
            # Windows 10
            else:
                output += "10"
                if build == 10240:
                    pass  # base Windows 10
                elif build == 10586:
                    output += " (1511)"
                elif build == 15063:
                    output += " (1703)"
                elif build == 16299:
                    output += " (1709)"
                elif build == 17134:
                    output += " (1803)"
                elif build == 17763:
                    output += " (1809)"
                elif build == 18362:
                    output += " (1903)"
                elif build == 18363:
                    output += " (1909)"
                elif build == 19041:
                    output += " (2004)"
                elif build == 19042:
                    output += " (20H2)"
                elif build == 19043:
                    output += " (21H1)"
                elif build == 19044:
                    output += " (21H2)"
        return output
    
    return output


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
    os_info = [output["server_OS_major"], output["server_OS_minor"], output["server_OS_build"]]
    
    os_version = ""
    for piece in os_info:
        if piece != "unknown":
            os_version += "." + str(piece)
        else:
            break
    
    if os_version == "":
        os_ver_name = "unknown"
        os_version = "unknown"
    else:
        os_version = os_version[1:]
        os_ver_name = win_version_translate(os_version)
        
    os_ver_name = output["server_OS"] if output["server_OS"] != "unknown" and os_version == "unknown" else os_ver_name
    
    ctx.os_version = f"{os_ver_name} (build: {os_version})" if os_version != "unknown" else os_ver_name
    
    ctx.ntlmv2_support = output["does_support_NTLMv2"]
    ctx.login_required = output["is_login_required"]
    ctx.signing_required = output["is_signing_required"]
    
    
    # Printing
    # ctx.out("SMB server info:")
    ctx.out(f"Server name:             {ctx.server_name}", "INFO", indent=4)
    ctx.out(f"OS version:              {ctx.os_version}", "INFO", indent=4)
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
