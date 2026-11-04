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

__MODULELABEL__ = "Security information"
__MODULECODE__ = "SECURITY"
__ORDER__ = 12

from ptsrvtester.protocols._base import ModuleContext
from ._common import get_output

def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return
    
    
    if output.used_dialect == "SMBv1":
        category = "VULN"
    elif output.used_dialect in ["SMBv2.0", "SMBv2.1"]:
        category = "WARNING"
    else:
        category = "NOTVULN"
    ctx.out(f"Used dialect:            {output.used_dialect}", category, indent=4)

    if output.used_dialect == "SMBv1" and output.v1_flags:
        ctx.debug("Reading SMBv1 flags:")
        signing_support = output.signing_support
        signing_requirement = output.signing_requirement
        user_level_auth = output.user_level_auth
        uses_challenge_response = output.uses_challenge_response

        if user_level_auth is None:
            category = "WARNING"
            msg = "Unknown"
        elif user_level_auth:
            category = "OK"
            msg = "Separate username/password per user"
        else:
            category = "WARNING"
            msg = "Shared password for the whole share"
        ctx.out(f"Authentication level:    {msg}", category, indent=4)

        if uses_challenge_response is None:
            category = "WARNING"
            msg = "Unknown"
        elif uses_challenge_response:
            category = "OK"
            msg = "Supports hashed/challenge-response auth"
        else:
            category = "WARNING"
            msg = "Only accepts plaintext passwords"
        ctx.out(f"Challenge response:      {msg}", category, indent=4)
        
        ctx.out(f"NTLMv2 supported:        {output.does_support_NTLMv2}",
                "WARNING" if not output.does_support_NTLMv2 else "OK", indent=4)
        
        if signing_requirement:
            category = "OK"
            msg = "Mandatory"
        elif signing_support:
            category = "WARNING"
            msg = "Available but optional"
        elif signing_requirement is None or signing_support is None:
            category = "WARNING"
            msg = "Unknown"
        else:
            category = "VULN"
            msg = "Unsupported"
        ctx.out(f"Message signing:         {msg}", category, indent=4)
        
        ctx.out(f"Login required:          {output.is_login_required}",
                "WARNING" if not output.is_login_required else "OK", indent=4)
        
        if output.null_session:
            category = "VULN"
            msg = "Allowed (possibly enables information gathering)"
        else:
            category = "OK"
            msg = "Could not establish"
        ctx.out(f"NULL session:            {msg}", category, indent=4)
        

    elif output.used_dialect != "SMBv1" and output.v23_flags:
        ctx.debug("Reading SMBv2/3 flags:")
        signing_support = output.signing_support
        signing_requirement = output.signing_requirement
        encryption_support = output.encryption_support
        session_encryption_requirement = output.session_encryption_requirement
        null_session = output.null_session

        if signing_requirement:
            category = "OK"
            msg = "Mandatory"
        elif signing_support:
            category = "WARNING"
            msg = "Available but optional"
        elif signing_requirement is None or signing_support is None:
            category = "WARNING"
            msg = "Unknown"
        else:
            category = "VULN"
            msg = "Not supported or enforced"
        ctx.out(f"Message signing:         {msg}", category, indent=4)
        
        if session_encryption_requirement:
            category = "OK"
            msg = "Was required for the session"
        elif encryption_support:
            category = "OK"
            msg = "Supported"
        elif session_encryption_requirement is None or encryption_support is None:
            category = "WARNING"
            msg = "Unknown"
        else:
            category = "VULN"
            msg = "Not supported or enforced"
        ctx.out(f"Encryption support:      {msg}", category, indent=4)

        ctx.out(f"NTLMv2 supported:        {output.does_support_NTLMv2}",
                "WARNING" if not output.does_support_NTLMv2 else "OK", indent=4)       

        ctx.out(f"Login required:          {output.is_login_required}",
                "WARNING" if not output.is_login_required else "OK", indent=4)

        if null_session is None:
            category = "WARNING"
            msg = "Could not determine"
        elif null_session:
            category = "VULN"
            msg = "Allowed (possibly enables information gathering)"
        else:
            category = "OK"
            msg = "Could not establish"
        ctx.out(f"NULL session:            {msg}", category, indent=4)
        
        if output.guest_session:
            category = "VULN"
            msg = "Allowed (possibly enables information gathering)"
        else:
            category = "OK"
            msg = "Could not establish"
        ctx.out(f"Guest session:           {msg}", category, indent=4)
        
    else:
        ctx.out(f"An error occured while parsing SMB flags", "ERROR", indent=4)
        return
