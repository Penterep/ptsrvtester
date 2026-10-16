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
__MODULECODE__ = "ENCRYPTION"
__ORDER__ = 12

# from ..smb_utils.helpers import SMBContext
from ..smb_utils.server_connection import ServerConnection
from ..smb_utils.helpers import SMBResults, SMBv1Flags, SMBv23Flags
from ptsrvtester.protocols._base import ModuleContext


def run(ctx: ModuleContext) -> None:
    ip, port = ctx.target
    output: SMBResults = ctx.output

    sc = ServerConnection(ctx)
    if not output.has_ran:
        ctx.out(f"IP address:              {ip}", "INFO", indent=4)
        ctx.out(f"Port:                    {port}", "INFO", indent=4)
        # TODO: add login and password check
        sc.connect()
    
    if output.had_error:
        ctx.out(f"Could not connect to server: {output.error_info}", "ERROR", indent=4)
        return
    
    if output.used_dialect == "SMBv1" and output.v1_flags:
        ctx.out(f"Used dialect:            {output.used_dialect}", "VULN", indent=4)
        flags1, flags2, security_mode, capabilities = output.v1_flags

        signing_support: bool = bool(flags2 & SMBv1Flags.FLAGS2_SMB_SECURITY_SIGNATURE)
        signing_requirement: bool = bool(flags2 & SMBv1Flags.FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED)
        extended_security_support: bool = bool(flags2 & SMBv1Flags.FLAGS2_EXTENDED_SECURITY)

        cap_extended_security_support: bool = bool(capabilities & SMBv1Flags.CAP_EXTENDED_SECURITY)
        assert extended_security_support == cap_extended_security_support
        
        user_level_auth: bool = bool(security_mode & SMBv1Flags.NEGOTIATE_USER_SECURITY)
        uses_challenge_response: bool = bool(security_mode & SMBv1Flags.NEGOTIATE_ENCRYPT_PASSWORDS)
        sec_signing_support: bool = bool(security_mode & SMBv1Flags.NEGOTIATE_SECURITY_SIGNATURE_ENABLE)
        sec_signing_requirement: bool = bool(security_mode & SMBv1Flags.NEGOTIATE_SECURITY_SIGNATURE_REQUIRED)

        assert signing_support == sec_signing_support
        assert signing_requirement == sec_signing_requirement
        
        if user_level_auth:
            category = "OK"
            msg = "Separate username/password per user"
        else:
            category = "WARNING"
            msg = "Shared password for the whole share"
        ctx.out(f"Authentication level:    {msg}", category, indent=4)

        if uses_challenge_response:
            category = "OK"
            msg = "Supports hashed/challenge-response auth"
        else:
            category = "WARNING"
            msg = "Only accepts plaintext passwords"
        ctx.out(f"Challenge response:      {msg}", category, indent=4)
        
        if signing_requirement:
            category = "OK"
            msg = "Signing is mandatory"
        elif signing_support:
            category = "WARNING"
            msg = "Signing is available but optional"
        else:
            category = "WARNING"
            msg = "Signing is unsupported"
        ctx.out(f"Message signing:         {msg}", category, indent=4)
        
        
    elif output.used_dialect != "SMBv1" and output.v23_flags:
        raise NotImplementedError
