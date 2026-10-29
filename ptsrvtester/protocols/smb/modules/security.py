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

# from ..smb_utils.helpers import SMBContext
from ..smb_utils.server_connection import ServerConnection
from ..smb_utils.helpers import SMBResults, SMBv1Flags, SMBv23Flags
from ptsrvtester.protocols._base import ModuleContext

def get_flag(source: int, mask: int) -> bool:
    return bool(source & mask)


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    ip, port = ctx.target
    output: SMBResults = ctx.output

    sc = ServerConnection(ctx)
    if not output.has_ran:
        ctx.out(f"IP address:              {ip}", "INFO", indent=4)
        ctx.out(f"Port:                    {port}", "INFO", indent=4)
        sc.connect()
    
    if output.had_error:
        ctx.out(f"Could not connect to server: {output.error_info}", "ERROR", indent=4)
        return
    
    
    if output.used_dialect == "SMBv1":
        category = "VULN"
    elif output.used_dialect in ["SMBv2.0", "SMBv2.1"]:
        category = "WARNING"
    else:
        category = "NOTVULN"
    ctx.out(f"Used dialect:            {output.used_dialect}", category, indent=4)

    if output.used_dialect == "SMBv1" and output.v1_flags:
        ctx.out("SMBv1 should be disabled unless you know what you're doing", "WARNING", indent=4)
        ctx.debug("Reading SMBv1 flags:")
        flags1, flags2, security_mode, capabilities = output.v1_flags

        signing_support: bool = get_flag(flags2, SMBv1Flags.FLAGS2_SMB_SECURITY_SIGNATURE)
        signing_requirement: bool = get_flag(flags2, SMBv1Flags.FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED)
        # extended_security_support: bool = get_flag(flags2, SMBv1Flags.FLAGS2_EXTENDED_SECURITY)

        # cap_extended_security_support: bool = get_flag(capabilities, SMBv1Flags.CAP_EXTENDED_SECURITY)
        
        user_level_auth: bool = get_flag(security_mode, SMBv1Flags.NEGOTIATE_USER_SECURITY)
        uses_challenge_response: bool = get_flag(security_mode, SMBv1Flags.NEGOTIATE_ENCRYPT_PASSWORDS)
        # sec_signing_support: bool = get_flag(security_mode, SMBv1Flags.NEGOTIATE_SECURITY_SIGNATURE_ENABLE)
        # sec_signing_requirement: bool = get_flag(security_mode, SMBv1Flags.NEGOTIATE_SECURITY_SIGNATURE_REQUIRED)

        ctx.debug(f"user_level_auth = {user_level_auth}")
        ctx.debug(f"uses_challenge_response = {uses_challenge_response}")
        ctx.debug(f"does_support_NTLMv2 = {output.does_support_NTLMv2}")
        ctx.debug(f"signing_support = {signing_support}")
        ctx.debug(f"signing_requirement = {signing_requirement}")
        ctx.debug(f"is_login_required = {output.is_login_required}")
        ctx.debug(f"guest_session = {output.guest_session}")

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
        
        ctx.out(f"NTLMv2 supported:        {output.does_support_NTLMv2}",
                "WARNING" if not output.does_support_NTLMv2 else "OK", indent=4)
        
        if signing_requirement:
            category = "OK"
            msg = "Mandatory"
        elif signing_support:
            category = "WARNING"
            msg = "Available but optional"
        else:
            category = "VULN"
            msg = "Unsupported"
        ctx.out(f"Message signing:         {msg}", category, indent=4)
        
        ctx.out(f"Login required:          {output.is_login_required}",
                "WARNING" if not output.is_login_required else "OK", indent=4)
        
        if output.successful_login:
            category = "VULN"
            msg = "Allowed (possibly enables information gathering)"
        else:
            category = "OK"
            msg = "Could not establish"
        ctx.out(f"NULL session:            {msg}", category, indent=4)
        

    elif output.used_dialect != "SMBv1" and output.v23_flags:
        ctx.debug("Reading SMBv2/3 flags:")
        security_mode, capabilities, session_flags = output.v23_flags

        signing_support: bool = get_flag(security_mode, SMBv23Flags.SMB2_NEGOTIATE_SIGNING_ENABLED)
        signing_requirement: bool = get_flag(security_mode, SMBv23Flags.SMB2_NEGOTIATE_SIGNING_REQUIRED)
        encryption_support: bool = get_flag(capabilities, SMBv23Flags.SMB2_GLOBAL_CAP_ENCRYPTION)
        session_encryption_requirement: bool = get_flag(session_flags, SMBv23Flags.SMB2_SESSION_FLAG_ENCRYPT_DATA)
        null_session: bool = get_flag(session_flags, SMBv23Flags.SMB2_SESSION_FLAG_IS_NULL)

        ctx.debug(f"signing_support = {signing_support}")
        ctx.debug(f"signing_requirement = {signing_requirement}")
        ctx.debug(f"encryption_support = {encryption_support}")
        ctx.debug(f"session_encryption_requirement = {session_encryption_requirement}")
        ctx.debug(f"does_support_NTLMv2 = {output.does_support_NTLMv2}")
        ctx.debug(f"is_login_required = {output.is_login_required}")
        ctx.debug(f"null_session = {null_session}")
        ctx.debug(f"guest_session = {output.guest_session}")

        if signing_requirement:
            category = "OK"
            msg = "Mandatory"
        elif signing_support:
            category = "WARNING"
            msg = "Available but optional"
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
        else:
            category = "VULN"
            msg = "Not supported or enforced"
        ctx.out(f"Encryption support:      {msg}", category, indent=4)

        ctx.out(f"NTLMv2 supported:        {output.does_support_NTLMv2}",
                "WARNING" if not output.does_support_NTLMv2 else "OK", indent=4)       

        ctx.out(f"Login required:          {output.is_login_required}",
                "WARNING" if not output.is_login_required else "OK", indent=4)

        if null_session:
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
