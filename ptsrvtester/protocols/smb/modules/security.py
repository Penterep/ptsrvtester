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

from .authlevel import run as run_authlevel
from .challengeresponse import run as run_challengeresponse
from .encryption import run as run_encryption
from .guest import run as run_guest
from .login import run as run_login
from .null import run as run_null
from .ntlmv2 import run as run_ntlmv2
from .signing import run as run_signing
from ptsrvtester.protocols._base import ModuleContext
from ._common import get_output


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return

    smb_dialects = [
        "SMBv1",
        "SMBv2.0",
        "SMBv2.1",
        "SMBv3.0",
        "SMBv3.0.2",
        "SMBv3.1.1",
    ]
    tests = {
        run_signing: smb_dialects,
        run_encryption: ["SMBv3.0", "SMBv3.0.2", "SMBv3.1.1"],
        run_ntlmv2: smb_dialects,
        run_login: smb_dialects,
        run_null: smb_dialects,
        run_guest: smb_dialects,
        run_authlevel: ["SMBv1"],
        run_challengeresponse: ["SMBv1"],
    }

    for test, dialects in tests.items():
        if output.used_dialect in dialects:
            test(ctx)
