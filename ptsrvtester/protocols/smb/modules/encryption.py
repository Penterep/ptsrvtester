"""SMB encryption support."""

__MODULELABEL__ = "SMB encryption support"
__MODULECODE__ = "ENCRYPTION"
__ORDER__ = 1
__RUN_IN_ALL__ = False

from ._common import get_output
from ptsrvtester.protocols._base import ModuleContext


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return

    if output.used_dialect in {"SMBv1", "SMBv2.0", "SMBv2.1"}:
        ctx.out("SMB encryption:          Only relevant for SMBv3", "INFO", indent=4)
        return

    if output.session_encryption_requirement:
        category = "OK"
        msg = "Was required for the session"
    elif output.encryption_support:
        category = "OK"
        msg = "Supported"
    elif output.session_encryption_requirement is None or output.encryption_support is None:
        category = "WARNING"
        msg = "Unknown"
    else:
        category = "VULN"
        msg = "Not supported or enforced"
    ctx.out(f"Encryption support:      {msg}", category, indent=4)
