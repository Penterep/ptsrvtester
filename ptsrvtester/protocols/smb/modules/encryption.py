"""SMB encryption and NTLMv2 support."""

__MODULELABEL__ = "Encryption and NTLMv2"
__MODULECODE__ = "ENCRYPTION"
__ORDER__ = 14

from ._common import get_output
from ptsrvtester.protocols._base import ModuleContext


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return

    if output.does_support_NTLMv2 is True:
        category = "OK"
        msg = "Yes"
    elif output.does_support_NTLMv2 is False:
        category = "WARNING"
        msg = "No"
    else:
        category = "WARNING"
        msg = "Unknown"
    ctx.out(f"NTLMv2 supported:        {msg}", category, indent=4)

    if output.used_dialect in {"SMBv1", "SMBv2.0", "SMBv2.1"}:
        ctx.out("SMB encryption:          Only relevant for SMBv3", "INFO", indent=4)
        return

    if output.session_encryption_requirement is True:
        category = "OK"
        msg = "Required for this session"
    elif output.encryption_support is True:
        category = "OK"
        msg = "Supported"
    elif output.session_encryption_requirement is None or output.encryption_support is None:
        category = "WARNING"
        msg = "Unknown"
    else:
        category = "VULN"
        msg = "Not supported or enforced"
    ctx.out(f"SMB encryption:          {msg}", category, indent=4)
