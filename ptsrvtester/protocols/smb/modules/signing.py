"""SMB message-signing support."""

__MODULELABEL__ = "SMB message signing support"
__MODULECODE__ = "SIGNING"
__ORDER__ = 1
__RUN_IN_ALL__ = False

from ._common import get_output
from ptsrvtester.protocols._base import ModuleContext


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return

    if output.signing_requirement:
        category = "OK"
        msg = "Mandatory"
    elif output.signing_support:
        category = "WARNING"
        msg = "Available but optional"
    elif output.signing_requirement is None or output.signing_support is None:
        category = "WARNING"
        msg = "Unknown"
    else:
        category = "VULN"
        msg = "Unsupported"
    ctx.out(f"Message signing:         {msg}", category, indent=4)