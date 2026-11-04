"""SMB message-signing configuration."""

__MODULELABEL__ = "Message signing"
__MODULECODE__ = "SIGNING"
__ORDER__ = 13

from ._common import get_output
from ptsrvtester.protocols._base import ModuleContext


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return

    if output.signing_requirement is True:
        category, msg = "OK", "Mandatory"
    elif output.signing_support is True:
        category, msg = "WARNING", "Available but optional"
    elif output.signing_requirement is None or output.signing_support is None:
        category, msg = "WARNING", "Unknown"
    else:
        category, msg = "VULN", "Not supported or enforced"
    ctx.out(f"Message signing:         {msg}", category, indent=4)
