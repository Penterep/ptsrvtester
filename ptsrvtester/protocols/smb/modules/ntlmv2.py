"""Whether the SMB server supports NTLMv2."""

__MODULELABEL__ = "NTLMv2 support"
__MODULECODE__ = "NTLMV2"
__ORDER__ = 1
__RUN_IN_ALL__ = False

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
