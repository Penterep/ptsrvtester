"""Whether an SMB null session is accepted."""

__MODULELABEL__ = "NULL session"
__MODULECODE__ = "NULL"
__ORDER__ = 1
__RUN_IN_ALL__ = False

from ._common import get_output
from ptsrvtester.protocols._base import ModuleContext


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return

    if output.null_session is True:
        category = "VULN"
        msg = "Allowed (possibly enables information gathering)"
    elif output.null_session is False:
        category = "OK"
        msg = "Could not establish"
    else:
        category = "INFO"
        msg = "Not tested"
    ctx.out(f"NULL session:            {msg}", category, indent=4)
