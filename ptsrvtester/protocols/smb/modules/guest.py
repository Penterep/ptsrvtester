"""Whether the SMB session is mapped to guest."""

__MODULELABEL__ = "Guest session"
__MODULECODE__ = "GUEST"
__ORDER__ = 1
__RUN_IN_ALL__ = False

from ._common import get_output
from ptsrvtester.protocols._base import ModuleContext


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return

    if output.successful_login:
        if output.guest_session:
            category = "VULN"
            msg = "Allowed (possibly enables information gathering)"
        else:
            category = "OK"
            msg = "Could not establish"
    else:
        category = "INFO"
        msg = "Not tested"
    ctx.out(f"Guest session:           {msg}", category, indent=4)
