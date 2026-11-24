"""Whether SMB login is required."""

__MODULELABEL__ = "SMB login requirement"
__MODULECODE__ = "LOGIN"
__ORDER__ = 1
__RUN_IN_ALL__ = False

from ._common import get_output
from ptsrvtester.protocols._base import ModuleContext


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return

    if output.is_login_required is True:
        category = "OK"
        msg = "Yes"
    elif output.is_login_required is False:
        category = "WARNING"
        msg = "No"
    else:
        category = "WARNING"
        msg = "Unknown"
    ctx.out(f"Login required:          {msg}", category, indent=4)
