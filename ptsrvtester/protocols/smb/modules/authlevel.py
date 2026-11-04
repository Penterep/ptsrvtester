"""SMB1 authentication level."""

__MODULELABEL__ = "Authentication level"
__MODULECODE__ = "AUTHLEVEL"
__ORDER__ = 16

from ._common import get_output
from ptsrvtester.protocols._base import ModuleContext


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return

    if output.used_dialect != "SMBv1":
        ctx.out("Only relevant for SMBv1", "INFO", indent=4)
    elif output.user_level_auth is None:
        category = "WARNING"
        msg = "Unknown"
    elif output.user_level_auth:
        category = "OK"
        msg = "Separate username/password per user"
    else:
        category = "WARNING"
        msg = "Shared password for the whole share"
    if output.used_dialect == "SMBv1":
        ctx.out(f"Authentication level:    {msg}", category, indent=4)
