"""SMB login requirement and anonymous/guest session checks."""

__MODULELABEL__ = "Login and session access"
__MODULECODE__ = "LOGIN"
__ORDER__ = 15

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

    if output.successful_login:
        category = "OK"
        msg = "Established"
    else:
        category = "INFO"
        msg = "Not established"
    ctx.out(f"SMB session:             {msg}", category, indent=4)

    if output.null_session is True:
        category = "VULN"
        msg = "Accepted (possibly enables information gathering)"
    elif output.null_session is False:
        category = "OK"
        msg = "Not accepted"
    else:
        category = "INFO"
        msg = "Not tested"
    ctx.out(f"NULL session:            {msg}", category, indent=4)

    if output.successful_login:
        if output.guest_session:
            category = "VULN"
            msg = "Established"
        else:
            category = "OK"
            msg = "Not established"
    else:
        category = "INFO"
        msg = "Not tested"
    ctx.out(f"Guest session:           {msg}", category, indent=4)
