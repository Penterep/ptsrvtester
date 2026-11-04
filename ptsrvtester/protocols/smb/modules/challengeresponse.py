"""SMB1 challenge-response password support."""

__MODULELABEL__ = "Challenge-response authentication"
__MODULECODE__ = "CHALLENGERESPONSE"
__ORDER__ = 17

from ._common import get_output
from ptsrvtester.protocols._base import ModuleContext


def run(ctx: ModuleContext) -> None:
    ctx.debug("Running test: " + __MODULECODE__)
    output = get_output(ctx)
    if output is None:
        return

    if output.used_dialect != "SMBv1":
        ctx.out("Challenge response:      Only relevant for SMBv1", "INFO", indent=4)
    elif output.uses_challenge_response is None:
        category = "WARNING"
        msg = "Unknown"
    elif output.uses_challenge_response:
        category = "OK"
        msg = "Supports hashed/challenge-response auth"
    else:
        category = "WARNING"
        msg = "Only accepts plaintext passwords"
    if output.used_dialect == "SMBv1":
        ctx.out(f"Challenge response:      {msg}", category, indent=4)
