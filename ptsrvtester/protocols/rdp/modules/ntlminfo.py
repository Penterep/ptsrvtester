"""Pre-authentication CredSSP/NTLM information adapter."""

__MODULELABEL__ = "RDP NTLM information"
__MODULECODE__ = "NTLMINFO"
__ORDER__ = 80


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
