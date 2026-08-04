"""Single CredSSP/NTLM authentication adapter."""

__MODULELABEL__ = "RDP authentication test"
__MODULECODE__ = "AUTH"
__ORDER__ = 90


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
