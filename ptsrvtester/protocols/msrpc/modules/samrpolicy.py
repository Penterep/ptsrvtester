"""SAMRPOLICY - read SAM password and account-lockout policy."""
__MODULELABEL__ = "SAM password and account-lockout policy"
__MODULECODE__ = "SAMRPOLICY"
__ORDER__ = 45

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "SamrPolicy", "query_samr_policy")
