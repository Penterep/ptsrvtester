"""SAMRUSERS - enumerate SAM user accounts and account-state flags."""
__MODULELABEL__ = "SAM user account enumeration"
__MODULECODE__ = "SAMRUSERS"
__ORDER__ = 46

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "SamrUsers", "enumerate_samr_users")
