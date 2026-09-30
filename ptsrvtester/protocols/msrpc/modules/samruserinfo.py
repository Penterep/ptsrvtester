"""SAMRUSERINFO - query available SAM account times and logon statistics."""
__MODULELABEL__ = "SAM user account details"
__MODULECODE__ = "SAMRUSERINFO"
__ORDER__ = 48

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "SamrUserInfo", "query_samr_user_info")
