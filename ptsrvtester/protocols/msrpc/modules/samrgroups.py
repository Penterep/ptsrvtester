"""SAMRGROUPS - enumerate SAM groups, aliases, and their direct members."""
__MODULELABEL__ = "SAM group and alias enumeration"
__MODULECODE__ = "SAMRGROUPS"
__ORDER__ = 47

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "SamrGroups", "enumerate_samr_groups")
