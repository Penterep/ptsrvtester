"""ZONEWALK — Zone walking."""
__MODULELABEL__ = "Zone walking"
__MODULECODE__ = "ZONEWALK"
__ORDER__ = 80

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Zonewalk = e.zone_walking()
