"""ZONEWALKFULL — Complete zone walking."""
__MODULELABEL__ = "Complete zone walking"
__MODULECODE__ = "ZONEWALKFULL"
__ORDER__ = 90

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Zonewalk_com = e.zone_walking_complete()
