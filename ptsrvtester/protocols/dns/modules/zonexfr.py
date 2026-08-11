"""ZONEXFR — Zone transfer."""
__MODULELABEL__ = "Zone transfer"
__MODULECODE__ = "ZONEXFR"
__ORDER__ = 30

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.ZoneTransfer = e.zone_transfer()
