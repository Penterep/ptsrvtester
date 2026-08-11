"""LOOKUP — DNS record lookup."""
__MODULELABEL__ = "DNS record lookup"
__MODULECODE__ = "LOOKUP"
__ORDER__ = 40

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Records = e.lookup_dns_records(getattr(ctx.args, 'lookup_records', None))
