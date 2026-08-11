"""INFO — DNS server information."""
__MODULELABEL__ = "DNS server information"
__MODULECODE__ = "INFO"
__ORDER__ = 10

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Info = e.print_dns_info()
