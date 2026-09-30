"""BLACKLIST — DNSBL lookup (no SMTP connection)."""
from ..._base import Out
from ..utils.blacklist_parser import BlacklistParser
from ..utils.helpers import _is_private_ip
from ..utils.results import BlacklistEntry, BlacklistResult
from ._common import eng

__MODULELABEL__ = "Blacklist information"
__MODULECODE__ = "BLACKLIST"
__ORDER__ = 70


def test_blacklist(e, target: str) -> tuple[BlacklistResult | None, bool]:
    """Run blacklist check. Returns (result, skipped_private). skipped_private=True for private IP."""
    e.ptdebug("Testing target against blacklists:", title=True)
    if e.target_is_ip and _is_private_ip(target):
        e.ptdebug("Blacklist test skipped: private/internal IP (not on public blacklists)", Out.INFO)
        return (None, True)

    blacklist_parser = BlacklistParser(e.ptdebug, e.args.json, e.args.debug)

    try:
        error_msg = blacklist_parser.lookup(target)
    except Exception as ex:
        e._fail(str(ex))

    if error_msg:
        e.ptdebug(error_msg, Out.VULN)
        if error_msg == "Cannot test Private IP Address":
            return (None, True)
        return (BlacklistResult(False, None), False)

    if blacklist_parser.result is None or "table_result" not in blacklist_parser.result:
        return (BlacklistResult(False, None), False)

    listed = [
        BlacklistEntry(r[1], r[2], r[3])
        for r in blacklist_parser.result["table_result"]
        if r[0] == "LISTED"
    ]
    if listed:
        return (BlacklistResult(True, listed), False)
    return (BlacklistResult(False, None), False)


def stream_blacklist_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (blacklist_error := e.results.blacklist_error) is not None:
        pp(f"Blacklist test failed: {blacklist_error}", bullet_type="VULN", condition=show, indent=4)
        return
    if e.results.blacklist_private_ip_skipped:
        pp(
            "Private/internal IP - blacklist check not applicable "
            "(addresses in private ranges are not listed on public blacklists)",
            bullet_type="TITLE",
            condition=show,
            indent=4,
        )
        return
    blacklist = e.results.blacklist
    if blacklist is None:
        return
    if not blacklist.listed:
        pp("Clean", bullet_type="NOTVULN", condition=show, indent=4)
        return
    if (results := blacklist.results) is not None:
        for r in results:
            pp(
                f'{r.blacklist.strip()}: "{r.reason}" (TTL={r.ttl})',
                bullet_type="VULN",
                condition=show,
                indent=4,
            )


def run(ctx):
    e = eng(ctx)
    try:
        bl_result, skipped_private = test_blacklist(e, e.target)
        if skipped_private:
            e.results.blacklist_private_ip_skipped = True
        elif bl_result is not None:
            e.results.blacklist = bl_result
    except Exception as ex:
        e.results.blacklist_error = str(ex)
        ctx.out(f"BLACKLIST failed: {ex}", "ERROR", indent=4)
        return
    stream_blacklist_result(e)
