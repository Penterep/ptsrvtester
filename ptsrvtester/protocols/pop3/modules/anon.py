"""ANON — AUTH ANONYMOUS probe."""
from ..utils.connection import auth_anonymous
from ..utils.results import VULNS

__MODULELABEL__ = "Anonymous authentication"
__MODULECODE__ = "ANON"
__ORDER__ = 60


def run(ctx):
    try:
        pop3 = ctx.connect(debug=ctx.debug)
        try:
            enabled, pairs = auth_anonymous(pop3, debug=ctx.debug)
        finally:
            pop3.close()
    except Exception as e:
        ctx.out(f"Anonymous probe failed: {e}", "ERROR", indent=4)
        return

    if enabled is None:
        ctx.out("AUTH ANONYMOUS timed out (not confirmed)", "WARNING", indent=4)
    elif enabled:
        ctx.out("Enabled", "VULN", indent=4)
        if pairs:
            ctx.report.note_poc(VULNS.Anonymous.value, *pairs)
        ctx.report.add_vulnerability(
            vuln_code=VULNS.Anonymous.value,
            vuln_request="anonymous authentication",
        )
    else:
        ctx.out("Disabled", "NOTVULN", indent=4)
