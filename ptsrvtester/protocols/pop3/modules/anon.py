"""ANON — AUTH ANONYMOUS probe."""
from ..utils.connection import auth_anonymous
from ..utils.results import VULNS

__MODULELABEL__ = "Anonymous authentication"
__MODULECODE__ = "ANON"
__ORDER__ = 60


def run(ctx):
    try:
        pop3 = ctx.connect()
        try:
            enabled = auth_anonymous(pop3)
        finally:
            pop3.close()
    except Exception as e:
        ctx.out(f"Anonymous probe failed: {e}", "ERROR", indent=4)
        return

    if enabled:
        ctx.out("Enabled", "VULN", indent=4)
        ctx.report.add_vulnerability(
            vuln_code=VULNS.Anonymous.value,
            vuln_request="anonymous authentication",
        )
    else:
        ctx.out("Disabled", "NOTVULN", indent=4)
