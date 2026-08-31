"""NOOP1 — NOOP connection duration (pre-auth + post-auth if -u/-p)."""
from ._common import eng

__MODULELABEL__ = "NOOP connection duration"
__MODULECODE__ = "NOOP1"
__ORDER__ = 85


def _evaluate_duration(result, thresholds):
    """Evaluate duration result and return (vulnerable, rating)."""
    maintained_min = result.maintained_seconds / 60.0
    vulnerable = False
    rating = "OK"
    
    high_min, significant_min, increased_min = thresholds
    
    if result.hit_test_cap:
        if result.maintained_seconds >= high_min:
            rating = "high"
            vulnerable = True
        elif result.maintained_seconds >= significant_min:
            rating = "significant"
            vulnerable = True
        elif result.maintained_seconds >= increased_min:
            rating = "increased"
            vulnerable = True
    elif result.disconnected:
        if result.disconnect_after_seconds and result.disconnect_after_seconds >= high_min:
            rating = "high"
            vulnerable = True
        elif result.disconnect_after_seconds and result.disconnect_after_seconds >= significant_min:
            rating = "significant"
            vulnerable = True
        elif result.disconnect_after_seconds and result.disconnect_after_seconds >= increased_min:
            rating = "increased"
            vulnerable = True
    
    return vulnerable, rating, maintained_min


def run(ctx):
    e = eng(ctx)
    
    from ..utils.results import (
        IMAP_NOOP_PREAUTH_DUR_HIGH_MIN,
        IMAP_NOOP_PREAUTH_DUR_INCREASED_MIN,
        IMAP_NOOP_PREAUTH_DUR_SIGNIFICANT_MIN,
        IMAP_NOOP_POSTAUTH_DUR_HIGH_MIN,
        IMAP_NOOP_POSTAUTH_DUR_INCREASED_MIN,
        IMAP_NOOP_POSTAUTH_DUR_SIGNIFICANT_MIN,
        VULNS,
    )
    
    # Pre-authentication test
    ctx.out("Pre-authentication", "TITLE", indent=4)
    
    try:
        result_preauth = e.test_noop_duration_preauth()
    except Exception as ex:
        ctx.out(f"Test failed: {ex}", "ERROR", indent=8)
        result_preauth = None
    
    if result_preauth and not result_preauth.error_message:
        thresholds = (
            IMAP_NOOP_PREAUTH_DUR_HIGH_MIN,
            IMAP_NOOP_PREAUTH_DUR_SIGNIFICANT_MIN,
            IMAP_NOOP_PREAUTH_DUR_INCREASED_MIN,
        )
        vulnerable, rating, maintained_min = _evaluate_duration(result_preauth, thresholds)
        
        if result_preauth.hit_test_cap:
            ctx.out(f"Connection maintained: >{maintained_min:.1f} min (unlimited)", "VULN" if vulnerable else "NOTVULN", indent=8)
        elif result_preauth.disconnected:
            disconnect_min = result_preauth.disconnect_after_seconds / 60.0 if result_preauth.disconnect_after_seconds else 0
            ctx.out(f"Connection maintained: {disconnect_min:.1f} min", "VULN" if vulnerable else "NOTVULN", indent=8)
        
        if vulnerable:
            ctx.out(f"Rating: {rating}", "VULN", indent=12)
            ctx.out(f"NOOPs: {result_preauth.noops_sent} sent, {result_preauth.noops_ok} OK, {result_preauth.noops_error} errors", "INFO", indent=12)
            ctx.report.add_vulnerability(
                vuln_code=VULNS.NoopDurationPreauth.value,
                vuln_request=f"pre-auth NOOP duration ({rating})",
            )
        else:
            ctx.out(f"NOOPs: {result_preauth.noops_sent} sent, {result_preauth.noops_ok} OK, {result_preauth.noops_error} errors", "INFO", indent=12)
    elif result_preauth:
        ctx.out(f"Test error: {result_preauth.error_message}", "ERROR", indent=8)
    
    # Post-authentication test (if credentials provided)
    if ctx.args.user and ctx.args.password:
        ctx.out("Post-authentication", "TITLE", indent=4)
        
        try:
            result_postauth = e.test_noop_duration_postauth(ctx.args.user, ctx.args.password)
        except Exception as ex:
            ctx.out(f"Test failed: {ex}", "ERROR", indent=8)
            result_postauth = None
        
        if result_postauth and not result_postauth.error_message:
            thresholds = (
                IMAP_NOOP_POSTAUTH_DUR_HIGH_MIN,
                IMAP_NOOP_POSTAUTH_DUR_SIGNIFICANT_MIN,
                IMAP_NOOP_POSTAUTH_DUR_INCREASED_MIN,
            )
            vulnerable, rating, maintained_min = _evaluate_duration(result_postauth, thresholds)
            
            if result_postauth.hit_test_cap:
                ctx.out(f"Connection maintained: >{maintained_min:.1f} min (unlimited)", "VULN" if vulnerable else "NOTVULN", indent=8)
            elif result_postauth.disconnected:
                disconnect_min = result_postauth.disconnect_after_seconds / 60.0 if result_postauth.disconnect_after_seconds else 0
                ctx.out(f"Connection maintained: {disconnect_min:.1f} min", "VULN" if vulnerable else "NOTVULN", indent=8)
            
            if vulnerable:
                ctx.out(f"Rating: {rating}", "VULN", indent=12)
                ctx.out(f"NOOPs: {result_postauth.noops_sent} sent, {result_postauth.noops_ok} OK, {result_postauth.noops_error} errors", "INFO", indent=12)
                ctx.report.add_vulnerability(
                    vuln_code=VULNS.NoopDurationPostauth.value,
                    vuln_request=f"post-auth NOOP duration ({rating})",
                )
            else:
                ctx.out(f"NOOPs: {result_postauth.noops_sent} sent, {result_postauth.noops_ok} OK, {result_postauth.noops_error} errors", "INFO", indent=12)
        elif result_postauth:
            ctx.out(f"Test error: {result_postauth.error_message}", "ERROR", indent=8)
    else:
        ctx.out("Post-authentication: Skipped (provide -u/--user and -p/--password)", "INFO", indent=4)
