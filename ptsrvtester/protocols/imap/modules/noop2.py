"""NOOP2 — NOOP connection count (pre-auth + post-auth if -u/-p)."""
from ._common import eng

__MODULELABEL__ = "NOOP connection count"
__MODULECODE__ = "NOOP2"
__ORDER__ = 86


def _evaluate_preauth_conn_count(maintained, thresholds):
    """Evaluate pre-auth connection count and return (vulnerable, rating)."""
    vulnerable = False
    rating = "OK"
    
    high_min, significant_min, increased_min = thresholds
    
    if maintained >= high_min:
        rating = "high"
        vulnerable = True
    elif maintained >= significant_min:
        rating = "significant"
        vulnerable = True
    elif maintained >= increased_min:
        rating = "increased"
        vulnerable = True
    
    return vulnerable, rating


def _evaluate_postauth_conn_count(maintained, ip_thresholds, acct_thresholds):
    """Evaluate post-auth connection count and return (vulnerable, rating_ip, rating_acct)."""
    vulnerable = False
    rating_ip = "OK"
    rating_acct = "OK"
    
    ip_high, ip_significant, ip_increased = ip_thresholds
    acct_high, acct_significant, acct_increased = acct_thresholds
    
    # Per-IP limits
    if maintained >= ip_high:
        rating_ip = "high"
        vulnerable = True
    elif maintained >= ip_significant:
        rating_ip = "significant"
        vulnerable = True
    elif maintained >= ip_increased:
        rating_ip = "increased"
        vulnerable = True
    
    # Per-account limits
    if maintained >= acct_high:
        rating_acct = "high"
        vulnerable = True
    elif maintained >= acct_significant:
        rating_acct = "significant"
        vulnerable = True
    elif maintained >= acct_increased:
        rating_acct = "increased"
        vulnerable = True
    
    return vulnerable, rating_ip, rating_acct


def run(ctx):
    e = eng(ctx)
    
    from ..utils.results import (
        IMAP_NOOP_PREAUTH_CONN_HIGH_MIN,
        IMAP_NOOP_PREAUTH_CONN_INCREASED_MIN,
        IMAP_NOOP_PREAUTH_CONN_SIGNIFICANT_MIN,
        IMAP_NOOP_POSTAUTH_CONN_ACCT_HIGH_MIN,
        IMAP_NOOP_POSTAUTH_CONN_ACCT_INCREASED_MIN,
        IMAP_NOOP_POSTAUTH_CONN_ACCT_SIGNIFICANT_MIN,
        IMAP_NOOP_POSTAUTH_CONN_IP_HIGH_MIN,
        IMAP_NOOP_POSTAUTH_CONN_IP_INCREASED_MIN,
        IMAP_NOOP_POSTAUTH_CONN_IP_SIGNIFICANT_MIN,
        VULNS,
    )
    
    # Pre-authentication test
    ctx.out("Pre-authentication", "TITLE", indent=4)
    
    try:
        result_preauth = e.test_noop_conn_count_preauth()
    except Exception as ex:
        ctx.out(f"Test failed: {ex}", "ERROR", indent=8)
        result_preauth = None
    
    if result_preauth and not result_preauth.error_message:
        maintained = result_preauth.connections_maintained
        thresholds = (
            IMAP_NOOP_PREAUTH_CONN_HIGH_MIN,
            IMAP_NOOP_PREAUTH_CONN_SIGNIFICANT_MIN,
            IMAP_NOOP_PREAUTH_CONN_INCREASED_MIN,
        )
        vulnerable, rating = _evaluate_preauth_conn_count(maintained, thresholds)
        
        ctx.out(f"Connections maintained: {maintained}/{result_preauth.connections_established}", "VULN" if vulnerable else "NOTVULN", indent=8)
        
        if vulnerable:
            ctx.out(f"Test duration: {result_preauth.test_duration_seconds:.0f}s", "INFO", indent=12)
            ctx.out(f"NOOPs: {result_preauth.total_noops_ok} OK, {result_preauth.total_noops_error} errors", "INFO", indent=12)
            ctx.report.add_vulnerability(
                vuln_code=VULNS.NoopConnCountPreauth.value,
                vuln_request=f"pre-auth NOOP connection count ({rating})",
            )
        else:
            ctx.out(f"Test duration: {result_preauth.test_duration_seconds:.0f}s", "INFO", indent=12)
            ctx.out(f"NOOPs: {result_preauth.total_noops_ok} OK, {result_preauth.total_noops_error} errors", "INFO", indent=12)
    elif result_preauth:
        ctx.out(f"Test error: {result_preauth.error_message}", "ERROR", indent=8)
    
    # Post-authentication test (if credentials provided)
    if ctx.args.user and ctx.args.password:
        ctx.out("Post-authentication", "TITLE", indent=4)
        
        try:
            result_postauth = e.test_noop_conn_count_postauth(ctx.args.user, ctx.args.password)
        except Exception as ex:
            ctx.out(f"Test failed: {ex}", "ERROR", indent=8)
            result_postauth = None
        
        if result_postauth and not result_postauth.error_message:
            maintained = result_postauth.connections_maintained
            ip_thresholds = (
                IMAP_NOOP_POSTAUTH_CONN_IP_HIGH_MIN,
                IMAP_NOOP_POSTAUTH_CONN_IP_SIGNIFICANT_MIN,
                IMAP_NOOP_POSTAUTH_CONN_IP_INCREASED_MIN,
            )
            acct_thresholds = (
                IMAP_NOOP_POSTAUTH_CONN_ACCT_HIGH_MIN,
                IMAP_NOOP_POSTAUTH_CONN_ACCT_SIGNIFICANT_MIN,
                IMAP_NOOP_POSTAUTH_CONN_ACCT_INCREASED_MIN,
            )
            vulnerable, rating_ip, rating_acct = _evaluate_postauth_conn_count(maintained, ip_thresholds, acct_thresholds)
            
            ctx.out(f"Connections maintained: {maintained}/{result_postauth.connections_established}", "VULN" if vulnerable else "NOTVULN", indent=8)
            
            if vulnerable:
                ctx.out(f"Test duration: {result_postauth.test_duration_seconds:.0f}s", "INFO", indent=12)
                ctx.out(f"NOOPs: {result_postauth.total_noops_ok} OK, {result_postauth.total_noops_error} errors", "INFO", indent=12)
                ctx.report.add_vulnerability(
                    vuln_code=VULNS.NoopConnCountPostauth.value,
                    vuln_request=f"post-auth NOOP connection count (IP:{rating_ip}, account:{rating_acct})",
                )
            else:
                ctx.out(f"Test duration: {result_postauth.test_duration_seconds:.0f}s", "INFO", indent=12)
                ctx.out(f"NOOPs: {result_postauth.total_noops_ok} OK, {result_postauth.total_noops_error} errors", "INFO", indent=12)
        elif result_postauth:
            ctx.out(f"Test error: {result_postauth.error_message}", "ERROR", indent=8)
    else:
        ctx.out("Post-authentication: Skipped (provide -u/--user and -p/--password)", "INFO", indent=4)
