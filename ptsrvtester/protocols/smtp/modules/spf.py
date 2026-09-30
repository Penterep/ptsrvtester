"""SPF — SPF records for a domain target."""
import re
import socket

import dns.resolver

from ..._base import Out
from ._common import eng

__MODULELABEL__ = "SPF records"
__MODULECODE__ = "SPF"
__ORDER__ = 80


def _rdata_to_str(rdata) -> str:
    str_rdata = str(rdata)
    if str_rdata.startswith('"') and str_rdata.endswith('"'):
        str_rdata = str_rdata[1:-1]
    return str_rdata


def _check_difference_between_ns_response(e, result) -> bool:
    is_difference = False
    values = list(result.values())
    for index, value in enumerate(values):
        for index_2, value_2 in enumerate(values):
            if index == index_2:
                continue
            if value != value_2:
                is_difference = True
    if is_difference:
        e.ptdebug("Different response between nameservers", Out.VULN)
        return True
    return False


def _get_spf_for_ns(e, domain, resolver) -> list[str]:
    try:
        result: list[str] = []
        for dns_type in ["TXT", "SPF"]:
            answer = resolver.resolve(domain, dns_type)
            for rdata in answer:
                record = _rdata_to_str(rdata)
                if dns_type == "TXT" and not re.search("v=spf1", record):
                    continue
                result.append(record)
                e.ptdebug(record)
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NoNameservers:
        return []
    except dns.resolver.Timeout:
        raise Exception("Timeout error")
    except Exception as ex:
        e.ptdebug(f"DNS error: {ex}", Out.ERROR)
        return []
    return result


def get_spf_records(e, domain) -> dict[str, list[str]]:
    e.ptdebug(f"Retrieving SPF records for: {e.target}", title=True)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 10
    resolver.lifetime = 10
    e.ptdebug(f"Retrieving nameservers for domain: {domain}", title=True)
    try:
        ns_query = resolver.resolve(domain, "NS", tcp=True)
        nameserver_list = [str(rdata)[:-1] for rdata in ns_query]
        e.ptdebug("\n".join(nameserver_list))
    except Exception as ex:
        error_msg = str(ex)
        if "does not exist" in error_msg or "NXDOMAIN" in error_msg:
            user_msg = f"Domain '{domain}' does not exist in DNS"
        elif "does not contain an answer" in error_msg or "NoAnswer" in str(type(ex).__name__):
            parts = domain.split(".")
            if len(parts) > 2:
                main_domain = ".".join(parts[-2:])
                user_msg = (
                    f"Could not retrieve nameservers for '{domain}'. "
                    f"SPF records are usually on the main domain. Try using '{main_domain}' instead."
                )
            else:
                user_msg = (
                    f"Could not retrieve nameservers for '{domain}'. "
                    "The domain may not have NS records configured."
                )
        else:
            user_msg = f"Error retrieving nameservers for '{domain}': {error_msg}"
        if e.run_all_mode:
            e._fail(user_msg)
        full_msg = f"{user_msg}\n\nUse 'ptsrvtester smtp -h' for help."
        e.ptjsonlib.end_error(full_msg, e.use_json)
        raise SystemExit

    spf_result: dict[str, list[str]] = {}
    for ns in nameserver_list:
        try:
            ns_ip = socket.gethostbyname(ns)
        except Exception as ex:
            e.ptdebug(f"Exception - {ex}", Out.ERROR)
            continue
        resolver.nameservers = [ns_ip]
        spf_result.update({ns: []})
        e.ptdebug(f"{ns}:", Out.INFO)
        spf_result[ns].extend(_get_spf_for_ns(e, domain, resolver))

    _check_difference_between_ns_response(e, spf_result)
    return {ns: val for ns, val in spf_result.items() if len(val) > 0}


def stream_spf_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if e.results.spf_requires_domain:
        pp("Test requires target specified by a domain name", bullet_type="TITLE", condition=show, indent=4)
        return
    if (spf_error := e.results.spf_error) is not None:
        pp(f"SPF test failed: {spf_error}", bullet_type="VULN", condition=show, indent=4)
        return
    spf_records = e.results.spf_records
    if spf_records is None:
        return
    for ns, records in spf_records.items():
        pp(f"Nameserver {ns}", bullet_type="TITLE", condition=show, indent=4)
        for r in records:
            pp(r, bullet_type="TEXT", condition=show, indent=8)


def run(ctx):
    e = eng(ctx)
    if e.target_is_ip:
        e.results.spf_requires_domain = True
    else:
        try:
            e.results.spf_records = get_spf_records(e, e.target)
        except Exception as ex:
            e.results.spf_error = str(ex)
            ctx.out(f"SPF failed: {ex}", "ERROR", indent=4)
            return
    stream_spf_result(e)
