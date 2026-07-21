import re, socket, dns.resolver


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
from ...utils import ptprinthelper
from ...utils.blacklist_parser import BlacklistParser

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from ..helpers import *
from ..results import *
from ..registry import *


class IndirectMixin:

    def test_blacklist(self, target: str) -> tuple[BlacklistResult | None, bool]:
        """Run blacklist check. Returns (result, skipped_private). skipped_private=True for private IP (no API call)."""
        self.ptdebug("Testing target against blacklists:", title=True)
        if self.target_is_ip and _is_private_ip(target):
            self.ptdebug("Blacklist test skipped: private/internal IP (not on public blacklists)", Out.INFO)
            return (None, True)

        blacklist_parser = BlacklistParser(self.ptdebug, self.args.json, self.args.debug)

        try:
            error_msg = blacklist_parser.lookup(target)
        except Exception as e:
            self._fail(str(e))

        if error_msg:
            self.ptdebug(error_msg, Out.VULN)
            # API returned "Cannot test Private IP Address" or similar
            if error_msg == "Cannot test Private IP Address":
                return (None, True)
            # Other error: no result, not "skipped private"
            return (BlacklistResult(False, None), False)

        # Check if result is None or doesn't have the expected structure
        if blacklist_parser.result is None or "table_result" not in blacklist_parser.result:
            return (BlacklistResult(False, None), False)

        listed = [
            BlacklistEntry(r[1], r[2], r[3])
            for r in blacklist_parser.result["table_result"]
            if r[0] == "LISTED"
        ]

        if len(listed) > 0:
            return (BlacklistResult(True, listed), False)
        return (BlacklistResult(False, None), False)

    def _resolver_query(self, resolver, domain, ns, record_type):
        data = resolver.resolve(domain, record_type)
        return [self._rdata_to_str(rdata) for rdata in data]

    def _get_spf_records(self, resolver, domain, ns):
        spf_result = {ns: []}
        try:
            for record in ["SPF", "TXT"]:
                data = resolver.resolve(domain, record)
                for rdata in data:
                    spf_result[ns].append(self._rdata_to_str(rdata))
        except dns.resolver.NoAnswer as e:
            pass
        except dns.resolver.Timeout as e:
            pass
        return spf_result

    def _rdata_to_str(self, rdata):
        str_rdata = str(rdata)
        if str_rdata.startswith('"') and str_rdata.endswith('"'):
            str_rdata = str_rdata[1:-1]
        return str_rdata

    def _get_nameservers(self, domain) -> dict[str, list[str]]:
        self.ptdebug(f"Retrieving SPF records for: {self.target}", title=True)

        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        self.ptdebug(f"Retrieving nameservers for domain: {domain}", title=True)
        try:
            ns_query = resolver.resolve(domain, "NS", tcp=True)
            nameserver_list = [str(rdata)[:-1] for rdata in ns_query]
            self.ptdebug("\n".join(nameserver_list))
        except Exception as e:
            # Make error message more user-friendly
            error_msg = str(e)
            if "does not exist" in error_msg or "NXDOMAIN" in error_msg:
                user_msg = f"Domain '{domain}' does not exist in DNS"
            elif "does not contain an answer" in error_msg or "NoAnswer" in str(type(e).__name__):
                # Check if it's a subdomain
                parts = domain.split('.')
                if len(parts) > 2:
                    main_domain = '.'.join(parts[-2:])
                    user_msg = f"Could not retrieve nameservers for '{domain}'. SPF records are usually on the main domain. Try using '{main_domain}' instead."
                else:
                    user_msg = f"Could not retrieve nameservers for '{domain}'. The domain may not have NS records configured."
            else:
                user_msg = f"Error retrieving nameservers for '{domain}': {error_msg}"
            if self.run_all_mode:
                self._fail(user_msg)
            full_msg = f"{user_msg}\n\nUse 'ptsrvtester smtp -h' for help."
            self.ptjsonlib.end_error(full_msg, self.use_json)
            raise SystemExit

        spf_result = {}
        for ns in nameserver_list:
            try:
                ns_ip = socket.gethostbyname(ns)
            except Exception as e:
                self.ptdebug(f"Exception - {e}", Out.ERROR)
                continue
            resolver.nameservers = [ns_ip]
            spf_result.update({ns: []})
            self.ptdebug(f"{ns}:", Out.INFO)
            spf_result[ns].extend(self._get_spf_for_ns(domain, resolver))

        is_spf_difference = self._check_difference_between_ns_response(spf_result)

        results = {ns: val for ns, val in spf_result.items() if len(val) > 0}
        return results

    def _check_difference_between_ns_response(self, result):
        is_difference = False
        for index, value in enumerate(result.values()):
            for index_2, value_2 in enumerate(result.values()):
                if index == index_2:
                    continue
                if value != value_2:
                    is_difference = True
        if is_difference:
            self.ptdebug(f"Different response between nameservers", Out.VULN)
            return True
        else:
            return False

    def _get_spf_for_ns(self, domain, resolver):
        try:
            result = []
            for dns_type in ["TXT", "SPF"]:
                answer = resolver.resolve(domain, dns_type)
                for rdata in answer:
                    rdata = self._rdata_to_str(rdata)
                    if dns_type == "TXT" and not re.search("v=spf1", rdata):
                        continue
                    result.append(rdata)
                    self.ptdebug(rdata)
        except dns.resolver.NoAnswer as e:
            pass
        except dns.resolver.NoNameservers as e:
            # DNS nameservers failed - return empty result
            return []
        except dns.resolver.Timeout as e:
            raise Exception("Timeout error")
        except Exception as e:
            # Catch any other DNS errors
            self.ptdebug(f"DNS error: {e}", Out.ERROR)
            return []
        return result

    def _stream_blacklist_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (blacklist_error := self.results.blacklist_error) is not None:
            pp(f"Blacklist test failed: {blacklist_error}", bullet_type="VULN", condition=show, indent=4)
            return
        if self.results.blacklist_private_ip_skipped:
            pp(
                "Private/internal IP - blacklist check not applicable (addresses in private ranges are not listed on public blacklists)",
                bullet_type="TITLE", condition=show, indent=4,
            )
            return
        blacklist = self.results.blacklist
        if blacklist is None:
            return
        if not blacklist.listed:
            pp("Clean", bullet_type="NOTVULN", condition=show, indent=4)
        else:
            if (results := blacklist.results) is not None:
                for r in results:
                    r_str = f'{r.blacklist.strip()}: "{r.reason}" (TTL={r.ttl})'
                    pp(r_str, bullet_type="VULN", condition=show, indent=4)

    def _stream_spf_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if self.results.spf_requires_domain:
            pp("Test requires target specified by a domain name", bullet_type="TITLE", condition=show, indent=4)
            return
        if (spf_error := self.results.spf_error) is not None:
            pp(f"SPF test failed: {spf_error}", bullet_type="VULN", condition=show, indent=4)
            return
        spf_records = self.results.spf_records
        if spf_records is None:
            return
        for ns, records in spf_records.items():
            pp(f"Nameserver {ns}", bullet_type="TITLE", condition=show, indent=4)
            for r in records:
                pp(r, bullet_type="TEXT", condition=show, indent=8)
