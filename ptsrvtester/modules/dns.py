from enum import Enum
import dns.resolver
import dns.rdataclass
import dns.message
import dns.query
import dns.zone
import dns.dnssec
import whois 
import argparse
from typing import List, NamedTuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from ptlibs.ptjsonlib import PtJsonLib

from ._base import BaseModule, BaseArgs, Out

class VULNS(Enum):
    ZoneTransfer = "PTV-SNMPv2-ZONETRANFER"
    Subdomains = "PTV-SNMPv3-SUBDOMAINS"
    DNSSEC = "PTV-SNMPv2-DNSSEC"
    ZoneWalk = "PTV-SNMPv3-ZONEWALK"


class info(NamedTuple):
    IP: str | None
    NSID: str | None
    bind_version: str | None   

@dataclass
class DNSResult:
    Info: Optional[List[info]] = None
    ReverseDomain: Optional[dict[str, list[str]]] = None
    ZoneTransfer: Optional[list[str]] = None
    Records: Optional[dict[str, dict[str, list[str]]]] = None
    Whois: Optional[dict[str, str]] = None
    Subdomains:Optional[list[str]] = None
    DNSSEC:Optional[list[str]]= None
    Zonewalk:Optional[list[str]] = None
    Zonewalk_com:Optional[list[str]] = None


class DNSArgs(BaseArgs):
    ip: str 
    port: int
    domain: str 
    subdomains: str 
    ip_file: str
    domain_file:str
    output:str
    command: str
    threads: int

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of SNMP arguments"""

        examples = """example usage:
    ptsrvtester dns whois -d example.com 
    ptsrvtester dns lookup -d example.com
    """
        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError

        dns_subparsers = parser.add_subparsers(dest="command", help="Select DNS command", required=True)

        # DNS info
        dns_info = dns_subparsers.add_parser("info", help="Retrieve DNS server information, including BIND version, NSID, and id.server.")
        dns_info.add_argument("-ip", "--ip", help="IP address of the target DNS server.")
        dns_info.add_argument("-p", "--port", type=int, default=53, help="Port of the DNS server (default: 53).")
        dns_info.add_argument("-ips", "--ip_file", help="File containing a list of target DNS server IP addresses.")

        # Reverse DNS Lookup
        reverse_dns_parser = dns_subparsers.add_parser("reverse-dns", help="Perform a reverse DNS lookup to resolve domain names from IP addresses.")
        reverse_dns_parser.add_argument("-ip", "--ip", help="IP address to perform reverse lookup.")
        reverse_dns_parser.add_argument("-ips", "--ip_file", help="File containing a list of target DNS server IP addresses.")
        
        # Zone Transfer
        zone_transfer_parser = dns_subparsers.add_parser("zone-transfer", help="Attempt a DNS zone transfer to enumerate DNS records from authoritative servers.")
        zone_transfer_parser.add_argument("-d", "--domain", required=True, help="Domain to attempt zone transfer.")
        zone_transfer_parser.add_argument("-o", "--output", help="File to save the output results.")
        
        # DNS Lookup 
        lookup_parser = dns_subparsers.add_parser("lookup", help="Query and display specified DNS records.")
        lookup_parser.add_argument("-d", "--domain", help="Domain name to analyze.")
        lookup_parser.add_argument("-rec", "--lookup-records", nargs='+', help="Specify DNS record types to query (default: A, AAAA, MX, TXT, CNAME, NS, SRV, PTR, SOA).")
        lookup_parser.add_argument("-dl", "--domain_file", help="File containing a list of domains to query.")
        
        # WHOIS Lookup
        whois_parser = dns_subparsers.add_parser("whois", help="Perform a WHOIS lookup to retrieve domain registration details.")
        whois_parser.add_argument("-d", "--domain", help="Domain name to analyze.")
        whois_parser.add_argument("-o", "--output", help="File to save the output results.")
        whois_parser.add_argument("-dl", "--domain_file", help="File containing a list of domains to analyze.")

        # Brute-force Subdomain Enumeration
        brute_subdomains_parser = dns_subparsers.add_parser("brute-subdomains", help="Conduct a brute-force attack to discover subdomains using a specified wordlist.")
        brute_subdomains_parser.add_argument("-d", "--domain", required=True, help="Target domain.")
        brute_subdomains_parser.add_argument("-sub", "--subdomains", required=True, help="Path to subdomains wordlist.")
        brute_subdomains_parser.add_argument("-o", "--output", help="File to save the output results.")
        brute_subdomains_parser.add_argument("-dl", "--domain_file", help="File containing a list of domains to analyze.")
        brute_subdomains_parser.add_argument("--threads", type=int, default=10, help="Number of threads to use for brute-force (default: 10)")
        # DNSSEC Check
        dnssec_parser = dns_subparsers.add_parser("dnssec", help="Check if the target domain has DNSSEC enabled and properly configured.")
        dnssec_parser.add_argument("-d", "--domain", help="Domain to check DNSSEC status.")
        dnssec_parser.add_argument("-dl", "--domain_file", help="File containing a list of domains to analyze.")

        # Zone Walking
        zone_walk_parser = dns_subparsers.add_parser("zone-walk", help="Attempt DNS zone walking using NSEC/NSEC3 records to enumerate available subdomains.")
        zone_walk_parser.add_argument("-d", "--domain", required=True, help="Domain to perform zone walking.")
        zone_walk_parser.add_argument("-o", "--output", help="File to save the output results.")
        
        # Complete Zone Walking
        zone_walk_complete_parser = dns_subparsers.add_parser("zone-walk-complete", help="Perform a full zone walking attempt to enumerate all subdomains using NSEC records.")
        zone_walk_complete_parser.add_argument("-d", "--domain", required=True, help="Domain to perform complete zone walking.")
        zone_walk_complete_parser.add_argument("-o", "--output", help="File to save the output results.")

class DNS(BaseModule):

    @staticmethod
    def module_args():
        return DNSArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: DNSResult | None = None

    def run(self) -> None:

        self.results = DNSResult()

        if self.args.command == "info":
            self.results.Info = self.print_dns_info()

        elif self.args.command == "reverse-dns":
            self.results.ReverseDomain = self.reverseDNS()

        elif self.args.command == "zone-transfer":
            self.results.ZoneTransfer = self.zone_transfer()

        elif self.args.command == "lookup":
            self.results.Records = self.lookup_dns_records(self.args.lookup_records)

        elif self.args.command == "whois":
            self.results.Whois = self.lookup_whois()

        elif self.args.command == "brute-subdomains":
            self.results.Subdomains = self.brute_force_subdomains()

        elif self.args.command == "dnssec":
            self.results.DNSSEC = self.check_dns()

        elif self.args.command == "zone-walk":
            self.results.Zonewalk = self.zone_walking()

        elif self.args.command == "zone-walk-complete":
            self.results.Zonewalk_com = self.zone_walking_complete()

        else:
            self.ptprint("Unknown command for DNS module.", out=Out.WARNING)


    def drawLine(self):
        self.ptprint('-' * 75)

    def drawDoubleLine(self):
        self.ptprint('=' * 75)

    def write_to_file(self, message_or_messages: str | list[str]):
        """
            File Output.
        """
        with open(self.args.output, 'a') as f:
            if isinstance(message_or_messages, str):
                # If it's a single message, write it directly
                f.write(message_or_messages + '\n')
            elif isinstance(message_or_messages, list):
                # If it's a list of messages, iterate and write each one
                for message in message_or_messages:
                    f.write(message + '\n')

    def _text_or_file(self, text: str | None, file_path: str | None):
        """
            One domain/address or file.
        """
        if text:
            return [text.strip()]
        elif file_path:
            try:
                with open(file_path, 'r') as file:
                    return [line.strip() for line in file if line.strip()]
            except Exception as e:
                self.ptprint(f"Error: reading file {file_path}: {e}", out=Out.WARNING)
                return []
        else:
            self.ptprint("Error: Neither text nor file input provided.", out=Out.WARNING)
            return []


    def get_version_bind(self):
        """
            Retrieve the BIND version from the DNS server.
        """
        ip_addrs = self._text_or_file(self.args.ip, self.args.ip_file)
        results = {}
        
        for ip in ip_addrs:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]
            
            try:
                answer = resolver.resolve('version.bind', 'TXT', rdclass=dns.rdataclass.CH)
                results[ip] = [record.to_text() for record in answer]
            except Exception as e:
                results[ip] =f"Error: {e}"
        
        return results
    
    def get_id_server_and_nsid(self):
        """ 
            Retrieve id.server TXT record and NSID from the DNS server. 
        """
        query = dns.message.make_query("id.server", dns.rdatatype.TXT, rdclass=dns.rdataclass.CH)
        query.use_edns(edns=0, ednsflags=0, options=[dns.edns.GenericOption(3, b"")])
        ip_addrs = self._text_or_file(self.args.ip, self.args.ip_file)
        results = {}
        
        for ip in ip_addrs:
            try:
                response = dns.query.udp(query, ip, port=self.args.port, timeout=5)
                id_server = next((item.to_text().strip('"') for answer in response.answer if answer.rdtype == dns.rdatatype.TXT
                                for item in answer.items), None)
                nsid = next((opt.nsid for opt in response.opt[0].options if opt), None) if response.opt else None
                results[ip] = (id_server, nsid)
            except Exception as e:
                results[ip] =f"Error: {e}"
        
        return results
    
    def print_dns_info(self) -> list[info]:
        """ 
            Print formatted DNS information. 
        """

        results: list[info] = []
        decoded_nsid = None
        
        self.drawDoubleLine()
        self.ptprint("Retrieving DNS banner information...", title=True)
        self.drawDoubleLine()
        self.ptprint("{:<20} {:<30}".format("Field", "Value"))
        self.drawLine()
        
        id_server_results = self.get_id_server_and_nsid()
        bind_version_results = self.get_version_bind()
        
        for ip, result in id_server_results.items():
            self.ptprint(f"Results for {ip}:")
            
            # Kontrola, zda je výsledek chybová zpráva
            if isinstance(result, str):
                self.ptprint(result, out=Out.ERROR)
            else:
                id_server, nsid = result
                decoded_nsid = nsid.decode() if nsid and isinstance(nsid, bytes) else None
                self.ptprint("{:<20} {:<30}".format("id.server", id_server if id_server else "Not available"))
                if nsid:
                    self.ptprint("{:<20} {:<30}".format("NSID (raw)", nsid.decode() if nsid and nsid.isascii() else nsid))
                    self.ptprint("{:<20} {:<30}".format("NSID (hex)", nsid.hex()))
            
            # Získání bind.version
            bind_version = bind_version_results.get(ip, ["Not available"])
            self.ptprint("{:<20} {:<30}".format("bind.version", ", ".join(bind_version) if isinstance(bind_version, list) else bind_version))
            self.drawLine()

            results.append(info(ip, decoded_nsid, bind_version))


    def reverseDNS(self) -> dict[str, list[str]]:
        """
            ipv4 addr -----> domain name
        """
        ip_addrs = self._text_or_file(self.args.ip, self.args.ip_file)
        results = {}

        for ip in ip_addrs:
            self.drawDoubleLine()
            self.ptprint(f"Performing reverse DNS lookup for {ip}...", title=True)
            self.drawDoubleLine()

            try:
                rev_name = dns.reversename.from_address(ip)  # Převod IP na reverzní formát
                response = dns.resolver.resolve(rev_name, "PTR")  # Dotaz na PTR záznam
                domains = [str(r) for r in response]  # Konverze výsledků na stringy
                answer = ', '.join(domains) if domains else "No PTR record"
                results[ip] = domains if domains else ["No PTR record"]
                self.ptprint("{:30} {:15}\n".format(ip, answer.rstrip('.')))
            except dns.resolver.NXDOMAIN:
                self.ptprint(f"Error: No PTR record found for {ip}", out=Out.ERROR)
                
            except dns.resolver.NoAnswer:
                self.ptprint(f"Error: No answer for PTR record query on {ip}", out=Out.ERROR)
            
            except dns.resolver.Timeout:
                self.ptprint(f"Error: Query timeout for {ip}", out=Out.WARNING)
           

        return results if results else []

    def resolveDNS(self, name):
        """
            domain name -----> ipv4 addr
        """
        resolver = dns.resolver.Resolver()
        try:
            results = resolver.resolve(name, "A")
            return results
        except dns.resolver.NoAnswer:
            self.ptprint(f"{name:<50} No A record found")
            return []
        

    def getNS (self, domain):
        """
            Name serververs for the domain.
        """
        mapping = {}
        try:
            name_servers = dns.resolver.resolve(domain, 'NS')
            for name_server in name_servers:
                A_records = self.resolveDNS(str(name_server))
                for item in A_records:
                    answer = ','.join([str(item)])
                mapping[str(name_server)] = answer
                self.ptprint("{:<50} {:<15}".format(str(name_server).rstrip('.'), answer))     
            return mapping
        
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
            self.ptprint(f"Error: Unable to retrieve authoritative NS - {e}", out=Out.ERROR)
            return None
    
    

    def zoneXFR(self, server):
        """
            Zone transfer from the name server
        """
        found_domains = []

        try:
            zone = dns.zone.from_xfr(dns.query.xfr(str(server).rstrip('.'), self.args.domain))
        except Exception as e:
            self.ptprint(f"Error: {e.__class__} {e}", out=Out.ERROR)
        else:
            for host in zone:
                found_domains.append(f"{host}.{self.args.domain}")
                if str(host) != '@':
                    A_records = self.resolveDNS(str(host) + "." + self.args.domain)
                    if A_records: 
                        found_domains.remove(f"{host}.{self.args.domain}") 
                        for item in A_records:
                            answer = ','.join([str(item)]) 
                        found_domains.append(f"{host}.{self.args.domain};{answer}")
                        fulldomain = f"{str(host)}.{self.args.domain}"
                        self.ptprint(f"{fulldomain:<50} {answer}")
            return found_domains


    def zone_transfer(self) -> list[str]:
        """
            Zone transfer formated output

            returns list of nameserver which allows zone transfer
        """
        result = []
        any_domains_found = False

        self.drawDoubleLine()
        self.ptprint(f"Retrieving name servers for {self.args.domain}...", title=True)
        self.drawDoubleLine()
        name_servers = self.getNS(self.args.domain)
        self.drawLine()
        if name_servers == None:
            self.ptprint(f"Error: Unable to start zone transfer for {self.args.domain}", out=Out.ERROR)
        else:
            for server in name_servers:
                self.ptprint("\n")
                self.ptprint(f"Attempting zone transfer from {server} ({name_servers[server]})...", out=Out.TITLE)
                self.drawLine()
                found_domains = self.zoneXFR(name_servers[server])
                if self.args.output:
                    self.write_to_file(found_domains)
                if found_domains:
                     result.append(server) 
                  
        return result



    def lookup_dns_records(self, record_types=None, banner = True) ->  dict[str, dict[str, list[str]]]:
        """
             Retrieve DNS records from the domain.
        """
        results = {}
        if record_types is None:
            # Default list
            record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SRV", "PTR", "SOA"]
        
        domains = self._text_or_file(self.args.domain, self.args.domain_file)
        for domain in domains:

            if banner:
                self.drawDoubleLine()
                self.ptprint(f"Querying DNS records for {domain}...", title=True)
                self.drawDoubleLine()
            self.ptprint("{:<15} {:<30}".format("Record type", "Value"))
            self.drawLine()

            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records = [str(r) for r in answers]

                    if domain not in results:
                        results[domain] = {}
                    results[domain][record_type] = records

                    self.ptprint("{:<15} {:<30}".format(record_type, ", ".join(records)))
                except dns.resolver.NXDOMAIN:
                    self.ptprint(f"{record_type:<15} No records found (NXDOMAIN)")
                except dns.resolver.NoAnswer:
                    self.ptprint(f"{record_type:<15} No answer")
                except dns.resolver.Timeout:
                    self.ptprint(f"{record_type:<15} Query timeout")
                except dns.resolver.NoNameservers:
                    self.ptprint(f"{record_type:<15} No available name servers")
                except Exception as e:
                    self.ptprint(f"{record_type:<15} Error - {e}")

        return results
    
    def lookup_whois(self) -> dict[str, str]:
        """
            Perform a WHOIS lookup for a given domain.
        """
        results = {}
        domains = self._text_or_file(self.args.domain, self.args.domain_file)
        for domain in domains:
            self.drawDoubleLine()
            self.ptprint(f"Querying WHOIS information for {domain}...", title=True)
            self.drawDoubleLine()

            try:
                info = whois.whois(domain)  # all whois records
                whois_text = info.text if hasattr(info, "text") else str(info) 
                self.ptprint(whois_text)

                results[domain] = whois_text
                
                if self.args.output:
                    self.write_to_file(whois_text)

            except Exception as e:
                self.ptprint(f"Error: {e}", out=Out.WARNING)
                
        return results

    def brute_force_subdomains(self) -> list[str]:
        """
            Perform a brute-force attack to find subdomains using a wordlist.
        """
        domains = self._text_or_file(self.args.domain, self.args.domain_file)
        for domain in domains:
            self.drawDoubleLine()
            self.ptprint(f"Starting brute-force attack on subdomains for {domain}...", title=True)
            self.drawDoubleLine()

            found_subdomains = []
            output = []
            record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SRV", "PTR", "SOA"]

            try: 
                with open(self.args.subdomains, "r") as f:
                    subdomains = [line.strip() for line in f]

                def resolve_subdomain(sub: str):
                    subdomain = f"{sub}.{domain}"
                    subdomain_records = {}
                    for record_type in record_types:
                        try:
                            answers = dns.resolver.resolve(subdomain, record_type)
                            subdomain_records[record_type] = [str(r) for r in answers]
                        except Exception:
                            continue
                    if subdomain_records:
                        return (subdomain, subdomain_records)
                    return None

                with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                    futures = [executor.submit(resolve_subdomain, sub) for sub in subdomains]
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            subdomain, records = result
                            found_subdomains.append((subdomain, records))
                            output.append(subdomain)
                            self.ptprint(f"Found: {subdomain}", out=Out.OK)
                            for rtype, values in records.items():
                                self.ptprint(f"   └── {rtype}: {', '.join(values)}")

                self.ptprint("\n")
                self.ptprint(f"Brute-force attack completed. Found {len(found_subdomains)} subdomains.", out=Out.INFO)
                if self.args.output:
                    self.write_to_file(output)

                results = [sub[0] for sub in found_subdomains]
                return results

            except FileNotFoundError:
                self.ptprint(f"Wordlist file {self.args.subdomains} not found.", out=Out.WARNING)
                return None
        
    def get_nsip(self, domain):
        """
            Get authoritatve nameserver for the domain and its ip address
        """
        try:
            # Get authoritative nameservers for the domain
            ns_response = dns.resolver.resolve(domain, dns.rdatatype.NS)
            ns_name = str(ns_response.rrset[0])

            # Use resolveDNS() to get the NS IP address
            ns_ip_results = self.resolveDNS(ns_name)
            if not ns_ip_results:
                self.ptprint(f"Error: No IP found for NS {ns_name}", out=Out.WARNING)
                return None

            else:
                ns_ip = str(ns_ip_results[0])
                return ns_ip

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
            self.ptprint(f"Error: Unable to retrieve authoritative NS - {e}", out=Out.ERROR)
            return None

    
    def check_dns(self) -> list[str] | None:
        """
            Check if the domain has DNSSEC.
        """
        insecure_domains = []
        domains = self._text_or_file(self.args.domain, self.args.domain_file)
        for domain in domains:
            self.drawDoubleLine()
            self.ptprint(f"Checking DNSSEC on {domain}...", title=True)
            self.drawDoubleLine()

            domain = domain.rstrip(".") + "."
            ns_ip = self.get_nsip(domain)

            try:
                # Query for DNSKEY records with DNSSEC support
                request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
                response = dns.query.udp(request, ns_ip, timeout=10)

                if response.rcode() != 0:
                    self.ptprint("Error: No DNSKEY record found", out=Out.ERROR)
                    insecure_domains.append(domain)
                    

                # Check if the response contains DNSKEY and RRSIG(DNSKEY)
                if len(response.answer) < 2:
                    self.ptprint("DNSSEC is NOT properly set! (Missing DNSSEC signatures RRSIG/DNSKEY)", out=Out.WARNING)
                    self.ptprint("Status: Insecure", out=Out.ERROR)
                    

                # Extract DNSKEY and RRSIG records
                dnskey_rrset = response.answer[0]
                rrsig_rrset = response.answer[1]

                # Validate the self-signed DNSKEY
                name = dns.name.from_text(domain)
                dns.dnssec.validate(dnskey_rrset, rrsig_rrset, {name: dnskey_rrset})

                self.ptprint("DNSSEC is ENABLED and properly signed!", out=Out.OK)
                self.ptprint("Status: Secure", out=Out.OK)
                self.ptprint("\n")
                self.ptprint("DNSKEY Details:", out=Out.INFO)
                self.drawLine()

                for key in dnskey_rrset:
                    key_id = dns.dnssec.key_id(key)  # Extract Key ID (Key Tag)
                    algorithm = dns.dnssec.algorithm_to_text(key.algorithm)  # Get signing algorithm
                    key_type = "KSK" if key.flags == 257 else "ZSK"  # 257 = KSK, 256 = ZSK

                    self.ptprint(f"{'Key ID:':<20} {key_id:<30}")
                    self.ptprint(f"{'Algorithm:':<20} {algorithm:<30}")
                    self.ptprint(f"{'Key Type:':<20} {key_type:<30}\n")

            except dns.dnssec.ValidationFailure:
                self.ptprint("DNSSEC validation failed! Domain is NOT properly signed.", out=Out.WARNING)
                self.ptprint("Status: Insecure", out=Out.ERROR)
                insecure_domains.append(domain)
                
            except dns.exception.Timeout:
                self.ptprint("Error: DNSSEC validation timeout.", out=Out.WARNING)
                insecure_domains.append(domain)
                
            except Exception as e:
                self.ptprint(f"Error: Unexpected error - {e}", out=Out.WARNING)

        return insecure_domains
                

    def zone_walking(self) -> list[str] | None:
        """
            Attempts to enumerate subdomains using NSEC/NSEC3 DNSSEC records.
        """

        self.drawDoubleLine()
        self.ptprint(f"Starting zone walking for {self.args.domain} using NSEC/NSEC3", title=True)
        self.drawDoubleLine()

        domain = self.args.domain.rstrip(".") + "."

        ns_ip = self.get_nsip(domain)


        # Means that the given domain doesnt exist
        if ns_ip == None:
            self.drawLine()
            split_domain = domain.split(".")

            for i in range(1, len(split_domain) - 1):  # Start from parent domains
                parent_domain = ".".join(split_domain[i:])
                ns_ip = self.get_nsip(parent_domain)

                if ns_ip != None:
                    break

        try:
            # Query for NSEC/NSEC3 records
            request = dns.message.make_query(domain, dns.rdatatype.NSEC, want_dnssec=True)
            response = dns.query.udp(request, ns_ip, timeout=10)
 
            found_subdomains = []    #NSEC
            hashed_subdomains = []   #NSEC3

            for rrset in response.authority:
                #NSEC
                if rrset.rdtype == dns.rdatatype.NSEC:
                    owner = rrset.name.to_text().rstrip(".")  # Current domain in the NSEC chain
                    found_subdomains.append(owner)  # Store the owner name (existing domain)
                    next_domain = rrset[0].next.to_text().rstrip(".")
                    found_subdomains.append(next_domain)  # Store next domain

                #NSEC3
                if rrset.rdtype == dns.rdatatype.NSEC3:
                    for rrset in response.authority:
                        domain_hash = rrset.name.to_text().rstrip(".")  # Extract the NSEC3 hashed domain
                        hashed_subdomains.append(domain_hash)  # Add to set to avoid duplicates

            self.ptprint("\n")
            self.ptprint(f"Zone walking results using NSEC/NSEC3 records:", out=Out.INFO)
            self.drawLine()

            if found_subdomains:
                if self.args.output: 
                    self.write_to_file(list(dict.fromkeys(found_subdomains)))
                for sub in dict.fromkeys(found_subdomains):
                    self.ptprint(f"{sub}")
                found_subdomains = list(dict.fromkeys(found_subdomains))
                return found_subdomains

            elif hashed_subdomains:
                if self.args.output: 
                    self.write_to_file(list(dict.fromkeys(hashed_subdomains)))
                for hashed in dict.fromkeys(hashed_subdomains):
                    self.ptprint(f"{hashed}")
                hashed_subdomains=list(dict.fromkeys(hashed_subdomains))
                return hashed_subdomains

            else: 
                self.ptprint("No subdomains discovered.", out=Out.ERROR)
                return None 
        
        except dns.exception.Timeout:
            self.ptprint("Error: Query timeout for NSEC enumeration.", out=Out.WARNING)
            return None
        except Exception as e:
            self.ptprint(f"Error: Unexpected error - {e}", out=Out.WARNING)
            return None
        

    def zone_walking_complete(self) -> list[str] | None:
        """
            Attempts to enumerate subdomains using NSEC.
        """
        
        self.drawDoubleLine()
        self.ptprint(f"Starting complete zone walking using NSEC from {self.args.domain}", title=True)
        self.drawDoubleLine()

        domain = self.args.domain.rstrip(".") + "."
        ns_ip = self.get_nsip(domain)


        # Means that the given domain doesnt exist
        if ns_ip == None:
            self.drawLine()
            split_domain = domain.split(".")

            for i in range(1, len(split_domain) - 1):  # Start from parent domains
                parent_domain = ".".join(split_domain[i:])
                ns_ip = self.get_nsip(parent_domain)

                if ns_ip != None:
                    break

        queue = [domain]  # Start with the given domain
        found_subdomains = []
        count = 0
        

        try:
            while queue and count != 3:
                last_len = len(found_subdomains)
                current_domain = queue.pop(0)

                # Query for NSEC records
                request = dns.message.make_query(current_domain, dns.rdatatype.NSEC, want_dnssec=True)
                response = dns.query.udp(request, ns_ip, timeout=10)

                for rrset in response.authority:
                    #NSEC
                    if rrset.rdtype == dns.rdatatype.NSEC:
                        owner = rrset.name.to_text().rstrip(".")  # Current domain in the NSEC chain
                        next_domain = rrset[0].next.to_text().rstrip(".")

                        if owner not in found_subdomains:
                            found_subdomains.append(owner)

                        if next_domain and next_domain not in found_subdomains:
                            found_subdomains.append(next_domain)

                        next_domain = "0." + next_domain
                        queue.append(next_domain)  # Queue next domain for walking
                        current_len = len(found_subdomains)

                        if current_len == last_len:
                            count += 1
                        else:
                            count = 0

            self.ptprint("\n")
            self.ptprint(f"Complete zone walking results using NSEC records:", out=Out.INFO)
            self.drawLine()

            unique_subs = list(dict.fromkeys(found_subdomains)) #to awoid duplicities

            if found_subdomains:
                for sub in sorted(unique_subs):
                    self.ptprint(sub)
                if self.args.output: 
                    self.write_to_file(unique_subs)
                return unique_subs

            else: 
                self.ptprint("No subdomains discovered.", out=Out.ERROR)
                return None 
        
        except dns.exception.Timeout:
            self.ptprint("Error: Query timeout for NSEC enumeration.", out=Out.WARNING)
            return None
        except Exception as e:
            self.ptprint(f"Error: Unexpected error - {e}", out=Out.WARNING)
            return None
        
    def output(self) -> None:
        """
        Info: Optional[List[info]] = None
        ReverseDomain: Optional[dict[str, list[str]]] = None
        ZoneTransfer: Optional[list[str]] = None
        Records: Optional[dict[str, list[str]]] = None
        Whois: Optional[dict[str, str]] = None
        Subdomains:Optional[list[str]] = None
        DNSSEC:Optional[bool]= None
        Zonewalk:Optional[list[str]] = None
        Zonewalk_com:Optional[list[str]] = None

        ZoneTransfer = "PTV-SNMPv2-ZONETRANFER"
        Subdomains = "PTV-SNMPv3-SUBDOMAINS"
        DNSSEC = "PTV-SNMPv2-DNSSEC"
        ZoneWalk = "PTV-SNMPv3-ZONEWALK"
        """

        if (self.results.ZoneTransfer != None):
            if len(self.results.ZoneTransfer) != 0:
                #domains of nameservers which allows Zone Transfer
                self.ptjsonlib.add_vulnerability(VULNS.ZoneTransfer.value, "Testing for Zone transfer", ",".join(self.results.ZoneTransfer))
        
        if (self.results.Subdomains != None):
            if len(self.results.Subdomains) != 0:
                self.ptjsonlib.add_vulnerability(VULNS.Subdomains.value, "Subdomains discovered via brute-force enumeration", ",".join(self.results.Subdomains))

        if (self.results.DNSSEC != None):
            if len(self.results.DNSSEC) != 0:
                self.ptjsonlib.add_vulnerability(VULNS.DNSSEC.value, "Domains without DNSSEC or with invalid DNSSEC configuration", ",".join(self.results.DNSSEC)) 

        if (self.results.Zonewalk != None):
            if len(self.results.Zonewalk) != 0:
                self.ptjsonlib.add_vulnerability(VULNS.ZoneWalk.value, "Subdomains discovered via DNS zone walking (NSEC/NSEC3)", ",".join(self.results.Zonewalk))
        

        self.ptprint(self.ptjsonlib.get_result_json(), json=True)