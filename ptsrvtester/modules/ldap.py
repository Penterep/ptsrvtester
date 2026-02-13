from dataclasses import dataclass
from enum import Enum
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from typing import  List, NamedTuple, Optional
import argparse 
from concurrent.futures import ThreadPoolExecutor, as_completed

from ptlibs.ptjsonlib import PtJsonLib

from ._base import BaseModule, BaseArgs, Out
from .utils.helpers import text_or_file

class VULNS(Enum):
    WeakUsername = "PTV-LDAP-WEAKUSERNAME"
    WeakCredentials = "PTV-LDAP-WEAKCREDENTIALS"
    Write = "PTV-LDAP-WRITEACCESS"

class Credential(NamedTuple):
    username: str | None
    password: str | None

class TestWriteResult(NamedTuple):
    target_dn: str | None
    atribute: str | None
    value: str | None
    credentials: str | None


@dataclass
class LDAPResult:
    Banner: Optional[dict] = None
    Search: Optional[list[dict]] = None
    usernames: Optional[list[str]] = None
    credentials: Optional[list[Credential]] = None
    Writetest: Optional[TestWriteResult] = None

class LDAPArgs(BaseArgs):
    ip: str
    port:int = 389
    command:str
    use_ssl:bool = False
    spray:bool = False
    output:str = None
    base_dn:str = None
    upn_domain:str=None
    username_file:str = None
    password_file:str = None
    user:str = None
    password:str = None
    ldap_filter:str ='(ObjectClass=*)'
    attributes: list[str] = None
    search_attribute: str = 'uid'
    cn_uid: list = ['uid', 'cn']
    target_dn:str = None
    attribute:str = 'sn'
    test_value:str = None
    threads:int

    @staticmethod
    def get_help():
        return [
            {"description": ["LDAP Testing Module"]},
            {"usage": ["ptsrvtester ldap <command> <options>"]},
            {"usage_example": [
                "ptsrvtester ldap banner -ip 192.168.1.1",
                "ptsrvtester ldap search -ip 192.168.1.1 -bd \"dc=example,dc=com\"",
                "ptsrvtester ldap userenum -ip 192.168.1.1 -ul usernames.txt"
            ]},
            {"options": [
                ["banner", "<options>", "", "Retrieve LDAP server banner"],
                ["search", "<options>", "", "Perform LDAP search query"],
                ["userenum", "<options>", "", "Enumerate valid LDAP users"],
                ["bruteforce", "<options>", "", "Brute-force LDAP credentials"],
                ["writetest", "<options>", "", "Test write permissions"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of SNMP arguments"""

        examples = """example usage:
        ptsrvtester ldap banner -ip 192.168.1.1
        ptsrvtester ldap search -ip 192.168.1.1 -bd "dc=example,dc=com" -f "(uid=user)"
        ptsrvtester ldap userenum -ip 192.168.1.1 -ul usernames.txt -bd "dc=example,dc=com"
        """

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError

        ldap_subparsers = parser.add_subparsers(dest="command", help="Select LDAP command", required=True)
    
        # Banner grabbing
        banner_parser = ldap_subparsers.add_parser("banner", help="Retrieve LDAP server banner information")
        banner_parser.add_argument("-ip", required=True, help="Target IP address")
        banner_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
        banner_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
        banner_parser.add_argument("-u", "--user", help="Username for authenticated bind (format: cn=admin,dc=example,dc=com OR user@example.com)")
        banner_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
        banner_parser.add_argument("-o", "--output", help="Output file to save results")

        # LDAP search
        search_parser = ldap_subparsers.add_parser("search", help="Perform LDAP search query")
        search_parser.add_argument("-ip", required=True, help="Target IP address")
        search_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
        search_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
        search_parser.add_argument("-u", "--user", help="Username for authenticated bind")
        search_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
        search_parser.add_argument("-bd", "--base-dn", help="Base DN (example: dc=example,dc=com). If not provided, it tries to auto-detect.")
        search_parser.add_argument("-f", "--filter", dest="ldap_filter", default="(objectClass=*)", help="""
                                                                                            LDAP search filter (RFC 4515 format).\n
                                                                                            Supports complex expressions with logical operators AND (&), OR (|), and NOT (!).\n\n

                                                                                            Examples:\n
                                                                                            "(objectClass=person)"              - Match all persons\n
                                                                                            "(uid=admin)"                       - Exact UID match\n
                                                                                            "(&(sn=Newton)(cn=Isaac Newton))"  - Match users with surname 'Newton' AND full name 'Isaac Newton'\n
                                                                                            "(|(uid=gauss)(uid=riemann))"      - Match users with UID 'gauss' OR 'riemann'\n
                                                                                            """
                                                                                            )
        search_parser.add_argument("-a", "--attributes", nargs='+', help="List of attributes to retrieve (example: cn mail sn). Default: all")
        search_parser.add_argument("-o", "--output", help="Output file to save results")

        # User Enumeration
        enum_parser = ldap_subparsers.add_parser("userenum", help="Enumerate valid LDAP users")
        enum_parser.add_argument("-ip", required=True, help="Target IP address")
        enum_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
        enum_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
        enum_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
        enum_parser.add_argument("-bd", "--base-dn", help="Base DN (recommended, but can try to auto-detect)")
        enum_parser.add_argument("-o", "--output", help="Output file to save results")
        enum_parser.add_argument("-ul", "--username_file", required=True, help="Username list file (one username per line)")
        enum_parser.add_argument("-u", "--user", help="Username for authenticated bind")

        # Brute-force
        brute_parser = ldap_subparsers.add_parser("bruteforce", help="Brute-force LDAP user credentials")
        brute_parser.add_argument("-ip", required=True, help="Target IP address")
        brute_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
        brute_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
        brute_parser.add_argument("-bd", "--base-dn", help="Base DN (example: dc=example,dc=com)")
        brute_parser.add_argument("-upn", "--upn-domain", help="UPN domain (example: example.com)")
        brute_parser.add_argument("-spray", action="store_true", help="Enable password spraying mode (one password across all users)")
        brute_parser.add_argument("--threads", type=int, default=10, help="Number of threads for parallel brute-force (default: 10)")
        brute_parser.add_argument("-o", "--output", help="Output file to save valid credentials")
        brute_parser.add_argument("-cnuid", nargs='+', default=['uid', 'cn'], help="Attributes to bind with (default: uid and cn)")

        user_group = brute_parser.add_mutually_exclusive_group(required=True)
        user_group.add_argument("-ul", "--username_file", help="Username list file (required if -u not provided)")
        user_group.add_argument("-u", "--user", help="Single username to try (required if -ul not used)")

        pass_group = brute_parser.add_mutually_exclusive_group(required=True)
        pass_group.add_argument("-pl", "--password_file", help="Password list file (required if -pw not provided)")
        pass_group.add_argument("-pw", "--password", help="Single password to try (required if -pl not used)")
        

        # Write-access Test
        # ToDo: potreba otestovat
        write_parser = ldap_subparsers.add_parser("writetest", help="Test write permissions on LDAP entries")
        write_parser.add_argument("-ip", required=True, help="Target IP address")
        write_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
        write_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
        write_parser.add_argument("-u", "--user", help="Username for authenticated bind")
        write_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
        write_parser.add_argument("-bd", "--base-dn", help="Base DN (for finding entries)")
        write_parser.add_argument("-t", "--target-dn", help="Specific DN to test writing to (Dfault: objectClass=person)")
        write_parser.add_argument("-attr", "--attribute", default="sn", help="Attribute to modify (default: sn)")
        write_parser.add_argument("-val", "--value", dest="test_value", help="Custom value to write instead of default: SecurityTest123")



class LDAP(BaseModule):
    @staticmethod
    def module_args():
        return LDAPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        self.args = args 
        self.ptjsonlib = ptjsonlib
        self.results: LDAPResult | None = None

    def run(self) -> None:
        """Main LDAP execution logic"""

        self.results = LDAPResult()

        if self.args.command == "banner":
            self.results.Banner = self.ldap_banner()
        
        elif self.args.command == "search":
            self.results.Search = self.ldap_search()
        
        elif self.args.command == "userenum":
            self.results.usernames = self.ldap_enumerate_users()

        elif self.args.command == "bruteforce":
            self.results.credentials = self.ldap_bruteforce()

        elif self.args.command == "writetest":
            self.results.Writetest = self.ldap_check_write_access()
        
        else:
            self.ptprint("Unknown command for LDAP module.", out=Out.WARNING)
        

    def drawLine(self):
        self.ptprint('-' * 75)

    def drawDoubleLine(self):
        self.ptprint('=' * 75)

    def write_to_file(self, message_or_messages: str | list[str]):
        """
            File Output.
        """
        try:
            with open(self.args.output, "a") as f:
                if isinstance(message_or_messages, str):
                    f.write(message_or_messages + "\n")
                elif isinstance(message_or_messages, list):
                    for message in message_or_messages:
                        f.write(message + "\n")
        except FileNotFoundError:
            raise argparse.ArgumentError(None, f"File not found: '{self.args.output}'")
        except PermissionError:
            raise argparse.ArgumentError(
                None, f"Cannot write file (permission denied): '{self.args.output}'"
            )
        except OSError as e:
            raise argparse.ArgumentError(None, f"Cannot write file '{self.args.output}': {e}")

    def _text_or_file(self, text: str | None, file_path: str | None):
        """
            One domain/address or file.
        """
        values = text_or_file(text.strip() if text else None, file_path)
        return [v.strip() for v in values if v.strip()]
        
    def print_title(self, title):
                self.ptprint("\n")
                self.ptprint(f"{title}", out=Out.TITLE)
                self.ptprint('-' * (len(title) + 6))
    
    def print_subtitle(self, title):
        self.ptprint(f"  - {title}")

    def print_list(self, title, items):
        self.print_title(title)
        if items:
            for item in items:
                self.ptprint(f"  - {item}")
        else:
            self.ptprint("    No data found.")

    def create_ldap_connection(self):
        """
        Establishes an LDAP connection and returns the connection object.
        """
        try:
            server = Server(self.args.ip, port=self.args.port, use_ssl=self.args.use_ssl, get_info=ALL)
            if self.args.user and self.args.password:
                conn = Connection(server, user=self.args.user, password=self.args.password, auto_bind=True)
            else:
                conn = Connection(server, auto_bind=True)

            if not conn.bound:
                self.ptprint("Bind failed.", out=Out.WARNING)
                return None
            return server, conn

        except Exception as e:
            self.ptprint(f"Error: {e}", out=Out.WARNING)
            return None

    def ldap_banner(self) -> dict:
        """
        Retrieves and displays detailed LDAP server information.
        """

        self.drawDoubleLine()
        self.ptprint(f"Retrieving LDAP banner information at {self.args.ip}:{self.args.port} (SSL: {self.args.use_ssl})", title=True)
        self.drawDoubleLine()

        connection = self.create_ldap_connection()
        if connection:
            server, conn = connection
            server_info = server.info
        else:
            return None
        
        if not conn.bind() ==True:
            return None

        if self.args.output:
                self.write_to_file(str(server_info)) 

        result = {
            "Supported LDAP Versions": server_info.supported_ldap_versions,
            "Naming Contexts": server_info.naming_contexts,
            "Supported Controls": server_info.supported_controls,
            "Supported Extensions": server_info.supported_extensions,
            "Supported Features": server_info.supported_features,
            "Supported SASL Mechanisms": server_info.supported_sasl_mechanisms,
            "Schema Entry": getattr(server_info, 'schema_entry', None),
            "Vendor Name": getattr(server_info, 'vendor_name', None),
            "Vendor Version": getattr(server_info, 'vendor_version', None),
            "Other Attributes": getattr(server_info, 'other', {}),
        }

        # Print output
        self.print_list("Supported LDAP Versions", result["Supported LDAP Versions"])
        self.print_list("Naming Contexts", result["Naming Contexts"])
        self.print_list("Supported Controls", result["Supported Controls"])
        self.print_list("Supported Extensions", result["Supported Extensions"])
        self.print_list("Supported Features", result["Supported Features"])
        self.print_list("Supported SASL Mechanisms", result["Supported SASL Mechanisms"])

        if result["Schema Entry"]:
            self.print_title("Schema Entry")
            self.ptprint(f"  - {result['Schema Entry']}")
            
        if result["Vendor Name"]:
            self.print_title("Vendor Name")
            self.ptprint(f"  - {result['Vendor Name']}")  

        if result["Vendor Version"]:
            self.print_title("Vendor Version")
            self.ptprint(f"  - {result['Vendor Version']}")



        self.print_title("Other Attributes")
        other = result["Other Attributes"]
        if other:
            for key, value in other.items():
                self.print_subtitle(key.capitalize())
                if not value:
                    self.ptprint("    No data found.")
                elif isinstance(value, list):
                    for item in value:
                        self.ptprint(f"    {item}")
                else:
                    self.ptprint(f"    {value}")

        else:
            self.ptprint(" No data found.")
            
        return result

    def ldap_search(self) -> list[dict]:
        """
        Performs an LDAP search with a custom filter and optional attribute list.
        """

        self.drawDoubleLine()
        self.ptprint(f"Search result for filter: {self.args.ldap_filter} in base: {self.args.base_dn}", title=True)
        self.drawDoubleLine()

        connection = self.create_ldap_connection()

        if not connection:
            return []
        
        server, conn = connection

        if not self.args.base_dn:
            if server.info.naming_contexts:
                base_dn = server.info.naming_contexts[0]
                self.ptprint(f"Warning: No base_dn provided. Using detected: {base_dn}", out=Out.WARNING)
            else:
                self.ptprint("Base DN could not be determined automatically.", out=Out.WARNING)
                self.ptprint("Please specify a base_dn manually. Otherwise, the search cannot continue.", out=Out.WARNING)
                return []
            
        else: base_dn = self.args.base_dn

        attributes = self.args.attributes if self.args.attributes else ['*']

        conn.search(
            search_base=base_dn,
            search_filter=self.args.ldap_filter,
            search_scope=SUBTREE,
            attributes=attributes
        )

        results = []

        for entry in conn.entries:
                self.print_ldapsearch(entry, attributes)

                results.append({
                    "dn": entry.entry_dn,
                    "attributes": entry.entry_attributes_as_dict
                })
        
        # If output file path is specified, write the retrieved server information to the file
        if self.args.output:
            self.write_to_file(str(conn.entries))
                
        conn.unbind()
        return results
  

    def print_ldapsearch(self, entry, attributes):
        """
        Nicely formats and prints LDAP entry details with selected attributes.
        """

        self.ptprint(' ')
        self.drawLine()
        self.ptprint("Entry DN", title=True)
        self.drawLine()
        self.ptprint(f"{entry.entry_dn}\n")


        if not attributes or attributes == ['*']:
            object_classes = entry['objectClass'].value if 'objectClass' in entry else []
            main_class = object_classes[1] if len(object_classes) > 1 else object_classes[0] if object_classes else "N/A"

            self.print_title("Object Class Overview")

            self.ptprint(f"Main Class     : {main_class}")
            self.ptprint("All Classes    : " + "-".join(object_classes) + "\n")

        self.print_title("Attributes")

        for attr in entry.entry_attributes:
            if attr == "objectClass":
                continue
            val = entry[attr].value
            if not val:
                val_display = "N/A"
            else:
                val_display = ", ".join(val) if isinstance(val, list) else str(val)
            self.ptprint(f"{attr.capitalize():<30}: {val_display}")


    def ldap_enumerate_users(self) -> list[str]:
        """
        Enumerates valid usernames by using the existing ldap_search function.
        """

        self.drawDoubleLine()
        self.ptprint(f"Starting LDAP username enumeration on {self.args.ip}:{self.args.port} (SSL: {self.args.use_ssl})", title=True)
        self.drawDoubleLine()

        if not self.args.username_file:
            self.ptprint("No username list provided for enumeration.", out=Out.WARNING)
            return []
        
        usernames = self._text_or_file(None, self.args.username_file)
        valid_users = []

        connection = self.create_ldap_connection()
        if connection:
            server, conn = connection
        else:
            return []

        if not self.args.base_dn:
            if server.info.naming_contexts:
                base_dn = server.info.naming_contexts[0]
                self.ptprint(f"No base_dn provided. Using detected: {base_dn}", out=Out.WARNING)
            else:
                self.ptprint("Base DN could not be determined automatically.", out=Out.WARNING)
                self.ptprint("Please specify a base_dn manually. Otherwise, the search cannot continue.", out=Out.WARNING)
                return []
        else: base_dn = self.args.base_dn

        try: 
            attributes = ['*']   

            for username in usernames:
                ldap_filter = f"(&({self.args.search_attribute}={username}))"

                conn.search(
                    search_base=base_dn,
                    search_filter=ldap_filter,
                    search_scope=SUBTREE,
                    attributes=attributes)
                
                found = len(conn.entries) > 0  #True if found, False otherwise

                if found:
                    self.ptprint(f"SUCCESS: {username}", out=Out.OK)
                    valid_users.append(username)
                else:
                    self.ptprint(f"FAIL: {username}", out=Out.ERROR)

            conn.unbind()

            if valid_users:

                # If output file path is specified, write the retrieved server information to the file
                if self.args.output:
                    self.write_to_file(valid_users)

                self.print_title("Valid users found:")
                for u in valid_users:
                    self.ptprint(f"  - {u}")
            else:
                self.ptprint("No valid users found.", out=Out.INFO)

            return valid_users
            
            
        except Exception as e:
            self.ptprint(f"ERROR: {e}", out=Out.WARNING)
            return []
        
        
       

    def ldap_bruteforce(self) -> list[Credential]:
        """
        Attempts to brute-force LDAP credentials using provided usernames and passwords.
        """
        def attempt_login(cred: Credential) -> Optional[Credential]:
            for i in self.args.cn_uid:
                try:
                    if self.args.base_dn:
                        bind_dn = f"{i}={cred.username},{self.args.base_dn}"
                    elif self.args.upn_domain:
                        bind_dn = f"{cred.username}@{self.args.upn_domain}"
                    else:
                        bind_dn = cred.username

                    server = Server(self.args.ip, port=self.args.port, use_ssl=self.args.use_ssl, get_info=ALL)
                    conn = Connection(server, user=bind_dn, password=cred.password, auto_bind=True)
                    if conn.bound:
                        self.ptprint(f"SUCCESS: {bind_dn}:{cred.password}", out=Out.OK)
                        conn.unbind()
                        return Credential(username=bind_dn, password=cred.password)
                except Exception as e:
                    err_msg = str(e).lower()
                    if "invalidcredentials" in err_msg:
                        self.ptprint(f"FAIL: {bind_dn}:{cred.password}", out=Out.ERROR)
                    else:
                        self.ptprint(f"ERROR for {bind_dn}:{cred.password} -> {e}", out=Out.WARNING)
            return None

        self.drawDoubleLine()
        self.ptprint(f"Starting LDAP brute-force on {self.args.ip}:{self.args.port} (SSL: {self.args.use_ssl})", title=True)
        self.drawDoubleLine()

        usernames = self._text_or_file(self.args.user, self.args.username_file)
        passwords = self._text_or_file(self.args.password, self.args.password_file)

        # Spray logic
        if self.args.spray:
            creds = [Credential(u, p) for p in passwords for u in usernames]
        else:
            creds = [Credential(u, p) for u in usernames for p in passwords]

        valid_credentials = []
        if not usernames or not passwords:
            self.ptprint("Usernames or passwords list is empty.", out=Out.WARNING)
            return
        
        if not self.args.base_dn and not self.args.upn_domain:
            self.ptprint("No base_dn provided.", out=Out.WARNING)
            self.ptprint("Proceeding with simple username-only bind. Success is unlikely unless the server accepts plain usernames.", out=Out.WARNING)

        max_threads = getattr(self.args, "threads", 10)

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(attempt_login, cred) for cred in creds]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    valid_credentials.append(result)

        if valid_credentials:

            # If output file path is specified, write the retrieved server information to the file
            if self.args.output:
                results = [f"Username: {cred.username}, Password: {cred.password}" for cred in valid_credentials]
                self.write_to_file(results)

            self.print_title("Valid credentials found:")
            for cred in valid_credentials:
                self.ptprint(f"Username: {cred.username:<50} Password: {cred.password}")

            return valid_credentials
        
        else:
            self.ptprint("No valid credentials were found.", out=Out.INFO)

            return []



    def ldap_check_write_access(self):
        """
        Tests LDAP write access by attempting to modify a specified attribute.
        """
        self.drawDoubleLine()
        self.ptprint(f"Testing write access on {self.args.ip}:{self.args.port} (SSL: {self.args.use_ssl})", title=True)
        self.drawDoubleLine()

        connection = self.create_ldap_connection()
        if not connection:
            return
        server, conn = connection

        try:
            # Find a candidate DN if not provided
            if not self.args.target_dn:
                base_dn = server.info.naming_contexts[0] if server.info.naming_contexts else ''
                conn.search(base_dn, '(objectClass=person)', attributes='sn', size_limit=1)
                if not conn.entries:
                    self.ptprint("Could not find a modifiable entry (objectClass=person).", out=Out.ERROR)
                    return []
                self.args.target_dn = conn.entries[0].entry_dn
                self.ptprint(f"Target DN: {self.args.target_dn}", out=Out.INFO)

            if self.args.test_value:
                test_value = self.args.test_value
            else:
                test_value = 'SecurityTest123'

            # Attempt modification
            success = conn.modify(
                dn=self.args.target_dn,
                changes={self.args.attribute: [(MODIFY_REPLACE, [test_value])]}
            )

            if success:
                self.ptprint(f"Write access is allowed", out=Out.VULN)
                self.ptprint("Note: Attribute was modified for testing purposes. Don't forget to revert it back if necessary.", out=Out.INFO)
                atribute = self.args.attribute
                username  = self.args.user
                password = self.args.password
                result = TestWriteResult(
                    target_dn=self.args.target_dn,
                    atribute=atribute,
                    value= test_value,
                    credentials=f"{username}:{password}"
                )
                return result

            else:
                self.ptprint(f"Write access is denied", out=Out.NOTVULN)
                if conn.result:
                    description = conn.result.get('description', '')
                    message = conn.result.get('message', '')
                    self.ptprint(f"Details: {description} - {message}")
                return []
        except Exception as e:
            self.ptprint(f"Error: {e}", out=Out.WARNING)
        finally:
            conn.unbind()

    def output(self) -> None:
        """
        Banner: Optional[dict] = None
        Search: Optional[list[dict]] = None
        usernames: Optional[list[str]] = None
        credentials: Optional[list[Credential]] = None
        Writetest: Optional[TestWriteResult] = None

        WeakUsername = "PTV-LDAP-WEAKUSERNAME"
        WeakCredentials = "PTV-LDAP-WEAKCREDENTIALS"
        Write = "PTV-LDAP-WRITEACCESS"
        """
        def credentials_to_string(creds: List[Credential]) -> str:
            return ", ".join(
                f"{c.username or 'None'}:{c.password or 'None'}"
                for c in creds
            )
        def write_results_to_string(result: TestWriteResult) -> str:
            return f"{result.target_dn or 'None'}-{result.atribute or 'None'}-{result.value}-{result.credentials}"

        properties = {
            "software_type": None,
            "name": "ldap",
            "version": None,
            "vendor": None,
            "description": None,
            "usernames": self.results.usernames if self.results.usernames is not None else None,
            "credentials": credentials_to_string(self.results.credentials) if self.results.credentials is not None else None,
            "writetest": ", ".join(write_results_to_string(r) for r in self.results.Writetest) if self.results.Writetest is not None and len(self.results.Writetest) != 0 else None,
        }
        deferred_vulns = []

        if self.results.usernames is not None and len(self.results.usernames) != 0:
            deferred_vulns.append({
                "vuln_code": VULNS.WeakUsername.value,
                "vuln_request": "Searching for usernames",
                "vuln_response": ",".join(self.results.usernames),
            })
        if self.results.credentials is not None and len(self.results.credentials) != 0:
            deferred_vulns.append({
                "vuln_code": VULNS.WeakCredentials.value,
                "vuln_request": "Bruteforcing LDAP credentials",
                "vuln_response": credentials_to_string(self.results.credentials),
            })
        if self.results.Writetest is not None and len(self.results.Writetest) != 0:
            deferred_vulns.append({
                "vuln_code": VULNS.Write.value,
                "vuln_request": "Testing write access",
                "vuln_response": ", ".join(write_results_to_string(r) for r in self.results.Writetest),
            })

        ldap_node = self.ptjsonlib.create_node_object("software", None, None, properties)
        self.ptjsonlib.add_node(ldap_node)
        node_key = ldap_node["key"]
        for v in deferred_vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **v)

        self.ptprint(self.ptjsonlib.get_result_json(), json=True)
