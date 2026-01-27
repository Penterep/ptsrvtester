import argparse
from dataclasses import dataclass
from enum import Enum
from typing import List, NamedTuple, Optional
from impacket.dcerpc.v5 import epm, transport
from impacket import uuid
from impacket.dcerpc.v5 import mgmt
from impacket.dcerpc.v5.epm import KNOWN_UUIDS
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT
from itertools import product
from concurrent.futures import ThreadPoolExecutor, as_completed

from ptlibs.ptjsonlib import PtJsonLib

from ._base import BaseModule, BaseArgs, Out


class VULNS(Enum):
    NullSession= "PTV-MSRCP-SMBNULLSESSION"
    WeakCreds_pipes = "PTV-MSRPC-WEAKPIPECREDS"
    WeakCreds_SMB = "PTV-MSRPC-WEAKSMBCREDS"
    WeakCreds_TCP = "PTV-MSRPC-WEAKRPCCREDS"
    WeakCreds_HTTP = "PTV-MSRPC-WEAKHTTPCREDS"

class Credential(NamedTuple):
    username: str | None
    password: str | None


KNOWN_UUIDS = {
    "12345778-1234-abcd-ef00-0123456789ab": {
        "pipe": r"\pipe\lsarpc",
        "description": "LSA interface, used to enumerate users."
    },
    "3919286a-b10c-11d0-9ba8-00c04fd92ef5": {
        "pipe": r"\pipe\lsarpc",
        "description": "LSA Directory Services (DS) interface, used to enumerate domains and trust relationships."
    },
    "12345778-1234-abcd-ef00-0123456789ac": {
        "pipe": r"\pipe\samr",
        "description": "LSA SAMR interface, used to access public SAM database elements (e.g., usernames) and brute-force user passwords regardless of account lockout policy."
    },
    "1ff70682-0a51-30e8-076d-740be8cee98b": {
        "pipe": r"\pipe\atsvc",
        "description": "Task scheduler, used to remotely execute commands."
    },
    "338cd001-2244-31f1-aaaa-900038001003": {
        "pipe": r"\pipe\winreg",
        "description": "Remote registry service, used to access and modify the system registry."
    },
    "367abb81-9844-35f1-ad32-98f038001003": {
        "pipe": r"\pipe\svcctl",
        "description": "Service control manager and server services, used to remotely start and stop services and execute commands."
    },
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": {
        "pipe": r"\pipe\srvsvc",
        "description": "Service control manager and server services, used to remotely start and stop services and execute commands."
    },
    "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57": {
        "pipe": r"\pipe\epmapper",
        "description": "DCOM interface, used for brute-force password grinding and information gathering via WM."
    },
}

@dataclass
class MSRPCResult:
    EpmapEndpoints: Optional[dict] = None
    MgmtEndpoints: Optional[List[str]] = None
    Pipes: Optional[List[str]] = None
    PipesCreds: Optional[List[Credential]] = None
    Anonymous: Optional[List[str]] = None  
    SMB_Brute: Optional[List[Credential]] = None
    TCP_Brute: Optional[List[Credential]] = None
    HTTP_Brute: Optional[List[Credential]] = None       

class MSRPCArgs(BaseArgs):
    ip: str
    port:int = None
    command:str = None
    pipes:list = None
    username:str = None
    password:str = None
    username_file:str = None
    password_file:str = None
    pipe:str = None
    domain: str = None
    verbose: str = True
    uuid: str = None
    output: str 
    threads: int

    @staticmethod
    def get_help():
        return [
            {"description": ["MSRPC Testing Module"]},
            {"usage": ["ptsrvtester msrpc <command> <options>"]},
            {"usage_example": [
                "ptsrvtester msrpc enumerate-epm --ip 192.168.1.1",
                "ptsrvtester msrpc brute-pipe --ip 192.168.1.1 --pipe svcctl -ul users.txt",
                "ptsrvtester msrpc brute-smb --ip 192.168.1.1 -ul users.txt -pl passwords.txt"
            ]},
            {"options": [
                ["enumerate-epm", "<options>", "", "Enumerate registered EPM endpoints"],
                ["enumerate-mgmt", "<options>", "", "Enumerate MGMT interface UUIDs"],
                ["brute-pipe", "<options>", "", "Brute-force credentials for named pipe"],
                ["brute-smb", "<options>", "", "Brute-force SMB credentials"],
                ["brute-tcp", "<options>", "", "Brute-force credentials via TCP"],
                ["brute-http", "<options>", "", "Brute-force credentials via RPC over HTTP"],
                ["anon-smb", "<options>", "", "Check anonymous SMB access"],
                ["enumerate-pipes", "<options>", "", "Enumerate accessible named pipes"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of MSRPC arguments"""

        examples = """example usage:
        ptsrvtester msrpc enumerate-epm --ip 192.168.1.1
        ptsrvtester msrpc brute-pipe --ip 192.168.1.1 --pipe svcctl -ul users.txt -pl passwords.txt
        ptsrvtester msrpc brute-smb --ip 192.168.1.1 -ul users.txt -pl passwords.txt
        ptsrvtester msrpc enumerate-mgmt --ip 192.168.1.1
        ptsrvtester msrpc brute-http --ip 192.168.1.1 -ul users.txt -pl passwords.txt
        """

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError

        msrpc_subparsers = parser.add_subparsers(dest="command", help="Select MSRPC command", required=True)

        # Enumerate EPM endpoints
        epm_parser = msrpc_subparsers.add_parser("enumerate-epm", help="Enumerate registered EPM endpoints")
        epm_parser.add_argument("-ip", required=True, help="Target IP address")
        epm_parser.add_argument("-p", "--port", type=int, default=135, help="Target port (default: 135)")
        epm_parser.add_argument("-o" , "--output", help="File to save the output results.")

        # Enumerate MGMT endpoints
        mgmt_parser = msrpc_subparsers.add_parser("enumerate-mgmt", help="Enumerate MGMT interface UUIDs")
        mgmt_parser.add_argument("-ip", required=True, help="Target IP address")
        mgmt_parser.add_argument("-p", "--port", type=int, default=135, help="Target port (default: 135)")
        mgmt_parser.add_argument("-o" , "--output", help="File to save the output results.")

        # Pipe bruteforce
        pipe_brute = msrpc_subparsers.add_parser("brute-pipe", help="Brute-force valid credentials for named pipe")
        pipe_brute.add_argument("-ip", required=True, help="Target IP address")
        pipe_brute.add_argument("--pipe", required=True, help="Named pipe to test")
        pipe_brute.add_argument("-d", "--domain", default='', help="Domain name")
        pipe_brute.add_argument("-o" , "--output", help="File to save the output results.")
        pipe_brute.add_argument("--threads", type=int, default=10, help="Number of threads to use for brute-force (default: 10)")

        user_group = pipe_brute.add_mutually_exclusive_group(required=True)
        user_group.add_argument("-ul", "--username_file", help="Username list file")
        user_group.add_argument("-u", "--username", help="Single username")

        pass_group = pipe_brute.add_mutually_exclusive_group(required=True)
        pass_group.add_argument("-pl", "--password_file", help="Password list file")
        pass_group.add_argument("-pw", "--password", help="Single password")

        # SMB bruteforce
        smb_brute = msrpc_subparsers.add_parser("brute-smb", help="Brute-force SMB credentials")
        smb_brute.add_argument("-ip", required=True, help="Target IP address")
        smb_brute.add_argument("-d", "--domain", default='', help="Domain name")
        smb_brute.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
        smb_brute.add_argument("-o" , "--output", help="File to save the output results.")
        smb_brute.add_argument("--threads", type=int, default=10, help="Number of threads to use for brute-force (default: 10)")

        user_group = smb_brute.add_mutually_exclusive_group(required=True)
        user_group.add_argument("-ul", "--username_file", help="Username list file")
        user_group.add_argument("-u", "--username", help="Single username")

        pass_group = smb_brute.add_mutually_exclusive_group(required=True)
        pass_group.add_argument("-pl", "--password_file", help="Password list file")
        pass_group.add_argument("-pw", "--password", help="Single password")

        # TCP UUID bruteforce
        tcp_brute = msrpc_subparsers.add_parser("brute-tcp", help="Brute-force credentials for specific UUID via TCP")
        tcp_brute.add_argument("-ip", required=True, help="Target IP address")
        tcp_brute.add_argument("-p", "--port", type=int,required=True, help="Target port")
        tcp_brute.add_argument("--uuid", required=True, help="UUID to bind to")
        tcp_brute.add_argument("-d", "--domain", default='', help="Domain name")
        tcp_brute.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
        tcp_brute.add_argument("-o" , "--output", help="File to save the output results.")
        tcp_brute.add_argument("--threads", type=int, default=10, help="Number of threads to use for brute-force (default: 10)")
        

        user_group = tcp_brute.add_mutually_exclusive_group(required=True)
        user_group.add_argument("-ul", "--username_file", help="Username list file")
        user_group.add_argument("-u", "--username", help="Single username")

        pass_group = tcp_brute.add_mutually_exclusive_group(required=True)
        pass_group.add_argument("-pl", "--password_file", help="Password list file")
        pass_group.add_argument("-pw", "--password", help="Single password")

        # HTTP UUID bruteforce
        http_brute = msrpc_subparsers.add_parser("brute-http", help="Brute-force credentials via RPC over HTTP")
        http_brute.add_argument("-ip", required=True, help="Target IP address")
        http_brute.add_argument("-d", "--domain", default='', help="Domain name")
        http_brute.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
        http_brute.add_argument("-o" , "--output", help="File to save the output results.")
        http_brute.add_argument("--threads", type=int, default=10, help="Number of threads to use for brute-force (default: 10)")

        user_group = http_brute.add_mutually_exclusive_group(required=True)
        user_group.add_argument("-ul", "--username_file", help="Username list file")
        user_group.add_argument("-u", "--username", help="Single username")

        pass_group = http_brute.add_mutually_exclusive_group(required=True)
        pass_group.add_argument("-pl", "--password_file", help="Password list file")
        pass_group.add_argument("-pw", "--password", help="Single password")

        # Anonymous SMB check
        anon_check = msrpc_subparsers.add_parser("anon-smb", help="Check anonymous SMB access and IPC$")
        anon_check.add_argument("-ip", required=True, help="Target IP address")
        anon_check.add_argument("-p", "--port", type=int, default=445, help="Target port (default: 445)")

        # Enumerate accessible named pipes with given credentials
        pipes_enum = msrpc_subparsers.add_parser("enumerate-pipes", help="Enumerate accessible named pipes with provided credentials")
        pipes_enum.add_argument("-ip", required=True, help="Target IP address")
        pipes_enum.add_argument("-u", "--username", help="Username")
        pipes_enum.add_argument("-pw", "--password", help="Password")
        
class MSRPC(BaseModule):
    @staticmethod
    def module_args():
        return MSRPCArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: MSRPCResult | None = None

    def run(self) -> None:
        """Main MSRPC execution logic"""

        self.results = MSRPCResult()

        if self.args.command == "enumerate-epm":
            self.results.EpmapEndpoints = self.enumerate_epm()

        elif self.args.command == "enumerate-mgmt":
            self.results.MgmtEndpoints = self.enumerate_mgmt()

        elif self.args.command == "brute-pipe":
            self.results.PipesCreds = self.pipe_dictionary_attack()

        elif self.args.command == "brute-smb":
            self.results.SMB_Brute = self.smb_brute()

        elif self.args.command == "brute-tcp":
            self.results.TCP_Brute = self.tcp_brute()

        elif self.args.command == "brute-http":
            self.results.HTTP_Brute = self.http_brute()

        elif self.args.command == "anon-smb":
            self.results.Anonymous = self.Anonymous_smb()

        elif self.args.command == "enumerate-pipes":
            self.results.Pipes = self.enumerate_pipes()
            
        else:
            self.ptprint("Unknown command for MSRPC module.", out=Out.WARNING)

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


    def _generate_credentials(self) -> list[Credential]:
        usernames = self._text_or_file(self.args.username, self.args.username_file)
        passwords = self._text_or_file(self.args.password, self.args.password_file)

        if not usernames or not passwords:
            return []

        return [Credential(u, p) for u, p in product(usernames, passwords)]

    def enumerate_epm(self) -> dict:

        self.drawDoubleLine()
        self.ptprint(f"Enumerating EPM endpoints at {self.args.ip}:{self.args.port}", title=True)
        self.drawDoubleLine()

        tmp_endpoints = {}
        
        try:
            rpctransport = transport.DCERPCTransportFactory(f'ncacn_ip_tcp:{self.args.ip}[{self.args.port}]')

            # Connection 
            dce = rpctransport.get_dce_rpc()
            dce.connect()

            # Enumeration trough all endpoints registrated on the machine's Endpoint Mapper
            entries = epm.hept_lookup(None, dce=dce)

            output_lines = []

            for entry in entries:
                binding = epm.PrintStringBinding(entry['tower']['Floors'])
                tmpUUID = str(entry['tower']['Floors'][0])
                

                if (tmpUUID in tmp_endpoints) is not True:
                    tmp_endpoints[tmpUUID] = {}
                    tmp_endpoints[tmpUUID]['Bindings'] = list()
                
                if uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18] in epm.KNOWN_UUIDS:
                    tmp_endpoints[tmpUUID]['EXE'] = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
                else:
                    tmp_endpoints[tmpUUID]['EXE'] = 'N/A'
                tmp_endpoints[tmpUUID]['annotation'] = entry['annotation'][:-1].decode('utf-8')
                tmp_endpoints[tmpUUID]['Bindings'].append(binding)

                if tmpUUID[:36] in epm.KNOWN_PROTOCOLS:
                    tmp_endpoints[tmpUUID]['Protocol'] = epm.KNOWN_PROTOCOLS[tmpUUID[:36]]

                else:
                    tmp_endpoints[tmpUUID]['Protocol'] = "N/A"

            for endpoint in list(tmp_endpoints.keys()):
                self.ptprint("Protocol: %s " % tmp_endpoints[endpoint]['Protocol'])
                output_lines.append(f"Protocol: {tmp_endpoints[endpoint]['Protocol']}")
                self.ptprint("Provider: %s " % tmp_endpoints[endpoint]['EXE'])
                output_lines.append(f"Provider: {tmp_endpoints[endpoint]['EXE']}")
                self.ptprint("UUID    : %s %s" % (endpoint, tmp_endpoints[endpoint]['annotation']))
                output_lines.append(f"UUID    : {endpoint} {tmp_endpoints[endpoint]['annotation']}") 
                self.ptprint("Bindings: ")
                output_lines.append("Bindings:")
                for binding in tmp_endpoints[endpoint]['Bindings']:
                    self.ptprint("          %s" % binding)
                    output_lines.append(f"          {binding}")
                self.ptprint("\n")
                output_lines.append("")

            dce.disconnect()
            self.ptprint(f"Total endpoints found: {len(tmp_endpoints)}", out=Out.INFO)
            output_lines.append(f"Total endpoints found: {len(tmp_endpoints)}")

            if self.args.output:
                self.write_to_file(output_lines)


            return tmp_endpoints

        except Exception as e:
            self.ptprint(f"Error during EPM enumeration: {e}", out=Out.WARNING)
            return tmp_endpoints
    

    def enumerate_mgmt(self) -> list[str]:

        self.drawDoubleLine()
        self.ptprint(f"Enumerating MGMT endpoints at {self.args.ip}:{self.args.port}", title=True)
        self.drawDoubleLine()

        dangerous_uuids = []
        other_uuids = []
        results =[]

        def handle_discovered_tup(tup):

            if tup[0] in epm.KNOWN_PROTOCOLS:
                self.ptprint("Protocol: %s" % (epm.KNOWN_PROTOCOLS[tup[0]]))
            else:
                self.ptprint("Procotol: N/A")

            if uuid.uuidtup_to_bin(tup)[: 18] in KNOWN_UUIDS:
                self.ptprint("Provider: %s" % (KNOWN_UUIDS[uuid.uuidtup_to_bin(tup)[:18]]))
            else:
                self.ptprint("Provider: N/A")

            self.ptprint("UUID: %s v%s" % (tup[0], tup[1]))
         
        rpctransport = transport.DCERPCTransportFactory(f'ncacn_ip_tcp:{self.args.ip}[{self.args.port}]')
        
        
        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(mgmt.MSRPC_UUID_MGMT)
            
            # Retrieving interfaces UUIDs from the MGMT interface
            ifids = mgmt.hinq_if_ids(dce)
            

            uuidtups = set(
            uuid.bin_to_uuidtup(ifids['if_id_vector']['if_id'][index]['Data'].getData())
            for index in range(ifids['if_id_vector']['count'])
            )

            uuidtups.add(('AFA8BD80-7D8A-11C9-BEF4-08002B102989', '1.0'))

            for tup in sorted(uuidtups):
                uuid_str = tup[0].lower()

                if uuid_str in KNOWN_UUIDS:
                    dangerous_uuids.append(tup)
                else:
                    other_uuids.append(tup)

            if other_uuids:
                for tup in other_uuids:
                    handle_discovered_tup(tup)
                    self.ptprint("\n")

            self.drawLine()       
            
            if dangerous_uuids:
                self.ptprint("Known Exploitable or Informative UUIDs", out=Out.INFO)
                self.drawLine()
                for tup in dangerous_uuids:
                    handle_discovered_tup(tup)
                    uuid_key = tup[0].lower()
                    if uuid_key in KNOWN_UUIDS:
                        self.ptprint(f"Named Pipe: {KNOWN_UUIDS[uuid_key]['pipe']}")
                        self.ptprint(f"Description: {KNOWN_UUIDS[uuid_key]['description']}")
                    else:
                        self.ptprint(f"Named Pipe: Unknown")
                        self.ptprint(f"Description: Unknown UUID")
                    self.ptprint("\n")
                    results.append(uuid_key)
            
            if self.args.output:
                self.write_to_file(results)

            return results

        except Exception as e:
            self.ptprint(f"Failed to connect/bind to MGMT interface: {e}", out=Out.ERROR)
            return []
        

    def try_authenticated_pipe_bind(self, pipe, username, password, domain=''):
        rpctransport = transport.DCERPCTransportFactory(f'ncacn_np:{self.args.ip}[\\pipe\\{pipe}]')
        rpctransport.set_credentials(username, password, domain)
        rpctransport.setRemoteHost(self.args.ip)

        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            self.ptprint(f"SUCCESS: \\\\{self.args.ip}\\pipe\\{pipe} ({username}:{password})", out=Out.OK)
            return True
        except Exception as e:
            self.ptprint(f"FAIL '{pipe}' ({username}:{password}): {e}", out=Out.ERROR)
            return False

    def enumerate_pipes(self) -> list[str]:


        self.drawDoubleLine()
        self.ptprint("Starting authenticated named pipe enumeration", title=True)
        self.drawDoubleLine()

        if self.args.username == None:
            self.args.username = ""
        if self.args.password == None:
            self.args.password = ""
        
        if self.args.pipes:
            known_pipes = self.args.pipes
        else:
            known_pipes = [
                'epmapper', 'browser', 'eventlog', 'lsarpc', 'samr', 'svcctl',
                'spoolss', 'netlogon', 'atsvc', 'wkssvc', 'ntsvcs', 'winreg', 'srvsvc'
            ]

        results = []
        pipes = []

        for pipe in known_pipes:
            try:
                success = self.try_authenticated_pipe_bind(pipe, self.args.username, self.args.password, self.args.domain or '')
                                                            
                if success:
                    results.append(pipe)
                    pipes.append(pipe)
            except Exception as e:
                self.ptprint(f"Error during pipe enumeration: {e}", out=Out.WARNING)
                continue
        self.ptprint("\n")
        self.ptprint(f"Found pipes:", out=Out.INFO)
        for pipe in pipes:
            self.ptprint(pipe)
        return results
    

    #Bruteforce - valid creds for specific pipe
    def  pipe_dictionary_attack(self) -> list[Credential]:

        self.drawDoubleLine()
        self.ptprint(f"Starting named pipe dictionary attack on \\\\{self.args.ip}\\pipe\\{self.args.pipe}", title=True)
        self.drawDoubleLine()    

        creds = self._generate_credentials()
        if not creds:
            self.ptprint("No credentials to test.", out=Out.WARNING)
            return []

        def attempt(cred: Credential) -> Optional[Credential]:
            try:
                if self.try_authenticated_pipe_bind(self.args.pipe, cred.username, cred.password, self.args.domain or ''):
                    return cred
            except Exception as e:
                self.ptprint(f"Error {cred.username}:{cred.password} - {str(e).strip()}", out=Out.WARNING)
            return None

        found = []
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = [executor.submit(attempt, cred) for cred in creds]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        self.ptprint("\n")
        self.ptprint("Valid credentials found:", out=Out.INFO) 
        if found:
            for cred in found:
                self.ptprint(f"{cred.username}:{cred.password}")

            if self.args.output:
                self.write_to_file([f"{cred.username}:{cred.password}" for cred in found])
        
        else: 
            self.ptprint("No valid credentials were found.")

        return found
    
    #Checking null session and also if it is possible to share trough IPC$
    #[True, True] worst case - both are allowed
    #[True, False] - smb anonymous allowed, IPC$ not

    def Anonymous_smb(self) -> list[str]:
        resutlt =[]

        self.drawDoubleLine()
        self.ptprint(f"Testing anonymous SMB connection to {self.args.ip}:{self.args.port}", title=True)
        self.drawDoubleLine()

        try:
            smb = SMBConnection(self.args.ip, self.args.ip, sess_port=self.args.port, timeout=5)
            smb.login('', '')  # (null session)

            try:
                shares = smb.listShares()
                self.ptprint("Anonymous SMB login is allowed", out=Out.VULN)
                for share in shares:
                    self.ptprint(f"    Share: {share['shi1_netname']}")
                smb.logoff()
                result = ["True", "True"]
                return result
            except Exception as e:
                self.ptprint("Anonymous SMB login is allowed (IPC$ access failed)", out=Out.VULN)
                smb.logoff()
                result = ["True", "False"]
                return result

        except Exception as e:
            self.ptprint("Anonymous SMB login is denied", out=Out.NOTVULN)
            return []
        
    # attack just on smb no pipes 
    def smb_brute(self) -> list[Credential]:

        self.drawDoubleLine()
        self.ptprint(f"Starting SMB brute-force on {self.args.ip}:{self.args.port or 445}", title=True)
        self.drawDoubleLine()

        creds = self._generate_credentials()
        if not creds:
            self.ptprint("No credentials to test.", out=Out.WARNING)
            return []

        def attempt(cred: Credential) -> Optional[Credential]:
            try:
                smb = SMBConnection(self.args.ip, self.args.ip, sess_port=self.args.port or 445, timeout=3)
                smb.login(cred.username, cred.password, self.args.domain)
                smb.logoff()
                self.ptprint(f"SUCCESS: {cred.username}:{cred.password}", out=Out.OK)
                return cred
            except Exception as e:
                if self.args.verbose:
                    self.ptprint(f"FAIL: {cred.username}:{cred.password} ({str(e).strip()})", out=Out.ERROR)
            return None

        found = []
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = [executor.submit(attempt, cred) for cred in creds]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        self.ptprint("\n")
        self.ptprint("Valid credentials found:", out=Out.INFO)   
        if found:
            for cred in found:
                self.ptprint(f"{cred.username}:{cred.password}")

            if self.args.output:
                self.write_to_file([f"{cred.username}:{cred.password}" for cred in found])

        else:
            self.ptprint("No valid credentials found.")


        return found
    
    def try_authenticated_bind(self, host, port, username, password, uuid, domain=''):
        binding = f'ncacn_ip_tcp:{host}[{port}]'
        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.set_credentials(username, password, domain)

        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(uuid)
            self.ptprint(f"SUCCESS: {username}:{password}", out=Out.OK)
            dce.disconnect()
            return True
        except Exception as e:
            self.ptprint(f"FAIL: {e}", out=Out.ERROR)
            return False
    

    #Bruteforce for specofic uuids trough TCP
    # Nutno otestovat
    def tcp_brute(self) -> list[Credential]:
        #Otestovat

        self.drawDoubleLine()
        self.ptprint(f"Starting brute-force attack on {self.args.domain}\\{self.args.ip}:{self.args.port}", title=True)
        self.drawDoubleLine()

        creds = self._generate_credentials()
        if not creds:
            self.ptprint("No credentials to test.", out=Out.WARNING)
            return []

        def attempt(cred: Credential) -> Optional[Credential]:
            try:
                if self.try_authenticated_bind(self.args.ip, self.args.port, cred.username, cred.password, self.args.uuid, self.args.domain):
                    return cred
            except Exception as e:
                if self.args.verbose:
                    self.ptprint(f"FAIL: {cred.username}:{cred.password} ({str(e).strip()})", out=Out.ERROR)
            return None

        found = []
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = [executor.submit(attempt, cred) for cred in creds]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        self.ptprint("\n")
        self.ptprint("Valid credentials found:", out=Out.INFO)   
        if found:
            for cred in found:
                self.ptprint(f"{cred.username}:{cred.password}")

            if self.args.output:
                self.write_to_file([f"{cred.username}:{cred.password}" for cred in found])

        else:
            self.ptprint("No valid credentials found.")

        return found
    
    # Http credentials bruteforce attack
    #Nutno otestovat
    def http_brute(self) -> List[Credential]:


        self.drawDoubleLine()
        self.ptprint(f"Starting brute-force attack on {self.args.ip}:{self.args.port}", title=True)
        self.drawDoubleLine()

        creds = self._generate_credentials()
        if not creds:
            self.ptprint("No credentials to test.", out=Out.WARNING)
            return []

        def attempt(cred: Credential) -> Optional[Credential]:
            try:
                rpctransport = transport.DCERPCTransportFactory(f'ncacn_http:{self.args.ip}')
                rpctransport.set_credentials(cred.username, cred.password, self.args.domain or "")
                rpctransport.set_auth_type(RPC_C_AUTHN_WINNT)
                rpctransport.setRemoteHost(self.args.ip)
                rpctransport.set_dport(443)

                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(MSRPC_UUID_PORTMAP)
                dce.disconnect()
                self.ptprint(f"SUCCESS: {cred.username}:{cred.password}", out=Out.OK)
                return cred
            except Exception as e:
                self.ptprint(f"FAIL: {cred.username}:{cred.password} ({str(e).strip()})", out=Out.ERROR)
            return None

        found = []
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = [executor.submit(attempt, cred) for cred in creds]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        self.ptprint("Valid credentials found:", out=Out.INFO)   
        if found:
            for cred in found:
                self.ptprint(f"{cred.username}:{cred.password}")
            if self.args.output:
                self.write_to_file([f"{cred.username}:{cred.password}" for cred in found])

        else:
            self.ptprint("No valid credentials found.")

        return found
    
    def output(self) -> None:
        """
            EpmapEndpoints: Optional[dict] = None
            MgmtEndpoints: Optional[List[str]] = None
            Pipes: Optional[List[str]] = None
            PipesCreds: Optional[List[Credential]] = None
            Anonymous: Optional[List[str]] = None  
            SMB_Brute: Optional[List[Credential]] = None
            TCP_Brute: Optional[List[Credential]] = None
            HTTP_Brute: Optional[List[Credential]] = None       

            NullSession= "PTV-MSRCP-SMBNULLSESSION"
            WeakCreds_pipes = "PTV-MSRPC-WEAKPIPECREDS"
            WeakCreds_SMB = "PTV-MSRPC-WEAKSMBCREDS"
            WeakCreds_TCP = "PTV-MSRPC-WEAKRPCCREDS"
            WeakCreds_HTTP = "PTV-MSRPC-WEAKHTTPCREDS"
        """

        def credentials_to_string(creds: List[Credential]) -> str:
            return ", ".join(
                f"{c.username or 'None'}:{c.password or 'None'}"
                for c in creds
            )

        if (self.results.Anonymous != None):
            if len(self.results.Anonymous) != 0:
                self.ptjsonlib.add_vulnerability(VULNS.NullSession.value, "Testing anonymous SMB access and IPC$ share.", ",".join(self.results.Anonymous))
        
        if (self.results.PipesCreds != None):
            if len(self.results.PipesCreds) != 0:
                cred_str = credentials_to_string(self.results.PipesCreds)
                self.ptjsonlib.add_vulnerability(VULNS.WeakCreds_pipes.value, "Bruteforcing credentials for specific pipes", cred_str)

        if (self.results.SMB_Brute != None):
            if len(self.results.SMB_Brute) != 0:
                cred_str = credentials_to_string(self.results.SMB_Brute)
                self.ptjsonlib.add_vulnerability(VULNS.WeakCreds_SMB.value, "Bruteforcing SMB credentials", cred_str) 

        if (self.results.TCP_Brute != None):
            if len(self.results.TCP_Brute) != 0:
                cred_str = credentials_to_string(self.results.TCP_Brute)
                self.ptjsonlib.add_vulnerability(VULNS.WeakCreds_TCP.value, "Bruteforcing RPC credentials for specific UUID", cred_str)
        
        if (self.results.HTTP_Brute != None):
            if len(self.results.HTTP_Brute) != 0:
                cred_str = credentials_to_string(self.results.HTTP_Brute)
                self.ptjsonlib.add_vulnerability(VULNS.WeakCreds_HTTP.value, "Bruteforcing HTTP credentials", cred_str)

        self.ptprint(self.ptjsonlib.get_result_json(), json=True)