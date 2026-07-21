from ptlibs.ptjsonlib import PtJsonLib
import argparse
from ._base import BaseModule, BaseArgs
from dataclasses import dataclass
from typing import List
from ptsrvtester.modules.utils.ptprinthelper import ptprint

from impacket.smbconnection import (
    SMBConnection,
    SMB_DIALECT,
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
)

from .utils.helpers import (
    valid_target,
    Target
)


def valid_target_smb(target: str) -> Target:
    # TODO: make adding port more robust
    if ":" not in target:
        target += ":445"

    return valid_target(target, domain_allowed=True)

def _get_if_available(getter):
    try:
        return getter()
    except Exception:
        return None


OPTIONS = ["info", "dialects", "encryption"]


class SMBArgs(BaseArgs):
    target: Target
    get_version: bool
    
    @staticmethod
    def get_help():
        return [
            {"description": ["SMB Testing Module"]},
            {"usage": ["ptsrvtester smb <command> <options>"]},
            {"usage_example": [
                "wow",
                "so",
                "many",
                "examples",
            ]},
            {"options": ["wow", "so", "many", "options"]},
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example will go here:
some kind of example"""
        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        
        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError
        
        parser.add_argument(
            "target",
            type=valid_target_smb,
            help="""IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:445); If PORT is left empty, 445 is default""",
        )
        
        tests = parser.add_argument_group(
            "TESTING TOOLS",
            "Toolbox of non-invasive tests on a specified target server"
        )
        
        # TODO: find option to not require args
        tests.add_argument("-ts", "--test", help="Testing toolbox for SMB",
                           choices=OPTIONS)
        
        # maybe still usable
        # smb_subparsers = parser.add_subparsers(dest="command", help="Select SMB command", required=True)
        
        # smb_info = smb_subparsers.add_parser("-i", "--info", help="Retrieve SMB host information")
        # smb_info.add_argument("-ip", "--ip", help="IP address of the target SMB server.")
        # smb_info.add_argument("-p", "--port", type=int, default=445, help="Port of the SMB server (default: 445).")


@dataclass
class SMBResult:
    Info: dict
    Dialects: List[str]


class SMB(BaseModule):
    mapping = {
        SMB_DIALECT:        "SMBv1",
        SMB2_DIALECT_002:   "SMBv2.0",
        SMB2_DIALECT_21:    "SMBv2.1",
        SMB2_DIALECT_30:    "SMBv3.0",
        SMB2_DIALECT_311:   "SMBv3.1.1",
    }
    
    @staticmethod
    def module_args():
        return SMBArgs()
    
    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        if not isinstance(args, SMBArgs):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: SMBResult = SMBResult(Info={}, Dialects=[])
    
    def run(self):
        self.results.Info["target"] = self.args.target.ip
        self.results.Info["port"] = self.args.target.port or 445

        if self.args.test == "info":
            self.get_info(True)
        elif self.args.test == "dialects":
            self.get_info()
        elif self.args.test == "encryption":
            self.get_info()
            self.parse_encryption_support()
    
    def output(self):
        if self.results.Dialects == []:
            ptprint("Connection couldn't be established", bullet_type="ERROR")
            return
        
        if self.args.test == "info":
            ptprint("Target:", bullet_type="INFO")
            ptprint(f"IP: {self.results.Info['target']}",
                    bullet_type="INFO", condition=True, indent=4)
            ptprint(f"Port: {self.results.Info['port']}",
                    bullet_type="INFO", condition=True, indent=4)

            ptprint("SMB server info:", bullet_type="INFO")
            ptprint(f"Server name: {self.results.Info['server_name']}",
                    bullet_type="INFO", condition=True, indent=4)
            ptprint(f"Server version: {self.results.Info['os_version']}",
                    bullet_type="INFO", condition=True, indent=4)
            ptprint(f"DNS domain name: {self.results.Info['dns_domain_name']}",
                    bullet_type="INFO", condition=True, indent=4)
            ptprint(f"DNS host name: {self.results.Info['dns_host_name']}",
                    condition=self.results.Info['dns_host_name'] != self.results.Info['dns_domain_name'],
                    bullet_type="INFO", indent=4)
            dialect = self.results.Dialects[0]
            ptprint(f"Lowest dialect version: {dialect}",
                    bullet_type="VULN" if dialect == "SMBv1" else "NOTVULN",
                    condition=True, indent=4)
            ptprint(f"Login required: {self.results.Info["login_required"]}",
                    bullet_type="WARNING" if not self.results.Info["login_required"] else "OK",
                    condition=True, indent=4)
            ptprint(f"Signing required: {self.results.Info["signing_required"]}",
                    bullet_type="VULN" if not self.results.Info["signing_required"] else "NOTVULN",
                    condition=True, indent=4)
            ptprint(f"NTLMv2 supported: {self.results.Info["ntlmv2_support"]}",
                    bullet_type="INFO", condition=True, indent=4)

        elif self.args.test == "dialects":
            ptprint("Negotiable SMB dialects:", bullet_type="INFO")
            for dialect in self.results.Dialects:
                ptprint(dialect, bullet_type="VULN" if dialect == "SMBv1" else "NOTVULN",
                        condition=True, indent=4)
        
        # TODO: add encryption requirement check
        elif self.args.test == "encryption":
            ptprint("SMB encryption status:", bullet_type="INFO")
            if "SMBv3.0" not in self.results.Dialects and "SMBv3.1.1" not in self.results.Dialects:
                ptprint("Encryption is only supported on SMBv3 and above. The server doensn't use them", bullet_type="INFO", condition=True, indent=4)
            else:
                v30_encryption = self.results.Info["v30_encryption"]
                ptprint(f"SMBv3.0: {v30_encryption if v30_encryption is not None else "unknown"}",
                        bullet_type="INFO", condition="SMBv3.0" in self.results.Dialects, indent=4)

                v311_encryption = self.results.Info["v311_encryption"]
                ptprint(f"SMBv3.1.1: {v311_encryption if v311_encryption is not None else "unknown"}",
                        bullet_type="INFO", condition="SMBv3.1.1" in self.results.Dialects, indent=4)

    def parse_encryption_support(self) -> None:
        results: List[bool | None] = []
        for v3dialect in [SMB2_DIALECT_30, SMB2_DIALECT_311]:
            try:
                smb_client = SMBConnection(
                    remoteName="*SMBSERVER",
                    remoteHost=self.args.target.ip,
                    sess_port=self.results.Info["port"],
                    preferredDialect=v3dialect,
                    timeout=5
                )
                server = smb_client.getSMBServer()
                results.append("Supported" if server._Connection['SupportsEncryption'] else "Unsupported")  # NOTE: sensitive to impacket changes
            except Exception:
                results.append(None)

        self.results.Info["v30_encryption"] = results[0]
        self.results.Info["v311_encryption"] = results[1]

    def fill_results_info(self, data: dict) -> None:
        for key in data.keys():
            if key not in self.results.Info.keys():
                self.results.Info[key] = data[key]
            elif self.results.Info[key] == "unknown":
                self.results.Info[key] = data[key]


    def pass_client_info(self, smb_client: SMBConnection) -> None:
        negotiated = smb_client.getDialect()
        negotiated_dialect = self.mapping.get(negotiated, f"Unknown dialect(raw dialect code: {negotiated})")
        if negotiated_dialect not in self.results.Dialects:
            self.results.Dialects.append(negotiated_dialect)

        server_name = _get_if_available(smb_client.getServerName)
        if not server_name:
            server_name = "unknown"

        dns_domain_name = _get_if_available(smb_client.getServerDNSHostName)
        if not dns_domain_name:
            dns_domain_name = "unknown"
        dns_host_name = _get_if_available(smb_client.getServerDNSHostName)
        if not dns_host_name:
            dns_host_name = dns_domain_name  # not a typo

        os_name = _get_if_available(smb_client.getServerOS)
        os_version = ""
        for getter in [smb_client.getServerOSMajor, smb_client.getServerOSMinor, smb_client.getServerOSBuild]:
            out = _get_if_available(getter)
            if out is None:
                break
            os_version += "." + str(out)

        if os_version == "":
            os_version = "unknown"
        else:
            os_version = os_version[1:]

        login_required = _get_if_available(smb_client.isLoginRequired)
        signing_required = _get_if_available(smb_client.isSigningRequired)
        ntlmv2_support = _get_if_available(smb_client.doesSupportNTLMv2)

        self.fill_results_info({
            "server_name": server_name,
            "os_version": (os_version if os_name is None or os_name == "" else f"{os_name} (build: {os_version})"),
            "dns_domain_name": dns_domain_name,
            "dns_host_name": dns_host_name,
            "ntlmv2_support": ntlmv2_support,
            "login_required": login_required,
            "signing_required": signing_required,
        })

    
    def get_info(self, just_info = False, test = False) -> None:
        """
        Goes through SMB dialects and tries getting information from the host
        """
        port = self.args.target.port or 445

        for dialect in self.mapping.keys():
            try:
                smb_client = SMBConnection(
                    remoteName="*SMBSERVER",
                    remoteHost=self.args.target.ip,
                    sess_port=port,
                    preferredDialect=dialect,
                    timeout=5
                )
                
                # Login will fail, but NTLM login challenge provides more info about server
                try:
                    smb_client.login('', '')
                except Exception:
                    pass
                
                if test:
                    getters = {
                        smb_client.getSMBServer: "getSMBServer",
                        smb_client.getDialect: "getDialect",
                        smb_client.getServerName: "getServerName",
                        smb_client.getClientName: "getClientName",
                        smb_client.getRemoteName: "getRemoteName",
                        smb_client.getServerDomain: "getServerDomain",
                        smb_client.getServerDNSDomainName: "getServerDNSDomainName",
                        smb_client.getServerDNSHostName: "getServerDNSHostName",
                        smb_client.getServerOS: "getServerOS",
                        smb_client.getServerOSMajor: "getServerOSMajor",
                        smb_client.getServerOSMinor: "getServerOSMinor",
                        smb_client.getServerOSBuild: "getServerOSBuild",
                        smb_client.doesSupportNTLMv2: "doesSupportNTLMv2",
                        smb_client.isLoginRequired: "isLoginRequired",
                        smb_client.isSigningRequired: "isSigningRequired",
                        smb_client.getCredentials: "getCredentials",
                        smb_client.getIOCapabilities: "getIOCapabilities",
                    }
                    
                    test = {}
                    for getter in getters.keys():
                        result = _get_if_available(getter)
                        if result is not None:
                            test[getters[getter]] = result

                self.pass_client_info(smb_client)
                smb_client.logoff()
            except Exception as e:
                error_str = str(e)
                
            if just_info and self.results.Dialects != []:
                break
