from ptlibs.ptjsonlib import PtJsonLib
import argparse
from ._base import BaseModule, BaseArgs, Out
from dataclasses import dataclass
from typing import List, Optional
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
        
        tests.add_argument("-ts", "--test", help="Testing toolbox for SMB")
        
        # maybe still usable
        # smb_subparsers = parser.add_subparsers(dest="command", help="Select SMB command", required=True)
        
        # smb_info = smb_subparsers.add_parser("-i", "--info", help="Retrieve SMB host information")
        # smb_info.add_argument("-ip", "--ip", help="IP address of the target SMB server.")
        # smb_info.add_argument("-p", "--port", type=int, default=445, help="Port of the SMB server (default: 445).")


@dataclass
class SMBResult:
    Info: dict
    Dialects: List


class SMB(BaseModule):
    mapping = {
        SMB_DIALECT:        "SMBv1",
        SMB2_DIALECT_002:   "SMBv2.0.2",
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

        if self.args.test == "version":
            self.info = self.get_ver()
    
    def output(self):
        if self.args.test == "version":
            ptprint("SMB server version info:", bullet_type="TITLE")
            ptprint(f"Target: {self.results.Info['target']}:{self.results.Info['port']}",
                    bullet_type="INFO")
            ptprint(f"Server name: {self.results.Info['server_name']}", bullet_type="INFO")
            ptprint(f"Server version: {self.results.Info['os_version']}", bullet_type="INFO")
            is_vuln = "SMBv1" in self.results.Dialects
            ptprint(f"Supported dialects: {", ".join(self.results.Dialects)}",
                    bullet_type="VULN" if is_vuln else "NOTVULN")

    def fill_results_info(self, data: dict) -> None:
        for key in data.keys():
            if key not in self.results.Info.keys():
                self.results.Info[key] = data[key]
            elif self.results.Info[key] == "unknown":
                self.results.Info[key] = data[key]


    def pass_client_info(self, smb_client: SMBConnection) -> None:
        negotiated = smb_client.getDialect()
        negotiated_dialect = self.mapping.get(negotiated, f"Unknown dialect({negotiated})")
        if negotiated_dialect not in self.results.Dialects:
            self.results.Dialects.append(negotiated_dialect)

        server_name = _get_if_available(smb_client.getServerName)
        if not server_name:
            server_name = _get_if_available(smb_client.getServerDNSHostName)
        if not server_name:
            server_name = "unknown"

        os_name = _get_if_available(smb_client.getServerOS)
        os_version = ""
        for getter in [smb_client.getServerOSMajor, smb_client.getServerOSMinor, smb_client.getServerOSBuild]:
            out = _get_if_available(getter)
            if out is None:
                break
            os_version += "." + out

        if os_version == "":
            os_version = "unknown"
        else:
            os_version = os_version[1:]
        
        self.fill_results_info({
            "server_name": server_name,
            "os_version": (os_version if os_name is None or os_name == "" else f"{os_name} ({os_version})")
        })

    
    def get_ver(self) -> None:
        """
        Checks the host system version and SMB dialect
        """
        # TODO: add check if server even connected
        # TODO: add timeout if server doesn't respond
        # TODO: fix server name and server ver fetch

        port = self.args.target.port or 445

        for dialect in self.mapping.keys():
            try:
                smb_client = SMBConnection(
                    remoteName="*SMBSERVER",
                    remoteHost=self.args.target.ip,
                    sess_port=port,
                    preferredDialect=dialect
                )
                self.pass_client_info(smb_client)
                smb_client.logoff()
            except Exception:
                continue
