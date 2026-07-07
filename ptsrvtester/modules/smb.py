from ptlibs.ptjsonlib import PtJsonLib
from dataclasses import dataclass
import argparse
import smbprotocol
import impacket

from ._base import BaseModule, BaseArgs, Out
from .utils.helpers import (
    valid_target,
    Target
)


def valid_target_smb(target: str) -> Target:
    return valid_target(target, domain_allowed=True)


class SMBArgs(BaseArgs):
    ip: str
    port: int
    domain: str
    def get_help(self):
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
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:25)",
        )
        
        parser.add_argument("-v", "--version", help="Gets SMB version of host")
        
        # smb_subparsers = parser.add_subparsers(dest="command", help="Select SMB command", required=True)
        
        # smb_info = smb_subparsers.add_parser("-i", "--info", help="Retrieve SMB host information")
        # smb_info.add_argument("-ip", "--ip", help="IP address of the target SMB server.")
        # smb_info.add_argument("-p", "--port", type=int, default=445, help="Port of the SMB server (default: 445).")
        



class SMB(BaseModule):
    @staticmethod
    def module_args():
        return SMBArgs()
    
    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        pass
    
    def run(self):
        pass
    
    def output(self):
        pass
        