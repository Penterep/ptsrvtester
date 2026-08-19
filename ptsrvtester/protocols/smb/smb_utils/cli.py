import argparse
from ptsrvtester.protocols._base import BaseArgs

from .helpers import Target, valid_target_smb


class SMBArgs(BaseArgs):
    target: Target

    @staticmethod
    def get_help():
        return [
            {"description": ["SMB Testing Module"]},
            {"usage": ["ptsrvtesNTPArgster smb <IP:PORT> <command> <options>"]},
            {"usage_example": [
                "ptsrvtester smb 192.168.1.1 -ts info,dialects",
                "ptsrvtester smb localhost:1234 -ts encryption"
                "ptsrvtester smb -h",
            ]},
            {"options": [
                ["-h", "--help", "", "Prints this menu"],
                ["-ts", "--tests", "<test>", "Comma-separated test codes (e.g. info,dialects) or ALL", "Options: info, dialects, encryption"]
            ]},
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """ptsrvtester smb 192.168.1.1 -ts info
ptsrvtester smb -h"""
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
        
        tests.add_argument(
            "-ts", "--tests", type=str, default=None, metavar="<test>", dest="tests",
            help="Comma-separated test codes (e.g. info,dialects) or ALL. Options: info, dialects, encryption",
        )