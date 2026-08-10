import argparse
from ptsrvtester.protocols._base import BaseArgs

from .helpers import Target  #TODO: add valid_target func

OPTIONS = ["info", "dialects", "encryption"]
# bad solution since they're generated automatically; will change once the system is settled


class SMBArgs(BaseArgs):
    target: Target
    get_version: bool

    @staticmethod
    def get_help():
        return [
            {"description": ["SMB Testing Module"]},
            {"usage": ["ptsrvtester smb <IP:PORT> <command> <options>"]},
            {"usage_example": [
                "ptsrvtester smb 192.168.1.1 -ts info",
                "ptsrvtester smb -h",
            ]},
            {"options": [
                ["-h", "--help", "", "Prints this menu"],
                ["-ts", "--test", "<option>", "Gets information about server", "Options: info, dialects, encryption"]
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
            # type=valid_target_smb,  # used to be a test for target validity; left in in case of errors
            help="""IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:445); If PORT is left empty, 445 is default""",
        )
        
        tests = parser.add_argument_group(
            "TESTING TOOLS",
            "Toolbox of non-invasive tests on a specified target server"
        )
        
        tests.add_argument("-ts", "--test", help="Testing toolbox for SMB",
                           choices=OPTIONS, nargs='*')