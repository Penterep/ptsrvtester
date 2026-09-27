import argparse
from ptsrvtester.protocols._base import BaseArgs

from .helpers import Target, valid_target_ntp


class NTPArgs(BaseArgs):
    target: Target

    @staticmethod
    def get_help():
        return [
            {"description": ["NTP Testing Module"]},
            {"usage": ["ptsrvtester ntp <IP:PORT> <command> <options>"]},
            {"usage_example": [
                "ptsrvtester ntp 192.168.1.1 -ts info",
                "ptsrvtester ntp -h",
            ]},
            {"options": [
                ["-h", "--help", "", "Prints this menu"],
                ["-ts", "--tests", "<test>", "Comma-separated test codes (e.g. info,dialects) or ALL", "Options: info, dialects, encryption"]
            ]},
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """ptsrvtester ntp 192.168.1.1 -ts info
ptsrvtester ntp -h"""
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
            type=valid_target_ntp,
            help="""IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:445); If PORT is left empty, 123 is default""",
        )
        
        tests = parser.add_argument_group(
            "TESTING TOOLS",
            "Toolbox of non-invasive tests on a specified target server"
        )
        
        tests.add_argument(
            "-ts", "--tests", type=str, default=None, metavar="<test>", dest="tests",
            help="Comma-separated test codes (e.g. info,template) or ALL. Options: info",
        )