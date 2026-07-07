from ._base import BaseModule, BaseArgs, Out
from ptlibs.ptjsonlib import PtJsonLib

class SMBArgs(BaseArgs):
    def get_help(self):
        return [
            {"description": ["SMB Testing Module"]},
            {"usage": ["test"]},
            {"usage_example": [
                "ptsrvtester smb -ts"
            ]},
            {"options": ["-h"]},
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = "example usage:\nptsrvtester smb -ts"
        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        
        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing



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
        