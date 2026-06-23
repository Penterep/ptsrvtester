import argparse
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional

from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib


# enum from ptdefs dict
class Out(Enum):
    TEXT = "TEXT"
    TITLE = "TITLE"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    OK = "OK"
    VULN = "VULN"
    NOTVULN = "NOTVULN"
    REDIR = "REDIR"
    PARSED = "PARSED"
    TITNOBULL = "TITNOBULL"
    ADDITIONS = "ADDITIONS"


class BaseArgs(argparse.Namespace):
    json: bool
    debug: bool
    module: str

    @abstractmethod
    def add_subparser(self, name: str, subparsers: argparse._SubParsersAction) -> None:
        """
        Each argument namespace specifies its own argument parser

        The code of this abstract method is only for demonstration purposes
        """

        modname = __name__.split(".")[-1]
        parser = subparsers.add_parser(modname, add_help=True)

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        from .utils.helpers import valid_target

        parser.add_argument(
            "target", type=valid_target, help="IP[:PORT] (e.g. 127.0.0.1 or 127.0.0.1:21)"
        )

        actions = parser.add_argument_group("actions")
        actions.add_argument("--banner", action="store_true", help="get the service banner")


class BaseModule(ABC):
    @staticmethod
    @abstractmethod
    def module_args() -> BaseArgs:
        return BaseArgs()

    @abstractmethod
    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        raise NotImplementedError

    @abstractmethod
    def run(self) -> None:
        raise NotImplementedError
    
    @abstractmethod
    def output(self) -> None:
        raise NotImplementedError

    def ptdebug(
        self,
        string: str,
        out: Out = Out.TEXT,
        title: bool = False,
        end: str = "\n",
        *,
        indent_override: Optional[int] = None,
    ) -> None:
        """Verbose-only (-vv / ``args.debug``): ``ptprinthelper.ptprint`` in ADDITIONS.

        Default indent is 4 spaces for every line (subsection ``title=True`` uses the same
        indent so blocks align under section headings like ``[+] RCPT TO limit``).
        Use ``indent_override=0`` when continuing the same physical line (e.g. table cells).
        ``out`` and ``title`` are kept for call-site compatibility; color is always ADDITIONS.
        Suppressed when ``--json`` is set.
        """
        if not self.args.debug or self.args.json:
            return

        if indent_override is not None:
            indent = indent_override
        else:
            indent = 4

        lines = string.splitlines()
        if not lines:
            lines = [string]

        if len(lines) == 1:
            ptprinthelper.ptprint(
                lines[0],
                "ADDITIONS",
                True,
                end=end,
                flush=True,
                colortext=True,
                indent=indent,
            )
            return

        for i, line in enumerate(lines):
            last = i == len(lines) - 1
            ptprinthelper.ptprint(
                line,
                "ADDITIONS",
                True,
                end=end if last else "\n",
                flush=True,
                colortext=True,
                indent=indent,
            )

    def ptprint(
        self,
        string: str,
        out: Out = Out.TEXT,
        title: bool = False,
        end: str = "\n",
        json: bool = False,
    ):
        """Prints in normal mode, with optional JSON override in JSON mode.

        Args:
            string (str): _description_
            out (Out, optional): output category. Defaults to Out.TEXT.
            title (bool, optional): whether to print a title. Defaults to False.
            end (str, optional): line ending. Defaults to "\n".
            json (bool, optional): force-print JSON in JSON mode. Defaults to False.
        """

        if json and not self.args.json:
            # trying to print JSON in normal mode
            return
        elif not json and self.args.json:
            # trying to print normal text in JSON mode
            return

        if title:
            colortext = True
            category = Out.TITLE.value
        else:
            # Out.INFO should have colored text (yellow) for headings
            colortext = (out == Out.INFO)
            category = out.value

        ptprinthelper.ptprint(string, category, True, flush=True, colortext=colortext, end=end)
