from __future__ import annotations

import argparse
import inspect
import os
import re
from functools import wraps

from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.ptprinthelper import out_if, ptprint

from ..._base import BaseMain, ModuleContext as BaseModuleContext, _DiscoveredModule


_ANSI_ESCAPE = re.compile(
    r"\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~]|[@-_])"
)


class ModuleContext(BaseModuleContext):
    def out(self, string="", category="TEXT", *, colortext=False, indent=0, condition=None):
        if condition is not None and not condition:
            return
        self.log(string, category, colortext=colortext, indent=indent)
        show = not self.json if condition is None else condition
        if string == "":
            if show:
                print(out_if(string, category, True, colortext=colortext, indent=indent), flush=True)
            return
        ptprint(string, category, show, colortext=colortext, indent=indent, flush=True)

    def debug(self, string="", *, indent=4):
        if self.verbose:
            self.out(string, "ADDITIONS", colortext=True, indent=indent)

    def log(self, string="", category="TEXT", *, colortext=False, indent=0):
        append_log = getattr(self.ptjsonlib, "add_to_log", None)
        if callable(append_log):
            line = out_if(str(string), category, True, colortext=colortext, indent=indent)
            line = _ANSI_ESCAPE.sub("", line)
            append_log(line.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n"))


def end_protocol_error(args, ptjsonlib, message: str, *, category="ERROR"):
    context = ModuleContext(args=args, ptjsonlib=ptjsonlib, target=None)
    context.log(f"Error: {message}" if category == "ERROR" else message, category)
    use_json = bool(getattr(args, "json", False))
    if category == "ERROR":
        ptjsonlib.end_error(message, use_json)
        return
    parameters = inspect.signature(ptjsonlib.end_error).parameters
    if "category" in parameters or any(
        item.kind == inspect.Parameter.VAR_KEYWORD for item in parameters.values()
    ):
        ptjsonlib.end_error(message, use_json, category=category)
        return
    # PtJsonLib.end_error() has no category parameter.
    ptjsonlib.set_status("error", str(message))
    if use_json:
        print(ptjsonlib.get_result_json(), flush=True)
    else:
        ptprint(str(message), category, colortext=True, flush=True)
    raise SystemExit(1)


def protocol_json_errors(method):
    @wraps(method)
    def guarded(self, *values, **options):
        try:
            return method(self, *values, **options)
        except (argparse.ArgumentError, OSError) as exc:
            args = getattr(self, "args", None)
            report = getattr(self, "ptjsonlib", None)
            if args is None:
                args = values[0] if values else options.get("args")
            if report is None:
                report = values[1] if len(values) > 1 else options.get("ptjsonlib")
            if not getattr(args, "json", False) or report is None:
                raise
            message = exc.message if isinstance(exc, argparse.ArgumentError) else str(exc)
            end_protocol_error(
                args, report, message,
                category="ERROR" if isinstance(exc, argparse.ArgumentError) else "TITLE",
            )
            raise
    return guarded


class ProtocolMain(BaseMain):
    def __init__(self, args, ptjsonlib):
        if (
            not callable(getattr(PtJsonLib, "add_to_log", None))
            or "poc" not in inspect.signature(PtJsonLib.add_vulnerability).parameters
        ):
            raise argparse.ArgumentError(
                None, f"{self.NAME.upper()} reporting requires ptlibs >=1.0.73,<2; "
                "upgrade ptlibs in the environment running ptsrvtester",
            )
        super().__init__(args, ptjsonlib)

    def _make_context(self, extras):
        context = ModuleContext(args=self.args, ptjsonlib=self.ptjsonlib, target=self.target)
        for key, value in extras.items():
            setattr(context, key, value)
        return context

    def _end_error(self, message, *, category="ERROR"):
        end_protocol_error(self.args, self.ptjsonlib, message, category=category)

    def _discover_modules(self):
        directory = self._modules_dir()
        discovered = {}
        skipped = []
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue
            name = filename[:-3]
            try:
                module = self._import_module_file(name, os.path.join(directory, filename))
            except Exception as exc:
                skipped.append(f"{name} ({exc})")
                continue
            if not callable(getattr(module, "run", None)):
                skipped.append(f"{name} (no run())")
                continue
            code = str(getattr(module, "__MODULECODE__", name.upper())).upper()
            label = str(getattr(module, "__MODULELABEL__", f"{code} module"))
            order = int(getattr(module, "__ORDER__", 100))
            discovered[code] = _DiscoveredModule(code, label, order, module)
        for code, entry in self._discover_shared_modules().items():
            discovered.setdefault(code, entry)
        if skipped and getattr(self.args, "debug", False):
            ModuleContext(
                args=self.args, ptjsonlib=self.ptjsonlib, target=self.target,
            ).debug("[skipped non-module files: " + ", ".join(skipped) + "]", indent=0)
        return discovered

    def run(self):
        discovered = self._discover_modules()
        if not discovered:
            self._end_error(f"No runnable modules found in {self.MODULES_DIRNAME}/")
            return
        selected = self._select_codes(discovered)
        if not selected:
            return
        extras = self.build_context()
        for code in selected:
            self._run_module(code, discovered, extras)
