import argparse
import importlib.util
import os
import sys
from abc import ABC, abstractmethod
from enum import Enum

from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.ptprinthelper import ptprint


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


class ModuleContext:
    """Everything a module's ``run(ctx)`` receives.

    The core fields are protocol-agnostic; a protocol's ``build_context()`` adds
    protocol-specific handles onto the same object as plain attributes.
    """

    def __init__(self, *, args, ptjsonlib, target):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.target = target                       # (ip, port)
        self.json = bool(getattr(args, "json", False))
        self.verbose = bool(getattr(args, "debug", False))
        self.module_code = None                     # set by BaseMain._run_module

    def out(self, string="", category="TEXT", *, colortext=False, indent=0, condition=None):
        """Buffer one formatted line (printed by the main after the module finishes).

        Suppressed in JSON mode unless ``condition`` is given explicitly.
        """
        cond = (not self.json) if condition is None else condition
        ptprint(string, category, cond, colortext=colortext, indent=indent)

    def debug(self, string="", *, indent=4):
        """Verbose breadcrumb: record it in the JSON log AND print it under ``-vv``.

        Modules call this with a short note of what they are doing right now. The
        note always lands in ``results.log`` (so the structured output keeps the
        run trace regardless of ``-vv`` / ``-j``) and is also printed live, as a
        grey ``[*]`` line, only with ``-vv`` and not in JSON mode. This is what
        feeds the ``-vv`` switch.
        """
        if string != "":
            self.log(string)
        if self.verbose and not self.json:
            ptprint(string, "ADDITIONS", True, colortext=True, indent=indent)

    def log(self, message="") -> None:
        """Append one entry to the JSON ``results.log`` via ptlibs ``add_to_log``.

        Unlike :meth:`out` (which prints to the terminal), this records a line in
        the structured output regardless of ``-j`` / ``-vv``. Entries are kept in
        order and separated by ``\\r\\n`` by ptlibs. :meth:`debug` routes through
        here, so a module's breadcrumbs are always captured in the log.
        """
        self.ptjsonlib.add_to_log(str(message))

    def add_vulnerability(self) -> None:
        """Record the running module's finding in ``results.vulnerabilities``.

        Adds ONLY the code, derived from the module as ``PTV-SVC-<MODULECODE>``
        (e.g. BANNER -> ``PTV-SVC-BANNER``) — no request/response/evidence. ptlibs
        de-duplicates by code, so a module records at most one entry.
        """
        self.ptjsonlib.add_vulnerability(vuln_code=f"PTV-SVC-{self.module_code}")


class _DiscoveredModule:
    """A module found in a protocol's ./modules/ plus its resolved metadata."""

    def __init__(self, code: str, label: str, order: int, module):
        self.code = code
        self.label = label
        self.order = order
        self.module = module


class BaseMain(BaseModule):
    """Generic protocol "main": discovers, selects and runs modules from ``./modules/``.

    A concrete protocol subclasses this and provides ONLY the protocol-specific
    bits — ``NAME``, ``ARGS_CLASS``, ``module_args()``, ``_prepare_target()`` and
    ``build_context()``. Everything else (discovery, ``-ts`` selection) is
    inherited unchanged. See ``protocols/_TEMPLATE_main.py`` for the copyable skeleton.

    Module contract (one file per module in the protocol's ``./modules/``)::

        __MODULELABEL__ = "Human-readable one-line label"   # section header
        __MODULECODE__  = "BANNER"      # optional; -ts code, defaults to FILENAME.upper()
        __ORDER__     = 10            # optional; run/print order, defaults to 100

        def run(ctx) -> None: ...

    ``ctx`` (a :class:`ModuleContext`) gives every module ``args``, ``target``,
    ``ptjsonlib``, ``out()``/``debug()``, ``json``/``verbose`` and
    whatever ``build_context()`` injects.
    """

    MODULES_DIRNAME = "modules"

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib) -> None:
        if not isinstance(args, self.ARGS_CLASS):
            raise argparse.ArgumentError(
                None, f'module "{getattr(args, "module", "?")}" received wrong arguments namespace'
            )
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.use_json = bool(getattr(args, "json", False))
        self._outputs: dict[str, str] = {}
        self._prepare_target()

    def _modules_dir(self) -> str:
        """The ``modules/`` directory next to the concrete subclass's own file."""
        module_file = sys.modules[type(self).__module__].__file__
        return os.path.join(os.path.dirname(os.path.abspath(module_file)), self.MODULES_DIRNAME)

    def _discover_modules(self) -> dict[str, _DiscoveredModule]:
        """Import every ``modules/*.py`` (not ``_``-prefixed) exposing ``run``.

        Files that fail to import or lack a callable ``run`` are skipped (they
        are not modules yet); a note is buffered only in verbose mode.
        """
        modules_dir = self._modules_dir()
        discovered: dict[str, _DiscoveredModule] = {}
        skipped: list[str] = []
        for fname in sorted(os.listdir(modules_dir)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            name = fname[:-3]
            path = os.path.join(modules_dir, fname)
            try:
                module = self._import_module_file(name, path)
            except Exception as e:
                skipped.append(f"{name} ({e})")
                continue
            run_fn = getattr(module, "run", None)
            if not callable(run_fn):
                skipped.append(f"{name} (no run())")
                continue
            code = str(getattr(module, "__MODULECODE__", name.upper())).upper()
            label = str(getattr(module, "__MODULELABEL__", f"{code} module"))
            order = int(getattr(module, "__ORDER__", 100))
            discovered[code] = _DiscoveredModule(code, label, order, module)

        for code, entry in self._discover_shared_modules().items():
            discovered.setdefault(code, entry)

        if skipped and getattr(self.args, "debug", False) and not self.use_json:
            sys.stdout.write("[skipped non-module files: " + ", ".join(skipped) + "]\n")
        return discovered

    def _discover_shared_modules(self) -> dict[str, _DiscoveredModule]:
        """Import every runnable ``_shared/modules/*.py`` as a real package member.

        Shared modules are loaded by dotted path (not spec-from-file) so a
        protocol that overrides :meth:`_import_module_file` for its own modules
        does not affect how the shared ones import.
        """
        try:
            import ptsrvtester.protocols._shared.modules as shared_pkg
        except Exception:
            return {}
        shared_dir = os.path.dirname(os.path.abspath(shared_pkg.__file__))
        discovered: dict[str, _DiscoveredModule] = {}
        for fname in sorted(os.listdir(shared_dir)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            name = fname[:-3]
            try:
                module = importlib.import_module(
                    f"ptsrvtester.protocols._shared.modules.{name}"
                )
            except Exception:
                continue
            if not callable(getattr(module, "run", None)):
                continue
            code = str(getattr(module, "__MODULECODE__", name.upper())).upper()
            label = str(getattr(module, "__MODULELABEL__", f"{code} module"))
            order = int(getattr(module, "__ORDER__", 100))
            discovered[code] = _DiscoveredModule(code, label, order, module)
        return discovered

    def _import_module_file(self, name: str, path: str):
        mod_name = f"_ptsrv_{self.NAME}_module_{name}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load spec for {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = module
        spec.loader.exec_module(module)
        return module

    def _select_codes(self, discovered: dict[str, _DiscoveredModule]) -> list[str]:
        """Resolve ``-ts`` into an ordered list of module codes.

        Empty / ``ALL`` -> every discovered module. Ordered by ``__ORDER__`` then code.
        """
        raw = getattr(self.args, "tests", None)
        codes = [c.strip().upper() for c in raw.split(",")] if raw else []
        codes = [c for c in codes if c]
        if not codes or "ALL" in codes:
            chosen = [
                code
                for code, entry in discovered.items()
                if getattr(entry.module, "__RUN_IN_ALL__", True)
            ]
        else:
            unknown = [c for c in codes if c not in discovered]
            if unknown:
                available = ", ".join(sorted(discovered)) or "(none)"
                self.ptjsonlib.end_error(
                    f"Unknown module(s): {', '.join(unknown)}. Available: ALL, {available}",
                    self.use_json,
                )
                return []
            chosen = [c for c in codes if c in discovered]
        chosen.sort(key=lambda c: (discovered[c].order, c))
        return chosen

    def run(self) -> None:
        discovered = self._discover_modules()
        if not discovered:
            self.ptjsonlib.end_error(
                f"No runnable modules found in {self.MODULES_DIRNAME}/", self.use_json
            )
            return

        selected = self._select_codes(discovered)
        if not selected:
            return

        extras = self.build_context()
        for testcode in selected:
            self._run_module(testcode, discovered, extras)

    def _run_module(self, code: str, discovered: dict[str, _DiscoveredModule], extras: dict) -> None:
        entry = discovered[code]
        ctx = self._make_context(extras)
        ctx.module_code = code
        ctx.out(entry.label, "INFO", colortext=True)
        try:
            entry.module.run(ctx)
        except Exception as e:
            ctx.out(f"Error in module {code}: {e}", "ERROR")

    def _make_context(self, extras: dict) -> ModuleContext:
        ctx = ModuleContext(
            args=self.args,
            ptjsonlib=self.ptjsonlib,
            target=self.target,
        )
        for key, value in extras.items():
            setattr(ctx, key, value)
        return ctx

    def output(self) -> None:
        self.ptjsonlib.set_status("finished")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())

    NAME: str = "base"
    ARGS_CLASS: type = BaseArgs

    def _prepare_target(self) -> None:
        """Resolve ``self.target`` (and any host state) before modules run.

        Default: best-effort ``(ip, port)`` from ``args.target``. Override to add
        protocol-specific behaviour (default port, DNS resolution, …).
        """
        target = getattr(self.args, "target", None)
        if target is None:
            self.target = None
        else:
            self.target = (getattr(target, "ip", None), getattr(target, "port", None))

    def build_context(self) -> dict:
        """Protocol handles injected onto every module's ``ctx`` (besides core fields).

        Override to expose whatever the protocol's modules need (a connection
        factory, resolved host, credentials, …); modules read them as ``ctx.<name>``.
        """
        return {}
