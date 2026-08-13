import argparse
import importlib.util
import ipaddress
import os
import socket
import sys
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.threads import ptthreads, printlock
from ptlibs.ptprinthelper import out_if


@dataclass
class Target:
    """A parsed ``HOST[:PORT]`` target. Shared by every protocol.

    Mutable on purpose: protocols fill a default ``port`` (0 -> 22/161/...) in
    their ``_prepare_target()``.
    """
    ip: str
    port: int


def valid_target(target: str, port_required: bool = False, domain_allowed: bool = False) -> Target:
    """Parse/validate a ``HOST[:PORT]`` target into a :class:`Target`.

    Single source of truth for every protocol's ``-tg/--target`` argument. Use
    it as the argparse ``type=`` (usually through a per-protocol wrapper that
    sets policy such as ``domain_allowed=True``) and feed that to
    :func:`add_target_arg`.

    Args:
        target: the raw ``HOST[:PORT]`` string from argparse.
        port_required: require an explicit ``:PORT``. Defaults to False.
        domain_allowed: allow (and resolve) hostnames, not just IPs. Defaults to False.

    Raises:
        argparse.ArgumentError: invalid format, IP, hostname or port.

    Returns:
        Target: parsed target (``port`` is 0 when omitted).
    """
    split = target.split(":")
    if not port_required and len(split) > 2:
        raise argparse.ArgumentError(None, "The target has to be IP[:PORT]")
    if port_required and len(split) != 2:
        raise argparse.ArgumentError(None, "The target has to be IP:PORT")

    host = split[0]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not domain_allowed:
            raise argparse.ArgumentError(None, "Invalid target IP address") from None
        try:
            socket.gethostbyname(host)
        except OSError:
            raise argparse.ArgumentError(
                None, f"Cannot resolve target name '{host}' into IP address"
            ) from None

    if len(split) > 1:
        try:
            port = int(split[1])
            if port <= 0 or port >= 65536:
                raise ValueError
        except ValueError:
            raise argparse.ArgumentError(None, "Invalid PORT number") from None
    else:
        port = 0
    return Target(host, port)


def add_target_arg(
    parser: argparse.ArgumentParser,
    *,
    validator=None,
    required: bool = True,
    metavar: str = "<host>",
    help: Optional[str] = None,
) -> None:
    """Add the standard ``-tg/--target`` switch to ``parser``.

    Centralises the switch so every protocol is identical: always ``-tg``,
    always ``dest="target"`` (so ``args.target`` is uniform downstream), and
    ``required=True`` by default -- an optional switch is NOT required unless we
    say so (a positional argument was; this preserves that).

    Args:
        validator: argparse ``type=`` callable; defaults to :func:`valid_target`.
            Pass a per-protocol wrapper (e.g. ``valid_target_ssh``) for policy.
        required: whether the target must be supplied. Defaults to True.
        metavar / help: display overrides (help keeps per-protocol port hints).
    """
    parser.add_argument(
        "-tg", "--target",
        dest="target",
        required=required,
        type=validator or valid_target,
        metavar=metavar,
        help=help or "IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or host.example.com:22)",
    )


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

        add_target_arg(parser, validator=valid_target)

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


class ModuleContext:
    """Everything a module's ``run(ctx)`` receives.

    The core fields are protocol-agnostic; a protocol's ``build_context()`` adds
    protocol-specific handles onto the same object as plain attributes.
    """

    def __init__(self, *, args, ptjsonlib, target, print_lock):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.target = target                       # (ip, port)
        self.print_lock = print_lock
        self.json = bool(getattr(args, "json", False))
        self.verbose = bool(getattr(args, "debug", False))

    def out(self, string="", category="TEXT", *, colortext=False, indent=0, condition=None):
        """Buffer one formatted line (printed by the main after the module finishes).

        Suppressed in JSON mode unless ``condition`` is given explicitly.
        """
        cond = (not self.json) if condition is None else condition
        self.print_lock.add_string_to_output(
            out_if(string, category, cond, colortext=colortext, indent=indent)
        )

    def debug(self, string="", *, indent=4):
        """Buffer a verbose-only line (``-vv``); suppressed in JSON mode."""
        if self.verbose and not self.json:
            self.print_lock.add_string_to_output(
                out_if(string, "ADDITIONS", True, colortext=True, indent=indent)
            )


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
    ``build_context()``. Everything else (discovery, ``-ts`` selection, parallel
    execution with ptlibs ``PtThreads``, isolated ``PrintLock`` output flushed in
    order, JSON output) is inherited unchanged. See ``protocols/_TEMPLATE_main.py``
    for the copyable skeleton.

    Module contract (one file per module in the protocol's ``./modules/``)::

        __MODULELABEL__ = "Human-readable one-line label"   # section header
        __MODULECODE__  = "BANNER"      # optional; -ts code, defaults to FILENAME.upper()
        __ORDER__     = 10            # optional; run/print order, defaults to 100

        def run(ctx) -> None: ...

    ``ctx`` (a :class:`ModuleContext`) gives every module ``args``, ``target``,
    ``ptjsonlib``, ``print_lock``, ``out()``/``debug()``, ``json``/``verbose`` and
    whatever ``build_context()`` injects.
    """

    #: Sub-directory (next to the concrete main file) that holds the protocol's modules.
    MODULES_DIRNAME = "modules"

    # ---- generic machinery (inherited unchanged; do not copy per protocol) ----

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib) -> None:
        if not isinstance(args, self.ARGS_CLASS):
            raise argparse.ArgumentError(
                None, f'module "{getattr(args, "module", "?")}" received wrong arguments namespace'
            )
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.use_json = bool(getattr(args, "json", False))
        self.ptthreads = ptthreads.PtThreads()
        self._lock = threading.Lock()
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

        if skipped and getattr(self.args, "debug", False) and not self.use_json:
            sys.stdout.write("[skipped non-module files: " + ", ".join(skipped) + "]\n")
        return discovered

    def _import_module_file(self, name: str, path: str):
        # The sys.modules name is prefixed with the protocol so same-named modules
        # from different protocols don't collide. NAME comes from the subclass.
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
            chosen = list(discovered.keys())
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
        self._outputs = {}
        # PtThreads.threads() consumes (mutates) the list it is given, so hand it
        # a copy and keep `selected` intact for the ordered flush below.
        self.ptthreads.threads(
            list(selected),
            lambda module_code: self._run_module(module_code, discovered, extras),
            self._thread_count(),
        )

        # Flush per-module buffers back in the selected (deterministic) order.
        for code in selected:
            chunk = self._outputs.get(code, "")
            if chunk:
                sys.stdout.write(chunk)
                sys.stdout.flush()

    def _run_module(self, code: str, discovered: dict[str, _DiscoveredModule], extras: dict) -> None:
        entry = discovered[code]
        lock = printlock.PrintLock()
        ctx = self._make_context(lock, extras)
        # The main owns the standardized section header so each module does not.
        ctx.out(entry.label, "INFO", colortext=True)
        try:
            entry.module.run(ctx)
        except Exception as e:  # one failing module must not abort the rest
            ctx.out(f"Error in module {code}: {e}", "ERROR")
        with self._lock:
            self._outputs[code] = lock.get_output_string()

    def _make_context(self, print_lock, extras: dict) -> ModuleContext:
        ctx = ModuleContext(
            args=self.args,
            ptjsonlib=self.ptjsonlib,
            target=self.target,
            print_lock=print_lock,
        )
        for key, value in extras.items():
            setattr(ctx, key, value)
        return ctx

    def _thread_count(self) -> int:
        return max(1, int(getattr(self.args, "module_threads", 1) or 1))

    def output(self) -> None:
        self.ptjsonlib.set_status("finished")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())

    # ---- protocol-specific hooks (override in the subclass) ----

    #: Short protocol identity; also namespaces this protocol's modules in sys.modules.
    NAME: str = "base"
    #: The protocol's argparse namespace class (used for the isinstance check).
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
