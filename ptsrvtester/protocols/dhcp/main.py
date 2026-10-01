"""TEMPLATE for a protocol main — copy this to protocols/DHCP/DHCP_main.py.

The generic machinery (module discovery, ``-ts`` selection, parallel execution,
ordered output, the ``ctx`` object) lives in :class:`BaseMain` (protocols/_base.py)
and is inherited unchanged. A protocol main declares only the five items below.

Steps to stand up a new protocol ``DHCP``:
  1. Create ``protocols/DHCP/`` with an ``__init__.py`` exporting the class.
  2. Put the CLI/args class in ``protocols/DHCP/DHCP_utils/cli.py`` (``DHCPArgs``).
  3. Copy this file to ``protocols/DHCP/DHCP_main.py`` and fill in the class below.
  4. Add tests as ``protocols/DHCP/tests/*.py`` (see protocols/smtp/tests/_TEMPLATE.py).
  5. Register the protocol in ``ptsrvtester.py`` MODULES: one line
     ``"DHCP": ("ptsrvtester.protocols.DHCP:DHCP", "DHCP testing module")``.
"""
import sys
from ptlibs.threads import printlock
from ptlibs.ptprinthelper import out_if

from .._base import BaseMain, BaseArgs, BaseModule
from .utils.cli import DHCPArgs



class DHCP(BaseMain):
    #: Short protocol identity (also namespaces this protocol's tests).
    NAME = "dhcp"
    #: The argparse namespace class for this protocol's options.
    ARGS_CLASS = DHCPArgs  # -> DHCPArgs

    @staticmethod
    def module_args() -> BaseArgs:
        # return DHCPArgs()
        return DHCPArgs()

    def _prepare_target(self) -> None:
        """Resolve self.target = (ip, port) before any module runs.

        Fill in protocol defaults (e.g. default port) and host resolution.
        If you don't override this, BaseMain's default takes (ip, port) straight
        from args.target.
        """

        self.target_host = None
        self.target = ("", 67)

        self.interface = self.args.interface

    def _run_module(self, code: str, discovered, extras: dict) -> None:
        """Heading now; ``-vv`` live; verdicts when the test finishes."""
        entry = discovered[code]
        lock = printlock.PrintLock()
        ctx = self._make_context(lock, extras)
        if not self.use_json:
            def live_debug(string="", *, indent=4):
                if not ctx.verbose:
                    return
                line = out_if(string, "ADDITIONS", True, colortext=True, indent=indent)
                if line:
                    sys.stdout.write(line if line.endswith("\n") else line + "\n")
                    sys.stdout.flush()
            ctx.debug = live_debug
        if entry.label.strip() and not self.use_json:
            sys.stdout.write(out_if(entry.label, "INFO", True, colortext=True) + "\n")
            sys.stdout.flush()
        try:
            entry.module.run(ctx)
        except Exception as e:
            ctx.out(f"Error in module {code}: {e}", "ERROR")
        chunk = lock.get_output_string()
        if chunk and not self.use_json:
            sys.stdout.write(chunk)
            sys.stdout.flush()
        with self._lock:
            self._outputs[code] = "" if not self.use_json else chunk

    def build_context(self) -> dict:
        """Protocol handles injected onto every module's ``ctx`` (besides core fields).

        Modules read them as ``ctx.<name>``. Return {} if none are needed.
        """

        return {
            "interface": self.interface.i_name,
            "write_to_file": getattr(self.args, "output", None),
            "timeout": getattr(self.args, "timeout", None),
            "duration": getattr(self.args, "duration", None),
            "count": getattr(self.args, "count", None),
            "xid": getattr(self.args, "transaction_id", None),
            "mac": getattr(self.args, "mac_address", None),
            "giaddr": getattr(self.args, "gateway_ip_address", None),
            "requested_ip": getattr(self.args, "requested_ip", None),
            "client_ip": getattr(self.args, "client_ip", None),
            "client_mac": getattr(self.args, "client_mac", None),
            "netmask": getattr(self.args, "netmask", None),
            "lease": getattr(self.args, "lease", None),
            "renewal_time": getattr(self.args, "renewal_time", None),
            "rebinding_time": getattr(self.args, "rebinding_time", None),
            "server_ip": getattr(self.args, "server_ip", None)
        }