"""Main class for MySQL protocol testing."""
import argparse, socket

from .._base import BaseMain, BaseArgs
from .utils.cli import MySQLArgs


class MySQL(BaseMain):
    #: Short protocol identity (also namespaces this protocol's tests).
    NAME = "mysql"
    #: The argparse namespace class for this protocol's options.
    ARGS_CLASS = MySQLArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return MySQLArgs()

    def _prepare_target(self) -> None:
        """Resolve self.target = (ip, port) before any module runs.

        Fill in protocol defaults (e.g. default port) and host resolution.
        If you don't override this, BaseMain's default takes (ip, port) straight
        from args.target.
        """
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = 3306  # <- set your protocol's default port here
        host = target.ip
        try:
            socket.inet_aton(host)
            ip = host
        except OSError:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve domain name '{host}' to IP address"
                )
        self.target_host = host
        self.target = (ip, target.port)

    def build_context(self) -> dict:
        """Protocol handles injected onto every module's ``ctx`` (besides core fields).

        Modules read them as ``ctx.<name>``. Return {} if none are needed.
        """
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            "username": getattr(self.args, "username", "root"),
            "password": getattr(self.args, "password", None)
        }
