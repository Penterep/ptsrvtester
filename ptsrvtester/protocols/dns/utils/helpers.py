"""DNS helpers shared by the DNS modules.

Kept deliberately small and DNS-specific: a :class:`Target` dataclass, the
argparse target validator, a robust text/file reader (for options that take
either a value or a file path) and a small factory for a dnspython resolver
pinned to a specific server.

The modules under ``dns/modules/`` are loaded dynamically by
:class:`BaseMain` and have no package parent, so they must import these via the
absolute path (``from ptsrvtester.protocols.dns.utils.helpers import ...``);
relative imports would fail. This mirrors ``ssh/utils/helpers.py``.
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
from dataclasses import dataclass


@dataclass
class Target:
    """A parsed ``-tg/--target`` value: host/IP plus a port (0 = use default)."""

    ip: str
    port: int


def valid_target(target: str, *, domain_allowed: bool = True) -> Target:
    """argparse ``type`` for ``-tg/--target``: ``IP[:PORT]`` or ``HOST[:PORT]``.

    The port is optional here; the protocol fills the DNS default (53) later in
    :meth:`DNS._prepare_target`. Raises :class:`argparse.ArgumentError` on an
    unresolvable host, a malformed value or an out-of-range port.
    """
    split = target.split(":")
    if len(split) > 2:
        raise argparse.ArgumentError(None, "The target has to be IP[:PORT] or HOST[:PORT]")

    host = split[0]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if domain_allowed:
            try:
                socket.gethostbyname(host)
            except OSError:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve target name '{host}' into IP address"
                )
        else:
            raise argparse.ArgumentError(None, "Invalid target IP address")

    if len(split) == 2:
        try:
            port = int(split[1])
            if not (0 < port < 65536):
                raise ValueError
        except ValueError:
            raise argparse.ArgumentError(None, "Invalid PORT number")
    else:
        port = 0

    return Target(host, port)


def text_or_file(text: str | list[str] | None, filepath: str | None) -> list[str]:
    """Return values from *text* (a single string or a list), else the lines of *filepath*.

    *text* wins over *filepath*. Files are decoded best-effort across a few
    common encodings so operator wordlists do not have to be UTF-8.
    """
    if text is not None:
        if isinstance(text, (list, tuple)):
            return [str(t).strip() for t in text if t is not None and str(t).strip()]
        return [text]

    if filepath is None:
        return []

    encodings = ("utf-8", "cp1250", "iso-8859-2", "cp1252", "latin-1")
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        raise argparse.ArgumentError(None, f"File not found: '{filepath}'")
    except PermissionError:
        raise argparse.ArgumentError(None, f"Cannot read file (permission denied): '{filepath}'")
    except OSError as e:
        raise argparse.ArgumentError(None, f"Cannot read file '{filepath}': {e}")

    for enc in encodings:
        try:
            return raw.decode(enc).splitlines()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace").splitlines()


def make_resolver(ip: str | None = None, port: int = 53, timeout: float = 5.0):
    """A dnspython ``Resolver`` pinned to *ip*:*port*, or the system resolver when *ip* is None.

    Modules that must query a specific server (``-tg``) build one with this;
    those that follow the system's configured resolvers call it with no *ip*.
    """
    import dns.resolver

    resolver = dns.resolver.Resolver()
    if ip:
        resolver.nameservers = [ip]
        resolver.port = port or 53
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver
