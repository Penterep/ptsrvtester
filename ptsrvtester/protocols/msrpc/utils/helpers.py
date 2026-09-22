"""Small, MSRPC-specific argument and wordlist helpers."""
from __future__ import annotations

import argparse
import ipaddress
import re
from dataclasses import dataclass


@dataclass
class Target:
    ip: str
    port: int = 0


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _valid_hostname(host: str) -> bool:
    candidate = host.rstrip(".")
    return (
        bool(candidate)
        and len(candidate) <= 253
        and all(_HOST_LABEL.fullmatch(label) for label in candidate.split("."))
    )


def valid_target(value: str) -> Target:
    """Parse an IPv4 address or hostname with an optional TCP port.

    DNS resolution deliberately happens once in :class:`MSRPC`, not while
    argparse is reading the command line.
    """
    raw = value.strip()
    if not raw:
        raise argparse.ArgumentTypeError("target must not be empty")
    if raw.count(":") > 1:
        raise argparse.ArgumentTypeError("target must be HOST[:PORT] (IPv6 is not supported)")

    host, separator, port_text = raw.partition(":")
    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        if not _valid_hostname(host):
            raise argparse.ArgumentTypeError("target must contain a valid IPv4 address or hostname")

    port = 0
    if separator:
        try:
            port = int(port_text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("target port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError("target port must be between 1 and 65535")
    return Target(host, port)


def text_or_file(
    text: str | None, filepath: str | None, *, preserve_whitespace: bool = False,
) -> list[str]:
    """Read direct values or a wordlist, optionally preserving password whitespace.

    Empty values are excluded. Password wordlists remove only CR/LF line
    separators, so a line containing spaces is a password, not a blank line.
    """
    if text is not None:
        value = str(text)
        if not preserve_whitespace:
            value = value.strip()
        return [value] if value else []
    if filepath is None:
        return []

    try:
        with open(filepath, "rb") as stream:
            raw = stream.read()
    except FileNotFoundError as exc:
        raise argparse.ArgumentError(None, f"File not found: '{filepath}'") from exc
    except PermissionError as exc:
        raise argparse.ArgumentError(
            None, f"Cannot read file (permission denied): '{filepath}'"
        ) from exc
    except OSError as exc:
        raise argparse.ArgumentError(None, f"Cannot read file '{filepath}': {exc}") from exc

    for encoding in ("utf-8", "cp1250", "iso-8859-2", "cp1252", "latin-1"):
        try:
            decoded = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:  # latin-1 always succeeds; retained as a defensive fallback.
        decoded = raw.decode("utf-8", errors="replace")
    if preserve_whitespace:
        return [line for line in re.split(r"\r\n|\r|\n", decoded) if line]
    return [line.strip() for line in decoded.splitlines() if line.strip()]


__all__ = ["Target", "text_or_file", "valid_target"]
