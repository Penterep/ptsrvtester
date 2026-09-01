"""Shared CLI wiring for the cross-protocol RATELIMIT test.

``add_shared_rate_limit_args`` is injected onto every protocol subparser by
``ptsrvtester.parse_args`` so ``<protocol> -ts RATELIMIT`` accepts the same
``--rate-*`` options everywhere.  It is a no-op for a protocol that already
defines its own rate-limit CLI (e.g. RDP keeps its specialised options and
engine, including its own ``--allow-load-test`` gate).
"""

from __future__ import annotations

import argparse


def add_shared_rate_limit_args(parser: argparse.ArgumentParser) -> None:
    """Add the shared RATELIMIT options unless the protocol has its own rate CLI.

    Skipped for protocols that ship their own rate-limit options — RDP
    (``--rate-count``) and SMTP (``--rate-limit`` for its own ``RATELIM`` test) —
    so we neither clobber them nor add inert flags a protocol never reads.
    """
    existing = parser._option_string_actions
    if "--rate-count" in existing or "--rate-limit" in existing:
        return

    group = parser.add_argument_group(
        "RATELIMIT (active load test)",
        "Connection rate-limiting checks — only run when explicitly selected with "
        "-ts RATELIMIT; never part of the default/ALL sweep",
    )
    group.add_argument(
        "--rate-count", type=int, default=30, metavar="<n>",
        help="connections per RATELIMIT scenario (default: 30; range 5-200)",
    )
    group.add_argument(
        "--rate-concurrency", type=int, default=10, metavar="<n>",
        help="parallel connections during RATELIMIT (default: 10; range 1-50)",
    )
    group.add_argument(
        "--rate-timeout", type=float, default=5.0, metavar="<seconds>",
        help="per-connection socket timeout for RATELIMIT (default: 5)",
    )
    group.add_argument(
        "--rate-hold-seconds", type=float, default=2.0, metavar="<seconds>",
        help="how long held connections stay open in the concurrency check (default: 2)",
    )
    group.add_argument(
        "--rate-cooldown-seconds", type=float, default=3.0, metavar="<seconds>",
        help="recovery delay after the burst before re-testing (default: 3)",
    )
    group.add_argument(
        "--rate-idle-max", type=float, default=30.0, metavar="<seconds>",
        help="max time to wait for an idle connection to drop; 0 disables (default: 30)",
    )
    group.add_argument(
        "--rate-idle-poll", type=float, default=1.0, metavar="<seconds>",
        help="how often to poll the idle connection's liveness (default: 1)",
    )


def rate_limit_help_rows(get_colored_text=None) -> list[list[str]]:
    """Help-table rows describing the RATELIMIT options (for a protocol's help)."""
    title = "RATELIMIT (active load test)"
    if get_colored_text is not None:
        title = get_colored_text(title, "TITLE")
    return [
        ["", "", "", ""],
        [title],
        ["", "--rate-count", "<n>", "Connections per scenario (default: 30)"],
        ["", "--rate-concurrency", "<n>", "Parallel connections (default: 10)"],
        ["", "--rate-timeout", "<seconds>", "Per-connection timeout (default: 5)"],
        ["", "--rate-hold-seconds", "<seconds>", "Hold time in concurrency check (default: 2)"],
        ["", "--rate-cooldown-seconds", "<seconds>", "Recovery delay after burst (default: 3)"],
        ["", "--rate-idle-max", "<seconds>", "Max wait for idle drop; 0 disables (default: 30)"],
        ["", "--rate-idle-poll", "<seconds>", "Idle liveness poll interval (default: 1)"],
    ]


__all__ = ["add_shared_rate_limit_args", "rate_limit_help_rows"]