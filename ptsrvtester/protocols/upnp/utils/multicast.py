"""IPv4 multicast M-SEARCH packet for target-scoped SSDP discovery."""

from __future__ import annotations

MULTICAST_ADDRESS = "239.255.255.250"
MULTICAST_PORT = 1900


def build_multicast_msearch(search_target: str, mx: int) -> bytes:
    """Build a bounded SSDP multicast search request (UPnP DA 2.0 section 1.3.2)."""
    if not search_target or len(search_target) > 255 or any(
        ord(char) < 33 or ord(char) > 126 for char in search_target
    ):
        raise ValueError("search target must be 1-255 visible ASCII characters without spaces")
    if not isinstance(mx, int) or isinstance(mx, bool) or not 1 <= mx <= 5:
        raise ValueError("MX must be an integer between 1 and 5")
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {MULTICAST_ADDRESS}:{MULTICAST_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {mx}\r\n"
        f"ST: {search_target}\r\n"
        "\r\n"
    ).encode("ascii")


__all__ = ["MULTICAST_ADDRESS", "MULTICAST_PORT", "build_multicast_msearch"]
