"""FTP PoC text.

The last reply is the proof. A one-line reply is wrapped in ``**``.
A multiline reply is left as sent, so the caller marks the proving line.
"""
from __future__ import annotations


def _crlf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")


def format_poc(*pairs: tuple[str, str]) -> str:
    """Join Send/Receive exchanges. Empty sends are skipped."""
    usable = [(send, recv) for send, recv in pairs if send]
    blocks: list[str] = []
    last = len(usable) - 1
    for index, (send, recv) in enumerate(usable):
        send_s = _crlf(str(send))
        if recv in (None, ""):
            recv_s = "(no reply)"
        else:
            recv_s = str(recv).replace("\r\n", "\n").replace("\r", "\n")
            if index == last and "**" not in recv_s and "\n" not in recv_s.strip("\n"):
                recv_s = f"**{recv_s.strip()}**"
            recv_s = recv_s.replace("\n", "\r\n")
        blocks.append(f"Send:\r\n{send_s}\r\n\r\nReceive:\r\n{recv_s}")
    return "\r\n\r\n".join(blocks)


def format_brute_poc(first: tuple[tuple[str, str], ...], last: tuple[tuple[str, str], ...], following: int) -> str:
    """First authorization exchange, how many came after it, and the last of those."""
    first_body = format_poc(*first)
    if following <= 0:
        return "First request to authorization:\r\n" + first_body
    last_body = format_poc(*last)
    return (
        "First request to authorization:\r\n"
        f"{first_body}\r\n\r\n"
        f"Send next {following} request to authorization\r\n\r\n"
        f"Last request to authorization from {following} requests\r\n"
        f"{last_body}"
    )
