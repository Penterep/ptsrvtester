"""IMAP PoC text.

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
