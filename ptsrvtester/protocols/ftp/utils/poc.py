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


def format_access_poc(rows: list[tuple[str, list[str], tuple]]) -> str:
    """Directories and the access that was allowed, then the proving exchanges."""
    lines = [f"{path}: {', '.join(forms)}" for path, forms, _proofs in rows if forms]
    pairs: list[tuple[str, str]] = []
    for _path, _forms, proofs in rows:
        for item in proofs:
            if len(item) >= 3:
                send, recv = item[-2], item[-1]
            elif len(item) == 2:
                send, recv = item
            else:
                continue
            if send:
                pairs.append((str(send), str(recv or "(no reply)")))
    header = "Directories:\r\n" + "\r\n".join(lines)
    body = format_poc(*pairs)
    if not body:
        return header
    return header + "\r\n\r\n" + body


def format_pasvport_poc(
    connections: int,
    low_command: str,
    low_reply: str,
    low_port: int,
    high_command: str,
    high_reply: str,
    high_port: int,
    span: int,
) -> str:
    """Passive port range proof: how many connections, then the low and high ports."""

    def block(title: str, command: str, reply: str, port: int) -> str:
        reply_s = str(reply).replace("\r\n", "\n").replace("\r", "\n").strip("\n")
        lines = [line for line in reply_s.split("\n") if line.strip()] or ["(no reply)"]
        body = [f"  {command}", f"  Receive: {lines[0]}"]
        body.extend(f"  {line}" for line in lines[1:])
        body.append(f"  Port **{port}**")
        return title + "\r\n" + "\r\n".join(body)

    return "\r\n".join(
        (
            f"Connection count: {connections}",
            block("Lowest port offered during the test", low_command, low_reply, low_port),
            block("Highest port offered during the test", high_command, high_reply, high_port),
            f"Range: **{span}** open ports",
        )
    )


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
