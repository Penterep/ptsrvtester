import socket

from ptsrvtester.protocols.rsync.utils.registry import rsync_debug


__MODULELABEL__ = "Rsync version detection module"
__MODULECODE__ = "banner"
__ORDER__ = 10


def _parse_greeting(greeting):
    return (
        greeting.removeprefix("@RSYNCD:").strip().split()
        if greeting.startswith("@RSYNCD:")
        else []
    )


def get_supported_digests(ctx):
    rsync_debug(ctx, f"Sent: TCP connection to rsync service at {ctx.ip}:{ctx.port}", indent=4)
    with socket.create_connection((ctx.ip, ctx.port), timeout=ctx.timeout) as sock:
        with sock.makefile("rb") as reader:
            greeting = reader.readline().decode(errors="replace").strip()
    rsync_debug(ctx, f"Received: {greeting or '<empty response>'}", indent=8)
    digests = _parse_greeting(greeting)[1:]
    rsync_debug(ctx, f"Received supported digest algorithms: {', '.join(digests) or '<none>'}", indent=8)
    return digests


def _rsync_grab_banner(ctx):
    motd = []
    try:
        rsync_debug(ctx, f"Sent: TCP connection to rsync service at {ctx.ip}:{ctx.port}", indent=4)
        with socket.create_connection((ctx.ip, ctx.port), timeout=ctx.timeout) as sock:
            with sock.makefile("rb") as reader:
                greeting = reader.readline().decode(errors="replace").strip()
                rsync_debug(ctx, f"Received: {greeting or '<empty response>'}", indent=8)
                greeting_fields = _parse_greeting(greeting)
                ctx.supported_digests.extend(greeting_fields[1:])
                version = greeting_fields[0] if greeting_fields else ""
                if version:
                    ctx.out(f"Grabbed Rsync server version: {version}", "VULN", indent=4)
                else:
                    ctx.out("Could not grab Rsync server version", "OK", indent=4)
                    return

                while True:
                    raw_line = reader.readline()
                    if not raw_line or raw_line.strip() == b"@RSYNCD: EXIT":
                        break
                    motd.append(raw_line.decode(errors="replace").rstrip("\r\n"))

        rsync_debug(ctx, f"Received MOTD: {' | '.join(motd) if motd else '<none>'}", indent=8)
        if motd:
            motd_text = "\n".join(motd)
            ctx.out(f"Grabbed Rsync server MOTD:\n{motd_text}", "VULN", indent=4)
        else:
            ctx.out("No Rsync server MOTD", "OK", indent=4)

    except TimeoutError as tm:
        if motd:
            ctx.out(f"Grabbed Rsync server MOTD:", "INFO", indent=4)
            for line in motd:
                ctx.out(f"{line}", "TEXT", indent=8)
        else:
            ctx.out(f"No MOTD provided by server", "OK", indent=4)
    except Exception as e:
        ctx.out(f"Error grabbing banner: {e}", "ERROR", condition=not ctx.json, indent=4)


def run(ctx):
    _rsync_grab_banner(ctx)