import socket


__MODULELABEL__ = "Rsync version detection module"
__MODULECODE__ = "banner"
__ORDER__ = 10


def _rsync_grab_banner(ctx):
    try:
        with socket.create_connection((ctx.ip, ctx.port), timeout=ctx.timeout) as sock:
            with sock.makefile("rb") as reader:
                greeting = reader.readline().decode(errors="replace").strip()
                greeting_fields = (
                    greeting.removeprefix("@RSYNCD:").strip().split()
                    if greeting.startswith("@RSYNCD:")
                    else []
                )
                ctx.supported_digests.extend(greeting_fields[1:])
                version = greeting_fields[0] if greeting_fields else ""
                if version:
                    ctx.out(f"Grabbed Rsync server version: {version}", "VULN", indent=4)
                else:
                    ctx.out("Could not grab Rsync server version", "OK", indent=4)
                    return

                motd = []
                while True:
                    raw_line = reader.readline()
                    if not raw_line or raw_line.strip() == b"@RSYNCD: EXIT":
                        break
                    motd.append(raw_line.decode(errors="replace").rstrip("\r\n"))

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