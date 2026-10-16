import os
import subprocess
import tempfile
import uuid

from ptlibs.ptprinthelper import ptprint
from ptsrvtester.protocols.rsync.utils.registry import rsync_env, rsync_url


__MODULELABEL__ = "Rsync bounded storage probe"
__MODULECODE__ = "FILL_SPACE"
__ORDER__ = 110

_CHUNK_SIZE = 1024



def _fill_module(ctx, module):
    env = rsync_env(ctx)
    uploaded_names = []

    with tempfile.TemporaryDirectory() as tmpdir:
        empty_dir = os.path.join(tmpdir, "empty")
        os.makedirs(empty_dir)
        uploaded_bytes = 1
        first_upload = True
        stop_reason = None
        show_progress = True # not getattr(ctx, "json", False) and sys.stdout.isatty()
        progress_line = None

        try:
            while uploaded_bytes:
                chunk_size = _CHUNK_SIZE
                probe_name = f"_space_{uuid.uuid4().hex}.bin"
                probe_path = os.path.join(tmpdir, probe_name)
                with open(probe_path, "wb") as probe:
                    probe.write(os.urandom(chunk_size))

                try:
                    upload = subprocess.run(
                        [
                            "rsync",
                            "--no-motd",
                            "--contimeout=5",
                            probe_path,
                            rsync_url(ctx, f"{module}/{probe_name}"),
                        ],
                        capture_output=True,
                        text=True,
                        input="",
                        env=env,
                        timeout=ctx.timeout,
                    )
                except subprocess.TimeoutExpired:
                    print(upload.stderr)
                    print(upload.stdout)
                    stop_reason = f"Upload to module {module} timed out"
                    break
                except FileNotFoundError:
                    ctx.out("rsync client binary not found on this machine", "ERROR", indent=4)
                    return "error"

                if upload.returncode != 0:
                    detail = upload.stderr.strip().splitlines()
                    detail = detail[0] if detail else f"rsync exited with status {upload.returncode}"
                    if first_upload:
                        stop_reason = f"Module {module} is not writable: {detail}"
                    else:
                        stop_reason = f"Upload stopped at {uploaded_bytes} bytes in module {module}: {detail}"
                    break

                uploaded_bytes += chunk_size
                first_upload = False
                progress_line = (
                    f"Uploaded {uploaded_bytes / (1024 * 1024):.1f} MiB "
                    f"to rsync module {module}"
                )
                if show_progress:
                    ptprint(
                        progress_line,
                        "INFO",
                        condition=True,
                        end="\r",
                        flush=True,
                        clear_to_eol=True,
                        indent=4,
                    )

            if uploaded_bytes:
                ctx.out(
                    f"Uploaded {uploaded_bytes / (1024 * 1024):.1f} MiB to module {module}",
                    "OK",
                    indent=4,
                )
            if stop_reason:
                ctx.out(stop_reason, "OK" if first_upload else "OK", indent=4)

        finally:
            if show_progress and progress_line is not None:
                ptprint(
                    progress_line,
                    "INFO",
                    condition=True,
                    end="\n",
                    flush=True,
                    clear_to_eol=True,
                    indent=4,
                )

    if uploaded_bytes:
        return "filled"
    if first_upload:
        return "not_writable"
    return "stopped"


def run(ctx):
    if not getattr(ctx, "dos", False):
        ctx.out("Storage probe is disabled; specify --dos to enable it", "OK", indent=4)
        return

    modules = getattr(ctx, "modules", None)
    if not modules:
        ctx.out("No rsync modules are available to test", "OK", indent=4)
        return

    for module in modules:
        result = _fill_module(ctx, module)
        if result == "filled":
            return
        if result == "stopped" or result == "error":
            return

    ctx.out("No writable rsync module was found", "OK", indent=4)