"""SFTPDATA — SFTP content scanning & resource limits (post-auth, aggressive).

Companion to the SFTP confinement test. Logs in, opens an SFTP session and, with
bounded and cleaned-up uploads, checks (see :mod:`..utils.sftpdata_core`):

  * **Antivirus** — upload an EICAR test file; is it rejected / removed, or stored
    intact (no on-upload scanning)?
  * **Content-processing DoS** — upload an incompressible baseline and a bounded,
    highly-compressible archive of the same on-wire size (plus a small XML/XXE
    probe). If the compressible one takes measurably longer, the server
    decompresses/parses uploads — a ZIP-bomb / XXE DoS surface.
  * **Quota / disk-fill** — write up to a small size bound and create a small
    number of files; if no limit is hit, filling the disk (DoS) is likely possible.

Aggressive and opt-in: never runs in the default / ALL sweep
(``__RUN_IN_ALL__ = False``); needs valid credentials. Every default is small and
the operator's flags are clamped to safe caps; nothing is left on the server.
"""
import io
import secrets
import time
import zipfile

import paramiko

# Importing ssh_helpers applies paramiko's legacy-host-key + logging setup as a
# side effect (so old servers still negotiate and paramiko does not spam stderr).
from ptsrvtester.protocols.ssh.utils import ssh_helpers  # noqa: F401
from ptsrvtester.protocols.ssh.utils.helpers import text_or_file
from ptsrvtester.protocols.ssh.utils.results import SSHCreds, VULNS
from ptsrvtester.protocols.ssh.utils.sftpdata_core import (
    CAP_BOMB_MB,
    CAP_MAX_FILES,
    CAP_MAX_MB,
    DEFAULT_BOMB_MB,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_MB,
    SftpDataObservations,
    assess_sftpdata,
)

__MODULELABEL__ = "SFTP content scanning & resource limits"
__MODULECODE__ = "SFTPDATA"
__ORDER__ = 38
__RUN_IN_ALL__ = False

_CONNECT_TIMEOUT = 10.0
_MB = 1024 * 1024


def _token() -> str:
    return "ptsrv_" + secrets.token_hex(6)


def _eicar_bytes() -> bytes:
    """The standard EICAR AV test string, assembled at runtime.

    Built from fragments so this source file does not itself contain the full
    signature (which local AV would quarantine). Harmless 68-byte test pattern.
    """
    parts = [r"X5O!P%@AP[4\PZX54(P^)7CC)7}", "$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "!$H+H*"]
    return ("".join(parts)).encode("ascii")


def _make_zip(decompressed_mb: int) -> bytes:
    """A real DEFLATE zip whose single entry decompresses to ``decompressed_mb`` of zeros."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr("data.bin", b"\0" * (decompressed_mb * _MB))
    return buf.getvalue()


def _xxe_xml(expand_kb: int = 256) -> bytes:
    """A small, BOUNDED XML entity-expansion / external-entity probe (not a real bomb)."""
    unit = "A" * 64
    reps = max(1, (expand_kb * 1024) // len(unit))
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE data [\n'
        '  <!ENTITY xxe SYSTEM "file:///etc/hostname">\n'
        f'  <!ENTITY blob "{unit * reps}">\n'
        ']>\n'
        '<data>&blob;&xxe;</data>\n'
    ).encode("ascii", errors="ignore")


def _data_creds(a, account: str) -> list[SSHCreds]:
    if getattr(a, "privkeys", None):
        return [SSHCreds(account, "", pk) for pk in ssh_helpers.parse_privkeys(a.privkeys)]
    passwords = text_or_file(getattr(a, "password", None), getattr(a, "passwords", None))
    return [SSHCreds(account, p, None) for p in passwords]


def _connect(ip: str, port: int, cred: SSHCreds):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy)
    try:
        if cred.privkey is not None:
            client.connect(ip, port, username=cred.user, key_filename=cred.privkey.keypath,
                           passphrase=cred.privkey.passphrase, look_for_keys=False,
                           allow_agent=False, banner_timeout=_CONNECT_TIMEOUT, timeout=_CONNECT_TIMEOUT)
        else:
            client.connect(ip, port, username=cred.user, password=cred.passw, look_for_keys=False,
                           allow_agent=False, banner_timeout=_CONNECT_TIMEOUT, timeout=_CONNECT_TIMEOUT)
        return client
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        return None


def _clamp(value, default, cap, minimum=1):
    try:
        v = int(value) if value is not None else default
    except (TypeError, ValueError):
        v = default
    return max(minimum, min(v, cap))


# --- probes (each best-effort, tracking created files for cleanup) ------------

def _timed_upload(sftp, name: str, data: bytes) -> float:
    start = time.time()
    with sftp.open(name, "wb") as fh:
        fh.write(data)
    return time.time() - start


def _probe_antivirus(sftp, obs: SftpDataObservations, created: list) -> None:
    name = _token() + "_eicar.com"
    obs.eicar_attempted = True
    payload = _eicar_bytes()
    try:
        with sftp.open(name, "wb") as fh:
            fh.write(payload)
        created.append(name)
    except Exception as e:
        obs.eicar_write_rejected = True
        obs.eicar_note = f"write rejected: {type(e).__name__}: {e}"
        return
    # Re-stat / re-read to see whether an AV layer removed or altered it.
    try:
        st = sftp.stat(name)
        with sftp.open(name, "rb") as fh:
            back = fh.read(len(payload) + 8)
        obs.eicar_persisted_intact = (getattr(st, "st_size", None) == len(payload)
                                      and back == payload)
    except Exception:
        obs.eicar_persisted_intact = False  # gone/unreadable after upload => AV likely acted


def _probe_processing(sftp, obs: SftpDataObservations, created: list, bomb_mb: int) -> None:
    obs.processing_tested = True
    zip_bytes = _make_zip(bomb_mb)
    baseline = secrets.token_bytes(len(zip_bytes))  # incompressible, same on-wire size

    base_name = _token() + "_base.bin"
    try:
        obs.baseline_seconds = _timed_upload(sftp, base_name, baseline)
        created.append(base_name)
    except Exception as e:
        obs.notes.append(f"baseline upload failed: {type(e).__name__}: {e}")
        obs.processing_tested = False
        return

    bomb_name = _token() + "_bomb.zip"
    try:
        obs.bomb_seconds = _timed_upload(sftp, bomb_name, zip_bytes)
        created.append(bomb_name)
    except Exception as e:
        obs.bomb_rejected = True
        obs.notes.append(f"archive upload rejected: {type(e).__name__}: {e}")

    xxe_name = _token() + "_probe.xml"
    try:
        with sftp.open(xxe_name, "wb") as fh:
            fh.write(_xxe_xml())
        created.append(xxe_name)
        obs.xxe_uploaded = True
    except Exception:
        obs.xxe_uploaded = False


def _probe_quota(sftp, obs: SftpDataObservations, created: list, max_mb: int, max_files: int) -> None:
    obs.quota_tested = True

    # size: grow one file 1 MB at a time up to max_mb.
    size_name = _token() + "_size.bin"
    chunk = b"\0" * _MB
    written = 0
    try:
        with sftp.open(size_name, "wb") as fh:
            for _ in range(max_mb):
                fh.write(chunk)
                written += 1
        created.append(size_name)
    except Exception:
        obs.size_limit_hit = True
        obs.size_limit_at_mb = float(written)
        created.append(size_name)
    obs.mb_written = float(written)

    # count: create up to max_files tiny files.
    made = 0
    for i in range(max_files):
        cname = f"{_token()}_c{i}"
        try:
            with sftp.open(cname, "wb") as fh:
                fh.write(b"x")
            created.append(cname)
            made += 1
        except Exception:
            obs.count_limit_hit = True
            obs.count_limit_at = made
            break
    obs.files_created = made


def _cleanup(sftp, created: list, obs: SftpDataObservations) -> None:
    for name in created:
        try:
            sftp.remove(name)
        except Exception:
            obs.notes.append(f"could not remove {name} — please delete manually")


def run(ctx):
    a = ctx.args
    ip, port = ctx.target

    account = a.user if (isinstance(a.user, str) and a.user) else (
        a.user[0] if isinstance(a.user, list) and a.user else None)
    if not account:
        ctx.out("SFTPDATA requires -u/--user (account to test)", "WARNING", indent=4)
        return
    creds = _data_creds(a, account)
    if not creds:
        ctx.out("SFTPDATA requires a secret to log in: -p/--password, -P/--passwords or --privkeys",
                "WARNING", indent=4)
        return

    max_mb = _clamp(getattr(a, "sftp_max_mb", None), DEFAULT_MAX_MB, CAP_MAX_MB)
    max_files = _clamp(getattr(a, "sftp_max_files", None), DEFAULT_MAX_FILES, CAP_MAX_FILES)
    bomb_mb = _clamp(getattr(a, "sftp_bomb_mb", None), DEFAULT_BOMB_MB, CAP_BOMB_MB)

    ctx.out(f"Testing SFTP content/limits for '{account}' on {ip}:{port} "
            f"(bounds: {max_mb} MB, {max_files} files, {bomb_mb} MB bomb)", "INFO",
            colortext=True, indent=4)
    ctx.out("aggressive test — uploads bounded test files (all cleaned up afterwards)",
            "WARNING", indent=4)

    client = None
    for c in creds:
        client = _connect(ip, port, c)
        if client is not None:
            break

    obs = SftpDataObservations()
    if client is None:
        _render(ctx, assess_sftpdata(account=account, obs=obs))
        return

    obs.authenticated = True
    created: list = []
    try:
        sftp = None
        try:
            sftp = client.open_sftp()
            obs.sftp_available = True
        except Exception as e:
            obs.notes.append(f"open_sftp failed: {type(e).__name__}: {e}")
        if sftp is not None:
            try:
                _probe_antivirus(sftp, obs, created)
                _probe_processing(sftp, obs, created, bomb_mb)
                _probe_quota(sftp, obs, created, max_mb, max_files)
            finally:
                _cleanup(sftp, created, obs)
                try:
                    sftp.close()
                except Exception:
                    pass
    finally:
        try:
            client.close()
        except Exception:
            pass

    _render(ctx, assess_sftpdata(account=account, obs=obs))


# --- rendering ----------------------------------------------------------------

def _render(ctx, r):
    obs = r.obs
    if not obs.authenticated:
        ctx.out(f"SFTPDATA: NOT TESTED — could not authenticate as '{r.account}'", "WARNING", indent=4)
        for n in r.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["sftpdataAccount"] = r.account
            ctx.properties["sftpdataVerdict"] = "no-auth"
        return
    if not obs.sftp_available:
        ctx.out("SFTP subsystem not available — nothing to upload", "OK", indent=4)
        with ctx.results_lock:
            ctx.properties["sftpdataAccount"] = r.account
            ctx.properties["sftpdataVerdict"] = "no-sftp"
        return

    # Antivirus
    ctx.out("Antivirus (EICAR upload)", "INFO", colortext=True, indent=4)
    if obs.eicar_write_rejected:
        ctx.out("EICAR upload rejected — an AV/DLP layer blocked it", "OK", indent=8)
    elif obs.eicar_persisted_intact is True:
        ctx.out("EICAR stored intact — no antivirus scanning on upload", "VULN", indent=8)
    elif obs.eicar_persisted_intact is False:
        ctx.out("EICAR removed/altered after upload — antivirus appears active", "OK", indent=8)
    else:
        ctx.out("EICAR result inconclusive", "TEXT", indent=8)

    # Content-processing DoS
    ctx.out("Content-processing DoS (ZIP bomb / XXE)", "INFO", colortext=True, indent=4)
    if obs.baseline_seconds is not None and obs.bomb_seconds is not None:
        ctx.out(f"baseline {obs.baseline_seconds:.2f}s vs compressible {obs.bomb_seconds:.2f}s",
                "TEXT", indent=8)
    if r.processing_suspected:
        ctx.out("server appears to decompress/process uploads — ZIP-bomb / XXE DoS surface",
                "VULN", indent=8)
    elif obs.bomb_rejected:
        ctx.out("server rejected the archive (inspects uploads but bounded the work)", "OK", indent=8)
    else:
        ctx.out("no timing amplification — no evidence uploads are decompressed on receipt",
                "OK", indent=8)

    # Quota / disk-fill
    ctx.out("Quota / disk-fill", "INFO", colortext=True, indent=4)
    if obs.size_limit_hit:
        ctx.out(f"size limit hit at ~{obs.size_limit_at_mb:.0f} MB (quota enforced)", "OK", indent=8)
    if obs.count_limit_hit:
        ctx.out(f"file-count limit hit at {obs.count_limit_at} files (quota enforced)", "OK", indent=8)
    if not obs.size_limit_hit and not obs.count_limit_hit:
        ctx.out(f"no size/count limit within bounds (~{obs.mb_written:.0f} MB, {obs.files_created} "
                "files) — disk-fill DoS likely possible", "VULN", indent=8)

    for n in r.notes:
        ctx.debug(n)

    with ctx.results_lock:
        ctx.properties["sftpdataAccount"] = r.account
        ctx.properties["sftpdataEicarPersisted"] = obs.eicar_persisted_intact
        ctx.properties["sftpdataProcessingSuspected"] = r.processing_suspected
        ctx.properties["sftpdataBaselineSeconds"] = obs.baseline_seconds
        ctx.properties["sftpdataBombSeconds"] = obs.bomb_seconds
        ctx.properties["sftpdataSizeLimitHit"] = obs.size_limit_hit
        ctx.properties["sftpdataCountLimitHit"] = obs.count_limit_hit
        ctx.properties["sftpdataMbWritten"] = obs.mb_written
        ctx.properties["sftpdataFilesCreated"] = obs.files_created
        _push_vulns(ctx, r)


def _push_vulns(ctx, r):
    obs = r.obs
    if r.no_antivirus_finding:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.SftpNoAntivirus.value,
            "vuln_request": f"account: {r.account}\nSFTP upload of the EICAR test file",
            "vuln_response": "the EICAR test file was stored intact — uploads are not scanned for "
                             "malware on receipt",
        })
    if r.processing_dos_finding:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.SftpContentProcessingDoS.value,
            "vuln_request": f"account: {r.account}\nSFTP upload of a compressible archive vs baseline",
            "vuln_response": f"compressible upload took {obs.bomb_seconds:.2f}s vs "
                             f"{obs.baseline_seconds:.2f}s baseline — the server processes/decompresses "
                             "uploads (ZIP-bomb / XXE denial-of-service surface)",
        })
    if r.no_quota_finding:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.SftpNoQuota.value,
            "vuln_request": f"account: {r.account}\nSFTP bounded write ({obs.mb_written:.0f} MB) and "
                            f"{obs.files_created} files",
            "vuln_response": "no size or file-count quota within the tested bounds — an attacker can "
                             "fill the disk (denial of service)",
        })
