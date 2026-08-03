from typing import NamedTuple, Optional, List
import argparse
import re
from ptsrvtester.protocols.smtp.utils.helpers import Target, valid_target
from enum import Enum
from dataclasses import dataclass
from pysnmp.hlapi.v3arch.asyncio import *

SNMP_TEST_GROUPS = [
    ("General", ["VERSION"]),
    ("SNMPv2", ["V2BRUTE", "V2WRITE", "V2WALK"]),
    ("SNMPv3", ["V3ENUM", "V3BRUTE", "V3WALK", "V3WRITE"])
]

# Per-test definitions:
#   desc      one-line description for the main -ts table
#   long      list of <=3 lines describing what the test does (per-test help)
#   flags     dict dest->value applied to the args namespace when selected
#   value     (dest, default) for tests whose flag carries a value (default set if None)
#   requires  human-readable prerequisite strings (per-test help)
#   common    True -> append common outbound message options to per-test help
#   mods      test-specific option rows [short, long, metavar, help] (per-test help)
SNMP_TESTS: dict[str, dict] = {
    "VERSION": {
        "desc": "Detect SNMP versions",
        "long": "",
        "flags": {"version_detection": True}
    },
    "V2BRUTE": {
        "desc": "SNMPv2 dictionary attack",
        "long": "",
        "flags": {"v2_brute_force": True}
    },
    "V2WRITE": {
        "desc": "Test SNMPv2 write permission",
        "long": "",
        "flags": {"v2_write": True}
    },
    "V2WALK": {
        "desc": "SNMPv2 MIB walk",
        "long": "",
        "flags": {"v2_walk": True}
    },
    "V3ENUM": {
        "desc": "SNMPv3 user enumeration",
        "long": "",
        "flags": {"v3_enum": True}
    },
    "V3BRUTE": {
        "desc": "SNMPv3 credentials bruteforce",
        "long": "",
        "flags": {"v3_brute_force": True}
    },
    "V3WALK": {
        "desc": "SNMPv3 MIB walk",
        "long": "",
        "flags": {"v3_walk": True}
    },
    "V3WRITE": {
        "desc": "Test SNMPv3 write permissions",
        "long": "",
        "flags": {"v3_write": True}
    }
}

def _parse_test_codes(raw: str | None) -> list[str]:
    """Split and upper-case a raw -ts value into a list of codes.

    raw may be a single string (possibly comma-separated) or a list of
    tokens as produced by argparse when -ts is given nargs='+'
    (space-separated). Either form, or a mix of the two
    (e.g. -ts VERSION,V2BRUTE V3WALK), is supported.
    """
    if not raw:
        return []
    if isinstance(raw, (list, tuple)):
        raw = " ".join(raw)
    return [c.strip().upper() for c in re.split(r"[,\s]+", str(raw)) if c.strip()]


def valid_target_snmp(target: str) -> Target:
    return valid_target(target, domain_allowed=True)

def _apply_SNMP_tests(args) -> None:
    """Translate ``-ts/--tests`` codes into the internal per-test dest flags.

    ``ALL`` (or no ``-ts``) leaves every flag at default -> run-all mode.
    """
    codes = _parse_test_codes(getattr(args, "tests", None))
    if not codes:
        return
    if "ALL" in codes:
        # Explicit full scan: apply nothing so _is_run_all_mode() stays True.
        return
    unknown = [c for c in codes if c not in SNMP_TESTS]
    if unknown:
        available = ", ".join(sorted(SNMP_TESTS))
        raise argparse.ArgumentError(
            None,
            f"Unknown test(s): {', '.join(unknown)}. Available: ALL, {available}",
        )

    for code in codes:
        spec = SNMP_TESTS[code]
        for dest, val in spec.get("flags", {}).items():
            setattr(args, dest, val)
        value = spec.get("value")
        if value is not None:
            dest, default = value
            if getattr(args, dest, None) is None and default is not None:
                setattr(args, dest, default)

    # Every explicitly selected test must actually activate; otherwise report what is
    # missing instead of silently falling back to run-all mode.
    inactive: list[tuple[str, list[str]]] = []
    for code in codes:
        spec = SNMP_TESTS[code]

        if "flags" in spec:
            active = all(getattr(args, dest, None) for dest in spec["flags"])
        elif "value" in spec:
            active = getattr(args, spec["value"][0], None) is not None
        else:
            active = True
        if not active:
            inactive.append((code, list(spec.get("requires", []))))
    if inactive:
        parts = [
            f"{code} requires {'; '.join(req)}" if req else f"{code} could not be activated"
            for code, req in inactive
        ]
        raise argparse.ArgumentError(None, "; ".join(parts))


def _SNMP_test_help(codes: list[str]):
    """Build a help object (for ptprinthelper.help_print) describing given test codes."""
    if not codes:
        return None
    valid = [c for c in codes if c in SNMP_TESTS]
    if not valid:
        available = ", ".join(sorted(SNMP_TESTS))
        return [
            {"unknown_test": [f"Unknown test: {', '.join(codes)}"]},
            {"available_tests": [f"ALL, {available}"]},
        ]
    out: list[dict] = []
    for code in valid:
        spec = SNMP_TESTS[code]
        header = f"{code} — {spec.get('desc', '')}"
        out.append({"test": [header, *spec.get("long", [])]})
        req = list(spec.get("requires", []))
        if req:
            out.append({"requires": req})
        rows: list[list[str]] = list(spec.get("mods", []))

        if rows:
            out.append({"test_options": rows})
        has_opts = bool(rows or req)
        usage = f"ptsrvtester SNMP -ts {code} " + ("<options> <target>" if has_opts else "<target>")
        out.append({"usage": [usage]})
    return out


class VULNS(Enum):
    WeakCommunityName = "PTV-SNMPv2-WEAKCOMMUNITYNAME"
    WeakUsername = "PTV-SNMPv3-WEAKUSERNAME"
    WeakCredentials = "PTV-SNMPv3-WEAKCREDENTIALS"
    Write_2 = "PTV-SNMPv2-WRITEACCESS"
    Write_3 = "PTV-SNMPv3-WRITEACCESS"
    Readmib_3 = "PTV-SNMPv3-READINGMIB"
    Readmib_2 = "PTV-SNMPv2-READINGMIB"

class Credential(NamedTuple):
    username: str | None
    password: str | None


class SNMPVersion(NamedTuple):
    v1: bool | None
    v2c: bool | None
    v3: bool | None

class WriteTestResult(NamedTuple):
    OID: str | None
    creds: str | None   #community for snmpv2
    value: str | None


class AuthPrivProtocols(NamedTuple):
    auth_protocols: str | None
    priv_protocols: str | None

PROTOCOL_NAMES = {
    usmHMACMD5AuthProtocol: "usmHMACMD5AuthProtocol",
    usmHMACSHAAuthProtocol: "usmHMACSHAAuthProtocol",
    usmHMAC128SHA224AuthProtocol: "usmHMAC128SHA224AuthProtocol",
    usmHMAC192SHA256AuthProtocol: "usmHMAC192SHA256AuthProtocol",
    usmHMAC256SHA384AuthProtocol: "usmHMAC256SHA384AuthProtocol",
    usmHMAC384SHA512AuthProtocol: "usmHMAC384SHA512AuthProtocol",
    usmDESPrivProtocol: "usmDESPrivProtocol",
    usmAesCfb128Protocol: "usmAesCfb128Protocol",
    usmAesCfb192Protocol: "usmAesCfb192Protocol",
    usmAesCfb256Protocol: "usmAesCfb256Protocol",
    None: "None",
}

@dataclass
class SNMPResult:
    version: Optional[SNMPVersion] = None
    communities: Optional[List[str]] = None
    usernames: Optional[List[str]] = None
    credentials: Optional[List[Credential]] = None
    Writetest3: Optional[List[WriteTestResult]] = None
    Writetest2: Optional[List[WriteTestResult]] = None
    Bulk2: Optional[str] = None
    Bulk3: Optional[str] = None

def _text_or_file(text: str | list[str] | None, filepath: str | None) -> list[str]:
    """Returns either `text` or `filepath` contents while prefering `text`

    Args:
        text (str | list[str] | None): single value or list (e.g. SMTP -u with nargs+)
        filepath (str | None): file with values

    Returns:
        list[str]: list of picked value(s)
    """
    result = []
    if text is not None:
        if isinstance(text, list):
            result = [str(t).strip() for t in text if t is not None and str(t).strip()]
        else:
            result = [text]
    elif filepath is not None:
        _encodings = ("utf-8", "cp1250", "iso-8859-2", "cp1252", "latin-1")
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
        except FileNotFoundError:
            raise argparse.ArgumentError(None, f"File not found: '{filepath}'")
        except PermissionError:
            raise argparse.ArgumentError(None, f"Cannot read file (permission denied): '{filepath}'")
        except OSError as e:
            raise argparse.ArgumentError(None, f"Cannot read file '{filepath}': {e}")
        for enc in _encodings:
            try:
                result = raw.decode(enc).splitlines()
                break
            except UnicodeDecodeError:
                continue
        else:
            result = raw.decode("utf-8", errors="replace").splitlines()

    return result

def text_or_file(text: str | None, file_path: str | None) -> List[str]:
    values = _text_or_file(text.strip() if text else None, file_path)
    return [v.strip() for v in values if v.strip()]