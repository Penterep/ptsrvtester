#!/usr/bin/python3

import ntlm_auth, struct
from ntlm_auth.constants import NegotiateFlags, AvId
from base64 import b64decode, b64encode
from typing import NamedTuple

from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib

from ._version import __version__


def text(data: bytes) -> str | None:
    """
    Attempts to decode bytes as a string

    Args:
        data (bytes): bytes to decode

    Returns:
        str | None: decoded string or None
    """
    try:
        return data.decode()
    except:
        return None


class NTLMInfo(NamedTuple):
    """
    Information decoded from NTLM authentication challenge
    """

    target_name: str | None
    netbios_domain: str | None
    netbios_computer: str | None
    dns_domain: str | None
    dns_computer: str | None
    dns_tree: str | None
    os_version: str | None


def get_NegotiateMessage_data(_: bytes | None = None) -> bytes:
    """Generates a new NTLM negotiation message

    Returns:
        bytes: byte representation of the message
    """
    # Nmap NTLMSSP configuration https://svn.nmap.org/nmap/scripts/imap-ntlm-info.nse
    negotiate_flags = (
        NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE
        + NegotiateFlags.NTLMSSP_NEGOTIATE_OEM
        + NegotiateFlags.NTLMSSP_REQUEST_TARGET
        + NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM
        + NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        + NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        + NegotiateFlags.NTLMSSP_NEGOTIATE_128
        + NegotiateFlags.NTLMSSP_NEGOTIATE_56
    )
    # TODO which approach is better? any reason to manually set the flags?
    return ntlm_auth.ntlm.NegotiateMessage(negotiate_flags, None, None).get_data()
    # return ntlm_auth.ntlm.NtlmContext(None, None).step()


def decode_ChallengeMessage_blob(ntlm_blob: bytes) -> NTLMInfo:
    """
    Decodes an NTLM challenge message
    and parses server information

    Args:
        ntlm_blob (bytes): NTLM challenge message byte representation

    Returns:
        NTLMInfo: parsed information
    """
    cm = ntlm_auth.ntlm.ChallengeMessage(ntlm_blob)
    try:
        # TODO Nmap checks if unpacked[4:8] == 0x000f, is it necessary?
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175
        version_data = cm.get_data()[48:56]
        unpacked = struct.unpack("<BB2B4B", version_data)

        major = unpacked[0]
        minor = unpacked[1]
        build = int.from_bytes(unpacked[2:4], "little")
        version = f"{major}.{minor}.{build}"
    except:
        version = None

    netbios_domain = None
    netbios_computer = None
    dns_domain = None
    dns_computer = None
    dns_tree = None

    if cm.target_info is not None:
        netbios_domain = text(cm.target_info[AvId.MSV_AV_NB_DOMAIN_NAME])
        netbios_computer = text(cm.target_info[AvId.MSV_AV_NB_COMPUTER_NAME])
        dns_domain = text(cm.target_info[AvId.MSV_AV_DNS_DOMAIN_NAME])
        dns_computer = text(cm.target_info[AvId.MSV_AV_DNS_COMPUTER_NAME])
        dns_tree = text(cm.target_info[AvId.MSV_AV_DNS_TREE_NAME])

    return NTLMInfo(
        target_name=text(cm.target_name),
        netbios_domain=netbios_domain,
        netbios_computer=netbios_computer,
        dns_domain=dns_domain,
        dns_computer=dns_computer,
        dns_tree=dns_tree,
        os_version=version,
    )


def main() -> None:
    global SCRIPTNAME
    SCRIPTNAME = "ptntlmauth"

    import argparse

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}", help="print version"
    )
    parser.add_argument("-j", "--json", action="store_true", help="use Penterep JSON output format")

    sub = parser.add_subparsers(required=True, dest="action")

    sub.add_parser("negotiate", help="Generate base64 encoded negotiate message")
    p = sub.add_parser("decode", help="Decode base64 encoded NTLM challenge message")
    p.add_argument("b64_ntlm_blob", type=str, help="Base64 encoded NTLM challenge message")

    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)

    ptjson = PtJsonLib()
    out_lines: list[str] = []

    try:
        if args.action == "decode":
            ntlm_blob = b64decode(args.b64_ntlm_blob)
            details = decode_ChallengeMessage_blob(ntlm_blob)

            out_lines.append(f"Target name: {details.target_name}")
            out_lines.append(f"NetBios domain name: {details.netbios_domain}")
            out_lines.append(f"NetBios computer name: {details.netbios_computer}")
            out_lines.append(f"DNS domain name: {details.dns_domain}")
            out_lines.append(f"DNS computer name: {details.dns_computer}")
            out_lines.append(f"DNS tree: {details.dns_tree}")
            out_lines.append(f"OS version: {details.os_version}")
        elif args.action == "negotiate":
            ntlm_blob = get_NegotiateMessage_data()

            out_lines.append(b64encode(ntlm_blob).decode())
    except Exception as e:
        ptjson.end_error(str(e), args.json)

    out = "\n".join(out_lines)

    ptjson.end_ok(out, args.json, "TEXT")


if __name__ == "__main__":
    main()
