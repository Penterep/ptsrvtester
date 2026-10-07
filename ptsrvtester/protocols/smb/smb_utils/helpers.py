from dataclasses import dataclass
from typing import Optional, Protocol, TYPE_CHECKING
import argparse, ipaddress, socket

from ptlibs.ptjsonlib import PtJsonLib

if TYPE_CHECKING:
    from .cli import SMBArgs

from impacket.smbconnection import (
    SMB_DIALECT,
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
)

@dataclass
class Target:
    ip: str
    port: int

@dataclass
class SMBv1Flags:
    # FLAGS1 - Header-level protocol flags
    FLAGS1_LOCK_AND_READ_OK: int = 0x01                     # bit 0   | Supports atomic lock-and-read operations
    FLAGS1_PATHCASELESS: int = 0x08                         # bit 3   | Paths are case-insensitive
    FLAGS1_CANONICALIZED_PATHS: int = 0x10                  # bit 4   | Paths are canonicalized by server
    FLAGS1_REPLY: int = 0x80                                # bit 7   | This is a reply packet from server

    # FLAGS2 - Extended protocol features
    FLAGS2_LONG_NAMES: int = 0x0001                         # bit 0   | Supports long filenames beyond 8.3 format
    FLAGS2_EAS: int = 0x0002                                # bit 1   | Supports extended attributes on files
    FLAGS2_SMB_SECURITY_SIGNATURE: int = 0x0004             # bit 2   | Message signing is supported and optional
    FLAGS2_COMPRESSED: int = 0x0008                         # bit 3   | Compression support for data
    FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED: int = 0x0010    # bit 4   | Message signing is required and enforced
    FLAGS2_IS_LONG_NAME: int = 0x0040                       # bit 6   | Response uses long filename format
    FLAGS2_EXTENDED_SECURITY: int = 0x0800                  # bit 11  | Supports Kerberos and NTLM extended authentication
    FLAGS2_DFS: int = 0x1000                                # bit 12  | Distributed File System support enabled
    FLAGS2_PAGING_IO: int = 0x2000                          # bit 13  | Supports paging I/O operations
    FLAGS2_NT_STATUS: int = 0x4000                          # bit 14  | Uses NT status codes instead of DOS error codes
    FLAGS2_UNICODE: int = 0x8000                            # bit 15  | Strings are UTF-16 encoded instead of ASCII

    # SECURITY_MODE - Authentication and signing security settings
    NEGOTIATE_USER_SECURITY: int = 0x01                     # bit 0   | User-level authentication vs share-level
    NEGOTIATE_ENCRYPT_PASSWORDS: int = 0x02                 # bit 1   | Challenge-response hashing vs plaintext
    NEGOTIATE_SECURITY_SIGNATURE_ENABLE: int = 0x04         # bit 2   | Message signing available for negotiation
    NEGOTIATE_SECURITY_SIGNATURE_REQUIRED: int = 0x08       # bit 3   | Message signing mandatory

    # CAPABILITIES - Server capabilities for negotiate
    CAP_RAW_MODE: int = 0x00000001                          # bit 0   | Raw read and write mode support
    CAP_MPX_MODE: int = 0x0002                              # bit 1   | Multiplexed I/O with multiple requests
    CAP_UNICODE: int = 0x0004                               # bit 2   | Server supports Unicode string encoding
    CAP_LARGE_FILES: int = 0x0008                           # bit 3   | Supports files larger than 2GB
    CAP_NT_SMBS: int = 0x10                                 # bit 4   | Uses NT SMB dialect instead of LANMAN
    CAP_RPC_REMOTE_APIS: int = 0x20                         # bit 5   | RPC over SMB protocol support
    CAP_USE_NT_ERRORS: int = 0x40                           # bit 6   | NT error codes instead of DOS error codes
    CAP_LARGE_READX: int = 0x00004000                       # bit 14  | Large read operations exceeding 64KB
    CAP_LARGE_WRITEX: int = 0x00008000                      # bit 15  | Large write operations exceeding 64KB
    CAP_EXTENDED_SECURITY: int = 0x80000000                 # bit 31  | Extended security with Kerberos and NTLM

@dataclass
class SMBv23Flags:
    # SMBv2/3 PACKET FLAGS
    SMB2_FLAGS_SERVER_TO_REDIR: int = 0x00000001            # bit 0   | This is a server-to-client reply packet
    SMB2_FLAGS_ASYNC_COMMAND: int = 0x00000002              # bit 1   | Operation is asynchronous
    SMB2_FLAGS_RELATED_OPERATIONS: int = 0x00000004         # bit 2   | Request is chained with previous
    SMB2_FLAGS_SIGNED: int = 0x00000008                     # bit 3   | Message is signed for integrity
    SMB2_FLAGS_DFS_OPERATIONS: int = 0x10000000             # bit 28  | Operation involves Distributed File System
    SMB2_FLAGS_REPLAY_OPERATION: int = 0x80000000           # bit 31  | Replay of a previous operation

    # SMBv3 SECURITY MODE - Signing settings (SMB3.0+ only)
    SMB2_NEGOTIATE_SIGNING_ENABLED: int = 0x1               # bit 0   | Message signing is supported and optional
    SMB2_NEGOTIATE_SIGNING_REQUIRED: int = 0x2              # bit 1   | Message signing is mandatory

    # SMBv2/3 CAPABILITIES - Server features for negotiate
    SMB2_GLOBAL_CAP_DFS: int = 0x01                         # bit 0   | Distributed File System support
    SMB2_GLOBAL_CAP_LEASING: int = 0x02                     # bit 1   | File leasing for optimization
    SMB2_GLOBAL_CAP_LARGE_MTU: int = 0x04                   # bit 2   | Multi-credit support for larger transfers
    SMB2_GLOBAL_CAP_MULTI_CHANNEL: int = 0x08               # bit 3   | Multiple channels for redundancy
    SMB2_GLOBAL_CAP_PERSISTENT_HANDLES: int = 0x10          # bit 4   | Persistent file handles across reconnects
    SMB2_GLOBAL_CAP_DIRECTORY_LEASING: int = 0x20           # bit 5   | Directory leasing support (SMB3+)
    SMB2_GLOBAL_CAP_ENCRYPTION: int = 0x40                  # bit 6   | Encryption support (SMB3+)

    # SMBv3 NEGOTIATE CONTEXT TYPES (SMB3.1.1+ only)
    SMB2_PREAUTH_INTEGRITY_CAPABILITIES: int = 0x1          # Pre-authentication integrity and hash algorithms
    SMB2_ENCRYPTION_CAPABILITIES: int = 0x2                 # Encryption cipher negotiation
    SMB2_COMPRESSION_CAPABILITIES: int = 0x3                # Compression algorithm support

    # SMBv2/3 SESSION SETUP FLAGS
    SMB2_SESSION_FLAG_BINDING: int = 0x01                   # bit 0   | Binding to existing session
    SMB2_SESSION_FLAG_IS_GUEST: int = 0x01                  # bit 0   | Session is guest authentication
    SMB2_SESSION_FLAG_IS_NULL: int = 0x02                   # bit 1   | Session is null/anonymous
    SMB2_SESSION_FLAG_ENCRYPT_DATA: int = 0x04              # bit 2   | Encryption required for this session


class SMBResults:
    has_ran: bool = False
    had_error: bool = False
    error_info: str = ""
    nmap_status = str = ""
    used_dialect: str = ""
    server_name: str = ""
    client_name: str = ""
    remote_name: str = ""
    server_domain: str = ""
    dns_domain_name: str = ""
    dns_hostname: str = ""
    server_OS: str = ""
    server_OS_major: str = ""
    server_OS_minor: str = ""
    server_OS_build: str = ""
    does_support_NTLMv2: bool | None = None
    is_login_required: bool | None = None
    is_signing_required: bool | None = None
    open_dialects: dict= {
            "SMBv1":        False,
            "SMBv2.0":      False,
            "SMBv2.1":      False,
            "SMBv3.0":      False,
            "SMBv3.0.2":    False,
            "SMBv3.1.1":    False,
        }
    v30_encryption: str = ""
    v311_encryption: str = ""
    v1_flags: tuple | None = None
    v23_flags: tuple | None = None


# class SMBContext(Protocol):
#     """Quality of life structural type for the ``ctx`` a module's ``run(ctx)`` receives.

#     Never instantiated - only exists so that ctx has hints
#     """

#     # core ModuleContext fields
#     args: "SMBArgs"
#     target: tuple[str, int]
#     ptjsonlib: PtJsonLib
#     json: bool
#     verbose: bool

#     def out(
#         self,
#         string: str = "",
#         category: str = "text",
#         *,
#         colortext: bool = False,
#         indent: int = 0,
#         condition: Optional[bool] = True,
#     ) -> None: ...

#     def debug(self, string: str = "", *, indent: int = 4) -> None: ...

#     host: str
#     ip: str
#     port: int
#     mapping: dict
#     server_name: str
#     os_version: str
#     dns_domain_name: str
#     dns_host_name: str
#     ntlmv2_support: bool | None
#     login_required: bool | None
#     signing_required: bool | None
#     successful_dialects: list
#     v30_encryption: str
#     v311_encryption: str
#     error: bool | None


def get_if_available(getter):
    try:
        return getter()
    except Exception:
        return "unknown"

def valid_target_smb(target: str) -> Target:
    return valid_target(target, domain_allowed=True)


def valid_target(target: str, port_required: bool = False, domain_allowed: bool = False) -> Target:
    """
    Decides whether the target argument is a valid IP address or hostname
    with optional valid port definition. Designed for automatic usage by argparse.

    Args:
        target (str): target argument
        port_required (bool, optional): whether to require port definition. Defaults to False.
        domain_allowed (bool, optional): whether to allow hostnames. Defaults to False.

    Raises:
        argparse.ArgumentError: invalid format
        argparse.ArgumentError: missing port number
        argparse.ArgumentError: invalid ip address
        argparse.ArgumentError: unresolvable hostname
        argparse.ArgumentError: invalid port number

    Returns:
        Target: parsed Target
    """
    split = target.split(":")
    if not port_required and len(split) > 2:
        raise argparse.ArgumentError(None, "The target has to be IP[:PORT]")

    if port_required and len(split) != 2:
        raise argparse.ArgumentError(None, "The target has to be IP:PORT")

    try:
        ipaddress.ip_address(split[0])
    except:
        if domain_allowed:
            try:
                socket.gethostbyname(split[0])
            except Exception:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve target name '{split[0]}' into IP address"
                )
        else:
            raise argparse.ArgumentError(None, "Invalid target IP address")

    if len(split) > 1:
        try:
            port = int(split[1])
            if port <= 0 or port >= 65536:
                raise ValueError
        except:
            raise argparse.ArgumentError(None, "Invalid PORT number")
    else:
        port = 0

    return Target(split[0], port)


def extract_smbv23_security_info(smb_server) -> dict:
    """
    Extract SMB2/3 security-relevant information from negotiated connection.
    
    Args:
        smb_server: The SMB/SMB3 object from smb_client.getSMBServer()
    
    Returns:
        dict: Security info including signing, encryption, capabilities
    """
    flags = SMBv23Flags()
    security_info = {}
    
    try:
        # Get the internal connection state (SMB3+ only)
        if hasattr(smb_server, '_Connection'):
            conn = smb_server._Connection
            
            # SECURITY MODE ANALYSIS
            security_mode = conn.get('SecurityMode', 0)
            security_info['signing_enabled'] = bool(security_mode & flags.SMB2_NEGOTIATE_SIGNING_ENABLED)
            security_info['signing_required'] = bool(security_mode & flags.SMB2_NEGOTIATE_SIGNING_REQUIRED)
            
            # CAPABILITIES ANALYSIS
            capabilities = conn.get('Capabilities', 0)
            security_info['supports_dfs'] = bool(capabilities & flags.SMB2_GLOBAL_CAP_DFS)
            security_info['supports_leasing'] = bool(capabilities & flags.SMB2_GLOBAL_CAP_LEASING)
            security_info['supports_large_mtu'] = bool(capabilities & flags.SMB2_GLOBAL_CAP_LARGE_MTU)
            security_info['supports_multi_channel'] = bool(capabilities & flags.SMB2_GLOBAL_CAP_MULTI_CHANNEL)
            security_info['supports_persistent_handles'] = bool(capabilities & flags.SMB2_GLOBAL_CAP_PERSISTENT_HANDLES)
            security_info['supports_directory_leasing'] = bool(capabilities & flags.SMB2_GLOBAL_CAP_DIRECTORY_LEASING)
            security_info['supports_encryption'] = bool(capabilities & flags.SMB2_GLOBAL_CAP_ENCRYPTION)
            
            # ENCRYPTION STATUS (SMB3+)
            security_info['encryption_required'] = conn.get('RequireEncryption', False)
            security_info['dialect'] = conn.get('Dialect', 'Unknown')
            
            # SESSION INFO
            security_info['require_signing'] = conn.get('RequireSigning', False)
            security_info['max_transact_size'] = conn.get('MaxTransactSize', 0)
            security_info['max_read_size'] = conn.get('MaxReadSize', 0)
            security_info['max_write_size'] = conn.get('MaxWriteSize', 0)
            
        # Get available methods from SMB/SMB3 object
        if hasattr(smb_server, 'is_signing_required'):
            security_info['is_signing_required_method'] = smb_server.is_signing_required()
        
        if hasattr(smb_server, 'getDialect'):
            security_info['negotiated_dialect'] = smb_server.getDialect()
            
    except Exception as e:
        security_info['error'] = str(e)
    
    return security_info


def extract_smbv1_security_info(smb_server) -> dict:
    """
    Extract SMB1 security-relevant information from negotiated connection.
    
    Args:
        smb_server: The SMB object from smb_client.getSMBServer()
    
    Returns:
        dict: Security info including auth level, signing, encryption
    """
    flags = SMBv1Flags()
    security_info = {}
    
    try:
        # Get the internal dialect parameters (SMB1)
        if hasattr(smb_server, '_dialects_parameters'):
            dialect_params = smb_server._dialects_parameters
            security_mode = dialect_params.get('SecurityMode', 0)
            
            # USER vs SHARE LEVEL AUTHENTICATION
            security_info['user_level_auth'] = bool(security_mode & flags.NEGOTIATE_USER_SECURITY)
            security_info['share_level_auth'] = not security_info['user_level_auth']
            
            # PASSWORD ENCRYPTION/HASHING
            security_info['encrypt_passwords'] = bool(security_mode & flags.NEGOTIATE_ENCRYPT_PASSWORDS)
            security_info['plaintext_only'] = not security_info['encrypt_passwords']
            
            # MESSAGE SIGNING
            security_info['signing_enabled'] = bool(security_mode & flags.NEGOTIATE_SECURITY_SIGNATURE_ENABLE)
            security_info['signing_required'] = bool(security_mode & flags.NEGOTIATE_SECURITY_SIGNATURE_REQUIRED)
            
            # CAPABILITIES
            capabilities = dialect_params.get('Capabilities', 0)
            security_info['supports_unicode'] = bool(capabilities & flags.CAP_UNICODE)
            security_info['supports_large_files'] = bool(capabilities & flags.CAP_LARGE_FILES)
            security_info['supports_nt_errors'] = bool(capabilities & flags.CAP_USE_NT_ERRORS)
            security_info['supports_extended_security'] = bool(capabilities & flags.CAP_EXTENDED_SECURITY)
            
        # Get available methods from SMB object
        if hasattr(smb_server, 'is_login_required'):
            security_info['is_login_required'] = smb_server.is_login_required()
        
        if hasattr(smb_server, 'is_signing_required'):
            security_info['is_signing_required'] = smb_server.is_signing_required()
        
        if hasattr(smb_server, 'doesSupportNTLMv2'):
            security_info['supports_ntlmv2'] = smb_server.doesSupportNTLMv2()
            
    except Exception as e:
        security_info['error'] = str(e)
    
    return security_info