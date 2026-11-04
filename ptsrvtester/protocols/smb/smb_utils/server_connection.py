from impacket.smbconnection import (
    SMBConnection,
    SMB_DIALECT,
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
)

from .helpers import get_flag, get_if_available
from .helpers import SMBResults, SMBv1Flags, SMBv23Flags
import nmap


class ServerConnection():
    int_to_dialect = {
        SMB_DIALECT:        "SMBv1",
        SMB2_DIALECT_002:   "SMBv2.0",
        SMB2_DIALECT_21:    "SMBv2.1",
        SMB2_DIALECT_30:    "SMBv3.0",
        SMB2_DIALECT_311:   "SMBv3.1.1",
    }
    
    dialect_to_int = {
        "SMBv1":        SMB_DIALECT,
        "SMBv2.0":      SMB2_DIALECT_002,
        "SMBv2.1":      SMB2_DIALECT_21,
        "SMBv3.0":      SMB2_DIALECT_30,
        "SMBv3.0.2":    SMB2_DIALECT_30,
        "SMBv3.1.1":    SMB2_DIALECT_311,
        # nmap strings:
        'NT LM 0.12 (SMBv1) [dangerous, but default]':  SMB_DIALECT,
        '2.0.2':                                        SMB2_DIALECT_002,
        '2.1':                                          SMB2_DIALECT_21,
        '3.0':                                          SMB2_DIALECT_30,
        '3.0.2':                                        SMB2_DIALECT_30,
        '3.1.1':                                        SMB2_DIALECT_311,
    }

    nm_to_std = {
        'NT LM 0.12 (SMBv1) [dangerous, but default]':  "SMBv1",
        '2.0.2':                                        "SMBv2.0",
        '2.1':                                          "SMBv2.1",
        '3.0':                                          "SMBv3.0",
        '3.0.2':                                        "SMBv3.0.2",
        '3.1.1':                                        "SMBv3.1.1",
    }
    
    def __init__(self, ctx) -> None:
        self.ctx = ctx
    
    def dial_str_converter(self, input: str | int):
        if input == SMB_DIALECT:
            return "SMBv1"
        if isinstance(input, str):
            if input not in self.dialect_to_int.keys():
                return "unknown dialect"
            return self.dialect_to_int[input]
        elif isinstance(input, int):
            if input not in self.int_to_dialect.keys():
                return "unknown dialect"
            return self.int_to_dialect[input]
        else:
            return None

    def login(self, smb_client: SMBConnection, username: str, password: str) -> bool:
        anon = username == password and username == ""
        if anon:
            self.ctx.debug(f"Trying empty login")
        else: 
            self.ctx.debug(f"Trying login u:{username} p:{password}")

        try:
            smb_client.login(username, password)
            self.ctx.debug("Successful NULL session login" if anon else f"Successful login on u:{username} p:{password}")
            return True
        except Exception as e:
            self.ctx.debug(f"Login failed")
        return False
    
    def try_tree_connection(self, smb_client: SMBConnection, share = "IPC$") -> bool:
        # TODO: Add ability to connect to specific folder
        self.ctx.debug(f"Attempting connection to: {share}")
        try:
            tree_id = smb_client.connectTree("IPC$")
            self.ctx.debug(f"Tree connection success! Tree ID: {str(tree_id)}")
            return True
        except Exception as e:
            self.ctx.debug("Tree connection failed: " + str(e))
        return False

    @staticmethod
    def _read_flag(source: int | None, mask: int) -> bool | None:
        if isinstance(source, bool) or not isinstance(source, int):
            return None
        return get_flag(source, mask)

    def connect(self, timeout = 3) -> None:
        username, password = self.ctx.userpass
        empty_login: bool = username == password and username == ""
        output: SMBResults = SMBResults()
        smb_client: SMBConnection
        output = self.ctx.output
        output.has_ran = True
        ip, port = self.ctx.target
        
        self.ctx.debug("Running nmap scan to determine supported dialects")
        nm_dialects = []
        nm = nmap.PortScanner()
        try:
            nm.scan(str(ip), str(port), "--script smb-protocols")
            output.nmap_status = str(nm[ip]['tcp'][port]['state'])
            nm_dialects = str(nm._scan_result['scan'][ip]['hostscript'][0]['output']).split("\n    ")[1:]

        except Exception as e:
            self.ctx.debug("Ran into an error: " + str(e))
            output.had_error = True
            output.error_info = "error during dialect scan: " + str(e)
            return

        self.ctx.debug("Found supported dialects")

        for dialect in nm_dialects:
            output.open_dialects[self.nm_to_std[dialect]] = True

        self.ctx.debug("Communicating with server")
        try:
            smb_client = SMBConnection(
                remoteName="*SMBSERVER",
                remoteHost=ip,
                sess_port=port,
                # TODO: check if I might have to try more dialects than the first accepted
                preferredDialect=self.dial_str_converter(nm_dialects[0]), # lowest accepted dialect
                timeout=timeout
            )

            if self.login(smb_client, username, password):
                output.successful_login = True
                output.guest_session = bool(smb_client.isGuestSession())
                self.try_tree_connection(smb_client)
            elif not empty_login:
                self.login(smb_client, "", "")
                output.successful_login = True
                output.guest_session = bool(smb_client.isGuestSession())
                self.try_tree_connection(smb_client)

            smb_client.close()
        except Exception as e:
            self.ctx.debug("Ran into an error: " + str(e))
            output.had_error = True
            output.error_info = str(e) + " (main scan)"
            return
        
        self.ctx.debug("Server communication successful")
        
        getters = {
            # "SMBServer_object":         smb_client.getSMBServer,
            # "dialect":                  smb_client.getDialect,
            "server_name":              smb_client.getServerName,
            "client_name":              smb_client.getClientName,
            "remote_name":              smb_client.getRemoteName,
            "server_domain":            smb_client.getServerDomain,
            "dns_domain_name":          smb_client.getServerDNSDomainName,
            "dns_hostname":             smb_client.getServerDNSHostName,
            "server_OS":                smb_client.getServerOS,
            "server_OS_major":          smb_client.getServerOSMajor,
            "server_OS_minor":          smb_client.getServerOSMinor,
            "server_OS_build":          smb_client.getServerOSBuild,
            "does_support_NTLMv2":      smb_client.doesSupportNTLMv2,
            "is_login_required":        smb_client.isLoginRequired,
            "is_signing_required":      smb_client.isSigningRequired,
            # "credentials":              smb_client.getCredentials,
            # "IO_capabilities":          smb_client.getIOCapabilities,
        }

        self.ctx.debug("Parsing found server info")

        for name, getter in getters.items():
            setattr(output, name, get_if_available(getter))

        output.used_dialect = self.dial_str_converter(smb_client.getDialect())
        
        if smb_client.getDialect() == SMB_DIALECT:
            flags1, flags2 = smb_client.getSMBServer().get_flags()
            security_mode = smb_client._SMBConnection._dialects_parameters.fields.get('SecurityMode', None)
            capabilities = smb_client._SMBConnection._dialects_parameters.fields.get('Capabilities', None)
            output.v1_flags = (flags1, flags2, security_mode, capabilities)

            output.signing_support = self._read_flag(
                flags2, SMBv1Flags.FLAGS2_SMB_SECURITY_SIGNATURE)
            output.signing_requirement = self._read_flag(
                flags2, SMBv1Flags.FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED)
            output.user_level_auth = self._read_flag(
                security_mode, SMBv1Flags.NEGOTIATE_USER_SECURITY)
            output.uses_challenge_response = self._read_flag(
                security_mode, SMBv1Flags.NEGOTIATE_ENCRYPT_PASSWORDS)
            output.null_session = output.successful_login

            self.ctx.debug(f"user_level_auth = {output.user_level_auth}")
            self.ctx.debug(f"uses_challenge_response = {output.uses_challenge_response}")
            self.ctx.debug(f"does_support_NTLMv2 = {output.does_support_NTLMv2}")
            self.ctx.debug(f"signing_support = {output.signing_support}")
            self.ctx.debug(f"signing_requirement = {output.signing_requirement}")
            self.ctx.debug(f"is_login_required = {output.is_login_required}")
            self.ctx.debug(f"guest_session = {output.guest_session}")
        else:
            security_mode = smb_client._SMBConnection._Connection.get('ServerSecurityMode', None)
            capabilities = smb_client._SMBConnection._Connection.get('ServerCapabilities', None)
            session_flags = smb_client._SMBConnection._Session.get('SessionFlags', None)
            output.v23_flags = (security_mode, capabilities, session_flags)
            output.signing_support = self._read_flag(
                security_mode, SMBv23Flags.SMB2_NEGOTIATE_SIGNING_ENABLED)
            output.signing_requirement = self._read_flag(
                security_mode, SMBv23Flags.SMB2_NEGOTIATE_SIGNING_REQUIRED)
            output.encryption_support = self._read_flag(
                capabilities, SMBv23Flags.SMB2_GLOBAL_CAP_ENCRYPTION)
            output.session_encryption_requirement = self._read_flag(
                session_flags, SMBv23Flags.SMB2_SESSION_FLAG_ENCRYPT_DATA)
            output.null_session = self._read_flag(
                session_flags, SMBv23Flags.SMB2_SESSION_FLAG_IS_NULL)
            
            self.ctx.debug(f"signing_support = {output.signing_support}")
            self.ctx.debug(f"signing_requirement = {output.signing_requirement}")
            self.ctx.debug(f"encryption_support = {output.encryption_support}")
            self.ctx.debug(f"session_encryption_requirement = {output.session_encryption_requirement}")
            self.ctx.debug(f"does_support_NTLMv2 = {output.does_support_NTLMv2}")
            self.ctx.debug(f"is_login_required = {output.is_login_required}")
            self.ctx.debug(f"null_session = {output.null_session}")
            self.ctx.debug(f"guest_session = {output.guest_session}")

        self.ctx.debug("Server connection done")
