from impacket.smbconnection import (
    SMBConnection,
    SMB_DIALECT,
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
)

from .helpers import get_if_available
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

    def connect(self, username = "", password = "", timeout = 3) -> None:
        output: SMBResults = SMBResults()
        smb_client: SMBConnection
        output = self.ctx.output
        output.has_ran = True
        ip, port = self.ctx.target
        
        nm_dialects = []
        nm = nmap.PortScanner()
        try:
            nm.scan(str(ip), str(port), "--script smb-protocols")
            output.nmap_status = str(nm[ip]['tcp'][port]['state'])
            nm_dialects = str(nm._scan_result['scan'][ip]['hostscript'][0]['output']).split("\n    ")[1:]

        except Exception as e:
            output.had_error = True
            output.error_info = "error during dialect scan: " + str(e)
            return

        for dialect in nm_dialects:
            output.open_dialects[self.nm_to_std[dialect]] = True
        
        try:
            smb_client = SMBConnection(
                remoteName="*SMBSERVER",
                remoteHost=ip,
                sess_port=port,
                # TODO: check if I might have to try more dialects than the first accepted
                preferredDialect=self.dial_str_converter(nm_dialects[0]), # lowest accepted dialect
                timeout=timeout
            )
            try:
                # TODO: implement login interaction
                smb_client.login(username, password)
            except Exception:
                pass
            smb_client.close()
        except Exception as e:
            output.had_error = True
            output.error_info = str(e) + " (main scan)"
            return
        
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

        for name, getter in getters.items():
            setattr(output, name, get_if_available(getter))

        output.used_dialect = self.dial_str_converter(smb_client.getDialect())
        
        if smb_client.getDialect() == SMB_DIALECT:
            flags1, flags2 = smb_client.getSMBServer().get_flags()
            security_mode = smb_client._SMBConnection._dialects_parameters.fields.get('SecurityMode', None)
            capabilities = smb_client._SMBConnection._dialects_parameters.fields.get('Capabilities', None)
            output.v1_flags = (flags1, flags2, security_mode, capabilities)
        else:
            security_mode = smb_client._SMBConnection._Connection.get('ServerSecurityMode', None)
            capabilities = smb_client._SMBConnection._Connection.get('ServerCapabilities', None)
            output.v23_flags = (security_mode, capabilities)
        
        
        # auth_level = {
        #     "user":	    "Separate username/password per user",
        #     "share":	"Shared password for the whole share",
        # }
        # challenge_response = {
        #     "supported"	        "Supports hashed/challenge-response auth"
        #     "plaintext-only"	"Only accepts plaintext passwords"
        # }
        # msg_signing = {
        #     "required"	        "Signing is mandatory"
        #     "supported"	        "Signing is available but optional"
        #     "disabled"	        "No message signing"
        # }
