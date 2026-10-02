from impacket.smbconnection import (
    SMBConnection,
    SMB_DIALECT,
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
)

from .helpers import get_if_available
from .helpers import SMBResults
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
        "SMBv3.1.1":    SMB2_DIALECT_311,
        # nmap strings:
        'NT LM 0.12 (SMBv1) [dangerous, but default]':  SMB_DIALECT,
        '2.0.2':                                        SMB2_DIALECT_002,
        '2.1':                                          SMB2_DIALECT_21,
        '3.0':                                          SMB2_DIALECT_30,
        '3.0.2':                                        SMB2_DIALECT_30,
        '3.1.1':                                        SMB2_DIALECT_311,
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
    

    def connect(self) -> None:
        output: SMBResults = SMBResults()
        smb_client: SMBConnection
        nm = nmap.PortScanner()
        ip, port = self.ctx.target
        
        try:
            nm.scan(str(ip), str(port), "--script smb-protocols")
            output.nmap_status = str(nm[ip]['tcp'][port]['state'])
            nm_out = str(nm._scan_result['scan']['103.144.245.59']['hostscript'][0]['output']).split("\n    ")[1:]
            

        except Exception as e:
            output.had_error = True
            output.error_info = str(e)
            return
        
        try:
            smb_client = SMBConnection(
                remoteName="*SMBSERVER",
                remoteHost=ip,
                sess_port=port,
                preferredDialect=dialect,
                timeout=3
            )
            try:
                smb_client.login('', '')
            except Exception:
                pass
            smb_client.close()
        except Exception as e:
            output.had_error = True
            output.error_info = str(e)
            return
        
        getters = {
            # smb_client.getSMBServer: "SMBServer_object",
            smb_client.getDialect: "dialect",
            smb_client.getServerName: "server_name",
            smb_client.getClientName: "client_name",
            smb_client.getRemoteName: "remote_name",
            smb_client.getServerDomain: "server_domain",
            smb_client.getServerDNSDomainName: "server_DNS_domain_name",
            smb_client.getServerDNSHostName: "server_DNS_hostname",
            smb_client.getServerOS: "server_OS",
            smb_client.getServerOSMajor: "server_OS_major",
            smb_client.getServerOSMinor: "server_OS_minor",
            smb_client.getServerOSBuild: "server_OS_build",
            smb_client.doesSupportNTLMv2: "does_support_NTLMv2",
            smb_client.isLoginRequired: "is_login_required",
            smb_client.isSigningRequired: "is_signing_required",
            # smb_client.getCredentials: "credentials",
            # smb_client.getIOCapabilities: "IO_capabilities",
        }
        
        if parse_encryption:
            if dialect in [SMB2_DIALECT_30, SMB2_DIALECT_311]:
                server = smb_client.getSMBServer()
                # NOTE: sensitive to impacket changes
                status = "Supported" if server._Connection['SupportsEncryption'] else "Unsupported"
                if dialect == SMB2_DIALECT_30:
                    output.v30_encryption = status
                else:
                    output.v311_encryption = status

        if parse_info:
            for getter in getters.keys():
                result = get_if_available(getter)
                if result is not None and result != "":
                    output[getters[getter]] = result
                else:
                    output[getters[getter]] = "unknown"
            

        return output if success else None
        
        