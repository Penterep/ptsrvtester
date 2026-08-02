from impacket.smbconnection import (
    SMBConnection,
    SMB_DIALECT,
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
)

from ptsrvtester.modules.smb.smb_main import (
    TestContext
)


class ServerConnection():
    int_to_dialect = {
        SMB_DIALECT:        "SMBv1",
        SMB2_DIALECT_002:   "SMBv2.0",
        SMB2_DIALECT_21:    "SMBv2.1",
        SMB2_DIALECT_30:    "SMBv3.0",
        SMB2_DIALECT_311:   "SMBv3.1.1",
    }
    
    def _get_if_available(self, getter):
        try:
            return getter()
        except Exception:
            return None
    
    def __init__(self, ctx: TestContext) -> None:
        self.ctx: TestContext = ctx
    
    # TODO: add conversion function: dialect code to str and vice versa
    
    def connect(self, dialect: int) -> dict | None:
        # if isinstance(dialect, str):
        #     dialect = 
        
        output = {}
        
        try:
            ip, port = self.ctx.target
            smb_client = SMBConnection(
                remoteName="*SMBSERVER",
                remoteHost=ip,
                sess_port=port,
                preferredDialect=dialect,
                timeout=5
            )
            try:
                smb_client.login('', '')
            except Exception:
                pass
            
            getters = {
                smb_client.getSMBServer: "SMBServer_object",
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
                smb_client.getCredentials: "credentials",
                smb_client.getIOCapabilities: "IO_capabilities",
            }
            
            output = {}
            for getter in getters.keys():
                result = self._get_if_available(getter)
                if result is not None and result != "":
                    output[getters[getter]] = result
            
        except Exception as e:
            error_str = str(e)
        
        return output if output != {} else None
        
        