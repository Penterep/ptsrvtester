[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTSRVTESTER - Server Penetration Testing Tool

## Installation
```
pip install ptsrvtester
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples

```
ptsrvtester snmp detection --ip 192.168.1.1
ptsrvtester dns whois -d example.com
ptsrvtester ldap banner -ip 192.168.1.1
ptsrvtester dhcp info --interface eth0
ptsrvtester xrdp bruteforce --target 192.168.1.1 --username admin --wordlist passwords.txt
ptsrvtester <module> -h     for help for module use
```


### Available Modules:

```
   <module>                     Select module to use
                         snmp   SNMP testing module
                         dns    DNS testing module
                         ldap   LDAP testing module
                         msrpc  MSRPC testing module
                         ftp    FTP testing module
                         ssh    SSH testing module
                         smtp   SMTP testing module
                         pop3   POP3 testing module
                         imap   IMAP testing module
                         dhcp   DHCP testing module
                         xrdp   XRDP testing module

   -v        --version          Show script version and exit
   -h        --help             Show this help message and exit
   -j        --json             Output in JSON format
             --debug            Enable debug messages

```

### Module Descriptions:

**SNMP Module**
- Version detection (SNMPv1, SNMPv2c, SNMPv3)
- SNMPv2 community string brute-force
- SNMPv3 user enumeration and credential brute-force
- Write permission testing
- MIB walking (SNMPv2/SNMPv3)

**DNS Module**
- DNS server information retrieval
- Reverse DNS lookup
- Zone transfer attempts
- DNS record lookup
- WHOIS queries
- Subdomain brute-forcing
- DNSSEC verification
- Zone walking (NSEC/NSEC3)

**LDAP Module**
- Server banner retrieval
- LDAP search queries
- User enumeration
- Credential brute-force
- Write permission testing

**MSRPC Module**
- Endpoint mapper enumeration
- MGMT interface enumeration
- Named pipe brute-force
- SMB/TCP/HTTP credential brute-force
- Anonymous SMB access testing
- Named pipe enumeration

**FTP Module**
- Banner and Service Identification
- Anonymous authentication testing
- Read/write access testing
- Credential brute-force
- FTP bounce attack testing

**SSH Module**
- Banner, Service Identification and host key retrieval
- Authentication method detection
- Bad public key detection
- SSH audit (CVE identification)
- Credential and private key brute-force

**SMTP Module**
- Banner and Service Identification
- Server information gathering
- Encryption testing (plaintext, STARTTLS, TLS); port 465 implicit TLS
- User enumeration (VRFY, EXPN, RCPT)
- NTLM information disclosure
- Open relay testing
- Catch-all mailbox detection
- RCPT TO limit test (per-message recipient limit; expects 452/421 or similar)
- Credential brute-force
- Blacklist testing

**POP3 Module**
- Banner, Service Identification and capabilities retrieval
- Encryption testing (plaintext, STLS, TLS); port 995 implicit TLS
- Anonymous authentication testing
- NTLM authentication inspection
- Credential brute-force

**IMAP Module**
- Banner, Service Identification and capabilities retrieval
- Anonymous authentication testing
- NTLM authentication inspection
- Credential brute-force

**DHCP Module**
- DHCP server information retrieval
- DHCP starvation attack testing
- DHCP DoS/flood attack testing
- Network interface based testing

**XRDP Module**
- XRDP server brute-force testing
- Credential testing via GUI automation
- Multi-threaded password testing
- CVE-2024-39917 exploitation (no rate limiting)
- Requires Linux with Xorg, xfreerdp3, and wmctrl

```

## Dependencies

```
cryptography>=42.0.8
dnspython>=2.7.0
impacket>=0.12.0
ldap3>=2.9.1
ptlibs>=1.0.20,<2
pysnmp>=7.1.20
python-whois>=0.9.5
paramiko>=4.0.0
beautifulsoup4>=4.14.0
httpx>=0.28.0
h2>=4.3.0
lxml>=6.0.0
ssh_audit>=3.3.0
ntlm-auth>=1.5.0
scapy>=2.6.1
dhcppython>=0.1.4
pillow>=12.0.0
python-xlib>=0.33
pynput>=1.8.0
XWindows>=0.0.7
```

### Additional System Requirements

For DHCP module:
- Root/sudo privileges (for network packet manipulation)

For XRDP module:
- Linux with Xorg (not Wayland)
- `xfreerdp3` command available
- `wmctrl` command available
- Disable screen saver/lock during use


## License

Copyright (c) 2024 Penterep Security s.r.o.

ptsrvtester is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptsrvtester is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptsrvtester. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the servers and systems which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!
