"""
Service identification from server banner.
Maps banner content to product name, version (if numeric), OS/distribution, and CPE 2.3 (NVD-style).
Only numeric app versions (e.g. 7.1.1, 4.96) are used as version and in CPE; distribution
names (e.g. Ubuntu, Debian/GNU Linux) from banner go to os, not version.

CPE 2.3 (NIST/NVD) has exactly 11 components after the "cpe:2.3:" prefix:
  part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other.
Unknown/NA components are represented as *.
"""
import re
from dataclasses import dataclass
from typing import Final

# Version string acceptable for CPE (NVD uses numeric versions). Reject distro names.
_CPE_VERSION_RE = re.compile(r"^\d+[.\d]*(?:p\d+)?[\w.-]*$", re.I)

# CPE 2.3: exactly 11 components after "cpe:2.3:"
_CPE_23_NUM_COMPONENTS = 11


def _cpe_23_normalize(cpe: str) -> str:
    """Return CPE 2.3 string with all 11 components; pad with * if shorter."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return cpe
    parts = cpe.split(":")
    if len(parts) < 3:
        return cpe
    # parts[0]=cpe, parts[1]=2.3, parts[2:]=component list
    components = parts[2:]
    while len(components) < _CPE_23_NUM_COMPONENTS:
        components.append("*")
    return ":".join([parts[0], parts[1]] + components[: _CPE_23_NUM_COMPONENTS])

# (pattern re, product display name, CPE base cpe:2.3:a:vendor:product:*)
# Order: more specific first. Version is first capture group if present.
# CPE vendor/product from NVD where available.
_BANNER_PATTERNS: Final[list[tuple[re.Pattern[str], str, str]]] = [
    # --- SMTP / mail (MTAs, gateways) ---
    (re.compile(r"Kerio\s+Connect\s+(\d+\.\d+(?:\.\d+)?)", re.I), "Kerio Connect", "cpe:2.3:a:kerio:connect:*"),
    (re.compile(r"Microsoft\s+ESMTP\s+MAIL\s+Service", re.I), "Microsoft Exchange Server", "cpe:2.3:a:microsoft:exchange_server:*"),
    (re.compile(r"Microsoft\s+SMTP\s+Server", re.I), "Microsoft SMTP Server", "cpe:2.3:a:microsoft:exchange_server:*"),
    (re.compile(r"\bgsmtp\b", re.I), "Google SMTP (Gmail)", "cpe:2.3:a:google:gmail:*"),
    (re.compile(r"yahoo\.com\s+ESMTP\s+ready", re.I), "Yahoo Mail Proxy", "cpe:2.3:a:yahoo:mail_proxy:*"),
    (re.compile(r"aol\.mail.*ESMTP\s+ready", re.I), "Yahoo Mail Proxy", "cpe:2.3:a:yahoo:mail_proxy:*"),
    (re.compile(r"Mailgun\s+Delivery\s+Service", re.I), "Mailgun", "cpe:2.3:a:mailgun:mailgun:*"),
    (re.compile(r"SendGrid\s+ESMTP", re.I), "SendGrid", "cpe:2.3:a:sendgrid:sendgrid:*"),
    (re.compile(r"email-smtp\.amazonaws\.com\s+ESMTP", re.I), "Amazon SES", "cpe:2.3:a:amazon:ses:*"),
    (re.compile(r"mandrillapp\.com\s+ESMTP", re.I), "Mandrill (Mailchimp)", "cpe:2.3:a:mailchimp:mandrill:*"),
    (re.compile(r"ESMTP\s+Sendinblue\s+SMTP\s+(\d+\.\d+)", re.I), "Sendinblue SMTP (Brevo)", "cpe:2.3:a:brevo:smtp:*"),
    (re.compile(r"\bSendinblue\b", re.I), "Sendinblue SMTP (Brevo)", "cpe:2.3:a:brevo:smtp:*"),
    (re.compile(r"(?:AsyncOS|IronPort)\s+(\d+\.\d+)", re.I), "Cisco Secure Email (IronPort)", "cpe:2.3:a:cisco:secure_email_gateway:*"),
    (re.compile(r"\b(?:AsyncOS|IronPort)\b", re.I), "Cisco Secure Email (IronPort)", "cpe:2.3:a:cisco:secure_email_gateway:*"),
    (re.compile(r"ESMTP\s+IceWarp\s+(\d+(?:\.\d+)+)", re.I), "IceWarp", "cpe:2.3:a:icewarp:icewarp_server:*"),
    (re.compile(r"\bIceWarp\s+(\d+(?:\.\d+)+)", re.I), "IceWarp", "cpe:2.3:a:icewarp:icewarp_server:*"),
    (re.compile(r"\bIceWarp\b", re.I), "IceWarp", "cpe:2.3:a:icewarp:icewarp_server:*"),
    (re.compile(r"ESMTP\s+FortiMail\s+(\d+\.\d+(?:\.\d+)?)", re.I), "FortiMail", "cpe:2.3:a:fortinet:fortimail:*"),
    (re.compile(r"\bFortiMail\b", re.I), "FortiMail", "cpe:2.3:a:fortinet:fortimail:*"),
    (re.compile(r"Oracle\s+Communications\s+Messaging\s+Server\s+(\d+\.\d+(?:\.\d+)?)", re.I), "Oracle Communications Messaging Server", "cpe:2.3:a:oracle:communications_messaging_server:*"),
    (re.compile(r"Oracle\s+Communications\s+Messaging\s+Server", re.I), "Oracle Communications Messaging Server", "cpe:2.3:a:oracle:communications_messaging_server:*"),
    (re.compile(r"Zimbra\s+(\d+\.\d+(?:\.\d+)?)", re.I), "Zimbra Collaboration", "cpe:2.3:a:zimbra:collaboration:*"),
    (re.compile(r"\bZCS\b", re.I), "Zimbra Collaboration", "cpe:2.3:a:zimbra:collaboration:*"),
    (re.compile(r"hMailServer\s+(\d+\.\d+(?:\.\d+)?)", re.I), "hMailServer", "cpe:2.3:a:hmailserver:hmailserver:*"),
    (re.compile(r"\bhMailServer\b", re.I), "hMailServer", "cpe:2.3:a:hmailserver:hmailserver:*"),
    (re.compile(r"Apache\s+James\s+(\d+\.\d+(?:\.\d+)?)", re.I), "Apache James", "cpe:2.3:a:apache:james:*"),
    (re.compile(r"\bJames\s+SMTP\b", re.I), "Apache James", "cpe:2.3:a:apache:james:*"),
    (re.compile(r"Haraka\s+(\d+\.\d+(?:\.\d+)?)", re.I), "Haraka", "cpe:2.3:a:haraka:haraka:*"),
    (re.compile(r"\bHaraka\b", re.I), "Haraka", "cpe:2.3:a:haraka:haraka:*"),
    (re.compile(r"Sendmail\s+(\d+\.\d+(?:\.\d+)?)(?:\/[^\s]*)?", re.I), "Sendmail", "cpe:2.3:a:sendmail:sendmail:*"),
    (re.compile(r"Exim\s+(\d+\.\d+(?:\.\d+)?)", re.I), "Exim", "cpe:2.3:a:exim:exim:*"),
    (re.compile(r"Postfix\s+(\d+\.\d+(?:\.\d+)?)", re.I), "Postfix", "cpe:2.3:a:postfix:postfix:*"),
    (re.compile(r"Postfix\s+\(([^)]+)\)", re.I), "Postfix", "cpe:2.3:a:postfix:postfix:*"),
    (re.compile(r"ESMTP\s+Postfix", re.I), "Postfix", "cpe:2.3:a:postfix:postfix:*"),
    (re.compile(r"\bPostfix\b", re.I), "Postfix", "cpe:2.3:a:postfix:postfix:*"),
    (re.compile(r"Lotus\s+Domino\s+(\d+\.\d+)", re.I), "IBM Lotus Domino", "cpe:2.3:a:ibm:domino:*"),
    (re.compile(r"\bDomino\b", re.I), "IBM Lotus Domino", "cpe:2.3:a:ibm:domino:*"),
    (re.compile(r"MailEnable\s+Service,\s+Version:\s*(\d+\.\d+(?:\.\d+)?)", re.I), "MailEnable", "cpe:2.3:a:mailenable:mailenable:*"),
    (re.compile(r"MailEnable\s+(\d+\.\d+)", re.I), "MailEnable", "cpe:2.3:a:mailenable:mailenable:*"),
    (re.compile(r"\bMailEnable\b", re.I), "MailEnable", "cpe:2.3:a:mailenable:mailenable:*"),
    (re.compile(r"Axigen\s+(\d+\.\d+(?:\.\d+)?)", re.I), "Axigen", "cpe:2.3:a:axigen:axigen_mail_server:*"),
    (re.compile(r"\bAxigen\b", re.I), "Axigen", "cpe:2.3:a:axigen:axigen_mail_server:*"),
    (re.compile(r"MDaemon\s+(\d+\.\d+)", re.I), "MDaemon", "cpe:2.3:a:alt-n:mdaemon:*"),
    (re.compile(r"\bMDaemon\b", re.I), "MDaemon", "cpe:2.3:a:alt-n:mdaemon:*"),
    (re.compile(r"SmarterMail\s+(\d+\.\d+(?:\.\d+)?)", re.I), "SmarterMail", "cpe:2.3:a:smartertools:smartermail:*"),
    (re.compile(r"\bSmarterMail\b", re.I), "SmarterMail", "cpe:2.3:a:smartertools:smartermail:*"),
    (re.compile(r"ESMTP\s+Postcow", re.I), "Mailcow: dockerized", "cpe:2.3:a:mailcow:mailcow:*"),
    (re.compile(r"\bPostcow\b", re.I), "Mailcow: dockerized", "cpe:2.3:a:mailcow:mailcow:*"),
    (re.compile(r"\bMailcow\b", re.I), "Mailcow: dockerized", "cpe:2.3:a:mailcow:mailcow:*"),
    (re.compile(r"Barracuda\s+(\d+\.\d+)", re.I), "Barracuda Email Security", "cpe:2.3:a:barracuda:email_security_gateway:*"),
    (re.compile(r"\bBarracuda\b", re.I), "Barracuda Email Security", "cpe:2.3:a:barracuda:email_security_gateway:*"),
    (re.compile(r"Welcome\s+to\s+coremail", re.I), "Coremail Mail Server", "cpe:2.3:a:coremail:coremail:*"),
    (re.compile(r"\bcoremail\b", re.I), "Coremail Mail Server", "cpe:2.3:a:coremail:coremail:*"),
    (re.compile(r"pphosted\.com", re.I), "Proofpoint Email Protection", "cpe:2.3:a:proofpoint:proofpoint_email_protection:*"),
    (re.compile(r"ESMTP\s+mfa-", re.I), "Proofpoint Email Protection", "cpe:2.3:a:proofpoint:proofpoint_email_protection:*"),
    (re.compile(r"\bmfa-\w+", re.I), "Proofpoint Email Protection", "cpe:2.3:a:proofpoint:proofpoint_email_protection:*"),
    (re.compile(r"\bProofpoint\b", re.I), "Proofpoint Email Protection", "cpe:2.3:a:proofpoint:proofpoint_email_protection:*"),
    (re.compile(r"ESMTP\s+\[Sophos\s+Email\s+Appliance\]", re.I), "Sophos Email Appliance", "cpe:2.3:a:sophos:email_appliance:*"),
    (re.compile(r"Sophos\s+Email\s+Appliance", re.I), "Sophos Email Appliance", "cpe:2.3:a:sophos:email_appliance:*"),
    (re.compile(r"ESMTP\s+\(Mimecast\)", re.I), "Mimecast", "cpe:2.3:a:mimecast:email_security_gateway:*"),
    (re.compile(r"\bMimecast\b", re.I), "Mimecast", "cpe:2.3:a:mimecast:email_security_gateway:*"),
    (re.compile(r"ESMTP\s+Trend\s+Micro\s+Email\s+Security\s+Service\s+ready", re.I), "Trend Micro Email Security", "cpe:2.3:a:trendmicro:email_security:*"),
    (re.compile(r"Trend\s+Micro\s+Email\s+Security", re.I), "Trend Micro Email Security", "cpe:2.3:a:trendmicro:email_security:*"),
    (re.compile(r"\bDovecot\b", re.I), "Dovecot", "cpe:2.3:a:dovecot:dovecot:*"),
    (re.compile(r"Courier\s+(?:mail\s+)?(?:server|Mail)", re.I), "Courier", "cpe:2.3:a:courier-mta:courier:*"),
    (re.compile(r"\bQmail\b", re.I), "Qmail", "cpe:2.3:a:qmail:qmail:*"),
    # Generic "ESMTP service ready" (no product name) = often customized Microsoft Exchange banner
    (re.compile(r"\bESMTP\s+service\s+ready\b", re.I), "Microsoft Exchange Server (custom banner)", "cpe:2.3:a:microsoft:exchange_server:*"),
    # --- IMAP / POP3 (Cyrus, etc.) ---
    (re.compile(r"Cyrus\s+IMAP4?\s+v?(\d+\.\d+(?:\.\d+)?)", re.I), "Cyrus IMAP", "cpe:2.3:a:cyrus:imap:*"),
    (re.compile(r"Cyrus\s+IMAP", re.I), "Cyrus IMAP", "cpe:2.3:a:cyrus:imap:*"),
    (re.compile(r"University\s+of\s+Washington", re.I), "UW IMAP", "cpe:2.3:a:university_of_washington:imap:*"),
    (re.compile(r"\bUW\s+IMAP\b", re.I), "UW IMAP", "cpe:2.3:a:university_of_washington:imap:*"),
    (re.compile(r"CommuniGate\s+Pro\s+(\d+\.\d+)", re.I), "CommuniGate Pro", "cpe:2.3:a:stalker:communigate_pro:*"),
    (re.compile(r"\bCommuniGate\b", re.I), "CommuniGate Pro", "cpe:2.3:a:stalker:communigate_pro:*"),
    # --- SSH ---
    (re.compile(r"SSH-2\.0-OpenSSH_([\d\.]+(?:p\d+)?)", re.I), "OpenSSH", "cpe:2.3:a:openbsd:openssh:*"),
    (re.compile(r"OpenSSH_([\d\.]+(?:p\d+)?)", re.I), "OpenSSH", "cpe:2.3:a:openbsd:openssh:*"),
    (re.compile(r"SSH-2\.0-libssh_([\d\.]+)", re.I), "libssh", "cpe:2.3:a:libssh:libssh:*"),
    (re.compile(r"libssh[_ ]([\d\.]+)", re.I), "libssh", "cpe:2.3:a:libssh:libssh:*"),
    (re.compile(r"SSH-2\.0-dropbear_(\d{4}\.\d+)", re.I), "Dropbear SSH", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*"),
    (re.compile(r"dropbear[_ ](\d{4}\.\d+)", re.I), "Dropbear SSH", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*"),
    (re.compile(r"SSH-2\.0-dropbear", re.I), "Dropbear SSH", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*"),
    (re.compile(r"SSH-2\.0-PuTTY(?:_Release_)?([\d\.]+)?", re.I), "PuTTY", "cpe:2.3:a:simon_tatham:putty:*"),
    (re.compile(r"\bPuTTY\b", re.I), "PuTTY", "cpe:2.3:a:simon_tatham:putty:*"),
    (re.compile(r"SSH-2\.0-Cisco-\d+\.\d+(?:\.\d+)?", re.I), "Cisco IOS SSH", "cpe:2.3:o:cisco:ios:*"),
    (re.compile(r"SSH-2\.0-Cisco", re.I), "Cisco IOS SSH", "cpe:2.3:o:cisco:ios:*"),
    # --- FTP ---
    (re.compile(r"ProFTPD\s+(\d+\.\d+(?:\.[\w]+)?)", re.I), "ProFTPD", "cpe:2.3:a:proftpd:proftpd:*"),
    (re.compile(r"ProFTPD\s+Server", re.I), "ProFTPD", "cpe:2.3:a:proftpd:proftpd:*"),
    (re.compile(r"\(vsFTPd\s+(\d+\.\d+\.\d+)\)", re.I), "vsftpd", "cpe:2.3:a:vsftpd_project:vsftpd:*"),
    (re.compile(r"vsFTPd\s+(\d+\.\d+\.\d+)", re.I), "vsftpd", "cpe:2.3:a:vsftpd_project:vsftpd:*"),
    (re.compile(r"\bvsFTPd\b", re.I), "vsftpd", "cpe:2.3:a:vsftpd_project:vsftpd:*"),
    (re.compile(r"Pure-FTPd\s+(\d+\.\d+(?:\.\d+)?)", re.I), "Pure-FTPd", "cpe:2.3:a:pure-ftpd:pure-ftpd:*"),
    (re.compile(r"Welcome\s+to\s+Pure-FTPd", re.I), "Pure-FTPd", "cpe:2.3:a:pure-ftpd:pure-ftpd:*"),
    (re.compile(r"Microsoft\s+FTP\s+Service", re.I), "Microsoft IIS FTP", "cpe:2.3:a:microsoft:internet_information_services:*"),
    (re.compile(r"\(MikroTik\s+(\d+\.\d+(?:\.\d+)?)\)", re.I), "MikroTik RouterOS FTP", "cpe:2.3:o:mikrotik:routeros:*"),
    (re.compile(r"MikroTik\s+(\d+\.\d+(?:\.\d+)?)", re.I), "MikroTik RouterOS FTP", "cpe:2.3:o:mikrotik:routeros:*"),
    (re.compile(r"\bMikroTik\b", re.I), "MikroTik RouterOS FTP", "cpe:2.3:o:mikrotik:routeros:*"),
    (re.compile(r"FileZilla\s+Server\s+(\d+\.\d+(?:\.\d+)?)", re.I), "FileZilla Server", "cpe:2.3:a:filezilla-project:filezilla_server:*"),
    (re.compile(r"FileZilla\s+Server", re.I), "FileZilla Server", "cpe:2.3:a:filezilla-project:filezilla_server:*"),
    (re.compile(r"Serv-U\s+(\d+\.\d+)", re.I), "Serv-U FTP", "cpe:2.3:a:solarwinds:serv-u:*"),
    (re.compile(r"\bServ-U\b", re.I), "Serv-U FTP", "cpe:2.3:a:solarwinds:serv-u:*"),
    (re.compile(r"WS_FTP\s+Server", re.I), "WS_FTP Server", "cpe:2.3:a:progress:ws_ftp:*"),
]


@dataclass(frozen=True)
class ServiceIdentification:
    """Result of banner-based service identification."""
    product: str
    version: str | None  # None if not specified or if captured string is OS/distro name
    cpe: str
    os: str | None = None  # OS/distribution from banner (e.g. Ubuntu), when not a product version


def identify_service(banner: str | None) -> ServiceIdentification | None:
    """
    Identify product and optional version from server banner.
    Returns ServiceIdentification(product, version, cpe, os) or None if no match.
    Version is set only for numeric app versions; distro names (Ubuntu, Debian, ...) go to os.
    CPE uses wildcard for version when not found: cpe:2.3:a:vendor:product:*
    """
    if not banner or not banner.strip():
        return None
    text = banner.replace("\r", " ").strip()
    if not text:
        return None
    # Use first line for matching (banner often multi-line)
    first_line = text.split("\n")[0].strip() if "\n" in text else text
    for pattern, product, cpe_base in _BANNER_PATTERNS:
        m = pattern.search(first_line)
        if m:
            raw = m.group(1).strip() if m.lastindex and m.lastindex >= 1 else None
            # Numeric version -> version; otherwise (e.g. Ubuntu, Debian/GNU) -> os, version stays None
            if raw and _CPE_VERSION_RE.match(raw):
                version, os_str = raw, None
            elif raw:
                version, os_str = None, raw
            else:
                version, os_str = None, None
            use_in_cpe = version and cpe_base.endswith("*")
            cpe = (cpe_base[:-1] + version) if use_in_cpe else cpe_base
            cpe = _cpe_23_normalize(cpe)
            return ServiceIdentification(product=product, version=version, cpe=cpe, os=os_str)
    return None
