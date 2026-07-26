#!/usr/bin/env python3
"""
Vulnerable POP3 + IMAP + FTP mock — findings expected on ptsrvtester -ts scans.

  python3 ptsrvtester/tools/vuln_mail_proto_mock.py

  ptsrvtester pop3 -ts ALL 127.0.0.1:1110
  ptsrvtester imap -ts ALL 127.0.0.1:1143
  ptsrvtester ftp  -ts ALL 127.0.0.1:2121
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running as script without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.mail_proto_mock import Profile, main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(default_profile=Profile.VULN))
