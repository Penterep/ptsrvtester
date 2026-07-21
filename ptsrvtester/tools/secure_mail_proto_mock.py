#!/usr/bin/env python3
"""
Hardened POP3 + IMAP + FTP mock — minimal findings; valid login test/test only.

  python3 ptsrvtester/tools/secure_mail_proto_mock.py

  ptsrvtester pop3 -ts ALL 127.0.0.1:1110
  ptsrvtester imap -ts ALL 127.0.0.1:1143
  ptsrvtester ftp  -ts ALL -u test -p test 127.0.0.1:2121
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.mail_proto_mock import Profile, main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(default_profile=Profile.SECURE))
