import os, queue, random, re, smtplib, socket, sys, threading, time
from typing import Callable


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
from .helpers import get_mode
from .progress import ThreadedProgress

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from .helpers import *
from .results import *
from .registry import *


class EnumMixin:

    def start_interactive_mode(self, smtp: smtplib.SMTP):
        self.ptprint("\n", end="")
        while True:
            user_input = input("[*] INTERACTIVE MODE: ").upper()
            status, reply = smtp.docmd(user_input)
            if user_input in ("EXIT", "QUIT"):
                break
            if user_input == "HELP":
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply))
            if not self.bytes_to_str(reply).endswith("\n"):
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply))
                self.ptprint(f" ")
            else:
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply).replace("\n", "\n      "))

