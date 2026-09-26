from dataclasses import dataclass
from typing import Any

@dataclass
class NTPResults:
    has_ran: bool
    error: bool
    error_info: str
    accepts_mode_6: bool
    kod_sent: bool
    version: str | int | None
    hostname: str | None
    processor: str | None
    system_os: str | None
    mode: int | None
    stratum: int | None
    ref_id: str | None
    leap: int | None
    precision: int | None
    ref_time: str | None
    transmit_time: str | None

    def __init__(self) -> None:
        self.has_ran = False
        self.error = False
        self.error_info = ""
        self.accepts_mode_6 = False
        self.kod_sent = False
        self.version = None
        self.hostname = None
        self.processor = None
        self.system_os = None
        self.mode = None
        self.stratum = None
        self.ref_id = None
        self.leap = None
        self.precision = None
        self.ref_time = None
        self.transmit_time = None