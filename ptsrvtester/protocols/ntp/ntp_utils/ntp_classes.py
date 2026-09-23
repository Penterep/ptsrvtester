from dataclasses import dataclass

@dataclass
class NTPResults:
    error: bool = False
    error_info: str = ""
    accepts_mode_6: bool = False
    kod_sent: bool = False
    version: str | int | None = None
    hostname: str | None = None
    processor: str | None = None
    system_os: str | None = None
    mode: int | None = None
    stratum: int | None = None
    ref_id: str | None = None
    leap: int | None = None
    precision: int | None = None
    ref_time: str | None = None
    transmit_time: str | None = None