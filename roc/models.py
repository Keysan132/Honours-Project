from dataclasses import dataclass
from typing import Literal

Mode = Literal["AUTO", "REMOTE", "HOLD"]
Health = Literal["OK", "WARN", "FAIL"]

AlertType = Literal["GPS_SPOOF", "DOS", "TAMPER", "REPLAY"]
Severity = Literal["LOW", "MED", "HIGH"]
Status = Literal["NORMAL", "SUSPICIOUS", "UNDER_ATTACK"]

MsgType = Literal["telemetry", "heartbeat", "command"]
Source = Literal["vessel", "roc", "unknown"]


@dataclass
class Telemetry:
    ts: float
    vessel_id: str
    lat: float
    lon: float
    speed_knots: float
    heading_deg: float
    link_quality: float
    autonomy_mode: Mode
    health: Health


@dataclass
class NetEvent:
    ts: float
    vessel_id: str
    msg_type: MsgType
    latency_ms: float
    dropped: bool
    auth_ok: bool
    checksum_ok: bool
    src: Source
    size_bytes: int
    nonce: int


@dataclass
class Alert:
    ts: float
    vessel_id: str
    alert_type: AlertType
    severity: Severity
    description: str