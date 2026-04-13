from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict

from .models import Alert, NetEvent, Telemetry


@dataclass
class VesselRuntime:
    telemetry_hist: Deque[Telemetry]
    net_hist: Deque[NetEvent]
    last_nonce_seen: int
    last_alert_ts: Dict[str, float]


@dataclass
class AppState:
    fleet: Dict[str, dict]
    runtime: Dict[str, VesselRuntime]
    alerts: list
    selected: str
    last_tick: float


def make_runtime(vessel_ids):
    return {
        vid: VesselRuntime(
            telemetry_hist=deque(maxlen=180),
            net_hist=deque(maxlen=360),
            last_nonce_seen=-1,
            last_alert_ts={
                "GPS_SPOOF": 0.0,
                "DOS": 0.0,
                "TAMPER": 0.0,
                "REPLAY": 0.0,
            },
        )
        for vid in vessel_ids
    }