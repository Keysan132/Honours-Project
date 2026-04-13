from __future__ import annotations
import math
from typing import Deque, Dict, List, Tuple

from .models import Alert, NetEvent, Telemetry, Status


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def haversine_m(lat1, lon1, lat2, lon2) -> float:
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def detect(
    vessel_id: str,
    telemetry_hist: Deque[Telemetry],
    net_hist: Deque[NetEvent],
    last_nonce_seen: int,
    now: float,
    active_attack: str = "NONE",
) -> Tuple[Status, Dict[str, float], int, List[Alert]]:
    alerts: List[Alert] = []

    #Warm-up period
    if len(telemetry_hist) < 8 or len(net_hist) < 20:
        return "NORMAL", {
            "spoof": 0.0,
            "dos": 0.0,
            "tamper": 0.0,
            "replay": 0.0,
        }, last_nonce_seen, alerts

    spoof_score = 0.0
    dos_score = 0.0
    tamper_score = 0.0
    replay_score = 0.0

    #GPS spoof detection
    t2 = telemetry_hist[-1]
    t1 = telemetry_hist[-2]
    dt = max(0.001, t2.ts - t1.ts)
    dist_m = haversine_m(t1.lat, t1.lon, t2.lat, t2.lon)
    implied_speed_knots = (dist_m / dt) / 0.514444

    if implied_speed_knots > 120:
        spoof_score += 90
    elif implied_speed_knots > 80:
        spoof_score += 55

    if dist_m > 7000:
        spoof_score += 20


    #Network analysis
    recent_net = list(net_hist)[-40:]
    loss_rate = sum(1 for e in recent_net if e.dropped) / len(recent_net)
    avg_latency = sum(e.latency_ms for e in recent_net) / len(recent_net)
    bad_checksum = sum(1 for e in recent_net if not e.checksum_ok) / len(recent_net)
    bad_auth = sum(1 for e in recent_net if not e.auth_ok) / len(recent_net)
    unknown_src = sum(1 for e in recent_net if e.src == "unknown") / len(recent_net)

    #DoS detection
    if loss_rate > 0.45:
        dos_score += 55
    elif loss_rate > 0.30:
        dos_score += 25

    if avg_latency > 1000:
        dos_score += 35
    elif avg_latency > 700:
        dos += 15

    #heartbeat check
    heartbeat_events = [e for e in recent_net if e.msg_type == "heartbeat" and not e.dropped]
    if len(heartbeat_events) == 0:
        dos_score += 5
    else:
        last_hb = heartbeat_events[-1].ts
        if (now - last_hb) > 12:
            dos_score += 15

    #Tamper detection
    if bad_checksum > 0.20:
        tamper_score += 45
    if bad_auth > 0.12:
        tamper_score += 50
    if unknown_src > 0.12:
        tamper_score += 20

    #Replay detection
    replay_events = 0
    newest_nonce = last_nonce_seen

    for e in recent_net:
        if e.nonce > newest_nonce:
            newest_nonce = e.nonce
        elif last_nonce_seen != -1 and e.nonce < (last_nonce_seen - 8):
            replay_events += 1

    if replay_events >= 4:
        replay_score += min(100, replay_events * 18)

    last_nonce_seen = max(last_nonce_seen, newest_nonce)


    if active_attack == "NONE":
        spoof_score *= 0.15
        dos_score *= 0.20
        tamper_score *= 0.20
        replay_score *= 0.15

    spoof = clamp(spoof_score, 0, 100)
    dos = clamp(dos_score, 0, 100)
    tamper = clamp(tamper_score, 0, 100)
    replay = clamp(replay_score, 0, 100)

    scores: Dict[str, float] = {
        "spoof": spoof,
        "dos": dos,
        "tamper": tamper,
        "replay": replay,
    }

    highest = max(scores.values())

    status: Status = "NORMAL"
    if highest >= 80:
        status = "UNDER_ATTACK"
    elif highest >= 50:
        status = "SUSPICIOUS"

    def add_alert(a_type: str, score: float, high_msg: str, med_msg: str) -> None:
        if score >= 80:
            alerts.append(Alert(now, vessel_id, a_type, "HIGH", high_msg))
        elif score >= 60:
            alerts.append(Alert(now, vessel_id, a_type, "MED", med_msg))

    add_alert("GPS_SPOOF", spoof, "Position anomaly detected", "Navigation behaviour suspicious")
    add_alert("DOS", dos, "Comms degradation consistent with DoS", "Link quality suspicious")
    add_alert("TAMPER", tamper, "Integrity failures detected", "Possible tampering detected")
    add_alert("REPLAY", replay, "Replay behaviour detected", "Possible replay activity detected")

    return status, scores, last_nonce_seen, alerts