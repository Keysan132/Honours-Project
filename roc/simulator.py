from __future__ import annotations
import math
import random
import time
from typing import Dict, Tuple

from .models import NetEvent, Telemetry

ATTACKS = ["NONE", "GPS_SPOOF", "TAMPER", "REPLAY", "DOS"]

def now_ts() -> float:
    return time.time()

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(x, hi))

def move_point(lat: float, lon: float, speed_knots: float, heading_degrees: float, dt_s: float) -> Tuple[float, float]:
    # Converting speed from knots to m/s
    speed_mps = speed_knots * 0.514444
    # Calculate the distance traveled in meters
    distance_m = speed_mps * dt_s
    # Convert heading to radians
    heading_rad = math.radians(heading_degrees)
    # Calculating position change 
    delta_lat = (distance_m * math.cos(heading_rad)) / 111_320.0  # Approximate conversion to degrees latitude
    delta_lon = (distance_m * math.sin(heading_rad)) / (111_320.0 * math.cos(math.radians(lat) + 1e-9))  # Approximate conversion to degrees longitude
    return lat + delta_lat, lon + delta_lon

def init_fleet(n: int = 6):
    base_lat = 57.1531
    base_lon = -2.0782

    fleet= {}
    for i in range(n):
        vid = f"V{(i+1):03d}"
        fleet[vid] = {
            "lat": base_lat,
            "lon": base_lon,
            "speed_knots": 10.0,
            "heading_deg": 90.0,
            "link_quality": 90.0,
            "autonomy_mode": "AUTO",
            "health": "OK",
            "attack_mode": "NONE",
            "attack_until": 0.0,
            "status": "NORMAL",
            "scores": {
                "spoof": 0.0,
                "dos": 0.0,
                "tamper": 0.0,
                "replay": 0.0
            },
            "nonce": 0
        }
    return fleet

def set_attack(fleet: Dict[str, dict], vessel_id: str, attack: str, duration_s: int =30 ) -> None:
    if attack not in ATTACKS:
        return
    fleet[vessel_id]["attack_mode"] = attack
    fleet[vessel_id]["attack_until"] = now_ts() + duration_s

def current_attack(fleet, vessel_id):
    if "attack_mode" not in fleet[vessel_id]:
        fleet[vessel_id]["attack_mode"] = "NONE"

    if "attack_until" not in fleet[vessel_id]:
        fleet[vessel_id]["attack_until"] = 0.0

    mode = fleet[vessel_id]["attack_mode"]
    until = fleet[vessel_id]["attack_until"]

    if mode != "NONE" and now_ts() > until:
        fleet[vessel_id]["attack_mode"] = "NONE"
        return "NONE"

    return mode

def gen_telemetry(fleet: Dict[str, dict], vessel_id: str, dt_s: float) -> Telemetry:
    s = fleet[vessel_id]
    attack = current_attack(fleet, vessel_id)

    # baseline drift
    s["heading_deg"] = (s["heading_deg"] + random.uniform(-2.5, 2.5)) % 360
    s["speed_knots"] = clamp(s["speed_knots"] + random.uniform(-0.3, 0.3), 0.0, 22.0)

    # move truth
    s["lat"], s["lon"] = move_point(s["lat"], s["lon"], s["heading_deg"], s["speed_knots"], dt_s)
    s["link_quality"] = clamp(s["link_quality"] + random.uniform(-1.3, 1.3), 0, 100)

    rep_lat, rep_lon = s["lat"], s["lon"]
    rep_speed = s["speed_knots"]
    rep_heading = s["heading_deg"]
    link = s["link_quality"]

    if attack == "GPS_SPOOF":
        if random.random() < 0.25:
            rep_lat += random.uniform(0.15, 0.35)
            rep_lon += random.uniform(0.15, 0.35)

    if attack == "DOS":
        link = clamp(link - random.uniform(10, 25), 0, 100)

    if attack == "TAMPER":
        if random.random() < 0.30:
            rep_speed = rep_speed * random.uniform(1.8, 3.2)
        if random.random() < 0.20:
            rep_heading = (rep_heading + random.uniform(90, 180)) % 360

    health = "OK"
    if link < 35:
        health = "WARN"

    return Telemetry(
        ts=now_ts(),
        vessel_id=vessel_id,
        lat=rep_lat,
        lon=rep_lon,
        speed_knots=rep_speed,
        heading_deg=rep_heading,
        link_quality=link,
        autonomy_mode=s["autonomy_mode"],
        health=health,
    )

def gen_network_event(fleet: Dict[str, dict], vessel_id: str) -> NetEvent:
    s = fleet[vessel_id]
    attack = current_attack(fleet, vessel_id)

    msg_type = random.choices(["telemetry", "heartbeat", "command"], weights=[0.55, 0.35, 0.10])[0]
    latency = random.uniform(80, 180)
    dropped = False
    auth_ok = True
    checksum_ok = True
    src = "vessel"
    size = int(random.uniform(220, 1400))

    # Increment nonce normally
    s["nonce"] += 1
    nonce = s["nonce"]

    if attack == "DOS":
        latency *= random.uniform(2.0, 5.0)
        dropped = random.random() < 0.35

    if attack == "TAMPER":
        if random.random() < 0.25:
            checksum_ok = False
        if random.random() < 0.12:
            auth_ok = False
        if random.random() < 0.10:
            src = "unknown"

    if attack == "REPLAY":
        # repeat old nonce sometimes to simulate replay
        if random.random() < 0.35:
            nonce = max(0, nonce - random.randint(5, 25))

    return NetEvent(
        ts=now_ts(),
        vessel_id=vessel_id,
        msg_type=msg_type,
        latency_ms=latency,
        dropped=dropped,
        auth_ok=auth_ok,
        checksum_ok=checksum_ok,
        src=src,
        size_bytes=size,
        nonce=nonce,
    )