from collections import deque
import time

from roc.detector import detect
from roc.models import NetEvent, Telemetry


def test_replay_detection_trips_when_nonce_goes_backwards():
    vid = "V001"
    now = time.time()

    tel_hist = deque(maxlen=10)
    tel_hist.append(Telemetry(now, vid, 57.1, -2.1, 10, 90, 90, "AUTO", "OK"))
    tel_hist.append(Telemetry(now + 1, vid, 57.1001, -2.0999, 10, 90, 90, "AUTO", "OK"))

    net_hist = deque(maxlen=50)
    # increasing nonces
    for i in range(10):
        net_hist.append(NetEvent(now + i, vid, "telemetry", 120, False, True, True, "vessel", 500, nonce=i))

    # introduce replay
    for i in range(10, 20):
        n = i
        if i % 3 == 0:
            n = 5  # old nonce
        net_hist.append(NetEvent(now + i, vid, "telemetry", 120, False, True, True, "vessel", 500, nonce=n))

    status, scores, last_nonce, alerts = detect(vid, tel_hist, net_hist, last_nonce_seen=9, now=now + 21)
    assert scores["replay"] >= 40
    assert any(a.alert_type == "REPLAY" for a in alerts)