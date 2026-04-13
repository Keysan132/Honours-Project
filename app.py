import time
import pandas as pd
import streamlit as st

from streamlit_autorefresh import st_autorefresh

from roc.detector import detect
from roc.simulator import current_attack, gen_network_event, gen_telemetry, init_fleet, set_attack
from roc.store import AppState, make_runtime


def fmt_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


#Page Config
st.set_page_config(page_title="ROC Fleet Security Dashboard", layout="wide")

st.title("ROC Security Dashboard")
st.caption("Simulated vessel cyber attack detection")

#Sidebar Controls to use to simulate an attack and adjust settings
with st.sidebar:
    st.header("Controls")

    refresh_interval = st.slider(
        "Refresh rate (ms)",
        500, 5000, 1000, step=250
    )

    sim_speed = st.slider(
        "Simulation speed",
        0.5, 5.0, 1.0, step=0.5
    )

    live_mode = st.checkbox("Live Mode", value=True)

    st.divider()

    st.subheader("Attack triggers")
    selected_attack_vessel = st.selectbox("Target vessel", ["V001", "V002", "V003", "V004", "V005", "V006"])
    duration = st.slider("Duration (seconds)", 10, 120, 30)

    c1, c2, c3, c4 = st.columns(4)
    if c1.button("GPS"):
        set_attack(st.session_state.app_state.fleet, selected_attack_vessel, "GPS_SPOOF", duration)
    if c2.button("DoS"):
        set_attack(st.session_state.app_state.fleet, selected_attack_vessel, "DOS", duration)
    if c3.button("Tamper"):
        set_attack(st.session_state.app_state.fleet, selected_attack_vessel, "TAMPER", duration)
    if c4.button("Replay"):
        set_attack(st.session_state.app_state.fleet, selected_attack_vessel, "REPLAY", duration)

    st.divider()

    if st.button("Reset Simulation"):
        fleet = init_fleet(n=6)
        runtime = make_runtime(list(fleet.keys()))

        st.session_state.app_state = AppState(
            fleet=fleet,
            runtime=runtime,
            alerts=[],
            selected=list(fleet.keys())[0],
            last_tick=time.time(),
        )

        st.session_state.alerts = []
        st.rerun()


#Auto Refresh to keep the simulation running and updating the UI
if live_mode:
    st_autorefresh(interval=refresh_interval, key="roc_refresh")


#Initialise State for the fleet, runtime data and alerts
if "app_state" not in st.session_state:
    fleet = init_fleet(n=6)
    runtime = make_runtime(list(fleet.keys()))

    st.session_state.app_state = AppState(
        fleet=fleet,
        runtime=runtime,
        alerts=[],
        selected=list(fleet.keys())[0],
        last_tick=time.time(),
    )

    st.session_state.alerts = []
    st.session_state.alert_cooldown = 4.0


state: AppState = st.session_state.app_state

#Simulation Tick for each vessel to generate telemetry and network events
current_time = time.time()
dt = max(0.05, min((current_time - state.last_tick) * sim_speed, 3.0))
state.last_tick = current_time

for vid in state.fleet.keys():
    tel = gen_telemetry(state.fleet, vid, dt)
    net = gen_network_event(state.fleet, vid)

    runtime = state.runtime[vid]

    runtime.telemetry_hist.append(tel)
    runtime.net_hist.append(net)

    active_attack = current_attack(state.fleet, vid)

    status, scores, new_nonce, alerts = detect(
    vessel_id=vid,
    telemetry_hist=runtime.telemetry_hist,
    net_hist=runtime.net_hist,
    last_nonce_seen=runtime.last_nonce_seen,
    now=current_time,
    active_attack=active_attack,
)

    runtime.last_nonce_seen = new_nonce

    for alert in alerts:
        last = runtime.last_alert_ts.get(alert.alert_type, 0.0)

        if alert.ts - last >= st.session_state.alert_cooldown:
            st.session_state.alerts.insert(0, {
                "time": fmt_ts(alert.ts),
                "vessel": alert.vessel_id,
                "type": alert.alert_type,
                "severity": alert.severity,
                "description": alert.description
            })
            runtime.last_alert_ts[alert.alert_type] = alert.ts

    state.fleet[vid]["status"] = status
    state.fleet[vid]["scores"] = scores
    state.fleet[vid]["link_quality"] = tel.link_quality
    state.fleet[vid]["health"] = tel.health

# UI Helper Functions
def badge(status):
    return {
        "NORMAL": "✅ NORMAL",
        "SUSPICIOUS": "⚠️ SUSPICIOUS",
        "UNDER_ATTACK": "🔴 UNDER ATTACK"
    }.get(status, status)


#Summary Metrics
column1, column2, column3, column4 = st.columns(4)

fleet = state.fleet

column1.metric("Fleet size", len(fleet))
column2.metric("Under attack", sum(1 for v in fleet.values() if v["status"] == "UNDER_ATTACK"))
column3.metric("Suspicious", sum(1 for v in fleet.values() if v["status"] == "SUSPICIOUS"))
column4.metric("Active attacks", sum(1 for v in fleet.values() if v.get("attack_mode", "NONE") != "NONE"))

#Layout for the fleet overview and vessel details sections
left, right = st.columns([0.35, 0.65])


#Fleet Overview for all vessels with key metrics
with left:
    st.subheader("Fleet Overview")

    rows = []
    for vid, v in fleet.items():
        rt = state.runtime[vid]

        last_seen = fmt_ts(rt.telemetry_hist[-1].ts) if rt.telemetry_hist else "-"

        rows.append({
            "Vessel": vid,
            "Status": badge(v["status"]),
            "Mode": v["autonomy_mode"],
            "Health": v["health"],
            "Link": int(v["link_quality"]),
            "Attack": current_attack(fleet, vid),
            "Last seen": last_seen,
        })

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    state.selected = st.selectbox("Inspect vessel", list(fleet.keys()))

    selected = state.selected
    st.markdown(f"### Selected: {selected}")
    st.write("Status:", badge(fleet[selected]["status"]))
    st.write("Scores:", fleet[selected]["scores"])


#Vessel Details to show recent telemetry, network events and map location
with right:
    selected = state.selected
    runtime = state.runtime[selected]

    st.subheader("Vessel Details")

    if runtime.telemetry_hist:
        t = runtime.telemetry_hist[-1]

        col1, col2, col3, col4, col5 = st.columns(5)

        col1.metric("Speed", f"{t.speed_knots:.1f}")
        col2.metric("Heading", f"{t.heading_deg:.0f}")
        col3.metric("Link", f"{t.link_quality:.0f}")
        col4.metric("Lat", f"{t.lat:.4f}")
        col5.metric("Lon", f"{t.lon:.4f}")

        st.map(pd.DataFrame([{"lat": t.lat, "lon": t.lon}]))

    st.subheader("Recent Network Events")

    if runtime.net_hist:
        df = pd.DataFrame([{
            "time": fmt_ts(e.ts),
            "latency": round(e.latency_ms, 1),
            "drop": e.dropped,
            "auth": e.auth_ok,
            "checksum": e.checksum_ok,
            "nonce": e.nonce
        } for e in list(runtime.net_hist)[-30:]])

        st.dataframe(df, use_container_width=True)


#Alerts section to show recent security alerts
st.subheader("Security Alerts")

if st.session_state.alerts:
    st.dataframe(pd.DataFrame(st.session_state.alerts[:100]), use_container_width=True, hide_index=True)
else:
    st.info("No alerts yet — trigger an attack from the sidebar")