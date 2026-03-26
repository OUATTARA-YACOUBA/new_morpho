import threading
import time
import os
from flask import Flask, render_template
from flask_socketio import SocketIO
from simulator import NetworkSimulator
from detector import AnomalyDetector
from honeypot import Honeypot
from neutralizer import NeutralizationEngine

app = Flask(__name__)
app.config["SECRET_KEY"] = "morphoshield-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

state = {
    "running": False, "attack_launched": False,
    "honeypot_active": False, "system_isolated": False,
    "neutralization_active": False, "neutralization_complete": False,
    "events": [], "attack_events": [], "honeypot_logs": [],
    "neutralization_logs": [], "alerts": [],
    "attacker_profile": None, "detector_status": {},
    "normal_count": 0, "attack_count": 0,
}

def handle_network_event(event):
    etype = event.get("type")
    if etype == "normal":
        state["normal_count"] += 1
        score, is_anomaly = detector.feed(event)
        event["score"] = score; event["anomaly"] = is_anomaly
        state["events"].append(event)
        if len(state["events"]) > 200: state["events"] = state["events"][-200:]
        socketio.emit("network_event", event)
    elif etype == "attack":
        state["attack_count"] += 1
        score, is_anomaly = detector.feed(event)
        event["score"] = score; event["anomaly"] = is_anomaly
        state["attack_events"].append(event)
        socketio.emit("attack_event", event)
        if is_anomaly and not state["honeypot_active"]:
            trigger_response(event)
    elif etype == "honeypot_traffic":
        state["attack_count"] += 1
        socketio.emit("honeypot_traffic", event)
    elif etype == "attack_phase":
        socketio.emit("attack_phase", event)
    elif etype == "honeypot_activated":
        socketio.emit("honeypot_activated", event)
    elif etype == "honeypot_log":
        state["honeypot_logs"].append(event)
        socketio.emit("honeypot_log", event)
    elif etype == "attacker_profile":
        state["attacker_profile"] = event
        socketio.emit("attacker_profile", event)
        # Auto-trigger neutralization after profile is built
        threading.Thread(target=_delayed_neutralization, daemon=True).start()
    # Neutralization events
    elif etype in ("neutralization_phase", "poison_file", "blocking_rule",
                   "rules_deployed", "degradation_step", "neutralization_complete"):
        state["neutralization_logs"].append(event)
        if etype == "neutralization_complete":
            state["neutralization_complete"] = True
        socketio.emit(etype, event)

def _delayed_neutralization():
    time.sleep(2)
    if not state["neutralization_active"]:
        state["neutralization_active"] = True
        techniques = [t["id"] for t in (state["attacker_profile"] or {}).get("techniques", [])]
        neutralizer.activate(techniques)

def handle_alert(alert):
    state["alerts"].append(alert)
    socketio.emit("alert", alert)

def trigger_response(triggering_event):
    state["honeypot_active"] = True; state["system_isolated"] = True
    simulator.honeypot_active = True
    socketio.emit("system_isolated", {"message": "Système réel isolé — Trafic suspect bloqué", "trigger": triggering_event})
    honeypot.activate()

detector    = AnomalyDetector(on_alert_callback=handle_alert)
honeypot    = Honeypot(on_event_callback=handle_network_event)
simulator   = NetworkSimulator(on_event_callback=handle_network_event)
neutralizer = NeutralizationEngine(on_event_callback=handle_network_event)

@socketio.on("connect")
def on_connect(**kwargs):
    socketio.emit("state_sync", {
        "running": state["running"], "attack_launched": state["attack_launched"],
        "honeypot_active": state["honeypot_active"], "system_isolated": state["system_isolated"],
        "neutralization_active": state["neutralization_active"],
        "neutralization_complete": state["neutralization_complete"],
        "normal_count": state["normal_count"], "attack_count": state["attack_count"],
        "alerts": state["alerts"], "honeypot_logs": state["honeypot_logs"],
        "neutralization_logs": state["neutralization_logs"],
        "attacker_profile": state["attacker_profile"],
        "detector_status": detector.get_status(),
    })

@socketio.on("start_simulation")
def on_start():
    if not state["running"]:
        state["running"] = True
        simulator.start()
        socketio.emit("simulation_started", {"message": "Simulation démarrée — Apprentissage de la baseline en cours..."})
        def notify_baseline_ready():
            while not detector.is_trained: time.sleep(1)
            socketio.emit("baseline_ready", {"message": "Baseline apprise — Vous pouvez déclencher l'attaque."})
        threading.Thread(target=notify_baseline_ready, daemon=True).start()

@socketio.on("manual_attack")
def on_manual_attack():
    if state["running"] and not state["attack_launched"]:
        state["attack_launched"] = True
        simulator.launch_attack()
        socketio.emit("attack_incoming", {"message": "Attaque lancée manuellement..."})

@socketio.on("reset")
def on_reset():
    global detector, honeypot, simulator, neutralizer, state
    simulator.stop(); honeypot.deactivate()
    state = {
        "running": False, "attack_launched": False,
        "honeypot_active": False, "system_isolated": False,
        "neutralization_active": False, "neutralization_complete": False,
        "events": [], "attack_events": [], "honeypot_logs": [],
        "neutralization_logs": [], "alerts": [],
        "attacker_profile": None, "detector_status": {},
        "normal_count": 0, "attack_count": 0,
    }
    detector    = AnomalyDetector(on_alert_callback=handle_alert)
    honeypot    = Honeypot(on_event_callback=handle_network_event)
    simulator   = NetworkSimulator(on_event_callback=handle_network_event)
    neutralizer = NeutralizationEngine(on_event_callback=handle_network_event)
    socketio.emit("reset_done", {})

@socketio.on("get_detector_status")
def on_detector_status():
    socketio.emit("detector_status", detector.get_status())

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)