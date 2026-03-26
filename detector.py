import numpy as np
from sklearn.ensemble import IsolationForest
from collections import deque
import threading

class AnomalyDetector:
    """
    Learns normal hospital network behavior and detects anomalies in real time.
    Uses Isolation Forest — no attack signatures needed, works on Zero-Day threats.
    """

    def __init__(self, on_alert_callback, contamination=0.05):
        self.on_alert = on_alert_callback
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42
        )
        self.baseline_data = []
        self.is_trained = False
        self.min_samples = 30          # train after 30 normal events
        self.score_history = deque(maxlen=100)
        self.alert_threshold = -0.15   # below this = anomaly
        self.lock = threading.Lock()
        self.alerted = False           # avoid duplicate alerts

    def _extract_features(self, event):
        """Convert a network event into a numeric feature vector."""
        # Feature 1: port number (normalized)
        port = event.get("port", 80) / 65535.0
        # Feature 2: bytes transferred (log-normalized)
        raw_bytes = event.get("bytes", 100)
        log_bytes = np.log1p(raw_bytes) / 15.0
        # Feature 3: is source internal? (1 = internal, 0 = external)
        src = event.get("src", "")
        is_internal = 1.0 if src.startswith("192.168.") else 0.0
        # Feature 4: destination server index
        dst_map = {
            "192.168.1.10": 0.1,
            "192.168.1.11": 0.2,
            "192.168.1.12": 0.3,
            "192.168.1.13": 0.4,
            "192.168.1.14": 0.5,
            "192.168.1.15": 0.6,
            "192.168.1.16": 0.7,
            "192.168.1.20": 0.8,
        }
        dst_idx = dst_map.get(event.get("dst", ""), 0.9)
        # Feature 5: port category (known=0, suspicious=1)
        known_ports = {80, 443, 8080, 3000, 5432, 3306}
        port_suspicious = 0.0 if event.get("port", 80) in known_ports else 1.0

        return [port, log_bytes, is_internal, dst_idx, port_suspicious]

    def feed(self, event):
        """Feed an event. Returns (score, is_anomaly)."""
        if event.get("type") not in ("normal", "attack", "honeypot_traffic"):
            return None, False

        features = self._extract_features(event)

        with self.lock:
            if not self.is_trained:
                self.baseline_data.append(features)
                if len(self.baseline_data) >= self.min_samples:
                    self._train()
                return None, False

            score = float(self.model.score_samples([features])[0])
            self.score_history.append(score)
            is_anomaly = bool(score < self.alert_threshold)

            if is_anomaly and not self.alerted and event.get("type") == "attack":
                self.alerted = True
                self.on_alert({
                    "score": round(float(score), 4),
                    "event": event,
                    "message": f"Anomalie détectée — Score: {score:.3f} | Source: {event.get('src')} → {event.get('dst_name')} port {event.get('port')}"
                })

            return round(score, 4), is_anomaly

    def _train(self):
        X = np.array(self.baseline_data)
        self.model.fit(X)
        self.is_trained = True

    def get_status(self):
        with self.lock:
            return {
                "trained": self.is_trained,
                "baseline_size": len(self.baseline_data),
                "min_samples": self.min_samples,
                "recent_scores": [round(float(s), 4) for s in list(self.score_history)[-20:]],
            }