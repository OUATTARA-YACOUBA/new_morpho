import random
import time
import threading

# Known hospital devices and their normal behavior
HOSPITAL_DEVICES = {
    "192.168.1.10": "Serveur Dossiers Patients",
    "192.168.1.11": "Serveur Imagerie (IRM)",
    "192.168.1.12": "Monitoring Cardiaque",
    "192.168.1.13": "Pharmacie Automatisée",
    "192.168.1.14": "Poste Médecin A",
    "192.168.1.15": "Poste Médecin B",
    "192.168.1.16": "Poste Infirmier",
    "192.168.1.20": "Routeur Principal",
}

NORMAL_PORTS = [80, 443, 8080, 3000, 5432, 3306]

# Normal traffic patterns: (src, dst, port, bytes, description)
NORMAL_PATTERNS = [
    ("192.168.1.14", "192.168.1.10", 443, lambda: random.randint(500, 2000), "Consultation dossier patient"),
    ("192.168.1.15", "192.168.1.10", 443, lambda: random.randint(500, 2000), "Consultation dossier patient"),
    ("192.168.1.16", "192.168.1.10", 443, lambda: random.randint(300, 800),  "Mise à jour prescriptions"),
    ("192.168.1.14", "192.168.1.11", 8080, lambda: random.randint(5000, 20000), "Accès imagerie IRM"),
    ("192.168.1.12", "192.168.1.10", 3000, lambda: random.randint(100, 300),  "Sync monitoring cardiaque"),
    ("192.168.1.13", "192.168.1.10", 443, lambda: random.randint(200, 600),  "Vérification prescriptions"),
    ("192.168.1.20", "192.168.1.10", 5432, lambda: random.randint(100, 400),  "Backup base données"),
]

# Attack phases
ATTACK_PHASES = [
    {
        "name": "Reconnaissance",
        "description": "Scan des ports et découverte du réseau",
        "events": [
            {"src": "10.0.0.99", "dst": "192.168.1.10", "port": 22,   "bytes": 60,  "label": "Scan SSH"},
            {"src": "10.0.0.99", "dst": "192.168.1.10", "port": 3389, "bytes": 60,  "label": "Scan RDP"},
            {"src": "10.0.0.99", "dst": "192.168.1.11", "port": 21,   "bytes": 60,  "label": "Scan FTP"},
            {"src": "10.0.0.99", "dst": "192.168.1.13", "port": 23,   "bytes": 60,  "label": "Scan Telnet"},
            {"src": "10.0.0.99", "dst": "192.168.1.12", "port": 445,  "bytes": 60,  "label": "Scan SMB"},
        ]
    },
    {
        "name": "Intrusion",
        "description": "Tentative d'accès aux dossiers patients",
        "events": [
            {"src": "10.0.0.99", "dst": "192.168.1.10", "port": 443, "bytes": 8500,  "label": "Brute-force login"},
            {"src": "10.0.0.99", "dst": "192.168.1.10", "port": 443, "bytes": 12000, "label": "Injection SQL"},
            {"src": "10.0.0.99", "dst": "192.168.1.10", "port": 5432, "bytes": 3000, "label": "Accès DB direct"},
        ]
    },
    {
        "name": "Exfiltration",
        "description": "Tentative de vol de données",
        "events": [
            {"src": "10.0.0.99", "dst": "192.168.1.10", "port": 443, "bytes": 95000, "label": "Exfiltration massive"},
            {"src": "10.0.0.99", "dst": "192.168.1.11", "port": 8080, "bytes": 45000, "label": "Vol images médicales"},
        ]
    }
]


class NetworkSimulator:
    def __init__(self, on_event_callback):
        self.on_event = on_event_callback
        self.running = False
        self.attack_active = False
        self.honeypot_active = False
        self._thread = None
        self._attack_thread = None

    def _make_normal_event(self):
        pattern = random.choice(NORMAL_PATTERNS)
        src, dst, port, bytes_fn, desc = pattern
        return {
            "type": "normal",
            "src": src,
            "dst": dst,
            "port": port,
            "bytes": bytes_fn(),
            "label": desc,
            "src_name": HOSPITAL_DEVICES.get(src, src),
            "dst_name": HOSPITAL_DEVICES.get(dst, dst),
        }

    def _normal_traffic_loop(self):
        while self.running:
            event = self._make_normal_event()
            self.on_event(event)
            time.sleep(1.0)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._normal_traffic_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def launch_attack(self):
        if self.attack_active:
            return
        self.attack_active = True
        self._attack_thread = threading.Thread(target=self._attack_sequence, daemon=True)
        self._attack_thread.start()

    def _attack_sequence(self):
        for phase in ATTACK_PHASES:
            if not self.attack_active:
                break
            # Signal phase start
            self.on_event({
                "type": "attack_phase",
                "phase": phase["name"],
                "description": phase["description"],
            })
            for ev in phase["events"]:
                if not self.attack_active:
                    break
                event = dict(ev)
                event["type"] = "attack"
                event["src_name"] = "Attaquant Externe"
                event["dst_name"] = HOSPITAL_DEVICES.get(ev["dst"], ev["dst"])
                # If honeypot active, redirect to honeypot
                if self.honeypot_active:
                    event["type"] = "honeypot_traffic"
                    event["dst"] = "192.168.99.1"
                    event["dst_name"] = "Honeypot [Leurre]"
                self.on_event(event)
                time.sleep(random.uniform(0.6, 1.4))
            time.sleep(1.5)