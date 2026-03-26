import time
import random
import threading

# Faux fichiers injectés dans le leurre pour piéger l'attaquant
POISON_FILES = [
    {"name": "patients_2024_full.sql",     "size": "847 MB", "type": "Base de données patients"},
    {"name": "admin_credentials.json",      "size": "2 KB",   "type": "Identifiants administrateur"},
    {"name": "backup_keys.tar.gz",          "size": "124 MB", "type": "Clés de chiffrement"},
    {"name": "network_topology.pdf",        "size": "3 MB",   "type": "Cartographie réseau interne"},
    {"name": "staff_directory_2024.xlsx",   "size": "1.2 MB", "type": "Répertoire du personnel"},
]

# Règles de blocage générées selon les techniques MITRE détectées
BLOCKING_RULES = {
    "T1083": {"rule": "DENY inbound file listing from 10.0.0.99/32",         "vector": "Exploration fichiers"},
    "T1003": {"rule": "DENY /etc/passwd read access — IP externe bloquée",   "vector": "Dump credentials"},
    "T1105": {"rule": "DENY outbound HTTP depuis zone DMZ vers 10.0.0.0/8",  "vector": "Transfert d'outils"},
    "T1222": {"rule": "DENY chmod/chown depuis sessions non-root",           "vector": "Modification permissions"},
    "T1005": {"rule": "DENY mysqldump depuis connexion non-localhost",        "vector": "Extraction données"},
    "T1048": {"rule": "DENY SCP/SFTP sortant vers IP non whitelistée",       "vector": "Exfiltration"},
    "T1053": {"rule": "DENY crontab write depuis utilisateur non-système",   "vector": "Persistance"},
}

# Phases de dégradation progressive du leurre
DEGRADATION_PHASES = [
    {"delay": 2,  "msg": "Latence réseau artificiellement augmentée (+800ms)",     "level": 25},
    {"delay": 4,  "msg": "Timeouts aléatoires injectés sur les connexions DB",     "level": 50},
    {"delay": 6,  "msg": "Fichiers corrompus — checksum invalide retourné",        "level": 75},
    {"delay": 8,  "msg": "Session TCP dégradée — paquets dropping à 40%",         "level": 90},
    {"delay": 10, "msg": "Déconnexion silencieuse — session expirée naturellement","level": 100},
]


class NeutralizationEngine:
    def __init__(self, on_event_callback):
        self.on_event = on_event_callback
        self.active = False
        self.complete = False
        self._thread = None

    def activate(self, techniques_seen):
        if self.active:
            return
        self.active = True
        self._thread = threading.Thread(
            target=self._run_sequence,
            args=(techniques_seen,),
            daemon=True
        )
        self._thread.start()

    def _run_sequence(self, techniques_seen):
        # ── PHASE 1 : Empoisonnement du leurre ───────────────────────────────
        self.on_event({
            "type": "neutralization_phase",
            "phase": "PHASE 1",
            "title": "Empoisonnement du leurre",
            "description": "Injection de fausses données stratégiques pour occuper l'attaquant",
        })
        time.sleep(1.5)

        for f in POISON_FILES:
            self.on_event({
                "type": "poison_file",
                "name": f["name"],
                "size": f["size"],
                "file_type": f["type"],
            })
            time.sleep(random.uniform(0.6, 1.2))

        # ── PHASE 2 : Inoculation du système réel ────────────────────────────
        time.sleep(1)
        self.on_event({
            "type": "neutralization_phase",
            "phase": "PHASE 2",
            "title": "Inoculation — Génération des anticorps",
            "description": "Déploiement automatique des règles de blocage ciblées",
        })
        time.sleep(1.5)

        rules_deployed = []
        for tech_id in techniques_seen:
            if tech_id in BLOCKING_RULES:
                rule = BLOCKING_RULES[tech_id]
                rules_deployed.append(rule)
                self.on_event({
                    "type": "blocking_rule",
                    "technique": tech_id,
                    "rule": rule["rule"],
                    "vector": rule["vector"],
                })
                time.sleep(random.uniform(0.8, 1.4))

        self.on_event({
            "type": "rules_deployed",
            "count": len(rules_deployed),
            "message": f"{len(rules_deployed)} règles déployées sur le système réel",
        })

        # ── PHASE 3 : Dégradation et déconnexion ─────────────────────────────
        time.sleep(1)
        self.on_event({
            "type": "neutralization_phase",
            "phase": "PHASE 3",
            "title": "Épuisement & Déconnexion silencieuse",
            "description": "Dégradation progressive du leurre — l'attaquant ne détecte rien",
        })

        for step in DEGRADATION_PHASES:
            time.sleep(step["delay"] * 0.4)
            self.on_event({
                "type": "degradation_step",
                "message": step["msg"],
                "level": step["level"],
            })

        # ── CONCLUSION ────────────────────────────────────────────────────────
        time.sleep(1)
        self.complete = True
        self.on_event({
            "type": "neutralization_complete",
            "message": "Attaquant neutralisé — Système réel sécurisé — Aucune donnée compromise",
            "rules_count": len(rules_deployed),
            "poison_files": len(POISON_FILES),
        })