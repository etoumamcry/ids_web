"""
MODULE 4 — Générateur d'alertes (démon)

Reçoit les intrusions depuis le Module 2 via une file thread-safe,
génère des alertes détaillées et les distribue vers :
  - La base de données (modèle Alert)
  - Le fichier log alerts/YYYY-MM-DD.log
  - (Optionnel) Email SMTP si configuré dans ids_config.json

Format d'alerte :
  ═══════════════════════════════════════════════════════
  [CRITIQUE] 2026-05-22 10:30:00 UTC
  ───────────────────────────────────────────────────────
  Intrusion détectée
  Utilisateur  : alice
  Ressource    : database
  Tâche        : execute
  Date accès   : 2026-05-22 10:30:00
  Source       : /var/log/auth.log
  ───────────────────────────────────────────────────────
  Violation    : Tâche 'execute' non autorisée sur 'database' pour 'alice'
  Détails      : Aucune règle de la politique ne permet cet accès
  ═══════════════════════════════════════════════════════
"""

import os
import sys
import time
import queue
import threading
import smtplib
from datetime import datetime
from email.mime.text import MIMEText

BASE_DIR   = os.path.dirname(os.path.dirname(__file__))
ALERTS_DIR = os.path.join(BASE_DIR, 'alerts')
CONFIG_FILE = os.path.join(BASE_DIR, 'ids_config.json')

status = {
    'running':        False,
    'alerts_sent':    0,
    'queue_size':     0,
    'last_alert':     None,
    'errors':         [],
}

SEVERITY_LABELS = {
    'critical': 'CRITIQUE',
    'high':     'HAUTE',
    'medium':   'MOYENNE',
    'low':      'FAIBLE',
}


# ── Formatage de l'alerte ────────────────────────────────────────────────────

def _format_alert(data: dict) -> str:
    event     = data.get('event', {})
    violation = data.get('violation', {})
    ts        = data.get('detected_at', datetime.utcnow().isoformat())

    severity_label = SEVERITY_LABELS.get(violation.get('severity', 'high'), 'HAUTE')

    return (
        f"\n{'═'*55}\n"
        f"[{severity_label}] {ts[:19].replace('T', ' ')} UTC\n"
        f"{'─'*55}\n"
        f"INTRUSION DÉTECTÉE\n"
        f"  Utilisateur : {event.get('username', '?')}\n"
        f"  Ressource   : {event.get('resource', '?')}\n"
        f"  Tâche       : {event.get('task', '?')}\n"
        f"  Date accès  : {event.get('execution_date', '?')[:19].replace('T',' ')}\n"
        f"  Source      : {event.get('source', '?')}\n"
        f"{'─'*55}\n"
        f"  Violation   : {violation.get('message', '?')}\n"
        f"  Type        : {violation.get('type', '?')}\n"
        f"  Ligne brute : {event.get('raw', '')[:100]}\n"
        f"{'═'*55}\n"
    )


# ── Écriture dans le fichier log ─────────────────────────────────────────────

_file_lock = threading.Lock()

def _write_alert_log(text: str):
    os.makedirs(ALERTS_DIR, exist_ok=True)
    day_file = os.path.join(ALERTS_DIR, datetime.utcnow().strftime('%Y-%m-%d') + '.log')
    with _file_lock:
        with open(day_file, 'a', encoding='utf-8') as f:
            f.write(text)


# ── Enregistrement en DB ─────────────────────────────────────────────────────

def _save_to_db(data: dict, app):
    with app.app_context():
        from models import db, Alert, Intrusion
        violation = data.get('violation', {})
        event     = data.get('event', {})

        intrusion_id = data.get('intrusion_id')

        alert = Alert(
            message=(
                f"[IDS] {event.get('username','?')} | "
                f"{event.get('task','?')} sur {event.get('resource','?')} | "
                f"{violation.get('message','?')}"
            ),
            severity=violation.get('severity', 'high'),
        )
        db.session.add(alert)
        db.session.commit()


# ── Envoi email (optionnel) ──────────────────────────────────────────────────

def _load_smtp_config() -> dict:
    import json
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
            return cfg.get('smtp', {})
    except Exception:
        return {}


def _send_email(subject: str, body: str, cfg: dict):
    try:
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From']    = cfg['from']
        msg['To']      = cfg['to']

        with smtplib.SMTP(cfg['host'], cfg.get('port', 587), timeout=10) as smtp:
            if cfg.get('tls', True):
                smtp.starttls()
            if cfg.get('user') and cfg.get('password'):
                smtp.login(cfg['user'], cfg['password'])
            smtp.send_message(msg)
    except Exception as e:
        status['errors'].append(f'Email: {e}')


# ── Démon principal ──────────────────────────────────────────────────────────

class AlertDaemon(threading.Thread):
    """Consomme la file d'alertes et distribue vers tous les canaux."""

    def __init__(self, app, alert_queue: queue.Queue):
        super().__init__(daemon=True, name='AlertDaemon')
        self.app   = app
        self.queue = alert_queue
        self._smtp_config = {}

    def run(self):
        status['running'] = True
        self._smtp_config = _load_smtp_config()
        print('[MODULE 4] Générateur d\'alertes démarré', file=sys.stderr)

        while True:
            status['queue_size'] = self.queue.qsize()

            try:
                data = self.queue.get(timeout=2)
            except queue.Empty:
                continue

            try:
                alert_text = _format_alert(data)

                # 1. Fichier log
                _write_alert_log(alert_text)

                # 2. Base de données
                _save_to_db(data, self.app)

                # 3. Email (si configuré)
                if self._smtp_config:
                    event     = data.get('event', {})
                    violation = data.get('violation', {})
                    subject = (
                        f"[IDS ALERTE {violation.get('severity','?').upper()}] "
                        f"{event.get('username','?')} — "
                        f"{event.get('task','?')} sur {event.get('resource','?')}"
                    )
                    _send_email(subject, alert_text, self._smtp_config)

                status['alerts_sent'] += 1
                status['last_alert']  = (
                    f"{data.get('event',{}).get('username','?')} | "
                    f"{data.get('violation',{}).get('type','?')}"
                )

                print(alert_text, file=sys.stderr)

            except Exception as e:
                status['errors'].append(f'AlertDaemon: {e}')

            self.queue.task_done()


def start(app, alert_queue: queue.Queue):
    """Démarre le générateur d'alertes."""
    os.makedirs(ALERTS_DIR, exist_ok=True)
    AlertDaemon(app, alert_queue).start()
