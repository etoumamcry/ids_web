"""
MODULE 2 — Analyseur d'événements (démon)

Surveille en continu le dossier events/ pour de nouveaux événements.
Pour chaque événement, compare aux règles de la politique de sécurité.
Si au moins une règle est violée → crée une Intrusion + notifie le Module 4.

Règle de détection :
  Un événement constitue une intrusion si AUCUNE règle de la politique
  n'autorise l'accès (user, resource, task, date). Défaut : tout refuser.

Types de violations :
  1. Utilisateur inconnu de la politique
  2. Tâche/ressource non autorisée pour cet utilisateur
  3. Date d'exécution hors de la plage autorisée
"""

import os
import sys
import json
import time
import threading
from datetime import datetime

BASE_DIR   = os.path.dirname(os.path.dirname(__file__))
EVENTS_DIR = os.path.join(BASE_DIR, 'events')
CURSOR_FILE = os.path.join(BASE_DIR, '.events_cursor.json')

status = {
    'running':    False,
    'analyzed':   0,
    'intrusions': 0,
    'last_check': None,
    'errors':     [],
}

# Queue partagée avec le Module 4
_alert_queue = None


def _load_cursor() -> dict:
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_cursor(cursor: dict):
    with open(CURSOR_FILE, 'w') as f:
        json.dump(cursor, f)


def _load_policy(app):
    """Charge la politique depuis la DB (AccessPolicy)."""
    with app.app_context():
        from models import AccessPolicy
        policies = AccessPolicy.query.filter_by(active=True).all()
        return [
            {
                'username':   p.user.username,
                'resource':   p.resource.name,
                'task':       p.task,
                'start_date': p.start_date,
                'end_date':   p.end_date,
            }
            for p in policies
        ]


def _check_event(event: dict, policies: list) -> dict | None:
    """
    Vérifie si un événement viole la politique.
    Retourne un dict de violation ou None si l'accès est autorisé.
    """
    username = event.get('username', '')
    resource = event.get('resource', '')
    task     = event.get('task', '')

    try:
        exec_date = datetime.fromisoformat(event.get('execution_date', ''))
    except Exception:
        exec_date = datetime.utcnow()

    # Exclure les IPs réseau et comptes système sans contrôle d'accès
    system_accounts = {'SYSTEM', 'root', 'LOCAL SERVICE', 'NETWORK SERVICE',
                       'daemon', 'nobody', 'www-data', '_apt'}
    if username in system_accounts:
        return None

    # Trouver toutes les règles concernant cet utilisateur
    user_rules = [p for p in policies if p['username'] == username]

    if not user_rules:
        return {
            'type':    'user_unknown',
            'message': f"Utilisateur '{username}' absent de la politique de sécurité",
            'severity': 'critical',
        }

    # Trouver les règles pour (user, resource, task)
    matching_rules = [
        p for p in user_rules
        if p['resource'] == resource and p['task'] == task
    ]

    if not matching_rules:
        return {
            'type':    'unauthorized_access',
            'message': (f"Aucune règle n'autorise '{username}' à effectuer "
                        f"'{task}' sur '{resource}'"),
            'severity': 'critical',
        }

    # Vérifier la plage de dates
    for rule in matching_rules:
        if rule['start_date'] <= exec_date <= rule['end_date']:
            return None  # Accès autorisé

    # Toutes les règles matchantes ont une date invalide
    best = matching_rules[0]
    return {
        'type':    'date_violation',
        'message': (f"Accès de '{username}' hors de la plage autorisée "
                    f"({best['start_date'].date()} → {best['end_date'].date()}) "
                    f"— date d'exécution : {exec_date.date()}"),
        'severity': 'high',
    }


def _process_file(filepath: str, cursor: dict, policies: list, app) -> int:
    """
    Lit les nouvelles lignes d'un fichier JSONL depuis la position du curseur.
    Retourne le nombre de nouvelles intrusions détectées.
    """
    fname = os.path.basename(filepath)
    pos   = cursor.get(fname, 0)
    intrusions = 0

    try:
        size = os.path.getsize(filepath)
        if size <= pos:
            return 0

        with open(filepath, encoding='utf-8', errors='replace') as f:
            f.seek(pos)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                status['analyzed'] += 1
                violation = _check_event(event, policies)

                if violation:
                    _record_intrusion(event, violation, app)
                    intrusions += 1
                    status['intrusions'] += 1

        cursor[fname] = size

    except Exception as e:
        status['errors'].append(f'Analyzer [{fname}]: {e}')

    return intrusions


def _record_intrusion(event: dict, violation: dict, app):
    """Crée une Intrusion en DB et notifie le Module 4."""
    with app.app_context():
        from models import db, EventFile, EventEntry, Intrusion

        # Récupérer ou créer le fichier d'événements du jour
        today = f"Live_{datetime.utcnow().strftime('%Y-%m-%d')}"
        ef = EventFile.query.filter_by(name=today).first()
        if not ef:
            num = (EventFile.query.count() or 0) + 1
            ef  = EventFile(file_number=num, name=today)
            db.session.add(ef)
            db.session.flush()

        # Créer l'entrée d'événement
        try:
            exec_date = datetime.fromisoformat(event.get('execution_date', ''))
        except Exception:
            exec_date = datetime.utcnow()

        entry = EventEntry(
            file_id=ef.id,
            username=event.get('username', 'unknown'),
            resource_name=event.get('resource', 'unknown'),
            task=event.get('task', 'unknown'),
            execution_date=exec_date,
        )
        db.session.add(entry)
        db.session.flush()

        # Créer l'intrusion
        intrusion = Intrusion(
            entry_id=entry.id,
            violation_type=violation['message'],
        )
        db.session.add(intrusion)
        db.session.commit()

        # Notifier le Module 4
        if _alert_queue is not None:
            _alert_queue.put({
                'intrusion_id':  intrusion.id,
                'event':         event,
                'violation':     violation,
                'detected_at':   datetime.utcnow().isoformat(),
            })


class EventAnalyzer(threading.Thread):
    """Démon qui surveille events/ et analyse chaque nouveau fichier."""

    def __init__(self, app, alert_queue):
        super().__init__(daemon=True, name='EventAnalyzer')
        self.app   = app
        global _alert_queue
        _alert_queue = alert_queue

    def run(self):
        cursor   = _load_cursor()
        last_policy_reload = 0
        policies = []

        status['running'] = True
        print('[MODULE 2] Analyseur démarré', file=sys.stderr)

        while True:
            # Recharger la politique toutes les 30 secondes
            if time.time() - last_policy_reload > 30:
                try:
                    policies = _load_policy(self.app)
                    last_policy_reload = time.time()
                except Exception as e:
                    status['errors'].append(f'Policy reload: {e}')

            # Scanner les fichiers JSONL du jour
            if os.path.isdir(EVENTS_DIR):
                for fname in sorted(os.listdir(EVENTS_DIR)):
                    if fname.endswith('.jsonl'):
                        fpath = os.path.join(EVENTS_DIR, fname)
                        _process_file(fpath, cursor, policies, self.app)

            _save_cursor(cursor)
            status['last_check'] = datetime.utcnow().strftime('%H:%M:%S')
            time.sleep(3)


def start(app, alert_queue):
    """Démarre l'analyseur d'événements."""
    os.makedirs(EVENTS_DIR, exist_ok=True)
    EventAnalyzer(app, alert_queue).start()
