"""
MODULE 3 — Gestion de la politique de sécurité (démon)

La politique de sécurité peut être gérée de deux façons :
  1. Via l'interface web (CRUD individuel par règle)
  2. Via le fichier policy.conf (CRUD global, séparateur ;)

Format policy.conf :
  # Commentaire
  username;resource;task;start_date(YYYY-MM-DD);end_date(YYYY-MM-DD);active(1/0)

  Exemple :
    alice;database;read;2026-01-01;2026-12-31;1
    alice;database;write;2026-01-01;2026-12-31;1
    bob;web_server;read;2026-01-01;2026-06-30;1
    bob;ssh_server;login;2026-01-01;2026-12-31;1

Ce module :
  - Charge policy.conf au démarrage et synchronise avec la DB
  - Surveille policy.conf pour tout changement (hot reload)
  - Exporte la politique DB vers policy.conf sur demande
  - Valide le format et signale les erreurs
"""

import os
import sys
import time
import threading
from datetime import datetime

BASE_DIR    = os.path.dirname(os.path.dirname(__file__))
POLICY_FILE = os.path.join(BASE_DIR, 'policy.conf')

def _parse_dt(s: str) -> datetime:
    """Parse YYYY-MM-DD ou YYYY-MM-DD HH:MM (avec heure pour restriction horaire)."""
    s = s.strip()
    for fmt in ['%Y-%m-%d %H:%M', '%Y-%m-%d']:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(f"Format invalide: '{s}' — attendu YYYY-MM-DD ou YYYY-MM-DD HH:MM")


HEADER = """\
# ============================================================
# IDS — Politique de Sécurité
# Format : username;resource;task;start_date;end_date;active
# Dates  : YYYY-MM-DD
# Active : 1=oui, 0=non
# Tâches : read, write, delete, execute, admin, login,
#          failed_login, backup, restore, connect
# ============================================================
"""

status = {
    'running':      False,
    'rules_loaded': 0,
    'last_reload':  None,
    'errors':       [],
    'file_path':    POLICY_FILE,
}


# ── Parsing ─────────────────────────────────────────────────────────────────

def parse_policy_file(path: str) -> list[dict]:
    """
    Lit et valide policy.conf.
    Retourne une liste de règles dict ou lève ValueError.
    """
    rules = []
    errors = []

    if not os.path.exists(path):
        return []

    with open(path, encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(';')
            if len(parts) != 6:
                errors.append(f'Ligne {lineno}: 6 champs attendus, {len(parts)} trouvés — "{line}"')
                continue

            username, resource, task, start_str, end_str, active_str = [p.strip() for p in parts]

            if not all([username, resource, task, start_str, end_str]):
                errors.append(f'Ligne {lineno}: champ vide')
                continue

            try:
                start_date = _parse_dt(start_str)
                end_date   = _parse_dt(end_str)
            except ValueError as e:
                errors.append(f'Ligne {lineno}: {e}')
                continue

            if start_date > end_date:
                errors.append(f'Ligne {lineno}: start_date > end_date')
                continue

            active = active_str not in ('0', 'false', 'False', 'no')

            rules.append({
                'username':   username,
                'resource':   resource,
                'task':       task,
                'start_date': start_date,
                'end_date':   end_date,
                'active':     active,
            })

    if errors:
        status['errors'].extend(errors)

    return rules


# ── Import policy.conf → DB ──────────────────────────────────────────────────

def import_from_file(app, path: str = None, replace: bool = True) -> dict:
    """
    Importe les règles depuis policy.conf vers la DB.
    Si replace=True, remplace toutes les règles existantes.
    Retourne un dict avec les compteurs et erreurs.
    """
    path = path or POLICY_FILE
    result = {'created': 0, 'skipped': 0, 'errors': []}

    rules = parse_policy_file(path)
    if not rules:
        result['errors'].append('Aucune règle valide trouvée dans le fichier')
        return result

    with app.app_context():
        from models import db, IDSUser, Resource, AccessPolicy

        if replace:
            AccessPolicy.query.delete()
            db.session.commit()

        for rule in rules:
            # Trouver ou créer l'utilisateur
            user = IDSUser.query.filter_by(username=rule['username']).first()
            if not user:
                user = IDSUser(username=rule['username'], role='user')
                db.session.add(user)
                db.session.flush()

            # Trouver ou créer la ressource
            res = Resource.query.filter_by(name=rule['resource']).first()
            if not res:
                res = Resource(name=rule['resource'], description=f'Auto-créé depuis policy.conf')
                db.session.add(res)
                db.session.flush()

            # Vérifier doublon si replace=False
            if not replace:
                exists = AccessPolicy.query.filter_by(
                    user_id=user.id, resource_id=res.id, task=rule['task']
                ).first()
                if exists:
                    result['skipped'] += 1
                    continue

            policy = AccessPolicy(
                user_id=user.id,
                resource_id=res.id,
                task=rule['task'],
                start_date=rule['start_date'],
                end_date=rule['end_date'],
                active=rule['active'],
            )
            db.session.add(policy)
            result['created'] += 1

        db.session.commit()

    status['rules_loaded'] = result['created']
    status['last_reload']  = datetime.utcnow().strftime('%H:%M:%S')
    return result


# ── Export DB → policy.conf ──────────────────────────────────────────────────

def export_to_file(app, path: str = None) -> int:
    """
    Exporte les règles de la DB vers policy.conf.
    Retourne le nombre de règles écrites.
    """
    path = path or POLICY_FILE

    with app.app_context():
        from models import AccessPolicy
        policies = AccessPolicy.query.order_by(AccessPolicy.user_id).all()

        lines = [HEADER]
        for p in policies:
            active = '1' if p.active else '0'
            # Inclure l'heure si elle n'est pas minuit (restriction horaire active)
            s_fmt = '%Y-%m-%d %H:%M' if p.start_date.hour or p.start_date.minute else '%Y-%m-%d'
            e_fmt = '%Y-%m-%d %H:%M' if p.end_date.hour or p.end_date.minute else '%Y-%m-%d'
            line = (f"{p.user.username};{p.resource.name};{p.task};"
                    f"{p.start_date.strftime(s_fmt)};"
                    f"{p.end_date.strftime(e_fmt)};{active}")
            lines.append(line)

        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')

        return len(policies)


# ── Surveillance du fichier (hot reload) ─────────────────────────────────────

class PolicyWatcher(threading.Thread):
    """Surveille policy.conf et recharge la politique si le fichier change."""

    def __init__(self, app):
        super().__init__(daemon=True, name='PolicyWatcher')
        self.app   = app
        self._mtime = 0

    def run(self):
        status['running']   = True
        status['file_path'] = POLICY_FILE

        # Chargement initial
        if os.path.exists(POLICY_FILE):
            result = import_from_file(self.app, replace=False)
            self._mtime = os.path.getmtime(POLICY_FILE)
            with self.app.app_context():
                from models import AccessPolicy
                total = AccessPolicy.query.count()
            print(f'[MODULE 3] Politique: {total} règle(s) actives ({result["created"]} nouvelle(s) depuis policy.conf)',
                  file=sys.stderr)
        else:
            # Créer un fichier template vide
            _create_default_policy()
            print(f'[MODULE 3] policy.conf créé : {POLICY_FILE}', file=sys.stderr)

        while True:
            time.sleep(5)
            if not os.path.exists(POLICY_FILE):
                continue
            try:
                mtime = os.path.getmtime(POLICY_FILE)
                if mtime != self._mtime:
                    self._mtime = mtime
                    result = import_from_file(self.app, replace=True)
                    n = result['created']
                    print(f'[MODULE 3] Politique rechargée: {n} règles', file=sys.stderr)
                    status['rules_loaded'] = n
                    status['last_reload']  = datetime.utcnow().strftime('%H:%M:%S')
            except Exception as e:
                status['errors'].append(f'PolicyWatcher: {e}')


def _create_default_policy():
    """Crée un policy.conf par défaut si absent."""
    default = HEADER + """\
# Exemple — décommentez et adaptez à votre environnement
# alice;database;read;2026-01-01;2026-12-31;1
# alice;database;write;2026-01-01;2026-12-31;1
# alice;ssh_server;login;2026-01-01;2026-12-31;1
# bob;web_server;read;2026-01-01;2026-06-30;1
# bob;ssh_server;login;2026-01-01;2026-12-31;1
# charlie;file_storage;read;2026-01-01;2026-12-31;1
"""
    with open(POLICY_FILE, 'w', encoding='utf-8') as f:
        f.write(default)


def validate_file(path: str) -> list[str]:
    """Valide un fichier policy.conf, retourne la liste des erreurs."""
    old_errors = status['errors'].copy()
    status['errors'] = []
    parse_policy_file(path)
    errors = status['errors'].copy()
    status['errors'] = old_errors
    return errors


def _load_policy_direct(app):
    """Charge la politique depuis la DB — injectée par app.py au démarrage."""
    raise NotImplementedError("Injectée par app.py au démarrage")


def start(app):
    """Démarre le watcher de politique."""
    PolicyWatcher(app).start()
