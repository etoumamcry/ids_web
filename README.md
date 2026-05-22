# IDS Web — Intrusion Detection System

Plateforme de détection d'intrusions modulaire. 4 modules démons, support Linux + Windows, interface web, temps réel.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     IDS Web Platform                          │
│                                                              │
│  Module 1 (Collecteur)     Module 3 (Politique)              │
│  ─────────────────────     ────────────────────              │
│  • auth.log / syslog       • CRUD web individuel             │
│  • Windows Event Log       • Import/Export policy.conf       │
│  • Capture réseau (scapy)  • Hot reload automatique          │
│  • Intégrité fichiers      • Format: user;res;task;d1;d2;1   │
│  • Processus suspects                                        │
│         │                           │                        │
│         ▼  events/YYYY-MM-DD.jsonl  ▼                        │
│  ┌──────────────────────────────────────────────────────┐    │
│  │       Module 2 — Analyseur (démon continu)            │    │
│  │  Surveille events/ → compare à la politique          │    │
│  │  Violation détectée → Intrusion en DB                │    │
│  └──────────────────────────┬───────────────────────────┘    │
│                             │ queue                          │
│                             ▼                               │
│  ┌──────────────────────────────────────────────────────┐    │
│  │       Module 4 — Alertes (démon)                      │    │
│  │  Format détaillé → alerts/YYYY-MM-DD.log             │    │
│  │  Sauvegarde DB → (Optionnel) Email SMTP               │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

## Installation

### Linux (Ubuntu / Debian)

```bash
# 1. Cloner / copier le projet
cd /opt && git clone <repo> ids_web && cd ids_web

# 2. Installer Python 3.10+
sudo apt update && sudo apt install python3 python3-pip -y

# 3. Installer les dépendances
pip3 install flask flask-sqlalchemy scapy psutil python-dotenv gunicorn

# 4. (Optionnel) Accès aux logs système
sudo chmod o+r /var/log/auth.log
# OU lancer avec sudo pour tout avoir

# 5. Lancer
python3 app.py
# Avec capture réseau complète :
sudo python3 app.py
```

### Linux (RHEL / CentOS / Fedora)

```bash
pip3 install flask flask-sqlalchemy scapy psutil
sudo chmod o+r /var/log/secure
python3 app.py
```

### Windows

```bash
# 1. Installer Python 3.10+ depuis python.org
# 2. Installer Npcap depuis https://npcap.com (pour scapy)
# 3. Dans PowerShell (Administrateur) :
pip install flask flask-sqlalchemy scapy psutil

# 4. Lancer en tant qu'Administrateur (pour Event Log + réseau)
python app.py
```

## Démarrage

```
http://localhost:5000
```

## Structure du projet

```
ids_web/
├── app.py                      # Orchestrateur principal + routes Flask
├── models.py                   # Modèles SQLAlchemy
├── policy.conf                 # Politique de sécurité (éditable)
│
├── modules/
│   ├── module1_collector.py    # Collecteur d'événements (démon)
│   ├── module2_analyzer.py     # Analyseur d'événements (démon)
│   ├── module3_policy.py       # Gestion de la politique (démon)
│   └── module4_alerter.py      # Générateur d'alertes (démon)
│
├── events/                     # Fichiers JSONL produits par Module 1
│   └── YYYY-MM-DD.jsonl
│
├── alerts/                     # Logs d'alertes produits par Module 4
│   └── YYYY-MM-DD.log
│
├── templates/                  # Interface web Flask
├── instance/ids.db             # Base de données SQLite
└── requirements.txt
```

## Format policy.conf

Un fichier texte, une règle par ligne, champs séparés par `;` :

```
# Commentaire
username;resource;task;start_date;end_date;active

# Exemples
alice;database;read;2026-01-01;2026-12-31;1
alice;database;write;2026-01-01;2026-12-31;1
bob;web_server;read;2026-01-01;2026-06-30;1
```

**Tâches reconnues** : `read`, `write`, `delete`, `execute`, `admin`, `login`, `failed_login`, `backup`, `restore`, `connect`

**Ressources détectées automatiquement** :
- `ssh_server` — connexions SSH
- `database` — accès MySQL, PostgreSQL, SQLite
- `web_server` — nginx, apache, httpd
- `email_server` — sendmail, postfix
- `system` — commandes sudo, su, sessions PAM
- `file_storage` — accès fichiers critiques
- `user_management` — useradd, usermod, passwd

## Format des fichiers d'événements (JSONL)

Chaque ligne est un objet JSON :

```json
{
  "id": "uuid4",
  "ts": "2026-05-22T10:30:00.123456",
  "source": "auth.log",
  "username": "alice",
  "resource": "ssh_server",
  "task": "login",
  "execution_date": "2026-05-22T10:30:00",
  "raw": "May 22 10:30:00 hostname sshd[1234]: Accepted password for alice from 192.168.1.10"
}
```

## Format des alertes (alerts/YYYY-MM-DD.log)

```
═══════════════════════════════════════════════════════
[CRITIQUE] 2026-05-22 10:30:00 UTC
───────────────────────────────────────────────────────
INTRUSION DÉTECTÉE
  Utilisateur : hacker_01
  Ressource   : database
  Tâche       : admin
  Date accès  : 2026-05-22 03:15:00
  Source      : auth.log
───────────────────────────────────────────────────────
  Violation   : Utilisateur 'hacker_01' absent de la politique de sécurité
  Type        : user_unknown
  Ligne brute : May 22 03:15:00 hostname sudo: hacker_01 : command not allowed
═══════════════════════════════════════════════════════
```

## Tests réels

### Test 1 — Connexion SSH autorisée (doit être OK)

```bash
# alice est dans la politique → pas d'intrusion
ssh alice@localhost
```

### Test 2 — Connexion SSH non autorisée (doit déclencher une intrusion)

```bash
# intrus n'est pas dans la politique → INTRUSION
ssh intrus@localhost
```

### Test 3 — Sudo (doit créer un événement)

```bash
sudo cat /etc/shadow
# → événement "execute" sur "file_storage"
# → intrusion si l'utilisateur n'est pas autorisé
```

### Test 4 — Scénario intégré

Dans l'interface web : **Scénario → Charger et Analyser**

Expected : 17-18 intrusions sur 25 entrées.

## Configuration email (optionnel)

Créer `ids_config.json` :

```json
{
  "smtp": {
    "host": "smtp.gmail.com",
    "port": 587,
    "user": "votre@gmail.com",
    "password": "app_password",
    "from": "ids@domaine.com",
    "to": "admin@domaine.com",
    "tls": true
  }
}
```

## Déploiement production (Linux)

```bash
# Avec gunicorn + systemd
pip install gunicorn

# Créer /etc/systemd/system/ids.service
[Unit]
Description=IDS Web Platform
After=network.target

[Service]
User=root
WorkingDirectory=/opt/ids_web
ExecStart=python3 /opt/ids_web/app.py
Restart=always

[Install]
WantedBy=multi-user.target

sudo systemctl enable ids && sudo systemctl start ids
```

## Dépendances

```
Flask>=3.1.0
Flask-SQLAlchemy>=3.1.1
scapy>=2.6.1          # capture réseau
psutil>=5.9.0         # surveillance processus
python-dotenv>=1.0.1
gunicorn>=23.0.0      # production Linux
```

Windows uniquement (optionnel) : `pywin32` pour accès Event Log avancé.

## Modules — Détail

| Module | Démon | Rôle |
|--------|-------|------|
| Module 1 | `LinuxLogCollector` + `NetworkCapture` + `FileIntegrityMonitor` + `ProcessMonitor` | Collecte et produit `events/YYYY-MM-DD.jsonl` |
| Module 2 | `EventAnalyzer` | Analyse les fichiers JSONL contre la politique, crée les intrusions |
| Module 3 | `PolicyWatcher` | Surveille `policy.conf`, synchronise avec la DB (hot reload) |
| Module 4 | `AlertDaemon` | Consomme la queue, formate et distribue les alertes |
