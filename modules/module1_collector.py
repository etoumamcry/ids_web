"""
MODULE 1 — Collecteur d'événements (démon)

Observe en continu les sources d'événements du système et produit
des fichiers d'événements physiques (JSONL) dans le dossier events/.

Sources supportées :
  Linux  : /var/log/auth.log, /var/log/syslog, /var/log/audit/audit.log
  Windows: Security Event Log (wevtutil), Application, System
  Réseau : capture de paquets IP (scapy, nécessite root/admin)
  Fichiers: surveillance d'intégrité des fichiers critiques (SHA-256)
  Processus: détection de nouveaux processus suspects (psutil)

Format de sortie (JSONL) :
  {"id":"...", "ts":"...", "source":"...", "username":"...",
   "resource":"...", "task":"...", "execution_date":"...", "raw":"..."}
"""

import os
import re
import sys
import json
import uuid
import time
import platform
import hashlib
import threading
import subprocess
from collections import defaultdict
from datetime import datetime

# ── Statut partagé (lu par l'interface web) ─────────────────────────────────
status = {
    'running':     False,
    'sources':     [],
    'events_today': 0,
    'last_event':  None,
    'errors':      [],
    'started_at':  None,
}

SYSTEM = platform.system()  # 'Linux', 'Windows', 'Darwin'

# ── Répertoire de sortie ─────────────────────────────────────────────────────
EVENTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'events')

# ── Fichiers Linux surveillés ────────────────────────────────────────────────
LINUX_LOG_CANDIDATES = [
    '/var/log/auth.log',
    '/var/log/secure',
    '/var/log/syslog',
    '/var/log/audit/audit.log',
]

# ── Fichiers critiques pour l'intégrité ─────────────────────────────────────
INTEGRITY_FILES = {
    'Linux':   ['/etc/passwd', '/etc/shadow', '/etc/sudoers',
                '/etc/hosts', '/etc/crontab'],
    'Windows': ['C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\Windows\\System32\\config\\SAM'],
}

# ── Ressources détectées automatiquement ─────────────────────────────────────
def _cmd_to_resource(cmd):
    c = cmd.lower()
    if any(x in c for x in ['mysql', 'psql', 'sqlite3', 'mongod', 'redis-cli']):
        return 'database'
    if any(x in c for x in ['nginx', 'apache2', 'httpd', 'flask']):
        return 'web_server'
    if any(x in c for x in ['sendmail', 'postfix', 'dovecot', 'mail']):
        return 'email_server'
    if any(x in c for x in ['useradd', 'usermod', 'passwd', 'chpasswd']):
        return 'user_management'
    if any(x in c for x in ['iptables', 'ufw', 'firewall']):
        return 'firewall'
    return 'system'


# ── Écriture d'un événement dans le fichier JSONL du jour ────────────────────
_write_lock = threading.Lock()

def write_event(username: str, resource: str, task: str,
                execution_date: datetime, source: str, raw: str = ''):
    """Écrit un événement dans events/YYYY-MM-DD.jsonl"""
    event = {
        'id':             str(uuid.uuid4()),
        'ts':             datetime.utcnow().isoformat(),
        'source':         source,
        'username':       username,
        'resource':       resource,
        'task':           task,
        'execution_date': execution_date.isoformat(),
        'raw':            raw[:300],
    }
    day_file = os.path.join(EVENTS_DIR, datetime.utcnow().strftime('%Y-%m-%d') + '.jsonl')
    with _write_lock:
        with open(day_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event) + '\n')

    status['events_today'] += 1
    status['last_event'] = f"{username} | {task} | {resource}"
    return event


# ════════════════════════════════════════════════════════════════════════════
# COLLECTEUR LINUX — lecture des logs système
# ════════════════════════════════════════════════════════════════════════════

def _parse_date(s: str) -> datetime:
    year = datetime.now().year
    for fmt in ['%Y %b %d %H:%M:%S', '%Y %b  %d %H:%M:%S']:
        try:
            return datetime.strptime(f'{year} {s.strip()}', fmt)
        except ValueError:
            continue
    return datetime.utcnow()


def _parse_auth_line(line: str) -> dict | None:
    """Parse une ligne de auth.log / secure et retourne un dict événement."""
    y = datetime.now().year

    # SSH login réussi
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*sshd.*Accepted \w+ for (\S+) from ([\d.]+)', line)
    if m:
        return dict(username=m.group(2), resource='ssh_server', task='login',
                    execution_date=_parse_date(m.group(1)), source='auth.log', raw=line.strip())

    # SSH login échoué
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*sshd.*Failed \w+ for (?:invalid user )?(\S+) from ([\d.]+)', line)
    if m:
        return dict(username=m.group(2), resource='ssh_server', task='failed_login',
                    execution_date=_parse_date(m.group(1)), source='auth.log', raw=line.strip())

    # sudo
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*sudo.*:\s+(\S+)\s+:.*COMMAND=(.+)', line)
    if m:
        return dict(username=m.group(2), resource=_cmd_to_resource(m.group(3)),
                    task='execute', execution_date=_parse_date(m.group(1)),
                    source='auth.log', raw=line.strip())

    # su
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*su.*:\s+\(to (\S+)\) (\S+)', line)
    if m:
        return dict(username=m.group(3), resource='system', task='admin',
                    execution_date=_parse_date(m.group(1)), source='auth.log', raw=line.strip())

    # Nouveau login PAM
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*pam.*session opened.*for user (\S+)', line, re.IGNORECASE)
    if m:
        return dict(username=m.group(2), resource='system', task='login',
                    execution_date=_parse_date(m.group(1)), source='syslog', raw=line.strip())

    # useradd / usermod
    m = re.search(r'(\w{3}\s+\d+\s+[\d:]+).*useradd.*new user.*name=(\S+)', line)
    if m:
        return dict(username=m.group(2), resource='user_management', task='write',
                    execution_date=_parse_date(m.group(1)), source='auth.log', raw=line.strip())

    return None


def _parse_audit_line(line: str) -> dict | None:
    """Parse une ligne de /var/log/audit/audit.log."""
    if 'type=USER_LOGIN' in line or 'type=USER_AUTH' in line:
        user_m = re.search(r'acct="(\S+)"', line)
        res_m  = re.search(r'res=(\S+)', line)
        ts_m   = re.search(r'msg=audit\((\d+)', line)
        if user_m:
            ts = datetime.fromtimestamp(float(ts_m.group(1))) if ts_m else datetime.utcnow()
            task = 'login' if (res_m and 'success' in res_m.group(1)) else 'failed_login'
            return dict(username=user_m.group(1), resource='system', task=task,
                        execution_date=ts, source='audit.log', raw=line.strip())

    if 'type=EXECVE' in line:
        user_m = re.search(r'uid=(\d+)', line)
        cmd_m  = re.search(r'a0="([^"]+)"', line)
        ts_m   = re.search(r'msg=audit\((\d+)', line)
        if user_m and cmd_m:
            ts = datetime.fromtimestamp(float(ts_m.group(1))) if ts_m else datetime.utcnow()
            try:
                import pwd
                username = pwd.getpwuid(int(user_m.group(1))).pw_name
            except Exception:
                username = f'uid_{user_m.group(1)}'
            return dict(username=username, resource=_cmd_to_resource(cmd_m.group(1)),
                        task='execute', execution_date=ts,
                        source='audit.log', raw=line.strip())
    return None


class LinuxLogCollector(threading.Thread):
    """Surveille les fichiers de log Linux en temps réel (tail -f)."""

    def __init__(self):
        super().__init__(daemon=True, name='LinuxLogCollector')
        self._log_file = None
        self._audit_file = None
        self._log_pos = 0
        self._audit_pos = 0

    def _find_log(self):
        for path in LINUX_LOG_CANDIDATES[:3]:  # auth.log / secure / syslog
            if os.path.exists(path):
                try:
                    open(path).close()
                    return path
                except PermissionError:
                    continue
        return None

    def run(self):
        self._log_file = self._find_log()
        if not self._log_file:
            status['errors'].append('auth.log inaccessible — lancez avec sudo')
            return

        self._log_pos = os.path.getsize(self._log_file)
        if os.path.exists('/var/log/audit/audit.log'):
            try:
                open('/var/log/audit/audit.log').close()
                self._audit_file = '/var/log/audit/audit.log'
                self._audit_pos = os.path.getsize(self._audit_file)
            except PermissionError:
                pass

        sources = [self._log_file]
        if self._audit_file:
            sources.append(self._audit_file)
        status['sources'].extend(sources)

        while True:
            self._poll_log()
            if self._audit_file:
                self._poll_audit()
            time.sleep(2)

    def _poll_log(self):
        try:
            size = os.path.getsize(self._log_file)
            if size > self._log_pos:
                with open(self._log_file, encoding='utf-8', errors='replace') as f:
                    f.seek(self._log_pos)
                    for line in f:
                        ev = _parse_auth_line(line)
                        if ev:
                            write_event(**ev)
                self._log_pos = size
        except Exception as e:
            status['errors'].append(f'LinuxLogCollector: {e}')

    def _poll_audit(self):
        try:
            size = os.path.getsize(self._audit_file)
            if size > self._audit_pos:
                with open(self._audit_file, encoding='utf-8', errors='replace') as f:
                    f.seek(self._audit_pos)
                    for line in f:
                        ev = _parse_audit_line(line)
                        if ev:
                            write_event(**ev)
                self._audit_pos = size
        except Exception as e:
            status['errors'].append(f'AuditCollector: {e}')


# ════════════════════════════════════════════════════════════════════════════
# COLLECTEUR WINDOWS — Windows Event Log
# ════════════════════════════════════════════════════════════════════════════

class WindowsLogCollector(threading.Thread):
    """Lit le journal d'événements Windows (Security, System) via wevtutil."""

    # Event IDs importants :
    # 4624 = login réussi, 4625 = login échoué, 4672 = admin privileges
    # 4688 = nouveau processus, 4663 = accès fichier, 4720 = user créé
    # 4732 = ajout groupe, 4728 = ajout groupe admin

    QUERIES = {
        'Security': {
            4624: ('login',        'system'),
            4625: ('failed_login', 'system'),
            4672: ('admin',        'system'),
            4688: ('execute',      'system'),
            4663: ('read',         'file_storage'),
            4720: ('write',        'user_management'),
            4732: ('write',        'user_management'),
        },
        'System': {
            7045: ('execute', 'system'),   # nouveau service installé
        }
    }

    def __init__(self):
        super().__init__(daemon=True, name='WindowsLogCollector')
        self._last_record = {}

    def _get_last_record_id(self, channel):
        try:
            result = subprocess.run(
                ['wevtutil', 'gli', channel],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if 'lastRecordNumber' in line:
                    return int(line.split(':')[1].strip())
        except Exception:
            pass
        return 0

    def _query_events(self, channel, last_id, count=50):
        try:
            xpath = f"*[System/EventRecordID>{last_id}]"
            result = subprocess.run(
                ['wevtutil', 'qe', channel, f'/q:{xpath}',
                 f'/c:{count}', '/rd:true', '/f:xml'],
                capture_output=True, text=True, timeout=15
            )
            return result.stdout
        except Exception:
            return ''

    def _parse_xml_events(self, xml_str, channel):
        import xml.etree.ElementTree as ET
        events = []
        ns = 'http://schemas.microsoft.com/win/2004/08/events/event'

        # wevtutil peut retourner plusieurs événements non encapsulés
        xml_str = f'<root>{xml_str}</root>'
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return events

        for ev in root.findall(f'{{{ns}}}Event'):
            try:
                system = ev.find(f'{{{ns}}}System')
                event_id = int(system.find(f'{{{ns}}}EventID').text)
                record_id = int(system.find(f'{{{ns}}}EventRecordID').text)
                ts_str = system.find(f'{{{ns}}}TimeCreated').attrib.get('SystemTime', '')
                ts = datetime.fromisoformat(ts_str.replace('Z', '')) if ts_str else datetime.utcnow()

                # Extraire le nom d'utilisateur depuis EventData
                username = 'SYSTEM'
                ed = ev.find(f'{{{ns}}}EventData')
                if ed is not None:
                    for data in ed.findall(f'{{{ns}}}Data'):
                        name = data.attrib.get('Name', '')
                        if name in ('SubjectUserName', 'TargetUserName', 'AccountName'):
                            val = data.text or ''
                            if val and val not in ('-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'):
                                username = val
                                break

                if event_id in self.QUERIES.get(channel, {}):
                    task, resource = self.QUERIES[channel][event_id]
                    events.append({
                        'username': username,
                        'resource': resource,
                        'task': task,
                        'execution_date': ts,
                        'source': f'Windows/{channel}',
                        'raw': f'EventID={event_id} RecordID={record_id}',
                        '_record_id': record_id,
                    })
            except Exception:
                continue
        return events

    def run(self):
        for channel in self.QUERIES:
            self._last_record[channel] = self._get_last_record_id(channel)

        status['sources'].append('Windows Event Log (Security, System)')

        while True:
            for channel in self.QUERIES:
                xml_str = self._query_events(channel, self._last_record[channel])
                if xml_str.strip():
                    events = self._parse_xml_events(xml_str, channel)
                    for ev in events:
                        rid = ev.pop('_record_id', 0)
                        write_event(**ev)
                        if rid > self._last_record[channel]:
                            self._last_record[channel] = rid
            time.sleep(5)


# ════════════════════════════════════════════════════════════════════════════
# CAPTURE RÉSEAU — scapy
# ════════════════════════════════════════════════════════════════════════════

# ── Détection Scan de Ports (fenêtre glissante par IP) ───────────────────────
_port_tracker:     dict = defaultdict(set)    # ip → {ports contactés}
_port_first_seen:  dict = {}                  # ip → timestamp premier paquet
PORT_SCAN_THRESHOLD = 15   # ports différents avant alerte
PORT_SCAN_WINDOW    = 60   # secondes

def _check_port_scan(src_ip: str, port: int) -> tuple[bool, int]:
    """
    Retourne (True, nb_ports) si l'IP a sondé trop de ports différents.
    Fenêtre glissante de PORT_SCAN_WINDOW secondes.
    """
    now = time.time()
    first = _port_first_seen.get(src_ip, now)

    if now - first > PORT_SCAN_WINDOW:
        _port_tracker[src_ip]   = set()
        _port_first_seen[src_ip] = now

    if src_ip not in _port_first_seen:
        _port_first_seen[src_ip] = now

    _port_tracker[src_ip].add(port)
    n = len(_port_tracker[src_ip])

    triggered = (n == PORT_SCAN_THRESHOLD or
                 (n > PORT_SCAN_THRESHOLD and (n - PORT_SCAN_THRESHOLD) % 10 == 0))
    return triggered, n


class NetworkCapture(threading.Thread):
    """Capture les paquets IP et génère des événements réseau."""

    def __init__(self):
        super().__init__(daemon=True, name='NetworkCapture')
        self._count = 0

    def run(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP, Raw
        except ImportError:
            status['errors'].append('NetworkCapture: pip install scapy')
            return

        if SYSTEM != 'Windows' and os.geteuid() != 0:
            status['errors'].append('NetworkCapture: droits root requis (sudo)')
            return

        status['sources'].append('Réseau (scapy)')

        def handle(pkt):
            if IP not in pkt:
                return
            self._count += 1
            src = pkt[IP].src
            dst = pkt[IP].dst
            port, proto, payload = 0, 'OTHER', ''

            if TCP in pkt:
                proto, port = 'TCP', pkt[TCP].dport
                if Raw in pkt:
                    try:
                        payload = bytes(pkt[Raw].load).decode('utf-8', errors='replace')[:200]
                    except Exception:
                        pass
            elif UDP in pkt:
                proto, port = 'UDP', pkt[UDP].dport

            if port in (5000, 5001):  # ignorer Flask
                return

            # ── Détection scan de ports ──────────────────────────────────
            scan_triggered, n_ports = _check_port_scan(src, port)
            if scan_triggered:
                write_event(
                    username=src,
                    resource='network_scanner',
                    task='port_scan',
                    execution_date=datetime.utcnow(),
                    source='network/port_scan',
                    raw=(f'SCAN DE PORTS: {src} a sondé {n_ports} ports différents '
                         f'en {PORT_SCAN_WINDOW}s')
                )

            # Mapper le port vers une ressource
            port_map = {
                22: 'ssh_server', 23: 'telnet_server', 80: 'web_server',
                443: 'web_server', 3306: 'database', 5432: 'database',
                25: 'email_server', 587: 'email_server', 445: 'file_storage',
                3389: 'rdp_server', 21: 'ftp_server',
            }
            resource = port_map.get(port, f'network_port_{port}')
            task = 'connect'
            if payload:
                pl = payload.lower()
                if 'select' in pl or 'insert' in pl or 'drop' in pl:
                    task = 'execute'
                elif 'get ' in pl or 'post ' in pl:
                    task = 'read'

            write_event(
                username=src,
                resource=resource,
                task=task,
                execution_date=datetime.utcnow(),
                source=f'network/{proto}',
                raw=f'{src}:{port} → {dst} [{proto}] {payload[:80]}'
            )

        try:
            sniff(prn=handle, store=False,
                  filter='ip and not (src host 127.0.0.1 or dst host 127.0.0.1)')
        except Exception as e:
            status['errors'].append(f'NetworkCapture: {e}')


# ════════════════════════════════════════════════════════════════════════════
# INTÉGRITÉ FICHIERS — hash SHA-256
# ════════════════════════════════════════════════════════════════════════════

class FileIntegrityMonitor(threading.Thread):
    """Surveille l'intégrité des fichiers critiques (SHA-256)."""

    def __init__(self):
        super().__init__(daemon=True, name='FileIntegrityMonitor')
        self._baseline = {}

    def _hash(self, path):
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def run(self):
        targets = INTEGRITY_FILES.get(SYSTEM, INTEGRITY_FILES['Linux'])
        existing = [p for p in targets if os.path.exists(p)]

        if not existing:
            return

        # Établir la baseline
        for path in existing:
            h = self._hash(path)
            if h:
                self._baseline[path] = h

        status['sources'].append(f'Intégrité fichiers ({len(existing)} fichiers)')

        while True:
            time.sleep(30)  # vérifier toutes les 30s
            for path in existing:
                current = self._hash(path)
                if current and current != self._baseline.get(path):
                    self._baseline[path] = current
                    write_event(
                        username='SYSTEM',
                        resource='file_storage',
                        task='write',
                        execution_date=datetime.utcnow(),
                        source='file_integrity',
                        raw=f'MODIFICATION: {path} (SHA256 changé)'
                    )


# ════════════════════════════════════════════════════════════════════════════
# SURVEILLANCE DES PROCESSUS — psutil
# ════════════════════════════════════════════════════════════════════════════

class ProcessMonitor(threading.Thread):
    """Détecte les nouveaux processus suspects via psutil."""

    SUSPICIOUS = [
        # Scanners réseau
        'nmap', 'masscan', 'zmap', 'unicornscan', 'hping3', 'angry ip',
        # Sniffers / MitM
        'tcpdump', 'wireshark', 'tshark', 'ettercap', 'dsniff', 'arpspoof',
        'bettercap', 'mitmproxy', 'responder',
        # Outils de connexion / reverse shells
        'nc', 'ncat', 'netcat', 'socat', 'chisel', 'ligolo', 'rpivot',
        # Exploitation / frameworks
        'msfconsole', 'msfvenom', 'metasploit', 'meterpreter',
        'empire', 'covenant', 'sliver', 'havoc', 'cobalt',
        # Webapps
        'sqlmap', 'nikto', 'burpsuite', 'zaproxy', 'dirb', 'gobuster',
        'dirbuster', 'ffuf', 'wfuzz', 'feroxbuster', 'nuclei',
        # Mots de passe / cracking
        'hydra', 'medusa', 'john', 'hashcat', 'ophcrack', 'fcrackzip',
        'cewl', 'crunch',
        # Post-exploitation Linux
        'linpeas', 'linEnum', 'pspy', 'gtfobins',
        # Post-exploitation Windows
        'mimikatz', 'procdump', 'wce', 'fgdump', 'pwdump',
        'rubeus', 'bloodhound', 'sharphound', 'powerview',
        'psexec', 'wmiexec', 'smbexec', 'impacket',
        # Escalade de privilèges
        'linux-exploit-suggester', 'windows-exploit-suggester',
        'wesng', 'sherlock',
        # Crypto mining
        'xmrig', 'minerd', 'cpuminer', 'ccminer', 'ethminer', 'nbminer',
        # Tunneling / persistance
        'proxychains', 'revsocks', 'iodine', 'dns2tcp', 'ptunnel',
        # Commandes shell suspectes (détection par cmdline)
        'bash -i', 'sh -i', 'python -c', 'python3 -c', 'perl -e',
        'ruby -e', 'php -r', 'curl | bash', 'wget | bash',
        # Outils Windows suspects
        'powershell -enc', 'powershell -nop', 'cmd /c',
        'reg add', 'schtasks /create', 'at /create',
    ]

    def __init__(self):
        super().__init__(daemon=True, name='ProcessMonitor')
        self._known_pids = set()

    def run(self):
        try:
            import psutil
        except ImportError:
            status['errors'].append('ProcessMonitor: pip install psutil')
            return

        import psutil
        self._known_pids = {p.pid for p in psutil.process_iter()}
        status['sources'].append('Processus (psutil)')

        while True:
            time.sleep(5)
            try:
                current_pids = set()
                for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
                    try:
                        pid  = proc.info['pid']
                        name = (proc.info['name'] or '').lower()
                        user = proc.info['username'] or 'SYSTEM'
                        cmd  = ' '.join(proc.info['cmdline'] or []).lower()
                        current_pids.add(pid)

                        if pid not in self._known_pids:
                            # Nouveau processus
                            is_suspicious = any(s in name or s in cmd
                                                for s in self.SUSPICIOUS)
                            if is_suspicious:
                                write_event(
                                    username=user,
                                    resource='system',
                                    task='execute',
                                    execution_date=datetime.utcnow(),
                                    source='process_monitor',
                                    raw=f'PROCESSUS SUSPECT: {name} (pid={pid}) cmd={cmd[:100]}'
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                self._known_pids = current_pids
            except Exception as e:
                status['errors'].append(f'ProcessMonitor: {e}')


# ════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE — démarre tous les collecteurs
# ════════════════════════════════════════════════════════════════════════════

def start(app=None):
    """Démarre tous les collecteurs comme démons en arrière-plan."""
    os.makedirs(EVENTS_DIR, exist_ok=True)

    status['running']    = True
    status['started_at'] = datetime.utcnow().isoformat()
    status['sources']    = []
    status['errors']     = []

    if SYSTEM == 'Windows':
        WindowsLogCollector().start()
    else:
        LinuxLogCollector().start()

    NetworkCapture().start()
    FileIntegrityMonitor().start()
    ProcessMonitor().start()

    print(f'[MODULE 1] Collecteur démarré (OS={SYSTEM})', file=sys.stderr)
