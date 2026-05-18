from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from models import db, SecurityRule, Event, Alert
from datetime import datetime
import re
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids_super_secret_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# ====================== ANALYSE D'ÉVÉNEMENT ======================
def analyze_event(event):
    rules = SecurityRule.query.filter_by(active=True).all()
    for rule in rules:
        match = False
        cond = rule.condition.lower()

        if "port==" in cond:
            try:
                port = int(cond.split("==")[1])
                if event.port == port:
                    match = True
            except:
                pass
        elif "keyword=" in cond:
            keyword = cond.split("keyword=")[1]
            if keyword in (event.payload or "").lower():
                match = True
        elif re.search(rule.condition, event.payload or "", re.IGNORECASE):
            match = True

        if match:
            alert = Alert(
                event_id=event.id,
                rule_id=rule.id,
                message=f"{rule.name} - {rule.description}",
                severity=rule.severity
            )
            db.session.add(alert)
            db.session.commit()
            print(f"🚨 ALERTE [{rule.severity.upper()}] : {rule.name}")

# ====================== ROUTES ======================

@app.route('/')
def index():
    events = Event.query.order_by(Event.timestamp.desc()).limit(15).all()
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    total_alerts = Alert.query.count()
    critical = Alert.query.filter_by(severity='critical').count()
    high = Alert.query.filter_by(severity='high').count()
    
    return render_template('index.html', 
                         events=events, 
                         alerts=alerts,
                         total_alerts=total_alerts,
                         critical=critical,
                         high=high)

@app.route('/events')
def events():
    all_events = Event.query.order_by(Event.timestamp.desc()).all()
    return render_template('events.html', events=all_events)

@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    if request.method == 'POST':
        event = Event(
            source_ip=request.form['source_ip'],
            destination_ip=request.form.get('dest_ip', '192.168.1.100'),
            port=int(request.form['port']),
            protocol=request.form.get('protocol', 'TCP'),
            payload=request.form.get('payload', ''),
            event_type=request.form.get('event_type', 'Manual')
        )
        db.session.add(event)
        db.session.commit()
        
        analyze_event(event)
        flash('Événement créé et analysé avec succès !', 'success')
        return redirect(url_for('index'))
    
    return render_template('create_event.html')

# Simulation de trafic
@app.route('/simulate')
def simulate_traffic():
    for _ in range(8):
        ports = [80, 443, 22, 445, 3389, 3306]
        payloads = ["", "SELECT * FROM users WHERE id=1", "1=1", "failed login", "GET /admin"]
        
        event = Event(
            source_ip=f"192.168.{random.randint(1,50)}.{random.randint(1,255)}",
            port=random.choice(ports),
            payload=random.choice(payloads),
            event_type="Simulated"
        )
        db.session.add(event)
        db.session.commit()
        analyze_event(event)
    
    flash('8 événements simulés générés !', 'info')
    return redirect(url_for('index'))

# ====================== GESTION DES RÈGLES ======================
@app.route('/rules')
def rules():
    all_rules = SecurityRule.query.all()
    return render_template('rules.html', rules=all_rules)

@app.route('/add_rule', methods=['POST'])
def add_rule():
    rule = SecurityRule(
        name=request.form['name'],
        description=request.form.get('description'),
        condition=request.form['condition'],
        severity=request.form['severity']
    )
    db.session.add(rule)
    db.session.commit()
    flash('Règle de sécurité ajoutée', 'success')
    return redirect(url_for('rules'))

@app.route('/toggle_rule/<int:rule_id>')
def toggle_rule(rule_id):
    rule = SecurityRule.query.get_or_404(rule_id)
    rule.active = not rule.active
    db.session.commit()
    return redirect(url_for('rules'))

# ====================== ALERTES ======================
@app.route('/alerts')
def alerts():
    all_alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    return render_template('alerts.html', alerts=all_alerts)

@app.route('/ack_alert/<int:alert_id>')
def ack_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.acknowledged = True
    db.session.commit()
    return redirect(url_for('alerts'))

# ====================== INITIALISATION ======================

# Pour Render (production)
if __name__ != '__main__':
    with app.app_context():
        db.create_all()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Règles par défaut
        if SecurityRule.query.count() == 0:
            defaults = [
                ("SMB Exploit", "Accès au port SMB suspect", "port==445", "high"),
                ("SQL Injection", "Tentative d'injection SQL", "keyword=1=1", "critical"),
                ("Brute Force", "Échecs de connexion répétés", "keyword=failed", "high"),
                ("Port Scan", "Scan de ports", "port==0", "medium"),
                ("Admin Access", "Accès à une page admin", "keyword=admin", "high"),
            ]
            for name, desc, cond, sev in defaults:
                db.session.add(SecurityRule(name=name, description=desc, condition=cond, severity=sev))
            db.session.commit()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
