from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class SecurityRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    condition = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), default="medium")
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(20), default="TCP")
    payload = db.Column(db.Text)
    event_type = db.Column(db.String(100))

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    rule_id = db.Column(db.Integer, db.ForeignKey('security_rule.id'))
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20))
    acknowledged = db.Column(db.Boolean, default=False)


