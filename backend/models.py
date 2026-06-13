from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user') # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    scans = db.relationship('ScanHistory', backref='user', lazy=True)

    @property
    def is_admin(self):
        return self.role == 'admin'

    @is_admin.setter
    def is_admin(self, value):
        self.role = 'admin' if value else 'user'

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_type = db.Column(db.String(10), nullable=False)  # 'URL' or 'EMAIL'
    target = db.Column(db.Text, nullable=False)          # The actual URL or Email body snippet/subject
    risk_score = db.Column(db.Integer, nullable=False)    # 0-100
    classification = db.Column(db.String(20), nullable=False)  # Safe, Suspicious, Malicious
    threat_explanation = db.Column(db.JSON, nullable=True) # JSON list of reasons/explanations
    domain_info = db.Column(db.JSON, nullable=True)        # IP, Country, Registrar details
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

