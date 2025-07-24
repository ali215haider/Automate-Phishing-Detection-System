from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)  # Renamed to avoid conflict with UserMixin
    
    @property
    def is_active(self):
        return self.active
    
    # Relationships
    scans = db.relationship('ScanHistory', backref='user', lazy=True, cascade='all, delete-orphan')
    reports = db.relationship('PhishingReport', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False)  # 'url', 'email', 'html'
    content = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(20), nullable=False)  # 'safe', 'phishing', 'suspicious'
    confidence_score = db.Column(db.Float, default=0.0)
    detection_method = db.Column(db.String(50), nullable=False)  # 'ml', 'rules', 'blacklist'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)  # JSON string with detailed analysis
    
    def __repr__(self):
        return f'<ScanHistory {self.scan_type}: {self.result}>'

class PhishingReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'verified', 'false_positive'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<PhishingReport {self.url}>'

class BlacklistDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    source = db.Column(db.String(100))  # Source of the blacklist entry
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<BlacklistDomain {self.domain}>'

class WhitelistDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<WhitelistDomain {self.domain}>'
