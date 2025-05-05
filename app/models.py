# app/models.py

from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.dialects.postgresql import JSONB
import pyotp
import secrets
import string

from .database import db

class User(UserMixin, db.Model):
    __tablename__ = 'users'  

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    name = db.Column(db.String(1000))
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    mfa_secret = db.Column(db.String(32))
    mfa_enabled = db.Column(db.Boolean, default=False)
    has_authenticator = db.Column(db.Boolean, default=False)
    is_mfa_setup_complete = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(100))
    email_verification_sent_at = db.Column(db.DateTime)
    backup_codes = db.Column(JSONB)
    preferred_mfa_method = db.Column(db.String(20), default='authenticator')
    password_reset_token = db.Column(db.String(100))
    password_reset_sent_at = db.Column(db.DateTime)
    subscription_id = db.Column(db.String(120))
    
    # Relationships
    conversations = db.relationship('Conversation', backref='user', lazy=True, 
                                  cascade='all, delete-orphan')
    activity = db.relationship('UserActivity', back_populates='user', lazy=True,
                             cascade='all, delete-orphan')
    subscription = db.relationship('Subscription', backref='user', uselist=False,
                                 cascade='all, delete-orphan')
    allowed_emails = db.relationship('AllowedEmail', backref='added_by_user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        return str(self.id)
    
    @property
    def is_authenticated(self):
        return True

    def verify_totp(self, token):
        """Verify a TOTP token"""
        if not self.mfa_secret:
            return False
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(token)

    def generate_mfa_secret(self):
        """Generate a new MFA secret"""
        self.mfa_secret = pyotp.random_base32()
        return self.mfa_secret

    def generate_backup_codes(self, count=8):
        """Generate new backup codes"""
        # Generate random backup codes
        alphabet = string.ascii_letters + string.digits
        codes = [''.join(secrets.choice(alphabet) for _ in range(10)) for _ in range(count)]
        
        # Store hashed versions
        self.backup_codes = [generate_password_hash(code) for code in codes]
        
        # Return unhashed codes to show to user
        return codes

    def verify_backup_code(self, code):
        """Verify and consume a backup code"""
        if not self.backup_codes:
            return False
            
        # Check each hashed code
        for i, hashed_code in enumerate(self.backup_codes):
            if check_password_hash(hashed_code, code):
                # Remove the used code
                codes = list(self.backup_codes)
                codes.pop(i)
                self.backup_codes = codes
                return True
        return False

    def get_mfa_uri(self, issuer_name="DevOpser FlaskAI Demo"):
        """Get the MFA provisioning URI for QR codes"""
        if not self.mfa_secret:
            self.generate_mfa_secret()
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.provisioning_uri(
            name=self.email,
            issuer_name=issuer_name
        )
    
    def generate_temp_password(self):
        alphabet = string.ascii_letters + string.digits
        temp_password = ''.join(secrets.choice(alphabet) for _ in range(12))
        return temp_password

    def __str__(self):
        return self.email

class Conversation(db.Model):
    __tablename__ = 'conversations'

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.String(36), unique=True, nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    chat_history = db.Column(JSONB)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'),
                       nullable=False)

class UserActivity(db.Model):
    __tablename__ = 'user_activities'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    activity_type = db.Column(db.String(50))  # login, api_call, etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.JSON)
    
    # Explicitly define the relationship
    user = db.relationship('User', back_populates='activity')

    def __str__(self):
        return f'<UserActivity {self.activity_type} by {self.user_id}>'

class Subscription(db.Model):
    __tablename__ = 'subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    stripe_subscription_id = db.Column(db.String(120))
    status = db.Column(db.String(50))  # active, canceled, past_due
    plan_id = db.Column(db.String(50))
    current_period_end = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __str__(self):
        return f'<Subscription {self.stripe_subscription_id}>'

class AllowedEmail(db.Model):
    __tablename__ = 'allowed_emails'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    added_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)