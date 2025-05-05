# app/__init__.py
from flask import Flask
from config import Config
from pathlib import Path
from flask_session import Session
import redis
import logging
from .bedrock_client import BedrockClient
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from .models import User
from .database import db
from flask_migrate import Migrate
from .admin import init_admin, admin_bp as admin_routes_bp
from .commands import init_cli
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
import os
import boto3
from werkzeug.middleware.proxy_fix import ProxyFix

APP_ROOT_PATH = Path(__file__).parent

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create mail instance
mail = Mail()

csrf = CSRFProtect()

def clear_old_cache(app):
    redis_client = app.config['REDIS_CLIENT']
    current_version = app.config['CACHE_VERSION']
    try:
        for key in redis_client.scan_iter("chat:*"):
            if isinstance(key, bytes):
                key = key.decode('utf-8')
            if not key.startswith(f"chat:{current_version}:"):
                redis_client.delete(key)
        for key in redis_client.scan_iter("session:*"):
            if isinstance(key, bytes):
                key = key.decode('utf-8')
            if not key.startswith(f"session:{current_version}:"):
                redis_client.delete(key)
        logger.info(f"Old cache cleared for version {current_version}")
    except redis.RedisError as e:
        logger.error(f"Redis error when clearing old cache: {str(e)}")

def get_secret_value(secret_name):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=os.environ['REGION']
    )
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        secret_value = get_secret_value_response['SecretString']
        return secret_value
    except Exception as e:
        logger.error(f"Error retrieving secret value: {str(e)}")

def create_app():
    """Initialize the core application."""
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(Config)

    # Set the secret key from AWS Secrets Manager
    secret_name = os.getenv('FLASK_SECRET_NAME', 'flask_secret_key-44kT6IBM8RJxMoQC')
    print(f"Loaded Flask Secret Name: {secret_name}")
    secret_value = get_secret_value(secret_name)
    app.config['SECRET_KEY'] = secret_value
    print(f"Retrieved Flask Secret Key: {secret_value[:6]}...")

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)  # Initialize mail
    
    # Add debug logging for mail configuration
    logger.info("Mail Configuration:")
    logger.info(f"MAIL_SERVER: {app.config.get('MAIL_SERVER')}")
    logger.info(f"MAIL_PORT: {app.config.get('MAIL_PORT')}")
    logger.info(f"MAIL_USE_TLS: {app.config.get('MAIL_USE_TLS')}")
    logger.info(f"MAIL_USERNAME: {app.config.get('MAIL_USERNAME')}")
    logger.info(f"MAIL_DEFAULT_SENDER: {app.config.get('MAIL_DEFAULT_SENDER')}")
    logger.info(f"MAIL_PASSWORD set: {'Yes' if app.config.get('MAIL_PASSWORD') else 'No'}")
    
    # Create Migrate instance inside create_app
    migrate = Migrate()
    migrate.init_app(app, db)
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Initialize admin interface
    admin = init_admin(app)

    # Initialize CLI commands
    init_cli(app)
    
    Session(app)

    # Initialize Redis client
    app.config['REDIS_CLIENT'] = redis.from_url(app.config['REDIS_URL'])

    # Initialize Bedrock client and store it in app config
    bedrock_client = BedrockClient(
        region_name=app.config.get('AWS_REGION', 'us-east-1'),
        cross_account_role_arn=app.config.get('CUSTOMER_CROSS_ACCOUNT_ROLE_ARN', '')  # NEW: Pass the ARN from config
    )
    app.config['BEDROCK_CLIENT'] = bedrock_client

    # Initialize CSRF protection
    csrf.init_app(app)

    # Add ProxyFix middleware for AWS ALB HTTPS handling
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    with app.app_context():
        # Import and register blueprint
        from .routes import routes_bp
        from .auth import auth as auth_blueprint
        app.register_blueprint(routes_bp)
        app.register_blueprint(auth_blueprint)
        app.register_blueprint(admin_routes_bp)

        
        # Clear old cache on startup
        clear_old_cache(app)
        db.create_all()

        
        logger.info(f"Application started with CACHE_VERSION: {app.config['CACHE_VERSION']}")
        
        return app