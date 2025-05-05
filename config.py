# config.py
"""App configuration."""
import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv
import redis
import logging
import time
from datetime import timedelta
from app.utils import *
import json

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Config:
    """Set Flask configuration vars from .env file."""
    # General Config
    load_dotenv()
    flask_secret_name = os.getenv('FLASK_SECRET_NAME')
    region_name = os.getenv('REGION')
    print(f"Loaded Flask Secret Name: {flask_secret_name}")
    print(f"Using AWS Region: {region_name}")
    
    if flask_secret_name:
        FLASK_SECRET_KEY = get_secret(flask_secret_name, region_name)
        print(f"Retrieved Flask Secret Key: {FLASK_SECRET_KEY[:5]}...")  # Only print partial key for security
    else:
        FLASK_SECRET_KEY = None
    
    # AWS Region for Bedrock
    AWS_REGION = region_name

    # NEW: Extract the customer-supplied cross-account role ARN from the environment.
    # This is the target role ARN that customers create in their AWS account.
    CUSTOMER_CROSS_ACCOUNT_ROLE_ARN = os.getenv('CUSTOMER_CROSS_ACCOUNT_ROLE_ARN', '')

    FLASK_APP = os.getenv('FLASK_APP')
    FLASK_ENV = os.getenv('FLASK_ENV')
    port = int(os.getenv('PORT', 8000))
    host='0.0.0.0'
    debug=True

    # Admin Users Secret
    ADMIN_USERS_SECRET_NAME = os.getenv('ADMIN_USERS_SECRET_NAME')

    # Additional Secrets
    ADDITIONAL_SECRETS_NAME = os.getenv('ADDITIONAL_SECRETS')
    try:
        if ADDITIONAL_SECRETS_NAME:
            additional_secrets_str = get_secret(ADDITIONAL_SECRETS_NAME, region_name)
            ADDITIONAL_SECRETS = json.loads(additional_secrets_str)
        else:
            ADDITIONAL_SECRETS = {}
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode ADDITIONAL_SECRETS as JSON: {str(e)}")
        ADDITIONAL_SECRETS = {}
    except Exception as e:
        logger.error(f"Error retrieving ADDITIONAL_SECRETS: {str(e)}")
        ADDITIONAL_SECRETS = {}

    # Cache Version Config
    CACHE_VERSION = os.getenv('CACHE_VERSION', f"1.0-{int(time.time())}")
    print(f"Using Cache Version: {CACHE_VERSION}")

    # Session Config
    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = f'session:{CACHE_VERSION}:'
    SESSION_REDIS = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379'))
    
    # Session security settings
    if FLASK_ENV == 'development':
        SESSION_COOKIE_SECURE = False
        SESSION_COOKIE_SAMESITE = 'Lax'
        PREFERRED_URL_SCHEME = 'http'
        SESSION_COOKIE_NAME = 'session'
        SESSION_COOKIE_DOMAIN = None
    else:
        SESSION_COOKIE_SECURE = True
        SESSION_COOKIE_SAMESITE = 'Lax' #use 'Strict' if you want there to be zero Cross-Site Request Forgery risk, but this impacts the email verification flash message
        PREFERRED_URL_SCHEME = 'https'
        SESSION_COOKIE_NAME = '__Host-session'
        SESSION_COOKIE_DOMAIN = None  # Required for __Host- prefix
        SESSION_COOKIE_PATH = '/'     # Required for __Host- prefix
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    

    # Redis client
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
    REDIS_CLIENT = redis.from_url(REDIS_URL)
    
    # Get mail password from Secrets Manager
    MAIL_SERVER_SECRET_NAME = os.getenv('MAIL_SERVER')
    MAIL_PORT_SECRET_NAME = os.getenv('MAIL_PORT')
    MAIL_USE_TLS_SECRET_NAME = os.getenv('MAIL_USE_TLS')
    MAIL_USERNAME_SECRET_NAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD_SECRET_NAME = os.getenv('MAIL_PASSWORD_SECRET_NAME')
    MAIL_DEFAULT_SENDER_SECRET_NAME = os.getenv('MAIL_DEFAULT_SENDER')

    try:
        if MAIL_SERVER_SECRET_NAME:
            MAIL_SERVER = get_secret(MAIL_SERVER_SECRET_NAME, region_name)
        if MAIL_PORT_SECRET_NAME:
            MAIL_PORT = int(get_secret(MAIL_PORT_SECRET_NAME, region_name))
        if MAIL_USE_TLS_SECRET_NAME:
            MAIL_USE_TLS = get_secret(MAIL_USE_TLS_SECRET_NAME, region_name).lower() == 'true'
        if MAIL_USERNAME_SECRET_NAME:
            MAIL_USERNAME = get_secret(MAIL_USERNAME_SECRET_NAME, region_name)
        if MAIL_PASSWORD_SECRET_NAME:
            MAIL_PASSWORD = get_secret(MAIL_PASSWORD_SECRET_NAME, region_name)
        if MAIL_DEFAULT_SENDER_SECRET_NAME:
            MAIL_DEFAULT_SENDER = get_secret(MAIL_DEFAULT_SENDER_SECRET_NAME, region_name)
        
        logger.info("Retrieved all mail configuration from AWS Secrets Manager")
    except Exception as e:
        logger.error(f"Error retrieving mail configuration: {str(e)}")
        raise e

# Database Configuration
    # Secret Names from environment variables
    DB_NAME_SECRET_NAME = os.getenv('DB_NAME_SECRET_NAME')
    DB_USER_SECRET_NAME = os.getenv('DB_USER_SECRET_NAME')
    DB_PASSWORD_SECRET_NAME = os.getenv('DB_PASSWORD_SECRET_NAME')
    DB_HOST_SECRET_NAME = os.getenv('DB_HOST_SECRET_NAME')
    DB_PORT_SECRET_NAME = os.getenv('DB_PORT_SECRET_NAME')

    # Configure database based on environment
    if FLASK_ENV == 'development':
        # Use hardcoded development database credentials that match Packer setup
        SQLALCHEMY_DATABASE_URI = "postgresql://devuser:password@localhost:5432/devdb"
        logger.info("Using local PostgreSQL database with development credentials")
    else:
        # Production: Use AWS Secrets Manager
        try:
            if all([DB_NAME_SECRET_NAME, DB_USER_SECRET_NAME, DB_PASSWORD_SECRET_NAME, DB_HOST_SECRET_NAME, DB_PORT_SECRET_NAME]):
                DB_NAME = get_secret(DB_NAME_SECRET_NAME, region_name)
                DB_USER = get_secret(DB_USER_SECRET_NAME, region_name)
                DB_PASSWORD = get_secret(DB_PASSWORD_SECRET_NAME, region_name)
                DB_HOST = get_secret(DB_HOST_SECRET_NAME, region_name)
                DB_PORT = get_secret(DB_PORT_SECRET_NAME, region_name)
                logger.info("Retrieved database credentials from AWS Secrets Manager")
                SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
            else:
                raise ValueError("Database secret names are not all set in environment variables")
        except Exception as e:
            logger.error(f"Error retrieving database credentials: {str(e)}")
            raise e

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    print(f"Redis URL: {REDIS_URL}")
    print(f"Session Key Prefix: {SESSION_KEY_PREFIX}")