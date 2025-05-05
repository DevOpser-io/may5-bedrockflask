#app/auth.py
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from flask_wtf.csrf import generate_csrf
from flask_wtf import FlaskForm
from .models import User, Conversation
from . import db
import time
import logging
from datetime import datetime, timedelta, timezone
import io
import base64
from flask_mail import Mail, Message
import secrets
import pyotp
import segno
import ntplib
from functools import wraps
from .utils import log_user_activity

logger = logging.getLogger(__name__)
auth = Blueprint('auth', __name__)
mail = Mail()

def rate_limit_emails(user):
    """Rate limit email sending to prevent abuse"""
    if user.email_verification_sent_at:
        time_since_last_email = datetime.utcnow() - user.email_verification_sent_at
        if time_since_last_email < timedelta(minutes=2):  # 2 minute cooldown
            remaining = timedelta(minutes=2) - time_since_last_email
            raise ValueError(f"Please wait {int(remaining.total_seconds())} seconds before requesting another email.")

def rate_limit_mfa_codes(user):
    """Rate limiting specifically for MFA codes"""
    redis_client = current_app.config['REDIS_CLIENT']
    cache_version = current_app.config['CACHE_VERSION']
    rate_limit_key = f"mfa_rate_limit:{cache_version}:{user.id}"
    
    # Check if rate limit exists
    last_mfa_time = redis_client.get(rate_limit_key)
    if last_mfa_time:
        time_since_last = int(time.time()) - int(last_mfa_time)
        if time_since_last < 120:  # 120-second cooldown
            raise ValueError(f"Please wait {120 - time_since_last} seconds before requesting another code.")
    
    # Set new rate limit with extended expiration
    redis_client.setex(rate_limit_key, 300, int(time.time()))  # 5 minute key expiration

def send_verification_email(user):
    """Send email verification link to user"""
    try:
        rate_limit_emails(user)
        token = secrets.token_urlsafe()
        user.email_verification_token = token
        user.email_verification_sent_at = datetime.utcnow()
        db.session.commit()

        verification_url = url_for('auth.verify_email', 
                                 token=token, 
                                 _external=True,
                                 _scheme=current_app.config['PREFERRED_URL_SCHEME'])
        
        msg = Message('Verify your email for <FlaskAI Demo App>',
                     recipients=[user.email])
        msg.body = f'''Thanks for signing up for <FlaskAI Demo App>!

Please click the following verification link to confirm your email address and log in:
{verification_url}

If you did not request this email, please ignore it.'''
        
        logger.info(f"Attempting to send verification email to: {user.email}")
        logger.info(f"Verification URL: {verification_url}")
        mail.send(msg)
        logger.info("Verification email sent successfully")
        
    except Exception as e:
        logger.error(f"Failed to send verification email: {str(e)}")
        db.session.rollback()
        raise e

def send_mfa_code_email(user):
    """Dedicated function for sending MFA codes"""
    logger.info(f"Starting send_mfa_code_email for user {user.email}")
    
    if not user.mfa_secret:
        logger.error("User has no MFA secret")
        raise ValueError("MFA not properly configured")
        
    try:
        totp = pyotp.TOTP(user.mfa_secret)
        synced_time = current_app.config.get('SYNCED_TIME')
        
        if not synced_time:
            logger.warning("No synced time available, syncing now")
            synced_time = sync_time()
            
        token = totp.at(synced_time)
        logger.info(f"Generated TOTP token using time: {synced_time}")
        
        msg = Message('Your MFA Code',
                     sender=current_app.config['MAIL_DEFAULT_SENDER'],
                     recipients=[user.email])
        msg.body = f'''Your verification code is: {token}

This code will expire in 120 seconds. If the code doesn't work, please request a new one.'''

        # Add retry logic for email sending
        max_retries = 3
        for attempt in range(max_retries):
            try:
                mail.send(msg)
                logger.info(f"Email sent successfully to {user.email}")
                return
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                logger.warning(f"Email send attempt {attempt + 1} failed: {str(e)}")
                time.sleep(1)
                
    except Exception as e:
        logger.error(f"Error in send_mfa_code_email: {str(e)}", exc_info=True)
        raise

def sync_time():
    """Sync server time with NTP"""
    try:
        ntp_client = ntplib.NTPClient()
        response = ntp_client.request('pool.ntp.org', version=3)
        synced_time = datetime.fromtimestamp(response.tx_time, timezone.utc)
        logger.info(f"NTP sync successful. Synced time: {synced_time}")
        return synced_time
    except Exception as e:
        logger.error(f"NTP sync failed: {str(e)}")
        current_time = datetime.now(timezone.utc)
        logger.warning(f"Using system time instead: {current_time}")
        return current_time

def with_synchronized_time(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_app.config['SYNCED_TIME'] = sync_time()
        logger.info(f"Using synchronized time: {current_app.config['SYNCED_TIME']}")
        logger.info(f"Current UTC time: {datetime.now(timezone.utc)}")
        return f(*args, **kwargs)
    return decorated_function

def send_mfa_email(user):
    """Send MFA code via email"""
    logger.info(f"Starting send_mfa_email for user {user.email}")
    try:
        if not user.mfa_secret:
            logger.error("User has no MFA secret")
            raise ValueError("MFA not properly configured")
            
        totp = pyotp.TOTP(user.mfa_secret)
        synced_time = current_app.config.get('SYNCED_TIME')
        if synced_time:
            token = totp.at(synced_time)
            logger.info(f"Generated TOTP token using synced time: {synced_time}")
        else:
            token = totp.now()
            logger.info("Generated TOTP token using current time")
            
        logger.info(f"Generated TOTP token for user with secret hash: {hash(user.mfa_secret)}")
        
        msg = Message('Your MFA Code',
                     sender=current_app.config['MAIL_DEFAULT_SENDER'],
                     recipients=[user.email])
        msg.body = f'''Your verification code is: {token}

This code will expire in 30 seconds.'''

        logger.info(f"About to send email to {user.email}")
        mail.send(msg)
        logger.info(f"Email sent successfully to {user.email}")
        
    except Exception as e:
        logger.error(f"Error in send_mfa_email: {str(e)}", exc_info=True)
        raise

def send_mfa_email_old(user):
    """Send MFA code via email"""
    logger.info(f"Starting send_mfa_email for user {user.email}")
    try:
        if not user.mfa_secret:
            logger.error("User has no MFA secret")
            raise ValueError("MFA not properly configured")
            
        totp = pyotp.TOTP(user.mfa_secret)
        token = totp.now()
        logger.info(f"Generated TOTP token for user")
        
        msg = Message('Your MFA Code',
                     sender=current_app.config['MAIL_DEFAULT_SENDER'],
                     recipients=[user.email])
        msg.body = f'''Your verification code is: {token}

This code will expire in 30 seconds.'''

        logger.info(f"About to send email to {user.email}")
        mail.send(msg)
        logger.info(f"Email sent successfully to {user.email}")
        
    except Exception as e:
        logger.error(f"Error in send_mfa_email: {str(e)}", exc_info=True)
        raise

def send_password_reset_email(user):
    """Send password reset link to user."""
    token = secrets.token_urlsafe()
    user.password_reset_token = token
    user.password_reset_sent_at = datetime.utcnow()
    db.session.commit()

    reset_url = url_for('auth.reset_password', token=token, _external=True)

    msg = Message('Reset Your Password',
                  recipients=[user.email])
    msg.body = f'''You requested a password reset.

Please click the following link to reset your password:
{reset_url}

If you did not request this, please ignore this email.
'''
    mail.send(msg)
    logger.info(f"Password reset email sent to: {user.email}")

@auth.route('/login')
def login():
    form = FlaskForm()  # Create a form instance for CSRF
    return render_template('login.html', form=form)

@auth.route('/login', methods=['POST'])
def login_post():
    """Handle login form submission"""
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # Check if user exists and password is correct
    if not user or not check_password_hash(user.password_hash, password):
        flash('Please check your login details and try again.', 'error')
        return redirect(url_for('auth.login'))

    # Check if email is verified
    if not user.email_verified:
        flash('Please verify your email before logging in.', 'error')
        return redirect(url_for('auth.login'))

    # Check MFA status
    if not user.is_mfa_setup_complete:
        # First time login needs MFA setup
        login_user(user, remember=False)
        flash('Please set up two-factor authentication to secure your account.', 'info')
        return redirect(url_for('auth.setup_authenticator'))
    else:
        # Regular login flow with email/authenticator verification
        session['mfa_user_id'] = user.id
        session['remember_me'] = remember
        
        if user.has_authenticator:
            return redirect(url_for('auth.mfa_verify', method='authenticator'))
        else:
            return redirect(url_for('auth.mfa_verify', method='email'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    # Password validation
    if len(password) < 8:
        flash('Password must be at least 8 characters long', 'error')
        return redirect(url_for('auth.signup'))
        
    if len(password) > 72:
        flash('Password must be less than 72 characters long', 'error')
        return redirect(url_for('auth.signup'))

    # Email validation
    if len(email) > 100:
        flash('Email address is too long', 'error')
        return redirect(url_for('auth.signup'))

    # Name validation
    if len(name) > 1000:
        flash('Name is too long', 'error')
        return redirect(url_for('auth.signup'))

    user = User.query.filter_by(email=email).first()
    if user:
        flash('Email address already exists', 'error')
        return redirect(url_for('auth.signup'))

    new_user = User(
        email=email,
        name=name
    )
    new_user.set_password(password)
    new_user.generate_mfa_secret()

    db.session.add(new_user)
    db.session.commit()

    # Send verification email
    try:
        send_verification_email(new_user)
        flash('Please check your email to verify your account before logging in.', 'info')
    except Exception as e:
        logger.error(f"Failed to send verification email: {str(e)}")
        flash('Account created but verification email could not be sent. Please request a new verification email.', 'warning')

    return redirect(url_for('auth.login'))

@auth.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(email_verification_token=token).first()
    
    if user and user.email_verification_sent_at:
        if datetime.utcnow() - user.email_verification_sent_at < timedelta(hours=24):
            user.email_verified = True
            user.email_verification_token = None
            db.session.commit()
            flash('Email verified successfully! You can now log in.', 'success')
        else:
            flash('Verification link has expired. Please request a new one.', 'error')
    else:
        flash('Invalid verification link.', 'error')
    
    return redirect(url_for('auth.login'))

@auth.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please provide your email address.', 'error')
            return redirect(url_for('auth.resend_verification'))
        
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found with that email address.', 'error')
            return redirect(url_for('auth.resend_verification'))
            
        if user.email_verified:
            flash('Email is already verified. Please log in.', 'info')
            return redirect(url_for('auth.login'))
            
        # Send new verification email
        try:
            send_verification_email(user)
            flash('Verification email has been resent. Please check your inbox.', 'success')
            return redirect(url_for('auth.login'))
        except ValueError as e:
            flash(str(e), 'error')
        except Exception as e:
            logger.error(f"Failed to resend verification email: {str(e)}")
            flash('Failed to send verification email. Please try again later.', 'error')
    
    return render_template('resend_verification.html')

@auth.route('/mfa-verify/<method>', methods=['GET', 'POST'])
@with_synchronized_time
def mfa_verify(method):
    logger.info(f"mfa_verify called with method: {method}, request method: {request.method}")
    
    if request.method == 'POST':
        logger.info(f"Form data: {request.form}")
        action = request.form.get('action')
        token = request.form.get('token')
        backup_code = request.form.get('backup_code')
        logger.info(f"Action: {action}, Token present: {bool(token)}, Backup code present: {bool(backup_code)}")
        
        if action == 'send_code':
            try:
                user = User.query.get(session['mfa_user_id'])
                logger.info(f"Sending MFA code to: {user.email if user else 'No user found'}")
                
                if not user:
                    logger.error("No user found in session")
                    flash('Please log in again.', 'error')
                    return redirect(url_for('auth.login'))
                
                send_mfa_email(user)
                flash('A verification code has been sent to your email.', 'success')
                return redirect(url_for('auth.mfa_verify', method=method, active_tab='email'))
                
            except Exception as e:
                logger.error(f"Failed to send MFA code: {str(e)}", exc_info=True)
                flash('Failed to send verification code. Please try again.', 'error')
                return redirect(url_for('auth.mfa_verify', method=method, active_tab='email'))
        
        if not token and not backup_code:
            logger.error("No verification token provided")
            flash('Please enter a verification code.', 'error')
            active_tab = 'backup' if request.form.get('backup_code') is not None else 'email' if method == 'email' else 'authenticator'
            return redirect(url_for('auth.mfa_verify', method=method, active_tab=active_tab))
            
        user = User.query.get(session['mfa_user_id'])
        if not user:
            logger.error("No user found in session during verification")
            flash('Please log in again.', 'error')
            return redirect(url_for('auth.login'))
            
        if backup_code:
            logger.info("Attempting backup code verification")
            if user.verify_backup_code(backup_code):
                logger.info("Backup code verification successful")
                login_user(user, remember=session.get('remember_me', False))
                session.pop('mfa_user_id', None)
                session.pop('remember_me', None)
                return redirect(url_for('routes_bp.chat_page'))
            logger.error("Invalid backup code used")
            flash('Invalid backup code.', 'error')
            return redirect(url_for('auth.mfa_verify', method=method, active_tab='backup'))
            
        try:
            logger.info("Attempting TOTP verification")
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(token, valid_window=2, for_time=current_app.config['SYNCED_TIME']):
                logger.info("TOTP verification successful")
                login_user(user, remember=session.get('remember_me', False))
                user.last_login = datetime.utcnow()
                log_user_activity(user, 'login', {'ip': request.remote_addr})
                session.pop('mfa_user_id', None)
                session.pop('remember_me', None)
                return redirect(url_for('routes_bp.chat_page'))
            else:
                logger.error(f"Invalid TOTP token: {token}")
                flash('Invalid verification code. Please try again.', 'error')
                active_tab = 'email' if method == 'email' else 'authenticator'
                return redirect(url_for('auth.mfa_verify', method=method, active_tab=active_tab))
        except Exception as e:
            logger.error(f"MFA verification error: {str(e)}", exc_info=True)
            flash('An error occurred during verification. Please try again.', 'error')
            active_tab = 'email' if method == 'email' else 'authenticator'
            return redirect(url_for('auth.mfa_verify', method=method, active_tab=active_tab))
    
    # GET request handling
    user = User.query.get(session.get('mfa_user_id'))
    if not user:
        logger.error("No user found in session for GET request")
        flash('Please log in again.', 'error')
        return redirect(url_for('auth.login'))
    
    # Set initial active tab based on method
    active_tab = request.args.get('active_tab', 'email' if method == 'email' else 'authenticator')
    return render_template('mfa_verify.html', method=method, active_tab=active_tab)

@auth.route('/send-mfa-code', methods=['POST'])
@with_synchronized_time
def send_mfa_code():
    """Dedicated endpoint for sending MFA codes"""
    logger.info("=== Starting send_mfa_code ===")
    
    try:
        # Get user either from current_user or session
        user = None
        if current_user.is_authenticated:
            user = current_user
            logger.info(f"Using authenticated user: {user.email}")
        else:
            user_id = session.get('mfa_user_id')
            if user_id:
                user = User.query.get(user_id)
                logger.info(f"Using session user: {user.email if user else None}")

        if not user:
            logger.error("No user found in session or authentication")
            return jsonify({
                'success': False,
                'message': 'Please log in again.'
            }), 401

        # Use MFA-specific rate limiting
        try:
            rate_limit_mfa_codes(user)
        except ValueError as e:
            logger.warning(f"Rate limit exceeded for user {user.email}: {str(e)}")
            return jsonify({
                'success': False,
                'message': str(e)
            }), 429

        # Ensure user has MFA secret
        if not user.mfa_secret:
            if current_user.is_authenticated:
                # During setup, generate new secret if needed
                user.generate_mfa_secret()
                db.session.commit()
                logger.info(f"Generated new MFA secret for {user.email}")
            else:
                logger.error(f"User {user.email} missing MFA secret during verification")
                return jsonify({
                    'success': False,
                    'message': 'Invalid MFA configuration. Please contact support.'
                }), 400

        # Send the code using MFA-specific function
        send_mfa_code_email(user)
        logger.info(f"Successfully sent MFA code to {user.email}")
        
        return jsonify({
            'success': True,
            'message': 'A verification code has been sent to your email.'
        })

    except Exception as e:
        logger.error(f"Error in send_mfa_code: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': 'Failed to send verification code. Please try again.'
        }), 500

@auth.route('/mfa-setup', methods=['GET', 'POST'])
@login_required
@with_synchronized_time
def mfa_setup():
    form = FlaskForm()
    
    if request.method == 'POST':
        logger.debug(f"MFA Setup POST request received")
        logger.debug(f"Headers: {dict(request.headers)}")
        logger.debug(f"Form data: {dict(request.form)}")
        
        # If this is an AJAX request for sending code
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            logger.debug("Processing AJAX request for MFA code")
            try:
                # Send the MFA code
                logger.debug(f"Sending MFA code to user: {current_user.email}")
                send_mfa_email(current_user)
                logger.info(f"Successfully sent MFA code to {current_user.email}")
                
                return jsonify({
                    'success': True,
                    'message': 'A verification code has been sent to your email.'
                })
            except Exception as e:
                logger.error(f"Failed to send MFA code: {str(e)}", exc_info=True)
                return jsonify({
                    'success': False,
                    'message': 'Failed to send verification code. Please try again.'
                }), 500
        
        # Handle verification code submission
        verification_code = request.form.get('verification_code')
        if verification_code:
            logger.debug("Processing verification code submission")
            try:
                logger.info(f"Verifying TOTP token for user {current_user.email}")
                
                totp = pyotp.TOTP(current_user.mfa_secret)
                synced_time = current_app.config.get('SYNCED_TIME')
                
                # Try with exact time first
                verified = totp.verify(verification_code, for_time=synced_time)
                if not verified:
                    # If exact time fails, try with a window
                    verified = totp.verify(verification_code, valid_window=2, for_time=synced_time)
                    if verified:
                        logger.info("Verification succeeded with extended window")
                    else:
                        expected_token = totp.at(synced_time)
                        logger.error(f"Verification failed. Expected: {expected_token}, Got: {verification_code}")
                
                if verified:
                    current_user.mfa_enabled = True
                    current_user.preferred_mfa_method = request.form.get('mfa_method', 'email')
                    backup_codes = current_user.generate_backup_codes(count=8)
                    db.session.commit()
                    logger.info(f"MFA setup successful for user {current_user.email}")
                    return render_template('backup_codes.html', backup_codes=backup_codes)
                
                flash('Invalid verification code. Please try again.', 'error')
                return redirect(url_for('auth.mfa_setup'))
                
            except Exception as e:
                logger.error(f"Error during MFA verification: {str(e)}", exc_info=True)
                flash('An error occurred during MFA setup. Please try again.', 'error')
                return redirect(url_for('auth.mfa_setup'))

    # Generate new MFA secret if not exists
    if not current_user.mfa_secret:
        current_user.generate_mfa_secret()
        db.session.commit()

    # Generate QR code using the model's method
    provisioning_uri = current_user.get_mfa_uri()
    qr = segno.make(provisioning_uri)
    buffer = io.BytesIO()
    qr.save(buffer, kind='svg', scale=4)
    qr_svg = buffer.getvalue().decode('utf-8')

    return render_template('mfa_setup.html',
                         mfa_secret=current_user.mfa_secret,
                         qr_svg=qr_svg,
                         form=form)

@auth.route('/setup-authenticator', methods=['GET', 'POST'])
@login_required
@with_synchronized_time
def setup_authenticator():
    form = FlaskForm()
    
    if request.method == 'POST':
        verification_code = request.form.get('verification_code')
        if verification_code:
            try:
                totp = pyotp.TOTP(current_user.mfa_secret)
                synced_time = current_app.config.get('SYNCED_TIME')
                
                # Try with exact time first, then with window
                verified = totp.verify(verification_code, for_time=synced_time) or \
                          totp.verify(verification_code, valid_window=2, for_time=synced_time)
                
                if verified:
                    current_user.has_authenticator = True
                    current_user.mfa_enabled = True
                    current_user.is_mfa_setup_complete = True
                    current_user.preferred_mfa_method = 'authenticator'
                    backup_codes = current_user.generate_backup_codes(count=8)
                    db.session.commit()
                    flash('Authenticator app setup successful!', 'success')
                    return render_template('backup_codes.html', backup_codes=backup_codes)
                
                flash('Invalid verification code. Please try again.', 'error')
                return redirect(url_for('auth.setup_authenticator'))
                
            except Exception as e:
                logger.error(f"Error during authenticator setup: {str(e)}", exc_info=True)
                flash('An error occurred during setup. Please try again.', 'error')
                return redirect(url_for('auth.setup_authenticator'))

    # Generate new MFA secret if not exists
    if not current_user.mfa_secret:
        current_user.generate_mfa_secret()
        db.session.commit()

    # Generate QR code
    provisioning_uri = current_user.get_mfa_uri()
    qr = segno.make(provisioning_uri)
    buffer = io.BytesIO()
    qr.save(buffer, kind='svg', scale=5)
    qr_svg = buffer.getvalue().decode('utf-8')

    return render_template('mfa_setup.html',
                         mfa_secret=current_user.mfa_secret,
                         qr_svg=qr_svg,
                         form=form)

@auth.route('/remove-authenticator', methods=['POST'])
@login_required
def remove_authenticator():
    try:
        current_user.has_authenticator = False
        current_user.preferred_mfa_method = 'email'  # Default back to email
        # Don't touch is_mfa_setup_complete - they've already done initial setup
        current_user.mfa_secret = None
        current_user.backup_codes = None
        db.session.commit()
        flash('Authenticator app removed successfully.', 'success')
    except Exception as e:
        logger.error(f"Error removing authenticator: {str(e)}", exc_info=True)
        flash('An error occurred while removing the authenticator.', 'error')
    
    return redirect(url_for('auth.account'))

@auth.route('/account')
@login_required
def account():
    """Account settings page for managing MFA and other user settings"""
    form = FlaskForm()  # Add form for CSRF protection
    return render_template('account.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        log_user_activity(current_user, 'logout', {'ip': request.remote_addr})
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth.route('/conversation/<conversation_id>/logout')
@login_required
def conversation_logout(conversation_id):
    # Get conversation ID before logout
    conversation_id = session.get('conversation_id')

    try:
        if conversation_id:
            # Get Redis client from app context
            redis_client = current_app.config.get('REDIS_CLIENT')
            if redis_client:
                # Get cache version from config
                cache_version = current_app.config.get('CACHE_VERSION')
                # Delete chat history
                chat_key = f"chat:{cache_version}:{conversation_id}"
                redis_client.delete(chat_key)
                logger.info(f"Cleaned up Redis chat data for conversation {conversation_id}")

                # Also delete any stream-related keys
                stream_key = f"stream:{cache_version}:{conversation_id}"
                redis_client.delete(stream_key)
                logger.info(f"Cleaned up Redis stream data for conversation {conversation_id}")

    except Exception as e:
        logger.error(f"Error cleaning up Redis on logout: {str(e)}", exc_info=True)

    finally:
        # Always perform these cleanup actions
        try:
            # Mark conversation as ended in database
            conversation = Conversation.query.filter_by(
                conversation_id=conversation_id
            ).first()
            
            if conversation:
                conversation.ended_at = datetime.utcnow()
                db.session.commit()
                logger.info(f"Marked conversation {conversation_id} as ended")

        except Exception as e:
            logger.error(f"Error updating conversation end time: {str(e)}", exc_info=True)
        
        # Always perform logout and session cleanup
        logout_user()
        session.clear()
        
        return redirect(url_for('routes_bp.index'))

@auth.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            try:
                send_password_reset_email(user)
                flash('If that email exists in our system, we have sent a reset link.', 'info')
            except Exception as e:
                logger.error(f"Error sending password reset email: {str(e)}")
                flash('Failed to send reset link. Please try again later.', 'error')
        else:
            # We do not say "no user" to avoid enumerating emails
            flash('If that email exists in our system, we have sent a reset link.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('forgot_password.html')

@auth.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(password_reset_token=token).first()

    if not user:
        flash('Invalid or expired password reset token.', 'error')
        return redirect(url_for('auth.login'))

    # Check if token expired (24 hours)
    if user.password_reset_sent_at and (datetime.utcnow() - user.password_reset_sent_at > timedelta(hours=24)):
        flash('Password reset link has expired. Please request a new one.', 'error')
        user.password_reset_token = None
        user.password_reset_sent_at = None
        db.session.commit()
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Please fill out both password fields.', 'error')
            return redirect(url_for('auth.reset_password', token=token))

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('auth.reset_password', token=token))

        if len(new_password) < 8 or len(new_password) > 72:
            flash('Password must be between 8 and 72 characters.', 'error')
            return redirect(url_for('auth.reset_password', token=token))

        # Update user's password
        user.set_password(new_password)
        user.password_reset_token = None
        user.password_reset_sent_at = None
        db.session.commit()

        flash('Your password has been reset. Please log in with your new password.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token)