from flask import Blueprint, redirect, url_for, flash, render_template, request, current_app, jsonify
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
from sqlalchemy import desc
from wtforms.fields import PasswordField
from flask_admin.form import rules
import pyotp
from markupsafe import Markup
from functools import wraps

from .models import db, User, UserActivity, Subscription

admin_bp = Blueprint('admin_routes', __name__, url_prefix='/admin')

def admin_required(f):
    @login_required
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You need to be an administrator to access this page.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        flash('You need to be an administrator to access this page.', 'error')
        return redirect(url_for('auth.login'))

class SecureIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not (current_user.is_authenticated and current_user.is_admin):
            return redirect(url_for('auth.login'))
        
        # Example metrics
        user_count = User.query.count()
        active_subscriptions = Subscription.query.filter_by(status='active').count()
        recent_signups = User.query.order_by(User.created_at.desc()).limit(5).all()

        return self.render('admin/dashboard.html', 
                           user_count=user_count, 
                           active_subscriptions=active_subscriptions,
                           recent_signups=recent_signups)

class UserModelView(SecureModelView):
    column_exclude_list = ['password_hash', 'mfa_secret']
    column_searchable_list = ['email']
    column_sortable_list = ['email', 'created_at', 'last_login']
    column_filters = ['is_admin', 'is_active', 'email_verified', 'created_at', 'last_login']
    form_excluded_columns = ['password_hash', 'activity', 'subscription', 'mfa_secret', 'backup_codes',
                           'email_verification_token', 'email_verification_sent_at', 'password_reset_token',
                           'password_reset_sent_at', 'conversation']
    
    # Add password field that's not tied to model
    form_extra_fields = {
        'password': PasswordField('New Password (leave empty to keep current)')
    }
    
    form_widget_args = {
        'created_at': {'readonly': True},
        'last_login': {'readonly': True}
    }
    
    column_labels = {
        'email': 'Email Address',
        'is_admin': 'Administrator',
        'is_active': 'Active',
        'email_verified': 'Email Verified',
        'created_at': 'Created At',
        'last_login': 'Last Login',
        'mfa_enabled': 'MFA Enabled',
        'has_authenticator': 'Has Authenticator'
    }
    
    can_edit = True
    # Only allow inline editing for safe fields
    column_editable_list = ['is_active', 'email_verified', 'is_admin']

    def on_model_change(self, form, model, is_created):
        # Only handle password if it's a full form edit (not inline edit)
        if hasattr(form, 'password'):
            if form.password.data:
                model.password_hash = generate_password_hash(form.password.data.strip())
            # Require password only for new users
            elif is_created and not model.password_hash:
                raise ValueError("Password is required for new users")
        
        # Ensure required fields are set for new users
        if is_created:
            model.is_active = True if model.is_active is None else model.is_active
            model.created_at = datetime.utcnow()
            
            # If email is verified, ensure MFA setup is properly initialized
            if model.email_verified and not model.is_mfa_setup_complete:
                model.is_mfa_setup_complete = False
                model.mfa_enabled = False
                model.mfa_secret = None

    def after_model_change(self, form, model, is_created):
        # Log the admin action
        activity_type = 'admin_user_create' if is_created else 'admin_user_update'
        details_str = f'User {"created" if is_created else "updated"} by admin'
        if hasattr(form, 'password') and form.password.data:
            details_str += ' (password changed)'
        
        # Create UserActivity record using SQLAlchemy
        activity = UserActivity(
            user_id=model.id,
            activity_type=activity_type,
            details={'message': details_str},
            timestamp=datetime.utcnow()
        )
        db.session.add(activity)
        db.session.commit()

class UserActivityModelView(SecureModelView):
    column_list = ['user.email', 'activity_type', 'timestamp', 'details']
    column_searchable_list = ['activity_type']  
    column_filters = ['timestamp', 'activity_type', 'user.email']
    column_labels = {
        'user.email': 'User Email',
        'activity_type': 'Activity Type',
        'timestamp': 'Time',
        'details': 'Details'
    }
    can_create = False
    can_edit = False
    can_delete = False

class SubscriptionModelView(SecureModelView):
    column_searchable_list = ['stripe_subscription_id', 'status', 'plan_id']
    column_filters = ['status', 'created_at', 'current_period_end']
    column_labels = {
        'user.email': 'User Email',
        'stripe_subscription_id': 'Stripe ID',
        'status': 'Status',
        'plan_id': 'Plan',
        'current_period_end': 'Period End',
    }
    form_excluded_columns = ['created_at']
    can_create = False

def init_admin(app):
    # Initialize Flask-Admin
    admin = Admin(
        app,
        name='FlaskAI Portal Admin',
        template_mode='bootstrap4',
        index_view=SecureIndexView(),
        base_template='admin/admin_custom_base.html'
    )
    
    admin.add_view(UserModelView(User, db.session, name='Users', endpoint='user', category='User Management'))
    admin.add_view(UserActivityModelView(UserActivity, db.session, name='User Activity', endpoint='useractivity', category='User Management'))
    admin.add_view(SubscriptionModelView(Subscription, db.session, name='Subscriptions', endpoint='subscription', category='Billing'))

    return admin

@admin_bp.route('/dashboard', endpoint='dashboard')
@admin_required
def dashboard():
    current_app.logger.debug('Dashboard route accessed')
    current_app.logger.debug(f'User accessing dashboard: {current_user.email if current_user else "No user"}')
    current_app.logger.debug(f'User is admin: {current_user.is_admin if current_user else False}')
    return render_template('admin/dashboard.html')

@admin_bp.route('/users', endpoint='users')
@admin_required
def user_list():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    users = User.query.paginate(page=page, per_page=per_page)
    return render_template('admin/users.html', users=users)

@admin_bp.route('/settings', methods=['GET', 'POST'], endpoint='settings')
@admin_required
def admin_settings():
    if request.method == 'POST':
        current_app.config['ALLOW_SIGNUP'] = request.form.get('allow_signup') == 'true'
        flash('Settings updated successfully.', 'success')
    return render_template('admin/settings.html')

@admin_bp.route('/users/<int:user_id>/mfa', methods=['POST'], endpoint='toggle_mfa')
@admin_required
def toggle_user_mfa(user_id):
    user = User.query.get_or_404(user_id)
    require_mfa = request.json.get('require_mfa', False)
    user.mfa_enabled = require_mfa
    if require_mfa and not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
    return jsonify({'status': 'success'})