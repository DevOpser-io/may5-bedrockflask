import click
from flask.cli import with_appcontext
from flask import current_app
from .models import db, User
from datetime import datetime
from .utils import get_secret
import os
import json

def init_cli(app):
    app.cli.add_command(create_admin)
    app.cli.add_command(init_admin_users)

@click.command('create-admin')
@click.option('--email', prompt='Admin email', help='Email address for the admin user')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Password for the admin user')
@click.option('--env', default='development', help='Environment (development/production)')
@with_appcontext
def create_admin(email, password, env):
    """Create an admin user."""
    try:
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if existing_user.is_admin:
                click.echo(f'Admin user {email} already exists!')
                return
            # Convert existing user to admin while preserving other attributes
            existing_user.is_admin = True
            existing_user.set_password(password)
            existing_user.updated_at = datetime.utcnow()  # Track when the user was upgraded
            db.session.commit()
            click.echo(f'Existing user {email} has been upgraded to admin!')
            return

        # Create new admin user
        user = User(
            email=email,
            is_admin=True,
            is_active=True,
            created_at=datetime.utcnow(),
            last_login=None
        )
        user.set_password(password)
        
        # Add and commit to database
        db.session.add(user)
        db.session.commit()
        
        click.echo(f'Admin user {email} created successfully!')

    except Exception as e:
        db.session.rollback()
        click.echo(f'Error creating admin user: {str(e)}', err=True)
        raise

# For use in production/Kubernetes environment
def create_admin_user(email, password):
    """
    Programmatically create an admin user.
    This function can be called from scripts or Kubernetes init containers.
    """
    try:
        from flask import current_app
        with current_app.app_context():
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                if not existing_user.is_admin:
                    existing_user.is_admin = True
                    existing_user.set_password(password)
                    existing_user.updated_at = datetime.utcnow()
                    db.session.commit()
                return True

            user = User(
                email=email,
                is_admin=True,
                is_active=True,
                created_at=datetime.utcnow()
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return True
    except Exception as e:
        db.session.rollback()
        print(f"Error creating admin user: {str(e)}")
        return False

@click.command('init-admin-users')
@with_appcontext
def init_admin_users():
    """Initialize admin users from AWS Secrets Manager."""
    region = current_app.config.get('AWS_REGION')
    secret_name = current_app.config.get('ADMIN_USERS_SECRET_NAME')
    
    if not secret_name:
        click.echo("ERROR: ADMIN_USERS_SECRET_NAME not set.")
        exit(1)
    
    if not region:
        click.echo("ERROR: AWS_REGION not set.")
        exit(1)
    
    # Retrieve and parse secret
    admin_secret = get_secret(secret_name, region)
    try:
        secret_data = json.loads(admin_secret)
        admin_users = secret_data.get('admin_users', [])
        if not isinstance(admin_users, list):
            click.echo("ERROR: 'admin_users' should be a JSON array.")
            exit(1)
    except json.JSONDecodeError as e:
        click.echo(f"ERROR: Failed to decode JSON: {e}")
        exit(1)
    
    # Create users if they don't exist
    for u in admin_users:
        email = u.get('email')
        password = u.get('password')
        if not (email and password):
            click.echo(f"Skipping invalid user entry: {u}")
            continue
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            click.echo(f"User {email} already exists, skipping...")
            continue
        
        # Create user
        new_user = User(email=email)
        new_user.set_password(password)
        new_user.is_admin = True
        db.session.add(new_user)
        db.session.commit()
        click.echo(f"Created admin user: {email}")
    
    click.echo("Admin user creation completed successfully.")
