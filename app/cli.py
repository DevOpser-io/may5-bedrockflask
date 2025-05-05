import click
from flask import current_app
from app.models import db, User
from app.utils import get_secret
from flask.cli import with_appcontext

@click.command('init-admin-users')
@with_appcontext
def init_admin_users():
    """Initialize admin users from AWS Secrets Manager."""
    region = current_app.config.get('AWS_REGION')
    secret_name = current_app.config.get('ADMIN_USERS_SECRET_NAME')
    
    if not secret_name:
        click.echo("ERROR: ADMIN_USERS_SECRET_NAME not set.")
        exit(1)
    
    # Retrieve and parse secret
    admin_secret = get_secret(secret_name, region)
    import json
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
