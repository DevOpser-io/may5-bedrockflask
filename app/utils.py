from datetime import datetime
from .models import db, UserActivity
import boto3
import os
import json
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def log_user_activity(user, activity_type, details=None):
    """
    Log user activity for tracking purposes.
    
    Args:
        user: User model instance
        activity_type: String describing the type of activity
        details: Optional dict containing additional activity details
    """
    act = UserActivity(
        user_id=user.id,
        activity_type=activity_type,
        timestamp=datetime.utcnow(),
        details=details or {}
    )
    db.session.add(act)
    db.session.commit()

def get_secret(secret_string, region_name, secret_type='plain_text'):
    """
    Retrieve a secret from AWS Secrets Manager
    
    Args:
        secret_string (str): Name/ARN of the secret
        region_name (str): AWS region name
        secret_type (str): Type of secret - 'plain_text' or 'json'
    
    Returns:
        Union[str, dict]: The secret value as either a string or dictionary
    """
    secret_name = secret_string
    region_name = region_name
    
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailure':
            logger.error("Secrets Manager can't decrypt the protected secret text using the provided KMS key")
        elif e.response['Error']['Code'] == 'InternalServiceError':
            logger.error("An error occurred on the server side")
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.error("You provided an invalid value for a parameter")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logger.error("You provided a parameter value that is not valid for the current state of the resource")
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.error("We can't find the resource that you asked for")
        else:
            logger.error(f"Unknown error: {e}")
        raise e
    
    secret = get_secret_value_response['SecretString']
    
    if secret_type.lower() == 'json':
        try:
            return json.loads(secret)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse secret as JSON: {e}")
            raise
    
    return secret

def get_additional_secrets():
   """
   Retrieve additional secrets from AWS Secrets Manager using environment variables.
   Provides flexibility for users to store any key-value pairs they need.
   
   Returns:
       dict: The secret values as a dictionary
   
   Raises:
       ValueError: When required environment variables are missing 
       Exception: For other errors during secret retrieval
   """
   try:
       # Get secret name and region from environment variables
       secret_name = os.environ.get('ADDITIONAL_SECRETS')
       region = os.environ.get('REGION')
       
       logger.info(f"Attempting to get secret from region: {region}")
       
       if not secret_name:
           logger.error("Environment variable 'ADDITIONAL_SECRETS' not found")
           raise ValueError("Missing required environment variable 'ADDITIONAL_SECRETS'")
           
       if not region:
           logger.error("Environment variable 'REGION' not found")
           raise ValueError("Missing required environment variable 'REGION'")
           
       # Use the built-in JSON parsing in get_secret
       secrets = get_secret(secret_name, region, 'json')
       
       # Validate the secret is a non-empty dictionary
       if not isinstance(secrets, dict):
           raise ValueError("Secret must be a JSON object (dictionary)")
       
       if not secrets:
           raise ValueError("Secret dictionary cannot be empty")
           
       # Log success without exposing values
       logger.info("Successfully retrieved secrets containing %d keys: %s", 
                  len(secrets), 
                  ', '.join(f"'{k}'" for k in secrets.keys()))
           
       return secrets
       
   except Exception as e:
       # Log error without potentially exposing secret values
       logger.error("Failed to retrieve additional secrets: %s", 
                   str(e).replace(secret_name, '[REDACTED]') if secret_name else str(e))
       raise

# Example usage of get_additional_secrets
# If your secret looks like this:
# {
#   awsSeamlessDomainUsername = "service_account"
#   awsSeamlessDomainPassword = "Password123!"
#   awsSeamlessDomainDirectoryId = "d-a1b2c3d4e5"
#   directoryServiceSecretVersion = "1"
#   schemaVersion = "1.0"
# }

# try:
#     domain_creds = get_additional_secrets()
    
#     # Access fields from your specific secret structure
#     username = domain_creds['awsSeamlessDomainUsername']  # will be "service_account"
#     password = domain_creds['awsSeamlessDomainPassword']  # will be "Password123!"
#     directory_id = domain_creds['awsSeamlessDomainDirectoryId']  # will be "d-a1b2c3d4e5"
#     version = domain_creds['directoryServiceSecretVersion']  # will be 1
#     schema = domain_creds['schemaVersion']  # will be "1.0"
    
#     print(f"Successfully retrieved credentials for user: {username}")
#     print(f"Using directory ID: {directory_id}")
#     print(f"Schema version: {schema}")
        
# except Exception as e:
#     print(f"Error retrieving additional secrets: {e}")