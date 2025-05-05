from flask import (
    Blueprint,
    render_template,
    request,
    Response,
    stream_with_context,
    jsonify,
    current_app,
    session,
    g,
    redirect,
    url_for
)
from flask_login import login_required, current_user
import json
from prometheus_client import Summary, Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
import time
import boto3
from botocore.exceptions import ClientError
import uuid
import redis
import logging
import asyncio
import os
from pathlib import Path
from . import db
from .models import Conversation
from datetime import datetime, timedelta, date
import hashlib
from .utils import *
from config import Config


# Create a Blueprint
routes_bp = Blueprint('routes_bp', __name__)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize metrics
call_metric = Counter('flaskai_monitor_home_count', 'Number of visits to FlaskAI', ["service", "endpoint"])
time_metric = Summary('flaskai_monitor_request_processing_seconds', 'Time spent processing request', ["method"])

# Create metric labels after defining the metrics
index_timer = time_metric.labels(method="index")
index_visitor_count = call_metric.labels(service="devopseraidemo", endpoint="index")

# Constants
CHAT_HISTORY_TTL = 3600  # Still useful for cleanup purposes

def get_redis_client():
    return current_app.config['REDIS_CLIENT']

def get_chat_history(conversation_id):
    """Get chat history from Redis"""
    try:
        redis_client = current_app.config['REDIS_CLIENT']
        cache_version = current_app.config['CACHE_VERSION']
        redis_key = f"chat:{cache_version}:{conversation_id}"
        
        logger.info(f"[CHAT_HISTORY] Attempting to get chat history for conversation {conversation_id}")
        logger.debug(f"[CHAT_HISTORY] Using Redis key: {redis_key}")
        
        chat_history_json = redis_client.get(redis_key)
        
        if chat_history_json:
            history = json.loads(chat_history_json)
            logger.info(f"[CHAT_HISTORY] Successfully loaded history for {conversation_id}, length: {len(history)}")
            logger.debug(f"[CHAT_HISTORY] Full history content: {json.dumps(history, indent=2)}")
            return history
        else:
            logger.info(f"[CHAT_HISTORY] No existing history found for conversation {conversation_id}")
            
    except json.JSONDecodeError as je:
        logger.error(f"[CHAT_HISTORY] JSON decode error for {conversation_id}: {str(je)}")
    except redis.RedisError as re:
        logger.error(f"[CHAT_HISTORY] Redis error for {conversation_id}: {str(re)}")
    except Exception as e:
        logger.error(f"[CHAT_HISTORY] Unexpected error for {conversation_id}: {str(e)}")
    
    # Return empty list by default
    logger.info(f"[CHAT_HISTORY] Returning empty history for conversation {conversation_id}")
    return []

def save_chat_history(conversation_id, chat_history):
    """Save chat history to Redis"""
    try:
        redis_client = current_app.config['REDIS_CLIENT']
        cache_version = current_app.config['CACHE_VERSION']
        chat_history_json = json.dumps(chat_history)
        
        redis_client.setex(
            f"chat:{cache_version}:{conversation_id}", 
            CHAT_HISTORY_TTL, 
            chat_history_json
        )
        logger.info(f"Successfully saved chat history to Redis for conversation {conversation_id}")
    except Exception as e:
        logger.error(f"Error saving chat history to Redis: {str(e)}")

def get_or_create_conversation_id():
    """Get existing conversation ID from session or create a new one"""
    if 'conversation_id' not in session:
        conversation_id = str(uuid.uuid4())
        session['conversation_id'] = conversation_id
        
        try:
            conversation = Conversation(
                conversation_id=conversation_id,
                chat_history=[],
                started_at=datetime.utcnow(),
                user_id=current_user.id  # Set the user_id to current user
            )
            db.session.add(conversation)
            db.session.commit()
            logger.info(f"Created new conversation record in PostgreSQL: {conversation_id}")
        except Exception as e:
            logger.error(f"Error creating conversation record: {str(e)}", exc_info=True)
            db.session.rollback()
            raise
            
        logger.info(f"Created new conversation ID: {conversation_id}")
    else:
        # Verify the existing conversation belongs to the current user
        conversation = Conversation.query.filter_by(
            conversation_id=session['conversation_id']
        ).first()
        
        if not conversation or conversation.user_id != current_user.id:
            # If conversation doesn't exist or belongs to another user, create new
            session.pop('conversation_id', None)
            return get_or_create_conversation_id()
            
    return session['conversation_id']

@routes_bp.before_request
def log_session_info():
    logger.info(f"Session ID: {session.sid}")
    logger.info(f"Session Data: {dict(session)}")

@routes_bp.route('/debug_session', methods=['GET'])
def debug_session():
    return jsonify({
        'session_type': current_app.config.get('SESSION_TYPE'),
        'session_cookie_name': current_app.config.get('SESSION_COOKIE_NAME'),
        'session_cookie_secure': current_app.config.get('SESSION_COOKIE_SECURE'),
        'session_cookie_httponly': current_app.config.get('SESSION_COOKIE_HTTPONLY'),
        'session_cookie_samesite': current_app.config.get('SESSION_COOKIE_SAMESITE'),
        'session_cookie_path': current_app.config.get('SESSION_COOKIE_PATH'),
        'preferred_url_scheme': current_app.config.get('PREFERRED_URL_SCHEME'),
        'flask_env': current_app.config.get('FLASK_ENV'),
        'session_permanent': current_app.config.get('SESSION_PERMANENT'),
        'session_use_signer': current_app.config.get('SESSION_USE_SIGNER'),
        'session_key_prefix': current_app.config.get('SESSION_KEY_PREFIX')
    })

@routes_bp.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200

@routes_bp.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@routes_bp.route("/", methods=["GET"])
def index():
    """Landing page - only non-auth route"""
    if current_user.is_authenticated:
        return redirect(url_for('routes_bp.chat_page'))
    return render_template('index.html')

@routes_bp.route("/chat", methods=["GET"])
@login_required
def chat_page():
    """Protected chat interface with all existing functionality"""
    try:
        # Generate a nonce for this request
        nonce = hashlib.sha256(os.urandom(32)).hexdigest()
        # Store nonce in Flask g object for access in after_request
        g.nonce = nonce
        
        start_time = time.time()  # Start timing

        # Increment the counter
        index_visitor_count.inc()

        # Get or create conversation ID
        conversation_id = get_or_create_conversation_id()
        logger.info(f"Chat: Using conversation ID {conversation_id}")
        logger.info(f"Session data in chat: {dict(session)}")
        
        # Get chat history
        chat_history = get_chat_history(conversation_id)
        logger.info(f"Chat: Retrieved chat history for conversation {conversation_id}")

        # Observe the time taken to process the request
        index_timer.observe(time.time() - start_time)

        return render_template(
            "chat.html", 
            nonce=nonce, 
            chat_history=chat_history,
            user=current_user
        )
    except Exception as e:
        logger.error(f"Error in chat route: {str(e)}")
        return render_template("chat.html", chat_history=[])

@routes_bp.route("/stream", methods=["GET"])
@login_required
def stream():
    try:
        conversation_id = get_or_create_conversation_id()
        bedrock_client = current_app.config['BEDROCK_CLIENT']
        app = current_app._get_current_object()
        
        logger.info(f"[STREAM] Starting stream for conversation {conversation_id}")
        
        chat_history = get_chat_history(conversation_id)
        
        def generate():
            assistant_response = ""
            chunk_count = 0
            
            try:
                with app.app_context():
                    # Check if user is still authenticated at start of stream
                    if not current_user.is_authenticated:
                        logger.info(f"[STREAM] User no longer authenticated, terminating stream")
                        return
                        
                    # Store stream status in Redis
                    redis_client = current_app.config['REDIS_CLIENT']
                    cache_version = current_app.config['CACHE_VERSION']
                    stream_key = f"stream:{cache_version}:{conversation_id}"
                    redis_client.setex(stream_key, 3600, 'active')  # 1 hour TTL
                    
                    response_stream = bedrock_client.create_chat_completion(
                        messages=chat_history,
                        stream=True
                    )
                    
                    for chunk in response_stream:
                        # Check stream status in Redis
                        if not redis_client.exists(stream_key):
                            logger.info(f"[STREAM] Stream terminated by logout")
                            break
                            
                        chunk_count += 1
                        if chunk.get('choices', [{}])[0].get('delta', {}).get('content'):
                            content = chunk['choices'][0]['delta']['content']
                            assistant_response += content
                            yield f"data: {json.dumps({'content': content})}\n\n"
                    
                    # After streaming complete, save the response if we haven't been interrupted
                    if assistant_response and redis_client.exists(stream_key):
                        logger.info(f"[STREAM] Stream complete. Total chunks: {chunk_count}")
                        current_chat_history = get_chat_history(conversation_id)
                        current_chat_history.append({
                            "role": "assistant",
                            "content": assistant_response
                        })
                        save_chat_history(conversation_id, current_chat_history)
                        update_conversation_in_db(conversation_id, current_chat_history)
                        
                    # Clean up stream key
                    redis_client.delete(stream_key)
                    
            except Exception as e:
                logger.error(f"[STREAM] Error in generator: {str(e)}", exc_info=True)
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Transfer-Encoding': 'chunked',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'
            }
        )
        
    except Exception as e:
        logger.error(f"[STREAM] Error in stream endpoint: {str(e)}", exc_info=True)
        return jsonify(error=str(e)), 500

@routes_bp.route("/chat", methods=["POST"])
@login_required
def chat():
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'error': 'No message provided'}), 400

        conversation_id = get_or_create_conversation_id()
        
        # Verify conversation belongs to current user
        conversation = Conversation.query.filter_by(
            conversation_id=conversation_id,
            user_id=current_user.id
        ).first()
        
        if not conversation:
            return jsonify({'error': 'Invalid conversation'}), 403
            
        chat_history = get_chat_history(conversation_id)
        
        # Add user message to history
        user_message = {
            'role': 'user',
            'content': data['message']
        }
        chat_history.append(user_message)
        
        # Save updated history
        save_chat_history(conversation_id, chat_history)
        
        return jsonify(success=True)
    except Exception as e:
        logger.error(f"Error in chat endpoint: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@routes_bp.route("/reset", methods=["POST"])
@login_required
def reset_chat():
    try:
        data = request.get_json() or {}
        was_temporary = data.get('wasTemporary', False)
        old_conversation_id = get_or_create_conversation_id()
        
        logger.info(f"Resetting chat for user {current_user.id}, conversation {old_conversation_id}")
        
        # Only save the old conversation to PostgreSQL if it wasn't temporary
        if not was_temporary:
            try:
                chat_history = get_chat_history(old_conversation_id)
                if chat_history:  # Only save if there was actual chat history
                    # Verify conversation belongs to current user
                    conversation = Conversation.query.filter_by(
                        conversation_id=old_conversation_id,
                        user_id=current_user.id
                    ).first()
                    
                    current_time = datetime.utcnow()
                    
                    if conversation:
                        logger.info(f"Updating existing conversation {old_conversation_id}")
                        conversation.chat_history = chat_history
                        conversation.ended_at = current_time
                        if not conversation.started_at:
                            conversation.started_at = current_time
                    else:
                        logger.info(f"Creating new conversation record for {old_conversation_id}")
                        conversation = Conversation(
                            conversation_id=old_conversation_id,
                            chat_history=chat_history,
                            started_at=current_time,
                            ended_at=current_time,
                            user_id=current_user.id
                        )
                        db.session.add(conversation)
                    
                    db.session.commit()
                    logger.info(f"Successfully saved conversation {old_conversation_id}")
            except Exception as e:
                logger.error(f"Database error saving old conversation: {str(e)}", exc_info=True)
                db.session.rollback()
                raise
        else:
            logger.info(f"Skipping save for temporary conversation {old_conversation_id}")
        
        # Delete old chat history from Redis
        try:
            delete_chat_history(old_conversation_id)
            logger.info(f"Deleted Redis history for {old_conversation_id}")
        except Exception as e:
            logger.warning(f"Failed to delete Redis history: {str(e)}", exc_info=True)

        # Generate new conversation ID and create initial record
        new_conversation_id = str(uuid.uuid4())
        current_time = datetime.utcnow()
        
        try:
            # Create new conversation record
            new_conversation = Conversation(
                conversation_id=new_conversation_id,
                chat_history=[],
                started_at=current_time,
                user_id=current_user.id
            )
            db.session.add(new_conversation)
            db.session.commit()
            
            # Update session
            session['conversation_id'] = new_conversation_id
            session.modified = True
            
            logger.info(f"Created new conversation {new_conversation_id}")
            
            return jsonify({
                'success': True,
                'new_conversation_id': new_conversation_id
            })
        except Exception as e:
            logger.error(f"Error creating new conversation: {str(e)}", exc_info=True)
            db.session.rollback()
            raise
            
    except Exception as e:
        logger.error(f"Error in reset_chat: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': 'Failed to reset chat'
        }), 500

def delete_chat_history(conversation_id):
    """Delete chat history from Redis"""
    try:
        redis_client = current_app.config['REDIS_CLIENT']
        cache_version = current_app.config['CACHE_VERSION']
        key = f"chat:{cache_version}:{conversation_id}"
        redis_client.delete(key)
        logger.info(f"Successfully deleted chat history for conversation {conversation_id}")
    except Exception as e:
        logger.error(f"Error deleting chat history from Redis: {str(e)}")

@routes_bp.route('/set_session', methods=['POST'])
@login_required
def set_session():
    session['user_input'] = request.json['message']
    return jsonify(success=True)

@routes_bp.route('/get_session', methods=['GET'])
@login_required
def get_session():
    user_input = session.get('user_input', 'No input set')
    return jsonify(user_input=user_input)

@routes_bp.route('/debug_redis', methods=['GET'])
@login_required
def debug_redis():
    redis_client = get_redis_client()
    try:
        # Test Redis connection
        redis_client.ping()
        
        # Get current conversation ID
        conversation_id = get_or_create_conversation_id()
        
        # Get cache version
        cache_version = current_app.config['CACHE_VERSION']
        
        # Get chat history key
        chat_key = f"chat:{cache_version}:{conversation_id}"
        
        # Get actual chat history
        chat_history = redis_client.get(chat_key)
        
        return jsonify({
            'redis_connected': True,
            'conversation_id': conversation_id,
            'cache_version': cache_version,
            'chat_key': chat_key,
            'chat_history': json.loads(chat_history) if chat_history else None,
            'ttl': redis_client.ttl(chat_key) if chat_history else None
        })
    except Exception as e:
        return jsonify({
            'redis_connected': False,
            'error': str(e)
        })

@routes_bp.route("/conversation_history", methods=["GET"])
@login_required
def get_conversation_history():
    try:
        logger.info(f"Fetching conversation history for user {current_user.id}")
        
        # Query only completed conversations for the current user
        conversations = (
            Conversation.query
            .filter(
                Conversation.user_id == current_user.id,  # Filter by current user
                Conversation.ended_at.isnot(None),  # Only completed conversations
                Conversation.chat_history.isnot(None)  # Ensure chat history exists
            )
            .order_by(Conversation.ended_at.desc())
            .limit(100)
            .all()
        )
        
        logger.info(f"Found {len(conversations)} completed conversations")
        
        today = date.today()
        seven_days_ago = today - timedelta(days=7)
        thirty_days_ago = today - timedelta(days=30)
        
        grouped_history = {
            "Today": [],
            "Previous 7 Days": [],
            "Previous 30 Days": []
        }
        
        for conv in conversations:
            try:
                if not conv.ended_at:
                    logger.warning(f"Conversation {conv.conversation_id} has no ended_at timestamp")
                    continue
                    
                conv_date = conv.ended_at.date()
                first_exchange = {
                    'id': conv.conversation_id,
                    'preview': '',
                    'timestamp': conv.ended_at.isoformat()
                }
                
                # Get first user message for preview
                if conv.chat_history:
                    for msg in conv.chat_history:
                        if isinstance(msg, dict) and msg.get('role') == 'user':
                            preview_text = msg.get('content', '').strip()
                            if preview_text:
                                first_exchange['preview'] = (preview_text[:47] + '...') if len(preview_text) > 50 else preview_text
                                break
                
                # Only add conversations with valid previews
                if first_exchange['preview']:
                    if conv_date == today:
                        grouped_history["Today"].append(first_exchange)
                    elif seven_days_ago <= conv_date < today:
                        grouped_history["Previous 7 Days"].append(first_exchange)
                    elif thirty_days_ago <= conv_date < seven_days_ago:
                        grouped_history["Previous 30 Days"].append(first_exchange)
            except Exception as e:
                logger.error(f"Error processing conversation {conv.conversation_id}: {str(e)}", exc_info=True)
                continue

        # Log summary of grouped conversations
        for group, convs in grouped_history.items():
            logger.info(f"{group}: {len(convs)} conversations")
            
        return jsonify({
            'success': True,
            'history': grouped_history
        })
    except Exception as e:
        logger.error(f"Error fetching conversation history: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve conversation history'
        }), 500

@routes_bp.route("/get_conversation/<conversation_id>", methods=["GET"])
@login_required
def get_conversation_by_id(conversation_id):
    try:
        logger.info(f"Loading conversation {conversation_id} for user {current_user.id}")
        
        conversation = Conversation.query.filter_by(
            conversation_id=conversation_id,
            user_id=current_user.id
        ).first()
        
        if not conversation:
            logger.warning(f"Conversation {conversation_id} not found or unauthorized")
            return jsonify({
                'success': False,
                'error': 'Conversation not found or unauthorized'
            }), 404
        
        # Ensure chat_history is a list
        chat_history = conversation.chat_history if conversation.chat_history else []
        
        # Validate chat_history format
        if not isinstance(chat_history, list):
            logger.error(f"Invalid chat history format for conversation {conversation_id}")
            return jsonify({
                'success': False,
                'error': 'Invalid chat history format'
            }), 500
            
        # Update Redis cache
        try:
            save_chat_history(conversation_id, chat_history)
            logger.info(f"Updated Redis cache for conversation {conversation_id}")
        except Exception as e:
            logger.warning(f"Failed to update Redis cache: {str(e)}", exc_info=True)
            
        # Update session
        session['conversation_id'] = conversation_id
        session.modified = True
        
        logger.info(f"Successfully retrieved conversation {conversation_id} with {len(chat_history)} messages")
        
        # Return chat_history directly at top level
        return jsonify({
            'success': True,
            'chat_history': chat_history
        })
        
    except Exception as e:
        logger.error(f"Error retrieving conversation: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve conversation'
        }), 500

def update_conversation_in_db(conversation_id, chat_history):
    """Update an existing conversation in PostgreSQL"""
    try:
        conversation = Conversation.query.filter_by(conversation_id=conversation_id).first()
        if conversation:
            conversation.chat_history = chat_history
            db.session.commit()
            logger.info(f"Successfully updated conversation {conversation_id} in PostgreSQL")
        else:
            logger.error(f"Conversation {conversation_id} not found in PostgreSQL")
    except Exception as e:
        logger.error(f"Error updating conversation in PostgreSQL: {str(e)}")
        db.session.rollback()

@routes_bp.after_request
def add_security_headers(response):
    # Base security headers for all responses
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = (
        "accelerometer=(), "
        "camera=(), "
        "geolocation=(), "
        "gyroscope=(), "
        "magnetometer=(), "
        "microphone=(), "
        "payment=(), "
        "usb=()"
    )

    # Enhanced CSP for HTML responses
    if 'text/html' in response.content_type:
        nonce = getattr(g, 'nonce', None)
        csp_directives = [
            "default-src 'self'",
            f"script-src 'self' 'nonce-{nonce}' https://devopser.io",
            "style-src 'self' 'unsafe-inline'",  # Temporary allowance for inline styles
            "img-src 'self' data: blob: svg:",  # Allow data URIs for QR codes and inline SVG
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'"
        ]
        response.headers['Content-Security-Policy'] = "; ".join(csp_directives)
    else:
        # Basic CSP for non-HTML responses
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "img-src 'self'; "
            "style-src 'self'; "
            "script-src 'self' https://devopser.io; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )

    return response

# Uncomment this to debug your sessions and cookies
@routes_bp.route('/debug_session_config')
def debug_session_config():
    return {
        'FLASK_ENV': current_app.config.get('FLASK_ENV'),
        'SESSION_COOKIE_NAME': current_app.config.get('SESSION_COOKIE_NAME'),
        'SESSION_COOKIE_SECURE': current_app.config.get('SESSION_COOKIE_SECURE'),
        'SESSION_COOKIE_SAMESITE': current_app.config.get('SESSION_COOKIE_SAMESITE')
    }

@routes_bp.route('/test-secrets', methods=['GET'])
def test_secrets():
    """
    Test route to verify secret retrieval is working.
    Returns a sanitized version of the secret data (no actual secrets exposed).
    """
    try:
        domain_creds = get_additional_secrets()
        
        # Add debug logging
        logger.info(f"Type of retrieved secret: {type(domain_creds)}")
        logger.info(f"Content of secret: {domain_creds}")  # Be careful with this in production!
        
        # Create a safe response that doesn't expose sensitive data
        safe_response = {
            'status': 'success',
            'secret_type': str(type(domain_creds)),
            'is_dict': isinstance(domain_creds, dict),
            'available_keys': list(domain_creds.keys()) if isinstance(domain_creds, dict) else None
        }
        
        logger.info("Successfully retrieved and verified secret structure")
        return jsonify(safe_response), 200
        
    except ValueError as e:
        # Handle missing environment variable
        return jsonify({
            'status': 'error',
            'message': str(e),
            'error_type': 'configuration_error'
        }), 400
        
    except Exception as e:
        # Handle other errors
        logger.error(f"Error testing secrets: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Failed to retrieve secrets: {str(e)}',
            'error_type': 'internal_error'
        }), 500
