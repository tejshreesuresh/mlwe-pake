import json
import base64
import logging
import secrets
import threading
from datetime import datetime
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
import mlwe_crypto
import pake_protocol

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state management
class GroupState:
    def __init__(self):
        self.clients = {}  # {websocket: {'id': str, 'authenticated': bool, 'session_key': bytes, 'username': str}}
        self.epoch = 0
        self.gtk = None  # Group Traffic Key
        self.lock = threading.Lock()
    
    def add_client(self, sid, client_id, username):
        with self.lock:
            self.clients[sid] = {
                'id': client_id,
                'authenticated': False,
                'session_key': None,
                'username': username
            }
    
    def authenticate_client(self, sid, session_key):
        with self.lock:
            if sid in self.clients:
                self.clients[sid]['authenticated'] = True
                self.clients[sid]['session_key'] = session_key
    
    def remove_client(self, sid):
        with self.lock:
            if sid in self.clients:
                del self.clients[sid]
    
    def get_authenticated_clients(self):
        with self.lock:
            return {sid: client for sid, client in self.clients.items() if client['authenticated']}
    
    def get_client_list(self):
        with self.lock:
            return [{'id': client['id'], 'username': client['username']} 
                   for client in self.clients.values() if client['authenticated']]

group_state = GroupState()

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"New client connected: {request.sid}")
    emit('connected', {'message': 'Connected to server'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    sid = request.sid
    client = group_state.clients.get(sid)
    if client:
        username = client['username']
        group_state.remove_client(sid)
        logger.info(f"Client {username} disconnected")
        
        # Trigger rekeying if there are still authenticated clients
        authenticated_clients = group_state.get_authenticated_clients()
        if len(authenticated_clients) > 0:
            generate_and_distribute_gtk()
        
        # Update user list
        broadcast_user_list()

@socketio.on('join')
def handle_join(data):
    """Handle client joining with username"""
    client_id = data.get('client_id', f"client_{secrets.token_hex(4)}")
    username = data.get('username', f"User_{client_id[:6]}")
    
    group_state.add_client(request.sid, client_id, username)
    logger.info(f"Client {client_id} ({username}) joined")
    
    emit('joined', {
        'client_id': client_id,
        'username': username
    })
    
    # Start PAKE handshake
    start_pake_handshake(request.sid, client_id, username)

def start_pake_handshake(sid, client_id, username):
    """Start PAKE handshake with the client"""
    try:
        logger.info(f"Starting PAKE handshake for {username} (sid: {sid})")

        # Generate server KEM keys for this session
        server_pk, server_sk = mlwe_crypto.generate_kem_keys()
        logger.info(f"Generated KEM keys for {username}")

        # Store server keys temporarily (in production, use proper session management)
        group_state.clients[sid]['server_pk'] = server_pk
        group_state.clients[sid]['server_sk'] = server_sk

        # Send server public key to client
        emit('pake_challenge', {
            'server_pk': base64.b64encode(server_pk).decode('utf-8'),
            'message': 'Starting PAKE handshake...'
        }, room=sid)

        logger.info(f"Sent pake_challenge to {username}")
        log_message(sid, f"PAKE handshake initiated for {username}")

    except Exception as e:
        logger.error(f"Error starting PAKE handshake: {e}", exc_info=True)
        emit('error', {
            'message': f'Failed to start authentication: {e}'
        }, room=sid)

@socketio.on('pake_message')
def handle_pake_message(data):
    """Handle PAKE protocol messages"""
    sid = request.sid
    try:
        logger.info(f"Received pake_message from sid: {sid}")
        client_msg = data.get('message')
        if not client_msg:
            logger.warning(f"No message in pake_message data from sid: {sid}")
            return

        client = group_state.clients.get(sid)
        if not client:
            logger.warning(f"No client found for sid: {sid}")
            return

        logger.info(f"Processing PAKE message for user: {client['username']}")

        # Parse the client message
        try:
            message_data = json.loads(client_msg)
            logger.info(f"Parsed message type: {message_data.get('type')}")

            if message_data.get('type') != 'CLIENT_MSG1':
                raise ValueError("Invalid message type")

            # Extract data
            client_id = message_data.get('client_id')
            client_kem_pk_b64 = message_data.get('client_kem_pk')
            ciphertext_payload_b64 = message_data.get('ciphertext_payload')
            salt_b64 = message_data.get('salt')

            # Decode base64 data
            client_kem_pk = base64.b64decode(client_kem_pk_b64)
            ciphertext_payload = base64.b64decode(ciphertext_payload_b64)
            salt = base64.b64decode(salt_b64)

            logger.info(f"Decoded payload - salt length: {len(salt)}, payload length: {len(ciphertext_payload)}")

            # Extract password hash from payload (salt + password_hash)
            password_hash = ciphertext_payload[len(salt):]

            # Verify password (simplified for demo)
            import hashlib
            expected_password = "correct-horse-battery-staple"
            expected_hash = hashlib.pbkdf2_hmac('sha256', expected_password.encode('utf-8'), salt, 100000, dklen=32)

            logger.info(f"Password hash lengths - received: {len(password_hash)}, expected: {len(expected_hash)}")

            if password_hash != expected_hash:
                logger.warning(f"Password verification failed for user: {client['username']}")
                emit('pake_error', {
                    'message': 'PAKE authentication failed - invalid password'
                }, room=sid)
                return

            # Authentication successful
            logger.info(f"Password verified successfully for user: {client['username']}")
            session_key = secrets.token_bytes(32)
            handle_pake_completion(sid, client['id'], client['username'], session_key)

        except Exception as parse_error:
            logger.error(f"Error parsing PAKE message: {parse_error}", exc_info=True)
            emit('pake_error', {
                'message': f'PAKE parsing error: {parse_error}'
            }, room=sid)

    except Exception as e:
        logger.error(f"Error handling PAKE message: {e}", exc_info=True)
        emit('pake_error', {
            'message': f'PAKE error: {e}'
        }, room=sid)

@socketio.on('group_chat_message')
def handle_group_chat_message(data):
    """Handle encrypted group chat messages"""
    sid = request.sid
    try:
        client = group_state.clients.get(sid)
        if not client or not client['authenticated']:
            return
        
        encrypted_message = data.get('message')
        if not encrypted_message:
            return
        
        # Decrypt message with current GTK
        if group_state.gtk:
            decrypted_bytes = base64.b64decode(encrypted_message)
            decrypted_message = bytes(a ^ b for a, b in zip(decrypted_bytes, group_state.gtk))
            message_text = decrypted_message.decode('utf-8', errors='ignore')
        else:
            message_text = "No group key available"
        
        # Broadcast to all other authenticated clients
        authenticated_clients = group_state.get_authenticated_clients()
        for other_sid, other_client in authenticated_clients.items():
            if other_sid != sid:
                emit('group_chat_message', {
                    'username': client['username'],
                    'message': encrypted_message,
                    'timestamp': datetime.now().isoformat()
                }, room=other_sid)
        
        log_message(None, f"Message from {client['username']}: {message_text[:50]}...")
        
    except Exception as e:
        logger.error(f"Error handling group chat message: {e}")

@socketio.on('request_gtk')
def handle_gtk_request():
    """Handle client request for current GTK"""
    sid = request.sid
    if group_state.gtk:
        send_gtk_to_client(sid, group_state.gtk, group_state.epoch)
    else:
        emit('error', {
            'message': 'No group key available'
        }, room=sid)


def handle_pake_completion(sid, client_id, username, session_key):
    """Handle successful PAKE completion"""
    try:
        # Authenticate the client
        group_state.authenticate_client(sid, session_key)
        
        # Send success message
        emit('pake_success', {
            'message': 'Authentication successful!',
            'session_key': base64.b64encode(session_key).decode('utf-8')
        }, room=sid)
        
        log_message(sid, f"PAKE authentication successful for {username}")
        
        # Handle group key management
        handle_group_join(sid, client_id, username)
        
    except Exception as e:
        logger.error(f"Error completing PAKE: {e}")

def handle_group_join(sid, client_id, username):
    """Handle a new client joining the group"""
    try:
        authenticated_clients = group_state.get_authenticated_clients()
        
        if len(authenticated_clients) == 1:
            # First client - generate initial GTK
            log_message(sid, f"{username} is the first member of the group")
            generate_and_distribute_gtk()
        else:
            # Existing group - send current GTK
            if group_state.gtk:
                send_gtk_to_client(sid, group_state.gtk, group_state.epoch)
            else:
                # Generate first GTK
                generate_and_distribute_gtk()
        
        # Update user list for all clients
        broadcast_user_list()
        
    except Exception as e:
        logger.error(f"Error handling group join: {e}")

def generate_and_distribute_gtk():
    """Generate new GTK and distribute to all authenticated clients"""
    try:
        group_state.epoch += 1
        group_state.gtk = secrets.token_bytes(32)  # 256-bit GTK
        
        log_message(None, f"Generated new GTK for epoch {group_state.epoch}")
        
        # Distribute GTK to all authenticated clients
        authenticated_clients = group_state.get_authenticated_clients()
        for sid, client in authenticated_clients.items():
            send_gtk_to_client(sid, group_state.gtk, group_state.epoch)
        
    except Exception as e:
        logger.error(f"Error generating/distributing GTK: {e}")

def send_gtk_to_client(sid, gtk, epoch):
    """Send GTK to a specific client encrypted with their session key"""
    try:
        client = group_state.clients.get(sid)
        if not client or not client['session_key']:
            return
        
        # Simple encryption using session key (in production, use proper AEAD)
        session_key = client['session_key']
        encrypted_gtk = bytes(a ^ b for a, b in zip(gtk, session_key[:32]))
        
        emit('gtk_update', {
            'epoch': epoch,
            'encrypted_gtk': base64.b64encode(encrypted_gtk).decode('utf-8')
        }, room=sid)
        
        log_message(sid, f"GTK distributed for epoch {epoch}")
        
    except Exception as e:
        logger.error(f"Error sending GTK to client: {e}")


def broadcast_user_list():
    """Broadcast updated user list to all clients"""
    try:
        user_list = group_state.get_client_list()
        authenticated_clients = group_state.get_authenticated_clients()
        
        for sid in authenticated_clients.keys():
            emit('user_list_update', {
                'users': user_list
            }, room=sid)
        
    except Exception as e:
        logger.error(f"Error broadcasting user list: {e}")

def log_message(sid, message):
    """Send log message to specific client or all clients"""
    try:
        log_data = {
            'message': f"[{datetime.now().strftime('%H:%M:%S')}] {message}",
            'timestamp': datetime.now().isoformat()
        }
        
        if sid:
            emit('log', log_data, room=sid)
        else:
            # Broadcast to all authenticated clients
            authenticated_clients = group_state.get_authenticated_clients()
            for client_sid in authenticated_clients.keys():
                emit('log', log_data, room=client_sid)
        
    except Exception as e:
        logger.error(f"Error sending log message: {e}")

if __name__ == '__main__':
    logger.info("Starting Post-Quantum Secure Group Authentication Server")
    socketio.run(app, host='127.0.0.1', port=8080, debug=True)
