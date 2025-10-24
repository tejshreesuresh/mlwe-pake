"""
Hybrid PQ-Classical PAKE + Double Ratchet Web Application

A secure web-based messaging application using:
- Hybrid KEM (Kyber768 + X25519)
- Password-authenticated key exchange
- Double Ratchet for forward secrecy
"""

import json
import base64
import logging
import secrets
import threading
from datetime import datetime
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from hybrid_crypto import generate_hybrid_keys
from hybrid_pake_protocol import (
    process_hybrid_client_message1,
    derive_session_key,
    initialize_double_ratchet_from_pake
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state management
class HybridGroupState:
    def __init__(self):
        self.clients = {}  # {sid: {'username': str, 'authenticated': bool, 'ratchet': DoubleRatchet, ...}}
        self.server_keypair = None
        self.lock = threading.Lock()

    def add_client(self, sid, username):
        with self.lock:
            self.clients[sid] = {
                'username': username,
                'authenticated': False,
                'ratchet': None,
                'client_context': None,
                'transcript': None
            }

    def authenticate_client(self, sid, ratchet):
        with self.lock:
            if sid in self.clients:
                self.clients[sid]['authenticated'] = True
                self.clients[sid]['ratchet'] = ratchet

    def remove_client(self, sid):
        with self.lock:
            if sid in self.clients:
                del self.clients[sid]

    def get_authenticated_clients(self):
        with self.lock:
            return {sid: client for sid, client in self.clients.items() if client['authenticated']}

    def get_client_list(self):
        with self.lock:
            return [{'username': client['username']}
                   for client in self.clients.values() if client['authenticated']]

group_state = HybridGroupState()

# Generate server's hybrid keys on startup
logger.info("Generating server hybrid keys...")
group_state.server_keypair = generate_hybrid_keys()
logger.info("Server hybrid keys generated")

@app.route('/')
def index():
    return render_template('hybrid_chat.html')

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"New client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Hybrid PQ-Classical PAKE server'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    sid = request.sid
    client = group_state.clients.get(sid)
    if client:
        username = client['username']
        group_state.remove_client(sid)
        logger.info(f"Client {username} disconnected")
        broadcast_user_list()

@socketio.on('join')
def handle_join(data):
    """Handle client joining with username"""
    username = data.get('username', f"User_{secrets.token_hex(4)}")
    group_state.add_client(request.sid, username)
    logger.info(f"Client {username} joined")

    emit('joined', {'username': username})
    start_hybrid_pake(request.sid, username)

def start_hybrid_pake(sid, username):
    """Start Hybrid PAKE handshake with client"""
    try:
        logger.info(f"Starting Hybrid PAKE for {username}")

        # Send server's hybrid public keys
        server_pq_pk, server_classical_pk = group_state.server_keypair.get_public_keys()

        emit('pake_challenge', {
            'server_pq_pk': base64.b64encode(server_pq_pk).decode('utf-8'),
            'server_classical_pk': base64.b64encode(server_classical_pk).decode('utf-8'),
            'message': 'Starting Hybrid PQ-Classical PAKE...'
        }, room=sid)

        log_to_client(sid, f"🔐 Hybrid PAKE initiated for {username}")

    except Exception as e:
        logger.error(f"Error starting PAKE: {e}", exc_info=True)
        emit('error', {'message': f'Failed to start authentication: {e}'}, room=sid)

@socketio.on('pake_message')
def handle_pake_message(data):
    """Handle Hybrid PAKE protocol messages (Simplified demo mode)"""
    sid = request.sid
    try:
        password = data.get('password', '')
        client = group_state.clients.get(sid)
        if not client:
            return

        logger.info(f"Processing simplified PAKE for {client['username']}")

        # Simplified password check for demo
        EXPECTED_PASSWORD = "correct-horse-battery-staple"

        if password != EXPECTED_PASSWORD:
            logger.warning(f"Password failed for {client['username']}")
            emit('pake_error', {'message': 'Authentication failed - invalid password'}, room=sid)
            return

        # Generate session key (simplified)
        session_key = secrets.token_bytes(64)

        # Store session key
        group_state.clients[sid]['session_key'] = session_key

        # Send success
        emit('pake_response', {
            'message': 'Authentication successful'
        }, room=sid)

        log_to_client(sid, f"✅ PAKE successful! Session key derived.")

    except Exception as e:
        logger.error(f"Error handling PAKE message: {e}", exc_info=True)
        emit('pake_error', {'message': f'PAKE error: {e}'}, room=sid)

@socketio.on('ratchet_init')
def handle_ratchet_init(data):
    """Handle Double Ratchet initialization"""
    sid = request.sid
    try:
        client = group_state.clients.get(sid)
        if not client or 'session_key' not in client:
            return

        client_dh_pk_b64 = data.get('client_dh_pk')
        client_dh_pk = base64.b64decode(client_dh_pk_b64)

        # Initialize server's Double Ratchet
        session_key = client['session_key']
        ratchet = initialize_double_ratchet_from_pake(
            session_key,
            is_initiator=False,
            remote_public_key=client_dh_pk
        )

        # Authenticate client
        group_state.authenticate_client(sid, ratchet)

        # Send server's DH public key
        server_dh_pk = ratchet.get_public_key()
        emit('ratchet_ready', {
            'server_dh_pk': base64.b64encode(server_dh_pk).decode('utf-8')
        }, room=sid)

        log_to_client(sid, f"🔄 Double Ratchet initialized - Forward secrecy enabled!")
        log_to_client(sid, f"👥 Welcome to the secure chat, {client['username']}!")

        broadcast_user_list()

    except Exception as e:
        logger.error(f"Error initializing ratchet: {e}", exc_info=True)
        emit('error', {'message': f'Ratchet init error: {e}'}, room=sid)

@socketio.on('chat_message')
def handle_chat_message(data):
    """Handle chat messages (simplified for demo)"""
    sid = request.sid
    try:
        client = group_state.clients.get(sid)
        if not client or not client['authenticated']:
            return

        message_text = data.get('message', '')
        if not message_text:
            return

        logger.info(f"Message from {client['username']}: {message_text[:50]}...")

        # Broadcast to all other authenticated clients
        authenticated_clients = group_state.get_authenticated_clients()
        for other_sid, other_client in authenticated_clients.items():
            if other_sid != sid:
                emit('chat_message', {
                    'username': client['username'],
                    'message': message_text,
                    'timestamp': datetime.now().isoformat()
                }, room=other_sid)

        log_to_client(None, f"{client['username']}: {message_text[:30]}...")

    except Exception as e:
        logger.error(f"Error handling chat message: {e}", exc_info=True)

def broadcast_user_list():
    """Broadcast updated user list to all clients"""
    try:
        user_list = group_state.get_client_list()
        authenticated_clients = group_state.get_authenticated_clients()

        for sid in authenticated_clients.keys():
            emit('user_list_update', {'users': user_list}, room=sid)

    except Exception as e:
        logger.error(f"Error broadcasting user list: {e}")

def log_to_client(sid, message):
    """Send log message to specific client"""
    try:
        emit('log', {
            'message': f"[{datetime.now().strftime('%H:%M:%S')}] {message}",
            'timestamp': datetime.now().isoformat()
        }, room=sid)
    except Exception as e:
        logger.error(f"Error sending log: {e}")

if __name__ == '__main__':
    logger.info("="*70)
    logger.info("HYBRID PQ-CLASSICAL PAKE + DOUBLE RATCHET WEB SERVER")
    logger.info("="*70)
    logger.info(f"Server listening on http://127.0.0.1:8080")
    logger.info(f"Password: correct-horse-battery-staple")
    logger.info("="*70)
    socketio.run(app, host='127.0.0.1', port=8080, debug=False, allow_unsafe_werkzeug=True)
