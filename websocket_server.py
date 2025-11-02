"""
FastAPI WebSocket server for MLWE-PAKE with group authentication.
Supports real-time group key agreement, pre-key system, and live metrics.
"""

import json
import asyncio
import time
import os
from typing import Dict, Set, Optional, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import base64
import uuid

from group_crypto import (
    GroupKeyAgreement,
    PreKeySystem,
    DoubleRatcheting,
    derive_with_hkdf
)
from mlwe_crypto import generate_kem_keys, kem_encapsulate, kem_decapsulate
from pake_protocol import create_client_message1, process_client_message1, calculate_final_key
from crypto_instrumentation import get_instrumentation

app = FastAPI(title="MLWE-PAKE Group Server")

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_sessions: Dict[str, Dict] = {}  # user_id -> session data
        self.groups: Dict[str, GroupKeyAgreement] = {}  # group_id -> GroupKeyAgreement
        self.pre_key_system = PreKeySystem()
        self.group_memberships: Dict[str, Set[str]] = {}  # user_id -> set of group_ids
        
    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        self.user_sessions[user_id] = {
            'connected_at': time.time(),
            'last_activity': time.time(),
            'ratchet': None,
            'group_keys': {}
        }
        
    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
        if user_id in self.user_sessions:
            del self.user_sessions[user_id]
        
        # Remove from groups
        for group_id in self.group_memberships.get(user_id, set()):
            if group_id in self.groups:
                self.groups[group_id].update_group_key(leaving_member_id=user_id)
        
        if user_id in self.group_memberships:
            del self.group_memberships[user_id]
    
    async def send_personal_message(self, message: dict, user_id: str):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_json(message)
    
    async def broadcast_to_group(self, message: dict, group_id: str, exclude_user: Optional[str] = None):
        """Broadcast message to all members of a group."""
        if group_id not in self.groups:
            return
        
        group = self.groups[group_id]
        for user_id in group.members.keys():
            if user_id != exclude_user and user_id in self.active_connections:
                await self.active_connections[user_id].send_json(message)


manager = ConnectionManager()


@app.get("/")
async def get_frontend():
    """Serve the frontend HTML."""
    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>MLWE-PAKE Group Server Dashboard</title>
    <script src="/static/frontend.js"></script>
    <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
    <div class="container">
        <h1>MLWE-PAKE Group Authentication Dashboard</h1>
        
        <div class="dashboard">
            <!-- Left Column: Controls -->
            <div class="left-column">
                <div class="panel">
                    <h2>Connection</h2>
                    <div style="background: #f0f8ff; padding: 10px; border-radius: 5px; margin-bottom: 10px; border-left: 4px solid #667eea;">
                        <strong>💡 Testing Multiple Users?</strong><br>
                        <small>Open multiple browser tabs/windows, each with a different User ID, then join the same group!</small>
                    </div>
                    <input type="text" id="userIdInput" placeholder="Enter User ID" value="user_1">
                    <button onclick="connect()">Connect</button>
                    <button onclick="disconnect()">Disconnect</button>
                    <div id="connectionStatus">Disconnected</div>
                    <div id="connectedUsers" style="margin-top: 10px; font-size: 0.9em; color: #666;">
                        <small>Total connected users: <span id="userCount">0</span></small>
                    </div>
                </div>
                
                <div class="panel">
                    <h2>Group Management</h2>
                    <input type="text" id="groupIdInput" placeholder="Enter Group ID" value="group_1">
                    <input type="password" id="passwordInput" placeholder="Password" value="test-password">
                    <button onclick="joinGroup()">Join Group</button>
                    <button onclick="leaveGroup()">Leave Group</button>
                    <div id="groupStatus"></div>
                </div>
                
                <div class="panel">
                    <h2>Send Group Message</h2>
                    <div class="input-group">
                        <label for="groupIdForMessage">Group ID:</label>
                        <input type="text" id="groupIdForMessage" placeholder="Group ID" value="group_1">
                    </div>
                    <div class="input-group">
                        <label for="messageInput">Message:</label>
                        <input type="text" id="messageInput" placeholder="Type your message here... (Press Enter to send)">
                    </div>
                    <button onclick="sendGroupMessage()" id="sendMessageButton">Send Message</button>
                    <div style="margin-top: 10px; font-size: 0.9em; color: #666;">
                        <small>💡 Tip: You must be connected and a member of the group to send messages.</small>
                    </div>
                </div>
            </div>
            
            <!-- Right Column: Metrics & Logs -->
            <div class="right-column">
                <div class="metrics-log-panel">
                    <div class="metrics-section">
                        <h2>Performance Metrics</h2>
                        <div id="metrics"></div>
                    </div>
                    <div class="log-section">
                        <h2>Messages & Protocol Log</h2>
                        <div id="messages"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
    """
    return HTMLResponse(content=html_content)


@app.get("/api/metrics")
async def get_metrics():
    """Get current performance metrics."""
    inst = get_instrumentation()
    stats = inst.get_stats()
    
    # Format for frontend
    formatted_stats = {}
    for op, data in stats.items():
        formatted_stats[op] = {
            'count': data.get('count', 0),
            'avg_time_ms': data.get('avg_time', 0) * 1000,
            'min_time_ms': data.get('min_time', 0) * 1000,
            'max_time_ms': data.get('max_time', 0) * 1000,
            'throughput_bps': data.get('throughput', 0),
            'success_rate': (data.get('success_count', 0) / data.get('count', 1)) * 100 if data.get('count', 0) > 0 else 0
        }
    
    return JSONResponse(content=formatted_stats)


@app.get("/api/groups")
async def get_groups():
    """Get list of active groups and connected users."""
    # Get group member details
    group_details = {}
    for group_id, group in manager.groups.items():
        group_details[group_id] = {
            'member_count': len(group.members),
            'members': list(group.members.keys()),
            'epoch': group.get_current_epoch()
        }
    
    return JSONResponse(content={
        'groups': list(manager.groups.keys()),
        'group_details': group_details,
        'total_users': len(manager.active_connections),
        'total_groups': len(manager.groups),
        'connected_user_ids': list(manager.active_connections.keys())
    })


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    """Main WebSocket endpoint for group authentication."""
    await manager.connect(websocket, user_id)
    
    try:
        while True:
            # Receive message
            data = await websocket.receive_json()
            message_type = data.get('type')
            
            manager.user_sessions[user_id]['last_activity'] = time.time()
            
            if message_type == 'join_group':
                await handle_join_group(user_id, data)
            elif message_type == 'leave_group':
                await handle_leave_group(user_id, data)
            elif message_type == 'group_message':
                await handle_group_message(user_id, data)
            elif message_type == 'request_pre_keys':
                await handle_request_pre_keys(user_id, data)
            elif message_type == 'pake_auth':
                await handle_pake_auth(user_id, data)
            else:
                await manager.send_personal_message({
                    'type': 'error',
                    'message': f'Unknown message type: {message_type}'
                }, user_id)
                
    except WebSocketDisconnect:
        manager.disconnect(user_id)
        # Notify group members
        for group_id in manager.group_memberships.get(user_id, set()):
            await manager.broadcast_to_group({
                'type': 'member_left',
                'user_id': user_id,
                'group_id': group_id
            }, group_id)


async def handle_join_group(user_id: str, data: dict):
    """Handle group join request with protocol step logging."""
    group_id = data.get('group_id')
    password = data.get('password', 'default-password')
    use_prekey = data.get('use_prekey', False)
    prekey_id = data.get('prekey_id')
    
    timestamp = time.time()
    
    # Step 1: Validation
    if not group_id:
        await manager.send_personal_message({
            'type': 'protocol_step',
            'step': 'ERROR',
            'message': 'Missing group_id',
            'timestamp': timestamp
        }, user_id)
        return
    
    await manager.send_personal_message({
        'type': 'protocol_step',
        'step': '1_VALIDATION',
        'message': f'Validating join request for group {group_id}',
        'timestamp': timestamp
    }, user_id)
    
    # Create group if it doesn't exist
    if group_id not in manager.groups:
        manager.groups[group_id] = GroupKeyAgreement(group_id)
        await manager.send_personal_message({
            'type': 'protocol_step',
            'step': '2_GROUP_CREATED',
            'message': f'Created new group: {group_id}',
            'timestamp': time.time()
        }, user_id)
    
    group = manager.groups[group_id]
    old_epoch = group.get_current_epoch()
    
    # Step 2: Add member (with history exclusion)
    await manager.send_personal_message({
        'type': 'protocol_step',
        'step': '3_MEMBER_ADD',
        'message': f'Adding member {user_id} to group (current epoch: {old_epoch})',
        'timestamp': time.time()
    }, user_id)
    
    try:
        group_pk, member_context, new_epoch = group.add_member(user_id, password, use_prekey, prekey_id)
        
        # History Exclusion: Notify if epoch changed
        if new_epoch > old_epoch:
            await manager.broadcast_to_group({
                'type': 'protocol_step',
                'step': 'HISTORY_EXCLUSION',
                'message': f'New member joined - epoch incremented from {old_epoch} to {new_epoch} (old messages no longer decryptable)',
                'epoch': new_epoch,
                'timestamp': time.time()
            }, group_id, exclude_user=user_id)
            
            await manager.send_personal_message({
                'type': 'protocol_step',
                'step': '4_HISTORY_EXCLUDED',
                'message': f'History exclusion active - joined at epoch {new_epoch} (cannot decrypt messages from epoch {old_epoch} and earlier)',
                'epoch': new_epoch,
                'previous_epoch': old_epoch,
                'timestamp': time.time()
            }, user_id)
        
        # Update membership tracking
        if user_id not in manager.group_memberships:
            manager.group_memberships[user_id] = set()
        manager.group_memberships[user_id].add(group_id)
        
        # Step 3: Establish group key if 2+ members
        if len(group.members) >= 2:
            await manager.send_personal_message({
                'type': 'protocol_step',
                'step': '5_KEY_ESTABLISHMENT',
                'message': f'Establishing group key (2+ members present)',
                'member_count': len(group.members),
                'timestamp': time.time()
            }, user_id)
            
            group_key = group.establish_group_key()
            manager.user_sessions[user_id]['group_keys'][group_id] = {
                'key': group_key,
                'epoch': new_epoch
            }
            
            # Initialize ratchet for forward secrecy
            if manager.user_sessions[user_id].get('ratchet') is None:
                # Initialize double ratchet with group key as root
                dh_key = os.urandom(32)  # Simplified: in real implementation, this would be a DH key
                ratchet = DoubleRatcheting(group_key, dh_key)
                manager.user_sessions[user_id]['ratchet'] = ratchet
                
                await manager.send_personal_message({
                    'type': 'protocol_step',
                    'step': '6_RATCHET_INIT',
                    'message': 'Double ratchet initialized - forward secrecy enabled',
                    'timestamp': time.time()
                }, user_id)
            
            # Notify all group members
            await manager.broadcast_to_group({
                'type': 'group_key_established',
                'group_id': group_id,
                'member_count': len(group.members),
                'epoch': new_epoch,
                'timestamp': time.time()
            }, group_id, exclude_user=user_id)
        
        await manager.send_personal_message({
            'type': 'joined_group',
            'group_id': group_id,
            'group_public_key': base64.b64encode(group_pk).decode('utf-8'),
            'member_count': len(group.members),
            'epoch': new_epoch,
            'can_decrypt_from_epoch': new_epoch,  # History exclusion info
            'timestamp': time.time()
        }, user_id)
        
        await manager.send_personal_message({
            'type': 'protocol_step',
            'step': '7_JOIN_COMPLETE',
            'message': f'Successfully joined group {group_id} at epoch {new_epoch}',
            'timestamp': time.time()
        }, user_id)
        
    except Exception as e:
        await manager.send_personal_message({
            'type': 'protocol_step',
            'step': 'ERROR',
            'message': f'Failed to join group: {str(e)}',
            'timestamp': time.time()
        }, user_id)
        await manager.send_personal_message({
            'type': 'error',
            'message': f'Failed to join group: {str(e)}'
        }, user_id)


async def handle_leave_group(user_id: str, data: dict):
    """Handle group leave request with forward secrecy."""
    group_id = data.get('group_id')
    timestamp = time.time()
    
    if group_id in manager.group_memberships.get(user_id, set()):
        await manager.send_personal_message({
            'type': 'protocol_step',
            'step': '1_LEAVE_INIT',
            'message': f'Initiating leave from group {group_id}',
            'timestamp': timestamp
        }, user_id)
        
        manager.group_memberships[user_id].remove(group_id)
        
        if group_id in manager.groups:
            old_epoch = manager.groups[group_id].get_current_epoch()
            
            # Forward Secrecy: Update group key without this member
            await manager.send_personal_message({
                'type': 'protocol_step',
                'step': '2_KEY_UPDATE',
                'message': f'Updating group key for forward secrecy (epoch {old_epoch} -> {old_epoch + 1})',
                'timestamp': time.time()
            }, user_id)
            
            new_key, new_epoch = manager.groups[group_id].update_group_key(leaving_member_id=user_id)
            
            # Update remaining members' keys
            for remaining_user_id in manager.groups[group_id].members.keys():
                if remaining_user_id in manager.user_sessions:
                    manager.user_sessions[remaining_user_id]['group_keys'][group_id] = {
                        'key': new_key,
                        'epoch': new_epoch
                    }
                    # Re-initialize ratchet with new key
                    dh_key = os.urandom(32)
                    manager.user_sessions[remaining_user_id]['ratchet'] = DoubleRatcheting(new_key, dh_key)
            
            # Notify remaining members
            await manager.broadcast_to_group({
                'type': 'protocol_step',
                'step': 'FORWARD_SECRECY_ACTIVE',
                'message': f'Member {user_id} left - group key updated (epoch {new_epoch}). Forward secrecy: departed member cannot decrypt future messages.',
                'epoch': new_epoch,
                'timestamp': time.time()
            }, group_id)
            
            await manager.broadcast_to_group({
                'type': 'member_left',
                'user_id': user_id,
                'group_id': group_id,
                'new_epoch': new_epoch,
                'timestamp': time.time()
            }, group_id)
        
        # Remove group key from session
        if group_id in manager.user_sessions[user_id]['group_keys']:
            del manager.user_sessions[user_id]['group_keys'][group_id]
        
        await manager.send_personal_message({
            'type': 'left_group',
            'group_id': group_id,
            'message': 'Left group - forward secrecy ensures you cannot decrypt future messages',
            'timestamp': time.time()
        }, user_id)
        
        await manager.send_personal_message({
            'type': 'protocol_step',
            'step': '3_LEAVE_COMPLETE',
            'message': f'Successfully left group {group_id}',
            'timestamp': time.time()
        }, user_id)


async def handle_group_message(user_id: str, data: dict):
    """Handle group message with ratcheting for forward secrecy."""
    group_id = data.get('group_id')
    message = data.get('message', '')
    
    if group_id not in manager.group_memberships.get(user_id, set()):
        await manager.send_personal_message({
            'type': 'error',
            'message': 'Not a member of this group'
        }, user_id)
        return
    
    timestamp = time.time()
    epoch = manager.groups[group_id].get_current_epoch()
    
    # Forward Secrecy: Ratchet forward for each message
    ratchet = manager.user_sessions[user_id].get('ratchet')
    if ratchet:
        # Derive message key using ratchet
        message_key = ratchet.ratchet_forward()
        
        await manager.send_personal_message({
            'type': 'protocol_step',
            'step': 'MESSAGE_RATCHET',
            'message': f'Message key derived via ratchet (forward secrecy active)',
            'timestamp': timestamp
        }, user_id)
    else:
        message_key = None
    
    # Broadcast to group with epoch info
    await manager.broadcast_to_group({
        'type': 'group_message',
        'user_id': user_id,
        'group_id': group_id,
        'message': message,
        'epoch': epoch,
        'message_key_hash': message_key[:8].hex() if message_key else None,  # For verification
        'timestamp': timestamp
    }, group_id)


async def handle_request_pre_keys(user_id: str, data: dict):
    """Handle pre-key bundle request for async joins."""
    target_user_id = data.get('target_user_id')
    
    if not target_user_id:
        await manager.send_personal_message({
            'type': 'error',
            'message': 'Missing target_user_id'
        }, user_id)
        return
    
    # Generate or retrieve pre-key bundle
    bundle = manager.pre_key_system.generate_pre_key_bundle(target_user_id)
    
    await manager.send_personal_message({
        'type': 'pre_key_bundle',
        'target_user_id': target_user_id,
        'bundle': bundle
    }, user_id)


async def handle_pake_auth(user_id: str, data: dict):
    """Handle PAKE authentication request."""
    password = data.get('password')
    target_user_id = data.get('target_user_id')
    
    if not password or not target_user_id:
        await manager.send_personal_message({
            'type': 'error',
            'message': 'Missing password or target_user_id'
        }, user_id)
        return
    
    # Simplified PAKE for demo - in production would use proper server key
    try:
        # Generate server key if not exists
        if 'server_keys' not in manager.user_sessions.get(target_user_id, {}):
            server_pk, server_sk = generate_kem_keys()
        else:
            server_pk = manager.user_sessions[target_user_id]['server_keys']['pk']
            server_sk = manager.user_sessions[target_user_id]['server_keys']['sk']
        
        # Create client message
        client_msg, client_context, transcript = create_client_message1(
            user_id, password, server_pk
        )
        
        if client_msg:
            await manager.send_personal_message({
                'type': 'pake_message',
                'message': client_msg
            }, user_id)
    except Exception as e:
        await manager.send_personal_message({
            'type': 'error',
            'message': f'PAKE authentication failed: {str(e)}'
        }, user_id)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

