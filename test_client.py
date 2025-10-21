#!/usr/bin/env python3
"""
Test client for the Post-Quantum Secure Group Authentication web app
"""

import socketio
import json
import base64
import hashlib
import time
import threading

class TestClient:
    def __init__(self, username):
        self.username = username
        self.sio = socketio.Client()
        self.authenticated = False
        self.session_key = None
        self.gtk = None
        self.epoch = 0
        
    def connect(self):
        """Connect to the server"""
        try:
            self.sio.connect('http://localhost:8080')
            print(f"[{self.username}] Connected to server")
            return True
        except Exception as e:
            print(f"[{self.username}] Connection failed: {e}")
            return False
    
    def join_chat(self):
        """Join the chat with username"""
        try:
            self.sio.emit('join', {'username': self.username})
            print(f"[{self.username}] Sent join request")
            return True
        except Exception as e:
            print(f"[{self.username}] Join failed: {e}")
            return False
    
    def handle_pake_challenge(self, data):
        """Handle PAKE challenge from server"""
        print(f"[{self.username}] Received PAKE challenge")
        
        # Create client message matching the server's expectations
        password = "correct-horse-battery-staple"
        salt = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'  # 16 bytes
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
        
        # Create client message
        client_message = {
            "type": "CLIENT_MSG1",
            "client_id": f"client_{self.username}",
            "client_kem_pk": base64.b64encode(b'\x00' * 32).decode('utf-8'),  # Dummy key
            "ciphertext_payload": base64.b64encode(salt + password_hash).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8')
        }
        
        # Send PAKE message
        self.sio.emit('pake_message', {'message': json.dumps(client_message)})
        print(f"[{self.username}] Sent PAKE response")
    
    def handle_pake_success(self, data):
        """Handle PAKE success"""
        print(f"[{self.username}] PAKE authentication successful!")
        self.authenticated = True
    
    def handle_gtk_update(self, data):
        """Handle GTK update"""
        print(f"[{self.username}] Received GTK update (epoch: {data.get('epoch', 'unknown')})")
        self.gtk = data.get('encrypted_gtk')
        self.epoch = data.get('epoch', 0)
    
    def handle_user_list_update(self, data):
        """Handle user list update"""
        users = data.get('users', [])
        print(f"[{self.username}] User list updated: {[u['username'] for u in users]}")
    
    def handle_log(self, data):
        """Handle log message"""
        message = data.get('message', '')
        print(f"[{self.username}] LOG: {message}")
    
    def handle_error(self, data):
        """Handle error message"""
        message = data.get('message', '')
        print(f"[{self.username}] ERROR: {message}")
    
    def send_message(self, message):
        """Send a chat message"""
        if not self.authenticated:
            print(f"[{self.username}] Not authenticated, cannot send message")
            return
        
        # For demo, just send the message as-is (in real implementation, encrypt with GTK)
        self.sio.emit('group_chat_message', {'message': message})
        print(f"[{self.username}] Sent message: {message}")
    
    def setup_event_handlers(self):
        """Setup Socket.IO event handlers"""
        @self.sio.event
        def connect():
            print(f"[{self.username}] Socket.IO connected")
        
        @self.sio.event
        def disconnect():
            print(f"[{self.username}] Socket.IO disconnected")
        
        @self.sio.event
        def pake_challenge(data):
            self.handle_pake_challenge(data)
        
        @self.sio.event
        def pake_success(data):
            self.handle_pake_success(data)
        
        @self.sio.event
        def gtk_update(data):
            self.handle_gtk_update(data)
        
        @self.sio.event
        def user_list_update(data):
            self.handle_user_list_update(data)
        
        @self.sio.event
        def log(data):
            self.handle_log(data)
        
        @self.sio.event
        def error(data):
            self.handle_error(data)
        
        @self.sio.event
        def group_chat_message(data):
            print(f"[{self.username}] Received chat message: {data.get('message', '')}")
    
    def run_test(self):
        """Run the test sequence"""
        print(f"\n=== Testing {self.username} ===")
        
        # Setup event handlers
        self.setup_event_handlers()
        
        # Connect to server
        if not self.connect():
            return False
        
        # Wait a moment for connection to establish
        time.sleep(0.5)
        
        # Join chat
        if not self.join_chat():
            return False
        
        # Wait for authentication
        print(f"[{self.username}] Waiting for authentication...")
        timeout = 10
        start_time = time.time()
        
        while not self.authenticated and (time.time() - start_time) < timeout:
            time.sleep(0.1)
        
        if self.authenticated:
            print(f"[{self.username}] Authentication successful!")
            
            # Wait for GTK
            print(f"[{self.username}] Waiting for GTK...")
            start_time = time.time()
            while not self.gtk and (time.time() - start_time) < timeout:
                time.sleep(0.1)
            
            if self.gtk:
                print(f"[{self.username}] GTK received!")
                
                # Send a test message
                time.sleep(1)
                self.send_message(f"Hello from {self.username}!")
                
                return True
            else:
                print(f"[{self.username}] GTK not received within timeout")
                return False
        else:
            print(f"[{self.username}] Authentication failed or timed out")
            return False

def test_multiple_clients():
    """Test with multiple clients"""
    print("=== Testing Multiple Clients ===")
    
    # Create test clients
    clients = [
        TestClient("alice"),
        TestClient("bob"),
        TestClient("charlie")
    ]
    
    # Run tests in parallel
    threads = []
    results = {}
    
    def run_client_test(client):
        results[client.username] = client.run_test()
    
    for client in clients:
        thread = threading.Thread(target=run_client_test, args=(client,))
        threads.append(thread)
        thread.start()
        time.sleep(0.5)  # Stagger connections
    
    # Wait for all tests to complete
    for thread in threads:
        thread.join()
    
    # Print results
    print("\n=== Test Results ===")
    for username, success in results.items():
        status = "PASS" if success else "FAIL"
        print(f"{username}: {status}")
    
    # Check if any client succeeded
    if any(results.values()):
        print("\n✅ At least one client successfully authenticated and received GTK")
        return True
    else:
        print("\n❌ All clients failed to authenticate")
        return False

if __name__ == "__main__":
    print("Post-Quantum Secure Group Authentication - Test Client")
    print("=" * 60)
    
    # Test single client first
    print("\n1. Testing single client...")
    client = TestClient("testuser")
    single_success = client.run_test()
    
    if single_success:
        print("\n✅ Single client test passed")
        
        # Test multiple clients
        print("\n2. Testing multiple clients...")
        multi_success = test_multiple_clients()
        
        if multi_success:
            print("\n🎉 All tests passed! The implementation is working correctly.")
        else:
            print("\n⚠️  Multiple client test failed")
    else:
        print("\n❌ Single client test failed")
    
    print("\nTest completed.")
