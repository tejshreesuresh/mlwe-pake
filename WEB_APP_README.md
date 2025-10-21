# Post-Quantum Secure Group Chat Web Application

## Overview

This web application demonstrates the "Post-Quantum Secure Group Authentication" protocol using MLWE-PAKE. It features a multi-client secure chat with visual logging of cryptographic operations, including PAKE handshakes, group key distribution, and dynamic rekeying.

## Features

### 🔐 Post-Quantum Cryptography
- **MLWE-PAKE Protocol**: Password-authenticated key exchange using Module Learning With Errors
- **Kyber KEM**: Post-quantum key encapsulation mechanism
- **Group Key Management**: Dynamic Group Traffic Key (GTK) generation and distribution
- **Forward Secrecy**: Automatic rekeying on member join/leave events

### 💬 Secure Group Chat
- **Real-time Messaging**: Encrypted group chat with multiple participants
- **Member Management**: Live user list with connection status
- **Protocol Visualization**: Real-time logging of cryptographic operations
- **Modern UI**: Responsive React-based interface

### 🛡️ Security Features
- **PAKE Authentication**: Secure password-based authentication
- **Session Keys**: Individual session keys for each client
- **Group Keys**: Shared GTK for group communication
- **Epoch Management**: Versioned group keys with automatic updates

## Architecture

### Backend (Flask + Socket.IO)
- **Flask Server**: Web application framework
- **Socket.IO**: Real-time bidirectional communication
- **Group State Management**: Centralized client and key management
- **PAKE Integration**: Uses existing `mlwe_crypto.py` and `pake_protocol.py`

### Frontend (React)
- **Single Page Application**: Modern React-based UI
- **Real-time Updates**: Live chat, member list, and protocol logs
- **Client-side Crypto**: Simplified cryptographic operations for demo
- **Responsive Design**: Works on desktop and mobile devices

## Installation & Setup

### Prerequisites
- Python 3.6+
- Virtual environment (recommended)
- Modern web browser with JavaScript enabled

### Backend Setup
```bash
# Clone the repository
git clone <repository-url>
cd mlwe-pake

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python app.py
```

The server will start on `http://localhost:8080`

### Frontend Access
Open your web browser and navigate to `http://localhost:8080`

## Usage

### 1. Join the Chat
1. Open the web application in your browser
2. Enter a username in the authentication form
3. Click "Join Chat" to start the PAKE authentication process

### 2. Authentication Process
- The application automatically initiates a PAKE handshake
- Watch the Protocol Log panel for authentication progress
- Upon successful authentication, you'll see "PAKE authentication successful!"

### 3. Group Communication
- Once authenticated, you can send messages in the chat
- Messages are automatically encrypted with the current GTK
- Other authenticated members will receive your messages
- The Group Members panel shows all active participants

### 4. Multi-Client Testing
- Open multiple browser tabs/windows
- Join with different usernames
- Observe the protocol logs for group key distribution
- Test message encryption/decryption across clients

## Protocol Flow

### 1. Client Connection
```
Client → Server: Connect with username
Server → Client: PAKE challenge with server public key
```

### 2. PAKE Authentication
```
Client → Server: Encrypted password hash
Server → Client: Authentication confirmation
Both: Derive session key
```

### 3. Group Key Management
```
First Client: No GTK needed
Second+ Client: Receive current GTK encrypted with session key
Member Leave: New GTK generated and distributed
```

### 4. Message Exchange
```
Client → Server: Message encrypted with GTK
Server → Other Clients: Forward encrypted message
Clients: Decrypt with current GTK
```

## Security Considerations

### ⚠️ Demo Implementation
This is a **demonstration application** with the following limitations:

- **Simplified Cryptography**: Uses basic XOR encryption for demo purposes
- **Fixed Password**: Uses hardcoded password "correct-horse-battery-staple"
- **No Key Confirmation**: Missing proper key confirmation phase
- **Basic Key Derivation**: Simplified key derivation functions
- **No Certificate Validation**: No PKI or certificate management

### 🔒 Production Requirements
For production use, implement:

- **Proper PAKE Protocol**: Use established protocols like OPAQUE
- **Strong Key Derivation**: Implement HKDF or similar
- **Authenticated Encryption**: Use AES-GCM or ChaCha20-Poly1305
- **Key Confirmation**: Add key confirmation phase
- **Certificate Management**: Implement proper PKI
- **Password Policies**: Strong password requirements
- **Rate Limiting**: Prevent brute force attacks
- **Audit Logging**: Comprehensive security logging

## File Structure

```
mlwe-pake/
├── app.py                 # Flask server with Socket.IO
├── templates/
│   └── index.html        # React frontend application
├── mlwe_crypto.py        # Cryptographic primitives
├── pake_protocol.py      # PAKE protocol implementation
├── requirements.txt      # Python dependencies
└── WEB_APP_README.md     # This file
```

## API Reference

### Socket.IO Events

#### Client → Server
- `join`: Join the chat with username
- `pake_message`: Send PAKE protocol message
- `group_chat_message`: Send encrypted chat message
- `request_gtk`: Request current group key

#### Server → Client
- `joined`: Confirmation of successful join
- `pake_challenge`: PAKE authentication challenge
- `pake_response`: PAKE protocol response
- `pake_success`: Authentication successful
- `pake_error`: Authentication failed
- `gtk_update`: New group key received
- `group_chat_message`: Encrypted message from other user
- `user_list_update`: Updated member list
- `log`: Protocol operation log entry
- `error`: General error message

## Troubleshooting

### Common Issues

1. **Server won't start**
   - Check if port 5000 is available
   - Verify all dependencies are installed
   - Check Python version compatibility

2. **Authentication fails**
   - Ensure password is "correct-horse-battery-staple"
   - Check browser console for errors
   - Verify Socket.IO connection

3. **Messages not appearing**
   - Check if user is authenticated
   - Verify group key is received
   - Check protocol logs for errors

4. **Multiple clients not working**
   - Use different usernames for each client
   - Check that all clients complete PAKE
   - Verify group key distribution

### Debug Mode
The server runs in debug mode by default. Check the console output for detailed logging.

## Development

### Adding Features
1. **New Message Types**: Add Socket.IO event handlers
2. **UI Components**: Modify React components in `index.html`
3. **Cryptographic Operations**: Extend `mlwe_crypto.py`
4. **Protocol Logic**: Modify `pake_protocol.py`

### Testing
- Test with multiple browser tabs
- Verify message encryption/decryption
- Check group key distribution
- Test member join/leave scenarios

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is for educational and demonstration purposes. See the main repository for license information.

## Acknowledgments

- **liboqs**: Open Quantum Safe library for post-quantum cryptography
- **Flask-SocketIO**: Real-time communication framework
- **React**: Frontend framework for modern web applications
- **MLWE-PAKE**: Original PAKE protocol implementation
