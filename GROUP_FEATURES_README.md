# MLWE-PAKE Group Authentication Extensions

This document describes the extended features added to the MLWE-PAKE implementation.

## Overview

The project has been extended with:
1. **Group primitives** for multi-party key agreement
2. **HKDF-based ratcheting** for forward secrecy
3. **WebSocket server** using FastAPI
4. **Pre-key system** for asynchronous joins
5. **Performance instrumentation** for crypto operations
6. **Web frontend** with live metrics dashboard

## New Files Created

### Core Modules

#### `group_crypto.py`
- **DoubleRatcheting**: Implements double ratcheting using HKDF for forward secrecy
- **GroupKeyAgreement**: Manages multi-party key establishment using MLWE-PAKE
- **PreKeySystem**: Handles pre-key bundles for async joins
- **HKDF functions**: Key derivation using HKDF from cryptography library

#### `crypto_instrumentation.py`
- **CryptoInstrumentation**: Thread-safe performance tracking system
- **CryptoMetric**: Data structure for individual operation metrics
- **@instrumented decorator**: Easy instrumentation of functions
- Tracks: timing, throughput, success rates, percentiles

#### `websocket_server.py`
- **FastAPI WebSocket server**: Real-time group authentication server
- **ConnectionManager**: Manages WebSocket connections and user sessions
- **Group management**: Join/leave groups, broadcast messages
- **REST API endpoints**: `/api/metrics`, `/api/groups`
- **Static file serving**: Frontend assets

### Frontend Files

#### `static/frontend.js`
- WebSocket client implementation
- Real-time metrics polling
- Group management UI controls
- Message handling and display

#### `static/styles.css`
- Modern, responsive dashboard design
- Gradient background and card-based layout
- Real-time metrics table styling
- Message panel with scrolling

## Key Features

### 1. Group Primitives
- **Multi-party key agreement**: Multiple users can join a group and establish shared keys
- **Forward secrecy**: Group keys are updated when members leave
- **Pairwise secrets**: Each pair establishes shared secrets for group key derivation

### 2. HKDF Ratcheting
- **Double ratcheting**: Forward secrecy through key ratcheting
- **Chain keys**: Sequential key derivation for message encryption
- **HKDF integration**: Uses cryptography library's HKDF implementation

### 3. Pre-Key System
- **Async joins**: Users can join groups without all members being online
- **Pre-key bundles**: Pre-generated keys for quick key exchange
- **One-time use**: Pre-keys are consumed after use

### 4. Performance Instrumentation
- **Real-time metrics**: Track operation timing and throughput
- **Success rates**: Monitor operation success/failure rates
- **Percentiles**: Calculate P50, P90, P95, P99 latencies
- **Thread-safe**: Supports concurrent operations

### 5. WebSocket Server
- **FastAPI-based**: Modern async web framework
- **Real-time communication**: WebSocket for bidirectional messaging
- **Group broadcasting**: Send messages to all group members
- **Session management**: Track user connections and group memberships

### 6. Web Frontend
- **Live dashboard**: Real-time metrics visualization
- **Group controls**: Join/leave groups through UI
- **Connection management**: Connect/disconnect WebSocket
- **Message display**: Show protocol messages and events

## Usage

### Starting the Server

```bash
# Install dependencies
pip install -r requirements.txt

# Start the WebSocket server
python websocket_server.py
# or
uvicorn websocket_server:app --host 0.0.0.0 --port 8000
```

### Accessing the Dashboard

1. Open browser to `http://localhost:8000`
2. Enter a user ID
3. Click "Connect"
4. Join a group with a group ID and password
5. View live metrics in the Performance Metrics panel

### API Endpoints

- `GET /`: Web dashboard
- `GET /api/metrics`: JSON metrics data
- `GET /api/groups`: List active groups
- `WS /ws/{user_id}`: WebSocket connection

### WebSocket Message Types

- `join_group`: Join a group with password
- `leave_group`: Leave a group
- `group_message`: Send message to group
- `request_pre_keys`: Request pre-key bundle
- `pake_auth`: Perform PAKE authentication

## Architecture

```
┌─────────────┐
│   Browser   │
│  (Frontend) │
└──────┬──────┘
       │ WebSocket/HTTP
       ▼
┌─────────────┐
│ FastAPI     │
│ WebSocket   │
│   Server    │
└──────┬──────┘
       │
       ├─► GroupKeyAgreement
       ├─► PreKeySystem
       ├─► DoubleRatcheting
       └─► CryptoInstrumentation
            │
            ▼
       ┌─────────────┐
       │  MLWE-Crypto│
       │  (liboqs)   │
       └─────────────┘
```

## Performance Metrics

The instrumentation tracks:
- **kem_key_generation**: Key pair generation timing
- **kem_encapsulation**: Encapsulation operation timing
- **kem_decapsulation**: Decapsulation operation timing

Metrics include:
- Operation count
- Average/min/max latency
- Throughput (bytes/second)
- Success rate percentage

## Security Notes

⚠️ **Important**: This is still a demonstration implementation. For production use:
- Replace simple password hashing with Argon2
- Implement proper authentication mechanisms
- Add rate limiting and DoS protection
- Use proper key management and rotation
- Implement proper error handling and logging
- Add input validation and sanitization

## Future Enhancements

- Message encryption using group keys
- Perfect forward secrecy across all operations
- Group key rotation on member changes
- Persistent storage for pre-keys
- Multi-group support per user
- End-to-end encrypted group messaging

