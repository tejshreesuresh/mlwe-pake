# MLWE-PAKE Implementation

A comprehensive Password-Authenticated Key Exchange (PAKE) protocol implementation using Module Learning With Errors (MLWE) cryptographic primitives, extended with group authentication capabilities, forward secrecy, and real-time performance monitoring.

## 🎯 Project Overview

This project demonstrates a **post-quantum secure** PAKE protocol implementation that:
- Uses **Kyber KEM** (quantum-resistant cryptography) for key exchange
- Supports **group authentication** with multi-party key agreement
- Implements **forward secrecy** through double ratcheting with HKDF
- Provides **asynchronous joins** via a pre-key system
- Includes **real-time performance instrumentation** and monitoring
- Features a **web-based dashboard** for visualization and testing

### Key Features

✅ **1-to-1 PAKE Protocol**: Traditional client-server password-authenticated key exchange  
✅ **Group Authentication**: Multi-party key agreement for secure group communication  
✅ **Forward Secrecy**: Double ratcheting mechanism using HKDF for message security  
✅ **Pre-Key System**: Asynchronous group joins without requiring all members online  
✅ **Performance Monitoring**: Real-time metrics on cryptographic operations  
✅ **Web Dashboard**: Live visualization of metrics, group management, and protocol flow  
✅ **WebSocket Server**: FastAPI-based real-time communication server

## 📋 Table of Contents

- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Workflow](#workflow)
- [API Documentation](#api-documentation)
- [Project Structure](#project-structure)
- [Technical Details](#technical-details)
- [Testing](#testing)
- [Security Notes](#security-notes)

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                      Web Dashboard                          │
│              (HTML/JS/CSS - Live Metrics)                   │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP/WebSocket
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              FastAPI WebSocket Server                        │
│              (websocket_server.py)                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Connection  │  │    Group     │  │    Pre-Key   │     │
│  │   Manager    │  │   Manager    │  │    System    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Group Crypto │ │ PAKE Protocol│ │ Performance  │
│  (HKDF/      │ │  (1-to-1 &   │ │Instrumentation│
│ Ratcheting)  │ │   Group)     │ │              │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                │
       └────────────────┼────────────────┘
                        ▼
              ┌─────────────────┐
              │   MLWE Crypto    │
              │  (liboqs/Kyber) │
              └─────────────────┘
```

### Protocol Flow

#### 1-to-1 PAKE Flow
```
Client                    Server
  │                         │
  │  1. Generate KEM keys   │
  │────────────────────────>│ Generate server keys
  │                         │
  │  2. CLIENT_MSG1         │
  │  (password encapsulated) │
  │────────────────────────>│
  │                         │ Verify password
  │  3. SERVER_MSG1         │
  │  (confirmation)         │
  │<────────────────────────│
  │                         │
  │  4. Derive shared key   │ Derive shared key
  │                         │
  │  ✓ Authenticated        │ ✓ Authenticated
```

#### Group Authentication Flow
```
User A          User B          User C          Server
  │               │               │               │
  │───────────────┼───────────────┼──────────────>│ Join Group
  │               │               │               │
  │<──────────────┼───────────────┼───────────────│ Group Key Established
  │               │               │               │
  │  All users share group key for secure communication
```

## 📦 Installation

### Prerequisites

- **Python 3.9+** (3.9 or higher recommended)
- **CMake** (for building liboqs)
- **C compiler** (gcc, clang, or MSVC)
- **Git** (for cloning repositories)
- **Virtual environment** (recommended)

### Step-by-Step Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/dbzkunalss/mlwe-pake.git
cd mlwe-pake
```

#### 2. Install liboqs

**Option A: Using Homebrew (macOS/Linux)**
```bash
brew install liboqs
```

**Option B: Build from Source**
```bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cd liboqs
cmake -S . -B build -DBUILD_SHARED_LIBS=ON
cmake --build build --parallel 8
sudo cmake --build build --target install
```

#### 3. Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

#### 4. Install liboqs-python Bindings

```bash
# Clone and install Python bindings
git clone https://github.com/open-quantum-safe/liboqs-python.git
cd liboqs-python
python3 -m build
pip install dist/*.whl
cd ..
```

#### 5. Verify Installation

```bash
python3 -c "import oqs; print('OQS Version:', oqs.oqs_version())"
```

You should see the liboqs version number printed.

## 🚀 Quick Start

### Option 1: WebSocket Server with Dashboard (Recommended)

```bash
# Start the FastAPI WebSocket server
python start_server.py
# or
uvicorn websocket_server:app --host 0.0.0.0 --port 8000
```

Then open your browser to `http://localhost:8000` to access the dashboard.

### Option 2: Traditional 1-to-1 PAKE

**Terminal 1 - Start Server:**
```bash
python pake_server.py
```

Copy the base64-encoded public key that appears.

**Terminal 2 - Run Client:**
```bash
# Edit pake_client.py and paste the server's public key into SERVER_PK_B64
python pake_client.py
```

## 💻 Usage

### WebSocket Server (Group Authentication)

#### Starting the Server

```bash
python start_server.py
```

The server will start on `http://localhost:8000`

#### Using the Dashboard

1. **Connect**: Enter a user ID and click "Connect"
2. **Join Group**: Enter a group ID and password, click "Join Group"
3. **View Metrics**: Real-time performance metrics are displayed automatically
4. **Send Messages**: Use the group message functionality (via WebSocket)

#### WebSocket API

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/user_123');
```

**Join Group:**
```json
{
  "type": "join_group",
  "group_id": "group_1",
  "password": "your-password"
}
```

**Leave Group:**
```json
{
  "type": "leave_group",
  "group_id": "group_1"
}
```

**Send Group Message:**
```json
{
  "type": "group_message",
  "group_id": "group_1",
  "message": "Hello group!"
}
```

### REST API Endpoints

- `GET /` - Web dashboard interface
- `GET /api/metrics` - Get performance metrics (JSON)
- `GET /api/groups` - List active groups and users
- `WS /ws/{user_id}` - WebSocket connection endpoint

### Traditional PAKE (1-to-1)

See the original `pake_client.py` and `pake_server.py` for socket-based 1-to-1 authentication.

## 🔄 Workflow

### 1-to-1 PAKE Workflow

1. **Server Initialization**
   - Server generates KEM key pair (public key + secret key)
   - Server listens on port 65432
   - Server public key is displayed (base64 encoded)

2. **Client Connection**
   - Client decodes server's public key
   - Client connects to server via socket

3. **Authentication Phase**
   - Client generates ephemeral KEM keys
   - Client hashes password (PBKDF2 with salt)
   - Client encapsulates password hash using server's public key
   - Client sends `CLIENT_MSG1` to server

4. **Server Verification**
   - Server decapsulates client message
   - Server verifies password hash
   - Server generates confirmation message
   - Server sends `SERVER_MSG1` back

5. **Key Derivation**
   - Both parties derive shared secret from:
     - KEM shared secrets (client→server and server→client)
     - Transcript hash (all exchanged messages)
   - Final key is derived using HKDF

### Group Authentication Workflow

1. **Group Creation**
   - First user joins group → Group is created
   - User generates KEM key pair
   - User stores group ephemeral public key

2. **Subsequent Joins**
   - New user requests to join group
   - User generates KEM key pair
   - Pairwise shared secrets established with existing members
   - Group key derived from all pairwise secrets

3. **Group Key Establishment**
   - When 2+ members present, group key is established
   - HKDF used to derive group key from all shared secrets
   - All members notified of group key establishment

4. **Forward Secrecy (Member Leaves)**
   - When member leaves, group key is updated
   - New ephemeral keys generated
   - Group key re-derived without departed member
   - Remaining members receive updated group key

5. **Async Joins (Pre-Keys)**
   - User generates pre-key bundle (100 keys)
   - Pre-keys stored on server
   - New joiners can use pre-keys when existing members offline
   - Pre-keys consumed after use (one-time)

### Double Ratcheting Workflow

1. **Initialization**
   - Root key established from PAKE protocol
   - DH key pair generated
   - Ratchet initialized with root + DH keys

2. **Message Sending**
   - Ratchet advances forward
   - Chain key derived from previous chain key
   - Message key derived from chain key
   - Message encrypted with message key

3. **Forward Secrecy**
   - Each message uses new key
   - Previous keys cannot decrypt future messages
   - Compromised keys don't affect future security

## 📁 Project Structure

```
mlwe-pake/
├── README.md                      # This file
├── GROUP_FEATURES_README.md       # Detailed group features documentation
├── requirements.txt               # Python dependencies
├── start_server.py                # Quick start script for WebSocket server
│
├── Core PAKE Implementation
│   ├── mlwe_crypto.py             # KEM operations, password hashing, key derivation
│   ├── pake_protocol.py          # PAKE protocol logic (1-to-1)
│   ├── pake_client.py             # Socket-based client implementation
│   └── pake_server.py             # Socket-based server implementation
│
├── Group Extensions
│   ├── group_crypto.py           # Group key agreement, ratcheting, pre-keys
│   ├── websocket_server.py       # FastAPI WebSocket server for groups
│   └── crypto_instrumentation.py # Performance tracking and metrics
│
├── Frontend
│   └── static/
│       ├── frontend.js           # Dashboard JavaScript
│       └── styles.css            # Dashboard styling
│
├── Testing
│   └── test_mlwe_pake.py         # Test suite
│
└── Documentation
    └── flowchart.png             # Protocol flow diagrams
```

## 🔧 Technical Details

### Cryptographic Algorithms

- **KEM Algorithm**: Kyber768 (post-quantum secure)
  - Public key: 1184 bytes
  - Secret key: 2400 bytes
  - Ciphertext: 1088 bytes
  - Shared secret: 32 bytes
- **Password Hashing**: PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Key Derivation**: HKDF-SHA256 (for group keys and ratcheting)
- **Transcript Hashing**: SHA3-256

### Key Components

#### `mlwe_crypto.py`
- `generate_kem_keys()`: Generate KEM key pairs
- `kem_encapsulate()`: Encapsulate shared secret with public key
- `kem_decapsulate()`: Decapsulate shared secret with secret key
- `hash_password_simple()`: Password hashing (PBKDF2)
- `derive_final_secret()`: Final key derivation
- All operations are instrumented for performance tracking

#### `pake_protocol.py`
- `create_client_message1()`: Create first client message
- `process_client_message1()`: Server processes client message
- `process_server_message1()`: Client processes server response
- `calculate_final_key()`: Derive final shared key

#### `group_crypto.py`
- `GroupKeyAgreement`: Manages multi-party groups
  - `add_member()`: Add member to group
  - `establish_group_key()`: Derive shared group key
  - `update_group_key()`: Update key when member leaves
- `DoubleRatcheting`: Forward secrecy mechanism
  - `ratchet_forward()`: Advance ratchet
  - `derive_message_key()`: Derive message encryption key
- `PreKeySystem`: Async join support
  - `generate_pre_key_bundle()`: Generate pre-keys
  - `consume_pre_key()`: Use pre-key for key exchange
- `derive_with_hkdf()`: HKDF-based key derivation
- `ratchet_key_derivation()`: Ratcheting key derivation

#### `crypto_instrumentation.py`
- `CryptoInstrumentation`: Thread-safe metrics collection
  - `start_operation()` / `end_operation()`: Track operation timing
  - `get_stats()`: Get aggregated statistics
  - `get_percentiles()`: Calculate latency percentiles
- `@instrumented`: Decorator for automatic instrumentation

#### `websocket_server.py`
- FastAPI application with WebSocket support
- `ConnectionManager`: Manages WebSocket connections
- Group management handlers
- REST API endpoints for metrics and groups

## 🧪 Testing

### Run Test Suite

```bash
python test_mlwe_pake.py
```

The test suite validates:
- KEM key generation
- KEM encapsulation/decapsulation
- Password hashing
- PAKE protocol flow
- Performance benchmarks

### Manual Testing

1. **Test 1-to-1 PAKE:**
   ```bash
   # Terminal 1
   python pake_server.py
   
   # Terminal 2 (after updating SERVER_PK_B64)
   python pake_client.py
   ```

2. **Test Group Authentication:**
   - Start WebSocket server
   - Open dashboard in multiple browser tabs
   - Connect different users
   - Join same group with same password
   - Verify group key establishment

3. **Test Performance Metrics:**
   - Perform operations through dashboard
   - Monitor `/api/metrics` endpoint
   - Verify metrics update in real-time

## ⚠️ Security Notes

### Important Warnings

**⚠️ THIS IS A DEMONSTRATION IMPLEMENTATION - NOT FOR PRODUCTION USE**

Current security limitations:

1. **Password Hashing**: Uses PBKDF2 (better than raw hash, but not ideal)
   - **For production**: Use Argon2id with proper parameters
   
2. **Password Transmission**: Simplified password handling
   - **For production**: Implement proper OPAQUE-style blinded password handling
   
3. **Key Management**: Keys generated fresh each run
   - **For production**: Implement persistent key storage with proper security
   
4. **Error Handling**: Basic error handling
   - **For production**: Add comprehensive validation and secure error messages
   
5. **Rate Limiting**: Not implemented
   - **For production**: Add rate limiting and DoS protection

### What Makes This Post-Quantum Secure

- **MLWE Cryptography**: Uses Kyber KEM, a NIST-standardized post-quantum algorithm
- **Quantum-Resistant**: Secure against attacks from both classical and quantum computers
- **Forward Secrecy**: Ratcheting ensures past messages remain secure if current keys are compromised
- **Group Forward Secrecy**: Group keys updated when members leave

### Recommended Production Improvements

1. Replace PBKDF2 with Argon2id for password hashing
2. Implement OPAQUE protocol for password handling
3. Add proper key rotation and management
4. Implement message authentication codes (MACs)
5. Add comprehensive logging and audit trails
6. Implement rate limiting and abuse prevention
7. Add TLS for transport security
8. Implement proper session management

## 📊 Performance Metrics

The instrumentation system tracks:

- **Operation Timing**: Average, min, max latencies
- **Throughput**: Bytes processed per second
- **Success Rates**: Percentage of successful operations
- **Percentiles**: P50, P90, P95, P99 latencies

Example metrics output:
```json
{
  "kem_key_generation": {
    "count": 100,
    "avg_time_ms": 15.23,
    "min_time_ms": 12.45,
    "max_time_ms": 18.67,
    "throughput_bps": 235689.45,
    "success_rate": 100.0
  }
}
```

## 🛠️ Development

### Adding New Features

1. Crypto operations should use `@instrumented` decorator
2. Group operations go in `group_crypto.py`
3. WebSocket handlers in `websocket_server.py`
4. Frontend updates in `static/` directory

### Code Structure Guidelines

- Keep crypto operations in `mlwe_crypto.py`
- Protocol logic in `pake_protocol.py`
- Group extensions in `group_crypto.py`
- All crypto functions should be instrumented

## 📚 Additional Documentation

- `GROUP_FEATURES_README.md` - Detailed group authentication features
- `test_mlwe_pake.py` - Example usage and testing patterns

## 🤝 Contributing

This is an educational/demonstration project. Contributions welcome for:
- Security improvements
- Performance optimizations
- Additional features
- Documentation improvements

## 📄 License

See LICENSE file in the repository.

## 🔗 References

- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [liboqs Documentation](https://github.com/open-quantum-safe/liboqs)
- [Kyber Algorithm Specification](https://pq-crystals.org/kyber/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

## 📞 Support

For issues, questions, or contributions, please use the GitHub issues page.

---

**Note**: This implementation is for educational and demonstration purposes. Always use production-grade cryptographic libraries and follow security best practices for real-world applications.
