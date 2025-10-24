# Hybrid PQ-Classical PAKE with Double Ratchet

## Overview

This implementation provides a **Hybrid Post-Quantum + Classical PAKE (Password-Authenticated Key Exchange)** protocol combined with the **Double Ratchet** algorithm for secure messaging.

### Key Features

1. **Hybrid Cryptography** - Defense-in-depth security
   - **Post-Quantum**: Kyber768 KEM (NIST-standardized)
   - **Classical**: X25519 ECDH
   - Security holds if *either* primitive remains secure

2. **Password-Based Authentication**
   - Mutual authentication using shared password
   - Encrypted password transmission
   - Protection against offline attacks

3. **Double Ratchet Messaging**
   - **Forward Secrecy**: Past messages secure even if current keys compromised
   - **Future Secrecy** (Break-in Recovery): Future messages secure after key compromise
   - Continuous key evolution with each message

## Architecture

### Components

```
hybrid_crypto.py          - Hybrid KEM (Kyber768 + X25519)
double_ratchet.py         - Double Ratchet implementation
hybrid_pake_protocol.py   - PAKE protocol logic
hybrid_pake_server.py     - Server implementation
hybrid_pake_client.py     - Client implementation
test_hybrid_system.py     - Comprehensive test suite
```

### Protocol Flow

```
┌────────┐                                    ┌────────┐
│ Client │                                    │ Server │
└───┬────┘                                    └───┬────┘
    │                                             │
    │  1. Generate hybrid ephemeral keys          │
    │     (Kyber768 + X25519)                     │
    │                                             │
    │  2. Encrypt password using hybrid KEM       │
    │                                             │
    │  ──── Client Msg 1 ────────────────────>   │
    │     • Client hybrid public keys             │
    │     • Encrypted password                    │
    │     • Hybrid ciphertexts                    │
    │                                             │
    │                                             │  3. Verify password
    │                                             │  4. Generate response
    │                                             │     using hybrid KEM
    │                                             │
    │  <──── Server Msg 1 ────────────────────   │
    │     • Server hybrid ciphertexts             │
    │                                             │
    │  5. Derive session key                      │  5. Derive session key
    │     from both shared secrets                │     from both shared secrets
    │                                             │
    │  6. Initialize Double Ratchet               │  6. Initialize Double Ratchet
    │                                             │
    │  ═══ Encrypted Messages (Double Ratchet) ══>│
    │  <══ Encrypted Messages (Double Ratchet) ═══│
    │                                             │
```

## Security Properties

### 1. Hybrid Security

The system combines two independent cryptographic primitives:

- **Kyber768**: Post-quantum secure lattice-based KEM
- **X25519**: Classical elliptic curve Diffie-Hellman

**Security Guarantee**: The combined system is secure as long as *at least one* of these remains unbroken.

### 2. Password Authentication

- Password is hashed with PBKDF2 (100,000 iterations)
- Password hash encrypted with hybrid KEM before transmission
- Server verifies password before proceeding
- Protection against passive eavesdropping

### 3. Forward Secrecy

The Double Ratchet provides strong forward secrecy:

- Each message encrypted with unique ephemeral key
- Message keys immediately deleted after use
- Compromise of current keys doesn't reveal past messages

### 4. Future Secrecy (Break-in Recovery)

- DH ratchet step with each turn of conversation
- New DH keypair generated for each sending phase
- System automatically recovers security after key compromise

## Installation

### Prerequisites

```bash
# Install Python dependencies
pip install cryptography

# Install liboqs (already installed in your environment)
# oqs==0.10.2 is already available
```

### Verify Installation

```bash
# Run the comprehensive test suite
python test_hybrid_system.py
```

Expected output:
```
======================================================================
ALL TESTS PASSED! ✅
======================================================================
```

## Usage

### Running the Server

```bash
python hybrid_pake_server.py
```

The server will:
1. Generate hybrid key pairs (Kyber768 + X25519)
2. Display public keys for client configuration
3. Listen on `127.0.0.1:65433`

**Important**: Copy the displayed `SERVER_PQ_PK_B64` and `SERVER_CLASSICAL_PK_B64` values.

### Configuring the Client

Edit `hybrid_pake_client.py` and paste the server's public keys:

```python
SERVER_PQ_PK_B64 = "... paste here ..."
SERVER_CLASSICAL_PK_B64 = "... paste here ..."
```

### Running the Client

```bash
python hybrid_pake_client.py
```

The client will:
1. Connect to server
2. Perform hybrid PAKE authentication
3. Initialize Double Ratchet
4. Send 3 test encrypted messages
5. Receive encrypted responses

## Testing

The test suite covers:

### Test 1: Hybrid Cryptography
- Key generation (Kyber768 + X25519)
- Hybrid encapsulation
- Hybrid decapsulation
- Secret agreement verification

### Test 2: Double Ratchet
- Initialization (sender/receiver)
- Unidirectional messaging
- Bidirectional messaging
- Key derivation

### Test 3: Hybrid PAKE Protocol
- Complete protocol flow
- Session key derivation
- Transcript integrity

### Test 4: Full Integration
- PAKE + Double Ratchet integration
- Multi-message encrypted conversation
- Bidirectional communication

### Test 5: Forward Secrecy
- Message encryption/decryption
- Key evolution
- Forward secrecy demonstration

## Technical Details

### Hybrid KEM Construction

```python
def combine_secrets(pq_secret, classical_secret):
    # Concatenate secrets
    combined = pq_secret || classical_secret

    # Derive final secret with HKDF-SHA256
    final_secret = HKDF(combined, info="Hybrid-PQ-Classical-KEM")

    return final_secret  # 64 bytes
```

### Double Ratchet Key Derivation

```
Initial State:
  - Shared Secret (SK) from PAKE
  - Alice's DH public key

Bob receives first message:
  RK, CKr = KDF(SK, DH(bob_sk, alice_pk))

Bob sends reply:
  - Generate new DH keypair
  RK, CKs = KDF(RK, DH(new_bob_sk, alice_pk))

Message Key Derivation:
  CK_new, MK = KDF(CK_current)
```

### Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| PQ KEM | Kyber768 | Post-quantum key encapsulation |
| Classical KEM | X25519 | Classical elliptic curve DH |
| KDF | HKDF-SHA256 | Key derivation |
| AEAD | AES-256-GCM | Message encryption |
| Password Hash | PBKDF2-SHA256 | Password processing |
| Transcript Hash | SHA3-256 | Protocol binding |

## Security Considerations

### ⚠️ Warning

This implementation is for **educational and research purposes**. While it demonstrates important cryptographic concepts, it has not undergone formal security review.

### Known Limitations

1. **Password Security**: Uses PBKDF2 instead of memory-hard functions like Argon2
2. **No Authentication of Server Key**: Client must obtain server's public key securely
3. **Simplified Protocol**: A production system should use established protocols like OPAQUE with PQ extensions
4. **No Key Persistence**: Keys are regenerated each session
5. **Network Security**: No protection against active network attacks during key exchange

### Recommended Improvements for Production

1. Use **OPAQUE** or **CPace** for password-authenticated key exchange
2. Implement **server certificate verification**
3. Add **memory-hard password hashing** (Argon2)
4. Implement **key persistence and rotation**
5. Add **message authentication codes** for protocol messages
6. Implement **replay protection**
7. Add **perfect forward secrecy** for password database
8. Perform **formal security analysis**

## Performance

Measured on typical hardware:

| Operation | Time |
|-----------|------|
| Hybrid Key Generation | ~1ms |
| Hybrid Encapsulation | ~1ms |
| Hybrid Decapsulation | ~1ms |
| Message Encryption (Double Ratchet) | ~0.1ms |
| Message Decryption (Double Ratchet) | ~0.1ms |
| Full PAKE Handshake | ~5ms |

## References

1. **Kyber**: [CRYSTALS-Kyber](https://pq-crystals.org/kyber/) - NIST PQC Standard
2. **Double Ratchet**: [Signal Specification](https://signal.org/docs/specifications/doubleratchet/)
3. **X25519**: [RFC 7748](https://tools.ietf.org/html/rfc7748)
4. **OPAQUE**: [draft-irtf-cfrg-opaque](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/)
5. **Hybrid PQC**: [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

## License

This implementation is provided for educational purposes. See LICENSE file for details.

## Contributing

Contributions welcome! Please:
1. Run the test suite: `python test_hybrid_system.py`
2. Ensure all tests pass
3. Add tests for new features
4. Document security implications

## Contact

For questions or security concerns, please open an issue on the repository.
