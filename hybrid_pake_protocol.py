"""
Hybrid PQ-Classical PAKE Protocol with Double Ratchet

Combines:
1. Hybrid KEM (Kyber768 + X25519) for initial key exchange
2. Password authentication
3. Double Ratchet for ongoing messaging with forward secrecy

WARNING: This is still a demonstration implementation.
Production systems should use established protocols like OPAQUE with PQ extensions.
"""

import json
import base64
import hashlib
from hybrid_crypto import (
    generate_hybrid_keys,
    hybrid_encapsulate,
    hybrid_decapsulate,
    derive_key_from_secret
)
from mlwe_crypto import hash_password_simple, hash_transcript
from double_ratchet import DoubleRatchet


def create_hybrid_client_message1(client_id, password, server_pq_pk, server_classical_pk):
    """
    Creates the first client message using hybrid cryptography.

    Args:
        client_id: Client identifier
        password: Client password
        server_pq_pk: Server's Kyber768 public key
        server_classical_pk: Server's X25519 public key

    Returns:
        tuple: (message_dict, client_context, transcript)
    """
    print(f"\n=== Client Message 1 Creation ===")

    # 1. Generate client's ephemeral hybrid keys
    client_keypair = generate_hybrid_keys()
    client_pq_pk, client_classical_pk = client_keypair.get_public_keys()

    # 2. Process password with salt
    salt, password_hash = hash_password_simple(password)

    # 3. Perform hybrid encapsulation to server
    try:
        pq_ct, classical_ephemeral_pk, shared_secret_cs = hybrid_encapsulate(
            server_pq_pk, server_classical_pk
        )

        print(f"Client→Server shared secret established: {len(shared_secret_cs)} bytes")

        # Derive key for password encryption
        pwd_key = derive_key_from_secret(shared_secret_cs, b"password-encryption", 32)

        # Encrypt password hash with AES-GCM
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os

        aesgcm = AESGCM(pwd_key)
        nonce = os.urandom(12)
        encrypted_password = aesgcm.encrypt(nonce, password_hash, salt)

    except Exception as e:
        print(f"Error during client hybrid encapsulation: {e}")
        return None, None, None

    # 4. Construct message
    message = {
        "type": "HYBRID_CLIENT_MSG1",
        "client_id": client_id,
        "client_pq_pk": base64.b64encode(client_pq_pk).decode('utf-8'),
        "client_classical_pk": base64.b64encode(client_classical_pk).decode('utf-8'),
        "pq_ciphertext": base64.b64encode(pq_ct).decode('utf-8'),
        "classical_ephemeral_pk": base64.b64encode(classical_ephemeral_pk).decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "encrypted_password": base64.b64encode(encrypted_password).decode('utf-8')
    }

    # Store client context
    client_context = {
        "keypair": client_keypair,
        "shared_secret_cs": shared_secret_cs
    }

    # Transcript contains the serialized message
    message_bytes = json.dumps(message, sort_keys=True).encode('utf-8')
    transcript = [message_bytes]

    print(f"Client Message 1 created successfully")
    return message, client_context, transcript


def process_hybrid_client_message1(message_bytes, server_id, server_keypair, expected_password):
    """
    Processes the first client message on the server using hybrid cryptography.

    Args:
        message_bytes: Received message bytes
        server_id: Server identifier
        server_keypair: Server's HybridKeyPair
        expected_password: Expected client password

    Returns:
        tuple: (response_message, server_context, transcript)
    """
    print(f"\n=== Server Processing Client Message 1 ===")

    try:
        message = json.loads(message_bytes.decode('utf-8'))
        if message.get("type") != "HYBRID_CLIENT_MSG1":
            raise ValueError("Invalid message type")

        client_id = message["client_id"]
        client_pq_pk = base64.b64decode(message["client_pq_pk"])
        client_classical_pk = base64.b64decode(message["client_classical_pk"])
        pq_ciphertext = base64.b64decode(message["pq_ciphertext"])
        classical_ephemeral_pk = base64.b64decode(message["classical_ephemeral_pk"])
        salt = base64.b64decode(message["salt"])
        nonce = base64.b64decode(message["nonce"])
        encrypted_password = base64.b64decode(message["encrypted_password"])

        # 1. Perform hybrid decapsulation
        server_pq_sk, server_classical_sk = server_keypair.get_secret_keys()
        shared_secret_cs = hybrid_decapsulate(
            server_pq_sk,
            server_classical_sk,
            pq_ciphertext,
            classical_ephemeral_pk
        )

        print(f"Server recovered Client→Server shared secret: {len(shared_secret_cs)} bytes")

        # 2. Decrypt and verify password
        pwd_key = derive_key_from_secret(shared_secret_cs, b"password-encryption", 32)

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(pwd_key)

        try:
            password_hash_received = aesgcm.decrypt(nonce, encrypted_password, salt)
        except Exception as e:
            print(f"Server: Password decryption failed: {e}")
            return None, None, None

        # Verify password
        _, expected_password_hash = hash_password_simple(expected_password, salt)
        if password_hash_received != expected_password_hash:
            print("Server: Password verification failed!")
            return None, None, None

        print("Server: Client password verified successfully")

        # 3. Perform hybrid encapsulation back to client
        pq_ct_sc, classical_ephemeral_pk_sc, shared_secret_sc = hybrid_encapsulate(
            client_pq_pk, client_classical_pk
        )

        print(f"Server→Client shared secret established: {len(shared_secret_sc)} bytes")

        # 4. Construct response message
        response = {
            "type": "HYBRID_SERVER_MSG1",
            "server_id": server_id,
            "pq_ciphertext_sc": base64.b64encode(pq_ct_sc).decode('utf-8'),
            "classical_ephemeral_pk_sc": base64.b64encode(classical_ephemeral_pk_sc).decode('utf-8')
        }

        # Store server context
        server_context = {
            "shared_secret_cs": shared_secret_cs,
            "shared_secret_sc": shared_secret_sc
        }

        # Transcript: both messages as bytes
        response_bytes = json.dumps(response, sort_keys=True).encode('utf-8')
        transcript = [message_bytes, response_bytes]

        print(f"Server Message 1 created successfully")
        return response, server_context, transcript

    except Exception as e:
        print(f"Server: Error processing client message: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None


def process_hybrid_server_message1(message_bytes, client_context):
    """
    Processes the server's response on the client using hybrid cryptography.

    Args:
        message_bytes: Received message bytes
        client_context: Client's context from message 1

    Returns:
        tuple: (final_client_context, transcript_update)
    """
    print(f"\n=== Client Processing Server Message 1 ===")

    try:
        message = json.loads(message_bytes.decode('utf-8'))
        if message.get("type") != "HYBRID_SERVER_MSG1":
            raise ValueError("Invalid message type")

        server_id = message["server_id"]
        pq_ciphertext_sc = base64.b64decode(message["pq_ciphertext_sc"])
        classical_ephemeral_pk_sc = base64.b64decode(message["classical_ephemeral_pk_sc"])

        # 1. Perform hybrid decapsulation
        keypair = client_context["keypair"]
        client_pq_sk, client_classical_sk = keypair.get_secret_keys()

        shared_secret_sc = hybrid_decapsulate(
            client_pq_sk,
            client_classical_sk,
            pq_ciphertext_sc,
            classical_ephemeral_pk_sc
        )

        print(f"Client recovered Server→Client shared secret: {len(shared_secret_sc)} bytes")

        # Client context now holds both necessary secrets
        final_client_context = {
            "shared_secret_cs": client_context["shared_secret_cs"],
            "shared_secret_sc": shared_secret_sc
        }

        transcript_update = [message_bytes]

        print(f"Client processing complete")
        return final_client_context, transcript_update

    except Exception as e:
        print(f"Client error processing server message: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def derive_session_key(context, transcript_messages):
    """
    Derives the final session key from the hybrid PAKE protocol.

    This key will be used to initialize the Double Ratchet.

    Args:
        context: Protocol context with shared secrets
        transcript_messages: List of all protocol messages

    Returns:
        bytes: 64-byte session key for Double Ratchet initialization
    """
    print(f"\n=== Deriving Session Key ===")

    # Hash the transcript
    transcript_hash = hash_transcript(transcript_messages)

    # Combine both shared secrets with transcript hash
    h = hashlib.sha3_512()
    h.update(b"HybridPAKE-SessionKey")
    h.update(context["shared_secret_cs"])
    h.update(context["shared_secret_sc"])
    h.update(transcript_hash)

    session_key = h.digest()  # 64 bytes

    print(f"Session key derived: {len(session_key)} bytes")
    print(f"Session key (first 16 bytes): {session_key[:16].hex()}")

    return session_key


def initialize_double_ratchet_from_pake(session_key, is_initiator, remote_public_key=None):
    """
    Initializes a Double Ratchet instance from the PAKE session key.

    Args:
        session_key: Session key from PAKE protocol
        is_initiator: True if this party initiated the PAKE, False otherwise
        remote_public_key: Remote party's DH public key (required if not initiator)

    Returns:
        DoubleRatchet: Initialized Double Ratchet instance
    """
    print(f"\n=== Initializing Double Ratchet ===")
    print(f"Party role: {'Initiator' if is_initiator else 'Responder'}")

    if is_initiator:
        ratchet = DoubleRatchet(session_key, sending=True)
    else:
        if remote_public_key is None:
            raise ValueError("Responder needs remote_public_key")
        ratchet = DoubleRatchet(session_key, sending=False, remote_public_key=remote_public_key)

    print(f"Double Ratchet initialized successfully")

    return ratchet
