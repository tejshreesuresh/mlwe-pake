"""
Hybrid Post-Quantum + Classical Cryptography Module

Combines:
- Kyber768 (Post-Quantum KEM)
- X25519 (Classical ECDH)

This provides defense-in-depth: security holds if either primitive is secure.
"""

import oqs
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# --- Configuration ---
KEM_ALG = "Kyber768"


class HybridKeyPair:
    """Holds both PQ and classical key pairs"""
    def __init__(self):
        # Generate Kyber768 keys
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            self.pq_public_key = kem.generate_keypair()
            self.pq_secret_key = kem.export_secret_key()

        # Generate X25519 keys
        self.classical_secret_key = x25519.X25519PrivateKey.generate()
        self.classical_public_key = self.classical_secret_key.public_key()

    def get_public_keys(self):
        """Returns tuple of (pq_pk, classical_pk_bytes)"""
        classical_pk_bytes = self.classical_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return self.pq_public_key, classical_pk_bytes

    def get_secret_keys(self):
        """Returns tuple of (pq_sk, classical_sk)"""
        return self.pq_secret_key, self.classical_secret_key


def generate_hybrid_keys():
    """
    Generates a hybrid public/private key pair.

    Returns:
        HybridKeyPair: Object containing both PQ and classical keys
    """
    keypair = HybridKeyPair()
    pq_pk, classical_pk_bytes = keypair.get_public_keys()

    print(f"Generated hybrid keys:")
    print(f"  - Kyber768 public key length: {len(pq_pk)} bytes")
    print(f"  - X25519 public key length: {len(classical_pk_bytes)} bytes")

    return keypair


def hybrid_encapsulate(pq_public_key, classical_public_key_bytes):
    """
    Performs hybrid encapsulation using both Kyber and X25519.

    Args:
        pq_public_key: Kyber768 public key (bytes)
        classical_public_key_bytes: X25519 public key (bytes)

    Returns:
        tuple: (pq_ciphertext, classical_public_key_ephemeral, shared_secret)
    """
    # 1. Kyber encapsulation
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        pq_ciphertext, pq_shared_secret = kem.encap_secret(pq_public_key)

    # 2. X25519 key exchange
    # Generate ephemeral X25519 key pair
    classical_ephemeral_sk = x25519.X25519PrivateKey.generate()
    classical_ephemeral_pk = classical_ephemeral_sk.public_key()

    # Perform DH key exchange
    classical_public_key = x25519.X25519PublicKey.from_public_bytes(classical_public_key_bytes)
    classical_shared_secret = classical_ephemeral_sk.exchange(classical_public_key)

    # 3. Combine secrets using HKDF
    shared_secret = combine_secrets(pq_shared_secret, classical_shared_secret)

    # Return both ciphertexts and the combined secret
    classical_ephemeral_pk_bytes = classical_ephemeral_pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    print(f"Hybrid encapsulation complete:")
    print(f"  - PQ ciphertext length: {len(pq_ciphertext)} bytes")
    print(f"  - Classical ephemeral PK length: {len(classical_ephemeral_pk_bytes)} bytes")
    print(f"  - Combined shared secret length: {len(shared_secret)} bytes")

    return pq_ciphertext, classical_ephemeral_pk_bytes, shared_secret


def hybrid_decapsulate(pq_secret_key, classical_secret_key, pq_ciphertext, classical_ephemeral_pk_bytes):
    """
    Performs hybrid decapsulation using both Kyber and X25519.

    Args:
        pq_secret_key: Kyber768 secret key (bytes)
        classical_secret_key: X25519PrivateKey object
        pq_ciphertext: Kyber768 ciphertext (bytes)
        classical_ephemeral_pk_bytes: X25519 ephemeral public key (bytes)

    Returns:
        bytes: Combined shared secret
    """
    # 1. Kyber decapsulation
    # Must use with context to load secret key, then decapsulate
    with oqs.KeyEncapsulation(KEM_ALG, secret_key=pq_secret_key) as kem:
        pq_shared_secret = kem.decap_secret(pq_ciphertext)

    # 2. X25519 key exchange
    classical_ephemeral_pk = x25519.X25519PublicKey.from_public_bytes(classical_ephemeral_pk_bytes)
    classical_shared_secret = classical_secret_key.exchange(classical_ephemeral_pk)

    # 3. Combine secrets using HKDF
    shared_secret = combine_secrets(pq_shared_secret, classical_shared_secret)

    print(f"Hybrid decapsulation complete:")
    print(f"  - Combined shared secret length: {len(shared_secret)} bytes")

    return shared_secret


def combine_secrets(pq_secret, classical_secret):
    """
    Combines PQ and classical shared secrets using HKDF.

    This ensures that the final secret is secure as long as at least
    one of the primitives is secure.

    Args:
        pq_secret: Shared secret from post-quantum KEM
        classical_secret: Shared secret from classical ECDH

    Returns:
        bytes: Combined 64-byte shared secret
    """
    # Concatenate the secrets
    combined_input = pq_secret + classical_secret

    # Use HKDF to derive a final secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # 512 bits
        salt=None,
        info=b"Hybrid-PQ-Classical-KEM"
    )

    derived_secret = hkdf.derive(combined_input)
    return derived_secret


def derive_key_from_secret(shared_secret, context_info, length=32):
    """
    Derives a key from a shared secret using HKDF.

    Args:
        shared_secret: The shared secret (bytes)
        context_info: Context-specific information (bytes)
        length: Length of the derived key in bytes

    Returns:
        bytes: Derived key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=context_info
    )

    return hkdf.derive(shared_secret)
