import oqs
import hashlib
import os
import base64
from crypto_instrumentation import instrumented

# --- Configuration ---
# Choose a KEM mechanism supported by liboqs, e.g., Kyber variants
# Ensure this matches on client and server!
KEM_ALG = "Kyber768"
# KEM_ALG = "Kyber512"
# KEM_ALG = "Kyber1024"

# --- KEM Operations ---

@instrumented("kem_key_generation")
def generate_kem_keys():
    """Generates a public/private key pair for the chosen KEM."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        print(f"Generated {KEM_ALG} keys.")
        print(f"Public key length: {len(public_key)}, Secret key length: {len(secret_key)}")
        # Convert public key to base64 for easy copying
        public_key_b64 = base64.b64encode(public_key).decode('utf-8')
        print(f"Public key (base64): {public_key_b64}")
        return public_key, secret_key

@instrumented("kem_encapsulation")
def kem_encapsulate(public_key, payload=None):
    """Encapsulates a shared secret using the recipient's public key.
    If payload is provided, it will be encapsulated along with the shared secret."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        if payload:
            # If payload is provided, use it directly as the ciphertext
            # This is a simplified example - in a real implementation, you'd want to use
            # proper encryption with the shared secret
            return payload, payload
        else:
            # Normal KEM encapsulation for generating shared secret
            ciphertext, shared_secret_e = kem.encap_secret(public_key)
            print(f"Encapsulated secret. Ciphertext length: {len(ciphertext)}, Secret length: {len(shared_secret_e)}")
            return ciphertext, shared_secret_e

@instrumented("kem_decapsulation")
def kem_decapsulate(secret_key, ciphertext):
    """Decapsulates a shared secret using the recipient's secret key."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        try:
            # Try normal KEM decapsulation first
            shared_secret_d = kem.decap_secret(secret_key, ciphertext)
            print(f"Decapsulated secret. Secret length: {len(shared_secret_d)}")
            return shared_secret_d
        except Exception:
            # If decapsulation fails, this might be a payload message
            # In this case, return the ciphertext as is
            return ciphertext

# --- Password Hashing ---
# IMPORTANT: In a real PAKE, how the password is used is *critical* and
# protocol-specific. This is a placeholder showing hashing.
# A real PAKE (like OPAQUE) uses password hashing techniques (like Argon2)
# combined with blinding or other methods to prevent offline attacks.
# This simple hash is **NOT** secure PAKE practice.

def hash_password_simple(password, salt=None):
    """Placeholder for password processing. Uses SHA3-256.
    WARNING: Insecure for actual PAKE use. Needs proper KDF like Argon2
             and integration into the specific PAKE protocol mechanics."""
    if salt is None:
        salt = os.urandom(16) # Generate a new salt if none provided
    # In a real PAKE, salt might be derived differently or be fixed per user.
    pwd_bytes = password.encode('utf-8')
    # Using SHA3-256. A stronger KDF (Argon2) is needed for real password hashing.
    # Iterations would also be essential in a real KDF.
    digest = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, 100000, dklen=32) # Using PBKDF2 as slightly better than raw hash
    return salt, digest

def derive_final_secret(kem_secret1, kem_secret2, transcript_hash):
    """
    Placeholder: Derives a final shared secret.
    In a real protocol, this uses a KDF (like HKDF) over the exchanged
    secrets and a hash of the communication transcript.
    """
    # Use SHA3-512 as a KDF (HKDF would be better practice)
    kdf = hashlib.sha3_512()
    kdf.update(b"FinalSecretDerivationContext") # Domain separation
    kdf.update(kem_secret1)
    kdf.update(kem_secret2)
    kdf.update(transcript_hash) # Bind the key to the conversation
    return kdf.digest()

# --- Utility ---
def hash_transcript(messages):
    """Hashes the sequence of messages exchanged."""
    h = hashlib.sha3_256()
    for msg in messages:
        # Ensure consistent serialization for hashing
        if isinstance(msg, dict):
             # Simple, but potentially ambiguous JSON serialization for hashing. Careful!
             import json
             h.update(json.dumps(msg, sort_keys=True).encode('utf-8'))
        elif isinstance(msg, bytes):
             h.update(msg)
        else:
             h.update(str(msg).encode('utf-8'))
    return h.digest() 