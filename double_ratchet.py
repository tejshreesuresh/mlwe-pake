"""
Double Ratchet Algorithm Implementation

Based on Signal's Double Ratchet specification:
https://signal.org/docs/specifications/doubleratchet/

Provides:
- Forward Secrecy: Past messages cannot be decrypted if current keys are compromised
- Future Secrecy (Break-in Recovery): Future messages are secure even if keys are temporarily compromised
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


# Constants
MAX_SKIP = 1000  # Maximum number of message keys to skip


class DoubleRatchet:
    """
    Implements the Double Ratchet algorithm for secure messaging.

    The Double Ratchet has two stages:
    1. Symmetric-key ratchet: Updates chain keys with each message
    2. DH ratchet: Updates root key when receiving new DH public key
    """

    def __init__(self, shared_secret, sending=True, remote_public_key=None):
        """
        Initialize Double Ratchet.

        Args:
            shared_secret: Initial shared secret from PAKE (bytes)
            sending: True if this party sends first, False otherwise
            remote_public_key: Remote party's initial DH public key (bytes), required for receiver
        """
        # Root key (RK) - updated with DH ratchet
        self.root_key = shared_secret

        # Chain keys (CK) - updated with symmetric ratchet
        self.sending_chain_key = None
        self.receiving_chain_key = None

        # DH ratchet keys
        self.dh_keypair = None
        self.dh_remote_public_key = None

        # Message numbers
        self.sending_message_number = 0
        self.receiving_message_number = 0
        self.previous_sending_chain_length = 0

        # Skipped message keys (for out-of-order messages)
        self.skipped_message_keys = {}  # {(dh_public_key, msg_num): message_key}

        if sending:
            # Initialize as sender
            self._initialize_sender()
        else:
            # Initialize as receiver
            if remote_public_key is None:
                raise ValueError("Receiver must have remote_public_key")
            self._initialize_receiver(remote_public_key)

    def _initialize_sender(self):
        """Initialize as the sending party"""
        # Generate initial DH keypair
        self.dh_keypair = x25519.X25519PrivateKey.generate()

        # Sender doesn't initialize sending chain yet - it will be initialized
        # after the first DH ratchet step when the receiver's public key is received
        # For now, we derive an initial sending chain from the root key
        # This is used for the very first message before any DH ratchet
        self.sending_chain_key = self._kdf_chain_key(self.root_key, b"initial-chain")

    def _initialize_receiver(self, remote_public_key_bytes):
        """Initialize as the receiving party"""
        # Store remote public key
        self.dh_remote_public_key = remote_public_key_bytes

        # For the initial message, derive receiving chain directly from root key
        # This matches what the sender does for their initial sending chain
        self.receiving_chain_key = self._kdf_chain_key(self.root_key, b"initial-chain")

        # Generate our DH keypair for future messages
        self.dh_keypair = x25519.X25519PrivateKey.generate()

    def _kdf_root_key(self, root_key, dh_output):
        """
        KDF for root key ratchet step.

        Args:
            root_key: Current root key
            dh_output: DH output from ratchet step

        Returns:
            tuple: (new_root_key, new_chain_key)
        """
        # Use HKDF to derive both new root key and chain key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for RK + 32 bytes for CK
            salt=root_key,
            info=b"DoubleRatchet-RootKey-KDF"
        )

        output = hkdf.derive(dh_output)
        new_root_key = output[:32]
        new_chain_key = output[32:]

        return new_root_key, new_chain_key

    def _kdf_chain_key(self, chain_key, context=b""):
        """
        KDF for chain key ratchet step.

        Args:
            chain_key: Current chain key
            context: Optional context for derivation

        Returns:
            bytes: New chain key or message key
        """
        h = hashlib.sha256()
        h.update(chain_key)
        h.update(context)
        return h.digest()

    def _derive_message_key(self, chain_key):
        """
        Derives a message key from a chain key.

        Args:
            chain_key: Current chain key

        Returns:
            tuple: (new_chain_key, message_key)
        """
        # Derive message key
        message_key = self._kdf_chain_key(chain_key, b"message-key")

        # Derive next chain key
        new_chain_key = self._kdf_chain_key(chain_key, b"chain-key")

        return new_chain_key, message_key

    def _dh_ratchet_for_sending(self):
        """
        Perform DH ratchet to initialize sending chain.
        Used when we need to send but don't have a sending chain yet.
        """
        if self.dh_remote_public_key is None:
            raise Exception("No remote DH key available for ratchet")

        # Generate new DH keypair
        self.dh_keypair = x25519.X25519PrivateKey.generate()

        # Perform DH with remote public key
        remote_public_key = x25519.X25519PublicKey.from_public_bytes(self.dh_remote_public_key)
        dh_output = self.dh_keypair.exchange(remote_public_key)

        # Update root key and derive sending chain
        self.root_key, self.sending_chain_key = self._kdf_root_key(self.root_key, dh_output)
        self.previous_sending_chain_length = self.sending_message_number
        self.sending_message_number = 0

    def _dh_ratchet_step_sending(self, remote_public_key_bytes):
        """
        Perform DH ratchet step when starting to send.

        Args:
            remote_public_key_bytes: Remote party's DH public key
        """
        # Store remote public key
        remote_public_key = x25519.X25519PublicKey.from_public_bytes(remote_public_key_bytes)
        self.dh_remote_public_key = remote_public_key_bytes

        # Perform DH with current keypair and remote public key
        dh_output = self.dh_keypair.exchange(remote_public_key)

        # Update root key and receiving chain key
        self.root_key, self.receiving_chain_key = self._kdf_root_key(self.root_key, dh_output)
        self.receiving_message_number = 0

        # Generate new DH keypair
        self.dh_keypair = x25519.X25519PrivateKey.generate()

        # Perform DH with new keypair
        dh_output = self.dh_keypair.exchange(remote_public_key)

        # Update root key and sending chain key
        self.root_key, self.sending_chain_key = self._kdf_root_key(self.root_key, dh_output)
        self.previous_sending_chain_length = self.sending_message_number
        self.sending_message_number = 0

    def _dh_ratchet_step_receiving(self, remote_public_key_bytes):
        """
        Perform DH ratchet step when receiving.

        Args:
            remote_public_key_bytes: Remote party's DH public key
        """
        # Generate keypair if this is the first time
        if self.dh_keypair is None:
            self.dh_keypair = x25519.X25519PrivateKey.generate()

        # Store previous chain length before ratcheting
        self.previous_sending_chain_length = self.sending_message_number

        # Store remote public key
        remote_public_key = x25519.X25519PublicKey.from_public_bytes(remote_public_key_bytes)
        self.dh_remote_public_key = remote_public_key_bytes

        # Perform DH with current keypair and remote public key
        dh_output = self.dh_keypair.exchange(remote_public_key)

        # Update root key and receiving chain key
        self.root_key, self.receiving_chain_key = self._kdf_root_key(self.root_key, dh_output)
        self.receiving_message_number = 0

    def encrypt_message(self, plaintext, associated_data=b""):
        """
        Encrypts a message using the Double Ratchet.

        Args:
            plaintext: Message to encrypt (bytes)
            associated_data: Additional authenticated data (bytes)

        Returns:
            dict: Encrypted message header and ciphertext
        """
        # If we don't have a sending chain, perform DH ratchet first
        if self.sending_chain_key is None:
            if self.dh_remote_public_key is None:
                raise Exception("Cannot encrypt: no sending chain and no remote DH key")
            # Perform DH ratchet to establish sending chain
            self._dh_ratchet_for_sending()

        # Get current DH public key
        dh_public_key = self.dh_keypair.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Derive message key from sending chain
        self.sending_chain_key, message_key = self._derive_message_key(self.sending_chain_key)

        # Encrypt with AES-GCM
        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        # Create message header
        message = {
            "dh_public_key": dh_public_key,
            "previous_chain_length": self.previous_sending_chain_length,
            "message_number": self.sending_message_number,
            "nonce": nonce,
            "ciphertext": ciphertext
        }

        # Increment message number
        self.sending_message_number += 1

        return message

    def decrypt_message(self, message, associated_data=b""):
        """
        Decrypts a message using the Double Ratchet.

        Args:
            message: Encrypted message dict with header and ciphertext
            associated_data: Additional authenticated data (bytes)

        Returns:
            bytes: Decrypted plaintext

        Raises:
            Exception: If decryption fails
        """
        dh_public_key = message["dh_public_key"]
        message_number = message["message_number"]
        nonce = message["nonce"]
        ciphertext = message["ciphertext"]

        # Check if we need to perform DH ratchet
        if self.dh_remote_public_key != dh_public_key:
            # New DH public key received, perform ratchet
            self._skip_message_keys(message["previous_chain_length"])
            self._dh_ratchet_step_receiving(dh_public_key)

        # Check if we need to skip message keys
        self._skip_message_keys(message_number)

        # Derive message key from receiving chain
        self.receiving_chain_key, message_key = self._derive_message_key(self.receiving_chain_key)
        self.receiving_message_number += 1

        # Decrypt with AES-GCM
        aesgcm = AESGCM(message_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except Exception as e:
            raise Exception(f"Decryption failed: {e}")

    def _skip_message_keys(self, until):
        """
        Skips message keys for out-of-order messages.

        Args:
            until: Message number to skip until
        """
        if self.receiving_message_number + MAX_SKIP < until:
            raise Exception("Too many skipped messages")

        if self.receiving_chain_key is not None:
            while self.receiving_message_number < until:
                # Derive and store skipped message key
                self.receiving_chain_key, message_key = self._derive_message_key(
                    self.receiving_chain_key
                )
                key = (self.dh_remote_public_key, self.receiving_message_number)
                self.skipped_message_keys[key] = message_key
                self.receiving_message_number += 1

    def get_public_key(self):
        """
        Returns the current DH public key.

        Returns:
            bytes: DH public key
        """
        if self.dh_keypair is None:
            return None

        return self.dh_keypair.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )


def initialize_double_ratchet_pair(shared_secret):
    """
    Initializes a pair of Double Ratchet instances for both parties.

    Args:
        shared_secret: Shared secret from PAKE protocol

    Returns:
        tuple: (sender_ratchet, receiver_ratchet)
    """
    sender = DoubleRatchet(shared_secret, sending=True)
    receiver = DoubleRatchet(shared_secret, sending=False)

    # Receiver needs sender's initial DH public key
    sender_pk = sender.get_public_key()

    return sender, receiver, sender_pk
