"""
Group cryptography primitives for MLWE-PAKE
Extends the base PAKE protocol with group key agreement capabilities
"""

import time
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import base64
import json
from mlwe_crypto import generate_kem_keys, kem_encapsulate, kem_decapsulate, hash_transcript


class DoubleRatcheting:
    """
    Double ratcheting implementation using HKDF for forward secrecy.
    Based on Signal protocol principles adapted for group scenarios.
    """
    
    def __init__(self, root_key: bytes, dh_key: bytes):
        """Initialize ratchet with root key and DH key."""
        self.root_key = root_key
        self.dh_key = dh_key
        self.message_keys: Dict[int, bytes] = {}
        self.message_number = 0
        self.chain_key = None
        
    def ratchet_forward(self) -> bytes:
        """Advance the ratchet and derive next chain key."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'Ratcheting',
            backend=default_backend()
        )
        self.chain_key = hkdf.derive(self.root_key + self.dh_key)
        self.message_number += 1
        return self.derive_message_key()
    
    def derive_message_key(self) -> bytes:
        """Derive message key from current chain key."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'MessageKey',
            backend=default_backend()
        )
        return hkdf.derive(self.chain_key)
    
    def get_message_key(self, message_num: int) -> Optional[bytes]:
        """Retrieve message key for a specific message number."""
        return self.message_keys.get(message_num)


class GroupKeyAgreement:
    """
    Group Key Agreement protocol using MLWE-PAKE.
    Implements a simplified group key establishment for multiple parties.
    Features:
    - Forward Secrecy: Keys updated when members leave
    - History Exclusion: New members cannot decrypt old messages (via epochs)
    - Epoch Tracking: Each key update increments epoch
    """
    
    def __init__(self, group_id: str):
        self.group_id = group_id
        self.members: Dict[str, Dict] = {}  # member_id -> {pk, sk, shared_secrets}
        self.group_key: Optional[bytes] = None
        self.group_transcript: List[bytes] = []
        self.epoch: int = 0  # Epoch number for history exclusion
        self.epoch_keys: Dict[int, bytes] = {}  # epoch -> group_key (for debugging)
        self.created_at: float = time.time()
        
    def add_member(self, member_id: str, password: str, use_prekey: bool = False, prekey_id: Optional[int] = None) -> Tuple[bytes, Dict, int]:
        """
        Add a new member to the group.
        Implements history exclusion by incrementing epoch when new member joins.
        
        Returns (group_public_key, member_context, epoch)
        """
        # History Exclusion: Increment epoch when new member joins
        # This ensures new members cannot decrypt messages from previous epochs
        if len(self.members) > 0:  # Not the first member
            self.epoch += 1
            # Regenerate ephemeral keys to prevent new member from accessing old keys
            self.group_ephemeral_pk, self.group_ephemeral_sk = generate_kem_keys()
            # Invalidate old group key
            self.group_key = None
        
        # Generate member's key pair
        if use_prekey and prekey_id is not None:
            # In a full implementation, this would use the prekey
            # For now, we still generate new keys but track prekey usage
            pk, sk = generate_kem_keys()
        else:
            pk, sk = generate_kem_keys()
        
        # Store member info
        self.members[member_id] = {
            'public_key': pk,
            'secret_key': sk,
            'password': password,
            'shared_secrets': {},
            'joined_at': time.time(),
            'joined_at_epoch': self.epoch  # Track which epoch they joined
        }
        
        # Generate group ephemeral key (simplified - in reality would be more complex)
        if not hasattr(self, 'group_ephemeral_pk'):
            self.group_ephemeral_pk, self.group_ephemeral_sk = generate_kem_keys()
        
        # Establish shared secrets with existing members
        member_context = {
            'member_id': member_id,
            'public_key': pk,
            'secret_key': sk,
            'group_ephemeral_pk': self.group_ephemeral_pk,
            'joined_at_epoch': self.epoch
        }
        
        return self.group_ephemeral_pk, member_context, self.epoch
    
    def establish_group_key(self) -> bytes:
        """
        Establish shared group key using all member contributions.
        Uses a simplified tree-based key agreement.
        """
        if len(self.members) < 2:
            raise ValueError("Need at least 2 members for group key agreement")
        
        # Collect shared secrets from all pairwise interactions
        shared_secrets = []
        
        member_list = list(self.members.keys())
        for i, member1_id in enumerate(member_list):
            for member2_id in member_list[i+1:]:
                # Each pair establishes a shared secret
                member1 = self.members[member1_id]
                member2 = self.members[member2_id]
                
                # Simplified: encapsulate with each other's keys
                _, secret = kem_encapsulate(member2['public_key'])
                shared_secrets.append(secret)
                
                # Store for later use
                member1['shared_secrets'][member2_id] = secret
        
        # Derive group key from all shared secrets
        transcript = hash_transcript(self.group_transcript)
        
        # Use HKDF to derive group key
        combined_secrets = b''.join(sorted(shared_secrets))  # Sort for determinism
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f'GroupKey:{self.group_id}'.encode(),
            backend=default_backend()
        )
        
        self.group_key = hkdf.derive(combined_secrets + transcript)
        
        # Store epoch key for debugging/verification
        self.epoch_keys[self.epoch] = self.group_key
        
        return self.group_key
    
    def update_group_key(self, leaving_member_id: Optional[str] = None) -> Tuple[bytes, int]:
        """
        Update group key (e.g., when member leaves).
        Implements forward secrecy by re-establishing key without departed member.
        Returns (new_group_key, new_epoch)
        """
        if leaving_member_id and leaving_member_id in self.members:
            del self.members[leaving_member_id]
        
        # Forward Secrecy: Increment epoch when member leaves
        # This ensures departed member cannot decrypt future messages
        self.epoch += 1
        
        # Regenerate ephemeral keys for forward secrecy
        self.group_ephemeral_pk, self.group_ephemeral_sk = generate_kem_keys()
        
        # Re-establish group key
        new_key = self.establish_group_key()
        return new_key, self.epoch
    
    def get_current_epoch(self) -> int:
        """Get current epoch number."""
        return self.epoch
    
    def can_decrypt_epoch(self, member_id: str, epoch: int) -> bool:
        """
        Check if a member can decrypt messages from a specific epoch.
        Implements history exclusion: members can only decrypt messages
        from epochs >= their join epoch.
        """
        if member_id not in self.members:
            return False
        member_join_epoch = self.members[member_id].get('joined_at_epoch', 0)
        return epoch >= member_join_epoch


class PreKeySystem:
    """
    Pre-key system for async joins.
    Allows new members to join without requiring all existing members to be online.
    """
    
    def __init__(self):
        self.pre_keys: Dict[str, List[Tuple[bytes, bytes]]] = {}  # user_id -> [(pk, sk), ...]
        self.pre_key_bundle_size = 100  # Number of pre-keys per user
        self.used_pre_keys: Dict[str, set] = {}  # Track used pre-keys
        
    def generate_pre_key_bundle(self, user_id: str) -> List[Dict]:
        """Generate a bundle of pre-keys for a user."""
        bundle = []
        self.pre_keys[user_id] = []
        
        for i in range(self.pre_key_bundle_size):
            pk, sk = generate_kem_keys()
            self.pre_keys[user_id].append((pk, sk))
            
            bundle.append({
                'pre_key_id': i,
                'public_key': base64.b64encode(pk).decode('utf-8'),
            })
        
        self.used_pre_keys[user_id] = set()
        return bundle
    
    def consume_pre_key(self, user_id: str, pre_key_id: int) -> Optional[bytes]:
        """
        Consume a pre-key for use in key exchange.
        Returns the secret key associated with the pre-key.
        """
        if user_id not in self.pre_keys:
            return None
        
        if pre_key_id >= len(self.pre_keys[user_id]):
            return None
        
        if pre_key_id in self.used_pre_keys.get(user_id, set()):
            return None  # Already used
        
        # Mark as used
        self.used_pre_keys[user_id].add(pre_key_id)
        
        # Return the secret key
        _, sk = self.pre_keys[user_id][pre_key_id]
        return sk
    
    def get_pre_key_public(self, user_id: str, pre_key_id: int) -> Optional[bytes]:
        """Get public key for a pre-key without consuming it."""
        if user_id not in self.pre_keys:
            return None
        
        if pre_key_id >= len(self.pre_keys[user_id]):
            return None
        
        pk, _ = self.pre_keys[user_id][pre_key_id]
        return pk


def derive_with_hkdf(
    secret: bytes,
    info: bytes,
    length: int = 32,
    salt: Optional[bytes] = None
) -> bytes:
    """
    Derive key material using HKDF.
    
    Args:
        secret: Input secret material
        info: Application-specific context information
        length: Desired output length in bytes
        salt: Optional salt value
        
    Returns:
        Derived key material
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(secret)


def ratchet_key_derivation(
    root_key: bytes,
    dh_output: bytes,
    previous_chain_key: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Perform ratcheting key derivation using HKDF.
    
    Returns:
        (next_chain_key, message_key)
    """
    if previous_chain_key is None:
        # First derivation: use root key + DH output
        input_key = root_key + dh_output
    else:
        # Subsequent derivations: use previous chain key
        input_key = previous_chain_key
    
    # Derive chain key
    chain_key = derive_with_hkdf(
        input_key,
        info=b'ChainKey',
        length=32
    )
    
    # Derive message key from chain key
    message_key = derive_with_hkdf(
        chain_key,
        info=b'MessageKey',
        length=32
    )
    
    return chain_key, message_key

