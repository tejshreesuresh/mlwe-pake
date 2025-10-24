#!/usr/bin/env python3
"""
Test script for MLWE PAKE implementation
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mlwe_crypto import (
    generate_kem_keys, kem_encapsulate, kem_decapsulate,
    hash_password_simple, derive_final_secret, hash_transcript
)
from pake_protocol import (
    create_client_message1, process_client_message1,
    process_server_message1, calculate_final_key
)
import time

def test_mlwe_crypto_functions():
    """Test the basic MLWE crypto functions"""
    print("Testing MLWE crypto functions...")
    
    # Test 1: Key generation
    print("\n1. Testing KEM key generation...")
    pk, sk = generate_kem_keys()
    print(f"✓ KEM keys generated: {len(pk)} bytes public key, {len(sk)} bytes secret key")
    
    # Test 2: KEM encapsulation/decapsulation
    print("\n2. Testing KEM encapsulation/decapsulation...")
    start_time = time.time()
    
    # Encapsulate with public key
    ciphertext, shared_secret1 = kem_encapsulate(pk)
    print(f"✓ KEM encapsulation successful: {len(ciphertext)} bytes ciphertext, {len(shared_secret1)} bytes secret")
    
    # Decapsulate with secret key
    shared_secret2 = kem_decapsulate(sk, ciphertext)
    print(f"✓ KEM decapsulation successful: {len(shared_secret2)} bytes secret")
    
    # Verify secrets match
    if shared_secret1 == shared_secret2:
        print("✓ Shared secrets match!")
    else:
        print("✗ Shared secrets do not match!")
        return False
    
    exchange_time = time.time() - start_time
    print(f"✓ KEM exchange completed in {exchange_time:.4f} seconds")
    
    # Test 3: Password hashing
    print("\n3. Testing password hashing...")
    password = "test-password-123"
    salt, password_hash = hash_password_simple(password)
    print(f"✓ Password hashed: {len(salt)} bytes salt, {len(password_hash)} bytes hash")
    
    # Test 4: Multiple KEM exchanges
    print("\n4. Testing multiple KEM exchanges...")
    for i in range(3):
        pk, sk = generate_kem_keys()
        ciphertext, secret1 = kem_encapsulate(pk)
        secret2 = kem_decapsulate(sk, ciphertext)
        
        if secret1 == secret2:
            print(f"✓ Round {i+1}: KEM exchange successful")
        else:
            print(f"✗ Round {i+1}: KEM exchange failed!")
            return False
    
    # Test 5: Performance test
    print("\n5. Performance test...")
    num_tests = 10
    start_time = time.time()
    
    for _ in range(num_tests):
        pk, sk = generate_kem_keys()
        ciphertext, secret1 = kem_encapsulate(pk)
        secret2 = kem_decapsulate(sk, ciphertext)
    
    total_time = time.time() - start_time
    avg_time = total_time / num_tests
    print(f"✓ {num_tests} KEM exchanges completed in {total_time:.4f} seconds")
    print(f"✓ Average time per exchange: {avg_time:.4f} seconds")
    
    print("\n🎉 All MLWE crypto tests passed!")
    return True

def test_pake_protocol():
    """Test the PAKE protocol functions"""
    print("\n" + "="*50)
    print("Testing PAKE Protocol Functions")
    print("="*50)
    
    try:
        # Test 1: Client message creation
        print("\n1. Testing client message creation...")
        client_id = "test_client"
        password = "test-password-123"
        
        # Generate server keys (simulating server setup)
        server_pk, server_sk = generate_kem_keys()
        print(f"✓ Server keys generated: {len(server_pk)} bytes public key")
        
        # Create client message
        client_msg = create_client_message1(client_id, password, server_pk)
        print(f"✓ Client message created: {len(client_msg)} bytes")
        
        # Test 2: Server processing client message
        print("\n2. Testing server processing...")
        server_id = "test_server"
        expected_password = password  # Same password for testing
        
        server_response = process_client_message1(client_msg, server_id, server_sk, expected_password)
        print(f"✓ Server response created: {len(server_response)} bytes")
        
        # Test 3: Client processing server response
        print("\n3. Testing client processing server response...")
        client_context = {
            'client_id': client_id,
            'password': password,
            'client_pk': client_msg['client_pk'],
            'client_sk': client_msg['client_sk']
        }
        
        client_final = process_server_message1(server_response, client_context)
        print(f"✓ Client final processing successful")
        
        # Test 4: Final key calculation
        print("\n4. Testing final key calculation...")
        transcript = [client_msg, server_response, client_final]
        final_key = calculate_final_key(client_context, transcript)
        print(f"✓ Final key calculated: {len(final_key)} bytes")
        
        print("\n🎉 PAKE protocol test passed!")
        return True
        
    except Exception as e:
        print(f"✗ PAKE protocol test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("MLWE PAKE Test Suite")
    print("="*50)
    
    # Run MLWE crypto functions test
    success1 = test_mlwe_crypto_functions()
    
    # Run PAKE protocol test
    success2 = test_pake_protocol()
    
    if success1 and success2:
        print("\n" + "="*50)
        print("🎉 ALL TESTS PASSED!")
        print("="*50)
        sys.exit(0)
    else:
        print("\n" + "="*50)
        print("❌ SOME TESTS FAILED!")
        print("="*50)
        sys.exit(1)
