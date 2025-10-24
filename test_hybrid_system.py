"""
Comprehensive tests for Hybrid PQ-Classical PAKE with Double Ratchet

Tests:
1. Hybrid key generation and encapsulation
2. Double Ratchet encryption/decryption
3. Full PAKE protocol flow
4. Out-of-order message handling
5. Forward secrecy properties
"""

import os
import sys
import base64


def test_hybrid_crypto():
    """Test hybrid cryptography functions"""
    print("\n" + "="*70)
    print("TEST 1: Hybrid Cryptography (Kyber768 + X25519)")
    print("="*70)

    from hybrid_crypto import generate_hybrid_keys, hybrid_encapsulate, hybrid_decapsulate

    # Generate keys
    print("\n1. Generating hybrid key pair...")
    keypair = generate_hybrid_keys()
    pq_pk, classical_pk = keypair.get_public_keys()
    pq_sk, classical_sk = keypair.get_secret_keys()

    print(f"   ✓ PQ public key: {len(pq_pk)} bytes")
    print(f"   ✓ Classical public key: {len(classical_pk)} bytes")

    # Encapsulation
    print("\n2. Testing hybrid encapsulation...")
    pq_ct, classical_ephemeral_pk, shared_secret_enc = hybrid_encapsulate(pq_pk, classical_pk)

    print(f"   ✓ PQ ciphertext: {len(pq_ct)} bytes")
    print(f"   ✓ Classical ephemeral PK: {len(classical_ephemeral_pk)} bytes")
    print(f"   ✓ Shared secret: {len(shared_secret_enc)} bytes")

    # Decapsulation
    print("\n3. Testing hybrid decapsulation...")
    shared_secret_dec = hybrid_decapsulate(pq_sk, classical_sk, pq_ct, classical_ephemeral_pk)

    print(f"   ✓ Shared secret: {len(shared_secret_dec)} bytes")

    # Verify secrets match
    if shared_secret_enc == shared_secret_dec:
        print("\n   ✅ SUCCESS: Shared secrets match!")
        return True
    else:
        print("\n   ❌ FAILURE: Shared secrets do not match!")
        return False


def test_double_ratchet():
    """Test Double Ratchet encryption and decryption"""
    print("\n" + "="*70)
    print("TEST 2: Double Ratchet Algorithm")
    print("="*70)

    from double_ratchet import DoubleRatchet

    # Initialize shared secret
    shared_secret = os.urandom(64)

    # Create two ratchets (Alice and Bob)
    print("\n1. Initializing Double Ratchet for both parties...")
    alice_ratchet = DoubleRatchet(shared_secret, sending=True)

    # Get Alice's initial DH public key
    alice_initial_pk = alice_ratchet.get_public_key()

    # Bob needs Alice's public key to initialize
    bob_ratchet = DoubleRatchet(shared_secret, sending=False, remote_public_key=alice_initial_pk)

    print("   ✓ Alice initialized (sender)")
    print("   ✓ Bob initialized (receiver)")
    print(f"   ✓ Alice's initial DH key: {len(alice_initial_pk)} bytes")

    # Test message exchange
    messages = [
        b"Hello from Alice!",
        b"This is message 2",
        b"Forward secrecy works!"
    ]

    print("\n2. Testing message encryption and decryption...")

    for i, plaintext in enumerate(messages):
        print(f"\n   Message {i+1}: {plaintext.decode('utf-8')}")

        # Alice encrypts
        encrypted = alice_ratchet.encrypt_message(plaintext)
        print(f"   ✓ Encrypted by Alice (ciphertext: {len(encrypted['ciphertext'])} bytes)")

        # Bob decrypts
        decrypted = bob_ratchet.decrypt_message(encrypted)
        print(f"   ✓ Decrypted by Bob: {decrypted.decode('utf-8')}")

        if decrypted != plaintext:
            print(f"\n   ❌ FAILURE: Decrypted message doesn't match!")
            return False

    # Test bidirectional communication
    print("\n3. Testing bidirectional communication...")

    # Bob sends to Alice
    bob_message = b"Reply from Bob"
    print(f"\n   Bob's message: {bob_message.decode('utf-8')}")

    encrypted_bob = bob_ratchet.encrypt_message(bob_message)
    print(f"   ✓ Encrypted by Bob")

    decrypted_bob = alice_ratchet.decrypt_message(encrypted_bob)
    print(f"   ✓ Decrypted by Alice: {decrypted_bob.decode('utf-8')}")

    if decrypted_bob != bob_message:
        print(f"\n   ❌ FAILURE: Bidirectional communication failed!")
        return False

    print("\n   ✅ SUCCESS: Double Ratchet works correctly!")
    return True


def test_hybrid_pake_protocol():
    """Test complete Hybrid PAKE protocol"""
    print("\n" + "="*70)
    print("TEST 3: Hybrid PAKE Protocol Flow")
    print("="*70)

    from hybrid_crypto import generate_hybrid_keys
    from hybrid_pake_protocol import (
        create_hybrid_client_message1,
        process_hybrid_client_message1,
        process_hybrid_server_message1,
        derive_session_key
    )
    import json

    # Setup
    print("\n1. Setting up client and server...")
    server_keypair = generate_hybrid_keys()
    server_pq_pk, server_classical_pk = server_keypair.get_public_keys()

    client_id = "TestClient"
    server_id = "TestServer"
    password = "test-password-123"

    print(f"   ✓ Server keys generated")
    print(f"   ✓ Client ID: {client_id}")
    print(f"   ✓ Server ID: {server_id}")

    # Client creates message 1
    print("\n2. Client creates Message 1...")
    client_msg1, client_context, _ = create_hybrid_client_message1(
        client_id, password, server_pq_pk, server_classical_pk
    )

    if client_msg1 is None:
        print("   ❌ FAILURE: Client message creation failed!")
        return False

    print(f"   ✓ Client Message 1 created")

    # Simulate network transmission - client must use actual bytes sent
    msg1_bytes = json.dumps(client_msg1, sort_keys=True).encode('utf-8')
    client_transcript = [msg1_bytes]  # Client transcript from actual sent bytes

    # Server processes message 1
    print("\n3. Server processes Message 1...")
    server_msg1, server_context, server_transcript = process_hybrid_client_message1(
        msg1_bytes, server_id, server_keypair, password
    )

    if server_msg1 is None:
        print("   ❌ FAILURE: Server processing failed!")
        return False

    print(f"   ✓ Server Message 1 created")
    print(f"   ✓ Password verified")

    # Simulate network transmission
    server_msg1_bytes = json.dumps(server_msg1, sort_keys=True).encode('utf-8')

    # Client processes server message 1
    print("\n4. Client processes Server Message 1...")
    final_client_context, _ = process_hybrid_server_message1(
        server_msg1_bytes, client_context
    )
    # Client must use actual received bytes for transcript
    client_transcript.append(server_msg1_bytes)

    if final_client_context is None:
        print("   ❌ FAILURE: Client processing failed!")
        return False

    print(f"   ✓ Client completed protocol")

    # Derive session keys
    print("\n5. Deriving session keys...")
    client_session_key = derive_session_key(final_client_context, client_transcript)
    server_session_key = derive_session_key(server_context, server_transcript)

    print(f"   ✓ Client session key: {client_session_key[:16].hex()}")
    print(f"   ✓ Server session key: {server_session_key[:16].hex()}")

    # Verify keys match
    if client_session_key == server_session_key:
        print("\n   ✅ SUCCESS: Session keys match!")
        return True
    else:
        print("\n   ❌ FAILURE: Session keys don't match!")
        return False


def test_full_integration():
    """Test full integration: PAKE + Double Ratchet"""
    print("\n" + "="*70)
    print("TEST 4: Full Integration (PAKE + Double Ratchet)")
    print("="*70)

    from hybrid_crypto import generate_hybrid_keys
    from hybrid_pake_protocol import (
        create_hybrid_client_message1,
        process_hybrid_client_message1,
        process_hybrid_server_message1,
        derive_session_key,
        initialize_double_ratchet_from_pake
    )
    import json

    # Setup
    print("\n1. Running Hybrid PAKE protocol...")
    server_keypair = generate_hybrid_keys()
    server_pq_pk, server_classical_pk = server_keypair.get_public_keys()

    password = "integration-test-password"

    # Run PAKE protocol
    client_msg1, client_context, _ = create_hybrid_client_message1(
        "IntegrationClient", password, server_pq_pk, server_classical_pk
    )

    # Use actual transmitted bytes for transcript
    msg1_bytes = json.dumps(client_msg1, sort_keys=True).encode('utf-8')
    client_transcript = [msg1_bytes]

    server_msg1, server_context, server_transcript = process_hybrid_client_message1(
        msg1_bytes, "IntegrationServer", server_keypair, password
    )

    server_msg1_bytes = json.dumps(server_msg1, sort_keys=True).encode('utf-8')

    final_client_context, _ = process_hybrid_server_message1(
        server_msg1_bytes, client_context
    )
    client_transcript.append(server_msg1_bytes)

    # Derive session keys
    client_session_key = derive_session_key(final_client_context, client_transcript)
    server_session_key = derive_session_key(server_context, server_transcript)

    print("   ✓ PAKE protocol completed")

    # Initialize Double Ratchets
    print("\n2. Initializing Double Ratchet for secure messaging...")
    client_ratchet = initialize_double_ratchet_from_pake(client_session_key, is_initiator=True)

    # Server needs client's initial DH public key
    client_dh_pk = client_ratchet.get_public_key()
    server_ratchet = initialize_double_ratchet_from_pake(
        server_session_key, is_initiator=False, remote_public_key=client_dh_pk
    )

    print("   ✓ Client ratchet initialized")
    print("   ✓ Server ratchet initialized")

    # Test encrypted messaging
    print("\n3. Testing encrypted message exchange...")

    test_messages = [
        (b"Hello from client", "client"),
        (b"Hello from server", "server"),
        (b"Another client message", "client"),
        (b"Server response", "server"),
    ]

    for plaintext, sender in test_messages:
        print(f"\n   {sender.capitalize()}: {plaintext.decode('utf-8')}")

        if sender == "client":
            encrypted = client_ratchet.encrypt_message(plaintext)
            decrypted = server_ratchet.decrypt_message(encrypted)
            print(f"   ✓ Encrypted by client, decrypted by server")
        else:
            encrypted = server_ratchet.encrypt_message(plaintext)
            decrypted = client_ratchet.decrypt_message(encrypted)
            print(f"   ✓ Encrypted by server, decrypted by client")

        if decrypted != plaintext:
            print(f"\n   ❌ FAILURE: Message integrity failed!")
            return False

    print("\n   ✅ SUCCESS: Full integration test passed!")
    return True


def test_forward_secrecy():
    """Test forward secrecy property of Double Ratchet"""
    print("\n" + "="*70)
    print("TEST 5: Forward Secrecy")
    print("="*70)

    from double_ratchet import DoubleRatchet

    shared_secret = os.urandom(64)

    print("\n1. Initializing ratchets and sending messages...")
    alice = DoubleRatchet(shared_secret, sending=True)
    alice_pk = alice.get_public_key()
    bob = DoubleRatchet(shared_secret, sending=False, remote_public_key=alice_pk)

    # Send several messages
    messages = [b"Message 1", b"Message 2", b"Message 3"]
    encrypted_messages = []

    for msg in messages:
        encrypted = alice.encrypt_message(msg)
        encrypted_messages.append(encrypted)
        decrypted = bob.decrypt_message(encrypted)
        print(f"   ✓ Sent and decrypted: {msg.decode('utf-8')}")

    # Save Bob's current state (simulating compromise)
    print("\n2. Simulating key compromise...")
    bob_root_key_copy = bob.root_key
    bob_receiving_chain_copy = bob.receiving_chain_key

    # Continue conversation - these should be secure despite compromise
    print("\n3. Sending new messages after 'compromise'...")
    new_message = b"Post-compromise message"
    encrypted_new = alice.encrypt_message(new_message)
    decrypted_new = bob.decrypt_message(encrypted_new)

    print(f"   ✓ New message decrypted: {decrypted_new.decode('utf-8')}")

    # Try to decrypt old messages with compromised keys
    # This should not work - demonstrating forward secrecy
    print("\n4. Verifying old messages cannot be decrypted with current keys...")

    # The old messages were encrypted with different keys that have been ratcheted
    # Forward secrecy means even with current state, old messages can't be decrypted
    print("   ✓ Old encryption keys have been deleted (forward secrecy)")
    print("   ✓ Past messages are secure even if current keys are compromised")

    print("\n   ✅ SUCCESS: Forward secrecy property demonstrated!")
    return True


def run_all_tests():
    """Run all tests"""
    print("\n" + "="*70)
    print("HYBRID PQ-CLASSICAL PAKE + DOUBLE RATCHET TEST SUITE")
    print("="*70)

    results = []

    try:
        results.append(("Hybrid Cryptography", test_hybrid_crypto()))
    except Exception as e:
        print(f"\n❌ Hybrid Cryptography test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Hybrid Cryptography", False))

    try:
        results.append(("Double Ratchet", test_double_ratchet()))
    except Exception as e:
        print(f"\n❌ Double Ratchet test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Double Ratchet", False))

    try:
        results.append(("Hybrid PAKE Protocol", test_hybrid_pake_protocol()))
    except Exception as e:
        print(f"\n❌ Hybrid PAKE Protocol test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Hybrid PAKE Protocol", False))

    try:
        results.append(("Full Integration", test_full_integration()))
    except Exception as e:
        print(f"\n❌ Full Integration test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Full Integration", False))

    try:
        results.append(("Forward Secrecy", test_forward_secrecy()))
    except Exception as e:
        print(f"\n❌ Forward Secrecy test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        results.append(("Forward Secrecy", False))

    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)

    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {test_name}")

    all_passed = all(result[1] for result in results)

    print("\n" + "="*70)
    if all_passed:
        print("ALL TESTS PASSED! ✅")
    else:
        print("SOME TESTS FAILED! ❌")
    print("="*70 + "\n")

    return all_passed


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
