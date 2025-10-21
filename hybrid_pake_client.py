"""
Hybrid PAKE Client with Double Ratchet

Demonstrates:
1. Initial authentication using Hybrid PQ-Classical PAKE
2. Secure messaging using Double Ratchet
"""

import socket
import json
import base64
from hybrid_pake_protocol import (
    create_hybrid_client_message1,
    process_hybrid_server_message1,
    derive_session_key,
    initialize_double_ratchet_from_pake
)

# --- Client Configuration ---
HOST = '127.0.0.1'
PORT = 65433  # Different port for hybrid implementation
CLIENT_ID = "HybridClient123"
PASSWORD = "correct-horse-battery-staple"

# Server's Public Keys (copied from server startup)
# You MUST run the server first and copy its public keys here
SERVER_PQ_PK_B64 = "N1osrdRHm8pWXmoMHKzNH/JuPXQSuZUaXfQeJHqzvtWLM2cORfmrl2zDE6JMUmNMigp3lbEJBuipJ2orZwiUTeutekiWqsXE9hIS17MbWDu29GiFAFaBEuQld5JblWIc9xG6esh+J/u9iMCSYVWRTDmXIoCp/5BwiHc/yddTORKhBhtHfCyCrKMK4ThQupJSQaUBQ2Eq9tumx0MjRep/AvUGMFnFt7UIOEAfYIdmqqDC/JOdHjKKFKizw0GmODt+QExf7hx4O2KK4IIUKYo+gkQ7r5DAzBB2LhaxTPCBFCU+jgdcerYI31BMY4hPm7gD/jwpK8VSa/JnuKAq1XczfYAibnvLmKwCJOBi2xVZSarMBOstH7xobdguVKmiUcWj9kSMomavuel0VshqZDigfBqkClIiHnZ4DLxPUWtkzDEYeZl4s5ufuGlJsCktbbJSJwyZvJx/bpV6ORSuYoVIn3q1zVGvuzK0w+t/T5SDT1iYD/CgR8sToYi0fJKw/GaVfuaFqbeXAEQYodO6a9ca9uZyqFdCUCEWdvi/0uEYomVFsqXFtHViq1h9kFmi7JtnI5ZkcvgH3SYhUjauLMkEBjNSVSK+uSeFkMhoKleB2jdIwESXxKkibChqXgLCQgp9ZDJDOKkNtRoRXXpHRAZVcGk8FkHOmAdpHswACIpzlSussDAp2fdOUpdwXBw+Drt+izcFv/E9qGylglSreQSV9eY2KtN0VzA/EetD/OZlqiRQSohvUxssirQFIZeHSNRACsCKHusW5kNZQrp2aIVAEPzMYaenCpxcyDBcJna0ZcI4Y2dZI1fAhRcRXdsycCgR9XhLXPQBJyxAzRhwFuNGxZTMBRnP8NqlHsggdHeVsZPOjka5Eru4x9ZpxErKR9gtTlIvEmyJdDYtWvOa2mqWzEN/CdwNrzs8uboi9zyX2BOJlxuqOzp1cDFmq5yUj0WkSDSox4kQ/wR/usHJV7c96QcliSdAzMRhaSRrZEAJCDVWjJtAMKB334uaFQRPCqtytvlSehM5xPJm7yCO/0cb3kpcGve7LhsnskkEGMk9VkCn31ZZdglVAMNE5uVTNhevfdCMFJW4OASQKPLK4gGn6ecFWPyG4ZJ8Q0I8JqZYc6WrtyN7e3yIKKdsudBbrVadlpYGWJOZdIsXDgrB+/I7CQMOn8Yrq6m5JKAaDXx/lNBwfVmEeRBNx8qbjSInvLlYOJiui9ZPPzdwC9JKH9WirlWsw9JSuDAcx2ZtSyB9WCfDzhaX9QkdPgcT0tuElTJ98PQOe2YWleypLLbFS5FZBoCA+xhPNNC/mWUcJEEglaZZV9e8C/qZhupLv0URyEVTzMuNkHLEEzHJZ8OGHrDDlYzIFzLFRcpM2Ju2ZWmg1HCZmMaZkUkAX1Ygo1i4gbVXWfc1tIPO1DCrf0JtRGkTzfN4W+dFihpL74JpXtJQDOsGc7gAUYKH3QQE7RlwXMoTZth4oGh9SHLIsJwyo4pAiuZhNNpR2Xt0HoSE5UEL3/EKs5IsgVZP+lzB6kc1SUsDVjqR2XASQ2ApgTD88RfT/bk60TDPvTVOt11bbDxEcx8="
SERVER_CLASSICAL_PK_B64 = "OGMLbQ5b8oRatTIC9iUwgsxHSi6Q7RlEhmuNHM1hEGY="


def send_test_messages(conn, ratchet):
    """
    Sends test messages using Double Ratchet encryption.

    Args:
        conn: Socket connection
        ratchet: DoubleRatchet instance
    """
    print("\n=== Testing Double Ratchet Messaging ===")

    test_messages = [
        b"Hello from client!",
        b"This is a secure message.",
        b"Forward secrecy is enabled!"
    ]

    for i, plaintext in enumerate(test_messages):
        print(f"\n--- Sending Message {i+1} ---")
        print(f"Plaintext: {plaintext.decode('utf-8')}")

        # Encrypt with Double Ratchet
        encrypted_msg = ratchet.encrypt_message(plaintext)

        # Prepare for transmission
        msg_to_send = {
            "type": "RATCHET_MESSAGE",
            "dh_public_key": base64.b64encode(encrypted_msg["dh_public_key"]).decode('utf-8'),
            "previous_chain_length": encrypted_msg["previous_chain_length"],
            "message_number": encrypted_msg["message_number"],
            "nonce": base64.b64encode(encrypted_msg["nonce"]).decode('utf-8'),
            "ciphertext": base64.b64encode(encrypted_msg["ciphertext"]).decode('utf-8')
        }

        # Send encrypted message
        conn.sendall(json.dumps(msg_to_send).encode('utf-8'))
        conn.sendall(b"\n")  # Message delimiter

        print(f"Encrypted message sent (ciphertext length: {len(encrypted_msg['ciphertext'])} bytes)")

        # Wait for server response
        response_data = conn.recv(4096)
        if not response_data:
            print("Server closed connection")
            break

        # Parse response
        try:
            response = json.loads(response_data.decode('utf-8'))
            if response.get("type") == "RATCHET_MESSAGE":
                # Decrypt server's response
                encrypted_response = {
                    "dh_public_key": base64.b64decode(response["dh_public_key"]),
                    "previous_chain_length": response["previous_chain_length"],
                    "message_number": response["message_number"],
                    "nonce": base64.b64decode(response["nonce"]),
                    "ciphertext": base64.b64decode(response["ciphertext"])
                }

                decrypted = ratchet.decrypt_message(encrypted_response)
                print(f"Received encrypted response from server")
                print(f"Decrypted: {decrypted.decode('utf-8')}")
        except Exception as e:
            print(f"Error processing server response: {e}")


def run_hybrid_client():
    """Main client function"""
    try:
        # Decode server public keys
        if SERVER_PQ_PK_B64.startswith("REPLACE"):
            print("ERROR: Server public keys not set!")
            print("Run hybrid_pake_server.py first and copy the public keys.")
            return

        server_pq_pk = base64.b64decode(SERVER_PQ_PK_B64)
        server_classical_pk = base64.b64decode(SERVER_CLASSICAL_PK_B64)

    except Exception as e:
        print(f"Error decoding server public keys: {e}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            print(f"Client connecting to {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print("Client: Connected.\n")

            # --- Hybrid PAKE Protocol ---
            # 1. Create and send Client Message 1
            client_msg1, client_context, transcript = create_hybrid_client_message1(
                CLIENT_ID, PASSWORD, server_pq_pk, server_classical_pk
            )

            if client_msg1 is None:
                print("Client: Failed to create Message 1")
                return

            print("\nClient: Sending Hybrid PAKE Message 1 to server")
            s.sendall(json.dumps(client_msg1).encode('utf-8'))

            # 2. Receive Server Message 1
            data_bytes = s.recv(8192)
            if not data_bytes:
                raise ConnectionError("Server disconnected prematurely")

            print("Client: Received Server Message 1")

            # Check for error
            try:
                possible_error = json.loads(data_bytes.decode('utf-8'))
                if possible_error.get("type") == "ERROR":
                    print(f"Client: Server error: {possible_error.get('info')}")
                    return
            except json.JSONDecodeError:
                pass

            # 3. Process Server Message 1
            final_context, transcript_update = process_hybrid_server_message1(
                data_bytes, client_context
            )
            transcript.extend(transcript_update)

            if final_context is None:
                print("Client: Hybrid PAKE failed")
                return

            # 4. Derive session key
            session_key = derive_session_key(final_context, transcript)

            print("\n" + "="*50)
            print("HYBRID PAKE SUCCESSFUL!")
            print(f"Session Key (first 16 bytes): {session_key[:16].hex()}")
            print("="*50)

            # 5. Initialize Double Ratchet
            ratchet = initialize_double_ratchet_from_pake(session_key, is_initiator=True)

            print("\n" + "="*50)
            print("DOUBLE RATCHET INITIALIZED")
            print("Ready for secure messaging with forward secrecy")
            print("="*50)

            # 6. Test encrypted messaging
            send_test_messages(s, ratchet)

            print("\n" + "="*50)
            print("CLIENT SESSION COMPLETE")
            print("="*50)

        except (ConnectionRefusedError, ConnectionResetError, TimeoutError) as e:
            print(f"Client Network Error: {e}")
        except Exception as e:
            print(f"Client Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            print("\nClient: Closing connection")


if __name__ == "__main__":
    if SERVER_PQ_PK_B64.startswith("REPLACE"):
        print("ERROR: Server public keys not configured!")
        print("\nInstructions:")
        print("1. Run hybrid_pake_server.py first")
        print("2. Copy the server's PQ and Classical public keys")
        print("3. Paste them into SERVER_PQ_PK_B64 and SERVER_CLASSICAL_PK_B64")
        print("4. Run this client again")
    else:
        run_hybrid_client()
