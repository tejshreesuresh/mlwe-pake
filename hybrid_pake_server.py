"""
Hybrid PAKE Server with Double Ratchet

Demonstrates:
1. Initial authentication using Hybrid PQ-Classical PAKE
2. Secure messaging using Double Ratchet
"""

import socket
import json
import base64
from hybrid_crypto import generate_hybrid_keys
from hybrid_pake_protocol import (
    process_hybrid_client_message1,
    derive_session_key,
    initialize_double_ratchet_from_pake
)

# --- Server Configuration ---
HOST = '127.0.0.1'
PORT = 65433  # Different port for hybrid implementation
SERVER_ID = "HybridPakeServer"
EXPECTED_CLIENT_PASSWORD = "correct-horse-battery-staple"


def handle_ratchet_messages(conn, ratchet):
    """
    Handles encrypted messages using Double Ratchet.

    Args:
        conn: Socket connection
        ratchet: DoubleRatchet instance
    """
    print("\n=== Ready to receive Double Ratchet messages ===")

    message_count = 0
    buffer = b""

    while message_count < 3:  # Expect 3 test messages
        try:
            # Receive data
            data = conn.recv(4096)
            if not data:
                print("Client closed connection")
                break

            buffer += data

            # Process complete messages (delimited by newline)
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)

                if not line.strip():
                    continue

                # Parse encrypted message
                encrypted_msg_json = json.loads(line.decode('utf-8'))

                if encrypted_msg_json.get("type") != "RATCHET_MESSAGE":
                    print(f"Unknown message type: {encrypted_msg_json.get('type')}")
                    continue

                print(f"\n--- Received Message {message_count + 1} ---")

                # Reconstruct encrypted message
                encrypted_msg = {
                    "dh_public_key": base64.b64decode(encrypted_msg_json["dh_public_key"]),
                    "previous_chain_length": encrypted_msg_json["previous_chain_length"],
                    "message_number": encrypted_msg_json["message_number"],
                    "nonce": base64.b64decode(encrypted_msg_json["nonce"]),
                    "ciphertext": base64.b64decode(encrypted_msg_json["ciphertext"])
                }

                # Decrypt message
                plaintext = ratchet.decrypt_message(encrypted_msg)
                print(f"Decrypted message: {plaintext.decode('utf-8')}")

                message_count += 1

                # Send encrypted response
                response_text = f"Server received message {message_count}".encode('utf-8')
                encrypted_response = ratchet.encrypt_message(response_text)

                # Prepare for transmission
                response_to_send = {
                    "type": "RATCHET_MESSAGE",
                    "dh_public_key": base64.b64encode(encrypted_response["dh_public_key"]).decode('utf-8'),
                    "previous_chain_length": encrypted_response["previous_chain_length"],
                    "message_number": encrypted_response["message_number"],
                    "nonce": base64.b64encode(encrypted_response["nonce"]).decode('utf-8'),
                    "ciphertext": base64.b64encode(encrypted_response["ciphertext"]).decode('utf-8')
                }

                conn.sendall(json.dumps(response_to_send).encode('utf-8'))
                print(f"Sent encrypted response")

        except Exception as e:
            print(f"Error handling ratchet message: {e}")
            import traceback
            traceback.print_exc()
            break

    print(f"\nProcessed {message_count} messages")


def run_hybrid_server():
    """Main server function"""
    # Generate server's long-term hybrid keys
    print("=== Generating Server Hybrid Keys ===\n")
    server_keypair = generate_hybrid_keys()
    server_pq_pk, server_classical_pk = server_keypair.get_public_keys()

    # Display public keys for client configuration
    print("\n" + "="*70)
    print("SERVER PUBLIC KEYS (copy these to hybrid_pake_client.py)")
    print("="*70)
    print(f"\nSERVER_PQ_PK_B64 = \"{base64.b64encode(server_pq_pk).decode('utf-8')}\"")
    print(f"\nSERVER_CLASSICAL_PK_B64 = \"{base64.b64encode(server_classical_pk).decode('utf-8')}\"")
    print("\n" + "="*70 + "\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        print("Waiting for client connection...\n")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}\n")

            try:
                # --- Hybrid PAKE Protocol ---
                # 1. Receive Client Message 1
                data_bytes = conn.recv(8192)
                if not data_bytes:
                    raise ConnectionError("Client disconnected prematurely")

                print("Server: Received Hybrid PAKE Message 1 from client")

                # 2. Process Client Message 1 and create Server Message 1
                server_msg1, server_context, transcript = process_hybrid_client_message1(
                    data_bytes, SERVER_ID, server_keypair, EXPECTED_CLIENT_PASSWORD
                )

                if server_msg1 is None:
                    print("Server: Hybrid PAKE failed - Authentication unsuccessful")
                    conn.sendall(json.dumps({"type": "ERROR", "info": "Authentication failed"}).encode('utf-8'))
                    return

                # 3. Send Server Message 1
                print("\nServer: Sending Hybrid PAKE Message 1 to client")
                conn.sendall(json.dumps(server_msg1).encode('utf-8'))

                # 4. Derive session key
                session_key = derive_session_key(server_context, transcript)

                print("\n" + "="*50)
                print("HYBRID PAKE SUCCESSFUL!")
                print(f"Session Key (first 16 bytes): {session_key[:16].hex()}")
                print("="*50)

                # 5. Initialize Double Ratchet
                ratchet = initialize_double_ratchet_from_pake(session_key, is_initiator=False)

                print("\n" + "="*50)
                print("DOUBLE RATCHET INITIALIZED")
                print("Ready for secure messaging with forward secrecy")
                print("="*50)

                # 6. Handle encrypted messages
                handle_ratchet_messages(conn, ratchet)

                print("\n" + "="*50)
                print("SERVER SESSION COMPLETE")
                print("="*50)

            except Exception as e:
                print(f"Server Error: {e}")
                import traceback
                traceback.print_exc()
            finally:
                print("\nServer: Closing connection")


if __name__ == "__main__":
    print("="*70)
    print("HYBRID PQ-CLASSICAL PAKE SERVER WITH DOUBLE RATCHET")
    print("="*70 + "\n")
    run_hybrid_server()
