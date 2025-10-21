import socket
import json
import base64
import mlwe_crypto
import pake_protocol

# --- Client Configuration ---
HOST = '127.0.0.1' # The server's hostname or IP address
PORT = 65432        # The port used by the server
CLIENT_ID = "DemoClient123"
PASSWORD = "correct-horse-battery-staple" # The password to authenticate with

# Server's Public KEM Key - needed by the client to start the protocol
# In a real system, this would be pre-configured or obtained securely.
# FOR DEMO: We assume the client somehow knows the server's PK generated when server starts.
# You MUST copy the public key output by the server when it starts and paste it here (base64 encoded).
# Example placeholder - REPLACE THIS WITH ACTUAL SERVER PK OUTPUT:
SERVER_PK_B64 = "U4x5JdFzxfYPc8EwoWUk1GFUo7fI1SUQEyqC99I1SshPWUOsv7N9M3NTtgKVQrK56Oozu+hBP1qHx0YXy4CktRVj9HiDdLZME6e/13HMypDF2idvXfeMATiycROJniy3XcCnQxe5zjsrALU2k0fGlEUIIvJ5MJC8PqpzjJu+vncnvHFPVOSWAWe+pkhtZHMWjRyvLCE50TwqtcqvvVuL3Eyw/MbGS5kth+aFF6mxGoWMBoSupDpd2FpUqLeLyYgukYB2dJeDVshFoPqq6kgtfKKjRJc8hEFyDlfEMnPPdQsbp9JU6GK9dOCt/qIWRJBz9ImwlBpruIF2uyExHoxZS8YmItoASdVY8Rl5tPyXzhq+t2hEp0hghDm40oZ8X2x1hSnAp9PNkce32eKW8fxbN2VaDjcn/ycp1zXNxGofkwRprcakTlaOeqxWfBe9+7tF7cYeMMxaPCeQEBKWboWzlrpwq+SuTzZSgJJy60tCXeekMxWiSbm9LAlmUkOvwlqXY6XJ9vl+9qeDOui0mcwYmvlDVSRkYjhoaaKl8Vh94Aml5tQakOQ4uzbByEqRdlQqt0FqN0wVxWJTNTS/mty+SWa2g9hOFqhupSyJ7viosiWSjVwLiul+2afMrhK/CndQl8tD1tDCM2BkTHFPASKH6DKSUMSF+3E7uXDONjc9LFKJpNuTjWVB48dpv4IjLze4q0UbdmSgBJOhhHEBWYFh6izAkVKooKvC/1N/zThMLTqLsatOL/WHaAm0bKSRpPpcaguBdYzP/aUvQ1S70hwLt8Z9q4KgCxEVPzqbuth6aQCV/rdldNiZWFaHc+G/tuHIRaJxlRFxBKQk5zG/9FxLgXmm0wLKlXNLUEVkiqaLsAIRseggLkkVcNZMSzdlRHi44CIqVuamtwwBR4ZAIitKJdxhzDrJzBU3fDnLrZIKgESOULssq/rIRFgozTqqGPFpzOYfKXJ2moemjas6FXgkqFU9Jbxmj/ZMHgdhcChC8TV1/xGwAC11/imMAAFVYfiveEULsHZBYGDKuXXNhgGT0iVCkDVhubqx6xoy5hCJF0FQ+LXOJmiiImM9A/WE2VBLgbq88AqhpzhDp/eypRcLPgF4/UVRmqijZqGO0Am4A2dAGzenyrF5crobTHmBBURdX8SIpwGnbEFTMSekl3cea8asX2cFFVVaFYNhDSat9yKQtAty18GLiZOg21XKgbh+/ONj/RrPJQtRWnUmFjHOUBhfl7ob5tJul+xW3xCQMNnK+peqckx/qwSpJKtljlQ2NtmDFFYTm5pspYUeRkCv+yUQ2DY/CHkUP+BXykOCQbyibZe/KdMt2gKGiECFS2ZIBCwMVKyNz7yMp+HEgjcQIJO/35B7JnyXJlWmvxlLJniEYXWdZlsRZWqfM+KRS+aMvzG2x5ltdYd4WhcdpxohISMgvdIQA0aKzDmgaxGOJRau38ePEeF04OoGslxwhpdhQiG3HVrOCQw9T7I6GFUYk1WaIfkXtqeJezFlkzMK4CxRTdAvJYNythMkuJMzADVkat8/+XskVqVefpJLm0eHOCPRSH5jMqFcddQHKcy1LEg="
def run_client():
    try:
        server_pk = base64.b64decode(SERVER_PK_B64)
        if not server_pk or SERVER_PK_B64.startswith("REPLACE"):
             print("ERROR: Server Public KEM Key not set in pake_client.py!")
             print("Run the server first, copy its base64 public key, and paste it into the SERVER_PK_B64 variable.")
             return
    except Exception as e:
        print(f"Error decoding server public key: {e}. Is it correct base64?")
        return


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            print(f"Client connecting to {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print("Client: Connected.")

            # --- PAKE Protocol Execution ---
            # 1. Create and Send Client Message 1
            client_msg1, client_context, transcript = pake_protocol.create_client_message1(
                CLIENT_ID, PASSWORD, server_pk
            )
            if client_msg1 is None:
                print("Client: Failed to create Message 1.")
                return

            print("Client: Sending Message 1 to server.")
            s.sendall(json.dumps(client_msg1).encode('utf-8'))

            # 2. Receive Server Message 1
            data_bytes = s.recv(4096) # Adjust buffer size as needed
            if not data_bytes:
                 raise ConnectionError("Server disconnected prematurely")
            print("Client: Received Message 1 from server.")

            # Check for explicit error message from server
            try:
                possible_error = json.loads(data_bytes.decode('utf-8'))
                if possible_error.get("type") == "ERROR":
                     print(f"Client: Received error from server: {possible_error.get('info')}")
                     return
            except json.JSONDecodeError:
                 pass # Not an error message, proceed

            # 3. Process Server Message 1
            final_client_context, transcript_update = pake_protocol.process_server_message1(
                 data_bytes, client_context
            )
            transcript.extend(transcript_update) # Add server message to transcript

            if final_client_context is None:
                print("Client: PAKE Failed during Message 1 processing.")
                return

            # --- Final Key Derivation (Client Side) ---
            final_client_key = pake_protocol.calculate_final_key(final_client_context, transcript)
            print("\n-------------------------------------")
            print(f"Client: PAKE Successful!")
            print(f"Client: Final Derived Key (first 16 bytes): {final_client_key[:16].hex()}")
            print("-------------------------------------\n")

            # TODO: Use the final_client_key for secure communication

        except (ConnectionRefusedError, ConnectionResetError, TimeoutError) as e:
             print(f"Client Network Error: {e}")
        except (json.JSONDecodeError, ValueError, Exception) as e:
             print(f"Client Error during PAKE: {e}")
        finally:
             print("Client: Closing connection.")


if __name__ == "__main__":
    if SERVER_PK_B64.startswith("REPLACE"):
         print("ERROR: Server Public KEM Key not set in pake_client.py!")
         print("Run the server first, copy its base64 public key output, and paste it into the SERVER_PK_B64 variable at the top of this script.")
    else:
        run_client() 