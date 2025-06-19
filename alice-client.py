import requests
import time
import threading
import secrets
import base64

# Import cryptographic functions from the updated encryption module
# Ensure 'encryption.py' is in the same directory or accessible in your Python path
from encryption_code import (
    gen_rsa_keys, # Though Alice won't generate RSA keys in this flow, keeping for reference
    rsa_encrypt,
    rsa_decrypt, # Alice won't decrypt RSA here, but good to have for consistency if roles shift
    derive_symmetric_key,
    encrypt_message_aes_gcm,
    decrypt_message_aes_gcm,
    MASTER_SECRET_BYTE_LENGTH, # To know what size master secret to generate
    AES_GCM_NONCE_LENGTH      # For consistency, if needed
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa # Needed for type checking

# --------- Server Communication ---------
# IMPORTANT: For production, change this to your HTTPS server URL (e.g., "https://your.secure.server:5000")
# And handle certificate verification.
server_url = "http://127.0.0.1:5000"

# --- Utility Functions for Base64 Encoding/Decoding (copied from server for self-containment) ---
def serialize_public_key_to_pem_b64(public_key):
    """
    Serializes a cryptography public key object to PEM format (bytes),
    then base64 encodes it to a UTF-8 string for JSON transmission.
    """
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Expected a cryptography RSA public key object.")
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(pem).decode('utf-8')

def deserialize_public_key_from_pem_b64(pem_b64_string):
    """
    Decodes a base64-encoded PEM string back to bytes, then deserializes it
    to a cryptography public key object.
    """
    pem = base64.b64decode(pem_b64_string.encode('utf-8'))
    return serialization.load_pem_public_key(pem, backend=default_backend())

def bytes_to_b64_str(data_bytes):
    """Encodes a bytes object to a base64 string."""
    if data_bytes is None:
        return None
    return base64.b64encode(data_bytes).decode('utf-8')

def b64_str_to_bytes(b64_string):
    """Decodes a base64 string to a bytes object."""
    if b64_string is None:
        return None
    return base64.b64decode(b64_string.encode('utf-8'))

# --- Helper functions for server communication ---
def get_bob_public_key_from_server():
    """
    Retrieves Bob's public key (PEM string) from the server and deserializes it.
    """
    try:
        response = requests.get(f"{server_url}/get_public_key/bob")
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)

        key_data = response.json()
        public_key_pem_b64 = key_data.get("public_key_pem_b64")

        if public_key_pem_b64:
            return deserialize_public_key_from_pem_b64(public_key_pem_b64)
        else:
            print(f"Unexpected response format for Bob's public key: {key_data}")
            return None
    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 404:
            return None # Expected if Bob hasn't registered his key yet
        else:
            print(f"HTTP error occurred while getting Bob's public key: {http_err}")
            return None
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred while getting Bob's public key: {conn_err}")
        return None
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred while getting Bob's public key: {timeout_err}")
        return None
    except requests.exceptions.RequestException as req_err:
        print(f"An unexpected error occurred during request for Bob's public key: {req_err}")
        return None
    except Exception as e: # Catch any other unexpected parsing errors
        print(f"An unexpected error occurred while processing JSON response for Bob's public key: {e}")
        return None

def send_encrypted_master_secret_to_bob(encrypted_master_secret_bytes):
    """
    Sends the RSA-encrypted master secret (as base64 string) to the server for Bob.
    """
    data = {"encrypted_master_secret_b64": bytes_to_b64_str(encrypted_master_secret_bytes)}
    try:
        response = requests.post(f"{server_url}/send_encrypted_master_secret", json=data)
        response.raise_for_status()
        print("Sent encrypted master secret to Bob:", response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error sending encrypted master secret: {e}")

def send_message_to_recipient(recipient_id, ciphertext, nonce, tag, associated_data=None):
    """
    Sends an AES-GCM encrypted message to the server for a specific recipient.
    All binary components are base64-encoded for JSON compatibility.
    """
    data = {
        "sender": "alice", # Hardcoded for Alice client
        "recipient": recipient_id,
        "ciphertext": bytes_to_b64_str(ciphertext),
        "nonce": bytes_to_b64_str(nonce),
        "tag": bytes_to_b64_str(tag),
        "associated_data": bytes_to_b64_str(associated_data) # Will be None if not provided
    }
    try:
        response = requests.post(f"{server_url}/send_message", json=data)
        response.raise_for_status()
        print("Sent message to Bob:", response.json())
    except requests.exceptions.RequestException as e:
        print(f"Send error to {recipient_id}: {e}")

def get_messages_for_alice_from_server():
    """
    Retrieves encrypted messages (base64-encoded) from the server for Alice.
    """
    try:
        response = requests.get(f"{server_url}/get_messages/alice")
        response.raise_for_status()
        return response.json().get("messages", [])
    except requests.exceptions.RequestException as e:
        print(f"Error getting messages for Alice: {e}")
        return []

# --- Key Exchange Logic for Alice ---
def establish_shared_aes_key_for_alice():
    """
    Handles Alice's part of the key exchange:
    1. Waits for Bob's public RSA key from the server.
    2. Generates a cryptographically secure master secret.
    3. Encrypts the master secret with Bob's public key using RSA OAEP padding.
    4. Sends the encrypted master secret to the server for Bob.
    5. Derives the symmetric AES key using HKDF from her master secret.
    Returns Alice's derived symmetric AES key.
    """
    print("\nAlice client ready. Initiating key exchange with Bob...")

    bob_public_key = None
    while bob_public_key is None:
        print("Waiting for Bob to register his public key...")
        bob_public_key = get_bob_public_key_from_server()
        if bob_public_key:
            print("Received Bob's public key.")
        time.sleep(1) # Wait a bit before retrying

    # Alice generates a cryptographically secure master secret (random bytes)
    alice_master_secret = secrets.token_bytes(MASTER_SECRET_BYTE_LENGTH)
    print(f"Alice's generated master secret (length: {len(alice_master_secret)} bytes): {alice_master_secret.hex()}")

    # Alice encrypts the master secret with Bob's public key (with OAEP padding)
    try:
        encrypted_master_secret = rsa_encrypt(alice_master_secret, bob_public_key)
        print(f"Alice encrypted master secret (length: {len(encrypted_master_secret)} bytes): {encrypted_master_secret.hex()}")
    except Exception as e:
        print(f"Error encrypting master secret with RSA: {e}")
        return None

    # Send the encrypted master secret to the server for Bob
    send_encrypted_master_secret_to_bob(encrypted_master_secret)
    print("Encrypted master secret sent to Bob. Awaiting Bob's decryption...")

    # Alice derives her symmetric AES key from the master secret
    alice_aes_key = derive_symmetric_key(alice_master_secret, info=b"chat_session_key_alice_bob")
    print(f"Alice derived AES key: {alice_aes_key.hex()}")

    return alice_aes_key

# --- Function to continuously poll for messages ---
def message_poller(shared_aes_key_to_use, stop_event):
    """
    Continuously polls the server for messages for Alice and decrypts them.
    """
    while not stop_event.is_set():
        messages_for_alice = get_messages_for_alice_from_server()
        for m in messages_for_alice:
            if shared_aes_key_to_use:
                try:
                    # Decode base64 strings back to bytes
                    ciphertext = b64_str_to_bytes(m["ciphertext"])
                    nonce = b64_str_to_bytes(m["nonce"])
                    tag = b64_str_to_bytes(m["tag"])
                    associated_data = b64_str_to_bytes(m["associated_data"]) # Can be None

                    decrypted_msg = decrypt_message_aes_gcm(
                        ciphertext,
                        nonce,
                        tag,
                        shared_aes_key_to_use,
                        associated_data=associated_data
                    )
                    print(f"\nBob: {decrypted_msg}\nAlice: ", end="", flush=True) # Print Bob's message and re-prompt Alice
                except Exception as e:
                    print(f"\n!!! Decryption error for a received message: {e}")
                    print("Alice: ", end="", flush=True) # Re-prompt Alice
            else:
                print("Error: Shared AES key not available for decryption in poller. Waiting for key exchange.")
                break # Stop processing messages if key is missing
        time.sleep(0.5) # Poll every 0.5 seconds

# --------- Main Client Program ---------
def main():
    alice_shared_aes_key = establish_shared_aes_key_for_alice()

    if alice_shared_aes_key is None:
        print("Failed to establish shared AES key. Exiting Alice client.")
        return

    print("\nAlice client ready. Type 'exit' to quit.\n")

    # Event to signal the poller thread to stop
    stop_poller = threading.Event()

    # Start the message polling thread
    poller_thread = threading.Thread(target=message_poller, args=(alice_shared_aes_key, stop_poller))
    poller_thread.daemon = True # Allows the main program to exit even if thread is running
    poller_thread.start()

    while True:
        try:
            msg = input("Alice: ")
            if msg.lower() == "exit":
                break

            if alice_shared_aes_key:
                # Example of using associated data (e.g., a simple message counter)
                # In a real app, this would be more robust, potentially a UUID or timestamp.
                current_timestamp_aad = str(int(time.time())).encode('utf-8')
                ciphertext, nonce, tag = encrypt_message_aes_gcm(
                    msg,
                    alice_shared_aes_key,
                    associated_data=current_timestamp_aad
                )
                # Send the encrypted components to Bob via the server
                send_message_to_recipient("bob", ciphertext, nonce, tag, associated_data=current_timestamp_aad)
            else:
                print("Error: Shared AES key not available. Cannot send message.")
                continue # Allow user to try again

        except EOFError: # Handles Ctrl+D or unexpected input stream end
            break
        except KeyboardInterrupt: # Handles Ctrl+C gracefully
            break
        except Exception as e:
            print(f"An unexpected error occurred during input/send: {e}")
            break

    # Signal the poller thread to stop and wait for it to finish
    stop_poller.set()
    poller_thread.join(timeout=2) # Give it a moment to clean up

    print("Alice client exited.")

if __name__ == "__main__":
    main()
