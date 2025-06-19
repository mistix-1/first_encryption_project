import requests
import time
import threading
import secrets
import base64

# Import cryptographic functions from the updated encryption module
# Ensure 'encryption.py' is in the same directory or accessible in your Python path
from encryption_code import (
    gen_rsa_keys,
    rsa_encrypt, # Bob encrypts replies, though typically Alice initiates master secret
    rsa_decrypt,
    derive_symmetric_key,
    encrypt_message_aes_gcm,
    decrypt_message_aes_gcm,
    AES_KEY_LENGTH # To derive correct AES key length
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
def register_bob_public_key_with_server(public_key_obj):
    """
    Registers Bob's RSA public key (object) with the server.
    Serializes the key to base64-encoded PEM before sending.
    """
    public_key_pem_b64 = serialize_public_key_to_pem_b64(public_key_obj)
    data = {"user_id": "bob", "public_key_pem_b64": public_key_pem_b64}
    try:
        response = requests.post(f"{server_url}/register_public_key", json=data)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        print("Bob's public key registered:", response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error registering Bob's public key: {e}")
        exit() # Exit if key registration fails, as communication won't work

def get_encrypted_master_secret_from_alice():
    """
    Retrieves the RSA-encrypted master secret (base64 string) from the server.
    """
    try:
        response = requests.get(f"{server_url}/get_encrypted_master_secret")
        response.raise_for_status() # This will raise an exception for 4xx/5xx status codes

        response_data = response.json()
        if isinstance(response_data, dict):
            return response_data.get("encrypted_master_secret_b64")
        else:
            print(f"Unexpected response type from server for encrypted master secret: {type(response_data)}")
            return None

    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 404:
            return None # Expected when secret is not yet available
        else:
            print(f"HTTP error occurred while getting encrypted master secret: {http_err}")
            return None
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred while getting encrypted master secret: {conn_err}")
        return None
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred while getting encrypted master secret: {timeout_err}")
        return None
    except requests.exceptions.RequestException as req_err:
        print(f"An unexpected error occurred during request for encrypted master secret: {req_err}")
        return None
    except Exception as e: # Catch any other unexpected parsing errors
        print(f"An unexpected error occurred while processing JSON response for encrypted master secret: {e}")
        return None

def get_messages_for_bob_from_server():
    """
    Retrieves encrypted messages (base64-encoded) from the server for Bob.
    """
    try:
        response = requests.get(f"{server_url}/get_messages/bob")
        response.raise_for_status()
        return response.json().get("messages", [])
    except requests.exceptions.RequestException as e:
        print(f"Error getting messages for Bob: {e}")
        return []

def send_message_to_recipient(recipient_id, ciphertext, nonce, tag, associated_data=None):
    """
    Sends an AES-GCM encrypted message to the server for a specific recipient.
    All binary components are base64-encoded for JSON compatibility.
    """
    data = {
        "sender": "bob", # Hardcoded for Bob client
        "recipient": recipient_id,
        "ciphertext": bytes_to_b64_str(ciphertext),
        "nonce": bytes_to_b64_str(nonce),
        "tag": bytes_to_b64_str(tag),
        "associated_data": bytes_to_b64_str(associated_data) # Will be None if not provided
    }
    try:
        response = requests.post(f"{server_url}/send_message", json=data)
        response.raise_for_status()
        print("Sent reply to Alice:", response.json())
    except requests.exceptions.RequestException as e:
        print(f"Send error to {recipient_id}: {e}")

# --- Key Exchange Logic for Bob ---
def establish_shared_aes_key_for_bob():
    """
    Handles Bob's part of the key exchange:
    1. Generates Bob's RSA key pair.
    2. Registers Bob's public key with the server.
    3. Waits for and decrypts Alice's RSA-encrypted master secret (with OAEP).
    4. Derives the symmetric AES key using HKDF from the decrypted master secret.
    Returns Bob's derived symmetric AES key.
    """
    print("\nBob client started. Generating RSA keys and registering public key...")
    # Generate RSA keys (public and private objects from cryptography library)
    bob_public_key, bob_private_key = gen_rsa_keys()
    
    # Register Bob's public key (PEM string) with the server
    register_bob_public_key_with_server(bob_public_key)
    print("Waiting for Alice's encrypted master secret...")

    decrypted_master_secret = None
    while decrypted_master_secret is None:
        encrypted_master_secret_b64 = get_encrypted_master_secret_from_alice()
        if encrypted_master_secret_b64:
            try:
                # Decode base64 string to bytes
                encrypted_master_secret_bytes = b64_str_to_bytes(encrypted_master_secret_b64)
                # Decrypt using Bob's private key (OAEP padding handled by rsa_decrypt)
                decrypted_master_secret = rsa_decrypt(encrypted_master_secret_bytes, bob_private_key)
                print(f"Successfully received and decrypted master secret (length: {len(decrypted_master_secret)} bytes): {decrypted_master_secret.hex()}")
            except Exception as e:
                print(f"Error decrypting master secret with RSA: {e}")
                decrypted_master_secret = None # Reset to try again if decryption failed (e.g., due to invalid padding)
        time.sleep(1) # Wait a bit before retrying

    # Bob derives his symmetric AES key from the master secret
    bob_aes_key = derive_symmetric_key(decrypted_master_secret, info=b"chat_session_key_alice_bob")
    print(f"Bob derived AES key: {bob_aes_key.hex()}")
    
    return bob_aes_key

# --- Function to continuously poll for messages ---
def message_poller(shared_aes_key_to_use, stop_event):
    """
    Continuously polls the server for messages for Bob and decrypts them.
    """
    while not stop_event.is_set():
        messages_for_bob = get_messages_for_bob_from_server()
        for m in messages_for_bob:
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
                    print(f"\nAlice: {decrypted_msg}\nBob: ", end="", flush=True) # Print Alice's message and re-prompt Bob
                except Exception as e:
                    print(f"\n!!! Decryption error for a received message: {e}")
                    print("Bob: ", end="", flush=True) # Re-prompt Bob
            else:
                print("Error: Shared AES key not available for decryption in poller. Waiting for key exchange.")
                break # Stop processing messages if key is missing
        time.sleep(0.5) # Poll every 0.5 seconds

# --- Main Client Program ---
def main():
    bob_shared_aes_key = establish_shared_aes_key_for_bob()

    if bob_shared_aes_key is None:
        print("Failed to establish shared AES key. Exiting Bob client.")
        return

    print("\nBob client ready. Type 'exit' to quit.\n")

    # Event to signal the poller thread to stop
    stop_poller = threading.Event()
    
    # Start the message polling thread
    poller_thread = threading.Thread(target=message_poller, args=(bob_shared_aes_key, stop_poller))
    poller_thread.daemon = True # Allows the main program to exit even if thread is running
    poller_thread.start()

    while True:
        try:
            msg = input("Bob: ") # Bob can now initiate here
            if msg.lower() == "exit":
                break

            if bob_shared_aes_key:
                # Example of using associated data (e.g., a simple message counter)
                # In a real app, this would be more robust, potentially a UUID or timestamp.
                current_timestamp_aad = str(int(time.time())).encode('utf-8')
                ciphertext, nonce, tag = encrypt_message_aes_gcm(
                    msg,
                    bob_shared_aes_key,
                    associated_data=current_timestamp_aad
                )
                # Send the encrypted components to Alice via the server
                send_message_to_recipient("alice", ciphertext, nonce, tag, associated_data=current_timestamp_aad)
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

    print("Bob client exited.")

if __name__ == "__main__":
    main()
