import requests
import time
import hmac
import hashlib
import secrets
import random
import threading # We'll use threading to allow concurrent input and message fetching

from encryption_code import (
    seedGenerator,
    miller_rabin,
    mod_inverse,
    generate_prime,
    gen_rsa_keys,
    rsa_encrypt,
    rsa_decrypt,
    encrypt_message,
    decrypt_message,
    exchange_seeds
)

# --------- Server Communication ---------
server_url = "http://127.0.0.1:5000"

# --- Helper functions for server communication ---
def get_bob_public_key():
    try:
        response = requests.get(f"{server_url}/get_bob_public_key")
        response.raise_for_status() # This will raise an exception for 4xx/5xx status codes
        
        key_data = response.json()
        if isinstance(key_data, dict) and "e" in key_data and "n" in key_data:
            return (key_data["e"], key_data["n"])
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


def send_encrypted_seed_to_bob(encrypted_seed):
    data = {"encrypted_seed": encrypted_seed}
    try:
        response = requests.post(f"{server_url}/send_encrypted_seed_to_bob", json=data)
        response.raise_for_status()
        print("Sent encrypted seed to Bob:", response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error sending encrypted seed: {e}")

def send_message_to_bob(encrypted_payload, iteration, original_length, auth_tag):
    data = {
        "message": encrypted_payload,
        "iteration": iteration,
        "length": original_length,
        "auth_tag": auth_tag
    }
    try:
        response = requests.post(f"{server_url}/send_from_alice", json=data)
        response.raise_for_status()
        print("Sent →", response.json())
    except requests.exceptions.RequestException as e:
        print(f"Send error: {e}")

def get_messages_for_alice():
    try:
        response = requests.get(f"{server_url}/get_for_alice")
        response.raise_for_status()
        return response.json().get("messages", [])
    except requests.exceptions.RequestException as e:
        return []

# --- New function to establish shared seed for Alice ---
def establish_shared_seed_for_alice():
    """
    Handles Alice's part of the key exchange:
    1. Waits for Bob's public key.
    2. Generates Alice's seed.
    3. Encrypts Alice's seed with Bob's public key.
    4. Sends the encrypted seed to the server for Bob.
    Returns Alice's chosen shared seed.
    """
    print("\nAlice client ready. Initiating key exchange with Bob...")

    bob_public_key = None
    while bob_public_key is None:
        print("Waiting for Bob to register his public key...")
        bob_public_key = get_bob_public_key()
        if bob_public_key:
            print("Received Bob's public key.")
        time.sleep(1)

    current_shared_seed = seedGenerator.seed_gen()
    print(f"Alice's chosen shared seed: {current_shared_seed}")

    encrypted_seed_for_bob = rsa_encrypt(current_shared_seed, bob_public_key)
    print(f"Encrypted seed for Bob: {encrypted_seed_for_bob}")

    send_encrypted_seed_to_bob(encrypted_seed_for_bob)
    print("Encrypted seed sent to Bob. Chat can now begin.")
    
    return current_shared_seed

# --- Function to continuously poll for messages ---
def message_poller(shared_seed_to_use, stop_event):
    while not stop_event.is_set():
        messages = get_messages_for_alice()
        for m in messages:
            if shared_seed_to_use:
                dec = decrypt_message(m["message"], m["iteration"], m["length"], shared_seed_to_use, m["auth_tag"])
                print(f"\nBob: {dec}\nAlice: ", end="", flush=True) # Print Bob's message and re-prompt Alice
            else:
                print("Error: Shared seed not available for decryption in poller.")
                break # Stop processing messages if seed is missing
        time.sleep(0.5) # Poll every 0.5 seconds

# --------- Main Client ---------
def main():
    alice_current_shared_seed = establish_shared_seed_for_alice()

    if not alice_current_shared_seed:
        print("Failed to establish shared seed. Exiting.")
        return

    print("\nAlice client ready. Type 'exit' to quit.\n")

    # Event to signal the poller thread to stop
    stop_poller = threading.Event()
    
    # Start the message polling thread
    # Pass the shared_seed_to_use as an argument to the thread function
    poller_thread = threading.Thread(target=message_poller, args=(alice_current_shared_seed, stop_poller))
    poller_thread.daemon = True # Allows the main program to exit even if thread is running
    poller_thread.start()

    while True:
        try:
            msg = input("Alice: ")
            if msg.lower() == "exit":
                break

            if alice_current_shared_seed:
                encrypted_payload, iteration, length, auth_tag = encrypt_message(msg, seedGenerator, alice_current_shared_seed)
                send_message_to_bob(encrypted_payload, iteration, length, auth_tag)
            else:
                print("Error: Shared seed not available. Cannot send message.")
                # This should ideally not happen after successful establishment
                continue
        except EOFError: # Handles Ctrl+D or unexpected input stream end
            break
        except KeyboardInterrupt: # Handles Ctrl+C gracefully
            break
        except Exception as e:
            print(f"An error occurred during input/send: {e}")
            break

    # Signal the poller thread to stop and wait for it to finish
    stop_poller.set()
    poller_thread.join(timeout=2) # Give it a moment to clean up

    print("Alice client exited.")

if __name__ == "__main__":
    main()