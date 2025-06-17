import requests
import time
import hmac
import hashlib
import threading # Import threading for concurrent operations

# --- Your encryption & RSA module ---
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
)

# --- Chat server address ---
server_url = "http://127.0.0.1:5000"

# --- Helper functions for server communication ---
def register_bob_public_key_with_server(public_key):
    e, n = public_key
    data = {"e": e, "n": n}
    try:
        response = requests.post(f"{server_url}/register_bob_public_key", json=data)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        print("Bob's public key registered:", response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error registering Bob's public key: {e}")
        exit() # Exit if key registration fails, as communication won't work

def get_encrypted_seed_from_alice():
    try:
        response = requests.get(f"{server_url}/get_encrypted_seed_for_bob")
        response.raise_for_status() # This will raise an exception for 4xx/5xx status codes

        response_data = response.json()
        if isinstance(response_data, dict):
            return response_data.get("encrypted_seed")
        else:
            print(f"Unexpected response type from server for encrypted seed: {type(response_data)}")
            return None

    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 404:
            return None # Expected when seed is not yet available
        else:
            print(f"HTTP error occurred while getting encrypted seed: {http_err}")
            return None
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred while getting encrypted seed: {conn_err}")
        return None
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred while getting encrypted seed: {timeout_err}")
        return None
    except requests.exceptions.RequestException as req_err:
        print(f"An unexpected error occurred during request for encrypted seed: {req_err}")
        return None
    except Exception as e: # Catch any other unexpected parsing errors
        print(f"An unexpected error occurred while processing JSON response for encrypted seed: {e}")
        return None


def get_messages_for_bob():
    try:
        response = requests.get(f"{server_url}/get_for_bob")
        response.raise_for_status()
        return response.json().get("messages", [])
    except requests.exceptions.RequestException as e:
        print(f"Error getting messages for Bob: {e}")
        return []

def send_message_to_alice(encrypted_payload, iteration, original_length, auth_tag):
    data = {
        "message": encrypted_payload,
        "iteration": iteration,
        "length": original_length,
        "auth_tag": auth_tag
    }
    try:
        response = requests.post(f"{server_url}/send_from_bob", json=data)
        response.raise_for_status()
        print("Sent reply:", response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error sending reply from Bob: {e}")

# --- New function to establish shared seed for Bob ---
def establish_shared_seed_for_bob():
    """
    Handles Bob's part of the key exchange:
    1. Generates Bob's RSA keys.
    2. Registers Bob's public key with the server.
    3. Waits for and decrypts Alice's encrypted seed.
    Returns the decrypted shared seed and Bob's private key.
    """
    print("\nBob client started. Generating RSA keys and registering public key...")
    bob_public_key, bob_private_key = gen_rsa_keys()
    register_bob_public_key_with_server(bob_public_key)
    print("Waiting for Alice's encrypted seed...")

    received_seed = None
    while received_seed is None:
        encrypted_seed = get_encrypted_seed_from_alice()
        if encrypted_seed:
            try:
                received_seed = rsa_decrypt(encrypted_seed, bob_private_key)
                print(f"Successfully received and decrypted shared seed: {received_seed}")
            except Exception as e:
                print(f"Error decrypting seed: {e}")
                received_seed = None # Reset to try again
        time.sleep(1)
    return received_seed, bob_private_key # Return both seed and private key

# --- Function to continuously poll for messages ---
def message_poller(shared_seed_to_use, stop_event):
    while not stop_event.is_set():
        messages = get_messages_for_bob()
        for m in messages:
            if shared_seed_to_use:
                dec = decrypt_message(m["message"], m["iteration"], m["length"], shared_seed_to_use, m["auth_tag"])
                print(f"\nAlice: {dec}\nBob: ", end="", flush=True) # Print Alice's message and re-prompt Bob
            else:
                print("Error: Shared seed not available for decryption in poller.")
                break # Stop processing messages if seed is missing
        time.sleep(0.5) # Poll every 0.5 seconds

# --- Main loop ---
def main():
    # Call the key establishment function; get both seed and private key locally
    bob_current_shared_seed, _bob_private_key_unused = establish_shared_seed_for_bob() # Private key is not needed in main loop itself

    if not bob_current_shared_seed:
        print("Failed to establish shared seed. Exiting.")
        return

    print("\nBob client ready. Type 'exit' to quit.\n")

    # Event to signal the poller thread to stop
    stop_poller = threading.Event()
    
    # Start the message polling thread
    poller_thread = threading.Thread(target=message_poller, args=(bob_current_shared_seed, stop_poller))
    poller_thread.daemon = True # Allows the main program to exit even if thread is running
    poller_thread.start()

    while True:
        try:
            msg = input("Bob: ") # Bob can now initiate here
            if msg.lower() == "exit":
                break

            if bob_current_shared_seed:
                encrypted_payload, iteration, original_length, auth_tag = encrypt_message(
                    msg, seedGenerator, bob_current_shared_seed
                )
                send_message_to_alice(encrypted_payload, iteration, original_length, auth_tag)
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

    print("Bob client exited.")

if __name__ == "__main__":
    main()