import base64
from flask import Flask, request, jsonify
# Import cryptographic functions from the updated encryption module
# Ensure 'encryption.py' is in the same directory or accessible in your Python path
from encryption_code import gen_rsa_keys, rsa_encrypt, rsa_decrypt, derive_symmetric_key, encrypt_message_aes_gcm, decrypt_message_aes_gcm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa # Needed for type checking

app = Flask(__name__)

# In-memory message store for encrypted messages
# Each message will now store ciphertext, nonce, tag, and associated_data
# All stored as base64-encoded strings for JSON compatibility.
messages = {
    "from_alice": [], # Messages sent by Alice, to be retrieved by Bob
    "from_bob": []    # Messages sent by Bob, to be retrieved by Alice
}

# Stores for key exchange artifacts, also base64-encoded for JSON transmission.
# In a real application, these might be stored in a database and associated with user IDs.
bob_public_key_pem_store = {} # To store Bob's public key as base64-encoded PEM string
encrypted_master_secret_store = {} # To store the encrypted master secret as base64-encoded bytes

# --- Utility Functions for Base64 Encoding/Decoding ---
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
    return base64.b64encode(data_bytes).decode('utf-8')

def b64_str_to_bytes(b64_string):
    """Decodes a base64 string to a bytes object."""
    return base64.b64decode(b64_string.encode('utf-8'))


@app.route('/')
def home():
    """Simple home route to indicate server is running."""
    return "🔐 Secure Chat Server is running! (Please use HTTPS in production)"

# --- Message Exchange Endpoints ---

@app.route('/send_message', methods=['POST'])
def send_message():
    """
    Receives encrypted messages (ciphertext, nonce, tag, associated_data)
    from a sender and stores them for the specified recipient.
    The message components are expected to be base64-encoded strings.
    """
    data = request.json
    if not data:
        return jsonify({"status": "No data received."}, 400)

    sender = data.get('sender') # e.g., 'alice', 'bob'
    recipient = data.get('recipient') # e.g., 'alice', 'bob'
    ciphertext_b64 = data.get('ciphertext')
    nonce_b64 = data.get('nonce')
    tag_b64 = data.get('tag')
    associated_data_b64 = data.get('associated_data') # Optional, can be None

    # Validate essential message components
    if not all([sender, recipient, ciphertext_b64, nonce_b64, tag_b64]):
        return jsonify({"status": "Missing essential message components (sender, recipient, ciphertext, nonce, tag)."}, 400)

    try:
        # Determine target queue based on recipient
        if recipient == "alice":
            messages["from_bob"].append({
                "ciphertext": ciphertext_b64,
                "nonce": nonce_b64,
                "tag": tag_b64,
                "associated_data": associated_data_b64 # Store as b64 string
            })
        elif recipient == "bob":
            messages["from_alice"].append({
                "ciphertext": ciphertext_b64,
                "nonce": nonce_b64,
                "tag": tag_b64,
                "associated_data": associated_data_b64 # Store as b64 string
            })
        else:
            return jsonify({"status": "Invalid recipient ID. Must be 'alice' or 'bob'."}, 400)

        print(f"Message from {sender} to {recipient} received and stored.")
        return jsonify({"status": f"Message from {sender} to {recipient} received!"})

    except Exception as e:
        print(f"Error processing message from {sender} to {recipient}: {e}")
        return jsonify({"status": f"Server error processing message: {e}"}, 500)


@app.route('/get_messages/<string:user_id>', methods=['GET'])
def get_messages(user_id):
    """
    Retrieves messages for a specific user and clears their message queue.
    Returns messages as a list of dictionaries, with components still base64-encoded.
    """
    msgs_for_user = []
    if user_id == "alice":
        msgs_for_user = list(messages["from_bob"])
        messages["from_bob"].clear() # Clear messages after retrieval
    elif user_id == "bob":
        msgs_for_user = list(messages["from_alice"])
        messages["from_alice"].clear() # Clear messages after retrieval
    else:
        return jsonify({"status": "Invalid user ID. Must be 'alice' or 'bob'."}, 400)

    print(f"Messages retrieved for {user_id}. {len(msgs_for_user)} messages found.")
    return jsonify({"messages": msgs_for_user})


# --- Key Exchange Endpoints ---

@app.route('/register_public_key', methods=['POST'])
def register_public_key():
    """
    Registers a user's RSA public key. For this setup, typically Bob registers his key.
    The public key is expected as a base64-encoded PEM string.
    Expected JSON payload: {'user_id': 'bob', 'public_key_pem_b64': '...'}.
    """
    data = request.json
    if not data:
        return jsonify({"status": "No data received."}, 400)

    user_id = data.get('user_id')
    public_key_pem_b64 = data.get('public_key_pem_b64')

    if user_id == "bob" and public_key_pem_b64:
        # In a real system, you'd associate this with a user's account in a DB.
        # For simplicity, we just store Bob's key in memory.
        bob_public_key_pem_store["key"] = public_key_pem_b64
        print(f"Bob's public key registered: {public_key_pem_b64[:60]}...") # Print a snippet
        return jsonify({"status": "Bob's public key registered."})
    else:
        return jsonify({"status": "Failed to register public key. Invalid user_id or missing key data."}, 400)

@app.route('/get_public_key/<string:user_id>', methods=['GET'])
def get_public_key(user_id):
    """
    Retrieves a user's RSA public key (base64-encoded PEM string).
    Alice will typically request Bob's public key.
    """
    if user_id == "bob" and "key" in bob_public_key_pem_store:
        print("Bob's public key requested and sent.")
        return jsonify({"public_key_pem_b64": bob_public_key_pem_store["key"]})
    return jsonify({"status": "Public key not available for the requested user ('bob')."}, 404)

@app.route('/send_encrypted_master_secret', methods=['POST'])
def send_encrypted_master_secret():
    """
    Receives Alice's RSA-encrypted master secret for Bob.
    The encrypted master secret is expected as a base64-encoded string.
    Expected JSON payload: {'encrypted_master_secret_b64': '...'}.
    """
    data = request.json
    if not data:
        return jsonify({"status": "No data received."}, 400)

    encrypted_master_secret_b64 = data.get('encrypted_master_secret_b64')
    if encrypted_master_secret_b64:
        # In a real system, this would be associated with Bob's user ID.
        encrypted_master_secret_store["secret"] = encrypted_master_secret_b64
        print(f"Encrypted master secret from Alice received: {encrypted_master_secret_b64[:60]}...") # Print a snippet
        return jsonify({"status": "Encrypted master secret from Alice received."})
    return jsonify({"status": "Failed to receive encrypted master secret."}, 400)

@app.route('/get_encrypted_master_secret', methods=['GET'])
def get_encrypted_master_secret():
    """
    Retrieves the encrypted master secret for Bob and clears it from the store.
    """
    if "secret" in encrypted_master_secret_store:
        secret_b64 = encrypted_master_secret_store["secret"]
        encrypted_master_secret_store.clear() # Clear after retrieval to simulate one-time use
        print(f"Encrypted master secret requested and sent to Bob: {secret_b64[:60]}...") # Print a snippet
        return jsonify({"encrypted_master_secret_b64": secret_b64})
    return jsonify({"status": "No encrypted master secret available."}, 404)


if __name__ == '__main__':
    # WARNING: This Flask development server is NOT secure for production!
    # It runs on HTTP by default. For production deployment, you MUST use:
    # 1. A production-ready WSGI server (e.g., Gunicorn, uWSGI).
    # 2. A reverse proxy (e.g., Nginx, Apache) configured to handle HTTPS (SSL/TLS certificates).
    # This ensures all network traffic is encrypted and the server is authenticated.
    print("--- Starting Secure Chat Server ---")
    print("WARNING: This server is running on HTTP for development. USE HTTPS IN PRODUCTION!")
    app.run(debug=True, port=5000)

