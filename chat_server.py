from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory message store
messages = {
    "from_alice": [],
    "from_bob": []
}

# New stores for key exchange
bob_public_key_store = {} # To store Bob's (e, N) tuple
encrypted_seed_store = {} # To store the encrypted seed from Alice

@app.route('/')
def home():
    return "🔐 Secure Chat Server is running!"

@app.route('/send_from_alice', methods=['POST'])
def send_from_alice():
    data = request.json
    message = data.get('message', '')
    iteration = data.get('iteration', 0)
    length = data.get('length', 0)
    auth_tag = data.get('auth_tag', '')
    
    # Store full message payload for Bob
    messages["from_alice"].append({
        "message": message,
        "iteration": iteration,
        "length": length,
        "auth_tag": auth_tag
    })
    return jsonify({"status": "Message from Alice received!"})

@app.route('/get_for_bob', methods=['GET'])
def get_for_bob():
    # Return and clear messages for Bob
    msgs_for_bob = list(messages["from_alice"])
    messages["from_alice"].clear()
    return jsonify({"messages": msgs_for_bob})

@app.route('/send_from_bob', methods=['POST'])
def send_from_bob():
    data = request.json
    message = data.get('message', '')
    iteration = data.get('iteration', 0)
    length = data.get('length', 0)
    auth_tag = data.get('auth_tag', '')

    # Store full message payload for Alice
    messages["from_bob"].append({
        "message": message,
        "iteration": iteration,
        "length": length,
        "auth_tag": auth_tag
    })
    return jsonify({"status": "Message from Bob received!"})

@app.route('/get_for_alice', methods=['GET'])
def get_for_alice():
    # Return and clear messages for Alice
    msgs_for_alice = list(messages["from_bob"])
    messages["from_bob"].clear()
    return jsonify({"messages": msgs_for_alice})

# --- New Key Exchange Endpoints ---

@app.route('/register_bob_public_key', methods=['POST'])
def register_bob_public_key():
    data = request.json
    e = data.get('e')
    n = data.get('n')
    if e is not None and n is not None:
        bob_public_key_store["key"] = {"e": e, "n": n}
        return jsonify({"status": "Bob's public key registered."})
    return jsonify({"status": "Failed to register Bob's public key."}, 400)

@app.route('/get_bob_public_key', methods=['GET'])
def get_bob_public_key():
    if "key" in bob_public_key_store:
        return jsonify(bob_public_key_store["key"])
    return jsonify({"status": "Bob's public key not available."}, 404)

@app.route('/send_encrypted_seed_to_bob', methods=['POST'])
def send_encrypted_seed_to_bob():
    data = request.json
    encrypted_seed = data.get('encrypted_seed')
    if encrypted_seed is not None:
        encrypted_seed_store["seed"] = encrypted_seed
        return jsonify({"status": "Encrypted seed from Alice received."})
    return jsonify({"status": "Failed to receive encrypted seed."}, 400)

@app.route('/get_encrypted_seed_for_bob', methods=['GET'])
def get_encrypted_seed_for_bob():
    if "seed" in encrypted_seed_store:
        seed = encrypted_seed_store["seed"]
        encrypted_seed_store.clear() # Clear after retrieval
        return jsonify({"encrypted_seed": seed})
    return jsonify({"status": "No encrypted seed available."}, 404)


if __name__ == '__main__':
    app.run(debug=True)