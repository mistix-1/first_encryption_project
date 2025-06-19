# Encrypted Chat System (Educational Project)
This repository contains a simple, yet illustrative, encrypted chat system designed for educational purposes. It demonstrates fundamental concepts of modern cryptography, including asymmetric (RSA) key exchange and symmetric (AES-GCM) message encryption, facilitated by a central server acting as a message broker.

# This project is intended for learning and understanding cryptographic principles. It is NOT built for production use and lacks many security considerations vital for real-world applications (e.g., robust authentication, certificate pinning, persistent storage, advanced threat modeling, comprehensive error handling, etc.).

# Learning Objectives
Through this project, you can learn about:

Asymmetric Cryptography (RSA): How public and private key pairs are used for secure key exchange. Specifically, RSA with OAEP padding for securely transmitting a shared secret.
Symmetric Cryptography (AES-GCM): How a shared secret key is used for efficient and authenticated encryption of messages. AES-GCM provides both confidentiality and integrity/authenticity.
Key Derivation Functions (HKDF): The importance of deriving strong session keys from master secrets to ensure proper key usage and reduce potential vulnerabilities.
Authenticated Encryption with Associated Data (AEAD): Understanding the role of Nonces (Initialization Vectors) and Authentication Tags, along with Associated Data (AAD), to protect against tampering, replay attacks, and to bind messages to specific contexts.
Secure Communication Flow: Visualizing the steps involved in establishing a secure channel between two parties (Alice and Bob) over an insecure medium.
Client-Server Architecture: How clients interact with a central server to facilitate message passing without the server needing to see plaintext.
Base64 Encoding: Its utility in safely transmitting binary cryptographic data (keys, ciphertexts, nonces, tags) over text-
based protocols like HTTP/JSON.

# How it Works
The system consists of three main components:

server_chat.py (Local API Server):

Built with Flask, it acts as a minimalist message relay and a public key directory.
It does not store or have access to the plaintext of any messages.
Facilitates the key exchange by temporarily holding Bob's public RSA key and the encrypted master secret from Alice.
Provides endpoints for clients to register public keys, send encrypted master secrets, and exchange encrypted chat messages.
All cryptographic material (keys, ciphertexts, nonces, tags) sent to/from the server is Base64-encoded to be compatible with JSON.
alice_client.py (Alice Client):

Simulates Alice, one of the communicating parties.
Initiates the secure communication by fetching Bob's public RSA key from the server.
Generates a random master secret.
Encrypts the master secret using Bob's public RSA key (OAEP padding) and sends it to the server for Bob.
Derives a symmetric AES key from the master secret using HKDF.
Encrypts her chat messages using AES-256 GCM with the shared AES key, a unique nonce, and includes a timestamp as Associated Data (AAD).
Continuously polls the server for new messages from Bob and decrypts them using the shared AES key.
bob_client.py (Bob Client):

Simulates Bob, the other communicating party.
Generates his own RSA key pair (public and private).
Registers his public RSA key with the server.
Polls the server until Alice's RSA-encrypted master secret is available.
Decrypts the master secret using his private RSA key (OAEP padding).
Derives a symmetric AES key from the master secret using HKDF (resulting in the same key as Alice).
Encrypts his reply messages using AES-256 GCM with the shared AES key, a unique nonce, and includes a timestamp as Associated Data (AAD).
Continuously polls the server for new messages from Alice and decrypts them using the shared AES key.
encryption_code.py (Core Cryptography Module):

Contains the fundamental cryptographic functions used by both clients.
# RSA Operations:
gen_rsa_keys(): Generates RSA public/private key pairs (4096-bit for strong security).
rsa_encrypt(): Encrypts data using RSA with Optimal Asymmetric Encryption Padding (OAEP) for security against various attacks.
rsa_decrypt(): Decrypts data using RSA with OAEP.
Key Derivation:
derive_symmetric_key(): Implements a Key Derivation Function (HKDF-SHA256) to derive a robust AES session key from the shared master secret. This is crucial for securely transforming a high-entropy secret into a key of the appropriate length for AES.
AES-GCM (Authenticated Encryption with Associated Data):
encrypt_message_aes_gcm(): Encrypts messages using AES-256 in Galois/Counter Mode (GCM). It generates a unique nonce and an authentication tag, and supports Associated Data (AAD) for binding unencrypted metadata to the ciphertext.
decrypt_message_aes_gcm(): Decrypts AES-GCM messages and, critically, verifies the authentication tag and associated data to ensure the message's integrity and authenticity. A failure in this step indicates tampering.

# Setup and Running
Prerequisites
Python 3.7+
requests library (pip install requests)
Flask library (pip install Flask)
cryptography library (pip install cryptography)

