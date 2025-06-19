import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Configuration Constants ---
# RSA key size in bits. Modern recommendation is 2048-bit minimum, 4096-bit for stronger security.
# This will result in p and q being 2048 bits each, for a total modulus of 4096 bits.
RSA_KEY_BITS = 4096

# Length of the symmetric master secret derived from RSA, in bytes.
# This will be the input key material for HKDF. 32 bytes = 256 bits, suitable for AES-256.
MASTER_SECRET_BYTE_LENGTH = 32

# Length of the nonce (Initialization Vector) for AES-GCM, in bytes.
# 12 bytes (96 bits) is the recommended size for AES-GCM for optimal security and performance.
AES_GCM_NONCE_LENGTH = 12

# Length of the derived AES key, in bytes (16, 24, or 32 for AES-128, AES-192, AES-256 respectively).
# We'll use 32 bytes for AES-256.
AES_KEY_LENGTH = 32

# --- RSA Key Generation, Encryption, and Decryption ---

def gen_rsa_keys():
    """
    Generates a new RSA public and private key pair using cryptography.hazmat.
    Key size is RSA_KEY_BITS (4096 bits). Public exponent is 65537.
    Returns:
        tuple: (public_key, private_key) where keys are cryptography objects.
    """
    print(f"Generating RSA keys of {RSA_KEY_BITS} bits...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_BITS,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    print("RSA key generation complete.")
    return public_key, private_key

def rsa_encrypt(plaintext_bytes, public_key):
    """
    Encrypts a byte string using RSA with OAEP padding.
    Args:
        plaintext_bytes (bytes): The data to encrypt (e.g., the master secret).
        public_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
            The recipient's RSA public key.
    Returns:
        bytes: The RSA-encrypted ciphertext.
    Raises:
        ValueError: If plaintext_bytes is too large for the RSA key with OAEP.
    """
    # OAEP requires the plaintext to be smaller than the modulus minus overhead.
    # The maximum input size for OAEP is k - 2*hLen - 2, where k is the RSA key size in bytes,
    # and hLen is the hash algorithm's output size in bytes (SHA256 = 32 bytes).
    max_plaintext_len = public_key.key_size // 8 - 2 * hashes.SHA256.digest_size - 2
    if len(plaintext_bytes) > max_plaintext_len:
        raise ValueError(
            f"Plaintext too large for RSA key with OAEP. "
            f"Max size: {max_plaintext_len} bytes, Got: {len(plaintext_bytes)} bytes."
        )

    return public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(ciphertext_bytes, private_key):
    """
    Decrypts RSA ciphertext using OAEP padding.
    Args:
        ciphertext_bytes (bytes): The RSA-encrypted data.
        private_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
            The recipient's RSA private key.
    Returns:
        bytes: The decrypted plaintext bytes (e.g., the master secret).
    Raises:
        cryptography.exceptions.InvalidTag: If the OAEP padding is invalid (tampered ciphertext).
    """
    return private_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# --- Key Derivation Function (KDF) ---

def derive_symmetric_key(master_secret: bytes, info: bytes = b"chat_aes_key"):
    """
    Derives a symmetric AES key from a master secret using HKDF.
    Args:
        master_secret (bytes): The high-entropy secret (e.g., decrypted RSA seed).
        info (bytes): Optional context information for key separation.
    Returns:
        bytes: The derived symmetric AES key.
    """
    # HKDF-SHA256 is used here. No salt is explicitly needed if master_secret has high entropy,
    # but a consistent salt could be added for domain separation if master_secret is reused for other purposes.
    # For now, we assume master_secret is unique per session.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH, # Desired length of the derived key
        salt=None,             # No salt needed if input_key_material has high entropy and is unique.
        info=info,             # Contextual info for key separation (e.g., "chat_aes_key")
        backend=default_backend()
    )
    return hkdf.derive(master_secret)

# --- Authenticated Encryption with Associated Data (AEAD) - AES-GCM ---

def encrypt_message_aes_gcm(message: str, aes_key: bytes, associated_data: bytes = None):
    """
    Encrypts a message using AES-256 in GCM mode, providing confidentiality and authenticity.
    Args:
        message (str): The plaintext message to encrypt.
        aes_key (bytes): The 32-byte AES-256 key.
        associated_data (bytes, optional): Optional data to authenticate but not encrypt.
                                          E.g., message ID, sender ID. Defaults to None.
    Returns:
        tuple: (ciphertext_bytes, nonce, tag)
    """
    nonce = secrets.token_bytes(AES_GCM_NONCE_LENGTH) # Generate a unique nonce for each encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    if associated_data is not None:
        encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag # The authentication tag

    return ciphertext, nonce, tag

def decrypt_message_aes_gcm(ciphertext: bytes, nonce: bytes, tag: bytes, aes_key: bytes, associated_data: bytes = None):
    """
    Decrypts a message encrypted with AES-GCM and verifies its authenticity.
    Args:
        ciphertext (bytes): The AES-GCM encrypted message.
        nonce (bytes): The nonce used during encryption.
        tag (bytes): The authentication tag.
        aes_key (bytes): The 32-byte AES-256 key.
        associated_data (bytes, optional): Optional data that was authenticated during encryption.
                                          Defaults to None.
    Returns:
        str: The decrypted plaintext message.
    Raises:
        cryptography.exceptions.InvalidTag: If the message has been tampered with or the key/nonce/tag is incorrect.
    """
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    if associated_data is not None:
        decryptor.authenticate_additional_data(associated_data)

    try:
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        # Catching a general exception for simplicity, but cryptography.exceptions.InvalidTag
        # is the specific one for authentication failure.
        print(f"!!! DECRYPTION FAILED: Message forged, altered, or incorrect key/nonce/tag. Error: {e}")
        return "[INVALID MESSAGE OR CORRUPTED]"

# --- Main Key Exchange Flow (for demonstration) ---

def exchange_keys():
    """
    Simulates the RSA key exchange to establish a shared symmetric key.
    Alice generates a master secret, encrypts it with Bob's public RSA key.
    Bob decrypts it with his private RSA key.
    Both then derive a symmetric AES key using HKDF from the master secret.

    Returns:
        tuple: (alice_aes_key, bob_aes_key) derived after successful exchange.
    """
    print("\n--- Initiating Key Exchange (RSA with OAEP) ---")

    # Bob generates his RSA key pair
    bob_public_key, bob_private_key = gen_rsa_keys()
    print("Bob's RSA keys generated.")

    # Alice generates a cryptographically secure master secret (input key material for HKDF)
    alice_master_secret = secrets.token_bytes(MASTER_SECRET_BYTE_LENGTH)
    print(f"Alice generates master secret (length: {len(alice_master_secret)} bytes)")

    # Alice encrypts the master secret with Bob's public key (using OAEP)
    encrypted_master_secret = rsa_encrypt(alice_master_secret, bob_public_key)
    print("Alice encrypted master secret with Bob's public key.")

    # Bob decrypts the master secret with his private key (using OAEP)
    decrypted_master_secret = rsa_decrypt(encrypted_master_secret, bob_private_key)
    print("Bob decrypted master secret.")

    # Verify if the decrypted master secret matches the original
    if alice_master_secret == decrypted_master_secret:
        print("Master secret exchange OK. Master secrets match.")
        # Both Alice and Bob derive their symmetric AES key from the shared master secret using HKDF
        alice_aes_key = derive_symmetric_key(alice_master_secret, info=b"chat_session_key")
        bob_aes_key = derive_symmetric_key(decrypted_master_secret, info=b"chat_session_key")
        print(f"Derived AES key (Alice): {alice_aes_key.hex()}")
        print(f"Derived AES key (Bob): {bob_aes_key.hex()}")
        return alice_aes_key, bob_aes_key
    else:
        print("!!! Master secret mismatch! Key exchange failed.")
        return None, None

# Example Usage (for testing this module independently)
if __name__ == "__main__":
    print("--- Testing Encryption Module ---")

    # 1. Simulate key exchange
    shared_aes_key_alice, shared_aes_key_bob = exchange_keys()

    if shared_aes_key_alice and shared_aes_key_bob:
        # 2. Alice encrypts a message
        original_message = "Hello Bob, this is a very secret message using AES-GCM!"
        print(f"\nAlice's original message: '{original_message}'")

        # Associated data could be anything unencrypted but authenticated, e.g., message_id, sender, timestamp
        msg_id = b"MSG001"
        ciphertext, nonce, tag = encrypt_message_aes_gcm(original_message, shared_aes_key_alice, associated_data=msg_id)

        print(f"Encrypted message (ciphertext): {ciphertext.hex()}")
        print(f"Nonce: {nonce.hex()}")
        print(f"Authentication Tag: {tag.hex()}")
        print(f"Associated Data: {msg_id.decode()}")

        # 3. Bob decrypts the message
        print("\nBob attempts to decrypt the message...")
        decrypted_message = decrypt_message_aes_gcm(ciphertext, nonce, tag, shared_aes_key_bob, associated_data=msg_id)
        print(f"Bob's decrypted message: '{decrypted_message}'")

        if original_message == decrypted_message:
            print("\nMessage decryption successful and authenticated!")
        else:
            print("\n!!! Message decryption FAILED or content altered!")

        # --- Test tampering (simulating a Man-in-the-Middle attack) ---
        print("\n--- Testing Tampering ---")
        tampered_ciphertext = ciphertext + b'\x00' # Append a byte to ciphertext
        print("Attempting to decrypt tampered ciphertext...")
        decrypted_tampered_message = decrypt_message_aes_gcm(tampered_ciphertext, nonce, tag, shared_aes_key_bob, associated_data=msg_id)
        print(f"Decrypted tampered message (expected failure): '{decrypted_tampered_message}'")

        tampered_nonce = secrets.token_bytes(AES_GCM_NONCE_LENGTH) # Use a wrong nonce
        print("\nAttempting to decrypt with wrong nonce...")
        decrypted_wrong_nonce_message = decrypt_message_aes_gcm(ciphertext, tampered_nonce, tag, shared_aes_key_bob, associated_data=msg_id)
        print(f"Decrypted wrong nonce message (expected failure): '{decrypted_wrong_nonce_message}'")

        tampered_associated_data = b"EVIL_ATTACK" # Change associated data
        print("\nAttempting to decrypt with tampered associated data...")
        decrypted_tampered_aad_message = decrypt_message_aes_gcm(ciphertext, nonce, tag, shared_aes_key_bob, associated_data=tampered_associated_data)
        print(f"Decrypted tampered AAD message (expected failure): '{decrypted_tampered_aad_message}'")

    else:
        print("Key exchange failed, aborting message test.")
