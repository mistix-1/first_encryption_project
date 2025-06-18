import random
import math
import binascii
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import secrets
from sympy import mod_inverse
from sympy import isprime as isPrime
import hashlib
import hmac

import secrets
import random
import hmac
import hashlib

# --------- Seed Generator Class ---------
class seedGenerator:
    @staticmethod
    def seed_gen():
        return secrets.randbelow(10**35 - 10**25) + 10**25

    @staticmethod
    def get_middle_digits(seed: int):
        seed_str = str(seed)
        length = len(seed_str)
        if length < 15:
            return seed
        start = (length // 2) - 7
        end = (length // 2) + 8
        return int(seed_str[start:end])

    @staticmethod
    def iteration(x: int, seed: int):
        current = seed
        for _ in range(x):
            middle = seedGenerator.get_middle_digits(current)
            current = middle ** 2
        return current

# --------- Miller-Rabin Primality Test ---------
def miller_rabin(n, k=5):
    if n in (2, 3): return True
    if n < 2 or n % 2 == 0: return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# --------- Modular Inverse ---------
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1: return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# --------- Prime generation ---------
def generate_prime(bits=514):
    while True:
        candidate = secrets.randbits(bits) | 1  # make sure it's odd
        if miller_rabin(candidate):
            return candidate

# --------- RSA Key Generation ---------
def gen_rsa_keys():
    p, q = generate_prime(), generate_prime()
    while p == q:
        q = generate_prime()
    N = p * q
    phi_N = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi_N)
    return (e, N), (d, N)  # public, private

# --------- RSA Encrypt/Decrypt ---------
def rsa_encrypt(seed_val, public_key):
    e, N = public_key
    return pow(seed_val, e, N)

def rsa_decrypt(cipherText, private_key):
    d, n = private_key
    return pow(cipherText, d, n)

# --------- Symmetric Encryption / Decryption ---------
ITER_BITS = 16
LEN_BITS = 16

def encrypt_message(message, seedGenerator, seed):
    def to_binary(text): return ''.join([bin(ord(c))[2:].zfill(8) for c in text])
    message_binary = to_binary(message)
    original_length_in_bits = len(message_binary)
    iteration = secrets.randbelow(9000) + 1000
    embedded_binary = bin(original_length_in_bits)[2:].zfill(LEN_BITS) + message_binary + bin(iteration)[2:].zfill(ITER_BITS)
    cipher_num = seedGenerator.iteration(iteration, seed)
    cipher_binary = bin(cipher_num)[2:]
    if len(cipher_binary) < len(embedded_binary):
        cipher_binary = (cipher_binary * (len(embedded_binary) // len(cipher_binary) + 1))[:len(embedded_binary)]
    def xor_binary(a, b): return ''.join('1' if x != y else '0' for x, y in zip(a, b))
    encrypted_binary = xor_binary(embedded_binary, cipher_binary)
    def bin_to_ascii(binary): return ''.join([chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)])
    payload = bin_to_ascii(encrypted_binary)
    hmac_key = str(seed).encode('utf-8')
    auth_tag = hmac.new(hmac_key, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return payload, iteration, original_length_in_bits, auth_tag

def decrypt_message(payload, iteration, length, seed, auth_tag):
    hmac_key = str(seed).encode('utf-8')
    calc_tag = hmac.new(hmac_key, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc_tag, auth_tag):
        print("!!! HMAC MISMATCH: Message forged or altered!")
        return "[INVALID MESSAGE]"
    def ascii_to_binary(text): return ''.join([bin(ord(c))[2:].zfill(8) for c in text])
    encrypted_binary = ascii_to_binary(payload)
    cipher_binary = bin(seedGenerator.iteration(iteration, seed))[2:]
    if len(cipher_binary) < len(encrypted_binary):
        cipher_binary = (cipher_binary * (len(encrypted_binary) // len(cipher_binary) + 1))[:len(encrypted_binary)]
    def xor_binary(a, b): return ''.join('1' if x != y else '0' for x, y in zip(a, b))
    decrypted_binary = xor_binary(encrypted_binary, cipher_binary)
    message_binary = decrypted_binary[LEN_BITS:-ITER_BITS]
    def binary_to_text(b): return ''.join([chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)])
    return binary_to_text(message_binary[:length])

def exchange_seeds():
    print("\n--- Initiating Seed Exchange (RSA) ---")
    # Generate RSA key pair for Bob (public/private)
    bob_public_key, bob_private_key = gen_rsa_keys()
    
    # Alice generates her seed
    alice_seed = seedGenerator.seed_gen()
    print(f"Alice seed: {alice_seed}")
    
    # Encrypt Alice's seed with Bob's public key
    encrypted_seed = rsa_encrypt(alice_seed, bob_public_key)
    
    # Decrypt it back using Bob's private key to verify correctness
    decrypted_seed = rsa_decrypt(encrypted_seed, bob_private_key)
    
    if alice_seed == decrypted_seed:
        print("Seed exchange OK")
    else:
        print("Seed mismatch!")
    
    return alice_seed

