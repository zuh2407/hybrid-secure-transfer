import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# --- AES (Symmetric) Functions ---

def generate_aes_key():
    """Generates a secure 32-byte (256-bit) AES key."""
    return os.urandom(32)

def encrypt_file_aes(file_data, key):
    """
    Encrypts file data using AES-256-GCM.
    Returns (ciphertext, nonce, tag)
    """
    # GCM is an authenticated mode, which is more secure.
    nonce = os.urandom(12)  # GCM recommended nonce size
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    
    # The 'tag' is the authentication part
    return ciphertext, nonce, encryptor.tag

def decrypt_file_aes(ciphertext, key, nonce, tag):
    """
    Decrypts file data using AES-256-GCM.
    Returns the original data or raises an exception if auth fails.
    """
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt and authenticate
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data
    except Exception as e:
        print(f"Decryption failed: {e}")
        # This will fail if the tag is invalid (i.e., data was tampered with)
        raise ValueError("Decryption failed. Data may be corrupt or tampered with.")

# --- RSA (Asymmetric) Functions ---

def load_public_key(public_key_path="storage/server_public_key.pem"):
    """Loads an RSA public key from a .pem file."""
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def load_private_key(private_key_path="storage/server_private_key.pem"):
    """Loads an RSA private key from a .pem file."""
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Assuming no password on key
            backend=default_backend()
        )
    return private_key

def encrypt_key_rsa(key_to_encrypt, public_key):
    """Encrypts a symmetric key (like an AES key) with an RSA public key."""
    encrypted_key = public_key.encrypt(
        key_to_encrypt,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_key_rsa(encrypted_key, private_key):
    """Decrypts a symmetric key with an RSA private key."""
    decrypted_key = private_key.decrypt(
        encrypted_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

# --- Digital Signature Functions ---

def sign_data(data, private_key):
    """
    Generates a digital signature for a piece of data (e.g., a file hash).
    """
    signature = private_key.sign(
        data,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data, signature, public_key):
    """
    Verifies the digital signature of data.
    Returns True if valid, raises an exception if not.
    """
    try:
        public_key.verify(
            signature,
            data,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        raise ValueError("Invalid signature.")

# --- Hashing Function ---

def hash_data(data):
    """Generates a SHA-256 hash of data."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()