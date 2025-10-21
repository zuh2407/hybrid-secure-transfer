from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

print("Generating RSA key pair...")

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Generate public key
public_key = private_key.public_key()

# --- Save Private Key ---
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open('storage/server_private_key.pem', 'wb') as f:
    f.write(pem_private)

# --- Save Public Key ---
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('storage/server_public_key.pem', 'wb') as f:
    f.write(pem_public)

print("Successfully generated and saved keys to /storage/")
print("-> server_private_key.pem (KEEP THIS SECRET)")
print("-> server_public_key.pem (This is shareable)")