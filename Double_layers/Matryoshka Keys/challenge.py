from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os
from Crypto.Cipher import ChaCha20_Poly1305 as XChaCha20_Poly1305

# Parameters for challenge
SALT_1 = os.urandom(16)
SALT_2 = os.urandom(16)
ITERATIONS = 100_000

# Challenge message
plaintext = b"isfcr{damn_your_good}"

# Step 1: Generate ECC key pair and shared secret
private_key = ec.generate_private_key(ec.SECP256K1())
public_key = private_key.public_key()
peer_private_key = ec.generate_private_key(ec.SECP256K1())
peer_public_key = peer_private_key.public_key()
shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

# Step 2: KDF chaining (HKDF -> PBKDF2)
# HKDF derivation step
hkdf = HKDF(
    algorithm=SHA256(),
    length=32,
    salt=SALT_1,
    info=b"challenge",
)
intermediate_key = hkdf.derive(shared_secret)

# PBKDF2 derivation step
pbkdf2 = PBKDF2HMAC(
    algorithm=SHA256(),
    length=32,
    salt=SALT_2,
    iterations=ITERATIONS,
)
final_key = pbkdf2.derive(intermediate_key)

# Step 3: Encrypt data with XChaCha20 (24-byte nonce using PyCryptodome)
nonce = os.urandom(24)  # XChaCha20 requires a 24-byte nonce
chacha = XChaCha20_Poly1305.new(key=final_key, nonce=nonce)
ciphertext, tag = chacha.encrypt_and_digest(plaintext)

# Output challenge data including private keys
print("Challenge Parameters:")
print("Private Key:", private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode())
print("Peer Private Key:", peer_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode())
print("Public Key:", public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode())
print("Peer Public Key:", peer_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode())
print("Ciphertext:", ciphertext.hex())
print("Tag:", tag.hex())
print("Nonce:", nonce.hex())
print("Salt 1:", SALT_1.hex())
print("Salt 2:", SALT_2.hex())