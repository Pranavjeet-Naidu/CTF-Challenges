from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import ChaCha20_Poly1305 as XChaCha20_Poly1305

def solve_challenge(private_key_pem, peer_public_key_pem, ciphertext_hex, tag_hex, nonce_hex, salt1_hex, salt2_hex):
    # Load the private key and peer public key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    peer_public_key = serialization.load_pem_public_key(
        peer_public_key_pem.encode()
    )
    
    # Generate shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Convert hex strings to bytes
    ciphertext = bytes.fromhex(ciphertext_hex)
    tag = bytes.fromhex(tag_hex)
    nonce = bytes.fromhex(nonce_hex)
    salt1 = bytes.fromhex(salt1_hex)
    salt2 = bytes.fromhex(salt2_hex)
    
    # HKDF step
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt1,
        info=b"challenge",
    )
    intermediate_key = hkdf.derive(shared_secret)
    
    # PBKDF2 step
    pbkdf2 = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt2,
        iterations=100_000,
    )
    final_key = pbkdf2.derive(intermediate_key)
    
    # Decrypt using XChaCha20-Poly1305
    chacha = XChaCha20_Poly1305.new(key=final_key, nonce=nonce)
    try:
        plaintext = chacha.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        return f"Decryption failed: {str(e)}"

# Challenge data
CHALLENGE_DATA = {
    "private_key": """-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg/p5gZADtHavmOXz5v5ay
19uGpWvFmZ0HVnDIUuqFzDuhRANCAARg7cs4wA2+4JpUgdost8NrrlvxfTWLGfJG
CNa+dXjDuLugHktHADomymwXToT2zoM9EuGy+lSEpfUuXB9oDWV1
-----END PRIVATE KEY-----""",
    "peer_public_key": """-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEE+sdvXfN3/rkAg7+nRUvQPz681ReGSUo
BUTMm8zILE99xUQqZcyPv0xQUrsac9k0HkwzPpwgVd34VuomQROtLQ==
-----END PUBLIC KEY-----""",
    "ciphertext": "b7a58ed40e28cfd224c5b16f4a5f0e53e4c76236e7",
    "tag": "9f45bdb8925d51575b0a2a73bde98f56",
    "nonce": "8ac70796d422587b944f9c59515b6a0e973562ba20655d73",
    "salt1": "ef4eba5912daeb610b16f3257342635b",
    "salt2": "85b0ad829884f0ebbab3f756a8c9f20a"
}

# Solve the challenge
plaintext = solve_challenge(
    CHALLENGE_DATA["private_key"],
    CHALLENGE_DATA["peer_public_key"],
    CHALLENGE_DATA["ciphertext"],
    CHALLENGE_DATA["tag"],
    CHALLENGE_DATA["nonce"],
    CHALLENGE_DATA["salt1"],
    CHALLENGE_DATA["salt2"]
)

print("Decrypted message:", plaintext.decode() if isinstance(plaintext, bytes) else plaintext)
