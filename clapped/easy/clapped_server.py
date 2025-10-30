"""
Minimal "underhanded" stream-cipher CTF server (Python 3)

- What this is: a tiny HTTP server that implements a stream cipher (XOR with a PRNG-derived keystream)
  but contains a small, subtle implementation bug that can be exploited with chosen plaintext queries.

- How the bug works (subtle):
  The server generates a keystream using a seeded PRNG. When encrypting, it normally consumes
  keystream bytes sequentially. However, for messages whose length is > 32 bytes the implementation
  *offsets the keystream consumption by `msg_len % 16`*, effectively causing keystream bytes to be
  reused at different positions across different-encrypted messages. This creates pairwise relations
  between ciphertext bytes for different requests (an exploitable leak similar in spirit to the
  Google CTF underhanded AES bug).

- Endpoints:
  POST /encrypt   - body: JSON {"data": "hex-encoded-plaintext"}
                    returns JSON {"ciphertext": "hex"}

  POST /encrypt_secret - body: JSON {"data": "hex-encoded-plaintext"}
                    returns JSON {"ciphertext": "hex"}
                    This endpoint appends a server-side secret to your plaintext before encrypting
                    and is the one you'd attack in a CTF setting.

- Usage:
  1) Install requirements: `pip install flask`
  2) Run: `python3 underhanded_stream_cipher_server.py`
  3) Send POSTs to http://127.0.0.1:5000/encrypt with hex plaintext.

- NOTE: This is intentionally insecure and meant for learning/CTF purposes only.

"""

from flask import Flask, request, jsonify, abort
import hashlib
import secrets
import struct
import json
import binascii
import random

app = Flask(__name__)

# Server-side secret (the flag) - small example secret
_FLAG = b"FLAG{underhanded_stream_example}"

# Master key (random, fixed while server runs)
_MASTER_KEY = secrets.token_bytes(32)

# Utility: derive a deterministic PRNG seed from key + nonce
def derive_seed(key: bytes, nonce: bytes) -> int:
    h = hashlib.sha256()
    h.update(key)
    h.update(nonce)
    # Use first 8 bytes of digest as int seed
    return struct.unpack_from("!Q", h.digest(), 0)[0]

# Create a keystream generator for given key+nonce
# Uses Python's random.Random for simplicity (intentionally deterministic here)
def keystream_for(key: bytes, nonce: bytes):
    seed = derive_seed(key, nonce)
    r = random.Random(seed)
    # yield bytes indefinitely
    while True:
        # generate 4 random bytes at a time
        val = r.getrandbits(32)
        yield from val.to_bytes(4, "big")

# The subtle bug is in this encrypt function.
# For "normal" lengths we XOR keystream sequentially starting at 0.
# If len(plaintext) > 32, we mistakenly start consuming keystream from offset = len(plaintext) % 16
# (i.e., keystream byte i uses ks[i + offset]). This creates keystream reuse between messages
# of different lengths in a predictable pattern.

def encrypt_stream_xor(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    ks = keystream_for(key, nonce)
    out = bytearray(len(plaintext))

    # BUG: introduce an offset for longer messages
    offset = 0
    if len(plaintext) > 32:
        # subtle arithmetic bug: offset depends on plaintext length (shouldn't matter),
        # causing reuse of keystream across different messages.
        offset = len(plaintext) % 16

    # consume offset bytes from the generator (but DON'T throw them away correctly)
    # subtlety: we advance the generator by 'offset' but then we re-use the same underlying generator
    # for all positions rather than creating fresh indices per byte. This is what creates reuse.
    for _ in range(offset):
        next(ks)

    # XOR plaintext with keystream
    for i in range(len(plaintext)):
        b = next(ks)
        out[i] = plaintext[i] ^ b
    return bytes(out)


# Helper to accept hex payload and return hex ciphertext
def route_encrypt(payload_bytes: bytes, append_secret: bool = False) -> dict:
    # nonce chosen per-request (should be random and unique!)
    # nonce = secrets.token_bytes(12)
    nonce = b"\x00" * 12   
    if append_secret:
        plaintext = payload_bytes + _FLAG
    else:
        plaintext = payload_bytes

    ct = encrypt_stream_xor(_MASTER_KEY, nonce, plaintext)

    # We return nonce + ciphertext so client can attempt to decrypt (but the bug still leaks across requests)
    return {"nonce": binascii.hexlify(nonce).decode(), "ciphertext": binascii.hexlify(ct).decode()}


@app.route('/encrypt', methods=['POST'])
def encrypt():
    if not request.data:
        abort(400)
    try:
        obj = request.get_json(force=True)
        hexdata = obj.get('data')
        payload = binascii.unhexlify(hexdata)
    except Exception:
        abort(400)
    resp = route_encrypt(payload, append_secret=False)
    return jsonify(resp)


@app.route('/encrypt_secret', methods=['POST'])
def encrypt_secret():
    if not request.data:
        abort(400)
    try:
        obj = request.get_json(force=True)
        hexdata = obj.get('data')
        payload = binascii.unhexlify(hexdata)
    except Exception:
        abort(400)
    # In a CTF you'd attack this endpoint to recover _FLAG
    resp = route_encrypt(payload, append_secret=True)
    return jsonify(resp)


if __name__ == '__main__':
    print("Underhanded stream-cipher server starting on http://127.0.0.1:5000")
    print("Endpoints: POST /encrypt and POST /encrypt_secret (JSON {\"data\": \"hex\"})")
    app.run(debug=True)
