

## Challenge Overview

This CTF challenge involves exploiting a subtle cryptographic flaw in a custom stream cipher implementation. The server presents two endpoints:
- `/encrypt` - encrypts user-provided data
- `/encrypt_secret` - encrypts user-provided data with a secret flag appended

The goal is to recover the secret flag by exploiting a vulnerability in the encryption algorithm.

## The Vulnerability

The flaw lies in the `encrypt_stream_xor` function in the server implementation:

```python
def encrypt_stream_xor(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    ks = keystream_for(key, nonce)
    out = bytearray(len(plaintext))

    # BUG: introduce an offset for longer messages
    offset = 0
    if len(plaintext) > 32:
        # subtle arithmetic bug: offset depends on plaintext length
        offset = len(plaintext) % 16

    # consume offset bytes from the generator
    for _ in range(offset):
        next(ks)

    # XOR plaintext with keystream
    for i in range(len(plaintext)):
        b = next(ks)
        out[i] = plaintext[i] ^ b
    return bytes(out)
```

The critical vulnerability:
1. For messages longer than 32 bytes, the function advances the keystream by `len(plaintext) % 16` bytes
2. This creates predictable patterns of keystream reuse across different messages
3. Combined with the fixed nonce (`nonce = b"\x00" * 12`), the same keystream is reused across requests

## The Exploit Solution

The solution works by:

1. **Keystream Collection**: 
   - Sending plaintexts filled with zeros (0x00) of various lengths
   - When a zero is XORed with a keystream byte, it directly reveals the keystream byte
   - By sending messages of different lengths, we can map out a large portion of the keystream

2. **Flag Recovery**:
   - Send a chosen plaintext to `/encrypt_secret` (the server appends the flag)
   - Calculate the offset used for this encryption based on total message length
   - XOR the flag portion of the ciphertext with the corresponding recovered keystream bytes

The solver works because:
- With a fixed nonce, the server generates the same keystream sequence for every request
- The offset bug makes it possible to reconstruct the entire keystream by sending carefully crafted requests
- Once we know the keystream, we can decrypt any message encrypted with it, including the flag

This is a classic example of why stream ciphers must never reuse keystreams - violating this rule makes the encryption vulnerable to known-plaintext attacks.