#!/usr/bin/env python3
"""
Clapped
A Python implementation of a ChaCha20-like stream cipher with a subtle backdoor.

The backdoor: When encrypting messages longer than 64 bytes, the keystream
generation uses negative indexing that wraps around, causing later blocks
to leak information about the key through predictable patterns.
"""

import os
import socketserver
import threading
from base64 import b64encode, b64decode

def rotl(a, b):
    """Rotate left"""
    return ((a << b) | (a >> (32 - b))) & 0xffffffff

def quarter_round(state, a, b, c, d):
    """ChaCha quarter round"""
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = rotl(state[d], 16)
    
    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = rotl(state[b], 12)
    
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = rotl(state[d], 8)
    
    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = rotl(state[b], 7)

def chacha_block(key, nonce, counter):
    """Generate a ChaCha20 block"""
    # Constants: "expand 32-byte k"
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    
    # Convert key bytes to 32-bit words
    key_words = [int.from_bytes(key[i:i+4], 'little') for i in range(0, 32, 4)]
    
    # Convert nonce bytes to 32-bit words
    nonce_words = [int.from_bytes(nonce[i:i+4], 'little') for i in range(0, 12, 4)]
    
    # Initial state
    state = (
        constants +
        key_words +
        [counter] +
        nonce_words
    )
    
    working_state = state[:]
    
    # 20 rounds (10 double rounds)
    for _ in range(10):
        # Column rounds
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        
        # Diagonal rounds
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)
    
    # Add original state
    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xffffffff
    
    # Convert back to bytes
    keystream = b''.join(w.to_bytes(4, 'little') for w in working_state)
    return keystream

class UnderhandedStreamCipher:
    def __init__(self, key):
        assert len(key) == 32, "Key must be 32 bytes"
        self.key = key
    
    def encrypt(self, plaintext, nonce=None):
        """
        Encrypt plaintext with the stream cipher.
        
        THE BACKDOOR: When generating keystream blocks, we use negative
        indexing for the counter in a way that causes it to wrap around
        and reuse earlier keystream material in a predictable pattern.
        
        This only affects messages longer than 64 bytes, so short test
        cases pass, but longer messages leak key information.
        """
        if nonce is None:
            nonce = b'\x00' * 12
        
        assert len(nonce) == 12, "Nonce must be 12 bytes"
        
        ciphertext = bytearray()
        blocks_needed = (len(plaintext) + 63) // 64
        
        for block_num in range(blocks_needed):
            # THE BACKDOOR: This looks innocent but uses negative indexing!
            # For block 0: counter = 0
            # For block 1: counter = 1  
            # For block 2+: counter wraps due to the [-64] causing predictable reuse
            keystream = chacha_block(
                self.key,
                nonce,
                block_num if block_num < 2 else block_num + (-64)  # BACKDOOR HERE!
            )
            
            start = block_num * 64
            end = min(start + 64, len(plaintext))
            
            for i in range(start, end):
                ciphertext.append(plaintext[i] ^ keystream[i - start])
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext, nonce=None):
        """Decrypt ciphertext (XOR is symmetric)"""
        return self.encrypt(ciphertext, nonce)


# CTF Challenge Server Configuration
FLAG = "shunya{m@ha_ch@l!3nge}"
SECRET_KEY = os.urandom(32)  # Generate a random key for each server instance
CIPHER = UnderhandedStreamCipher(SECRET_KEY)

class ChallengeTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"=== Clapped ===\n")
        
        while True:
            self.request.sendall(b"\nMenu:\n")
            self.request.sendall(b"1. Encrypt a message\n")
            self.request.sendall(b"2. Get encrypted flag\n")
            self.request.sendall(b"3. Exit\n")
            self.request.sendall(b"\nChoice: ")
            
            try:
                choice = self.request.recv(1024).strip()
                if not choice:
                    break
                    
                if choice == b"1":
                    self.request.sendall(b"Enter message to encrypt (base64 encoded): ")
                    message_data = self.request.recv(8192).strip()
                    
                    try:
                        message = b64decode(message_data)
                        ciphertext = CIPHER.encrypt(message)
                        self.request.sendall(b"Encrypted: " + b64encode(ciphertext) + b"\n")
                    except Exception as e:
                        self.request.sendall(f"Error: {str(e)}\n".encode())
                
                elif choice == b"2":
                    encrypted_flag = CIPHER.encrypt(FLAG.encode())
                    self.request.sendall(b"Encrypted flag: " + b64encode(encrypted_flag) + b"\n")
                
                elif choice == b"3":
                    self.request.sendall(b"Goodbye!\n")
                    break
                
                else:
                    self.request.sendall(b"Invalid choice. Please try again.\n")
                    
            except Exception as e:
                self.request.sendall(f"Error: {str(e)}\n".encode())
                break


def run_server(host="0.0.0.0", port=1337):
    print(f"Starting Underhanded Stream Cipher Challenge server on {host}:{port}")
    print(f"Flag: {FLAG}")
    
    server = socketserver.ThreadingTCPServer((host, port), ChallengeTCPHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    print("Server started. Press Ctrl+C to stop.")
    
    try:
        server_thread.join()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    run_server()