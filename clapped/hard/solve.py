#!/usr/bin/env python3
# filepath: /Users/grass/projects/CTF-Challenges/clapped/hard/solve.py

import socket
import sys
from base64 import b64encode, b64decode

class RemoteCipherOracle:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        # Drain initial welcome message
        data = b""
        while not data.endswith(b"Choice: "):
            chunk = self.sock.recv(1)
            if not chunk:
                raise Exception("Connection closed")
            data += chunk
        
    def encrypt(self, plaintext, nonce=None):
        # Option 1: Encrypt a message
        self.sock.sendall(b"1\n")
        self._recv_until(b": ")  # Wait for prompt
        
        # Send plaintext (base64 encoded)
        self.sock.sendall(b64encode(plaintext) + b"\n")
        response = self._recv_until(b"\n")
        
        # Parse response
        prefix = b"Encrypted: "
        if response.startswith(prefix):
            encrypted = b64decode(response[len(prefix):])
            # Drain until next menu
            self._drain_until_menu()
            return encrypted
        else:
            raise Exception(f"Unexpected response: {response}")
    
    def get_encrypted_flag(self):
        # Option 2: Get encrypted flag
        self.sock.sendall(b"2\n")
        response = self._recv_until(b"\n")
        
        # Parse response
        prefix = b"Encrypted flag: "
        if response.startswith(prefix):
            encrypted = b64decode(response[len(prefix):])
            # Drain until next menu
            self._drain_until_menu()
            return encrypted
        else:
            raise Exception(f"Unexpected response: {response}")
    
    def close(self):
        # Option 3: Exit
        try:
            self.sock.sendall(b"3\n")
            self.sock.close()
        except:
            pass
    
    def _recv_until(self, delimiter):
        buffer = b""
        while not buffer.endswith(delimiter):
            data = self.sock.recv(1)
            if not data:
                raise Exception("Connection closed")
            buffer += data
        return buffer[:-len(delimiter)]
    
    def _drain_until_menu(self):
        """Drain socket until we see the menu prompt again"""
        data = b""
        while not data.endswith(b"Choice: "):
            chunk = self.sock.recv(1)
            if not chunk:
                return
            data += chunk

class Exploit:
    def __init__(self, oracle):
        self.oracle = oracle
        self.recovered_keystream = {}
        self.nonce = None  # Default nonce
    
    def recover_keystream_blocks(self, num_blocks=5):
        """Recover keystream blocks using known plaintext"""
        print("Recovering keystream blocks...")
        
        # Encrypt a message of all zeros to get raw keystream
        plaintext = b'\x00' * (num_blocks * 64)
        ciphertext = self.oracle.encrypt(plaintext)
        
        # Extract keystream blocks
        for block_num in range(num_blocks):
            start = block_num * 64
            end = start + 64
            if end <= len(ciphertext):
                self.recovered_keystream[block_num] = ciphertext[start:end]
                print(f"  Block {block_num}: {self.recovered_keystream[block_num][:16].hex()}...")
        
        return self.recovered_keystream
    
    def decrypt_message(self, ciphertext):
        """Decrypt a message using recovered keystream"""
        print("Decrypting message...")
        
        plaintext = bytearray()
        blocks_needed = (len(ciphertext) + 63) // 64
        
        for block_num in range(blocks_needed):
            # The backdoor reuses block 2 for all blocks ≥ 2
            effective_block = min(block_num, 2)
            
            if effective_block not in self.recovered_keystream:
                raise ValueError(f"Block {effective_block} not in recovered keystream")
            
            keystream = self.recovered_keystream[effective_block]
            start = block_num * 64
            end = min(start + 64, len(ciphertext))
            
            for i in range(start, end):
                plaintext.append(ciphertext[i] ^ keystream[i - start])
        
        return bytes(plaintext)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    print(f"Connecting to {host}:{port}...")
    
    # Connect to the server
    oracle = RemoteCipherOracle(host, port)
    oracle.connect()
    
    # Create exploit instance
    exploit = Exploit(oracle)
    
    try:
        # Step 1: Recover keystream blocks
        exploit.recover_keystream_blocks(5)  # Recover 5 blocks
        
        # Step 2: Get the encrypted flag
        encrypted_flag = oracle.get_encrypted_flag()
        print(f"Encrypted flag: {encrypted_flag.hex()}")
        
        # Step 3: Decrypt the flag
        flag = exploit.decrypt_message(encrypted_flag)
        print(f"Flag: {flag.decode()}")
        
    finally:
        oracle.close()

if __name__ == "__main__":
    main()