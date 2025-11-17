import socket
import threading
import sys
import secrets

# ============= RSA Implementation for Key Exchange =============
class RSA:
    """Simple RSA implementation for key exchange"""
    
    @staticmethod
    def encrypt(plaintext, public_key):
        """Encrypt integer with RSA public key"""
        e, n = public_key
        return pow(plaintext, e, n)


# ============= DES Implementation (Original) =============
class DES:
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]
    
    FP = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]
    
    E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
    
    S_BOXES = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 0, 5],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 15, 3, 12, 0],
         [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]
    
    P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
    
    PC1 = [57, 49, 41, 33, 25, 17, 9, 1,
           58, 50, 42, 34, 26, 18, 10, 2,
           59, 51, 43, 35, 27, 19, 11, 3,
           60, 52, 44, 36, 63, 55, 47, 39,
           31, 23, 15, 7, 62, 54, 46, 38,
           30, 22, 14, 6, 61, 53, 45, 37,
           29, 21, 13, 5, 28, 20, 12, 4]
    
    PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
           15, 6, 21, 10, 23, 19, 12, 4,
           26, 8, 16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55, 30, 40,
           51, 45, 33, 48, 44, 49, 39, 56,
           34, 53, 46, 42, 50, 36, 29, 32]
    
    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    @staticmethod
    def permute(block, table):
        return [block[i - 1] for i in table]
    
    @staticmethod
    def xor(a, b):
        return [x ^ y for x, y in zip(a, b)]
    
    @staticmethod
    def sbox_lookup(block):
        output = []
        for i in range(8):
            row = (block[i * 6] << 1) | block[i * 6 + 5]
            col = (block[i * 6 + 1] << 3) | (block[i * 6 + 2] << 2) | \
                  (block[i * 6 + 3] << 1) | block[i * 6 + 4]
            val = DES.S_BOXES[i][row][col]
            output.extend([(val >> (3 - j)) & 1 for j in range(4)])
        return output
    
    @staticmethod
    def generate_subkeys(key):
        key_bits = [(key >> (63 - i)) & 1 for i in range(64)]
        key = DES.permute(key_bits, DES.PC1)
        c = key[:28]
        d = key[28:]
        subkeys = []
        for i in range(16):
            for _ in range(DES.SHIFTS[i]):
                c.append(c.pop(0))
                d.append(d.pop(0))
            cd = c + d
            subkey = DES.permute(cd, DES.PC2)
            subkeys.append(subkey)
        return subkeys
    
    @staticmethod
    def f_function(r, subkey):
        expanded = DES.permute(r, DES.E)
        xored = DES.xor(expanded, subkey)
        output = DES.sbox_lookup(xored)
        return DES.permute(output, DES.P)
    
    @staticmethod
    def encrypt_block(plaintext, key):
        subkeys = DES.generate_subkeys(key)
        text_bits = [(plaintext >> (63 - i)) & 1 for i in range(64)]
        text_bits = DES.permute(text_bits, DES.IP)
        l = text_bits[:32]
        r = text_bits[32:]
        for i in range(16):
            f_out = DES.f_function(r, subkeys[i])
            l, r = r, DES.xor(l, f_out)
        combined = r + l
        ciphertext_bits = DES.permute(combined, DES.FP)
        ciphertext = 0
        for bit in ciphertext_bits:
            ciphertext = (ciphertext << 1) | bit
        return ciphertext
    
    @staticmethod
    def decrypt_block(ciphertext, key):
        subkeys = DES.generate_subkeys(key)
        subkeys.reverse()
        text_bits = [(ciphertext >> (63 - i)) & 1 for i in range(64)]
        text_bits = DES.permute(text_bits, DES.IP)
        l = text_bits[:32]
        r = text_bits[32:]
        for i in range(16):
            f_out = DES.f_function(r, subkeys[i])
            l, r = r, DES.xor(l, f_out)
        combined = r + l
        plaintext_bits = DES.permute(combined, DES.FP)
        plaintext = 0
        for bit in plaintext_bits:
            plaintext = (plaintext << 1) | bit
        return plaintext
    
    @staticmethod
    def pad_plaintext(plaintext):
        padding_length = 8 - (len(plaintext) % 8)
        padding = bytes([padding_length] * padding_length)
        return plaintext + padding
    
    @staticmethod
    def unpad_plaintext(plaintext):
        padding_length = plaintext[-1]
        return plaintext[:-padding_length]
    
    @staticmethod
    def encrypt(plaintext, key):
        plaintext = DES.pad_plaintext(plaintext)
        ciphertext = bytearray()
        for i in range(len(plaintext) // 8):
            block = 0
            for j in range(8):
                block = (block << 8) | plaintext[i * 8 + j]
            encrypted_block = DES.encrypt_block(block, key)
            for j in range(8):
                ciphertext.append((encrypted_block >> (56 - j * 8)) & 0xFF)
        return bytes(ciphertext)
    
    @staticmethod
    def decrypt(ciphertext, key):
        plaintext = bytearray()
        for i in range(len(ciphertext) // 8):
            block = 0
            for j in range(8):
                block = (block << 8) | ciphertext[i * 8 + j]
            decrypted_block = DES.decrypt_block(block, key)
            for j in range(8):
                plaintext.append((decrypted_block >> (56 - j * 8)) & 0xFF)
        plaintext = DES.unpad_plaintext(plaintext)
        return bytes(plaintext)


class DESChatClient:
    def __init__(self, host, port, key=None):
        self.host = host
        self.port = port
        self.key = key  # Will be generated and exchanged via RSA if None
        self.socket = None
        self.running = False
        print(f"📱 Client initialized for {host}:{port}")
        
    def exchange_keys(self):
        """Perform RSA key exchange to establish DES secret key"""
        try:
            # Receive RSA public key from server
            length_data = self.socket.recv(4)
            key_length = int.from_bytes(length_data, byteorder='big')
            
            public_key_data = b''
            while len(public_key_data) < key_length:
                chunk = self.socket.recv(key_length - len(public_key_data))
                if not chunk:
                    raise Exception("Connection lost during key exchange")
                public_key_data += chunk
            
            # Parse RSA public key
            e_str, n_str = public_key_data.decode('utf-8').split(',')
            e = int(e_str)
            n = int(n_str)
            rsa_public_key = (e, n)
            
            print(f"📥 Received RSA public key from server")
            
            # Generate random DES key (64-bit)
            self.key = secrets.randbits(64)
            print(f"🔑 Generated DES secret key: {hex(self.key)}")
            
            # Encrypt DES key with RSA public key
            encrypted_des_key = RSA.encrypt(self.key, rsa_public_key)
            print(f"🔒 Encrypted DES key with RSA")
            
            # Send encrypted DES key to server
            encrypted_key_data = encrypted_des_key.to_bytes((encrypted_des_key.bit_length() + 7) // 8, byteorder='big')
            msg_length = len(encrypted_key_data).to_bytes(4, byteorder='big')
            self.socket.sendall(msg_length + encrypted_key_data)
            
            print(f"📤 Sent encrypted DES key to server")
            print(f"✅ Secure key exchange completed!")
            
            return True
            
        except Exception as e:
            print(f"❌ Key exchange failed: {e}")
            return False
        
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            print("=" * 60)
            print("📱 DES ENCRYPTED CHAT CLIENT")
            print("=" * 60)
            print(f"🔌 Connecting to {self.host}:{self.port}...")
            
            self.socket.connect((self.host, self.port))
            self.running = True
            
            print(f"✅ Connected to server!")
            
            # Perform RSA key exchange if no key provided
            if not self.key:
                print("=" * 60)
                if not self.exchange_keys():
                    print("❌ Failed to establish secure connection")
                    return
            else:
                print(f"🔑 DES Key: {hex(self.key)} (pre-shared)")
            
            print("=" * 60)
            print("💬 Chat started! Type your messages below:")
            print("=" * 60)
            
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            self.send_messages()
            
        except ConnectionRefusedError:
            print(f"❌ Connection refused. Make sure server is running on {self.host}:{self.port}")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            self.disconnect()
    
    def receive_messages(self):
        """Receive and decrypt messages from server"""
        while self.running:
            try:
                length_data = self.socket.recv(4)
                if not length_data:
                    break
                    
                msg_length = int.from_bytes(length_data, byteorder='big')
                
                encrypted = b''
                while len(encrypted) < msg_length:
                    chunk = self.socket.recv(msg_length - len(encrypted))
                    if not chunk:
                        break
                    encrypted += chunk
                
                if not encrypted:
                    break
                
                decrypted = DES.decrypt(encrypted, self.key)
                message = decrypted.decode('utf-8')
                
                print(f"\n📩 Server: {message}")
                print("You: ", end='', flush=True)
                
            except Exception as e:
                if self.running:
                    print(f"\n❌ Error receiving message: {e}")
                break
        
        print("\n🔴 Disconnected from server")
        self.running = False
    
    def send_messages(self):
        """Send encrypted messages to server"""
        try:
            while self.running:
                message = input("You: ")
                
                if message.lower() == '/quit':
                    print("👋 Closing connection...")
                    break
                
                if message.strip():
                    encrypted = DES.encrypt(message.encode('utf-8'), self.key)
                    
                    msg_length = len(encrypted).to_bytes(4, byteorder='big')
                    self.socket.sendall(msg_length + encrypted)
                    
        except KeyboardInterrupt:
            print("\n\n👋 Client closing...")
        except Exception as e:
            print(f"\n❌ Error sending message: {e}")
    
    def disconnect(self):
        """Disconnect from server"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("🛑 Client disconnected")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🔐 DES ENCRYPTED CHAT - CLIENT MODE")
    print("=" * 60)
    
    host = input("Enter server IP address (default localhost): ").strip()
    if not host:
        host = "localhost"
    
    port = input("Enter port (default 5555): ").strip()
    port = int(port) if port else 5555
    
    # Ask if user wants RSA key exchange or manual key
    mode = input("Use RSA key exchange? (Y/n): ").strip().lower()
    
    key = None
    if mode == 'n':
        key_input = input("Enter DES key in hex (default 133457799BBCDFF1): ").strip()
        key = int(key_input, 16) if key_input else 0x133457799BBCDFF1
    
    client = DESChatClient(host=host, port=port, key=key)
    
    try:
        client.connect()
    except KeyboardInterrupt:
        print("\n\n👋 Client interrupted by user")
        client.disconnect()