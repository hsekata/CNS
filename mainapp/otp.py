import os
import base64

def generate_otp_key(length):
    return os.urandom(length)

def otp_encrypt(plaintext, key):
    return bytes([p ^ k for p, k in zip(plaintext.encode(), key)])

def otp_decrypt(ciphertext, key):
    var = bytes([c ^ k for c, k in zip(ciphertext, key)])
    print(f"Decrypted bytes: {var}")
    try:
        return var.decode('utf-8')  
    except UnicodeDecodeError:
        return base64.b64encode(var).decode('utf-8')
