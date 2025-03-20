from Crypto.Cipher import DES3
import base64
import os

def generate_des3_key():
    return DES3.adjust_key_parity(os.urandom(24))

def des3_encrypt(plaintext, key):
    cipher = DES3.new(key, DES3.MODE_ECB)

    pad_len = 8 - (len(plaintext) % 8)
    plaintext += chr(pad_len) * pad_len  

    return cipher.encrypt(plaintext.encode())

def des3_decrypt(ciphertext, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)

    pad_len = plaintext[-1] 
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding detected")
    
    plaintext = plaintext[:-pad_len]

    try:
        return plaintext.decode('utf-8')  
    except UnicodeDecodeError:
        return base64.b64encode(plaintext).decode('utf-8')
