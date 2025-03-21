from Crypto.Cipher import DES3
import base64
import os

def generate_des3_key():
    return DES3.adjust_key_parity(os.urandom(24))

def des3_encrypt(plaintext, key):
    iv = os.urandom(8)
    cipher = DES3.new(key, DES3.MODE_CBC,iv)
    pad_len = 8 - (len(plaintext) % 8)
    plaintext += chr(pad_len) * pad_len 
    ciphertext = cipher.encrypt(plaintext.encode())
    return iv+ciphertext, pad_len
def des3_decrypt(ciphertext, key, pad_len):
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    print(f" plain text is {plaintext} !!!!!!!!!!")   
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding detected")

    plaintext = plaintext[:-pad_len]

    try:
        return plaintext.decode('utf-8')  
    except UnicodeDecodeError:
        return base64.b64encode(plaintext).decode('utf-8')
