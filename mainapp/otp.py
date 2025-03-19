
import os

def generate_otp_key(length):
    return os.urandom(length)

def otp_encrypt(plaintext, key):
    return bytes([p ^ k for p, k in zip(plaintext.encode(), key)])

def otp_decrypt(ciphertext, key):
    return bytes([c ^ k for c, k in zip(ciphertext, key)]).decode()