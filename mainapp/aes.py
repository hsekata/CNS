
from cryptography.fernet import Fernet

def generate_aes_key():
    return Fernet.generate_key()

def aes_encrypt(plaintext, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(plaintext.encode())

def aes_decrypt(ciphertext, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(ciphertext).decode()