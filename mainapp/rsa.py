from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os
import json
import base64
RSA_KEY_DIR = os.path.dirname(os.path.abspath(__file__))

def load_public_key():
    key_path = os.path.join(RSA_KEY_DIR, 'public_key.pem')
    if not os.path.exists(key_path):
        print(f"Public key file not found at {key_path}")
        raise FileNotFoundError(f"Public key file not found at {key_path}")
    try:
        with open(key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            print(f"Successfully loaded public key from {key_path}")
            return public_key
    except Exception as e:
        print(f"Error loading public key: {str(e)}")
        raise

def load_private_key():
    key_path = os.path.join(RSA_KEY_DIR, 'private_key.pem')
    if not os.path.exists(key_path):
        print(f"Private key file not found at {key_path}")
        raise FileNotFoundError(f"Private key file not found at {key_path}")
    try:
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            print(f"Successfully loaded private key from {key_path}")
            return private_key
    except Exception as e:
        print(f"Error loading private key: {str(e)}")
        raise

def rsa_encrypt(plaintext):
    try:
        public_key = load_public_key()
        ciphertext = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        print(f"Encrypted '{plaintext}' to '{ciphertext_b64}'")
        return ciphertext_b64
    except Exception as e:
        print(f"RSA encryption failed: {str(e)}")
        raise

def rsa_decrypt(ciphertext_b64):
    try:
        private_key = load_private_key()
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        plaintext_str = plaintext.decode('utf-8')
        # print(f"Decrypted '{ciphertext_b64}' to '{plaintext_str}'")
        return plaintext_str
    except base64.binascii.Error as e:
        
        raise ValueError(f"Invalid base64 input: {str(e)}")
    except ValueError as e:
        
        raise ValueError(f"Decryption error: {str(e)}")
    except Exception as e:
        
        raise
