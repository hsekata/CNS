import os
import json
import base64
from django.shortcuts import render
from django.http import JsonResponse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from .otp import generate_otp_key, otp_encrypt, otp_decrypt
from .des3 import generate_des3_key, des3_encrypt, des3_decrypt
from .aes import generate_aes_key, aes_encrypt, aes_decrypt

# Store encryption manager per session
encryption_managers = {}

# AES session-based encryption manager
class EncryptionManager:
    def __init__(self, session_key):
        self.session_key = session_key
        self._key = generate_aes_key()
        print(f"Generated AES key for session {self.session_key}: {self._key}")

    def get_key(self):
        return self._key

    def encrypt(self, plaintext):
        return aes_encrypt(plaintext, self._key)

    def decrypt(self, ciphertext):
        return aes_decrypt(ciphertext, self._key)

# RSA key management
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

# Views
def index(request):
    if not request.session.session_key:
        request.session.create()
    
    session_key = request.session.session_key
    if session_key not in encryption_managers:
        encryption_managers[session_key] = EncryptionManager(session_key)
    
    return render(request, 'mainapp/index.html')

def encrypt(request):
    if not request.session.session_key:
        return JsonResponse({'error': 'Session not initialized'}, status=400)
    
    try:
        data = json.loads(request.body)
        algorithm = data.get('algorithm')
        plaintext = data.get('plainOrCipherText', '')

        if algorithm == 'OTP':
            key = generate_otp_key(len(plaintext))
            ciphertext = otp_encrypt(plaintext, key)
            request.session["otp_key"] = base64.b64encode(key).decode('utf-8')
            return JsonResponse({'ciphertext': base64.b64encode(ciphertext).decode('utf-8')})

        elif algorithm == '3DES':
            key = generate_des3_key()
            ciphertext, pad_len = des3_encrypt(plaintext, key)
            request.session["des3_key"] = base64.b64encode(key).decode('utf-8')
            request.session["pad_len"] = pad_len
            return JsonResponse({'ciphertext': base64.b64encode(ciphertext).decode('utf-8')})

        elif algorithm == 'AES':
            manager = encryption_managers[request.session.session_key]
            ciphertext = manager.encrypt(plaintext)
            return JsonResponse({'ciphertext': base64.b64encode(ciphertext).decode('utf-8')})

        elif algorithm == 'RSA':
            ciphertext = rsa_encrypt(plaintext)
            return JsonResponse({'ciphertext': ciphertext})

        return JsonResponse({'error': 'Unsupported algorithm'}, status=400)

    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return JsonResponse({'error': f"Encryption failed: {str(e)}"}, status=400)

def decrypt(request):
    if not request.session.session_key:
        return JsonResponse({'error': 'Session not initialized'}, status=400)
    
    try:
        data = json.loads(request.body)
        algorithm = data.get('algorithm')
        ciphertext = data.get('plainOrCipherText', '')

        if algorithm == 'OTP':
            key = base64.b64decode(request.session.get("otp_key", ""))
            plaintext = otp_decrypt(base64.b64decode(ciphertext), key)
            return JsonResponse({'plaintext': plaintext})

        elif algorithm == '3DES':
            key = base64.b64decode(request.session.get("des3_key", ""))
            pad_len = request.session.get("pad_len", 0)
            plaintext = des3_decrypt(base64.b64decode(ciphertext), key, pad_len)
            return JsonResponse({'plaintext': plaintext})

        elif algorithm == 'AES':
            manager = encryption_managers[request.session.session_key]
            plaintext = manager.aes_decrypt(base64.b64decode(ciphertext))
            return JsonResponse({'plaintext': plaintext.decode('utf-8')})

        elif algorithm == 'RSA':
            plaintext = rsa_decrypt(ciphertext)
            return JsonResponse({'plaintext': plaintext})

        return JsonResponse({'error': 'Unsupported algorithm'}, status=400)

    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return JsonResponse({'error': f"Decryption failed: {str(e)}"}, status=400)