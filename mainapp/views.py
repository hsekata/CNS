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
from .rsa import rsa_decrypt, rsa_encrypt, load_private_key, load_public_key
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
            plaintext = manager.decrypt(base64.b64decode(ciphertext))
            return JsonResponse({'plaintext': plaintext.decode('utf-8')})

        elif algorithm == 'RSA':
            plaintext = rsa_decrypt(ciphertext)
            return JsonResponse({'plaintext': plaintext})

        return JsonResponse({'error': 'Unsupported algorithm'}, status=400)

    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return JsonResponse({'error': f"Decryption failed: {str(e)}"}, status=400)