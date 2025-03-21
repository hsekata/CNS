import json
import base64
from django.shortcuts import render
from django.http import JsonResponse
from .otp import generate_otp_key, otp_encrypt, otp_decrypt
from .des3 import generate_des3_key, des3_encrypt, des3_decrypt
from .aes import generate_aes_key, aes_encrypt, aes_decrypt

encryption_managers = {}

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
    
    session_key = request.session.session_key
    if session_key not in encryption_managers:
        encryption_managers[session_key] = EncryptionManager(session_key)
    encryption_manager = encryption_managers[session_key]

    data = json.loads(request.body)
    algorithm = data.get('algorithm')
    plaintext = data.get('plainOrCipherText')

    if algorithm == 'OTP':
        key = generate_otp_key(len(plaintext))
        ciphertext = otp_encrypt(plaintext, key)
        key_base64 = base64.b64encode(key).decode('utf-8')
        request.session["otp_key"] = key_base64

    elif algorithm == '3DES':
        key = generate_des3_key()
        ciphertext, pad_len = des3_encrypt(plaintext, key)
        request.session["des3_key"] = base64.b64encode(key).decode('utf-8')
        request.session["pad_len"] = pad_len
    elif algorithm == 'AES':
        try:
            ciphertext = encryption_manager.encrypt(plaintext)
        except ValueError as e:
            return JsonResponse({'error': f"Invalid key for AES: {str(e)}"}, status=400)

    return JsonResponse({'ciphertext': ciphertext.hex()})

def decrypt(request):
    if not request.session.session_key:
        return JsonResponse({'error': 'Session not initialized'}, status=400)
    
    session_key = request.session.session_key
    if session_key not in encryption_managers:
        return JsonResponse({'error': 'No encryption manager found for this session'}, status=404)
    encryption_manager = encryption_managers[session_key]

    data = json.loads(request.body)
    algorithm = data.get('algorithm')
    ciphertext = bytes.fromhex(data.get('plainOrCipherText')) 
    if algorithm == 'OTP':
        key = base64.b64decode(request.session["otp_key"])  
        plaintext = otp_decrypt(ciphertext, key)

    elif algorithm == '3DES':
        pad_len = request.session.get("pad_len")
        key = base64.b64decode(request.session.get("des3_key", ""))
        plaintext = des3_decrypt(ciphertext, key, pad_len)

    elif algorithm == 'AES':
        try:
            plaintext = encryption_manager.decrypt(ciphertext)
        except ValueError as e:
            return JsonResponse({'error': f"Invalid key for AES decryption: {str(e)}"}, status=400)

    if isinstance(plaintext, bytes):
        plaintext = base64.b64encode(plaintext).decode('utf-8') 

    return JsonResponse({'plaintext': plaintext})
