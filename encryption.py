from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def quantum_aes_encrypt(data, quantum_key):
    """Encrypt data using AES with a quantum key as the seed."""
    aes_key = hashlib.sha256(quantum_key.encode()).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC)
    if not isinstance(data, bytes):
        data = data.encode()
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return cipher.iv + ciphertext

def quantum_aes_decrypt(ciphertext, quantum_key):
    """Decrypt AES-encrypted data."""
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    aes_key = hashlib.sha256(quantum_key.encode()).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded_data = cipher.decrypt(actual_ciphertext)
    return unpad(padded_data, AES.block_size)

def otp_encrypt(data, quantum_key):
    """Encrypt data using One-Time Pad with a quantum key (using SHAKE for expansion)."""
    if not isinstance(data, bytes):
        data = data.encode()
    shake = hashlib.shake_256()
    shake.update(quantum_key.encode())
    pad = shake.digest(len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, pad))
    return ciphertext

def otp_decrypt(ciphertext, quantum_key):
    """Decrypt OTP-encrypted data (same as encrypt due to XOR)."""
    if not isinstance(ciphertext, bytes):
        ciphertext = ciphertext.encode()
    shake = hashlib.shake_256()
    shake.update(quantum_key.encode())
    pad = shake.digest(len(ciphertext))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, pad))
    return plaintext