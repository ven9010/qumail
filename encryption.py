from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def quantum_aes_encrypt(data, quantum_key):
    """Encrypt data using AES with a quantum key as the seed."""
    aes_key = hashlib.sha256(quantum_key.encode()).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC)
    padded_data = pad(data.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return cipher.iv + ciphertext

def quantum_aes_decrypt(ciphertext, quantum_key):
    """Decrypt AES-encrypted data."""
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    aes_key = hashlib.sha256(quantum_key.encode()).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded_data = cipher.decrypt(actual_ciphertext)
    return unpad(padded_data, AES.block_size).decode()

def otp_encrypt(data, quantum_key):
    """Encrypt data using One-Time Pad with a quantum key."""
    if len(quantum_key) < len(data):
        raise ValueError("Quantum key must be at least as long as the data")
    ciphertext = bytes(a ^ b for a, b in zip(data.encode(), quantum_key))
    return ciphertext

def otp_decrypt(ciphertext, quantum_key):
    """Decrypt OTP-encrypted data (same as encrypt due to XOR)."""
    if len(quantum_key) < len(ciphertext):
        raise ValueError("Quantum key must be at least as long as the ciphertext")
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, quantum_key))
    return plaintext.decode()