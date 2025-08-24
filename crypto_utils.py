# crypto_utils.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256

# --- Level 2: Quantum-Aided AES ---

def encrypt_aes(plaintext_bytes, quantum_key):
    """
    Encrypts plaintext using AES-GCM. The quantum key is used as a seed
    to derive a secure 256-bit AES key.
    """
    # Use SHA-256 to derive a 32-byte (256-bit) key from the quantum key
    aes_key = sha256(quantum_key).digest()
    aesgcm = AESGCM(aes_key)
    
    # A nonce (number used once) is required for GCM mode. 12 bytes is standard.
    nonce = os.urandom(12)
    
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    return ciphertext, nonce

def decrypt_aes(ciphertext, nonce, quantum_key):
    """Decrypts AES-GCM ciphertext."""
    try:
        aes_key = sha256(quantum_key).digest()
        aesgcm = AESGCM(aes_key)
        
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes
    except Exception as e:
        print(f"AES decryption failed: {e}")
        return None

# --- Level 3: Hybrid OTP + AES ---

def encrypt_hybrid_otp(plaintext_bytes, quantum_key):
    """
    Encrypts large data using a hybrid OTP + AES scheme.
    1. A new random AES key (session key) is generated.
    2. The session key is encrypted with the quantum OTP key.
    3. The plaintext data is encrypted with the session key using AES-GCM.
    """
    if len(quantum_key) < 32:
        raise ValueError("Quantum key must be at least 32 bytes for hybrid encryption.")
    
    # 1. Generate a new 32-byte (256-bit) AES key for this session
    session_key = os.urandom(32)
    
    # 2. Encrypt the session key with the first 32 bytes of the quantum key
    otp_part_of_key = quantum_key[:32]
    encrypted_session_key = bytes([s ^ k for s, k in zip(session_key, otp_part_of_key)])

    # 3. Encrypt the actual data using the (unencrypted) session key
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    return ciphertext, nonce, encrypted_session_key


def decrypt_hybrid_otp(ciphertext, nonce, encrypted_session_key, quantum_key):
    """Decrypts data encrypted with the hybrid OTP + AES scheme."""
    try:
        # 1. Decrypt the session key using the quantum key
        otp_part_of_key = quantum_key[:32]
        session_key = bytes([s ^ k for s, k in zip(encrypted_session_key, otp_part_of_key)])
        
        # 2. Use the decrypted session key to decrypt the actual data
        aesgcm = AESGCM(session_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes
    except Exception as e:
        print(f"Hybrid OTP decryption failed: {e}")
        return None