# encryption.py
import hashlib
import base64
from typing import Union
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ---------- helpers ----------
def _normalize_key_to_bytes(quantum_key: Union[str, bytes, tuple, None]) -> bytes:
    """
    Convert various shapes of quantum_key to raw bytes.
    Accepts:
      - tuple like ('hexstring',) or (b'rawbytes',)
      - bytes
      - hex string (will be interpreted as hex)
      - plain string (utf-8)
    Raises TypeError/ValueError on unsupported shapes.
    """
    if quantum_key is None:
        raise ValueError("quantum_key is None")

    # If DB returned a tuple (common with cursor.fetchone())
    if isinstance(quantum_key, tuple):
        if len(quantum_key) == 0:
            raise ValueError("Empty tuple for quantum_key")
        quantum_key = quantum_key[0]

    # If bytes already, use as-is
    if isinstance(quantum_key, (bytes, bytearray)):
        return bytes(quantum_key)

    # If str, try hex first, then fallback to utf-8 bytes
    if isinstance(quantum_key, str):
        # strip common whitespace/newline
        s = quantum_key.strip()
        # try hex
        try:
            return bytes.fromhex(s)
        except ValueError:
            # not hex, try base64 decode (some key providers return base64)
            try:
                return base64.b64decode(s)
            except Exception:
                # fallback to raw utf-8 bytes
                return s.encode('utf-8')

    raise TypeError(f"Unsupported quantum_key type: {type(quantum_key)}")


def _normalize_ciphertext(ct_obj: Union[str, bytes, bytearray]) -> bytes:
    """
    Normalize ciphertext to raw bytes.
    Accepts:
      - bytes
      - hex string
      - base64 (standard or urlsafe) string
      - plain string (will be encoded to utf-8 as last resort)
    """
    if ct_obj is None:
        raise ValueError("ciphertext is None")

    if isinstance(ct_obj, (bytes, bytearray)):
        return bytes(ct_obj)

    if isinstance(ct_obj, str):
        s = ct_obj.strip()
        # try hex
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
        # try base64 (urlsafe then standard)
        try:
            return base64.urlsafe_b64decode(s + '===')
        except Exception:
            try:
                return base64.b64decode(s + '===')
            except Exception:
                # fallback to utf-8 raw bytes
                return s.encode('utf-8')

    raise TypeError(f"Unsupported ciphertext type: {type(ct_obj)}")


# ---------- AES (quantum) ----------
def quantum_aes_encrypt(data: Union[str, bytes], quantum_key: Union[str, bytes, tuple]) -> bytes:
    """
    Encrypt data using AES-CBC. Returns raw bytes: IV(16) + ciphertext.
    quantum_key can be tuple/bytes/hex/str; it'll be normalized.
    """
    key_bytes = _normalize_key_to_bytes(quantum_key)
    aes_key = hashlib.sha256(key_bytes).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC)
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode('utf-8')
    padded = pad(data, AES.block_size)
    ct = cipher.encrypt(padded)
    return cipher.iv + ct


def quantum_aes_decrypt(ciphertext: Union[str, bytes], quantum_key: Union[str, bytes, tuple], is_text: bool = True) -> Union[str, bytes]:
    """
    Decrypt AES-CBC data where input format is IV(16) || ciphertext.
    Accepts hex/base64/bytes/str for ciphertext and returns utf-8 string (is_text=True)
    or raw bytes (is_text=False).
    Raises informative errors on invalid inputs (e.g. incorrect IV length).
    """
    key_bytes = _normalize_key_to_bytes(quantum_key)
    aes_key = hashlib.sha256(key_bytes).digest()

    raw = _normalize_ciphertext(ciphertext)

    if len(raw) < 16:
        raise ValueError(f"Ciphertext too short to contain IV + payload (len={len(raw)})")

    iv = raw[:16]
    if len(iv) != 16:
        raise ValueError(f"Incorrect IV length (it must be 16 bytes long), got {len(iv)}")

    ct_body = raw[16:]
    if len(ct_body) == 0:
        raise ValueError("Ciphertext body is empty after extracting IV")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ct_body)

    # Unpad and validate
    try:
        data = unpad(padded, AES.block_size)
    except ValueError as e:
        # likely wrong key or corrupted ciphertext
        raise ValueError(f"Unpadding failed after decrypt (possible wrong key or corrupted ciphertext): {e}")

    if is_text:
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.decode('utf-8', errors='replace')
    return data


# ---------- OTP (XOR) ----------
def otp_encrypt(data: Union[str, bytes], quantum_key: Union[str, bytes, tuple]) -> bytes:
    """
    One-time pad using SHAKE-256 to expand the quantum key deterministically.
    Returns raw bytes (XOR output). Accepts str or bytes for data.
    """
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode('utf-8')
    key_bytes = _normalize_key_to_bytes(quantum_key)
    shake = hashlib.shake_256()
    shake.update(key_bytes)
    pad_bytes = shake.digest(len(data))
    return bytes(a ^ b for a, b in zip(data, pad_bytes))


def otp_decrypt(ciphertext: Union[str, bytes], quantum_key: Union[str, bytes, tuple], is_text: bool = True) -> Union[str, bytes]:
    """
    OTP decryption is same as encryption (XOR). Accepts hex strings as ciphertext too.
    """
    if isinstance(ciphertext, str):
        # try hex then base64 then utf-8 fallback
        try:
            ciphertext = bytes.fromhex(ciphertext)
        except ValueError:
            try:
                ciphertext = base64.b64decode(ciphertext)
            except Exception:
                ciphertext = ciphertext.encode('utf-8')

    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes or hex/base64/str")

    key_bytes = _normalize_key_to_bytes(quantum_key)
    shake = hashlib.shake_256()
    shake.update(key_bytes)
    pad_bytes = shake.digest(len(ciphertext))
    decrypted = bytes(a ^ b for a, b in zip(ciphertext, pad_bytes))

    if is_text:
        try:
            return decrypted.decode('utf-8')
        except UnicodeDecodeError:
            return decrypted.decode('utf-8', errors='replace')
    return decrypted
