"""
crypto.py — Fernet (AES-128-CBC + HMAC-SHA256) file encryption.
Imports: only 'cryptography' and standard library.
"""
import os
from cryptography.fernet import Fernet

_KEY_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "database_files", "fernet.key")
)


def ensure_key():
    """Generate and save a Fernet key if one does not exist yet."""
    os.makedirs(os.path.dirname(_KEY_PATH), exist_ok=True)
    if not os.path.exists(_KEY_PATH):
        key = Fernet.generate_key()
        with open(_KEY_PATH, "wb") as f:
            f.write(key)
        print("[CRYPTO] New Fernet key generated.")


def _load_key() -> bytes:
    ensure_key()
    with open(_KEY_PATH, "rb") as f:
        return f.read()


def encrypt_bytes(data: bytes) -> bytes:
    """Encrypt raw bytes and return ciphertext."""
    return Fernet(_load_key()).encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    """Decrypt ciphertext and return original bytes.
    Raises cryptography.fernet.InvalidToken if tampered."""
    return Fernet(_load_key()).decrypt(data)
