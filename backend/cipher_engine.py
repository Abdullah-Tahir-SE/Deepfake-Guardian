import hashlib

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _normalize_key(key):
    if isinstance(key, bytes):
        return key
    return str(key).encode("utf-8")


def _to_bytes(text_or_bytes):
    if isinstance(text_or_bytes, bytes):
        return text_or_bytes
    return str(text_or_bytes).encode("utf-8")


def _derive_des_key_iv(key):
    raw = hashlib.sha256(_normalize_key(key)).digest()
    des_key = raw[:8]
    iv = raw[8:16]
    return des_key, iv


def _derive_aes_key_iv(key):
    raw = hashlib.sha256(_normalize_key(key)).digest()
    aes_key = raw  # 32 bytes => AES-256
    iv = hashlib.sha256(_normalize_key(key) + b"_iv").digest()[:16]
    return aes_key, iv


def caesar_encrypt(text_or_bytes, key):
    shift = int(key) % 256
    data = _to_bytes(text_or_bytes)
    return bytes((b + shift) % 256 for b in data)


def caesar_decrypt(text_or_bytes, key):
    shift = int(key) % 256
    data = _to_bytes(text_or_bytes)
    return bytes((b - shift) % 256 for b in data)


def vigenere_encrypt(text_or_bytes, key):
    data = _to_bytes(text_or_bytes)
    key_bytes = _normalize_key(key)
    if not key_bytes:
        raise ValueError("Vigenere key cannot be empty")
    out = bytearray()
    for i, byte in enumerate(data):
        out.append((byte + key_bytes[i % len(key_bytes)]) % 256)
    return bytes(out)


def vigenere_decrypt(text_or_bytes, key):
    data = _to_bytes(text_or_bytes)
    key_bytes = _normalize_key(key)
    if not key_bytes:
        raise ValueError("Vigenere key cannot be empty")
    out = bytearray()
    for i, byte in enumerate(data):
        out.append((byte - key_bytes[i % len(key_bytes)]) % 256)
    return bytes(out)


def stream_encrypt(text_or_bytes, key):
    data = _to_bytes(text_or_bytes)
    key_stream = hashlib.sha256(_normalize_key(key)).digest()
    out = bytearray()
    for i, byte in enumerate(data):
        out.append(byte ^ key_stream[i % len(key_stream)])
    return bytes(out)


def stream_decrypt(text_or_bytes, key):
    return stream_encrypt(text_or_bytes, key)


def des_encrypt(text_or_bytes, key):
    data = _to_bytes(text_or_bytes)
    des_key, iv = _derive_des_key_iv(key)
    padder = padding.PKCS7(64).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.TripleDES(des_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def des_decrypt(text_or_bytes, key):
    data = _to_bytes(text_or_bytes)
    des_key, iv = _derive_des_key_iv(key)
    cipher = Cipher(algorithms.TripleDES(des_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes_encrypt(text_or_bytes, key):
    data = _to_bytes(text_or_bytes)
    aes_key, iv = _derive_aes_key_iv(key)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(text_or_bytes, key):
    data = _to_bytes(text_or_bytes)
    aes_key, iv = _derive_aes_key_iv(key)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()
