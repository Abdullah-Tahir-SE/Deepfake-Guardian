import os
import sqlite3
import time
import hashlib

from cipher_engine import (
    caesar_encrypt,
    caesar_decrypt,
    vigenere_encrypt,
    vigenere_decrypt,
    stream_encrypt,
    stream_decrypt,
    des_encrypt,
    des_decrypt,
    aes_encrypt,
    aes_decrypt,
)
from database_manager import DB_PATH


VAULT_DIR = os.path.join(os.path.dirname(__file__), "vault")


def _ensure_vault_dir():
    if not os.path.exists(VAULT_DIR):
        os.makedirs(VAULT_DIR)


def _encrypt_by_cipher(data, cipher_name, key):
    name = (cipher_name or "").lower()
    if name == "caesar":
        return caesar_encrypt(data, key)
    if name == "vigenere":
        return vigenere_encrypt(data, key)
    if name in ("stream", "xor", "stream-xor"):
        return stream_encrypt(data, key)
    if name == "des":
        return des_encrypt(data, key)
    if name in ("aes", "aes-256"):
        return aes_encrypt(data, key)
    if name in ("des+aes", "des-aes"):
        return aes_encrypt(des_encrypt(data, key), key)
    raise ValueError("Unsupported cipher")


def _decrypt_by_cipher(data, cipher_name, key):
    name = (cipher_name or "").lower()
    if name == "caesar":
        return caesar_decrypt(data, key)
    if name == "vigenere":
        return vigenere_decrypt(data, key)
    if name in ("stream", "xor", "stream-xor"):
        return stream_decrypt(data, key)
    if name == "des":
        return des_decrypt(data, key)
    if name in ("aes", "aes-256"):
        return aes_decrypt(data, key)
    if name in ("des+aes", "des-aes"):
        return des_decrypt(aes_decrypt(data, key), key)
    raise ValueError("Unsupported cipher")


def upload_file(file, cipher_name, key, user_id):
    _ensure_vault_dir()
    original_name = file.filename
    raw_data = file.read()
    encrypted_data = _encrypt_by_cipher(raw_data, cipher_name, key)

    token_input = f"{user_id}|{original_name}|{time.time()}".encode("utf-8")
    token = hashlib.sha256(token_input).hexdigest()[:20]
    stored_name = f"{user_id}_{token}.vault"
    file_path = os.path.join(VAULT_DIR, stored_name)

    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO vault_files (user_id, original_name, stored_name, cipher_name, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (str(user_id), original_name, stored_name, cipher_name, time.time()),
    )
    conn.commit()
    conn.close()

    return {
        "stored_name": stored_name,
        "original_name": original_name,
        "cipher_name": cipher_name,
    }


def download_file(filename, cipher_name, key, user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT original_name, stored_name, cipher_name
        FROM vault_files
        WHERE stored_name = ? AND user_id = ?
        """,
        (filename, str(user_id)),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise ValueError("File not found for user")

    original_name, stored_name, stored_cipher = row
    use_cipher = cipher_name or stored_cipher
    file_path = os.path.join(VAULT_DIR, stored_name)
    if not os.path.exists(file_path):
        raise ValueError("Encrypted file missing")

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = _decrypt_by_cipher(encrypted_data, use_cipher, key)
    return {"filename": original_name, "content": decrypted_data}


def download_encrypted_file(filename, key, user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT original_name, stored_name, cipher_name
        FROM vault_files
        WHERE stored_name = ? AND user_id = ?
        """,
        (filename, str(user_id)),
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise ValueError("File not found for user")

    original_name, stored_name, stored_cipher = row
    file_path = os.path.join(VAULT_DIR, stored_name)
    if not os.path.exists(file_path):
        raise ValueError("Encrypted file missing")

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    # Validate security key by attempting decrypt; prevents unauthorized downloads.
    _decrypt_by_cipher(encrypted_data, stored_cipher, key)
    return {"filename": stored_name, "content": encrypted_data, "original_name": original_name}


def delete_file(filename, key, user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT stored_name, cipher_name
        FROM vault_files
        WHERE stored_name = ? AND user_id = ?
        """,
        (filename, str(user_id)),
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    stored_name, stored_cipher = row
    file_path = os.path.join(VAULT_DIR, stored_name)
    if not os.path.exists(file_path):
        conn.close()
        return False

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    # Validate key before delete.
    try:
        _decrypt_by_cipher(encrypted_data, stored_cipher, key)
    except Exception:
        conn.close()
        return False

    os.remove(file_path)
    cursor.execute(
        "DELETE FROM vault_files WHERE stored_name = ? AND user_id = ?",
        (filename, str(user_id)),
    )
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def list_files(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT original_name, stored_name, cipher_name, timestamp
        FROM vault_files
        WHERE user_id = ?
        ORDER BY timestamp DESC
        """,
        (str(user_id),),
    )
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "original_name": row[0],
            "stored_name": row[1],
            "cipher_name": row[2],
            "timestamp": row[3],
        }
        for row in rows
    ]
