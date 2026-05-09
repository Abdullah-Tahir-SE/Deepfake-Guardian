import sqlite3
import time

from database_manager import DB_PATH
from cipher_engine import aes_encrypt, aes_decrypt


def save_password(user_id, site_name, username, password, security_key):
    encrypted_password = aes_encrypt(password, security_key).hex()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO passwords (user_id, site_name, username, encrypted_password, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (str(user_id), site_name, username, encrypted_password, time.time()),
    )
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def get_passwords(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, site_name, username, encrypted_password, timestamp
        FROM passwords
        WHERE user_id = ?
        ORDER BY timestamp DESC
        """,
        (str(user_id),),
    )
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "site_name": row[1],
            "username": row[2],
            "encrypted_password": row[3],
            "timestamp": row[4],
        }
        for row in rows
    ]


def decrypt_password(user_id, password_id, security_key):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT encrypted_password
        FROM passwords
        WHERE id = ? AND user_id = ?
        """,
        (int(password_id), str(user_id)),
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    try:
        return aes_decrypt(bytes.fromhex(row[0]), security_key).decode("utf-8")
    except Exception:
        return None


def delete_password(user_id, password_id, security_key):
    plain = decrypt_password(user_id, password_id, security_key)
    if plain is None:
        return False

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM passwords WHERE id = ? AND user_id = ?",
        (int(password_id), str(user_id)),
    )
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def get_password_receipt_record(user_id, password_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, site_name, username, encrypted_password, timestamp
        FROM passwords
        WHERE id = ? AND user_id = ?
        """,
        (int(password_id), str(user_id)),
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "site_name": row[1],
        "username": row[2],
        "encrypted_password": row[3],
        "timestamp": row[4],
    }


def check_password_strength(password):
    length_ok = len(password) >= 12
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    score = sum([length_ok, has_upper, has_lower, has_digit, has_special])
    if score <= 2:
        return "Weak"
    if score == 3:
        return "Medium"
    if score == 4:
        return "Strong"
    return "Very Strong"
