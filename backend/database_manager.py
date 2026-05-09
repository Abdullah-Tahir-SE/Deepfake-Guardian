import sqlite3
import os
from security import hash_password

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

def init_db():
    """Initialize database schema."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
        '''
    )

    # Vault metadata table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS vault_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT UNIQUE NOT NULL,
            cipher_name TEXT NOT NULL,
            timestamp REAL NOT NULL
        )
        '''
    )

    # Password manager table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            site_name TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            timestamp REAL NOT NULL
        )
        '''
    )

    # Persistent blockchain table
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS blockchain_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_index INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            hash TEXT NOT NULL
        )
        '''
    )

    # Login scans table for biometric verification photos
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS login_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            encrypted_photo BLOB NOT NULL,
            timestamp REAL NOT NULL
        )
        '''
    )

    conn.commit()
    conn.close()

def add_user(name, email, password):
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        password_hash = hash_password(password)
        cursor.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name, email, password_hash)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        if conn:
            conn.close()

def verify_user(username, password):
    """Verify user by username and password hash."""
    if not all([username, password]):
        return False
    password_hash = hash_password(password)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE name = ? AND password_hash = ?",
        (username, password_hash)
    )
    user = cursor.fetchone()
    conn.close()
    return user is not None

def get_user(employee_id):
    """Fetch user by employee_id."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name, email, password_hash FROM users WHERE email = ?",
        (employee_id,)
    )
    row = cursor.fetchone()
    conn.close()
    return row


def get_user_by_email(email):
    """Fetch user by registered email."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name, email FROM users WHERE email = ? ORDER BY id DESC LIMIT 1",
        (email,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def get_user_summary(identifier):
    """Fetch user summary by name or email."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, name, email
        FROM users
        WHERE name = ? OR email = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (identifier, identifier),
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "name": row[1], "email": row[2]}


def update_user_password_by_email(email, new_password):
    """Update password hash for a user identified by email."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    password_hash = hash_password(new_password)
    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (password_hash, email),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def save_login_scan(user_id, encrypted_photo):
    """Save an encrypted biometric scan photo for a login event."""
    import time
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO login_scans (user_id, encrypted_photo, timestamp) VALUES (?, ?, ?)",
        (user_id, encrypted_photo, time.time())
    )
    conn.commit()
    conn.close()
