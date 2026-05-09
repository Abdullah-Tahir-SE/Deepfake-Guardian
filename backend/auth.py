import hashlib

from database_manager import add_user, verify_user


def _hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def signup_user(name, email, employee_id, password):
    if not all([name, email, employee_id, password]):
        return False
    password_hash = _hash_password(password)
    return add_user(name, email, employee_id, password_hash)


def login_user(username, employee_id, password):
    if not all([username, employee_id, password]):
        return False
    password_hash = _hash_password(password)
    return verify_user(username, employee_id, password_hash)
