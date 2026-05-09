import os
import random
import smtplib
import time
from email.mime.text import MIMEText

import cv2
import numpy as np
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file

from database_manager import (
    init_db,
    add_user,
    verify_user,
    get_user_by_email,
    get_user_summary,
    update_user_password_by_email,
    save_login_scan,
)
from detector_logic import BiometricDetector
from blockchain_log import BlockchainLedger
from file_vault import upload_file, download_file, download_encrypted_file, delete_file, list_files
from passfort import save_password, get_passwords, decrypt_password, delete_password, get_password_receipt_record, check_password_strength
from recommender import recommend_cipher, recommend_stack
from cipher_engine import aes_encrypt

# Absolute paths to ensure reliable asset resolution from any working directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, 
            template_folder=os.path.join(BASE_DIR, '../frontend/templates'), 
            static_folder=os.path.join(BASE_DIR, '../frontend/static'))

# Enable Live Server-like experience for frontend development
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

app.secret_key = 'deepfake_guardian_secure_secret_hash' 

# Global components
ledger = BlockchainLedger()
detector = BiometricDetector()

# In-memory rate limiting dictionary
login_attempts = {}
password_reset_otps = {}

with app.app_context():
    init_db()
    ledger.log_event("SYSTEM", "BOOT", "Database initialized and app booted")


def _send_reset_otp(email, otp):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    from_email = os.getenv("SMTP_FROM", smtp_user or "noreply@deepfake-guardian.local")

    if not smtp_host or not smtp_user or not smtp_pass:
        raise RuntimeError("Email service not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS.")

    msg = MIMEText(
        f"Your Deepfake Guardian password reset OTP is: {otp}\n\n"
        "This OTP will expire in 5 minutes."
    )
    msg["Subject"] = "Deepfake Guardian Password Reset OTP"
    msg["From"] = from_email
    msg["To"] = email

    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)

@app.route('/')
def index():
    """Default route to load Landing view dynamically"""
    return render_template('index.html', active_section='landing')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Single file rendering routing for Registration logic"""
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        success = add_user(name, email, password)
        
        if success:
            ledger.log_event(email, "SIGNUP_SUCCESS", "Registration successful")
            # Send them to Login Screen automatically upon success
            return render_template('index.html', active_section='login', success_msg="Registration Complete! Please Login.")
        else:
            return render_template('index.html', active_section='signup', error="Signup failed. Check required fields or duplicate employee ID.")

    return render_template('index.html', active_section='signup')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Single file rendering routing for Auth logic and strict lockouts"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_state = login_attempts.get(username, {'attempts': 0, 'locked_until': 0})
        current_time = time.time()
        
        if user_state['locked_until'] > current_time:
            lockout_time = int(user_state['locked_until'] - current_time)
            return render_template('index.html', active_section='login', error="Security Lockout Active.", lockout=lockout_time)
            
        if verify_user(username, password):
            login_attempts[username] = {'attempts': 0, 'locked_until': 0}
            session.pop('logged_in', None)
            session.pop('email', None)
            session['pre_auth_user'] = username
            session['liveness_scores'] = []
            ledger.log_event(username, "LOGIN_SUCCESS", "Credentials verified; awaiting biometric")
            return redirect(url_for('liveness'))
        else:
            user_state['attempts'] += 1
            if user_state['attempts'] >= 3:
                user_state['locked_until'] = current_time + 10
                login_attempts[username] = user_state
                ledger.log_event(username, "LOGIN_LOCKOUT", "Brute-force lockout triggered")
                return render_template('index.html', active_section='login', error="Max attempts reached. System locked.", lockout=10)
                
            login_attempts[username] = user_state
            ledger.log_event(username, "LOGIN_FAILED", "Invalid credentials")
            return render_template('index.html', active_section='login', error=f"Invalid Credentials. Attempt {user_state['attempts']}/3")
            
    if session.get('pre_auth_user') and not session.get('logged_in'):
        return redirect(url_for('liveness'))
    return render_template('index.html', active_section='login')


def _liveness_cooldown_remaining():
    until = session.get('not_human_until') or 0
    return max(0, int(until - time.time()))


@app.route('/liveness')
def liveness():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    if not session.get('pre_auth_user'):
        return redirect(url_for('login'))
    return render_template(
        'liveness.html',
        cooldown_remaining=_liveness_cooldown_remaining(),
    )


@app.route('/api/liveness/begin', methods=['POST'])
def liveness_begin():
    if not session.get('pre_auth_user'):
        return jsonify({"error": "Session expired. Login again."}), 401
    if _liveness_cooldown_remaining() > 0:
        return jsonify({"error": "Cooldown active", "cooldown": _liveness_cooldown_remaining()}), 429
    session.modified = True
    return jsonify({"status": "ok"}), 200


@app.route('/api/liveness/frame', methods=['POST'])
def liveness_frame():
    if not session.get('pre_auth_user'):
        return jsonify({"error": "Session expired."}), 401
    if _liveness_cooldown_remaining() > 0:
        return jsonify({"error": "Cooldown active", "cooldown": _liveness_cooldown_remaining()}), 429

    file = request.files.get('frame')
    if not file:
        return jsonify({"error": "No frame uploaded"}), 400

    data = np.frombuffer(file.read(), np.uint8)
    frame = cv2.imdecode(data, cv2.IMREAD_COLOR)
    if frame is None:
        return jsonify({"error": "Invalid image"}), 400

    result = detector.check_liveness(frame)
    return jsonify({
        "face_detected": result.get("face_detected", False),
        "box": result.get("box")
    }), 200


@app.route('/api/liveness/finish', methods=['POST'])
def liveness_finish():
    if not session.get('pre_auth_user'):
        return jsonify({"error": "Session expired."}), 401
    if _liveness_cooldown_remaining() > 0:
        return jsonify(
            {"status": "cooldown", "cooldown": _liveness_cooldown_remaining()}
        ), 429

    username = session['pre_auth_user']
    photo = request.files.get('photo')
    
    if not photo:
        return jsonify({"status": "error", "message": "No scan photo received."}), 400

    try:
        # Read the raw image data
        raw_photo_data = photo.read()
        
        # Encrypt the photo data using the app secret key
        # In a real app, you might use a user-derived key
        encrypted_photo = aes_encrypt(raw_photo_data, app.secret_key)
        
        # Save to database
        save_login_scan(username, encrypted_photo)
        
        ledger.log_event(username, "BIOMETRIC_PASS", "10s Face detection completed; Encrypted scan archived.")
        
        session['logged_in'] = True
        session['email'] = username
        session.pop('pre_auth_user', None)
        session.pop('not_human_until', None)
        
        return jsonify({"status": "human", "redirect": url_for('dashboard')}), 200
        
    except Exception as e:
        ledger.log_event(username, "BIOMETRIC_ERROR", f"Failed to process scan: {str(e)}")
        return jsonify({"status": "error", "message": "Encryption or storage failure."}), 500


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = (request.form.get('email') or '').strip()
    if not email:
        return render_template('index.html', active_section='reset', reset_error="Email is required.")

    user = get_user_by_email(email)
    if not user:
        return render_template('index.html', active_section='reset', reset_error="No account found for this email.")

    otp = f"{random.randint(0, 999999):06d}"
    password_reset_otps[email] = {"otp": otp, "expires_at": time.time() + 300}
    try:
        _send_reset_otp(email, otp)
    except Exception as exc:
        return render_template(
            'index.html',
            active_section='reset',
            reset_error=f"Failed to send OTP email: {exc}",
        )

    ledger.log_event(email, "PASSWORD_RESET_OTP_SENT", "Password reset OTP issued")
    return render_template(
        'index.html',
        active_section='reset',
        reset_success="OTP sent to your email. Enter it below to reset password.",
        reset_email=email,
    )


@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = (request.form.get('email') or '').strip()
    otp = (request.form.get('otp') or '').strip()
    new_password = request.form.get('new_password') or ''
    confirm_password = request.form.get('confirm_password') or ''

    if not all([email, otp, new_password, confirm_password]):
        return render_template('index.html', active_section='reset', reset_error="All reset fields are required.")
    if new_password != confirm_password:
        return render_template('index.html', active_section='reset', reset_error="Passwords do not match.", reset_email=email)
    if len(new_password) < 8:
        return render_template('index.html', active_section='reset', reset_error="Password must be at least 8 characters.", reset_email=email)

    otp_state = password_reset_otps.get(email)
    now = time.time()
    if not otp_state or otp_state["expires_at"] < now:
        password_reset_otps.pop(email, None)
        return render_template('index.html', active_section='reset', reset_error="OTP expired or invalid. Request a new OTP.", reset_email=email)
    if otp_state["otp"] != otp:
        return render_template('index.html', active_section='reset', reset_error="Invalid OTP.", reset_email=email)

    updated = update_user_password_by_email(email, new_password)
    password_reset_otps.pop(email, None)
    if not updated:
        return render_template('index.html', active_section='reset', reset_error="Unable to update password.", reset_email=email)

    ledger.log_event(email, "PASSWORD_RESET_SUCCESS", "Password changed via OTP flow")
    return render_template('index.html', active_section='login', success_msg="Password reset successful. Please login.")

@app.route('/dashboard')
def dashboard():
    """Secure Dashboard rendering."""
    if session.get('pre_auth_user') and not session.get('logged_in'):
        return redirect(url_for('liveness'))
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/encrypt-file', methods=['POST'])
def encrypt_file_route():
    account_email = session.get('email') or request.form.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    file = request.files.get('file')
    cipher_name = request.form.get('cipher_name')
    key = request.form.get('key')

    if not file or not cipher_name or not key:
        return jsonify({"error": "file, cipher_name, and key are required"}), 400

    try:
        data = upload_file(file, cipher_name, key, account_email)
        ledger.log_event(account_email, "FILE_ENCRYPTED", f"{data['original_name']} via {cipher_name}")
        return jsonify(data), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route('/decrypt-file', methods=['POST'])
def decrypt_file_route():
    account_email = session.get('email') or request.form.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    filename = request.form.get('filename')
    cipher_name = request.form.get('cipher_name')
    key = request.form.get('key')
    if not filename or not key:
        return jsonify({"error": "filename and key are required"}), 400

    try:
        result = download_file(filename, cipher_name, key, account_email)
        output_name = result["filename"]
        output_path = os.path.join(BASE_DIR, "vault", f"dec_{int(time.time())}_{output_name}")
        with open(output_path, "wb") as out_file:
            out_file.write(result["content"])
        ledger.log_event(account_email, "FILE_DECRYPTED", output_name)
        return send_file(output_path, as_attachment=True, download_name=output_name)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route('/download-encrypted-file', methods=['POST'])
def download_encrypted_file_route():
    account_email = session.get('email') or request.form.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    filename = request.form.get('filename')
    key = request.form.get('key')
    if not filename or not key:
        return jsonify({"error": "filename and key are required"}), 400

    try:
        result = download_encrypted_file(filename, key, account_email)
        ledger.log_event(account_email, "FILE_ENCRYPTED_DOWNLOAD", result["filename"])
        encrypted_path = os.path.join(BASE_DIR, "vault", result["filename"])
        return send_file(encrypted_path, as_attachment=True, download_name=result["filename"])
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route('/delete-file', methods=['POST'])
def delete_file_route():
    account_email = session.get('email') or request.form.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    filename = request.form.get('filename')
    key = request.form.get('key')
    if not filename or not key:
        return jsonify({"error": "filename and key are required"}), 400

    success = delete_file(filename, key, account_email)
    if not success:
        return jsonify({"error": "Delete failed. Invalid security key or file missing."}), 400

    ledger.log_event(account_email, "FILE_DELETED", filename)
    return jsonify({"status": "deleted"}), 200


@app.route('/my-files', methods=['GET'])
def my_files_route():
    account_email = session.get('email') or request.args.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401
    return jsonify(list_files(account_email)), 200


@app.route('/save-password', methods=['POST'])
def save_password_route():
    account_email = session.get('email') or request.form.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    site_name = request.form.get('site_name')
    username = request.form.get('username')
    password = request.form.get('password')
    security_key = request.form.get('security_key')
    if not all([site_name, username, password, security_key]):
        return jsonify({"error": "site_name, username, password, security_key are required"}), 400

    try:
        password_id = save_password(account_email, site_name, username, password, security_key)
        block = ledger.log_event(account_email, "PASSWORD_ENCRYPTED", f"Credential encrypted for {site_name}")
        return jsonify({"status": "saved", "password_id": password_id, "audit_id": block["hash"]}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route('/get-passwords', methods=['GET'])
def get_passwords_route():
    account_email = session.get('email') or request.args.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    try:
        result = get_passwords(account_email)
        return jsonify(result), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route('/decrypt-password', methods=['POST'])
def decrypt_password_route():
    account_email = session.get('email') or request.form.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    password_id = request.form.get('password_id')
    security_key = request.form.get('security_key')
    if not password_id or not security_key:
        return jsonify({"error": "password_id and security_key are required"}), 400

    plain = decrypt_password(account_email, password_id, security_key)
    if plain is None:
        return jsonify({"error": "Decryption Failed"}), 400

    ledger.log_event(account_email, "PASSWORD_DECRYPTED", f"Credential decrypted for record {password_id}")
    return jsonify({"password": plain}), 200


@app.route('/delete-password', methods=['POST'])
def delete_password_route():
    account_email = session.get('email') or request.form.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    password_id = request.form.get('password_id')
    security_key = request.form.get('security_key')
    if not password_id or not security_key:
        return jsonify({"error": "password_id and security_key are required"}), 400

    success = delete_password(account_email, password_id, security_key)
    if not success:
        return jsonify({"error": "Delete failed. Invalid Security Key or record not found."}), 400

    ledger.log_event(account_email, "PASSWORD_DELETED", f"Credential deleted for record {password_id}")
    return jsonify({"status": "deleted"}), 200


@app.route('/download-password-receipt', methods=['GET'])
def download_password_receipt_route():
    account_email = session.get('email') or request.args.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    password_id = request.args.get('password_id')
    if not password_id:
        return jsonify({"error": "password_id is required"}), 400

    record = get_password_receipt_record(account_email, password_id)
    if not record:
        return jsonify({"error": "Password record not found"}), 404

    try:
        from fpdf import FPDF
    except Exception:
        return jsonify({"error": "PDF library missing. Install fpdf."}), 500

    latest_block = ledger.chain[-1]["hash"] if ledger.chain else "N/A"
    pdf_path = os.path.join(BASE_DIR, f"passfort_encrypted_receipt_{password_id}_{int(time.time())}.pdf")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 15)
    pdf.cell(0, 10, "PassFort Encrypted Receipt", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.ln(4)
    pdf.multi_cell(0, 8, f"Site Name: {record['site_name']}")
    pdf.multi_cell(0, 8, f"Username: {record['username']}")
    pdf.multi_cell(0, 8, f"Encrypted Password: {record['encrypted_password']}")
    pdf.multi_cell(0, 8, f"Timestamp: {record['timestamp']}")
    pdf.multi_cell(0, 8, f"Audit ID: {latest_block}")
    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, download_name=f"encrypted_receipt_{password_id}.pdf")


@app.route('/download-password-receipt-decrypted', methods=['POST'])
def download_password_receipt_decrypted_route():
    account_email = session.get('email') or request.form.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    password_id = request.form.get('password_id')
    security_key = request.form.get('security_key')
    if not password_id or not security_key:
        return jsonify({"error": "password_id and security_key are required"}), 400

    record = get_password_receipt_record(account_email, password_id)
    if not record:
        return jsonify({"error": "Password record not found"}), 404
    plain = decrypt_password(account_email, password_id, security_key)
    if plain is None:
        return jsonify({"error": "Decryption Failed"}), 400

    ledger.log_event(account_email, "PASSWORD_DECRYPTED", f"Credential decrypted for PDF record {password_id}")
    try:
        from fpdf import FPDF
    except Exception:
        return jsonify({"error": "PDF library missing. Install fpdf."}), 500

    latest_block = ledger.chain[-1]["hash"] if ledger.chain else "N/A"
    pdf_path = os.path.join(BASE_DIR, f"passfort_decrypted_receipt_{password_id}_{int(time.time())}.pdf")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 15)
    pdf.cell(0, 10, "PassFort Decrypted Receipt", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.ln(4)
    pdf.multi_cell(0, 8, f"Site Name: {record['site_name']}")
    pdf.multi_cell(0, 8, f"Username: {record['username']}")
    pdf.multi_cell(0, 8, f"Decrypted Password: {plain}")
    pdf.multi_cell(0, 8, f"Encrypted Password: {record['encrypted_password']}")
    pdf.multi_cell(0, 8, f"Timestamp: {record['timestamp']}")
    pdf.multi_cell(0, 8, f"Audit ID: {latest_block}")
    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, download_name=f"decrypted_receipt_{password_id}.pdf")


@app.route('/download-auth-receipt', methods=['GET'])
def download_auth_receipt_route():
    account_email = session.get('email') or request.args.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401

    user = get_user_summary(account_email)
    if not user:
        return jsonify({"error": "User profile not found"}), 404

    auth_actions = {"SIGNUP_SUCCESS", "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_LOCKOUT"}
    auth_logs = [
        block for block in ledger.chain
        if block.get("action") in auth_actions and block.get("user_id") in {account_email, user["name"], user["email"]}
    ]

    if not auth_logs:
        auth_logs = [
            block for block in ledger.chain
            if block.get("action") in auth_actions and block.get("user_id") == "SYSTEM"
        ]

    payload = [
        f"USER_ID:{user['id']}",
        f"NAME:{user['name']}",
        f"EMAIL:{user['email']}",
    ]
    for entry in auth_logs[-20:]:
        payload.append(
            f"{entry.get('timestamp', 0)}|{entry.get('action', 'UNKNOWN')}|{entry.get('details', '')}"
        )
    encrypted_blob_hex = aes_encrypt("\n".join(payload), app.secret_key).hex()

    try:
        from fpdf import FPDF
    except Exception:
        return jsonify({"error": "PDF library missing. Install fpdf."}), 500

    pdf_path = os.path.join(BASE_DIR, f"auth_receipt_{user['id']}_{int(time.time())}.pdf")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "CipherVault Auth Encrypted Receipt", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.ln(2)
    pdf.multi_cell(0, 7, "This receipt contains encrypted login/signup information.")
    pdf.multi_cell(0, 7, f"User: {user['name']} ({user['email']})")
    pdf.multi_cell(0, 7, f"Generated At: {time.ctime()}")
    pdf.ln(2)
    pdf.set_font("Arial", "B", 10)
    pdf.multi_cell(0, 6, "Encrypted Payload (AES-256 Hex)")
    pdf.set_font("Arial", "", 9)
    pdf.multi_cell(0, 5, encrypted_blob_hex)
    pdf.output(pdf_path)

    ledger.log_event(account_email, "AUTH_RECEIPT_DOWNLOADED", f"Encrypted auth receipt generated for user {user['id']}")
    return send_file(pdf_path, as_attachment=True, download_name=f"auth_receipt_encrypted_{user['id']}.pdf")


@app.route('/check-strength', methods=['POST'])
def check_strength_route():
    password = request.form.get('password', '')
    return jsonify({"strength": check_password_strength(password)}), 200


@app.route('/blockchain-log', methods=['GET'])
def blockchain_log_route():
    account_email = session.get('email') or request.args.get('email')
    if not account_email:
        return jsonify({"error": "Authentication required"}), 401
    return jsonify(
        {
            "verified": ledger.verify_chain(),
            "logs": ledger.get_logs(account_email),
        }
    ), 200


@app.route('/recommend', methods=['POST'])
def recommend_route():
    filename = request.form.get('filename')
    filesize = request.form.get('filesize', '0')
    if not filename:
        return jsonify({"error": "filename is required"}), 400
    try:
        filesize_int = int(filesize)
    except ValueError:
        return jsonify({"error": "filesize must be integer"}), 400

    return jsonify(
        {
            "cipher": recommend_cipher(filename, filesize_int),
            "stack": recommend_stack(filename, filesize_int),
        }
    ), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
