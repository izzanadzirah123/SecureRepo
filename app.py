from flask import send_file, Flask, render_template, request, redirect, url_for, flash, session
import io
import pyotp
import os
import qrcode
import base64
from io import BytesIO
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from database import db, User, Document
from security import encrypt_file, decrypt_file, generate_key
import datetime

app = Flask(__name__)

# 1. Setup Configs
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_repo.db'
app.config['SECRET_KEY'] = 'dev_key_123'  
app.config['UPLOAD_FOLDER'] = 'storage'

# 2. Ensure storage folder exists
if not os.path.exists('storage'):
    os.makedirs('storage')

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- IMPORTANT: KEY MANAGEMENT ---
# REPLACE the line below with your static key from the terminal to fix the InvalidToken error.
# Example: FILE_ENCRYPTION_KEY = b'your_permanent_key_here='
# New VALID key (Copy this exactly):
# Replace your current broken key with this valid one:
FILE_ENCRYPTION_KEY = b'uX6H6-Y-Z6f_X-uW1l-QvP5f-X-uW1l-QvP5f-X-uW1='

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- ROUTES ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # SMOOTH FIX: Clear any old MFA data when someone hits the login page
    if request.method == 'GET':
        session.pop('mfa_user_id', None)
        session.pop('personal_keyword', None)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # Set fresh session data
            session['mfa_user_id'] = user.id
            session['personal_keyword'] = user.security_keyword 
            
            # If no MFA secret, go to setup. Otherwise, go to verify.
            if not user.mfa_secret:
                return redirect(url_for('setup_mfa_direct', user_id=user.id))
            
            return redirect(url_for('mfa_verify')) 
        
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    user_id = session.get('mfa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    totp = pyotp.TOTP(user.mfa_secret)

    # DEBUG: Help you see the code in the VS Code terminal
    print(f"--- MFA DEBUG ---")
    print(f"Current Time: {datetime.datetime.now()}")
    print(f"Expected Code: {totp.now()}")
    print(f"-----------------")

    if request.method == 'POST':
        otp_code = request.form.get('otp')
        # Check for valid code OR the bypass button click
        is_bypass = request.form.get('bypass') == 'true'
        
        if (otp_code and totp.verify(otp_code, valid_window=2)) or is_bypass: 
            login_user(user)
            session.pop('mfa_user_id', None) 
            flash("Identity Verified!")
            return redirect(url_for('dashboard')) 
        else:
            flash("Invalid MFA Code. Check your terminal for the correct code.")
            
    return render_template('mfa_verify.html', keyword=session.get('personal_keyword'))

# --- ADD THIS TO YOUR ADMIN ROUTES ---

@app.route('/admin/reset-mfa/<int:user_id>')
@login_required
def reset_mfa(user_id):
    """Clears a user's MFA so they must re-scan a QR code next login"""
    if current_user.role != 'Admin':
        flash("Access Denied.")
        return redirect(url_for('dashboard'))
    
    user = db.session.get(User, user_id)
    if user:
        user.mfa_secret = None 
        db.session.commit()
        flash(f"MFA for {user.username} reset! They will see a QR code on next login.")
    
    return redirect(url_for('manage_users'))

@app.route('/setup-mfa-direct/<int:user_id>')
def setup_mfa_direct(user_id):
    # Security check: Ensure user is allowed to see this setup
    if session.get('mfa_user_id') != user_id:
        return redirect(url_for('login'))

    user = db.session.get(User, user_id) # Fix legacy warning
    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32() # Generates and saves the new secret
        db.session.commit()

    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name="SecureRepo")

    img = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template('setup_mfa.html', qr_code=img_base64, secret=user.mfa_secret)

@app.route('/dashboard')
@login_required
def dashboard():
    all_files = os.listdir(app.config['UPLOAD_FOLDER'])
    clean_files = [f.replace('.enc', '') for f in all_files if f.endswith('.enc')]
    return render_template('dashboard.html', user=current_user, files=clean_files)


@app.route('/mfa-setup-complete', methods=['GET', 'POST'])
def mfa_setup_complete():
    # After scanning, we send them to the verify page to test their first code
    return redirect(url_for('mfa_verify'))


@app.route('/upload', methods=['POST'])
@login_required
def upload_document():
    if current_user.role not in ['Admin', 'Trainer']:
        flash("Access Denied.")
        return redirect(url_for('dashboard'))

    file = request.files.get('file')
    if file:
        file_content = file.read()
        encrypted_data = encrypt_file(file_content, FILE_ENCRYPTION_KEY)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file.filename}.enc")
        with open(file_path, "wb") as f:
            f.write(encrypted_data)
        
        with open("audit_log.txt", "a") as log:
            log.write(f"[{datetime.datetime.now()}] USER: {current_user.username} | ACTION: Uploaded {file.filename}\n")
        
        flash(f"File '{file.filename}' uploaded and encrypted!")
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.enc")
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data, FILE_ENCRYPTION_KEY)
        return send_file(io.BytesIO(decrypted_data), download_name=filename, as_attachment=True)
    
    flash("File not found.")
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    # COMPLETELY clear the session on logout
    session.clear() 
    flash("You have been logged out.")
    return redirect(url_for('login'))

# --- ADMIN ROUTES ---

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'Admin':
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = generate_password_hash(request.form.get('password'))
        new_role = request.form.get('role')
        new_keyword = request.form.get('security_keyword') 

        # Check if user already exists to avoid errors
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user:
            flash("Username already exists!")
        else:
            # We set mfa_secret=None so they see the QR code on first login
            new_user = User(
                username=new_username, 
                password=new_password, 
                role=new_role, 
                security_keyword=new_keyword,
                mfa_secret=None 
            )
            db.session.add(new_user)
            db.session.commit()
            flash(f"User {new_username} created. They will scan QR on first login.")
        
    users = User.query.all()
    return render_template('manage_users.html', users=users, user=current_user)

# --- ADD THESE MISSING ROUTES ---

@app.route('/admin/delete-user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'Admin':
        flash("Access Denied.")
        return redirect(url_for('dashboard'))
    
    user = db.session.get(User, user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} deleted.")
    return redirect(url_for('manage_users'))

@app.route('/admin/export-logs')
@login_required
def export_logs():
    if current_user.role != 'Admin':
        return redirect(url_for('dashboard'))
    
    if os.path.exists("audit_log.txt"):
        return send_file("audit_log.txt", as_attachment=True)
    
    flash("No logs found.")
    return redirect(url_for('view_logs'))


@app.route('/admin/logs')
@login_required
def view_logs():
    if current_user.role != 'Admin':
        return redirect(url_for('dashboard'))
    logs = []
    if os.path.exists("audit_log.txt"):
        with open("audit_log.txt", "r") as f:
            logs = f.readlines()
    return render_template('logs.html', logs=reversed(logs))

@app.route('/delete/<filename>')
@login_required
def delete_file(filename):
    # Only Admin/Trainer can delete
    if current_user.role not in ['Admin', 'Trainer']:
        flash("Access Denied.")
        return redirect(url_for('dashboard'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.enc")
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f"File '{filename}' deleted successfully.")
        
        # Log the action
        with open("audit_log.txt", "a") as log:
            log.write(f"[{datetime.datetime.now()}] USER: {current_user.username} | ACTION: Deleted {filename}\n")
    else:
        flash("File not found.")
        
    return redirect(url_for('dashboard'))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username='Izza').first()
        if not admin:
            new_admin = User(
                username="Izza",
                password=generate_password_hash("Izza@1234"), # Use your password
                role="Admin",
                security_keyword="MasterAccess2026",
                mfa_secret=None # Setting to None ensures she sees the QR code first
            )
            db.session.add(new_admin)
            db.session.commit()
            print("Admin Izza created. Please scan QR on first login.")
            
    app.run(debug=True)