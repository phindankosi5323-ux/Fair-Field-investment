from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
import sqlite3
import string
import random
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
import re

# Initialize Flask app
app = Flask(__name__)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'elviskinq91@gmail.com'
app.config['MAIL_PASSWORD'] = 'Elvisking@1'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

mail = Mail(app)

# Configure the app (make sure you set the secret key and database URI)
app.secret_key = 'supersecretkey'  # Change this for production!
DATABASE = 'app.db'

# Continue with the rest of your code...


# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE,
        full_name TEXT,
        phone TEXT,
        id_number TEXT,
        gender TEXT,
        dob TEXT,
        address TEXT,
        country TEXT,
        referral_code TEXT UNIQUE,
        referred_by TEXT,
        verified TEXT DEFAULT 'unverified',
        profile_image TEXT,
        is_admin INTEGER DEFAULT 0
    )
    ''')
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS investments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount REAL,
        daily_rate REAL,
        duration INTEGER,
        start_date TEXT,
        status TEXT DEFAULT 'active',
        next_roi TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')


    c.execute('''
    CREATE TABLE IF NOT EXISTS investments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount REAL,
        daily_rate REAL,
        duration INTEGER,
        start_date TEXT,
        status TEXT DEFAULT 'active',
        next_roi TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        method TEXT,
        destination TEXT,
        amount REAL,
        status TEXT DEFAULT 'pending',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')

    conn.commit()
    conn.close()

# --- DATABASE CONNECTION ---
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# --- Database Functions ---
def get_db():
    """Database connection"""
    conn = sqlite3.connect('app.db')  # Make sure this path is correct
    conn.row_factory = sqlite3.Row  # Allows column access by name
    return conn

def get_user_by_email(email):
    """Fetch a user from the database by email"""
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user

def update_user_password(email, new_password):
    """Update user password in the database"""
    conn = get_db()
    conn.execute('UPDATE users SET password = ? WHERE email = ?', (new_password, email))
    conn.commit()
    conn.close()

# --- UNIVERSAL BALANCE CALCULATOR ---
def calculate_user_balance(user_id):
    conn = get_db()
    balance = conn.execute('''
        SELECT COALESCE(SUM(
            CASE
                WHEN type = 'deposit' AND status = 'approved' THEN amount
                WHEN type = 'withdrawal' AND status = 'approved' THEN -amount
                WHEN type = 'investment' AND status = 'approved' THEN amount  -- investment already negative
                ELSE 0
            END), 0)
        FROM transactions WHERE user_id = ?
    ''', (user_id,)).fetchone()[0]
    conn.close()
    return round(balance or 0, 2)

# --- ADMIN AUTH DECORATOR ---
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or 'is_admin' not in session:
            return redirect(url_for('login'))

        # Handle simulated admin
        if session.get('username') == 'admin' and session.get('is_admin') is True:
            return f(*args, **kwargs)

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()

        if not user or user['is_admin'] != 1:
            return "Unauthorized", 403
        return f(*args, **kwargs)
    return decorated
    
# --- USER LOGIN REQUIRED DECORATOR ---
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.get_json()

            # Step 1: Validate Input
            required_fields = ['fullName', 'username', 'email', 'password', 
                               'phone', 'idNumber', 'gender', 'dob', 'address', 'country']
            errors = {}
            for field in required_fields:
                if not data.get(field):
                    errors[field] = f"{field} is required"
            if not errors.get('email') and not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', data['email']):
                errors['email'] = "Invalid email format"
            if not errors.get('password') and len(data['password']) < 8:
                errors['password'] = "Password must be at least 8 characters"
            if not errors.get('phone') and not re.match(r'^\+?[\d\s\-]{10,15}$', data['phone']):
                errors['phone'] = "Invalid phone number format"
            if errors:
                return jsonify({'success': False, 'errors': errors}), 400

            conn = get_db()
            existing_user = conn.execute(
                'SELECT * FROM users WHERE username = ? OR email = ?',
                (data['username'], data['email'])
            ).fetchone()
            if existing_user:
                conn.close()
                field = 'username' if existing_user['username'] == data['username'] else 'email'
                return jsonify({'success': False, 'errors': {field: f"This {field} is already registered"}}), 400

            # Step 2: Hash the password
            hashed_password = generate_password_hash(data['password'])
            
            # Step 3: Generate a unique referral code for the new user
            referral_code = str(uuid.uuid4())[:8]

            # Step 4: Check if the user is referred by someone (via referral_code in the data)
            referred_by = data.get('referral_code', None)

            # Step 5: Insert the new user into the database
            conn.execute(
                '''INSERT INTO users 
                (username, password, email, full_name, phone, id_number, gender, dob, address, country, referral_code, referred_by, verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (data['username'], hashed_password, data['email'], data['fullName'],
                 data['phone'], data['idNumber'], data['gender'], data['dob'],
                 data['address'], data['country'], referral_code, referred_by, 'unverified')
            )
            conn.commit()
            conn.close()

            # Step 6: Create the referral link to send to the user
            referral_link = f"/register?ref={referral_code}"

            # Debugging: Print referral link to verify if it's correct
            print(f"Generated Referral Link: {referral_link}")

            # Step 7: Send back the response with a success message and the referral link
            return jsonify({
                'success': True, 
                'message': 'Registration successful', 
                'referral_link': referral_link
            })

        except Exception as e:
            print(f"Registration error: {e}")
            return jsonify({'success': False, 'message': 'An error occurred during registration'}), 500

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            return jsonify({'success': True, 'fica_status': user['verified']})
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials or account still pending for approval'}), 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route("/dashboard-data")
@login_required
def dashboard_data():
    user_id = session['user_id']
    conn = get_db()

    # Get user balance (updated after investment)
    balance = calculate_user_balance(user_id)

    # Get recent activity
    activities = conn.execute('''
        SELECT type, amount, timestamp as date, status
        FROM transactions WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5
    ''', (user_id,)).fetchall()

    # Get active investments
    active_investments = conn.execute('''
        SELECT id, amount, daily_rate, duration, start_date
        FROM investments WHERE user_id = ? AND status = 'active'
    ''', (user_id,)).fetchall()

    conn.close()

    # Format and return data
    return jsonify({
        'balance': balance,
        'activities': [dict(act) for act in activities],
        'activeInvestments': [dict(inv) for inv in active_investments]
    })

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')
    
@app.route('/get_profile')
@login_required
def get_profile():
    conn = get_db()
    user = conn.execute('SELECT username, email FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    balance = calculate_user_balance(session['user_id'])

    return jsonify({
        'name': user['username'],
        'email': user['email'],
        'balance': balance
    })

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    new_email = data.get('email')
    new_password = data.get('password')
    if not new_email or not new_password:
        return jsonify({'success': False, 'message': 'Missing fields'}), 400
    hashed_password = generate_password_hash(new_password)
    conn = get_db()
    try:
        conn.execute('UPDATE users SET email = ?, password = ? WHERE id = ?',
                     (new_email, hashed_password, session['user_id']))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Profile update error: {e}")
        return jsonify({'success': False, 'message': 'Failed to update'}), 500
    finally:
        conn.close()

@app.route('/api/deposit', methods=['POST'])
@login_required
def deposit():
    data = request.get_json()
    method = data.get('method')
    amount = data.get('amount')
    if not method or method not in ['crypto', 'bank_transfer', 'mobile_money']:
        return jsonify({'success': False, 'message': 'Invalid deposit method'}), 400
    try:
        amount = float(amount)
        if amount < 200:
            return jsonify({'success': False, 'message': 'Minimum deposit is R200'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid amount'}), 400
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO transactions (user_id, type, method, amount, status) VALUES (?, ?, ?, ?, ?)',
            (session['user_id'], 'deposit', method, amount, 'pending')
        )
        conn.commit()
        balance = conn.execute('''
            SELECT COALESCE(SUM(
                CASE 
                    WHEN type = 'deposit' AND status = 'approved' THEN amount
                    WHEN type = 'withdrawal' AND status = 'approved' THEN -amount
                    ELSE 0
                END), 0)
            FROM transactions WHERE user_id = ?
        ''', (session['user_id'],)).fetchone()[0]
        return jsonify({'success': True, 'message': 'Deposit submitted successfully.', 'newBalance': balance})
    except Exception as e:
        print(f"Deposit error: {e}")
        return jsonify({'success': False, 'message': 'Something went wrong. Try again.'}), 500
    finally:
        conn.close()

@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    data = request.get_json()
    method = data.get('method')
    destination = data.get('destination')
    amount = data.get('amount')

    if not method or method not in ['crypto', 'bank', 'mobile']:
        return jsonify({'success': False, 'message': 'Invalid withdrawal method'}), 400

    try:
        amount = float(amount)
        if amount < 1:
            return jsonify({'success': False, 'message': 'Minimum withdrawal is R1'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid amount'}), 400

    if not destination:
        return jsonify({'success': False, 'message': 'Withdrawal destination is required'}), 400

    balance = calculate_user_balance(session['user_id'])

    if amount > balance:
        return jsonify({'success': False, 'message': 'Insufficient funds'}), 400

    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO transactions (user_id, type, method, destination, amount, status) VALUES (?, ?, ?, ?, ?, ?)',
            (session['user_id'], 'withdrawal', method, destination, amount, 'pending')
        )
        conn.commit()
        return jsonify({'success': True, 'message': 'Withdrawal submitted'})
    except Exception as e:
        print(f"Withdrawal error: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route("/api/my-investments")
@login_required
def get_my_investments():
    user_id = session["user_id"]
    conn = get_db()
    investments = conn.execute('''
        SELECT amount, daily_rate, duration, start_date, status
        FROM investments
        WHERE user_id = ?
        ORDER BY start_date DESC
    ''', (user_id,)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in investments])

@app.route('/api/transactions')
@login_required
def transactions():
    user_id = session.get("user_id")  # 🔥 Add this line!
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM transactions
        WHERE user_id = ?
        ORDER BY timestamp DESC
    ''', (user_id,))
    transactions = cursor.fetchall()
    
    # Get filter params
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    txn_type = request.args.get('type')
    status = request.args.get('status')

    query = "SELECT type, amount, status, timestamp as date FROM transactions WHERE user_id = ?"
    params = [user_id]

    if start_date:
        query += " AND DATE(timestamp) >= DATE(?)"
        params.append(start_date)
    if end_date:
        query += " AND DATE(timestamp) <= DATE(?)"
        params.append(end_date)
    if txn_type:
        query += " AND type = ?"
        params.append(txn_type)
    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY timestamp DESC"

    txns = conn.execute(query, tuple(params)).fetchall()
    conn.close()

    return jsonify({
        'transactions': [dict(row) for row in txns]
    })

@app.route('/verify', methods=['POST'])
@login_required
def verify():
    print("User ID in session:", session.get('user_id'))

    if 'idDocument' not in request.files or 'proofAddress' not in request.files:
        return jsonify({'success': False, 'message': 'Missing required documents'}), 400

    id_file = request.files['idDocument']
    proof_file = request.files['proofAddress']

    allowed_exts = {'pdf', 'png', 'jpg', 'jpeg'}

    def is_valid(file):
        return '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_exts

    if not is_valid(id_file) or not is_valid(proof_file):
        return jsonify({'success': False, 'message': 'Invalid file type. Use JPG, PNG, or PDF.'}), 400

    # Base folder for all FICA files
    base_path = os.path.join('static/fica')

    # User-specific folder (e.g. static/fica/user_123)
    user_folder = os.path.join(base_path, f'user_{session["user_id"]}')
    os.makedirs(user_folder, exist_ok=True)

    # Subfolders inside user folder
    id_docs_folder = os.path.join(user_folder, 'id_docs')
    proof_address_folder = os.path.join(user_folder, 'proof_address')
    images_folder = os.path.join(user_folder, 'images')  # example extra folder

    os.makedirs(id_docs_folder, exist_ok=True)
    os.makedirs(proof_address_folder, exist_ok=True)
    os.makedirs(images_folder, exist_ok=True)

    # Secure filenames and save files
    id_filename = secure_filename(id_file.filename)
    proof_filename = secure_filename(proof_file.filename)

    id_file.save(os.path.join(id_docs_folder, id_filename))
    proof_file.save(os.path.join(proof_address_folder, proof_filename))

    # Update DB verification status
    conn = get_db()
    conn.execute("UPDATE users SET verified = 'pending' WHERE id = ?", (session['user_id'],))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Documents uploaded and verification started.'})

@app.route('/verification')
@login_required
def verification():
    return render_template('verification.html')
    
@app.route('/invitation')
@login_required
def invitation():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    referrals = conn.execute('SELECT * FROM users WHERE referred_by = ?', (user['referral_code'],)).fetchall()
    conn.close()
    return render_template('invitation.html', user=user, referrals=referrals)

@app.route('/api/get-referrals', methods=['GET'])
@login_required
def get_referrals():
    # Retrieve user_id from query parameters
    referral_code = request.args.get('referral_code')

    if not referral_code:
        return jsonify({"success": False, "message": "referral_code is required"}), 400

    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid user ID"}), 400

    # Connect to the database
    conn = get_db()

    # Query users who were referred by the given user_id
    referrals = conn.execute('''
        SELECT id, username, email, full_name, phone, referred_by 
        FROM users 
        WHERE referred_by = ?
    ''', (user_id,)).fetchall()
    
    conn.close()

    # Check if there are referrals
    if not referrals:
        return jsonify({"success": False, "message": "No referrals found"}), 404

    # Format the referral data
    referred_users = [
        {
            "id": referral['id'],
            "username": referral['username'],
            "email": referral['email'],
            "full_name": referral['full_name'],
            "phone": referral['phone'],
            "referred_by": referral['referred_by']
        }
        for referral in referrals
    ]

    return jsonify({"success": True, "referrals": referred_users})

@app.route('/api/get-referral-link')
@login_required
def get_referral_link():
    user_id = request.args.get('referral_code')
    
    try:
        referral_code = int(referral_code)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid user ID"}), 400
    
    # Fetch user from the database using raw SQL
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if user is None:
        return jsonify({"success": False, "message": "User not found"}), 404

    # Generate the referral link
    referral_link = f"/register?ref={user_id}"

    return jsonify({"success": True, "referral_link": referral_link})
    
@app.route("/api/invest", methods=["POST"])
@login_required
def invest():
    data = request.get_json()
    amount = float(data.get("amount"))
    days = int(data.get("days"))
    rate = float(data.get("rate"))
    user_id = session["user_id"]

    try:
        with get_db() as conn:
            c = conn.cursor()

            # Calculate current balance
            c.execute('''
                SELECT COALESCE(SUM(
                    CASE
                        WHEN type = 'deposit' AND status = 'approved' THEN amount
                        WHEN type = 'withdrawal' AND status = 'approved' THEN -amount
                        ELSE 0
                    END), 0)
                FROM transactions WHERE user_id = ?
            ''', (user_id,))
            balance = c.fetchone()[0]

            if balance < amount:
                return jsonify({"success": False, "message": "Insufficient balance"}), 400

            # Record investment
            start_date = datetime.now().strftime("%Y-%m-%d")
            c.execute('''
                INSERT INTO investments (user_id, amount, daily_rate, duration, start_date, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, amount, rate, days, start_date, "active"))

            # Add a negative transaction to simulate balance deduction
            c.execute('''
                INSERT INTO transactions (user_id, type, method, amount, status)
                VALUES (?, 'investment', 'internal', ?, 'approved')
            ''', (user_id, -amount))  # negative amount for investment deduction

            conn.commit()

            # Update the balance after investment
            updated_balance = calculate_user_balance(user_id)

        return jsonify({"success": True, "message": "Investment successful!", "newBalance": updated_balance})
    except Exception as e:
        print("Investment error:", e)
        return jsonify({"success": False, "message": "Server error"}), 500

@app.route('/api/forgot/password', methods=['POST', 'GET'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        # Check if email exists in the system
        if email not in users:
            flash("No account found with this email", "error")
            return redirect(url_for('forgot_password'))

        # Generate a password reset token (this should be more secure in a real app)
        reset_token = ''.join(random.choices(string.ascii_letters + string.digits, k=20))

        # Store the reset token (e.g., in a database or cache for real-time validation)
        # For this example, we'll just print it to the console
        print(f"Password Reset Token for {email}: {reset_token}")

        # Create password reset email
        reset_link = url_for('reset_password', token=reset_token, _external=True)
        msg = Message('Password Reset Request',
                      recipients=[email],
                      body=f"Click the following link to reset your password: {reset_link}")

        try:
            # Send email
            mail.send(msg)
            flash("A password reset link has been sent to your email", "success")
            return redirect(url_for('login'))  # Redirect to login page or display success
        except Exception as e:
            flash(f"Error sending email: {str(e)}", "error")
            return redirect(url_for('forgot_password'))
            return render_template('forgot_password.html')

# Password Reset Route
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['new_password']
        # In a real app, verify token and update the user's password
        print(f"Password reset for token: {token}. New password: {new_password}")
        flash("Your password has been successfully reset", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# Reset Password Page (where users set new password)
@app.route('/reset-password-form', methods=['GET', 'POST'])
def reset_password_form():
    return render_template('reset_password.html')
    
@app.route('/deposit', methods=['GET'])
@login_required
def deposit_page():
    return render_template('deposit.html')
    
@app.route('/investment-levels', methods=['GET'])
def investment_levels():
    return render_template('investment_levels.html')

@app.route('/invitation/maintenance', methods=['GET'])
@login_required
def invitation_maintenance():
    return render_template('invitation_maintenance.html')
    
@app.route('/withdrawal', methods=['GET'])
@login_required
def withdrawal_page():
    return render_template('withdrawal.html')

@app.route('/forgot-password', methods=['GET'])
def forgot_password_page():
    return render_template('forgot_password.html')
    
@app.route('/invest', methods=['GET'])
@login_required
def Invest_page():
    return render_template('invest.html')

@app.route('/investments')
@login_required
def investments():
    return render_template('investments.html')

@app.route('/transactions', methods=['GET'])
@login_required
def transactions_page():
    return render_template('transactions.html')  

@app.route('/about', methods=['GET'])
def about_page():
    return render_template('about.html')  
    
# --- ADMIN ROUTES ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # Simulated admin login (hardcoded)
        if username == 'elvisking@#890' and password == 'Jojo03@1@1':
            session['user_id'] = 0  # Use 0 or any ID you want for simulated admin
            session['username'] = 'admin'
            session['is_admin'] = True
            return jsonify({'success': True, 'message': 'Simulated admin login successful'})
        
        # Otherwise, check real admin user in DB
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND is_admin = 1', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = True
            return jsonify({'success': True})
 
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
@admin_required
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/api/fica')
@admin_required
def admin_get_fica():
    conn = get_db()
    users = conn.execute("SELECT id, username, email, verified FROM users WHERE verified = 'pending'").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/admin/api/fica/<int:user_id>/<string:action>', methods=['POST'])
@admin_required
def admin_fica_action(user_id, action):
    if action not in ('approve', 'reject'):
        return jsonify({'success': False, 'message': 'Invalid action'}), 400
    new_status = 'approved' if action == 'approve' else 'rejected'
    conn = get_db()
    conn.execute("UPDATE users SET verified = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'User verification {new_status}'})

@app.route('/admin/api/deposits', methods=['GET'])
@admin_required
def admin_get_deposits():
    conn = get_db()
    rows = conn.execute("""
        SELECT t.id, u.username AS user, t.amount, t.timestamp, t.method, t.status
        FROM transactions t
        JOIN users u ON u.id = t.user_id
        WHERE t.type = 'deposit' AND t.status = 'pending'
        ORDER BY t.timestamp DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/admin/api/deposits/<int:txn_id>/<string:action>', methods=['POST'])
@admin_required
def admin_deposit_action(txn_id, action):
    if action not in ('approve', 'reject'):
        return jsonify({'success': False, 'message': 'Invalid action'}), 400
    new_status = 'approved' if action == 'approve' else 'rejected'
    conn = get_db()

    # Approve deposit and add funds (by marking approved)
    try:
        # Check deposit exists and is pending
        deposit = conn.execute('SELECT * FROM transactions WHERE id = ? AND type = ?', (txn_id, 'deposit')).fetchone()
        if not deposit:
            conn.close()
            return jsonify({'success': False, 'message': 'Deposit not found'}), 404
        if deposit['status'] == 'approved':
            conn.close()
            return jsonify({'success': False, 'message': 'Deposit already approved'}), 400

        conn.execute("UPDATE transactions SET status = ? WHERE id = ?", (new_status, txn_id))
        conn.commit()
        return jsonify({'success': True, 'message': f'Deposit {new_status}'})
    except Exception as e:
        print("Error approving deposit:", e)
        return jsonify({'success': False, 'message': 'Internal error'}), 500
    finally:
        conn.close()

@app.route('/admin/api/withdrawals', methods=['GET'])
@admin_required
def admin_get_withdrawals():
    conn = get_db()
    rows = conn.execute("""
        SELECT t.id, u.username AS user, t.amount, t.timestamp, t.method, t.destination, t.status
        FROM transactions t
        JOIN users u ON u.id = t.user_id
        WHERE t.type = 'withdrawal' AND t.status = 'pending'
        ORDER BY t.timestamp DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/admin/api/withdrawals/<int:txn_id>/<string:action>', methods=['POST'])
@admin_required
def admin_withdrawal_action(txn_id, action):
    if action not in ('approve', 'reject'):
        return jsonify({'success': False, 'message': 'Invalid action'}), 400
    new_status = 'approved' if action == 'approve' else 'rejected'
    conn = get_db()

    try:
        withdrawal = conn.execute('SELECT * FROM transactions WHERE id = ? AND type = ?', (txn_id, 'withdrawal')).fetchone()
        if not withdrawal:
            conn.close()
            return jsonify({'success': False, 'message': 'Withdrawal not found'}), 404
        if withdrawal['status'] == 'approved':
            conn.close()
            return jsonify({'success': False, 'message': 'Withdrawal already approved'}), 400

        conn.execute("UPDATE transactions SET status = ? WHERE id = ?", (new_status, txn_id))
        conn.commit()
        return jsonify({'success': True, 'message': f'Withdrawal {new_status}'})
    except Exception as e:
        print("Error approving withdrawal:", e)
        return jsonify({'success': False, 'message': 'Internal error'}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
