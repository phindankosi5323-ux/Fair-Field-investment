from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
import re

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change for production!
DATABASE = 'app.db'

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
        if 'user_id' not in session:
            return redirect(url_for('login'))
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
            
            hashed_password = generate_password_hash(data['password'])
            referral_code = str(uuid.uuid4())[:8]
            
            conn.execute(
                '''INSERT INTO users 
                (username, password, email, full_name, phone, id_number, gender, dob, address, country, referral_code, verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (data['username'], hashed_password, data['email'], data['fullName'],
                 data['phone'], data['idNumber'], data['gender'], data['dob'],
                 data['address'], data['country'], referral_code, 'unverified')
            )
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Registration successful'})
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

@app.route('/deposit', methods=['GET'])
@login_required
def deposit_page():
    return render_template('deposit.html')

@app.route('/withdrawal', methods=['GET'])
@login_required
def withdrawal_page():
    return render_template('withdrawal.html')

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
        if username == 'admin' and password == 'admin123':
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
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/api/fica')
def admin_get_fica():
    conn = get_db()
    users = conn.execute("SELECT id, username, email, verified FROM users WHERE verified = 'pending'").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/admin/api/fica/<int:user_id>/<string:action>', methods=['POST'])
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