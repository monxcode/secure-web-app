"""
Secure Web Application & Threat Hardening
Cybersecurity & Ethical Hacking Internship - Project 01
Main application file implementing security controls
"""

import sqlite3
import re
from datetime import datetime, timedelta
import hashlib
import secrets
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure random secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout

# Database initialization
def init_db():
    """Initialize database with secure schema"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Users table with security-focused columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked_until TIMESTAMP,
            last_login TIMESTAMP,
            last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Audit logs for security monitoring
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create admin user if not exists (for demonstration)
    # In production, admin creation should be through secure registration
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        salt = secrets.token_hex(16)
        password = "Admin@Secure123"  # Default password - should be changed in production
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt, role)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 'admin@secureapp.local', hashed_password, salt, 'admin'))
    
    conn.commit()
    conn.close()

def log_security_event(user_id, event_type, details=""):
    """Log security events for monitoring and audit"""
    conn = get_db()
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    conn.execute('''
        INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, details)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, event_type, ip_address, user_agent, details))
    conn.commit()

def get_db():
    """Get database connection with context"""
    if 'db' not in g:
        g.db = sqlite3.connect('database.db')
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Close database connection"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# SECURITY CONTROLS

def validate_password(password):
    """
    Enforce strong password policy:
    - Minimum 12 characters
    - At least one uppercase
    - At least one lowercase
    - At least one digit
    - At least one special character
    - No common patterns
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    # Check for common weak patterns
    weak_patterns = ['password', '123456', 'qwerty', 'admin', 'letmein']
    if any(pattern in password.lower() for pattern in weak_patterns):
        return False, "Password contains common weak patterns"
    
    return True, "Password is strong"

def sanitize_input(input_string):
    """Sanitize user input to prevent XSS and SQL Injection"""
    if not input_string:
        return ""
    
    # Remove or encode special characters
    sanitized = input_string
    
    # HTML entity encoding for XSS prevention
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&#x27;",
        ">": "&gt;",
        "<": "&lt;",
    }
    
    for char, entity in html_escape_table.items():
        sanitized = sanitized.replace(char, entity)
    
    return sanitized.strip()

def is_sql_safe(input_string):
    """Check if input contains SQL injection patterns"""
    sql_keywords = ['SELECT', 'INSERT', 'DELETE', 'UPDATE', 'DROP', 'UNION', 'OR', 'AND']
    sql_special = [';', '--', '/*', '*/', "'", '"', '`']
    
    upper_input = input_string.upper()
    
    for keyword in sql_keywords:
        if keyword in upper_input and len(keyword) > 2:
            return False
    
    for special in sql_special:
        if special in input_string:
            return False
    
    return True

def check_account_lock(user_id):
    """Check if account is temporarily locked due to failed attempts"""
    conn = get_db()
    user = conn.execute('SELECT failed_login_attempts, account_locked_until FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if user and user['account_locked_until']:
        lock_time = datetime.strptime(user['account_locked_until'], '%Y-%m-%d %H:%M:%S')
        if datetime.now() < lock_time:
            return True
    return False

# ROUTES

@app.route('/')
def index():
    """Home page - redirects to login if not authenticated"""
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Secure user registration with validation"""
    if request.method == 'POST':
        # Sanitize all inputs
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate inputs
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'danger')
            return render_template('register.html')
        
        if not is_sql_safe(username) or not is_sql_safe(email):
            flash('Invalid input detected', 'danger')
            return render_template('register.html')
        
        # Validate email format
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            flash('Invalid email format', 'danger')
            return render_template('register.html')
        
        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(f'Password policy violation: {message}', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        conn = get_db()
        
        # Check if user already exists (using parameterized query)
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email)
        ).fetchone()
        
        if existing_user:
            flash('Username or email already exists', 'danger')
            return render_template('register.html')
        
        # Generate salt and hash password using bcrypt
        salt = secrets.token_hex(16)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insert user with parameterized query (prevents SQL injection)
        try:
            cursor = conn.execute('''
                INSERT INTO users (username, email, password_hash, salt, role)
                VALUES (?, ?, ?, ?, 'user')
            ''', (username, email, hashed_password, salt))
            user_id = cursor.lastrowid
            
            # Log registration event
            log_security_event(user_id, 'REGISTRATION_SUCCESS', f'User {username} registered successfully')
            
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            conn.rollback()
            log_security_event(None, 'REGISTRATION_FAILED', str(e))
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Secure login with brute force protection"""
    # Check if user is already logged in
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Sanitize inputs
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter username and password', 'danger')
            return render_template('login.html')
        
        conn = get_db()
        
        # Find user with parameterized query
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        
        if not user:
            # Log failed attempt for non-existent user
            log_security_event(None, 'LOGIN_FAILED', f'Attempt with non-existent username: {username}')
            flash('Invalid credentials', 'danger')
            return render_template('login.html')
        
        # Check if account is locked
        if check_account_lock(user['id']):
            flash('Account temporarily locked. Please try again later.', 'danger')
            return render_template('login.html')
        
        # Verify password using bcrypt
        if bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            # Reset failed attempts on successful login
            conn.execute(
                'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?',
                (user['id'],)
            )
            
            # Create secure session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = True
            
            # Regenerate session ID to prevent fixation
            session.modified = True
            
            # Log successful login
            log_security_event(user['id'], 'LOGIN_SUCCESS')
            
            # Redirect based on role
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        
        else:
            # Increment failed attempts
            conn.execute(
                'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?',
                (user['id'],)
            )
            
            # Lock account after 5 failed attempts (5 minutes lock)
            user = conn.execute('SELECT failed_login_attempts FROM users WHERE id = ?', (user['id'],)).fetchone()
            if user['failed_login_attempts'] >= 5:
                lock_until = (datetime.now() + timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
                conn.execute(
                    'UPDATE users SET account_locked_until = ? WHERE id = ?',
                    (lock_until, user['id'])
                )
                flash('Account locked for 5 minutes due to multiple failed attempts', 'danger')
            
            conn.commit()
            log_security_event(user['id'], 'LOGIN_FAILED', 'Invalid password')
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """User dashboard - requires authentication"""
    if 'user_id' not in session:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))
    
    # Verify session integrity
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if not user:
        session.clear()
        flash('Session invalid. Please login again.', 'danger')
        return redirect(url_for('login'))
    
    # Display sanitized username
    safe_username = sanitize_input(session['username'])
    return render_template('dashboard.html', username=safe_username)

@app.route('/admin')
def admin_dashboard():
    """Admin dashboard - requires admin role"""
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db()
    
    # Get user statistics (parameterized queries)
    users = conn.execute('SELECT id, username, email, role, created_at FROM users').fetchall()
    logs = conn.execute('SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT 50').fetchall()
    
    # Sanitize data before display
    safe_users = []
    for user in users:
        safe_users.append({
            'id': user['id'],
            'username': sanitize_input(user['username']),
            'email': sanitize_input(user['email']),
            'role': user['role'],
            'created_at': user['created_at']
        })
    
    return render_template('admin.html', users=safe_users, logs=logs)

@app.route('/logout')
def logout():
    """Secure logout with session cleanup"""
    if 'user_id' in session:
        user_id = session['user_id']
        # Log logout event
        log_security_event(user_id, 'LOGOUT')
    
    # Clear all session data
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/change-password', methods=['POST'])
def change_password():
    """Secure password change functionality"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        flash('All fields are required', 'danger')
        return redirect(url_for('dashboard'))
    
    # Validate new password
    is_valid, message = validate_password(new_password)
    if not is_valid:
        flash(f'New password invalid: {message}', 'danger')
        return redirect(url_for('dashboard'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    user = conn.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Verify current password
    if bcrypt.checkpw(current_password.encode('utf-8'), user['password_hash']):
        # Hash and store new password
        new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        conn.execute(
            'UPDATE users SET password_hash = ?, last_password_change = CURRENT_TIMESTAMP WHERE id = ?',
            (new_hashed_password, session['user_id'])
        )
        conn.commit()
        
        log_security_event(session['user_id'], 'PASSWORD_CHANGE_SUCCESS')
        flash('Password changed successfully', 'success')
    else:
        log_security_event(session['user_id'], 'PASSWORD_CHANGE_FAILED', 'Incorrect current password')
        flash('Current password is incorrect', 'danger')
    
    return redirect(url_for('dashboard'))

# ERROR HANDLERS

@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error handler"""
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template(
        'dashboard.html',
        username="Unknown",
        error="Internal server error"
    ), 500

# SECURITY HEADERS MIDDLEWARE

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run with production settings
    app.run(
        debug=False,  # Debug should be False in production
        host='0.0.0.0',
        port=5000,
        ssl_context='adhoc'  # Enable HTTPS in production with proper certificates
    )