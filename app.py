# =============== IMPORTANT: Production Deployment Notes ===============
# 1. For production, change SECRET_KEY to a strong random string
# 2. Database: SQLite works for testing, but consider PostgreSQL for production
# 3. File uploads: 5MB limit set, stored locally (ephemeral on Render)
# 4. WhatsApp: Currently simulated in console (logs only)
# ======================================================================

import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file, send_from_directory
from flask_cors import CORS
from flask_talisman import Talisman
from dotenv import load_dotenv
import sqlite3
import datetime
import secrets
import hashlib
import pandas as pd
from werkzeug.utils import secure_filename
import traceback
import logging
from functools import wraps

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Security configuration
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production-2024')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# File upload configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

# Security headers for production
if os.environ.get('FLASK_ENV') == 'production':
    Talisman(app, content_security_policy={
        'default-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "code.jquery.com", "cdn.datatables.net"],
        'style-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "cdn.datatables.net"],
        'script-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "code.jquery.com", "cdn.datatables.net"],
        'font-src': ["'self'", "cdnjs.cloudflare.com"]
    })

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============== DATABASE FUNCTIONS ===============
def init_db():
    """Initialize database with all tables"""
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Create technicians table
        c.execute('''CREATE TABLE IF NOT EXISTS technicians (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL UNIQUE,
            code TEXT NOT NULL UNIQUE,
            email TEXT,
            username TEXT UNIQUE,
            password TEXT,
            points_balance INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            whatsapp_sent BOOLEAN DEFAULT 0,
            last_login TIMESTAMP
        )''')
        
        # Create invoices table
        c.execute('''CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technician_id INTEGER NOT NULL,
            invoice_number TEXT NOT NULL,
            invoice_date DATE NOT NULL,
            invoice_amount REAL NOT NULL,
            vendor_name TEXT,
            items_description TEXT,
            file_path TEXT,
            status TEXT DEFAULT 'pending',
            points_awarded INTEGER DEFAULT 0,
            admin_notes TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP,
            reviewed_by INTEGER,
            FOREIGN KEY (technician_id) REFERENCES technicians(id)
        )''')
        
        # Create points_history table
        c.execute('''CREATE TABLE IF NOT EXISTS points_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technician_id INTEGER NOT NULL,
            invoice_id INTEGER,
            points_change INTEGER NOT NULL,
            description TEXT,
            balance_after INTEGER NOT NULL,
            transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (technician_id) REFERENCES technicians(id),
            FOREIGN KEY (invoice_id) REFERENCES invoices(id)
        )''')
        
        # Create admin table
        c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Create rewards table
        c.execute('''CREATE TABLE IF NOT EXISTS rewards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            points_required INTEGER NOT NULL,
            category TEXT,
            stock INTEGER DEFAULT 1,
            expiry_date DATE,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Create sessions table for better session management
        c.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT NOT NULL,
            user_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )''')
        
        # Insert default admin if not exists
        try:
            c.execute("SELECT id FROM admin_users WHERE username = 'admin'")
            if not c.fetchone():
                c.execute("INSERT INTO admin_users (username, password, role) VALUES (?, ?, ?)", 
                          ('admin', hash_password('admin123'), 'superadmin'))
                logger.info("Default admin created: admin/admin123")
        except Exception as e:
            logger.warning(f"Could not create default admin: {e}")
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")

def get_db_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def backup_database():
    """Create a backup of the database"""
    try:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f'database_backup_{timestamp}.db'
        import shutil
        shutil.copy2('database.db', backup_file)
        logger.info(f"Database backup created: {backup_file}")
        return backup_file
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        return None

# =============== HELPER FUNCTIONS ===============
def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_username(name):
    """Generate unique username from name"""
    base = name.lower().replace(' ', '.')
    return f"{base}.{secrets.randbelow(1000):03d}"

def generate_password():
    """Generate secure random password"""
    return secrets.token_urlsafe(10)

def generate_code():
    """Generate unique technician code"""
    return f"TECH-{datetime.datetime.now().strftime('%Y%m%d')}-{secrets.randbelow(10000):04d}"

def calculate_points(amount):
    """Calculate points based on invoice amount"""
    if amount < 100:
        return 0
    elif amount < 500:
        return int(amount / 10)
    elif amount < 1000:
        return int(amount / 10) + 10
    else:
        return int(amount / 10) + 20

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_whatsapp_message(phone, message):
    """Simulate WhatsApp message sending (logs to console)"""
    try:
        logger.info("\n" + "="*50)
        logger.info("📱 WHATSAPP MESSAGE (SIMULATION)")
        logger.info("="*50)
        logger.info(f"To: +{phone}")
        logger.info(f"Message: {message}")
        logger.info("="*50 + "\n")
        
        # In production, integrate with Twilio WhatsApp API or similar
        # Example with Twilio (uncomment and configure):
        # from twilio.rest import Client
        # account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
        # auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
        # client = Client(account_sid, auth_token)
        # message = client.messages.create(
        #     from_='whatsapp:+14155238886',  # Twilio WhatsApp number
        #     body=message,
        #     to=f'whatsapp:+{phone}'
        # )
        
        return True
    except Exception as e:
        logger.error(f"WhatsApp sending failed: {e}")
        return False

# =============== DECORATORS ===============
def technician_required(f):
    """Decorator to require technician login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'technician_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Authentication required'}), 401
            return redirect('/technician/login')
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            if request.is_json:
                return jsonify({'success': False, 'message': 'Admin access required'}), 403
            return redirect('/admin')
        return f(*args, **kwargs)
    return decorated_function

# =============== ROUTES ===============

@app.route('/')
def home():
    """Homepage - Technician Registration"""
    return render_template('index.html')

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.now().isoformat(),
        'service': 'technician-loyalty-portal'
    })

@app.route('/api/register', methods=['POST'])
def register():
    """Register new technician"""
    try:
        data = request.json
        
        # Validate required fields
        if not data.get('name') or not data.get('phone'):
            return jsonify({'success': False, 'message': 'Name and phone are required'})
        
        # Validate phone number (10 digits)
        phone = data['phone'].strip()
        if not phone.isdigit() or len(phone) != 10:
            return jsonify({'success': False, 'message': 'Invalid phone number. Must be 10 digits'})
        
        # Generate credentials
        code = generate_code()
        username = generate_username(data['name'])
        password = generate_password()
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # Check if phone already exists
        c.execute("SELECT id FROM technicians WHERE phone = ?", (phone,))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Phone number already registered'})
        
        # Insert technician
        c.execute('''INSERT INTO technicians (name, phone, code, email, username, password, points_balance) 
                     VALUES (?, ?, ?, ?, ?, ?, 0)''',
                  (data['name'], phone, code, data.get('email', ''), username, hash_password(password)))
        
        tech_id = c.lastrowid
        
        # Create welcome message
        login_url = request.host_url + 'technician/login'
        message = f"""🎉 Welcome {data['name']}!

Your Technician Portal Credentials:
• Username: {username}
• Password: {password}
• Loyalty Code: {code}

Login at: {login_url}

Start uploading invoices to earn points! 📊

For assistance, contact support.
"""
        
        # Send WhatsApp (simulated)
        send_whatsapp_message(phone, message)
        
        c.execute("UPDATE technicians SET whatsapp_sent = 1 WHERE id = ?", (tech_id,))
        conn.commit()
        conn.close()
        
        logger.info(f"New technician registered: {data['name']} (ID: {tech_id})")
        
        return jsonify({
            'success': True,
            'message': 'Registration successful! Check WhatsApp for login credentials.',
            'code': code,
            'username': username
        })
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed. Please try again.'})

@app.route('/technician/login', methods=['GET', 'POST'])
def technician_login():
    """Technician login page and API"""
    if request.method == 'GET':
        return render_template('technician_login.html')
    
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute('''SELECT * FROM technicians 
                     WHERE username = ? AND password = ? AND status = 'active' ''',
                  (username, hash_password(password)))
        technician = c.fetchone()
        
        if technician:
            # Update last login
            c.execute("UPDATE technicians SET last_login = CURRENT_TIMESTAMP WHERE id = ?", 
                     (technician['id'],))
            conn.commit()
            
            # Set session
            session['technician_id'] = technician['id']
            session['technician_name'] = technician['name']
            session['technician_code'] = technician['code']
            
            logger.info(f"Technician logged in: {technician['name']} (ID: {technician['id']})")
            
            return jsonify({
                'success': True,
                'message': 'Login successful'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid credentials or account inactive'
            })
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed. Please try again.'})

@app.route('/technician/dashboard')
@technician_required
def technician_dashboard():
    """Technician dashboard"""
    technician_id = session['technician_id']
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get technician details
    c.execute("SELECT * FROM technicians WHERE id = ?", (technician_id,))
    technician = dict(c.fetchone())
    
    # Get technician's invoices
    c.execute('''SELECT * FROM invoices 
                 WHERE technician_id = ? 
                 ORDER BY uploaded_at DESC''', (technician_id,))
    invoices = [dict(row) for row in c.fetchall()]
    
    # Get points history
    c.execute('''SELECT * FROM points_history 
                 WHERE technician_id = ? 
                 ORDER BY transaction_date DESC LIMIT 20''', (technician_id,))
    points_history = [dict(row) for row in c.fetchall()]
    
    # Calculate stats
    total_invoices = len(invoices)
    pending_invoices = len([i for i in invoices if i['status'] == 'pending'])
    approved_invoices = len([i for i in invoices if i['status'] == 'approved'])
    
    conn.close()
    
    return render_template('technician_portal.html',
                         technician=technician,
                         invoices=invoices,
                         points_history=points_history,
                         total_invoices=total_invoices,
                         pending_invoices=pending_invoices,
                         approved_invoices=approved_invoices)

@app.route('/api/upload-invoice', methods=['POST'])
@technician_required
def upload_invoice():
    """Upload invoice for review"""
    try:
        technician_id = session['technician_id']
        
        # Validate form data
        required_fields = ['invoice_number', 'invoice_date', 'invoice_amount', 'items_description']
        for field in required_fields:
            if not request.form.get(field):
                return jsonify({'success': False, 'message': f'{field} is required'})
        
        # Parse data
        invoice_number = request.form.get('invoice_number').strip()
        invoice_date = request.form.get('invoice_date')
        invoice_amount = float(request.form.get('invoice_amount'))
        vendor_name = request.form.get('vendor_name', '').strip()
        items_description = request.form.get('items_description').strip()
        
        # Validate amount
        if invoice_amount <= 0:
            return jsonify({'success': False, 'message': 'Amount must be positive'})
        
        # Validate file
        if 'invoice_image' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'})
        
        file = request.files['invoice_image']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})
        
        if not (file and allowed_file(file.filename)):
            return jsonify({'success': False, 'message': 'Invalid file type. Allowed: JPG, PNG, PDF'})
        
        # Save file
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = secure_filename(f"{technician_id}_{timestamp}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # Insert invoice
        c.execute('''INSERT INTO invoices 
                     (technician_id, invoice_number, invoice_date, invoice_amount, 
                      vendor_name, items_description, file_path, status) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')''',
                  (technician_id, invoice_number, invoice_date, invoice_amount,
                   vendor_name, items_description, filename))
        
        invoice_id = c.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"Invoice uploaded: #{invoice_number} by technician {technician_id}")
        
        return jsonify({
            'success': True,
            'message': 'Invoice uploaded successfully! It will be reviewed by admin.',
            'invoice_number': invoice_number,
            'invoice_id': invoice_id
        })
        
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid amount format'})
    except Exception as e:
        logger.error(f"Invoice upload error: {e}")
        return jsonify({'success': False, 'message': 'Upload failed. Please try again.'})

@app.route('/api/invoice/<int:invoice_id>')
@technician_required
def get_invoice(invoice_id):
    """Get invoice details"""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''SELECT * FROM invoices 
                 WHERE id = ? AND technician_id = ?''', 
              (invoice_id, session['technician_id']))
    invoice = c.fetchone()
    
    if invoice:
        invoice_dict = dict(invoice)
        
        # Get technician info
        c.execute("SELECT name, code FROM technicians WHERE id = ?", (invoice_dict['technician_id'],))
        tech = c.fetchone()
        if tech:
            invoice_dict['tech_name'] = tech['name']
            invoice_dict['tech_code'] = tech['code']
        
        conn.close()
        return jsonify({'success': True, 'invoice': invoice_dict})
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'Invoice not found'})

@app.route('/api/cancel-invoice/<int:invoice_id>', methods=['POST'])
@technician_required
def cancel_invoice(invoice_id):
    """Cancel pending invoice"""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''SELECT * FROM invoices 
                 WHERE id = ? AND technician_id = ? AND status = 'pending' ''',
              (invoice_id, session['technician_id']))
    
    invoice = c.fetchone()
    if invoice:
        c.execute("UPDATE invoices SET status = 'cancelled' WHERE id = ?", (invoice_id,))
        conn.commit()
        conn.close()
        
        logger.info(f"Invoice cancelled: {invoice_id}")
        return jsonify({'success': True, 'message': 'Invoice cancelled successfully'})
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'Cannot cancel invoice'})

@app.route('/technician/logout')
def technician_logout():
    """Logout technician"""
    session.clear()
    return redirect('/technician/login')

# =============== ADMIN ROUTES ===============

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'GET':
        return render_template('admin_login.html')
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT * FROM admin_users WHERE username = ? AND password = ?",
              (username, hash_password(password)))
    admin = c.fetchone()
    conn.close()
    
    if admin:
        session['admin_logged_in'] = True
        session['admin_username'] = admin['username']
        session['admin_id'] = admin['id']
        
        logger.info(f"Admin logged in: {username}")
        return redirect('/admin/dashboard')
    
    flash('Invalid credentials')
    return redirect('/admin')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get technicians
    c.execute("SELECT * FROM technicians ORDER BY registration_date DESC")
    technicians = [dict(row) for row in c.fetchall()]
    
    # Get invoices with technician info
    c.execute('''SELECT i.*, t.name as tech_name, t.code as tech_code 
                 FROM invoices i 
                 JOIN technicians t ON i.technician_id = t.id 
                 ORDER BY i.uploaded_at DESC''')
    invoices = [dict(row) for row in c.fetchall()]
    
    # Get statistics
    c.execute("SELECT COUNT(*) FROM technicians")
    total_tech = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM invoices")
    total_invoices = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM invoices WHERE status = 'pending'")
    pending_invoices = c.fetchone()[0]
    
    c.execute("SELECT SUM(invoice_amount) FROM invoices WHERE status = 'approved'")
    total_amount = c.fetchone()[0] or 0
    
    conn.close()
    
    return render_template('admin_panel.html',
                         admin_username=session.get('admin_username'),
                         technicians=technicians,
                         invoices=invoices,
                         total_tech=total_tech,
                         total_invoices=total_invoices,
                         pending_invoices=pending_invoices,
                         total_amount=total_amount)

@app.route('/admin/approve_invoice', methods=['POST'])
@admin_required
def approve_invoice():
    """Approve invoice and award points"""
    try:
        invoice_id = request.form.get('invoice_id')
        points = int(request.form.get('points', 0))
        reason = request.form.get('reason', 'Invoice approved').strip()
        notify = request.form.get('notify', 'false') == 'true'
        
        if not invoice_id:
            return jsonify({'success': False, 'message': 'Invoice ID required'})
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # Get invoice with technician details
        c.execute('''SELECT i.*, t.name, t.phone, t.points_balance 
                     FROM invoices i 
                     JOIN technicians t ON i.technician_id = t.id 
                     WHERE i.id = ?''', (invoice_id,))
        invoice = c.fetchone()
        
        if not invoice:
            return jsonify({'success': False, 'message': 'Invoice not found'})
        
        if invoice['status'] != 'pending':
            return jsonify({'success': False, 'message': 'Invoice already processed'})
        
        # Calculate points if not provided
        if points <= 0:
            points = calculate_points(invoice['invoice_amount'])
        
        # Update invoice
        c.execute('''UPDATE invoices 
                     SET status = 'approved', 
                         points_awarded = ?,
                         reviewed_at = CURRENT_TIMESTAMP,
                         reviewed_by = ?
                     WHERE id = ?''', 
                  (points, session.get('admin_id'), invoice_id))
        
        # Update technician points
        new_balance = invoice['points_balance'] + points
        c.execute("UPDATE technicians SET points_balance = ? WHERE id = ?",
                  (new_balance, invoice['technician_id']))
        
        # Record in points history
        c.execute('''INSERT INTO points_history 
                     (technician_id, invoice_id, points_change, description, balance_after) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (invoice['technician_id'], invoice_id, points, reason, new_balance))
        
        conn.commit()
        
        # Send notification
        if notify:
            message = f"""✅ Invoice Approved!

Invoice #{invoice['invoice_number']} has been approved.
Amount: ₹{invoice['invoice_amount']:.2f}
Points Awarded: {points} points
New Balance: {new_balance} points

Thank you for your submission!"""
            
            send_whatsapp_message(invoice['phone'], message)
        
        conn.close()
        
        logger.info(f"Invoice approved: #{invoice_id}, Points: {points}")
        
        return jsonify({
            'success': True,
            'message': f'Invoice approved! {points} points awarded.',
            'points': points,
            'new_balance': new_balance
        })
        
    except Exception as e:
        logger.error(f"Invoice approval error: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/reject_invoice', methods=['POST'])
@admin_required
def reject_invoice():
    """Reject invoice"""
    try:
        invoice_id = request.form.get('invoice_id')
        reason = request.form.get('reason', '').strip()
        notify = request.form.get('notify', 'false') == 'true'
        
        if not invoice_id:
            return jsonify({'success': False, 'message': 'Invoice ID required'})
        
        if not reason:
            return jsonify({'success': False, 'message': 'Reason is required for rejection'})
        
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute('''SELECT i.*, t.name, t.phone 
                     FROM invoices i 
                     JOIN technicians t ON i.technician_id = t.id 
                     WHERE i.id = ?''', (invoice_id,))
        invoice = c.fetchone()
        
        if not invoice:
            return jsonify({'success': False, 'message': 'Invoice not found'})
        
        if invoice['status'] != 'pending':
            return jsonify({'success': False, 'message': 'Invoice already processed'})
        
        # Update invoice
        c.execute('''UPDATE invoices 
                     SET status = 'rejected', 
                         admin_notes = ?,
                         reviewed_at = CURRENT_TIMESTAMP,
                         reviewed_by = ?
                     WHERE id = ?''', 
                  (reason, session.get('admin_id'), invoice_id))
        
        conn.commit()
        
        # Send notification
        if notify:
            message = f"""⚠️ Invoice Requires Attention

Invoice #{invoice['invoice_number']} requires review.

Reason: {reason}

Please check your dashboard for details."""
            
            send_whatsapp_message(invoice['phone'], message)
        
        conn.close()
        
        logger.info(f"Invoice rejected: #{invoice_id}, Reason: {reason[:50]}...")
        
        return jsonify({
            'success': True,
            'message': 'Invoice rejected successfully'
        })
        
    except Exception as e:
        logger.error(f"Invoice rejection error: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/send_whatsapp', methods=['POST'])
@admin_required
def admin_send_whatsapp():
    """Send WhatsApp message from admin"""
    phone = request.form.get('phone', '').strip()
    message = request.form.get('message', '').strip()
    
    if not phone or not message:
        return jsonify({'success': False, 'message': 'Phone and message required'})
    
    # Validate phone (10 digits)
    if not phone.isdigit() or len(phone) != 10:
        return jsonify({'success': False, 'message': 'Invalid phone number'})
    
    success = send_whatsapp_message(phone, message)
    
    if success:
        logger.info(f"Admin WhatsApp sent to {phone}")
        return jsonify({'success': True, 'message': 'WhatsApp message sent (simulated)'})
    else:
        return jsonify({'success': False, 'message': 'Failed to send message'})

@app.route('/admin/quick_approve', methods=['POST'])
@admin_required
def quick_approve():
    """Quick approve with default points"""
    invoice_id = request.form.get('invoice_id')
    
    if not invoice_id:
        return jsonify({'success': False, 'message': 'Invoice ID required'})
    
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''SELECT i.*, t.points_balance 
                 FROM invoices i 
                 JOIN technicians t ON i.technician_id = t.id 
                 WHERE i.id = ? AND i.status = 'pending' ''', (invoice_id,))
    invoice = c.fetchone()
    
    if not invoice:
        return jsonify({'success': False, 'message': 'Invoice not found or already processed'})
    
    points = calculate_points(invoice['invoice_amount'])
    new_balance = invoice['points_balance'] + points
    
    # Update invoice
    c.execute('''UPDATE invoices 
                 SET status = 'approved', 
                     points_awarded = ?,
                     reviewed_at = CURRENT_TIMESTAMP,
                     reviewed_by = ?
                 WHERE id = ?''', 
              (points, session.get('admin_id'), invoice_id))
    
    # Update technician points
    c.execute("UPDATE technicians SET points_balance = ? WHERE id = ?",
              (new_balance, invoice['technician_id']))
    
    # Record in points history
    c.execute('''INSERT INTO points_history 
                 (technician_id, invoice_id, points_change, description, balance_after) 
                 VALUES (?, ?, ?, ?, ?)''',
              (invoice['technician_id'], invoice_id, points, 'Quick approval', new_balance))
    
    conn.commit()
    conn.close()
    
    logger.info(f"Quick approve: #{invoice_id}, Points: {points}")
    
    return jsonify({
        'success': True,
        'message': f'Quick approved! {points} points awarded.',
        'points': points
    })

@app.route('/admin/export/<data_type>')
@admin_required
def export_data(data_type):
    """Export data to Excel"""
    if data_type == 'technicians':
        conn = get_db_connection()
        df = pd.read_sql_query("SELECT * FROM technicians ORDER BY registration_date DESC", conn)
        conn.close()
        
        filename = f'technicians_{datetime.datetime.now().strftime("%Y%m%d")}.xlsx'
        excel_path = f'temp_{filename}'
        df.to_excel(excel_path, index=False)
        
        logger.info(f"Exported technicians data: {filename}")
        
        return send_file(excel_path, as_attachment=True, download_name=filename)
    
    elif data_type == 'invoices':
        conn = get_db_connection()
        df = pd.read_sql_query('''SELECT i.*, t.name as technician_name, t.code as technician_code 
                                   FROM invoices i 
                                   JOIN technicians t ON i.technician_id = t.id 
                                   ORDER BY i.uploaded_at DESC''', conn)
        conn.close()
        
        filename = f'invoices_{datetime.datetime.now().strftime("%Y%m%d")}.xlsx'
        excel_path = f'temp_{filename}'
        df.to_excel(excel_path, index=False)
        
        logger.info(f"Exported invoices data: {filename}")
        
        return send_file(excel_path, as_attachment=True, download_name=filename)
    
    else:
        return jsonify({'success': False, 'message': 'Invalid data type'})

@app.route('/admin/backup')
@admin_required
def admin_backup():
    """Create database backup"""
    backup_file = backup_database()
    if backup_file:
        return send_file(backup_file, as_attachment=True)
    else:
        flash('Backup failed')
        return redirect('/admin/dashboard')

@app.route('/admin/logout')
def admin_logout():
    """Logout admin"""
    session.clear()
    return redirect('/admin')

# =============== STATIC FILES & UPLOADS ===============

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return "File not found", 404

@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

# =============== ERROR HANDLERS ===============

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Server error: {error}")
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Internal server error'}), 500
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large(error):
    """Handle file too large errors"""
    return jsonify({'success': False, 'message': 'File too large (max 5MB)'}), 413

# =============== APPLICATION STARTUP ===============

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Print startup information
    print("\n" + "="*60)
    print("🤖 TECHNICIAN LOYALTY PORTAL v1.0")
    print("="*60)
    print("\n✅ System Ready! Access URLs:")
    print("   👤 Technician Registration: http://localhost:5000")
    print("   🔐 Technician Login:        http://localhost:5000/technician/login")
    print("   👑 Admin Panel:             http://localhost:5000/admin")
    print("   🔑 Admin Login:             admin / admin123")
    print("\n📱 WhatsApp messages are simulated in console/logs")
    print("="*60 + "\n")
    
    # Get port from environment or default
    port = int(os.environ.get('PORT', 5000))
    
    # Run application
    app.run(
        host='0.0.0.0',
        port=port,
        debug=os.environ.get('FLASK_ENV') != 'production'
    )