import os
import json
import datetime
import sqlite3
import time
import re
import random
import string
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
import PyPDF2
import google.generativeai as genai
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import resend

# Try to import python-docx
try:
    from docx import Document
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False
    print("⚠️ python-docx not installed.")

# --- CONFIGURATION ---
resend.api_key = "re_Lxc7NCzq_868MV6REjdK5oxhH1iKv9JiQ"
API_KEY = "AIzaSyDeOV18QvpAOKG7qP9bl51AYuTInBbrClE"

load_dotenv()
app = Flask(__name__)
app.secret_key = "production_grade_secret_key_change_in_prod"

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DATABASE = 'database.db'

# --- OTP STORAGE ---
otp_storage = {}

# --- DATABASE MANAGEMENT ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row 
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                url TEXT NOT NULL,
                uploader TEXT NOT NULL,
                upload_date TEXT NOT NULL,
                category TEXT,
                title TEXT,
                summary TEXT,
                risk_score INTEGER,
                tags TEXT,
                extracted_text TEXT,
                financial_value REAL DEFAULT 0.0,
                status TEXT DEFAULT 'Pending'
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Viewer',
                full_name TEXT
            )
        ''')
        try:
            cursor = db.execute("PRAGMA table_info(users)")
            cols = [col[1] for col in cursor.fetchall()]
            if 'email' not in cols:
                db.execute('ALTER TABLE users ADD COLUMN email TEXT')
                db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)')
        except: pass

        try:
            admin_pass = generate_password_hash("admin123")
            db.execute('INSERT INTO users (username, email, password_hash, role, full_name) VALUES (?, ?, ?, ?, ?)', 
                       ('admin', 'admin@documind.ai', admin_pass, 'Admin', 'System Administrator'))
            db.commit()
        except sqlite3.IntegrityError: pass
        db.commit()

init_db()

# --- AI CONFIG ---
genai.configure(api_key=API_KEY)
model = genai.GenerativeModel("gemini-2.5-flash")

# --- HELPER: PRO EMAIL TEMPLATE ---
def get_email_html(otp_code, purpose="Verification"):
    """Generates a professional, engaging email template."""
    title = "Verify your account"
    message = "Use the code below to complete your registration."
    color = "#4F46E5" # Indigo
    
    if purpose == 'reset':
        title = "Reset Password"
        message = "You requested a password reset. Use this code to proceed."
        color = "#DC2626" # Red
    elif purpose == 'profile_update':
        title = "Confirm Changes"
        message = "Verify your identity to update your profile details."
        color = "#0891B2" # Cyan

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Helvetica Neue', Arial, sans-serif; background-color: #f4f4f5; margin: 0; padding: 0; }}
            .container {{ max-width: 480px; margin: 40px auto; background: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }}
            .header {{ background-color: {color}; padding: 30px 20px; text-align: center; }}
            .header h1 {{ color: white; margin: 0; font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }}
            .content {{ padding: 40px 30px; text-align: center; }}
            .text {{ color: #3f3f46; font-size: 16px; line-height: 1.5; margin-bottom: 25px; }}
            .otp-box {{ background-color: #f4f4f5; border: 2px dashed {color}; border-radius: 12px; padding: 15px; display: inline-block; margin-bottom: 25px; }}
            .otp {{ font-family: 'Courier New', monospace; font-size: 32px; font-weight: 700; color: #18181b; letter-spacing: 5px; margin: 0; }}
            .footer {{ background-color: #fafafa; padding: 20px; text-align: center; color: #a1a1aa; font-size: 12px; border-top: 1px solid #eeeeee; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>DocuMind.ai</h1>
            </div>
            <div class="content">
                <h2 style="color: #18181b; margin-top: 0;">{title}</h2>
                <p class="text">{message}</p>
                <div class="otp-box">
                    <p class="otp">{otp_code}</p>
                </div>
                <p style="color: #71717a; font-size: 13px;">This code will expire in 10 minutes.<br>If you didn't request this, you can safely ignore this email.</p>
            </div>
            <div class="footer">
                &copy; 2025 DocuMind Inc. All rights reserved.
            </div>
        </div>
    </body>
    </html>
    """

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_email_otp(to_email, otp_code, purpose='register'):
    try:
        subject = "DocuMind Verification Code"
        if purpose == 'reset': subject = "Reset Your Password"
        elif purpose == 'profile_update': subject = "Verify Profile Update"
        
        html_content = get_email_html(otp_code, purpose)
        
        r = resend.Emails.send({
            "from": "DocuMind@resend.dev", 
            "to": to_email,
            "subject": subject,
            "html": html_content
        })
        print(f"📧 Email Sent to {to_email}: {r}")
        return True
    except Exception as e:
        print(f"❌ Email Error: {e}")
        return False

def clean_money(val):
    if not val: return 0.0
    try: return float(re.sub(r'[^\d.]', '', str(val)))
    except: return 0.0

def validate_password_strength(password):
    if len(password) < 8: return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
        return False, "Password must contain both letters and numbers."
    return True, None

def analyze_document(text):
    if not text: raise ValueError("File content is empty")
    try:
        prompt = f"""
        Analyze this text. Return ONLY JSON.
        Format:
        {{
            "category": "Finance" | "HR" | "Legal" | "Technical" | "General",
            "title": "Title",
            "summary": "Summary",
            "risk_score": 0-100,
            "financial_value": 0.0,
            "tags": ["tag1"]
        }}
        Text: {text[:15000]}
        """
        resp = model.generate_content(prompt)
        raw = resp.text.strip()
        if raw.startswith('```'):
            raw = raw[raw.find('{'):raw.rfind('}')+1]
        
        try: data = json.loads(raw)
        except: 
            import re
            m = re.search(r'\{.*\}', raw, re.DOTALL)
            data = json.loads(m.group()) if m else {}

        data.setdefault('category', 'General')
        data.setdefault('title', 'Untitled')
        data.setdefault('summary', 'No summary available.')
        data.setdefault('risk_score', 0)
        data.setdefault('financial_value', 0.0)
        data.setdefault('tags', [])
        data['risk_score'] = max(0, min(100, int(data['risk_score'])))
        data['financial_value'] = clean_money(data['financial_value'])
        return data
    except Exception as e:
        raise Exception(f"AI Error: {str(e)}")

def extract_text(path, filename):
    ext = os.path.splitext(filename)[1].lower()
    text = ""
    try:
        if ext == '.pdf':
            with open(path, 'rb') as f:
                for p in PyPDF2.PdfReader(f).pages: text += p.extract_text() or ""
        elif ext == '.docx' and DOCX_AVAILABLE:
            doc = Document(path)
            for p in doc.paragraphs: text += p.text + "\n"
        elif ext == '.txt':
            with open(path, 'r', encoding='utf-8', errors='ignore') as f: text = f.read()
    except Exception as e: raise e
    return text

def valid_file(filename):
    return os.path.splitext(filename)[1].lower() in {'.pdf', '.docx', '.txt'}

# --- AUTH ROUTES ---

@app.route('/')
def login_page():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    purpose = data.get('purpose')
    
    if purpose == 'profile_update' and 'user_id' in session:
        db = get_db()
        user = db.execute('SELECT email FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if user: email = user['email']
    
    if not email: return jsonify({'success': False, 'error': 'Email is required.'})
    
    db = get_db()
    user_exists = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    
    if purpose == 'register' and user_exists:
        return jsonify({'success': False, 'error': 'Email already registered.'})
    if purpose == 'reset' and not user_exists:
        return jsonify({'success': False, 'error': 'Account not found.'})
    
    otp = generate_otp()
    otp_storage[email] = {'code': otp, 'expires': time.time() + 600}
    
    if send_email_otp(email, otp, purpose):
        return jsonify({'success': True, 'message': 'OTP sent.'})
    return jsonify({'success': False, 'error': 'Failed to send email.'})

@app.route('/auth/register', methods=['POST'])
def register():
    username = request.form.get('username').lower()
    email = request.form.get('email').lower()
    password = request.form.get('password')
    full_name = request.form.get('full_name')
    role = request.form.get('role', 'Viewer')
    otp = request.form.get('otp')
    
    rec = otp_storage.get(email)
    if not rec or rec['code'] != otp or time.time() > rec['expires']:
        flash("❌ Invalid or expired OTP.", "error")
        return redirect('/')
        
    is_valid, msg = validate_password_strength(password)
    if not is_valid:
        flash(f"❌ {msg}", "error")
        return redirect('/')

    db = get_db()
    try:
        db.execute('INSERT INTO users (username, email, password_hash, role, full_name) VALUES (?, ?, ?, ?, ?)',
                   (username, email, generate_password_hash(password), role, full_name))
        db.commit()
        del otp_storage[email]
        flash("✅ Registration successful! Login now.", "success")
    except:
        flash("❌ Username or Email already exists.", "error")
    return redirect('/')

@app.route('/auth/login', methods=['POST'])
def login():
    uid = request.form.get('username').lower()
    pw = request.form.get('password')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ? OR email = ?', (uid, uid)).fetchone()
    if user and check_password_hash(user['password_hash'], pw):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['full_name'] = user['full_name']
        session['email'] = user['email']
        return redirect(url_for('dashboard'))
    flash("❌ Invalid credentials.", "error")
    return redirect('/')

# --- PROFILE & API ---

@app.route('/api/update-profile', methods=['POST'])
def upd_profile():
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'Unauthorized'})
    data = request.json or {}
    
    new_full_name = (data.get('full_name') or '').strip()
    new_username = (data.get('username') or '').strip().lower()
    new_email = (data.get('email') or '').strip().lower()
    otp = data.get('otp')
    
    if not new_full_name or not new_username or not new_email:
        return jsonify({'success': False, 'error': 'All fields required.'})
    
    db = get_db()
    current_user = db.execute('SELECT email FROM users WHERE id=?', (session['user_id'],)).fetchone()
    old_email = current_user['email']
    
    if otp:
        rec = otp_storage.get(old_email)
        if not rec or rec['code'] != otp: return jsonify({'success': False, 'error': 'Invalid OTP.'})
    else:
        return jsonify({'success': False, 'error': 'OTP required.'})

    exists = db.execute('SELECT id FROM users WHERE (username=? OR email=?) AND id != ?', 
                        (new_username, new_email, session['user_id'])).fetchone()
    if exists: return jsonify({'success': False, 'error': 'Username or Email taken.'})
    
    try:
        db.execute('UPDATE users SET full_name=?, username=?, email=? WHERE id=?', 
                   (new_full_name, new_username, new_email, session['user_id']))
        db.commit()
        if otp: del otp_storage[old_email]
        session.update({'full_name': new_full_name, 'username': new_username, 'email': new_email})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/change-password', methods=['POST'])
def chg_pw():
    data = request.json
    old_pw = data.get('old_password')
    new_pw = data.get('new_password')
    if not old_pw or not new_pw: return jsonify({'success': False, 'error': 'Fields required.'})
    
    db = get_db()
    user = db.execute('SELECT password_hash FROM users WHERE id=?', (session['user_id'],)).fetchone()
    
    if not check_password_hash(user['password_hash'], old_pw):
        return jsonify({'success': False, 'error': 'Incorrect current password.'})
    is_valid, msg = validate_password_strength(new_pw)
    if not is_valid: return jsonify({'success': False, 'error': msg})
    if check_password_hash(user['password_hash'], new_pw):
        return jsonify({'success': False, 'error': 'New password must be different.'})
        
    db.execute('UPDATE users SET password_hash=? WHERE id=?', (generate_password_hash(new_pw), session['user_id']))
    db.commit()
    return jsonify({'success': True})

# --- RESET PASSWORD (API + FORM FALLBACK) ---
@app.route('/api/reset-password', methods=['POST'])
def api_reset_pw():
    data = request.json
    email = data.get('email', '').strip().lower()
    otp = data.get('otp')
    new_pw = data.get('new_password')
    
    rec = otp_storage.get(email)
    if not rec or rec['code'] != otp: return jsonify({'success': False, 'error': 'Invalid OTP.'})
    
    is_valid, msg = validate_password_strength(new_pw)
    if not is_valid: return jsonify({'success': False, 'error': msg})
    
    db = get_db()
    db.execute('UPDATE users SET password_hash = ? WHERE email = ?', (generate_password_hash(new_pw), email))
    db.commit()
    del otp_storage[email]
    return jsonify({'success': True})

@app.route('/auth/reset-password', methods=['POST'])
def reset_pw_form():
    # Kept for backward compatibility or direct form posts
    email = request.form.get('email').lower()
    otp = request.form.get('otp')
    new_pw = request.form.get('new_password')
    
    rec = otp_storage.get(email)
    if not rec or rec['code'] != otp:
        flash("❌ Invalid OTP.", "error")
        return redirect('/')
        
    db = get_db()
    db.execute('UPDATE users SET password_hash = ? WHERE email = ?', (generate_password_hash(new_pw), email))
    db.commit()
    del otp_storage[email]
    flash("✅ Password reset! Login now.", "success")
    return redirect('/')

# --- UPLOAD & DASHBOARD ---

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session: return redirect('/')
    files = request.files.getlist('files')
    if not files or not files[0].filename: files = request.files.getlist('file')
    valid = [f for f in files if f.filename.strip()]
    if not valid:
        flash("❌ No files.", "error")
        return redirect('/dashboard')
        
    db = get_db()
    user = session['username']
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    
    for f in valid:
        try:
            if not valid_file(f.filename):
                flash(f"❌ {f.filename}: Invalid type.", "error")
                continue
            
            safe_name = secure_filename(f.filename)
            unique_filename = f"{user}_{safe_name}"
            
            exists = db.execute('SELECT id FROM documents WHERE filename = ?', (unique_filename,)).fetchone()
            if exists:
                flash(f"⚠️ {f.filename}: File already exists. Skipped.", "warning")
                continue 
            
            path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            f.save(path)
            
            try: text = extract_text(path, f.filename)
            except: 
                flash(f"❌ {f.filename}: Read error.", "error")
                os.remove(path)
                continue
            
            if len(text.strip()) < 10:
                flash(f"❌ {f.filename}: Empty file.", "error")
                os.remove(path)
                continue

            try: data = analyze_document(text)
            except:
                flash(f"❌ {f.filename}: Analysis failed.", "error")
                os.remove(path)
                continue
                
            cat = data['category']
            if session['role'] not in ['Admin', 'Auditor'] and cat != 'General' and session['role'] != cat:
                flash(f"❌ {f.filename}: Access Denied ({cat}).", "error")
                os.remove(path)
                continue
                
            db.execute('''
                INSERT INTO documents (filename, url, uploader, upload_date, category, title, summary, risk_score, tags, extracted_text, financial_value, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (unique_filename, url_for('static', filename=f'uploads/{unique_filename}'), user, date, cat, data['title'], data['summary'], data['risk_score'], ",".join(data['tags']), text, data['financial_value'], 'Pending'))
            db.commit()
            flash(f"✅ {f.filename}: Processed!", "success")
        except Exception as e:
            flash(f"❌ {f.filename}: Error {e}", "error")
            
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect('/')
    db = get_db()
    user = session['username']
    role = session['role']
    
    if role in ['Admin', 'Auditor']:
        query = 'SELECT * FROM documents WHERE id IN (SELECT MAX(id) FROM documents GROUP BY filename) ORDER BY id DESC'
        rows = db.execute(query).fetchall()
    else:
        query = 'SELECT * FROM documents WHERE uploader = ? AND id IN (SELECT MAX(id) FROM documents WHERE uploader = ? GROUP BY filename) ORDER BY id DESC'
        rows = db.execute(query, (user, user)).fetchall()
        
    docs = []
    for r in rows:
        d = dict(r)
        d['formatted_money'] = f"${d['financial_value']:,.2f}" if d['financial_value'] else None
        d['tag_list'] = [t.strip() for t in d['tags'].split(',')] if d['tags'] else []
        docs.append(d)
    return render_template('dashboard.html', docs=docs, user=session)

@app.route('/profile')
def profile():
    if 'user_id' not in session: return redirect('/')
    db = get_db()
    user_data = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    count = db.execute('SELECT COUNT(*) FROM documents WHERE uploader = ?', (session['username'],)).fetchone()[0]
    val = db.execute('SELECT SUM(financial_value) FROM documents WHERE uploader = ?', (session['username'],)).fetchone()[0] or 0
    recent = db.execute('SELECT * FROM documents WHERE uploader = ? ORDER BY id DESC LIMIT 5', (session['username'],)).fetchall()
    return render_template('profile.html', user=dict(user_data), user_session=session, total_docs=count, total_value=val, recent_uploads=recent)

@app.route('/api/stats')
def stats():
    if 'user_id' not in session: return jsonify({})
    db = get_db()
    user = session['username']
    role = session['role']
    if role in ['Admin', 'Auditor']:
        val = db.execute('SELECT SUM(financial_value) FROM documents').fetchone()[0] or 0
        risk = db.execute('SELECT COUNT(*) FROM documents WHERE risk_score > 70').fetchone()[0]
        pend = db.execute("SELECT COUNT(*) FROM documents WHERE status='Pending'").fetchone()[0]
    else:
        val = db.execute('SELECT SUM(financial_value) FROM documents WHERE uploader=?', (user,)).fetchone()[0] or 0
        risk = db.execute('SELECT COUNT(*) FROM documents WHERE uploader=? AND risk_score>70', (user,)).fetchone()[0]
        pend = db.execute("SELECT COUNT(*) FROM documents WHERE uploader=? AND status='Pending'", (user,)).fetchone()[0]
    return jsonify({"total_value": val, "high_risk": risk, "pending_reviews": pend})

@app.route('/chat', methods=['POST'])
def chat():
    if 'user_id' not in session: return jsonify({"answer": "Login first."}), 401
    q = request.json.get('query')
    if not q: return jsonify({"answer": "Ask something."})
    db = get_db()
    user = session['username']
    if session['role'] in ['Admin', 'Auditor']:
        rows = db.execute('SELECT title, summary, financial_value, category FROM documents LIMIT 50').fetchall()
    else:
        rows = db.execute('SELECT title, summary, financial_value, category FROM documents WHERE uploader=? LIMIT 50', (user,)).fetchall()
    ctx = "\n".join([f"- {r['title']} ({r['category']}): {r['summary']}" for r in rows])
    try:
        ans = model.generate_content(f"Context:\n{ctx}\nUser: {q}\nAnswer:")
        return jsonify({"answer": ans.text})
    except: return jsonify({"answer": "AI Error"})

@app.route('/api/delete-document/<int:id>', methods=['POST'])
def delete_doc(id):
    db = get_db()
    doc = db.execute('SELECT filename FROM documents WHERE id=?', (id,)).fetchone()
    if doc:
        try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], doc['filename']))
        except: pass
        db.execute('DELETE FROM documents WHERE id=?', (id,))
        db.commit()
    return jsonify({'success': True})

@app.route('/api/mark-reviewed/<int:id>', methods=['POST'])
def mark_reviewed(id):
    db = get_db()
    db.execute("UPDATE documents SET status='Reviewed' WHERE id=?", (id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard/value')
def dv(): return redirect('/dashboard')
@app.route('/dashboard/risk')
def dr(): return redirect('/dashboard')
@app.route('/dashboard/pending')
def dp(): return redirect('/dashboard')

if __name__ == '__main__':
    app.run(debug=True)