import os
import json
import datetime
import sqlite3
import time
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
import PyPDF2
import google.generativeai as genai
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Try to import python-docx for .docx support
try:
    from docx import Document
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False
    print("⚠️ python-docx not installed. .docx files will not be supported. Install with: pip install python-docx")

load_dotenv()
app = Flask(__name__)
app.secret_key = "production_grade_secret_key_change_in_prod"

# --- CONFIG ---
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DATABASE = 'database.db'

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
        
        # 1. Documents Table
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
        
        # 2. Users Table (NEW for Production Auth)
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Viewer',
                full_name TEXT
            )
        ''')
        
        # Create a default Admin if not exists (Pass: admin123)
        try:
            admin_pass = generate_password_hash("admin123")
            db.execute('INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)', 
                       ('admin', admin_pass, 'Admin', 'System Administrator'))
            db.commit()
        except sqlite3.IntegrityError:
            pass # Admin already exists

        db.commit()

init_db()

# --- AI CONFIG ---
API_KEY="YOUR_API_KEY_HERE"
genai.configure(api_key=API_KEY)
# Updated to use gemini-2.5-flash (gemini-1.5-flash is deprecated)
model = genai.GenerativeModel("gemini-2.5-flash")

def clean_money(value):
    if not value: return 0.0
    try:
        clean = re.sub(r'[^\d.]', '', str(value))
        return float(clean) if clean else 0.0
    except: return 0.0

def analyze_document(text):
    if not text: 
        print("❌ ERROR: PDF text is empty! PyPDF2 couldn't read the file.")
        raise ValueError("Empty file - no text content found")
    
    try:
        print(f"--- Sending {len(text)} characters to AI... ---")
        
        prompt = f"""
        Analyze this document text and return ONLY valid JSON, no other text.
        
        Required JSON structure:
        {{
            "category": "Finance" or "HR" or "Legal" or "Technical" or "General",
            "title": "Brief document title",
            "summary": "Short summary of the document content",
            "risk_score": number between 0-100,
            "financial_value": number (0 if none),
            "tags": ["tag1", "tag2", "tag3"]
        }}
        
        Document text to analyze:
        {text[:15000]}
        """
        
        response = model.generate_content(prompt)
        
        # DEBUG: Print what AI actually replied
        print(f"AI Response: {response.text[:500]}...") 

        # Clean up the response - remove markdown code blocks if present
        raw = response.text.strip()
        
        # Remove markdown code blocks
        if raw.startswith('```'):
            # Find the start and end of JSON
            start = raw.find('{')
            end = raw.rfind('}') + 1
            if start != -1 and end > start:
                raw = raw[start:end]
            else:
                # Try removing just the code block markers
                raw = raw.replace('```json', '').replace('```', '').strip()
        else:
            # Try to find JSON object in the response
            start = raw.find('{')
            end = raw.rfind('}') + 1
            if start != -1 and end > start:
                raw = raw[start:end]
        
        # Parse JSON
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as je:
            print(f"JSON Parse Error: {je}")
            print(f"Raw response was: {raw[:500]}")
            # Try to extract JSON-like content more aggressively
            import re
            json_match = re.search(r'\{[^{}]*"category"[^{}]*\}', raw, re.DOTALL)
            if json_match:
                try:
                    data = json.loads(json_match.group())
                except:
                    raise ValueError(f"Could not parse AI response as JSON. Error: {je}")
            else:
                raise ValueError(f"AI did not return valid JSON. Response: {raw[:200]}")
        
        # Validate required fields
        required_fields = ['category', 'title', 'summary', 'risk_score', 'financial_value', 'tags']
        for field in required_fields:
            if field not in data:
                print(f"⚠️ Missing field: {field}, using default")
                if field == 'category':
                    data[field] = 'General'
                elif field == 'title':
                    data[field] = 'Untitled Document'
                elif field == 'summary':
                    data[field] = 'No summary available'
                elif field == 'risk_score':
                    data[field] = 0
                elif field == 'financial_value':
                    data[field] = 0.0
                elif field == 'tags':
                    data[field] = []
        
        # Clean and validate data
        data['category'] = str(data.get('category', 'General')).capitalize()
        if data['category'] not in ['Finance', 'HR', 'Legal', 'Technical', 'General']:
            data['category'] = 'General'
        
        data['risk_score'] = int(data.get('risk_score', 0))
        if data['risk_score'] < 0 or data['risk_score'] > 100:
            data['risk_score'] = max(0, min(100, data['risk_score']))
        
        data['financial_value'] = clean_money(data.get('financial_value', 0))
        
        if not isinstance(data.get('tags'), list):
            data['tags'] = []
        
        data['title'] = str(data.get('title', 'Untitled Document'))[:200]
        data['summary'] = str(data.get('summary', 'No summary available'))[:1000]
        
        print(f"✅ Analysis successful: {data['category']} - {data['title']}")
        return data

    except Exception as e:
        print(f"\n🔥 CRITICAL AI ERROR: {e}\n")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        raise Exception(f"Document analysis failed: {str(e)}")
# --- AUTH ROUTES ---

@app.route('/')
def login_page():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/auth/register', methods=['POST'])
def register():
    username = request.form.get('username').lower()
    password = request.form.get('password')
    full_name = request.form.get('full_name')
    role = request.form.get('role', 'Viewer') # In real prod, generic users shouldn't self-select Admin
    
    if not username or not password:
        flash("Username and Password required.", "error")
        return redirect('/')
        
    hashed_pw = generate_password_hash(password)
    
    db = get_db()
    try:
        db.execute('INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)',
                   (username, hashed_pw, role, full_name))
        db.commit()
        flash("✅ Account created! Please login.", "success")
    except sqlite3.IntegrityError:
        flash("❌ Username already taken.", "error")
        
    return redirect('/')

@app.route('/auth/login', methods=['POST'])
def login():
    username = request.form.get('username').lower()
    password = request.form.get('password')
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['full_name'] = user['full_name']
        return redirect(url_for('dashboard'))
    else:
        flash("❌ Invalid credentials.", "error")
        return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# --- CORE ROUTES ---

@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session: return jsonify({})
    db = get_db()
    
    role = session.get('role')
    username = session.get('username')
    
    # Filter based on user role and ownership
    if role in ['Admin', 'Auditor']:
        # Admins/Auditors see all documents
        total_val = db.execute('SELECT SUM(financial_value) FROM documents').fetchone()[0] or 0.0
        high_risk = db.execute('SELECT COUNT(*) FROM documents WHERE risk_score > 70').fetchone()[0]
        pending = db.execute("SELECT COUNT(*) FROM documents WHERE status = 'Pending'").fetchone()[0]
    else:
        # Regular users see ONLY their own uploaded documents (private stats)
        total_val = db.execute('SELECT SUM(financial_value) FROM documents WHERE uploader = ?', (username,)).fetchone()[0] or 0.0
        high_risk = db.execute('SELECT COUNT(*) FROM documents WHERE uploader = ? AND risk_score > 70', (username,)).fetchone()[0]
        pending = db.execute("SELECT COUNT(*) FROM documents WHERE uploader = ? AND status = 'Pending'", (username,)).fetchone()[0]
    
    return jsonify({
        "total_value": total_val,
        "high_risk": high_risk,
        "pending_reviews": pending
    })

@app.route('/chat', methods=['POST'])
def chat():
    if 'user_id' not in session: return jsonify({"answer": "Please login first."}), 401
    
    data = request.get_json()
    query = data.get('query')
    
    if not query:
        return jsonify({"answer": "Please type a question."})

    db = get_db()
    role = session.get('role')
    username = session.get('username')
    
    # RAG: Get relevant context (filtered by user)
    if role in ['Admin', 'Auditor']:
        rows = db.execute('SELECT title, summary, financial_value, category, tags FROM documents LIMIT 50').fetchall()
    else:
        # Regular users only see their own documents in chat context
        rows = db.execute('SELECT title, summary, financial_value, category, tags FROM documents WHERE uploader = ? LIMIT 50', (username,)).fetchall()
    
    context = "\n".join([f"- [{r['category']}] {r['title']} (${r['financial_value']}): {r['summary']} Tags: {r['tags']}" for r in rows])
    
    prompt = f"""
    You are the AI assistant for DocuMind.
    User Question: {query}
    
    Database Context:
    {context}
    
    Instructions:
    1. Answer based strictly on the context provided.
    2. If the user asks for totals, sum them carefully.
    3. Keep answers professional and concise.
    """
    
    try:
        resp = model.generate_content(prompt)
        return jsonify({"answer": resp.text})
    except Exception as e:
        print(e)
        return jsonify({"answer": "I'm having trouble connecting to the AI brain right now."})

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect('/')
    
    documents = [] 
    try:
        db = get_db()
        role = session.get('role')
        username = session.get('username')
        
        # Filter documents based on user role and ownership
        if role in ['Admin', 'Auditor']:
            # Admins/Auditors see all documents
            rows = db.execute('SELECT * FROM documents ORDER BY id DESC').fetchall()
        else:
            # Regular users see ONLY their own uploaded documents (private dashboard)
            rows = db.execute('''
                SELECT * FROM documents 
                WHERE uploader = ?
                ORDER BY id DESC
            ''', (username,)).fetchall()
        
        for row in rows:
            try:
                d = dict(row)
                
                # --- SAFETY FIXES (Prevents crashes) ---
                
                # 1. Ensure Risk Score is a number (Default to 0 if None)
                if d.get('risk_score') is None:
                    d['risk_score'] = 0
                else:
                    d['risk_score'] = int(d['risk_score'])

                # 2. Ensure Financial Value is a number
                if d.get('financial_value') is None:
                    d['financial_value'] = 0.0
                
                # 3. Format Money String
                if d['financial_value'] > 0:
                    d['formatted_money'] = "${:,.2f}".format(d['financial_value'])
                else:
                    d['formatted_money'] = None

                # 4. Safe Tag Parsing
                raw_tags = d.get('tags')
                if raw_tags:
                    clean = str(raw_tags).replace("'", "").replace('"', "").replace('[', '').replace(']', '')
                    d['tag_list'] = [t.strip() for t in clean.split(',') if t.strip()]
                else:
                    d['tag_list'] = []

                documents.append(d)
                    
            except Exception as row_e:
                print(f"Skipping bad row: {row_e}")
                continue

    except Exception as e:
        print(f"Dashboard DB Error: {e}")
        documents = []

    return render_template('dashboard.html', docs=documents, user=session)

@app.route('/profile')
def profile():
    if 'user_id' not in session: return redirect('/')
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Get user statistics
    total_docs = db.execute('SELECT COUNT(*) FROM documents WHERE uploader = ?', (session.get('username'),)).fetchone()[0]
    total_value = db.execute('SELECT SUM(financial_value) FROM documents WHERE uploader = ?', (session.get('username'),)).fetchone()[0] or 0.0
    
    # Get recent uploads
    recent_uploads = db.execute('''
        SELECT id, filename, upload_date, category, title 
        FROM documents 
        WHERE uploader = ? 
        ORDER BY id DESC 
        LIMIT 10
    ''', (session.get('username'),)).fetchall()
    
    return render_template('profile.html', 
                         user=dict(user) if user else {}, 
                         user_session=session,
                         total_docs=total_docs,
                         total_value=total_value,
                         recent_uploads=recent_uploads)

@app.route('/dashboard/value')
def dashboard_value():
    """Detailed view of documents with financial value"""
    if 'user_id' not in session: return redirect('/')
    
    documents = []
    try:
        db = get_db()
        role = session.get('role')
        username = session.get('username')
        
        if role in ['Admin', 'Auditor']:
            rows = db.execute('''
                SELECT * FROM documents 
                WHERE financial_value > 0
                ORDER BY financial_value DESC
            ''').fetchall()
        else:
            rows = db.execute('''
                SELECT * FROM documents 
                WHERE uploader = ? AND financial_value > 0
                ORDER BY financial_value DESC
            ''', (username,)).fetchall()
        
        for row in rows:
            d = dict(row)
            d['risk_score'] = int(d.get('risk_score') or 0)
            d['financial_value'] = float(d.get('financial_value') or 0.0)
            d['formatted_money'] = "${:,.2f}".format(d['financial_value']) if d['financial_value'] > 0 else None
            raw_tags = d.get('tags', '')
            if raw_tags:
                clean = str(raw_tags).replace("'", "").replace('"', "").replace('[', '').replace(']', '')
                d['tag_list'] = [t.strip() for t in clean.split(',') if t.strip()]
            else:
                d['tag_list'] = []
            documents.append(d)
    except Exception as e:
        print(f"Error: {e}")
    
    total_value = sum(d['financial_value'] for d in documents)
    return render_template('dashboard_detail.html', 
                         docs=documents, 
                         user=session,
                         title="Financial Value Documents",
                         subtitle=f"Total Value: ${total_value:,.2f}",
                         icon="fa-dollar-sign",
                         color="green")

@app.route('/dashboard/risk')
def dashboard_risk():
    """Detailed view of high-risk documents"""
    if 'user_id' not in session: return redirect('/')
    
    documents = []
    try:
        db = get_db()
        role = session.get('role')
        username = session.get('username')
        
        if role in ['Admin', 'Auditor']:
            rows = db.execute('''
                SELECT * FROM documents 
                WHERE risk_score > 70
                ORDER BY risk_score DESC
            ''').fetchall()
        else:
            rows = db.execute('''
                SELECT * FROM documents 
                WHERE uploader = ? AND risk_score > 70
                ORDER BY risk_score DESC
            ''', (username,)).fetchall()
        
        for row in rows:
            d = dict(row)
            d['risk_score'] = int(d.get('risk_score') or 0)
            d['financial_value'] = float(d.get('financial_value') or 0.0)
            d['formatted_money'] = "${:,.2f}".format(d['financial_value']) if d['financial_value'] > 0 else None
            raw_tags = d.get('tags', '')
            if raw_tags:
                clean = str(raw_tags).replace("'", "").replace('"', "").replace('[', '').replace(']', '')
                d['tag_list'] = [t.strip() for t in clean.split(',') if t.strip()]
            else:
                d['tag_list'] = []
            documents.append(d)
    except Exception as e:
        print(f"Error: {e}")
    
    return render_template('dashboard_detail.html', 
                         docs=documents, 
                         user=session,
                         title="High Risk Documents",
                         subtitle=f"{len(documents)} documents requiring attention",
                         icon="fa-exclamation-triangle",
                         color="red")

@app.route('/dashboard/pending')
def dashboard_pending():
    """Detailed view of pending documents"""
    if 'user_id' not in session: return redirect('/')
    
    documents = []
    try:
        db = get_db()
        role = session.get('role')
        username = session.get('username')
        
        if role in ['Admin', 'Auditor']:
            rows = db.execute('''
                SELECT * FROM documents 
                WHERE status = 'Pending'
                ORDER BY id DESC
            ''').fetchall()
        else:
            rows = db.execute('''
                SELECT * FROM documents 
                WHERE uploader = ? AND status = 'Pending'
                ORDER BY id DESC
            ''', (username,)).fetchall()
        
        for row in rows:
            d = dict(row)
            d['risk_score'] = int(d.get('risk_score') or 0)
            d['financial_value'] = float(d.get('financial_value') or 0.0)
            d['formatted_money'] = "${:,.2f}".format(d['financial_value']) if d['financial_value'] > 0 else None
            raw_tags = d.get('tags', '')
            if raw_tags:
                clean = str(raw_tags).replace("'", "").replace('"', "").replace('[', '').replace(']', '')
                d['tag_list'] = [t.strip() for t in clean.split(',') if t.strip()]
            else:
                d['tag_list'] = []
            documents.append(d)
    except Exception as e:
        print(f"Error: {e}")
    
    return render_template('dashboard_detail.html', 
                         docs=documents, 
                         user=session,
                         title="Pending Documents",
                         subtitle=f"{len(documents)} documents awaiting review",
                         icon="fa-clock",
                         color="yellow")


def extract_text_from_file(file_path, filename):
    """Extract text from .pdf, .docx, or .txt files"""
    file_ext = os.path.splitext(filename)[1].lower()
    text = ""
    
    try:
        if file_ext == '.pdf':
            with open(file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                for page in pdf.pages:
                    text += page.extract_text() or ""
        
        elif file_ext == '.docx':
            if DOCX_AVAILABLE:
                doc = Document(file_path)
                for paragraph in doc.paragraphs:
                    text += paragraph.text + "\n"
            else:
                raise Exception("python-docx library not installed. Cannot read .docx files.")
        
        elif file_ext == '.txt':
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        
        else:
            raise Exception(f"Unsupported file type: {file_ext}")
            
    except Exception as e:
        print(f"Text extraction error for {filename}: {e}")
        raise e
    
    return text

def is_valid_file_type(filename):
    """Check if file extension is allowed"""
    allowed_extensions = {'.pdf', '.docx', '.txt'}
    file_ext = os.path.splitext(filename)[1].lower()
    return file_ext in allowed_extensions

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session: return redirect('/')
    
    # Get all files from the request - try both 'files' (multiple) and 'file' (single) for compatibility
    files = request.files.getlist('files')
    
    # If no files found with 'files', try 'file' (fallback for single file)
    if not files or all(not f.filename or f.filename.strip() == '' for f in files):
        files = request.files.getlist('file')
    
    # Debug: Check what we received
    print(f"DEBUG: Received {len(files)} file(s)")
    for f in files:
        print(f"DEBUG: File - filename: '{f.filename}', content_type: '{f.content_type}'")
    
    # Filter out empty files
    valid_files = [f for f in files if f and f.filename and f.filename.strip()]
    
    if not valid_files:
        flash("❌ No files selected.", "error")
        return redirect(url_for('dashboard'))
    
    db = get_db()
    role = session.get('role')
    username = session.get('username')
    upload_date = datetime.datetime.now().strftime("%Y-%m-%d")
    
    success_count = 0
    failed_files = []
    
    for file in valid_files:
        
        filename = file.filename
        file_path = None
        
        try:
            # 1. Validate file type
            if not is_valid_file_type(filename):
                failed_files.append(f"{filename} (Invalid file type - only .pdf, .docx, .txt allowed)")
                continue
            
            # 2. Save file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Handle duplicate filenames
            counter = 1
            base_name, ext = os.path.splitext(filename)
            while os.path.exists(file_path):
                new_filename = f"{base_name}_{counter}{ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                filename = new_filename
                counter += 1
            
            file.save(file_path)
            
            # 3. Extract Text
            try:
                text = extract_text_from_file(file_path, filename)
                if not text or len(text.strip()) < 10:
                    raise ValueError("File appears to be empty or unreadable. The file may be corrupted, password-protected, or contain only images.")
            except Exception as e:
                # Failed to extract text - mark as failed
                failed_files.append(f"{filename} (Text extraction failed: {str(e)})")
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except:
                        pass
                continue
            
            # 4. AI Analysis
            try:
                data = analyze_document(text)
                cat = data.get('category', 'General')
            except Exception as e:
                # AI analysis failed - don't save the document
                error_msg = str(e)
                print(f"❌ Analysis failed for {filename}: {error_msg}")
                failed_files.append(f"{filename} (Analysis failed: {error_msg})")
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except:
                        pass
                continue
            
            # 5. Jurisdiction Check
            if role not in ['Admin', 'Auditor'] and cat != 'General' and role != cat:
                time.sleep(0.5)
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except PermissionError:
                    pass
                failed_files.append(f"{filename} (Access Denied: {role} cannot upload {cat} documents)")
                continue
            
            # 6. Save to Database (successful upload)
            db.execute('''
                INSERT INTO documents (filename, url, uploader, upload_date, category, title, summary, risk_score, tags, extracted_text, financial_value, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (filename, url_for('static', filename=f'uploads/{filename}'), username, upload_date, cat, data.get('title'), data.get('summary'), data.get('risk_score'), ",".join(data.get('tags', [])), text, data.get('financial_value'), 'Pending'))
            db.commit()
            success_count += 1
            
        except Exception as e:
            print(f"Error processing {filename}: {e}")
            failed_files.append(f"{filename} (Upload failed: {str(e)})")
            # Clean up file if it was saved
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass
    
    # Flash messages
    if success_count > 0:
        flash(f"✅ {success_count} document(s) uploaded and analyzed successfully!", "success")
    
    if failed_files:
        for failed in failed_files:
            flash(f"❌ {failed}", "error")
    
    return redirect(url_for('dashboard'))

@app.route('/api/mark-reviewed/<int:doc_id>', methods=['POST'])
def mark_reviewed(doc_id):
    """Mark a document as reviewed when user views its analysis"""
    if 'user_id' not in session: 
        return jsonify({"error": "Not authorized"}), 401
    
    db = get_db()
    role = session.get('role')
    username = session.get('username')
    
    # Verify document belongs to user (or user is Admin/Auditor)
    doc = db.execute('SELECT * FROM documents WHERE id = ?', (doc_id,)).fetchone()
    
    if not doc:
        return jsonify({"error": "Document not found"}), 404
    
    # Check permissions
    if role not in ['Admin', 'Auditor'] and doc['uploader'] != username:
        return jsonify({"error": "Not authorized"}), 403
    
    # Update status to Reviewed
    db.execute('UPDATE documents SET status = ? WHERE id = ?', ('Reviewed', doc_id))
    db.commit()
    
    return jsonify({"success": True, "status": "Reviewed"})

@app.route('/api/delete-document/<int:doc_id>', methods=['POST'])
def delete_document(doc_id):
    """Delete a document - users can only delete their own documents"""
    if 'user_id' not in session: 
        return jsonify({"error": "Not authorized"}), 401
    
    db = get_db()
    role = session.get('role')
    username = session.get('username')
    
    # Get document info
    doc = db.execute('SELECT * FROM documents WHERE id = ?', (doc_id,)).fetchone()
    
    if not doc:
        return jsonify({"error": "Document not found"}), 404
    
    # Check permissions - users can only delete their own documents (unless Admin/Auditor)
    if role not in ['Admin', 'Auditor'] and doc['uploader'] != username:
        return jsonify({"error": "Not authorized to delete this document"}), 403
    
    try:
        # Delete physical file
        filename = doc['filename']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Warning: Could not delete file {file_path}: {e}")
        
        # Delete from database
        db.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
        db.commit()
        
        return jsonify({"success": True, "message": "Document deleted successfully"})
    
    except Exception as e:
        print(f"Error deleting document: {e}")
        return jsonify({"error": f"Failed to delete document: {str(e)}"}), 500

# --- PROFILE UPDATE ROUTE ---
@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated.'}), 401

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user:
        return jsonify({'success': False, 'error': 'User not found.'}), 404

    data = request.get_json() or {}
    new_full_name = (data.get('full_name') or '').strip()
    new_username = (data.get('username') or '').strip().lower()

    if not new_full_name or not new_username:
        return jsonify({'success': False, 'error': 'Full name and username are required.'}), 400

    old_username = user['username']

    # If username changed, ensure availability
    if new_username != old_username:
        exists = db.execute('SELECT id FROM users WHERE username = ? AND id != ?', (new_username, user['id'])).fetchone()
        if exists:
            return jsonify({'success': False, 'error': 'Username already taken.'}), 409

    try:
        # Update user record
        db.execute('UPDATE users SET full_name = ?, username = ? WHERE id = ?', (new_full_name, new_username, user['id']))

        # If username changed, update documents.uploader so uploaded files remain associated
        if new_username != old_username:
            db.execute('UPDATE documents SET uploader = ? WHERE uploader = ?', (new_username, old_username))

        db.commit()

        # Update session values so UI and subsequent requests use the new username
        session['full_name'] = new_full_name
        session['username'] = new_username

        return jsonify({'success': True, 'message': 'Profile updated successfully.', 'full_name': new_full_name, 'username': new_username})

    except Exception as e:
        db.rollback()
        print(f"Error updating profile: {e}")
        return jsonify({'success': False, 'error': 'Failed to update profile.'}), 500

# --- CHANGE PASSWORD ROUTE ---
@app.route('/api/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated.'}), 401
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user:
        return jsonify({'success': False, 'error': 'User not found.'}), 404
    data = request.get_json()
    old_pw = data.get('old_password', '')
    new_pw = data.get('new_password', '')
    confirm_pw = data.get('confirm_password', '')
    if not old_pw or not new_pw or not confirm_pw:
        return jsonify({'success': False, 'error': 'All fields are required.'}), 400
    if new_pw != confirm_pw:
        return jsonify({'success': False, 'error': 'New passwords do not match.'}), 400
    if not check_password_hash(user['password_hash'], old_pw):
        return jsonify({'success': False, 'error': 'Old password is incorrect.'}), 403
    db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (generate_password_hash(new_pw), user['id']))
    db.commit()
    return jsonify({'success': True, 'message': 'Password changed successfully.'})

# --- FORGOT PASSWORD ROUTE (stub, for demo) ---
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    db = get_db()
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    if not username:
        return jsonify({'success': False, 'error': 'Username required.'}), 400
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        return jsonify({'success': False, 'error': 'User not found.'}), 404
    # For demo: just return success (in real app, send email or code)
    return jsonify({'success': True, 'message': 'Password reset link sent (demo).', 'username': username})

if __name__ == '__main__':
    app.run(debug=True)
