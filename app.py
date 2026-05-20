import os
import time
import sqlite3
from datetime import datetime
from flask import Flask, request, render_template, jsonify, flash, redirect, url_for
from werkzeug.utils import secure_filename
import requests
from dotenv import load_dotenv

from user_storage import add_user, user_exists  # Import user_storage functions

# Initialize Flask
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv('VT_API_KEY')
if not VT_API_KEY:
    raise Exception("❌ VirusTotal API Key not found! Please set it in .env file.")
VT_HEADERS = {"x-apikey": VT_API_KEY}

# Database initialization
def init_db():
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            scan_type TEXT,
            target TEXT,
            file_hash TEXT,
            status TEXT,
            result TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suspicious_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            target TEXT,
            email TEXT,
            issue TEXT
        )
    """)
    conn.commit()
    conn.close()

# Initialize database tables on app startup
init_db()

# ----------- Helper Functions -----------

def scan_url_with_virustotal(url):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(scan_url, headers=VT_HEADERS, data={"url": url})

    if response.status_code == 401:
        return {"error": "Unauthorized. Check your VirusTotal API key."}
    elif response.status_code != 200:
        return {"error": f"VirusTotal scan failed. Status: {response.status_code}"}

    data_id = response.json()["data"]["id"]

    report_url = f"https://www.virustotal.com/api/v3/analyses/{data_id}"

    # Polling for analysis completion
    max_attempts = 10
    attempt = 0
    while attempt < max_attempts:
        report_response = requests.get(report_url, headers=VT_HEADERS)
        if report_response.status_code != 200:
            return {"error": "Failed to retrieve analysis report."}
        result = report_response.json()
        status = result.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            scan_result = result.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = scan_result.get("malicious", 0)
            harmless = scan_result.get("harmless", 0)
            return {
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "URL",
                "target": url,
                "status": "Completed",
                "result": f"Malicious: {malicious} | Clean: {harmless}",
                "malicious": malicious,
                "harmless": harmless
            }
        else:
            time.sleep(3)
            attempt += 1

    return {"error": "Analysis timed out. Please try again later."}

def save_scan_to_db(scan_type, target, status, result):
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (date, scan_type, target, status, result) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_type, target, status, result)
    )
    conn.commit()
    conn.close()

def save_report_to_db(name, target, email, issue):
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO suspicious_reports (name, target, email, issue) VALUES (?, ?, ?, ?)",
        (name, target, email, issue)
    )
    conn.commit()
    conn.close()

# ----------- Routes -----------

@app.route('/')
def index():
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, date, scan_type, target, status, result FROM scan_history ORDER BY id DESC LIMIT 3")
    records = cursor.fetchall()
    conn.close()
    # Parse malicious count for each record
    parsed_records = []
    for record in records:
        malicious = 0
        if record[5]:
            parts = record[5].split('|')
            for part in parts:
                if 'Malicious:' in part:
                    try:
                        malicious = int(part.split(':')[1].strip())
                    except:
                        malicious = 0
        # Append a dict instead of tuple for easier template access
        parsed_records.append({
            'record': record,
            'malicious': malicious
        })
    return render_template('index.html', scan_history=parsed_records)

@app.route('/full-history')
def full_history():
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, date, scan_type, target, status, result FROM scan_history ORDER BY id DESC")
    records = cursor.fetchall()
    conn.close()
    # Parse malicious count for each record
    parsed_records = []
    for record in records:
        malicious = 0
        if record[5]:
            parts = record[5].split('|')
            for part in parts:
                if 'Malicious:' in part:
                    try:
                        malicious = int(part.split(':')[1].strip())
                    except:
                        malicious = 0
        parsed_records.append({
            'record': record,
            'malicious': malicious
        })
    return render_template('full_history.html', scan_history=parsed_records)

from flask import jsonify

@app.route('/scan-url', methods=['POST'])
def scan_url():
    url = request.form.get('url')
    result = scan_url_with_virustotal(url)

    scan_data = {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "URL",
        "target": url,
        "status": "Completed" if 'result' in result else "Failed",
        "result": result.get("result", result.get("error", "Error during scan")),
        "malicious": result.get("malicious", 0),
        "harmless": result.get("harmless", 0)
    }

    save_scan_to_db(scan_data['type'], scan_data['target'], scan_data['status'], scan_data['result'])

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Return JSON response for AJAX requests
        return jsonify(scan_data)

    if 'result' in result:
        flash("✅ URL scanned successfully! Result: " + scan_data['result'], "url_scan")
    else:
        flash(f"❌ URL scan failed: {result.get('error', 'Unknown error')}", "url_scan")

    return redirect(url_for('index') + '#scan-section')

@app.route('/scan_file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        flash("❌ No file part in the request.", "file_scan")
        return redirect(url_for('index') + '#scan-section')

    file = request.files['file']
    if file.filename == '':
        flash("⚠️ No file selected.", "file_scan")
        return redirect(url_for('index') + '#scan-section')

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    # Fix for Windows path issue: use absolute path with forward slashes
    abs_file_path = os.path.abspath(file_path).replace("\\", "/")

    # Fix for Windows path issue: open file using raw string path
    raw_path = r"{}".format(abs_file_path)

    # Upload file to VirusTotal for scanning
    with open(raw_path, 'rb') as f:
        files = {'file': (filename, f)}
        response = requests.post('https://www.virustotal.com/api/v3/files', headers=VT_HEADERS, files=files)

    if response.status_code != 200:
        flash(f"❌ File scan failed. Status: {response.status_code}", "file_scan")
        return redirect(url_for('index') + '#scan-section')

    data = response.json()
    data_id = data.get('data', {}).get('id')
    file_hash = data.get('data', {}).get('attributes', {}).get('sha256')  # Extract SHA-256 hash

    if not data_id:
        flash("❌ Failed to get scan ID from VirusTotal.", "file_scan")
        return redirect(url_for('index') + '#scan-section')

    report_url = f"https://www.virustotal.com/api/v3/analyses/{data_id}"

    # Polling for analysis completion
    max_attempts = 10
    attempt = 0
    scan_result = None
    malicious = 0
    harmless = 0
    while attempt < max_attempts:
        report_response = requests.get(report_url, headers=VT_HEADERS)
        if report_response.status_code != 200:
            flash("❌ Failed to retrieve analysis report.", "file_scan")
            return redirect(url_for('index') + '#scan-section')
        result = report_response.json()
        status = result.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            scan_stats = result.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = scan_stats.get("malicious", 0)
            harmless = scan_stats.get("harmless", 0)
            scan_result = f"Malicious: {malicious} | Clean: {harmless}"
            break
        else:
            time.sleep(3)
            attempt += 1

    if scan_result is None:
        flash("❌ Analysis timed out. Please try again later.", "file_scan")
        return redirect(url_for('index') + '#scan-section')

    scan_data = {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "File",
        "target": filename,
        "file_hash": file_hash,  # Store the SHA-256 hash
        "status": "Completed",
        "result": scan_result,
        "malicious": malicious,
        "harmless": harmless
    }

    # Save scan data including file_hash in the database
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    # Check if scan_history table has file_hash column, else fallback to storing in result
    try:
        cursor.execute("INSERT INTO scan_history (date, scan_type, target, file_hash, status, result) VALUES (?, ?, ?, ?, ?, ?)",
                       (scan_data['date'], scan_data['type'], scan_data['target'], scan_data['file_hash'], scan_data['status'], scan_data['result']))
    except sqlite3.OperationalError:
        # If file_hash column does not exist, store file_hash in result field appended
        result_with_hash = scan_data['result'] + f" | SHA256: {scan_data['file_hash']}"
        cursor.execute("INSERT INTO scan_history (date, scan_type, target, status, result) VALUES (?, ?, ?, ?, ?)",
                       (scan_data['date'], scan_data['type'], scan_data['target'], scan_data['status'], result_with_hash))
    conn.commit()
    conn.close()

    flash("✅ File scanned successfully! Result: " + scan_data['result'], "file_scan")
    return redirect(url_for('index') + '#scan-section')

@app.route('/report', methods=['POST'])
def report():
    name = request.form.get('name')
    target = request.form.get('target')
    email = request.form.get('email')
    issue = request.form.get('message')

    if name and target and email and issue:
        save_report_to_db(name, target, email, issue)
        flash("Your report has been submitted successfully!", "report")
    else:
        flash("Please fill in all fields.", "report")

    return redirect(url_for('index') + "#contact")


# ----------- Run App -----------

@app.route('/scan_report/<int:scan_id>')
def scan_report(scan_id):
    def fetch_virustotal_file_details(file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=VT_HEADERS)
        if response.status_code != 200:
            return {}
        data = response.json().get("data", {}).get("attributes", {})
        # Extract relevant fields with fallback to None
        return {
            "md5": data.get("md5"),
            "sha1": data.get("sha1"),
            "sha256": data.get("sha256"),
            "ssdeep": data.get("ssdeep"),
            "tlsh": data.get("tlsh"),
            "file_type": data.get("type_description"),
            "source": data.get("meaningful_name"),
            "magic": data.get("magic"),
            "trid": data.get("trid", {}).get("file_type", None) if data.get("trid") else None,
            "magika": data.get("magik", None),  # Note: field name might differ
            "file_size": data.get("size")
        }

    def fetch_virustotal_url_details(url_id):
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(url, headers=VT_HEADERS)
        if response.status_code != 200:
            return {}
        data = response.json().get("data", {}).get("attributes", {})
        # Extract relevant URL details
        return {
            "last_final_url": data.get("last_final_url"),
            "reputation": data.get("reputation"),
            "categories": data.get("categories"),
            "last_analysis_stats": data.get("last_analysis_stats"),
            "last_analysis_results": data.get("last_analysis_results")
        }

    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, date, scan_type, target, status, result FROM scan_history WHERE id = ?", (scan_id,))
    record = cursor.fetchone()
    conn.close()
    if record is None:
        return "Scan report not found", 404
    # Convert tuple to dict for template usage
    scan_dict = {
        'id': record[0],
        'date': record[1],
        'scan_type': record[2],
        'target': record[3],
        'status': record[4],
        'result': record[5]
    }
    # Parse malicious and harmless counts from result string
    malicious = 0
    harmless = 0
    file_hash = None
    if scan_dict['result']:
        parts = scan_dict['result'].split('|')
        for part in parts:
            if 'Malicious:' in part:
                try:
                    malicious = int(part.split(':')[1].strip())
                except:
                    malicious = 0
            elif 'Clean:' in part:
                try:
                    harmless = int(part.split(':')[1].strip())
                except:
                    harmless = 0
            elif 'SHA256:' in part:
                try:
                    file_hash = part.split(':')[1].strip()
                except:
                    file_hash = None
    scan_dict['malicious'] = malicious
    scan_dict['harmless'] = harmless

    # Determine file hash to query VirusTotal
    if not file_hash:
        # Fallback: check if target looks like a hash
        target = scan_dict.get('target')
        if target:
            if len(target) == 64 and all(c in '0123456789abcdefABCDEF' for c in target):
                file_hash = target.lower()
            elif len(target) == 32 and all(c in '0123456789abcdefABCDEF' for c in target):
                file_hash = target.lower()

    # Fetch file or URL details from VirusTotal
    file_details = {}
    url_details = {}
    if scan_dict['scan_type'].lower() == 'file' and file_hash:
        file_details = fetch_virustotal_file_details(file_hash)
    elif scan_dict['scan_type'].lower() == 'url':
        # For URL, encode target to URL ID format used by VirusTotal (base64 without padding)
        import base64
        url_id = base64.urlsafe_b64encode(scan_dict['target'].encode()).decode().rstrip("=")
        url_details = fetch_virustotal_url_details(url_id)

    # Merge file details into scan_dict with fallback to None
    scan_dict.update({
        "md5": file_details.get("md5"),
        "sha1": file_details.get("sha1"),
        "sha256": file_details.get("sha256"),
        "ssdeep": file_details.get("ssdeep"),
        "tlsh": file_details.get("tlsh"),
        "file_type": file_details.get("file_type"),
        "source": file_details.get("source"),
        "magic": file_details.get("magic"),
        "trid": file_details.get("trid"),
        "magika": file_details.get("magika"),
        "file_size": file_details.get("file_size"),
        "url_last_final_url": url_details.get("last_final_url"),
        "url_reputation": url_details.get("reputation"),
        "url_categories": url_details.get("categories"),
        "url_last_analysis_stats": url_details.get("last_analysis_stats"),
        "url_last_analysis_results": url_details.get("last_analysis_results")
    })

    return render_template('report_detail.html', scan=scan_dict)

from flask import send_file
import io

@app.route('/download_report/<int:scan_id>')
def download_report(scan_id):
    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()
    cursor.execute("SELECT result FROM scan_history WHERE id = ?", (scan_id,))
    record = cursor.fetchone()
    conn.close()
    if record is None:
        return "Report not found", 404
    report_content = record[0]
    # Create a BytesIO stream and write the report content
    buffer = io.BytesIO()
    buffer.write(report_content.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"scan_report_{scan_id}.txt", mimetype='text/plain')

@app.route('/rescan/<int:scan_id>')
def rescan(scan_id):
    # Implement rescan logic here, for now just redirect to index or show a message
    flash(f"Rescan requested for scan ID {scan_id}. Feature not implemented yet.", "info")
    return redirect(url_for('index'))

from flask import render_template, request

@app.route('/login')
def login():
    action = request.args.get('action', 'login')
    return render_template('login.html', action=action)

from flask import request, redirect, url_for, flash

from flask_login import LoginManager, login_user, logout_user, current_user

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User:
    def __init__(self, id, username):
        self.id = id
        self.username = username
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    import sqlite3
    conn = sqlite3.connect("user_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(id=row[0], username=row[1])
    return None

@app.route('/login', methods=['POST'])
def login_post():
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    email = request.form.get('email')
    password = request.form.get('password')
    remember = request.form.get('remember') == 'on'

    logger.debug(f"Login attempt for email: {email}, remember: {remember}")

    if not email or not password:
        flash('Please enter both email and password.', 'danger')
        logger.debug("Missing email or password")
        return redirect(url_for('login'))

    if not email_exists(email):
        # Email not found, redirect to signup page
        flash('Email not found. Please sign up.', 'warning')
        logger.debug("Email not found in database")
        return redirect(url_for('login', action='signup'))

    from user_storage import verify_user_by_email, get_user_by_email

    if verify_user_by_email(email, password):
        user_data = get_user_by_email(email)
        if user_data:
            user = User(id=user_data[0], username=user_data[1])
            login_user(user, remember=remember)
            flash('Logged in successfully.', 'success')
            logger.debug("Login successful, redirecting to index")
            return redirect(url_for('index'))
        else:
            flash('User not found.', 'danger')
            logger.debug("User data not found after verification")
            return redirect(url_for('login'))
    else:
        flash('Invalid email or password.', 'danger')
        logger.debug("Password verification failed")
        return redirect(url_for('login'))

@app.route('/forgot_password')
def forgot_password():
    return "Forgot password placeholder"

from flask import redirect

@app.route('/google_login')
def google_login():
    return redirect("https://accounts.google.com/signin")

@app.route('/facebook_login')
def facebook_login():
    return redirect("https://www.facebook.com/login.php")

@app.route('/twitter_login')
def twitter_login():
    return redirect("https://twitter.com/login")

from user_storage import email_exists

@app.route('/signup_post', methods=['POST'])
def signup_post():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if not username or not email or not password or not confirm_password:
        flash("Please fill in all fields.", "signup_error")
        return redirect(url_for('login', action='signup'))

    if password != confirm_password:
        flash("Passwords do not match.", "signup_error")
        return redirect(url_for('login', action='signup'))

    from user_storage import user_exists_by_username

    if user_exists_by_username(username):
        flash("Username already exists.", "signup_error")
        return redirect(url_for('login', action='signup'))

    if email_exists(email):
        flash("Email already exists.", "signup_error")
        return redirect(url_for('login', action='signup'))

    success = add_user(username, email, password)
    if success:
        flash("Account created successfully! Please log in.", "signup_success")
        return redirect(url_for('login'))
    else:
        flash("Failed to create account. Please try again.", "signup_error")
        return redirect(url_for('login', action='signup'))

@app.route('/terms')
def terms():
    return "Terms of Service placeholder"

@app.route('/privacy')
def privacy():
    return "Privacy Policy placeholder"

try:
    from flask_login import LoginManager, login_required, current_user
except ImportError:
    # flask_login is not installed, define dummy decorators and objects
    def login_required(func):
        return func
    class DummyCurrentUser:
        name = "Guest"
    current_user = DummyCurrentUser()
    class LoginManager:
        def init_app(self, app):
            pass
        login_view = None
        def user_loader(self, func):
            # Dummy decorator for user_loader
            return func

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy user loader for example, replace with your user loader
@login_manager.user_loader
def load_user(user_id):
    # Implement user loading logic here
    return None

@app.route('/dashboard')
@login_required
def dashboard():
    import sqlite3
    from datetime import datetime

    conn = sqlite3.connect("viroscan.db")
    cursor = conn.cursor()

    # Total scans
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0] or 0

    # Clean scans
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE result LIKE '%Clean%'")
    clean_scans = cursor.fetchone()[0] or 0

    # Threat scans
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE result LIKE '%Malicious%' OR result LIKE '%Threat%'")
    threat_scans = cursor.fetchone()[0] or 0

    # Days protected - calculate from earliest scan date to today
    cursor.execute("SELECT MIN(date) FROM scan_history")
    first_scan_date_str = cursor.fetchone()[0]
    if first_scan_date_str:
        first_scan_date = datetime.strptime(first_scan_date_str, "%Y-%m-%d %H:%M:%S")
        days_protected = (datetime.now() - first_scan_date).days
    else:
        days_protected = 0

    # Last login date and IP - placeholder as not stored
    last_login_date = "N/A"
    last_login_ip = "N/A"

    # Recent scans - latest 5
    cursor.execute("SELECT id, date, scan_type, target, status, result FROM scan_history ORDER BY date DESC LIMIT 5")
    recent_scans = cursor.fetchall()

    conn.close()

    return render_template('dashboard.html',
                           total_scans=total_scans,
                           clean_scans=clean_scans,
                           threat_scans=threat_scans,
                           days_protected=days_protected,
                           last_login_date=last_login_date,
                           last_login_ip=last_login_ip,
                           recent_scans=recent_scans,
                           current_user=current_user)

@app.route('/profile')
def profile():
    return "Profile placeholder"

@app.route('/settings')
def settings():
    return "Settings placeholder"

@app.route('/logout')
def logout():
    return redirect(url_for('index'))

from flask import jsonify

@app.route('/check_email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    exists = email_exists(email)
    return jsonify({'exists': exists})

if __name__ == '__main__':
    app.run(debug=True)
