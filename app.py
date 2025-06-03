import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'doc', 'docx'}

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# -----------------------------
# User Model
# -----------------------------
class User(UserMixin):
    def __init__(self, id, username, password_hash, role):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(*user)
    return None

# -----------------------------
# Allowed File Type
# -----------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -----------------------------
# Student Dashboard
# -----------------------------
@app.route('/student')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash("Access denied.")
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT slot_number, filename, status, score FROM submissions WHERE student_id = ?", (current_user.id,))
    submissions = {row[0]: row for row in c.fetchall()}
    conn.close()

    # Ensure all 3 slots are represented
    full_submissions = []
    for slot in range(1, 4):
        if slot in submissions:
            full_submissions.append(submissions[slot])
        else:
            full_submissions.append((slot, None, "Awaiting submission", None))

    return render_template('student_dashboard.html', submissions=full_submissions)

# -----------------------------
# Upload Submission
# -----------------------------
@app.route('/upload_submission', methods=['POST'])
@login_required
def upload_submission():
    if current_user.role != 'student':
        flash("Access denied.")
        return redirect(url_for('dashboard'))

    slot_number = int(request.form['slot_number'])
    file = request.files['file']

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{current_user.id}_slot{slot_number}_{filename}")
        file.save(save_path)

        conn = sqlite3.connect('users.db')
        c = conn.cursor()

        c.execute("SELECT * FROM submissions WHERE student_id = ? AND slot_number = ?", (current_user.id, slot_number))
        if c.fetchone():
            c.execute("""
                UPDATE submissions
                SET filename = ?, status = 'Awaiting Marking', score = NULL
                WHERE student_id = ? AND slot_number = ?
            """, (filename, current_user.id, slot_number))
        else:
            c.execute("""
                INSERT INTO submissions (student_id, slot_number, filename, status, score)
                VALUES (?, ?, ?, 'Awaiting Marking', NULL)
            """, (current_user.id, slot_number, filename))

        conn.commit()
        conn.close()
        flash(f"Slot {slot_number} uploaded successfully.")
    else:
        flash("Invalid file type. Only .doc and .docx allowed.")

    return redirect(url_for('student_dashboard'))

# -----------------------------
# Other Routes: login, register, dashboards, etc.
# (Omitted here for brevity – keep them unchanged)
# -----------------------------

# -----------------------------
# DB Initialisation
# -----------------------------
def init_user_table():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            marker_id INTEGER NOT NULL,
            FOREIGN KEY(student_id) REFERENCES users(id),
            FOREIGN KEY(marker_id) REFERENCES users(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            slot_number INTEGER NOT NULL,
            filename TEXT,
            status TEXT,
            score INTEGER,
            FOREIGN KEY(student_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    init_user_table()
    app.run(debug=True)