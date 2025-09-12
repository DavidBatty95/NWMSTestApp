from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    send_from_directory, abort, send_file, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, text
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from io import BytesIO
from PyPDF2 import PdfMerger, PdfReader
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from pathlib import Path
import os
import json
import secrets
import traceback

# ===================================================
# App & Core Config
# ===================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')

# ---------- Environment detection ----------
project_root = Path(__file__).resolve().parent
is_render = bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))

# ---------- Database on Persistent Disk (/var/data) ----------
env_db_url = (os.getenv("DATABASE_URL") or "").strip()

if is_render:
    db_dir = Path("/var/data")                    # Render persistent disk
else:
    db_dir = project_root / "data"                # Local dev
db_dir.mkdir(parents=True, exist_ok=True)

sqlite_path = db_dir / "database.db"

if env_db_url and not env_db_url.lower().startswith("sqlite"):
    app.config["SQLALCHEMY_DATABASE_URI"] = env_db_url   # e.g. Postgres on Render
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{sqlite_path}"
    # Needed for SQLite with threaded servers like gunicorn
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": {"check_same_thread": False}}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 10 * 1024 * 1024))  # 10 MB default

# ---------- Durable storage roots (/var/data or ./data) ----------
persist_root = Path("/var/data") if is_render else (project_root / "data")
persist_root.mkdir(parents=True, exist_ok=True)

# Uploads (PDFs)
upload_root = persist_root / "uploads"
pdf_dir = upload_root / "pdfs"
pdf_dir.mkdir(parents=True, exist_ok=True)
app.config["UPLOAD_FOLDER"] = str(upload_root)

# Activity logs
LOGS_DIR = persist_root / "activity_logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------- One-time boot logger & DB initializer (Flask 3.x safe) ----------
_boot_logged = False
_db_initialized = False

@app.before_request
def _bootstrap_once():
    """Log storage info once and ensure DB tables exist before any query."""
    global _boot_logged, _db_initialized
    if not _boot_logged:
        app.logger.info(f"[BOOT] DB URI: {app.config.get('SQLALCHEMY_DATABASE_URI')}")
        app.logger.info(f"[BOOT] Uploads dir: {upload_root}")
        app.logger.info(f"[BOOT] PDFs dir: {pdf_dir}")
        app.logger.info(f"[BOOT] Logs dir: {LOGS_DIR}")
        app.logger.info(f"[BOOT] Render? {is_render}")
        _boot_logged = True

    if not _db_initialized:
        try:
            with app.app_context():
                db.create_all()
                ensure_sqlite_schema()
            _db_initialized = True
            app.logger.info("[BOOT] Database initialized / tables ensured.")
        except Exception as e:
            app.logger.error("DB initialization failed: %r", e)
            # Let the normal error handler show a friendly 500; logs contain full trace.

# ---------- Catch-all error handler for quick diagnosis ----------
@app.errorhandler(Exception)
def _catch_all(e):
    app.logger.error("=== Unhandled exception ===")
    app.logger.error("Path: %s", request.path)
    app.logger.error("Error: %s", repr(e))
    app.logger.error("Traceback:\n%s", traceback.format_exc())
    return ("An unexpected error occurred. Check server logs for details.", 500)

# ---------- Health endpoint ----------
@app.get("/_health")
def _health():
    return jsonify({
        "db_uri": app.config["SQLALCHEMY_DATABASE_URI"],
        "uploads": str(upload_root.resolve()),
        "pdfs": str(pdf_dir.resolve()),
        "logs": str(LOGS_DIR.resolve()),
        "render": is_render,
        "time": datetime.now().isoformat()
    })

# ===================================================
# Constants
# ===================================================
COURSE_WORKBOOKS = {'FREC4': 3, 'SALM': 1, 'CFR': 1}
MARKING_DEADLINE_DAYS = 14
MAX_ATTEMPTS = 4

QUESTION_COUNTS = {
    ('FREC4', 1): 10, ('FREC4', 2): 10, ('FREC4', 3): 10,
    ('CFR', 1): 10, ('SALM', 1): 8,
    ('*', 1): 10, ('*', 2): 10, ('*', 3): 10,
}
COURSE_DEADLINES = {
    "FREC4": 6,   # months to deadline
    "ILS": 3,
    "SALM": 3,
    "CFR": 3,
}

DISPLAY_TZ = ZoneInfo(os.environ.get('DISPLAY_TZ', 'Europe/London'))

# ===================================================
# Helpers: time/format
# ===================================================
def now_utc(): return datetime.now(timezone.utc)
def now_utc_naive(): return now_utc().replace(tzinfo=None)

def _format_ts_human(ts_iso: str | None) -> str:
    if not ts_iso:
        return "—"
    try:
        dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        return dt.astimezone(DISPLAY_TZ).strftime("%a %d %b %Y, %H:%M %Z")
    except Exception:
        return ts_iso

def add_months(dt, months):
    if not dt: return None
    year = dt.year + (dt.month - 1 + months) // 12
    month = (dt.month - 1 + months) % 12 + 1
    from calendar import monthrange
    day = min(dt.day, monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)

# ===================================================
# Helpers: storage
# ===================================================
def save_uploaded_pdf(file_storage, filename: str) -> str:
    """Save into pdf_dir and return safe filename (DB stores filenames, not paths)."""
    safe = secure_filename(filename)
    full_path = pdf_dir / safe
    file_storage.save(full_path)
    return safe

def file_path(filename: str) -> Path:
    return pdf_dir / filename

def _file_is_referenced_elsewhere(filename: str, exclude_submission_id=None) -> bool:
    if not filename:
        return False
    q = WorkbookSubmission.query.filter(
        or_(WorkbookSubmission.file_path == filename,
            WorkbookSubmission.corrected_submission_path == filename)
    )
    if exclude_submission_id is not None:
        q = q.filter(WorkbookSubmission.id != exclude_submission_id)
    return db.session.query(q.exists()).scalar()

def _maybe_delete_uploaded_file(filename: str):
    if not filename or _file_is_referenced_elsewhere(filename):
        return
    path = file_path(filename)
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass

# ===================================================
# Activity logging (per-student JSONL)
# ===================================================
def student_log_path(student_id: int) -> Path:
    return LOGS_DIR / f"student_{student_id}.log"

def log_student_event(student_id: int, event: str, details: dict | None = None):
    try:
        payload = {
            "ts": now_utc().isoformat(),
            "event": event,
            "student_id": student_id,
            "ip": (request.headers.get('X-Forwarded-For') or request.remote_addr),
            "ua": request.headers.get('User-Agent'),
        }
        if details:
            payload["details"] = details
        with student_log_path(student_id).open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass

# ===================================================
# Token helpers (password reset)
# ===================================================
def _get_serializer(): return URLSafeTimedSerializer(app.config['SECRET_KEY'])
def generate_reset_token(user):
    return _get_serializer().dumps({'uid': user.id, 'email': user.email}, salt='pw-reset')
def verify_reset_token(token, max_age=3600):
    s = _get_serializer()
    try:
        data = s.loads(token, salt='pw-reset', max_age=max_age)
        user = db.session.get(User, data.get('uid'))
        return user if user and user.email == data.get('email') else None
    except (SignatureExpired, BadSignature):
        return None

# ===================================================
# Models
# ===================================================
class Cohort(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=True)
    course = db.Column(db.String(10), nullable=False)              # 'FREC4'|'SALM'|'CFR'
    marker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    passcode = db.Column(db.String(24), nullable=False, unique=True)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=now_utc_naive)

    marker = db.relationship('User', foreign_keys=[marker_id])

class User(UserMixin, db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email    = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role     = db.Column(db.String(50),  nullable=False)           # 'student','marker','admin'
    course   = db.Column(db.String(10),  nullable=True)            # for students
    cohort_id = db.Column(db.Integer, db.ForeignKey('cohort.id'), nullable=True)

    cohort = db.relationship('Cohort', foreign_keys=[cohort_id])

class WorkbookSubmission(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    student_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    workbook_number = db.Column(db.Integer, nullable=False)
    file_path   = db.Column(db.String(255))
    submission_time = db.Column(db.DateTime, default=now_utc_naive)
    marked      = db.Column(db.Boolean, default=False)
    score       = db.Column(db.Integer, nullable=True)   # questions passed (or 0 on fail)
    feedback    = db.Column(db.Text, nullable=True)
    is_referral = db.Column(db.Boolean, default=False)
    referral_count = db.Column(db.Integer, default=0)
    corrected_submission_path = db.Column(db.String(255), nullable=True)
    corrected_submission_time = db.Column(db.DateTime, nullable=True)

    student = db.relationship('User', foreign_keys=[student_id])

class QuestionFeedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('workbook_submission.id'), nullable=False)
    question_number = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(10), nullable=False)  # 'Pass' or 'Refer'
    comment = db.Column(db.Text, nullable=True)

    submission = db.relationship('WorkbookSubmission', foreign_keys=[submission_id])

class Assignment(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    marker_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# ===================================================
# SQLite schema helper (adds new columns on existing DB)
# ===================================================
from sqlalchemy.exc import OperationalError
def ensure_sqlite_schema():
    """Make best-effort ALTERs for SQLite to add newer columns if missing."""
    try:
        if not db.engine.url.get_backend_name().startswith('sqlite'):
            return
        with db.engine.connect() as conn:
            cols_ws = [row['name'] for row in conn.execute(text("PRAGMA table_info(workbook_submission)")).mappings()]
            if 'corrected_submission_time' not in cols_ws:
                conn.execute(text("ALTER TABLE workbook_submission ADD COLUMN corrected_submission_time DATETIME"))
            cols_user = [row['name'] for row in conn.execute(text("PRAGMA table_info(user)")).mappings()]
            if 'cohort_id' not in cols_user:
                conn.execute(text("ALTER TABLE user ADD COLUMN cohort_id INTEGER"))
            conn.commit()
    except Exception as e:
        app.logger.warning("ensure_sqlite_schema() warning: %r", e)

# ===================================================
# Utility logic
# ===================================================
def get_question_count(course: str | None, workbook_number: int) -> int:
    return QUESTION_COUNTS.get((course or '*', workbook_number),
           QUESTION_COUNTS.get(('*', workbook_number), 10))

def build_workbook_item(student_id, wb_number):
    latest = (WorkbookSubmission.query
              .filter_by(student_id=student_id, workbook_number=wb_number)
              .order_by(WorkbookSubmission.submission_time.desc())
              .first())

    item = {
        "wb_number": wb_number,
        "latest": latest,
        "attempts_so_far": 0,
        "attempts_left": MAX_ATTEMPTS,
        "label": "Awaiting submission",
        "badge": "bg-secondary",
        "can_upload": True,
        "can_reattempt": False,
    }
    if not latest:
        return item

    attempts_so_far = (latest.referral_count or 0) + 1
    attempts_left = max(0, MAX_ATTEMPTS - attempts_so_far)
    item["attempts_so_far"] = attempts_so_far
    item["attempts_left"] = attempts_left
    item["can_upload"] = False

    if not latest.marked:
        item["label"] = "Submitted"
        item["badge"] = "bg-warning text-dark"
        return item

    if latest.score is not None and not latest.is_referral:
        q_total = get_question_count(latest.student.course, wb_number)
        if latest.score == q_total:
            item["label"] = "Marked Pass"
            item["badge"] = "bg-success"
            return item
        if latest.score == 0:
            item["label"] = "Failed"
            item["badge"] = "bg-dark text-white"
            return item

    if latest.is_referral:
        if attempts_left > 0:
            item["label"] = "Waiting for reattempt"
            item["badge"] = "bg-danger"
            item["can_reattempt"] = True
        else:
            item["label"] = "Failed"
            item["badge"] = "bg-dark text-white"
    else:
        item["label"] = "Submitted"
        item["badge"] = "bg-warning text-dark"

    return item

def compute_overall_status(items, required):
    if any(it["label"] == "Failed" for it in items):
        return "Fail"
    if sum(1 for it in items if it["label"] == "Marked Pass") == required:
        return "Pass"
    return "In Progress"

def get_student_status(student: 'User', required_workbooks: int) -> str:
    labels = []
    for wb in range(1, required_workbooks + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())
        if not latest:
            labels.append('Awaiting submission'); continue
        if not latest.marked:
            labels.append('Submitted'); continue
        q_total = get_question_count(student.course, wb)
        if latest.is_referral:
            attempts_left = max(0, MAX_ATTEMPTS - (1 + (latest.referral_count or 0)))
            labels.append('Failed' if attempts_left == 0 else 'Referral')
        else:
            if latest.score == q_total:
                labels.append('Marked Pass')
            elif latest.score == 0:
                labels.append('Failed')
            else:
                labels.append('Submitted')
    if any(lbl == 'Failed' for lbl in labels):
        return 'Fail'
    if labels.count('Marked Pass') == required_workbooks:
        return 'Pass'
    return 'In Progress'

def get_marking_deadline(submission: 'WorkbookSubmission'):
    deadline = submission.submission_time + timedelta(days=MARKING_DEADLINE_DAYS)
    time_left = deadline - now_utc_naive()
    days = max(time_left.days, 0)
    hours = max(time_left.seconds // 3600, 0)
    return days, hours, deadline

def get_assigned_students_for_marker(marker_id: int):
    return (db.session.query(User)
            .join(Assignment, Assignment.student_id == User.id)
            .filter(User.role == 'student', Assignment.marker_id == marker_id)
            .all())

def marker_is_assigned_to_student(marker_id: int, student_id: int) -> bool:
    return Assignment.query.filter_by(marker_id=marker_id, student_id=student_id).first() is not None

def generate_passcode(length: int = 10) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ===================================================
# Login manager
# ===================================================
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# ===================================================
# Routes: Auth
# ===================================================
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip()
        password_raw = request.form.get('password') or ''
        role = (request.form.get('role') or '').strip()

        if not username or not email or not password_raw or role not in ('student', 'marker', 'admin'):
            flash('Please provide all required fields.', 'warning')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'warning')
            return redirect(url_for('register'))

        if role == 'student':
            raw_code = (request.form.get('cohort_passcode') or '').strip()
            norm_code = ''.join(raw_code.split()).upper()
            if not norm_code:
                flash('Please enter your cohort passcode.', 'danger')
                return redirect(url_for('register'))

            cohort = None
            for ch in Cohort.query.filter_by(active=True).all():
                if (ch.passcode or '').upper() == norm_code:
                    cohort = ch; break
            if not cohort:
                flash('Cohort passcode not recognized or inactive.', 'danger')
                return redirect(url_for('register'))

            user = User(
                username=username, email=email,
                password=generate_password_hash(password_raw),
                role='student', course=cohort.course, cohort_id=cohort.id
            )
            db.session.add(user); db.session.commit()

            existing = Assignment.query.filter_by(student_id=user.id).first()
            if existing: existing.marker_id = cohort.marker_id
            else: db.session.add(Assignment(student_id=user.id, marker_id=cohort.marker_id))
            db.session.commit()

            flash('Account created and cohort assigned. Please log in.', 'success')
            return redirect(url_for('login'))

        user = User(
            username=username, email=email,
            password=generate_password_hash(password_raw), role=role
        )
        db.session.add(user); db.session.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'student':
                log_student_event(user.id, "login", {"username": user.username})
            return redirect(url_for(
                'admin_dashboard'  if user.role == 'admin'  else
                'marker_dashboard' if user.role == 'marker' else
                'student_dashboard'
            ))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip()
        user = User.query.filter_by(email=identifier).first() or User.query.filter_by(username=identifier).first()
        if not user:
            flash('If that account exists, a reset link has been created.', 'info')
            return render_template('forgot_password.html', reset_link=None)
        token = generate_reset_token(user)
        reset_url = url_for('reset_password', token=token, _external=True)
        flash('If that account exists, a reset link has been created.', 'info')
        return render_template('forgot_password.html', reset_link=reset_url)
    return render_template('forgot_password.html', reset_link=None)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = verify_reset_token(token)
    if not user:
        flash('This reset link is invalid or has expired. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_pw = request.form.get('password') or ''
        confirm = request.form.get('confirm_password') or ''
        if len(new_pw) < 6:
            flash('Password must be at least 6 characters.', 'warning')
            return render_template('reset_password.html')
        if new_pw != confirm:
            flash('Passwords do not match.', 'warning')
            return render_template('reset_password.html')
        user.password = generate_password_hash(new_pw)
        db.session.commit()
        flash('Your password has been reset. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# ===================================================
# Routes: Student
# ===================================================
@app.route('/student_dashboard', methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('login'))

    if request.method == 'POST':
        wb_number = int(request.form.get('workbook_number', '0') or 0)
        if wb_number <= 0:
            flash('Invalid workbook number.', 'warning')
            return redirect(url_for('student_dashboard'))

        up_file = request.files.get('file')
        ref_file = request.files.get('referral_file')

        if up_file and up_file.filename:
            filename = save_uploaded_pdf(up_file, up_file.filename)

            latest_existing = (WorkbookSubmission.query
                               .filter_by(student_id=current_user.id, workbook_number=wb_number)
                               .order_by(WorkbookSubmission.submission_time.desc())
                               .first())
            referral_count = (latest_existing.referral_count if latest_existing else 0) or 0

            submission = WorkbookSubmission(
                student_id=current_user.id,
                workbook_number=wb_number,
                file_path=filename,
                referral_count=referral_count,
                marked=False,
                is_referral=False
            )
            db.session.add(submission); db.session.commit()

            log_student_event(current_user.id, "upload", {"workbook_number": wb_number, "filename": filename})
            flash(f'Workbook {wb_number} uploaded.', 'success')
            return redirect(url_for('student_dashboard'))

        elif ref_file and ref_file.filename:
            filename = save_uploaded_pdf(ref_file, ref_file.filename)
            latest = (WorkbookSubmission.query
                      .filter_by(student_id=current_user.id, workbook_number=wb_number)
                      .order_by(WorkbookSubmission.submission_time.desc())
                      .first())
            if not latest:
                flash('No prior submission found for this workbook.', 'warning')
                return redirect(url_for('student_dashboard'))

            latest.corrected_submission_path = filename
            latest.corrected_submission_time = now_utc_naive()
            db.session.commit()

            log_student_event(current_user.id, "reupload", {"workbook_number": wb_number, "filename": filename})
            flash(f'Workbook {wb_number} re-uploaded for referral.', 'success')
            return redirect(url_for('student_dashboard'))

        else:
            flash('Please choose a PDF to upload.', 'warning')
            return redirect(url_for('student_dashboard'))

    course_code = (current_user.course or '').upper()
    required = COURSE_WORKBOOKS.get(course_code, 3)

    start_date = current_user.cohort.start_date if (getattr(current_user, "cohort", None) and current_user.cohort.start_date) else None
    months_allowed = COURSE_DEADLINES.get(course_code, 6)
    deadline_date = add_months(start_date, months_allowed) if start_date else None

    items = [build_workbook_item(current_user.id, n) for n in range(1, required + 1)]
    overall_status = compute_overall_status(items, required)

    return render_template(
        'student_dashboard.html',
        items=items,
        overall_status=overall_status,
        course_start_date=start_date,
        course_deadline=deadline_date,
        months_allowed=months_allowed
    )

@app.route('/student_feedback/<int:workbook_number>')
@login_required
def student_view_feedback(workbook_number):
    if current_user.role != 'student':
        return redirect(url_for('login'))

    submission = (WorkbookSubmission.query
                  .filter_by(student_id=current_user.id, workbook_number=workbook_number, marked=True)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())
    if not submission:
        flash('No marked feedback is available for this workbook yet.', 'info')
        return redirect(url_for('student_dashboard'))

    log_student_event(current_user.id, "view_feedback", {"workbook_number": workbook_number})

    q_items = (QuestionFeedback.query
               .filter_by(submission_id=submission.id)
               .order_by(QuestionFeedback.question_number.asc()).all())

    pdf_filename = submission.corrected_submission_path or submission.file_path
    is_pdf = bool(pdf_filename and pdf_filename.lower().endswith('.pdf'))
    total = len(q_items)
    passed = sum(1 for f in q_items if f.status == 'Pass')

    q_total = get_question_count(current_user.course, workbook_number)
    if submission.is_referral:
        overall = 'Referral'
    elif submission.score == passed == q_total:
        overall = 'Pass'
    elif submission.score == 0:
        overall = 'Fail'
    else:
        overall = 'Marked'

    return render_template('student_view_feedback.html',
                           workbook_number=workbook_number, submission=submission,
                           overall=overall, pdf_filename=pdf_filename if is_pdf else None,
                           q_items=q_items, total=total, passed=passed)

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    # Serve from pdf_dir to prevent access outside
    return send_from_directory(pdf_dir, filename, as_attachment=False)

# ===================================================
# Routes: Marker
# ===================================================
@app.route('/marker_dashboard')
@login_required
def marker_dashboard():
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    # Students assigned to this marker
    assigned_student_ids = [a.student_id for a in Assignment.query.filter_by(marker_id=current_user.id).all()]

    students = (User.query
                .filter(User.role == 'student', User.id.in_(assigned_student_ids))
                .order_by(User.username.asc())
                .all())
    users_map = {u.id: u for u in students}

    # ---------- Donut / workload ----------
    total_unsubmitted = 0
    total_to_mark = 0
    total_marked = 0
    overview_rows = []

    for s in students:
        required = COURSE_WORKBOOKS.get((s.course or '').upper(), 3)
        s_unsubmitted = required
        s_to_mark = 0
        s_marked = 0
        for wb in range(1, required + 1):
            latest = (WorkbookSubmission.query
                      .filter_by(student_id=s.id, workbook_number=wb)
                      .order_by(WorkbookSubmission.submission_time.desc())
                      .first())
            if not latest:
                continue
            s_unsubmitted -= 1
            if latest.marked:
                s_marked += 1
            else:
                s_to_mark += 1

        total_unsubmitted += s_unsubmitted
        total_to_mark += s_to_mark
        total_marked += s_marked

        overview_rows.append({
            "student": s, "required": required,
            "unsubmitted": s_unsubmitted, "to_mark": s_to_mark, "marked": s_marked,
        })

    donut_data = {
        "unsubmitted": total_unsubmitted,
        "to_mark": total_to_mark,
        "marked": total_marked,
        "total": total_unsubmitted + total_to_mark + total_marked
    }

    # ---------- Needs marking list (ordered by least time remaining) ----------
    def _time_left_fields(sub):
        deadline = sub.submission_time + timedelta(days=MARKING_DEADLINE_DAYS)
        delta = deadline - now_utc_naive()
        seconds = int(delta.total_seconds())
        overdue = seconds < 0
        secs_abs = abs(seconds)
        days = secs_abs // 86400
        hours = (secs_abs % 86400) // 3600
        return {
            "deadline": deadline,
            "seconds_left": seconds,   # negative means overdue
            "overdue": overdue,
            "days": days,
            "hours": hours,
        }

    # We care about unmarked items (initial or re-upload)
    unmarked = (WorkbookSubmission.query
                .filter(WorkbookSubmission.student_id.in_(assigned_student_ids),
                        WorkbookSubmission.marked.is_(False))
                .order_by(WorkbookSubmission.submission_time.desc())
                .all())

    to_mark_list = []
    for sub in unmarked:
        # Skip if we lost user map (shouldn't happen)
        student = users_map.get(sub.student_id)
        if not student:
            continue
        tlf = _time_left_fields(sub)
        to_mark_list.append({
            "submission": sub,
            "student": student,
            "wb": sub.workbook_number,
            **tlf
        })

    # Least time remaining first → sort by seconds_left ascending (overdue first)
    to_mark_list.sort(key=lambda x: x["seconds_left"])

    # (Optional) cap list length for UI
    to_mark_list = to_mark_list[:20]

    return render_template(
        'marker_dashboard.html',
        donut_data=donut_data,
        students_overview=overview_rows,
        to_mark_list=to_mark_list,   # << use this in template
    )

@app.route('/marker_students')
@login_required
def marker_students():
    if current_user.role != 'marker':
        return redirect(url_for('login'))
    students = get_assigned_students_for_marker(current_user.id)
    data = []
    for s in students:
        required = COURSE_WORKBOOKS.get(s.course, 1)
        data.append({"student": s, "status": get_student_status(s, required), "required": required})
    return render_template('marker_students.html', students=data)

@app.route('/marker_view_student/<int:student_id>')
@login_required
def marker_view_student(student_id):
    if current_user.role != 'marker':
        return redirect(url_for('login'))
    if not marker_is_assigned_to_student(current_user.id, student_id):
        abort(403)

    student = db.session.get(User, student_id)
    if not student: abort(404)

    workbooks = WorkbookSubmission.query.filter_by(student_id=student.id).all()
    required = COURSE_WORKBOOKS.get(student.course, 1)
    workbooks_dict = {w.workbook_number: w for w in workbooks}

    assigned_students = get_assigned_students_for_marker(current_user.id)
    ids = [s.id for s in sorted(assigned_students, key=lambda s: s.id)]
    idx = ids.index(student.id)
    prev_id = ids[idx - 1] if idx > 0 else None
    next_id = ids[idx + 1] if idx < len(ids) - 1 else None

    return render_template('marker_view_student.html', student=student, required=required,
                           workbooks=workbooks, workbooks_dict=workbooks_dict,
                           status=get_student_status(student, required), now=now_utc_naive(),
                           timedelta=timedelta, prev_id=prev_id, next_id=next_id,
                           get_marking_deadline=get_marking_deadline)

@app.route('/mark_workbook_questions/<int:submission_id>', methods=['GET', 'POST'])
@login_required
def mark_workbook_questions(submission_id):
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    submission = db.session.get(WorkbookSubmission, submission_id)
    if not submission: abort(404)
    if not marker_is_assigned_to_student(current_user.id, submission.student_id):
        abort(403)

    student = db.session.get(User, submission.student_id)
    if not student: abort(404)

    wb_num = submission.workbook_number
    q_count = get_question_count(student.course, wb_num)

    attempts_so_far = 1 + (submission.referral_count or 0)
    attempts_left = max(0, MAX_ATTEMPTS - attempts_so_far)
    final_attempt = (attempts_left == 0)

    previous_submissions = (WorkbookSubmission.query
                            .filter_by(student_id=student.id, workbook_number=wb_num)
                            .filter(WorkbookSubmission.id != submission.id)
                            .order_by(WorkbookSubmission.submission_time.desc())
                            .all())

    previously_referred = set()
    prev_pass_comments = {}
    last_prev = previous_submissions[0] if previous_submissions else None
    if last_prev:
        for q in QuestionFeedback.query.filter_by(submission_id=last_prev.id).all():
            if q.status == 'Refer':
                previously_referred.add(q.question_number)
            elif q.status == 'Pass':
                prev_pass_comments[q.question_number] = (q.comment or '')

    is_first_attempt = (attempts_so_far == 1 and not previous_submissions)
    open_questions = list(range(1, q_count + 1)) if is_first_attempt else sorted(previously_referred)

    if request.method == 'POST':
        QuestionFeedback.query.filter_by(submission_id=submission.id).delete()

        for qn in open_questions:
            status = request.form.get(f"q_{qn}_status")  # 'Pass' | 'Refer' | 'Fail' (UI maps Fail→Refer on save)
            comment = (request.form.get(f"q_{qn}_comment") or '').strip()

            if status == 'Fail':
                status = 'Refer'
            if status in ('Pass', 'Refer'):
                db.session.add(QuestionFeedback(
                    submission_id=submission.id,
                    question_number=qn,
                    status=status,
                    comment=comment
                ))

        if not is_first_attempt and last_prev:
            for qn, com in prev_pass_comments.items():
                if qn not in previously_referred:
                    db.session.add(QuestionFeedback(
                        submission_id=submission.id,
                        question_number=qn,
                        status='Pass',
                        comment=com
                    ))

        submission.marked = True
        all_fb = QuestionFeedback.query.filter_by(submission_id=submission.id).all()
        total = len(all_fb)
        passed = sum(1 for f in all_fb if f.status == 'Pass')
        submission.score = passed

        if passed == total and total > 0:
            submission.is_referral = False
            flash(f'Saved: all {passed} questions passed. Submission set to Pass.', 'success')
        else:
            if final_attempt:
                submission.is_referral = False
                submission.score = 0
                flash('Saved on final attempt: not all questions passed. Submission set to Fail.', 'danger')
            else:
                submission.is_referral = True
                submission.referral_count = (submission.referral_count or 0) + 1
                flash(f'Saved: {passed}/{total} questions passed. Submission set to Referral.', 'warning')

        db.session.commit()
        return redirect(url_for('marker_view_student', student_id=student.id))

    rows = []
    for qn in range(1, q_count + 1):
        is_open = True if is_first_attempt else (qn in previously_referred)
        rows.append({
            'number': qn,
            'open': is_open,
            'prev_state': (None if is_first_attempt else ('Refer' if qn in previously_referred else 'Pass')),
            'prev_comment': None if is_open else prev_pass_comments.get(qn, '')
        })

    pdf_filename = submission.corrected_submission_path or submission.file_path
    is_pdf = bool(pdf_filename and pdf_filename.lower().endswith('.pdf'))

    return render_template('mark_workbook_questions.html',
                           submission=submission, student=student, wb_number=wb_num,
                           q_count=q_count, rows=rows,
                           pdf_filename=pdf_filename if is_pdf else None,
                           previously_referred=sorted(previously_referred),
                           is_first_attempt=is_first_attempt,
                           final_attempt=final_attempt)

# ===================================================
# Export Student Report (Workbook PDFs + Feedback pages)
# ===================================================
def _render_feedback_page(submission: WorkbookSubmission, student: User, workbook_number: int) -> BytesIO:
    rows = (QuestionFeedback.query
            .filter_by(submission_id=submission.id)
            .order_by(QuestionFeedback.question_number.asc()).all())

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    W, H = A4
    left = 18 * mm
    right = W - 18 * mm
    top = H - 18 * mm
    line_h = 6.4 * mm

    def header():
        c.setFont("Helvetica-Bold", 13)
        c.drawString(left, top, f"Workbook {workbook_number} – Feedback Summary")
        c.setFont("Helvetica", 10)
        course = student.course or "-"
        attempt_no = (submission.referral_count or 0) + 1
        sub_dt = submission.submission_time.strftime("%Y-%m-%d %H:%M")
        c.drawString(left, top - 12*mm, f"Student: {student.username}   Course: {course}")
        c.drawString(left, top - 17*mm, f"Attempt: {attempt_no}   Submitted: {sub_dt}")
        c.setFont("Helvetica-Bold", 9)
        y = top - 27*mm
        c.drawString(left, y, "Q#")
        c.drawString(left + 18*mm, y, "Result")
        c.drawString(left + 45*mm, y, "Comment")
        c.drawString(right - 70*mm, y, "Marked By")
        c.drawString(right - 30*mm, y, "When")
        c.line(left, y - 2, right, y - 2)
        return y - 6

    def flush_page():
        c.showPage()

    y = header()
    c.setFont("Helvetica", 9)

    if not rows:
        c.drawString(left, y, "No question-level feedback recorded for this submission.")
        flush_page(); c.save(); buf.seek(0); return buf

    marker_name = "-"
    assign = Assignment.query.filter_by(student_id=submission.student_id).first()
    if assign:
        marker = db.session.get(User, assign.marker_id)
        if marker:
            marker_name = marker.username
    when_txt = submission.submission_time.strftime("%Y-%m-%d %H:%M")

    for row in rows:
        if y < 28 * mm:
            flush_page(); y = header(); c.setFont("Helvetica", 9)
        comment = (row.comment or "").replace("\n", " ").strip()
        max_comment_chars = 80
        short_comment = (comment[:max_comment_chars] + "…") if len(comment) > max_comment_chars else comment
        c.drawString(left, y, str(row.question_number))
        c.drawString(left + 18*mm, y, row.status or "-")
        c.drawString(left + 45*mm, y, short_comment or "—")
        c.drawString(right - 70*mm, y, marker_name)
        c.drawRightString(right, y, when_txt)
        y -= line_h

    flush_page(); c.save(); buf.seek(0)
    return buf

def _latest_submission(student_id: int, wb: int) -> WorkbookSubmission | None:
    return (WorkbookSubmission.query
            .filter_by(student_id=student_id, workbook_number=wb)
            .order_by(WorkbookSubmission.submission_time.desc())
            .first())

@app.route('/export_student_report/<int:student_id>')
@login_required
def export_student_report(student_id):
    if current_user.role == 'marker':
        if not marker_is_assigned_to_student(current_user.id, student_id):
            abort(403)
    elif current_user.role != 'admin':
        abort(403)

    student = db.session.get(User, student_id)
    if not student: abort(404)

    required = COURSE_WORKBOOKS.get((student.course or '').upper(), 3)
    merger = PdfMerger()
    merged = False
    merged_info, skipped_info = [], []

    for wb in range(1, required + 1):
        sub = _latest_submission(student.id, wb)

        # 1) Workbook PDF
        if sub:
            src_name = sub.corrected_submission_path or sub.file_path
            if src_name:
                src_path = file_path(src_name)
                if src_path.exists() and str(src_path).lower().endswith('.pdf'):
                    try:
                        with open(src_path, 'rb') as fh:
                            merger.append(fh)
                        merged = True
                        merged_info.append(f"WB{wb}: {src_path.name}")
                    except Exception:
                        try:
                            with open(src_path, 'rb') as fh:
                                reader = PdfReader(fh, strict=False)
                                if getattr(reader, "is_encrypted", False):
                                    try: reader.decrypt("")
                                    except Exception: pass
                                if getattr(reader, "is_encrypted", False):
                                    skipped_info.append(f"WB{wb}: encrypted (skipped)")
                                else:
                                    for page in reader.pages:
                                        merger.add_page(page)
                                    merged = True
                                    merged_info.append(f"WB{wb}: {src_path.name} (page-merge)")
                        except Exception:
                            skipped_info.append(f"WB{wb}: unreadable (skipped)")
                else:
                    skipped_info.append(f"WB{wb}: missing file")
            else:
                skipped_info.append(f"WB{wb}: no file path")
        else:
            skipped_info.append(f"WB{wb}: no submission")

        # 2) Feedback page (always append a summary page)
        if sub:
            fb_buf = _render_feedback_page(sub, student, wb)
        else:
            tmp = BytesIO()
            c = canvas.Canvas(tmp, pagesize=A4)
            W, H = A4
            c.setFont("Helvetica-Bold", 16)
            c.drawCentredString(W/2, H - 80, f"Workbook {wb} – Feedback Summary")
            c.setFont("Helvetica", 12)
            c.drawCentredString(W/2, H - 110, "No submission found.")
            c.showPage(); c.save()
            tmp.seek(0)
            fb_buf = tmp
        merger.append(fb_buf)

    if not merged:
        flash("No PDF workbooks could be merged." + (f" Skipped: {'; '.join(skipped_info)}" if skipped_info else ""), "warning")
        return redirect(url_for('marker_view_student', student_id=student.id) if current_user.role == 'marker' else 'admin_dashboard')

    out = BytesIO()
    try:
        merger.write(out)
    finally:
        try: merger.close()
        except Exception: pass
    out.seek(0)

    if merged_info: flash("Merged: " + "; ".join(merged_info[:6]) + ("…" if len(merged_info) > 6 else ""), "success")
    if skipped_info: flash("Skipped: " + "; ".join(skipped_info[:6]) + ("…" if len(skipped_info) > 6 else ""), "info")

    download_name = f"{secure_filename(student.username or 'student')}_report.pdf"
    return send_file(out, as_attachment=True, download_name=download_name, mimetype="application/pdf", max_age=0)

# ===================================================
# Routes: Admin (dashboard, assign, delete, activity, cohorts)
# ===================================================
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    students = User.query.filter_by(role='student').all()
    markers  = User.query.filter_by(role='marker').all()
    assignments = Assignment.query.all()

    workload = {m.id: 0 for m in markers}
    for a in assignments:
        workload[a.marker_id] = workload.get(a.marker_id, 0) + 1

    status_counts = {"Unsubmitted": 0, "Awaiting Marking": 0, "Referral": 0, "Passed": 0}
    for student in students:
        subs = WorkbookSubmission.query.filter_by(student_id=student.id).all()
        if not subs:
            status_counts["Unsubmitted"] += 1; continue
        latest = max(subs, key=lambda s: s.corrected_submission_time or s.submission_time)
        if not latest.marked and latest.is_referral:
            status_counts["Referral"] += 1
        elif not latest.marked:
            status_counts["Awaiting Marking"] += 1
        elif latest.marked and not latest.is_referral and latest.score == get_question_count(student.course, latest.workbook_number):
            status_counts["Passed"] += 1
        else:
            status_counts["Awaiting Marking"] += 1

    recent_submissions = (WorkbookSubmission.query
                          .order_by(WorkbookSubmission.submission_time.desc())
                          .limit(8).all())

    users = {u.id: u for u in User.query.all()}

    return render_template('admin_dashboard.html', students=students, markers=markers,
                           assignments=assignments, workload=workload,
                           status_counts=status_counts, recent_submissions=recent_submissions,
                           users=users)

@app.route('/admin_assign', methods=['GET', 'POST'])
@login_required
def admin_assign():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        marker_id  = request.form.get('marker_id')
        if not student_id or not marker_id:
            flash('Please choose both a student and a marker.', 'warning')
            return redirect(url_for('admin_assign'))
        try: student_id = int(student_id); marker_id = int(marker_id)
        except ValueError:
            flash('Invalid selection.', 'danger'); return redirect(url_for('admin_assign'))

        student = db.session.get(User, student_id); marker = db.session.get(User, marker_id)
        if not student or student.role != 'student': flash('Selected student not found.', 'danger'); return redirect(url_for('admin_assign'))
        if not marker or marker.role != 'marker': flash('Selected marker not found.', 'danger'); return redirect(url_for('admin_assign'))

        assignment = Assignment.query.filter_by(student_id=student.id).first()
        if assignment: assignment.marker_id = marker.id
        else: db.session.add(Assignment(student_id=student.id, marker_id=marker.id))
        db.session.commit()
        flash(f'Assigned {student.username} to {marker.username}.', 'success')
        return redirect(url_for('admin_assign'))

    students = User.query.filter_by(role='student').order_by(User.username.asc()).all()
    markers  = User.query.filter_by(role='marker').order_by(User.username.asc()).all()
    current_marker_by_student = {a.student_id: a.marker_id for a in Assignment.query.all()}
    return render_template('admin_assign.html', students=students, markers=markers,
                           current_marker_by_student=current_marker_by_student)

@app.route('/admin_delete_students')
@login_required
def admin_delete_students():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    students = User.query.filter_by(role='student').order_by(User.username.asc()).all()
    return render_template('admin_delete_students.html', students=students)

@app.route('/delete_student/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    if current_user.role != 'admin':
        abort(403)
    student = db.session.get(User, student_id)
    if not student or student.role != 'student':
        flash('Only student accounts can be deleted from this page.', 'warning')
        return redirect(url_for('admin_delete_students'))

    assignment = Assignment.query.filter_by(student_id=student.id).first()
    if assignment: db.session.delete(assignment)

    submissions = WorkbookSubmission.query.filter_by(student_id=student.id).all()
    for sub in submissions:
        _maybe_delete_uploaded_file(sub.file_path)
        _maybe_delete_uploaded_file(sub.corrected_submission_path)
        QuestionFeedback.query.filter_by(submission_id=sub.id).delete()
        db.session.delete(sub)

    db.session.delete(student); db.session.commit()
    flash('Student and related data deleted.', 'success')
    return redirect(url_for('admin_delete_students'))

@app.route('/admin_delete_markers')
@login_required
def admin_delete_markers():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    markers = User.query.filter_by(role='marker').order_by(User.username.asc()).all()
    assigned_counts = {m.id: 0 for m in markers}
    for a in Assignment.query.all():
        if a.marker_id in assigned_counts: assigned_counts[a.marker_id] += 1
    return render_template('admin_delete_markers.html', markers=markers, assigned_counts=assigned_counts)

@app.route('/delete_marker/<int:marker_id>', methods=['POST'])
@login_required
def delete_marker(marker_id):
    if current_user.role != 'admin':
        abort(403)
    marker = db.session.get(User, marker_id)
    if not marker or marker.role != 'marker':
        flash('Only marker accounts can be deleted here.', 'warning')
        return redirect(url_for('admin_delete_markers'))

    assignments = Assignment.query.filter_by(marker_id=marker.id).all()
    unassigned = len(assignments)
    for a in assignments: db.session.delete(a)

    db.session.delete(marker); db.session.commit()
    flash(('Marker deleted. {0} student(s) are now unassigned.'.format(unassigned)) if unassigned else 'Marker deleted.', 'success')
    return redirect(url_for('admin_delete_markers'))

# -------- Admin Activity --------
@app.route('/admin_activity')
@login_required
def admin_activity():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    def _last_event_readable(p: Path):
        if not p.exists(): return None, None, None
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line in reversed(lines):
                try:
                    obj = json.loads(line)
                    ts = obj.get("ts")
                    ev = (obj.get("event") or "").lower()
                    wb = (obj.get("details") or {}).get("workbook_number")
                    if ev == "login": action = "Login"
                    elif ev == "upload": action = f"Upload WB#{wb}" if wb else "Upload"
                    elif ev == "reupload": action = f"Re-upload WB#{wb}" if wb else "Re-upload"
                    elif ev == "view_feedback": action = f"Viewed Feedback WB#{wb}" if wb else "Viewed Feedback"
                    else: action = ev.replace("_", " ").title() if ev else "—"
                    return ts, _format_ts_human(ts), action
                except Exception:
                    continue
        except Exception:
            pass
        return None, None, None

    students = User.query.filter_by(role='student').order_by(User.username.asc()).all()
    rows = []
    for s in students:
        p = student_log_path(s.id)
        entries = 0
        if p.exists():
            try:
                with p.open("rb") as f:
                    for entries, _ in enumerate(f, 1): pass
            except Exception:
                entries = 0
        last_ts, last_ts_human, last_action = _last_event_readable(p)
        rows.append({"student": s, "has_log": p.exists(), "entries": entries,
                     "last_ts": last_ts, "last_ts_human": last_ts_human, "last_action": last_action})
    return render_template('admin_activity.html', rows=rows)

@app.route('/admin_activity/<int:student_id>')
@login_required
def admin_activity_student(student_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    student = db.session.get(User, student_id)
    if not student or student.role != 'student': abort(404)
    p = student_log_path(student_id)
    events = []
    if p.exists():
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    obj = json.loads(line)
                    events.append({"ts": obj.get("ts"),
                                   "event": obj.get("event"),
                                   "details": obj.get("details", {}) or {}})
                except Exception:
                    continue
            events.sort(key=lambda e: e.get("ts") or "", reverse=True)
        except Exception:
            pass
    simple = []
    for e in events:
        ev = (e.get("event") or "").lower()
        wb = e.get("details", {}).get("workbook_number")
        if ev == "login": action = "Login"
        elif ev == "upload": action = f"Upload WB#{wb}" if wb else "Upload"
        elif ev == "reupload": action = f"Re-upload WB#{wb}" if wb else "Re-upload"
        elif ev == "view_feedback": action = f"Viewed Feedback WB#{wb}" if wb else "Viewed Feedback"
        else: action = ev.replace("_", " ").title() if ev else "—"
        simple.append({"ts": e.get("ts"),
                       "formatted_ts": _format_ts_human(e.get("ts")),
                       "action": action})
    return render_template('admin_activity_student.html',
                           student=student, events=simple, log_exists=p.exists())

@app.route('/admin_activity/<int:student_id>/download')
@login_required
def admin_activity_download(student_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    p = student_log_path(student_id)
    if not p.exists():
        flash('No log file for this student.', 'info')
        return redirect(url_for('admin_activity_student', student_id=student_id))
    records = []
    try:
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                obj = json.loads(line)
                ts = obj.get("ts"); ev = (obj.get("event") or "").lower()
                wb = (obj.get("details") or {}).get("workbook_number")
                if ev == "login": action = "Login"
                elif ev == "upload": action = f"Upload WB#{wb}" if wb else "Upload"
                elif ev == "reupload": action = f"Re-upload WB#{wb}" if wb else "Re-upload"
                elif ev == "view_feedback": action = f"Viewed Feedback WB#{wb}" if wb else "Viewed Feedback"
                else: action = ev.replace("_", " ").title() if ev else "—"
                records.append((ts, action))
            except Exception:
                continue
    except Exception:
        records = []
    records.sort(key=lambda r: r[0] or "", reverse=True)
    lines = [f"{_format_ts_human(ts)} — {action}" for ts, action in records] or ["No log entries for this student."]
    buf = BytesIO(("\n".join(lines) + "\n").encode("utf-8"))
    student = db.session.get(User, student_id)
    filename = f"{secure_filename((student.username if student else f'student_{student_id}') or f'student_{student_id}')}_activity.txt"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="text/plain")

@app.route('/admin_activity/<int:student_id>/clear', methods=['POST'])
@login_required
def admin_activity_clear(student_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    p = student_log_path(student_id)
    try:
        if p.exists(): p.unlink(); flash('Log cleared for student.', 'success')
        else: flash('No log file to clear.', 'info')
    except Exception:
        flash('Could not clear log file.', 'danger')
    return redirect(url_for('admin_activity_student', student_id=student_id))

# -------- Admin: Cohorts / Classes --------
@app.route('/admin_cohorts', methods=['GET', 'POST'])
@login_required
def admin_cohorts():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    markers = User.query.filter_by(role='marker').order_by(User.username.asc()).all()
    courses = sorted(COURSE_WORKBOOKS.keys())

    if request.method == 'POST':
        course = request.form.get('course') or ''
        marker_id = request.form.get('marker_id') or ''
        start_date_str = request.form.get('start_date') or ''
        name = (request.form.get('name') or '').strip()

        if course not in COURSE_WORKBOOKS:
            flash('Please choose a valid course.', 'warning'); return redirect(url_for('admin_cohorts'))
        try:
            marker_id = int(marker_id)
        except ValueError:
            flash('Please choose a marker.', 'warning'); return redirect(url_for('admin_cohorts'))
        marker = db.session.get(User, marker_id)
        if not marker or marker.role != 'marker':
            flash('Selected marker not found.', 'danger'); return redirect(url_for('admin_cohorts'))
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Please provide a valid start date (YYYY-MM-DD).', 'warning'); return redirect(url_for('admin_cohorts'))

        passcode = None
        for _ in range(6):
            candidate = generate_passcode(10)
            if not Cohort.query.filter_by(passcode=candidate).first():
                passcode = candidate; break
        if not passcode:
            flash('Could not generate a unique passcode. Try again.', 'danger')
            return redirect(url_for('admin_cohorts'))

        cohort = Cohort(
            name=name or f"{course} {start_date.strftime('%b %Y')}",
            course=course, marker_id=marker_id,
            start_date=start_date, passcode=passcode, active=True
        )
        db.session.add(cohort); db.session.commit()
        flash(f'Cohort created. Passcode: {passcode}', 'success')
        return redirect(url_for('admin_cohorts'))

    cohorts = Cohort.query.order_by(Cohort.created_at.desc()).all()
    marker_map = {m.id: m for m in User.query.filter_by(role='marker').all()}
    return render_template('admin_cohorts.html', cohorts=cohorts, markers=markers,
                           marker_map=marker_map, courses=courses)

@app.route('/admin_cohorts/<int:cohort_id>/toggle', methods=['POST'])
@login_required
def admin_cohorts_toggle(cohort_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    cohort = db.session.get(Cohort, cohort_id)
    if not cohort: abort(404)
    cohort.active = not cohort.active
    db.session.commit()
    flash(f'Cohort "{cohort.name}" is now {"active" if cohort.active else "inactive"}.', 'info')
    return redirect(url_for('admin_cohorts'))

@app.route('/admin_cohorts/<int:cohort_id>/regen', methods=['POST'])
@login_required
def admin_cohorts_regen(cohort_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    cohort = db.session.get(Cohort, cohort_id)
    if not cohort: abort(404)
    for _ in range(6):
        candidate = generate_passcode(10)
        if not Cohort.query.filter_by(passcode=candidate).first():
            cohort.passcode = candidate; break
    else:
        flash('Could not generate a new passcode. Try again.', 'danger')
        return redirect(url_for('admin_cohorts'))
    db.session.commit()
    flash(f'New passcode: {cohort.passcode}', 'success')
    return redirect(url_for('admin_cohorts'))

# ===================================================
# Contact page (marker visible to student)
# ===================================================
@app.route('/contact')
@login_required
def contact():
    show_core_contacts = (current_user.role != 'admin')

    marker_user = None
    show_marker_card = False
    if current_user.role == 'student':
        assign = Assignment.query.filter_by(student_id=current_user.id).first()
        if assign:
            marker_user = db.session.get(User, assign.marker_id)
        show_marker_card = marker_user is not None

    contacts = {
        "director": {"name": "Jane", "title": "Training Director", "email": "jane.edwards@northwestmedicalsolutions.co.uk"},
        "admin": {"name": "David", "title": "Training Admin Support", "email": "david.batty@northwestmedicalsolutions.co.uk"}
    }

    return render_template('contact.html',
                           show_core_contacts=show_core_contacts,
                           show_marker_card=show_marker_card,
                           marker_user=marker_user,
                           contacts=contacts)

# ===================================================
# Main (dev local only; Gunicorn/Render ignores this)
# ===================================================
if __name__ == '__main__':
    # In local dev, ensure DB now
    with app.app_context():
        db.create_all()
        ensure_sqlite_schema()
    app.run(debug=True)