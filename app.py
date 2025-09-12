from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    send_from_directory, abort, send_file
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
from pathlib import Path
import os
import json
import secrets

# ===================================================
# App & Config
# ===================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 10 * 1024 * 1024))  # 10 MB default

# ---------- Storage selection ----------
# Priority: explicit UPLOAD_ROOT -> Render persistent disk -> local ./uploads
project_root = Path(__file__).resolve().parent
is_render = bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))

if os.getenv("UPLOAD_ROOT"):
    # explicit override (works for both dev & prod)
    upload_root = Path(os.getenv("UPLOAD_ROOT"))
elif is_render:
    # production on Render: use persistent disk
    upload_root = Path(os.getenv("PERSIST_ROOT", "/var/data")) / "uploads"
else:
    # local dev in PyCharm: keep files in repo folder
    upload_root = project_root / "uploads"

upload_root.mkdir(parents=True, exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(upload_root)

# Optional: keep PDFs in a tidy subfolder
pdf_dir = Path(app.config['UPLOAD_FOLDER']) / "pdfs"
pdf_dir.mkdir(parents=True, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ===== helper (use this when saving) =====
def save_uploaded_pdf(file_storage, filename: str) -> str:
    """Save a PDF to the correct env-specific upload folder and return the full path."""
    safe = secure_filename(filename)
    full_path = pdf_dir / safe
    file_storage.save(full_path)
    return str(full_path)

# ===================================================
# Constants
# ===================================================
COURSE_WORKBOOKS = {'FREC4': 3, 'SALM': 1, 'CFR': 1}
COURSE_PASSCODES = {'FREC4': 'nwmsfrec4', 'SALM': 'nwmssalm', 'CFR': 'nwmscfr'}  # legacy fallback
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
def get_question_count(course: str | None, workbook_number: int) -> int:
    return QUESTION_COUNTS.get((course or '*', workbook_number),
           QUESTION_COUNTS.get(('*', workbook_number), 10))

DISPLAY_TZ = ZoneInfo(os.environ.get('DISPLAY_TZ', 'Europe/London'))
def _format_ts_human(ts_iso: str | None) -> str:
    if not ts_iso:
        return "—"
    try:
        dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        return dt.astimezone(DISPLAY_TZ).strftime("%a %d %b %Y, %H:%M %Z")
    except Exception:
        return ts_iso

# ===================================================
# Activity logging (per-student JSONL)
# ===================================================
LOGS_DIR = Path(os.environ.get('ACTIVITY_LOGS_DIR', 'activity_logs'))
LOGS_DIR.mkdir(parents=True, exist_ok=True)
def student_log_path(student_id: int) -> Path:
    return LOGS_DIR / f"student_{student_id}.log"
def log_student_event(student_id: int, event: str, details: dict | None = None):
    try:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
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
# Time / Token Helpers
# ===================================================
def now_utc(): return datetime.now(timezone.utc)
def now_utc_naive(): return now_utc().replace(tzinfo=None)
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
# Countdown Status
# ===================================================
def add_months(dt, months):
    """Add calendar months to a date, clamping the day where needed (no python-dateutil required)."""
    if not dt:
        return None
    year = dt.year + (dt.month - 1 + months) // 12
    month = (dt.month - 1 + months) % 12 + 1
    # clamp day to month length
    from calendar import monthrange
    day = min(dt.day, monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)

def build_workbook_item(student_id, wb_number):
    """Return per-workbook dict for template."""
    latest = (WorkbookSubmission.query
              .filter_by(student_id=student_id, workbook_number=wb_number)
              .order_by(WorkbookSubmission.submission_time.desc())
              .first())

    # Defaults
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

    # Attempts are tracked by referral_count (increments when marker selects "Refer")
    # Attempts so far = referral_count + 1 (the current attempt)
    attempts_so_far = (latest.referral_count or 0) + 1
    attempts_left = max(0, MAX_ATTEMPTS - attempts_so_far)
    item["attempts_so_far"] = attempts_so_far
    item["attempts_left"] = attempts_left
    item["can_upload"] = False

    if not latest.marked:
        # Submitted but not yet marked
        item["label"] = "Submitted"
        item["badge"] = "bg-warning text-dark"
        item["can_reattempt"] = False
        return item

    # Marked:
    if latest.score == 100 and not latest.is_referral:
        item["label"] = "Marked Pass"
        item["badge"] = "bg-success"
        item["can_reattempt"] = False
        return item

    # Referred case (most typical for non-pass prior to final attempt)
    if latest.is_referral:
        if attempts_left > 0:
            item["label"] = "Waiting for reattempt"
            item["badge"] = "bg-danger"
            item["can_reattempt"] = True
        else:
            item["label"] = "Failed"
            item["badge"] = "bg-dark text-white"
            item["can_reattempt"] = False
        return item

    # Explicit Fail (used on final attempt)
    if latest.score == 0:
        if attempts_left == 0:
            item["label"] = "Failed"
            item["badge"] = "bg-dark text-white"
            item["can_reattempt"] = False
        else:
            # If a Fail was recorded earlier than final (shouldn't normally happen),
            # treat as needs reattempt while there are attempts available.
            item["label"] = "Waiting for reattempt"
            item["badge"] = "bg-danger"
            item["can_reattempt"] = True
        return item

    # Fallback (shouldn't hit)
    return item

def compute_overall_status(items, required):
    """Overall student status: Pass if all passed; Fail if all failed; else In Progress."""
    passes = 0
    fails = 0
    for it in items:
        label = it["label"]
        if label == "Marked Pass":
            passes += 1
        elif label == "Failed":
            fails += 1
    if passes == required:
        return "Pass"
    if fails == required:
        return "Fail"
    return "In Progress"

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
    score       = db.Column(db.Integer, nullable=True)   # number of questions passed
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
    if not db.engine.url.get_backend_name().startswith('sqlite'):
        return
    with db.engine.connect() as conn:
        # workbook_submission.corrected_submission_time
        try:
            cols_ws = [row['name'] for row in conn.execute(text("PRAGMA table_info(workbook_submission)")).mappings()]
            if 'corrected_submission_time' not in cols_ws:
                conn.execute(text("ALTER TABLE workbook_submission ADD COLUMN corrected_submission_time DATETIME"))
        except OperationalError:
            pass
        # user.cohort_id
        try:
            cols_user = [row['name'] for row in conn.execute(text("PRAGMA table_info(user)")).mappings()]
            if 'cohort_id' not in cols_user:
                conn.execute(text("ALTER TABLE user ADD COLUMN cohort_id INTEGER"))
        except OperationalError:
            pass
        conn.commit()

# ===================================================
# Load user
# ===================================================
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# ===================================================
# Helpers
# ===================================================
def get_student_status(student: User, required_workbooks: int) -> str:
    # NEW RULE: If any workbook has 0 attempts left and did not pass => overall Fail
    for wb in range(1, required_workbooks + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())
        if not latest:
            continue
        attempts_so_far = 1 + (latest.referral_count or 0)
        attempts_left = max(0, MAX_ATTEMPTS - attempts_so_far)
        q_total = get_question_count(student.course, wb)

        # If no attempts left AND latest is marked AND not a full pass => immediate Fail
        if attempts_left == 0 and latest.marked:
            is_full_pass = (latest.score is not None and latest.score == q_total and not latest.is_referral)
            if not is_full_pass:
                return 'Fail'

    # Otherwise fall back to the original aggregate logic
    states = []
    for wb in range(1, required_workbooks + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())
        if not latest:
            states.append('pending'); continue
        if latest.corrected_submission_path and not latest.marked:
            states.append('submitted'); continue
        if not latest.marked:
            states.append('submitted'); continue

        q_total = get_question_count(student.course, wb)
        if latest.is_referral:
            states.append('referral')
        elif latest.score is not None and latest.score == q_total:
            states.append('pass')
        elif latest.score == 0:
            states.append('fail')
        else:
            states.append('submitted')

    if states and all(s == 'pass' for s in states):
        return 'Pass'
    if states and all(s == 'fail' for s in states):
        return 'Fail'
    return 'In Progress'

def get_marking_deadline(submission: WorkbookSubmission):
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
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

def generate_passcode(length: int = 10) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

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

        # STUDENT: cohort passcode is required (no course dropdown anymore)
        if role == 'student':
            raw_code = (request.form.get('cohort_passcode') or '').strip()
            # normalize (remove internal spaces + uppercase) to be forgiving
            norm_code = ''.join(raw_code.split()).upper()
            if not norm_code:
                flash('Please enter your cohort passcode.', 'danger')
                return redirect(url_for('register'))

            # fetch cohorts and compare normalized (uppercase, no spaces)
            # NOTE: Cohort.passcode is stored uppercase by our generator.
            cohort = None
            for ch in Cohort.query.filter_by(active=True).all():
                if (ch.passcode or '').upper() == norm_code:
                    cohort = ch
                    break

            if not cohort:
                flash('Cohort passcode not recognized or inactive.', 'danger')
                return redirect(url_for('register'))

            # Create the student with cohort+course from cohort, and auto-assign marker
            user = User(
                username=username,
                email=email,
                password=generate_password_hash(password_raw),
                role='student',
                course=cohort.course,
                cohort_id=cohort.id
            )
            db.session.add(user)
            db.session.commit()

            # Auto-assign to cohort's marker
            existing = Assignment.query.filter_by(student_id=user.id).first()
            if existing:
                existing.marker_id = cohort.marker_id
            else:
                db.session.add(Assignment(student_id=user.id, marker_id=cohort.marker_id))
            db.session.commit()

            flash('Account created and cohort assigned. Please log in.', 'success')
            return redirect(url_for('login'))

        # MARKER or ADMIN
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password_raw),
            role=role
        )
        db.session.add(user)
        db.session.commit()
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

# Password reset (dev-friendly: shows link on page)
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

    # Handle uploads
    if request.method == 'POST':
        wb_number = int(request.form.get('workbook_number', '0') or 0)
        if wb_number <= 0:
            flash('Invalid workbook number.', 'warning')
            return redirect(url_for('student_dashboard'))

        # First submission
        up_file = request.files.get('file')
        # Reattempt upload (after referral)
        ref_file = request.files.get('referral_file')

        if up_file and up_file.filename:
            filename = secure_filename(up_file.filename)
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            up_file.save(path)
            # Derive referral_count from the latest (keep continuity)
            latest_existing = (WorkbookSubmission.query
                               .filter_by(student_id=current_user.id, workbook_number=wb_number)
                               .order_by(WorkbookSubmission.submission_time.desc())
                               .first())
            referral_count = (latest_existing.referral_count if latest_existing else 0) or 0
            # Create a new submission row
            submission = WorkbookSubmission(
                student_id=current_user.id,
                workbook_number=wb_number,
                file_path=filename,
                referral_count=referral_count,
                marked=False,
                is_referral=False
            )
            db.session.add(submission)
            db.session.commit()
            flash(f'Workbook {wb_number} uploaded.', 'success')
            return redirect(url_for('student_dashboard'))

        elif ref_file and ref_file.filename:
            # Attach the corrected file to the latest submission record
            filename = secure_filename(ref_file.filename)
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            ref_file.save(path)

            latest = (WorkbookSubmission.query
                      .filter_by(student_id=current_user.id, workbook_number=wb_number)
                      .order_by(WorkbookSubmission.submission_time.desc())
                      .first())
            if not latest:
                flash('No prior submission found for this workbook.', 'warning')
                return redirect(url_for('student_dashboard'))

            latest.corrected_submission_path = filename
            # keep the submission unmarked; marker will review this corrected file
            db.session.commit()
            flash(f'Workbook {wb_number} re-uploaded for referral.', 'success')
            return redirect(url_for('student_dashboard'))

        else:
            flash('Please choose a PDF to upload.', 'warning')
            return redirect(url_for('student_dashboard'))

    # --- Build dashboard view data ---
    course_code = (current_user.course or '').upper()
    required = COURSE_WORKBOOKS.get(course_code, 3)

    # Cohort start date (if you have a Cohort model wired to the user)
    start_date = None
    if hasattr(current_user, "cohort") and current_user.cohort and current_user.cohort.start_date:
        start_date = current_user.cohort.start_date

    # Compute deadline by course
    months_allowed = COURSE_DEADLINES.get(course_code, 6)
    deadline_date = add_months(start_date, months_allowed) if start_date else None

    # Per-workbook rows
    items = []
    for n in range(1, required + 1):
        items.append(build_workbook_item(current_user.id, n))

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

    if submission.is_referral:
        overall = 'Referral'
    elif submission.score == passed == get_question_count(current_user.course, workbook_number):
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
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

# ===================================================
# Routes: Marker
# ===================================================
@app.route('/marker_dashboard')
@login_required
def marker_dashboard():
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    # Only students assigned to this marker
    assigned_student_ids = [a.student_id for a in Assignment.query.filter_by(marker_id=current_user.id).all()]
    students = User.query.filter(User.role == 'student', User.id.in_(assigned_student_ids)).order_by(User.username.asc()).all()

    # Donut counters (per-student workload; each student contributes their course's required count)
    total_unsubmitted = 0
    total_to_mark = 0
    total_marked = 0

    # Per-student summary (optional for list below donut)
    overview_rows = []

    for s in students:
        required = COURSE_WORKBOOKS.get((s.course or '').upper(), 3)
        s_unsubmitted = required
        s_to_mark = 0
        s_marked = 0

        # For each workbook slot 1..required, look at the *latest* submission for that slot
        for wb in range(1, required + 1):
            latest = (WorkbookSubmission.query
                      .filter_by(student_id=s.id, workbook_number=wb)
                      .order_by(WorkbookSubmission.submission_time.desc())
                      .first())
            if not latest:
                # No submission yet → stays counted as Unsubmitted
                continue

            # A submission exists → it no longer counts as Unsubmitted
            s_unsubmitted -= 1

            if latest.marked:
                # Marked (Pass/Fail/Referral) counts as Marked for volume (the marker already handled it)
                s_marked += 1
            else:
                # Awaiting marking (initial or reupload) → workload
                s_to_mark += 1

        total_unsubmitted += s_unsubmitted
        total_to_mark += s_to_mark
        total_marked += s_marked

        overview_rows.append({
            "student": s,
            "required": required,
            "unsubmitted": s_unsubmitted,
            "to_mark": s_to_mark,
            "marked": s_marked,
        })

    donut_data = {
        "unsubmitted": total_unsubmitted,
        "to_mark": total_to_mark,
        "marked": total_marked,
        "total": total_unsubmitted + total_to_mark + total_marked
    }

    # Recent submissions list (unchanged, optional)
    recent_submissions = (WorkbookSubmission.query
                          .order_by(WorkbookSubmission.submission_time.desc())
                          .limit(10)
                          .all())
    users = {u.id: u for u in User.query.filter(User.id.in_(assigned_student_ids)).all()}

    return render_template(
        'marker_dashboard.html',
        donut_data=donut_data,
        students_overview=overview_rows,
        recent_submissions=recent_submissions,
        users=users
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

    # Determine attempt info
    attempts_so_far = 1 + (submission.referral_count or 0)
    attempts_left = max(0, MAX_ATTEMPTS - attempts_so_far)
    final_attempt = (attempts_left == 0)

    # Figure out which questions should be open:
    #  - First attempt: all questions open
    #  - Later attempts: only previously referred questions open; previously passed are locked/greyed
    previous_submissions = (WorkbookSubmission.query
                            .filter_by(student_id=student.id, workbook_number=wb_num)
                            .filter(WorkbookSubmission.id != submission.id)
                            .order_by(WorkbookSubmission.submission_time.desc())
                            .all())

    # Gather previously referred/pass info from immediately previous marked submission (if any)
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
        # Clear existing feedback for this submission and re-save
        QuestionFeedback.query.filter_by(submission_id=submission.id).delete()

        # Save new decisions for open questions
        for qn in open_questions:
            status = request.form.get(f"q_{qn}_status")  # 'Pass' or 'Refer' (or 'Fail' label maps to 'Refer' if final)
            comment = (request.form.get(f"q_{qn}_comment") or '').strip()

            # For final attempt UI we will post 'Fail' but we normalize:
            if status == 'Fail':
                status = 'Refer'  # store as 'Refer' to keep schema consistent; we'll force overall Fail below

            if status in ('Pass', 'Refer'):
                db.session.add(QuestionFeedback(
                    submission_id=submission.id,
                    question_number=qn,
                    status=status,
                    comment=comment
                ))

        # Carry forward previously passed questions on reattempts so totals are correct
        if not is_first_attempt and last_prev:
            for qn, com in prev_pass_comments.items():
                if qn not in previously_referred:
                    db.session.add(QuestionFeedback(
                        submission_id=submission.id,
                        question_number=qn,
                        status='Pass',
                        comment=com
                    ))

        # Finalize submission outcome
        submission.marked = True
        all_fb = QuestionFeedback.query.filter_by(submission_id=submission.id).all()
        total = len(all_fb)
        passed = sum(1 for f in all_fb if f.status == 'Pass')
        submission.score = passed

        if passed == total and total > 0:
            # Full pass
            submission.is_referral = False
            flash(f'Saved: all {passed} questions passed. Submission set to Pass.', 'success')
        else:
            if final_attempt:
                # NEW RULE: final attempt & not full pass => force Fail (no more referrals)
                submission.is_referral = False
                submission.score = 0  # treat as fail score (optional but clear)
                flash('Saved on final attempt: not all questions passed. Submission set to Fail.', 'danger')
            else:
                # Still have attempts left → Referral as before
                submission.is_referral = True
                submission.referral_count = (submission.referral_count or 0) + 1
                flash(f'Saved: {passed}/{total} questions passed. Submission set to Referral.', 'warning')

        db.session.commit()
        return redirect(url_for('marker_view_student', student_id=student.id))

    # GET: build rows for the template; lock previously passed when not first attempt
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
                           final_attempt=final_attempt)  # <-- tell template

# ===================================================
# Export Student Report (merge PDFs)
# ===================================================
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

    required = COURSE_WORKBOOKS.get(student.course, 3)
    candidates = []
    for wb in range(1, required + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc()).first())
        if not latest:
            candidates.append((wb, None, "missing")); continue
        chosen = latest.corrected_submission_path or latest.file_path
        if not chosen:
            candidates.append((wb, None, "no_file")); continue
        fullpath = os.path.join(app.config['UPLOAD_FOLDER'], chosen)
        candidates.append((wb, fullpath if os.path.exists(fullpath) else None, "ok" if os.path.exists(fullpath) else "not_found"))

    merger = PdfMerger()
    merged_any = False
    merged_list, skipped_list = [], []
    for wb, path, state in sorted(candidates, key=lambda t: t[0]):
        if state != "ok" or not path:
            skipped_list.append(f"WB{wb}: {state}")
            continue
        if not path.lower().endswith('.pdf'):
            skipped_list.append(f"WB{wb}: not a PDF ({os.path.basename(path)})")
            continue
        try:
            with open(path, "rb") as fh:
                merger.append(fh)
            merged_any = True
            merged_list.append(f"WB{wb}: {os.path.basename(path)}")
        except Exception:
            try:
                with open(path, "rb") as fh:
                    reader = PdfReader(fh, strict=False)
                    if getattr(reader, "is_encrypted", False):
                        try: reader.decrypt("")
                        except Exception: pass
                    if getattr(reader, "is_encrypted", False):
                        skipped_list.append(f"WB{wb}: encrypted (skipped)")
                        continue
                    for page in reader.pages:
                        merger.add_page(page)
                merged_any = True
                merged_list.append(f"WB{wb}: {os.path.basename(path)} (page-merge)")
            except Exception:
                skipped_list.append(f"WB{wb}: unreadable (skipped)")

    if not merged_any:
        flash("No PDF workbooks could be merged." + (f" Skipped: {'; '.join(skipped_list)}" if skipped_list else ""), "warning")
        return redirect(url_for('marker_view_student', student_id=student.id) if current_user.role == 'marker' else 'admin_dashboard')

    buf = BytesIO()
    try: merger.write(buf)
    finally:
        try: merger.close()
        except Exception: pass
    buf.seek(0)

    if merged_list: flash("Merged: " + "; ".join(merged_list[:6]) + ("…" if len(merged_list) > 6 else ""), "success")
    if skipped_list: flash("Skipped: " + "; ".join(skipped_list[:6]) + ("…" if len(skipped_list) > 6 else ""), "info")

    download_name = f"{secure_filename(student.username or 'student')}_workbooks.pdf"
    return send_file(buf, as_attachment=True, download_name=download_name, mimetype="application/pdf", max_age=0)

# ===================================================
# Routes: Admin (dashboard, assign, delete, activity)
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

    return render_template('admin_dashboard.html', students=students, markers=markers,
                           assignments=assignments, workload=workload,
                           status_counts=status_counts, recent_submissions=recent_submissions)

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

# -------- Admin Activity log pages --------
@app.route('/admin_activity')
@login_required
def admin_activity():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    def _last_event_readable(p: Path):
        """Return (ts_iso, formatted_ts, action_str) for the last valid JSONL event in a log file."""
        if not p.exists():
            return None, None, None
        try:
            # Read all and walk backwards to find last valid JSON event
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line in reversed(lines):
                try:
                    obj = json.loads(line)
                    ts = obj.get("ts")
                    ev = (obj.get("event") or "").lower()
                    wb = (obj.get("details") or {}).get("workbook_number")

                    if ev == "login":
                        action = "Login"
                    elif ev == "upload":
                        action = f"Upload WB#{wb}" if wb else "Upload"
                    elif ev == "reupload":
                        action = f"Re-upload WB#{wb}" if wb else "Re-upload"
                    elif ev == "view_feedback":
                        action = f"Viewed Feedback WB#{wb}" if wb else "Viewed Feedback"
                    else:
                        action = ev.replace("_", " ").title() if ev else "—"

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
        # count entries (best-effort)
        entries = 0
        if p.exists():
            try:
                with p.open("rb") as f:
                    for entries, _ in enumerate(f, 1):
                        pass
            except Exception:
                entries = 0

        last_ts, last_ts_human, last_action = _last_event_readable(p)
        rows.append({
            "student": s,
            "has_log": p.exists(),
            "entries": entries,
            "last_ts": last_ts,
            "last_ts_human": last_ts_human,
            "last_action": last_action,
        })

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
                    events.append({
                        "ts": obj.get("ts"),
                        "event": obj.get("event"),
                        "details": obj.get("details", {}) or {}
                    })
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
        simple.append({"ts": e.get("ts"), "formatted_ts": _format_ts_human(e.get("ts")), "action": action})

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

# ===================================================
# Admin: Cohorts / Classes
# ===================================================
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

        # unique passcode generation
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

    # Replace these placeholders if/when you have real addresses
    contacts = {
        "director": {
            "name": "Jane",
            "title": "Training Director",
            "email": "jane.edwards@northwestmedicalsolutions.co.uk"
        },
        "admin": {
            "name": "David",
            "title": "Training Admin Support",
            "email": "david.batty@northwestmedicalsolutions.co.uk"
        }
    }

    return render_template(
        'contact.html',
        show_core_contacts=show_core_contacts,
        show_marker_card=show_marker_card,
        marker_user=marker_user,
        contacts=contacts
    )

# ===================================================
# Main
# ===================================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_sqlite_schema()
    app.run(debug=True)