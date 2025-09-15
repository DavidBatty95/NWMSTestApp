from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    abort, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, text, func
from sqlalchemy.exc import OperationalError
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

project_root = Path(__file__).resolve().parent
is_render = bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))

# ---------- Database (Render persistent or local) ----------
if os.getenv("DATABASE_URL"):
    db_url = os.getenv("DATABASE_URL")
elif is_render:
    data_dir = Path(os.getenv("PERSIST_ROOT", "/var/data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    db_url = f"sqlite:///{(data_dir / 'database.db').as_posix()}"
else:
    data_dir = project_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    db_url = f"sqlite:///{(data_dir / 'database.db').as_posix()}"

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ---------- Uploads (Render persistent or local) ----------
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 50 * 1024 * 1024))  # 50 MB default

if os.getenv("UPLOAD_ROOT"):
    upload_root = Path(os.getenv("UPLOAD_ROOT"))
elif is_render:
    upload_root = Path(os.getenv("PERSIST_ROOT", "/var/data")) / "uploads"
else:
    upload_root = project_root / "uploads"

upload_root.mkdir(parents=True, exist_ok=True)
pdf_dir = upload_root / "pdfs"
pdf_dir.mkdir(parents=True, exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(upload_root)

# ===================================================
# DB / Login
# ===================================================
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ===================================================
# Constants
# ===================================================
COURSE_WORKBOOKS = {'FREC4': 3, 'SALM': 1, 'CFR': 1}
QUESTION_COUNTS = {
    ('FREC4', 1): 10, ('FREC4', 2): 10, ('FREC4', 3): 10,
    ('CFR', 1): 10, ('SALM', 1): 8,
    ('*', 1): 10, ('*', 2): 10, ('*', 3): 10,
}
COURSE_DEADLINES = {"FREC4": 6, "ILS": 3, "SALM": 3, "CFR": 3}
MARKING_DEADLINE_DAYS = 14
MAX_ATTEMPTS = 4
DISPLAY_TZ = ZoneInfo(os.environ.get('DISPLAY_TZ', 'Europe/London'))

# ===================================================
# Helpers / Time
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
    if not dt:
        return None
    year = dt.year + (dt.month - 1 + months) // 12
    month = (dt.month - 1 + months) % 12 + 1
    from calendar import monthrange
    day = min(dt.day, monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)

def generate_passcode(length: int = 10) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ===================================================
# Upload helpers (relative paths + normalization)
# ===================================================
def save_uploaded_pdf(file_storage, filename: str) -> str:
    """
    Save PDF into UPLOAD_ROOT/pdfs/YYYY/MM/<rand>-<secure>.pdf
    Returns a RELATIVE path like 'pdfs/2025/09/abcd1234-workbook.pdf'
    """
    if not file_storage or not filename:
        abort(400, "No file provided")
    safe = secure_filename(filename)
    today = datetime.now().strftime('%Y/%m')
    target_dir = pdf_dir / today
    target_dir.mkdir(parents=True, exist_ok=True)
    final_name = f"{secrets.token_hex(8)}-{safe}"
    full_path = (target_dir / final_name).resolve()
    file_storage.save(full_path)
    return str(full_path.relative_to(upload_root))

def _rel_to_upload_root(p: Path) -> str | None:
    try:
        return str(p.resolve().relative_to(upload_root.resolve()))
    except Exception:
        return None

def normalize_db_file_path(db_value: str | None) -> str | None:
    """
    Accepts absolute or relative DB path and returns a clean RELATIVE path
    under upload_root suitable for url_for('uploaded_file', filename=...).
    Returns None if invalid/missing.
    """
    if not db_value:
        return None
    p = Path(db_value)
    if p.is_absolute():
        return _rel_to_upload_root(p)
    q = (upload_root / p).resolve()
    if str(q).startswith(str(upload_root.resolve())) and q.exists():
        return str(p)
    return None

# ===================================================
# Activity logs
# ===================================================
LOGS_DIR = Path(os.getenv('ACTIVITY_LOGS_DIR', upload_root / "activity_logs"))
LOGS_DIR.mkdir(parents=True, exist_ok=True)

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
# Reset tokens
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
# Seed defaults
# ===================================================
def seed_default_courses():
    defaults = [
        {"code": "FREC4", "name": "FREC 4", "workbooks": 3, "questions": 10},
        {"code": "CFR",   "name": "CFR",    "workbooks": 1, "questions": 10},
        {"code": "SALM",  "name": "SALM",   "workbooks": 1, "questions": 10},
    ]
    for d in defaults:
        course = Course.query.filter(func.upper(Course.code) == d["code"]).first()
        if not course:
            course = Course(code=d["code"], name=d["name"], workbooks_count=d["workbooks"])
            db.session.add(course)
            db.session.flush()
        else:
            if (course.workbooks_count or 0) < d["workbooks"]:
                course.workbooks_count = d["workbooks"]
        for i in range(1, d["workbooks"] + 1):
            cq = CourseQuestion.query.filter_by(course_id=course.id, workbook_number=i).first()
            if not cq:
                db.session.add(CourseQuestion(course_id=course.id, workbook_number=i, question_count=d["questions"]))
            else:
                if not cq.question_count or cq.question_count <= 0:
                    cq.question_count = d["questions"]
    db.session.commit()

# ===================================================
# Models
# ===================================================
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), nullable=False, unique=True)
    name = db.Column(db.String(120), nullable=False)
    workbooks_count = db.Column(db.Integer, nullable=False, default=3)
    created_at = db.Column(db.DateTime, default=now_utc_naive)
    questions = db.relationship("CourseQuestion", backref="course", cascade="all, delete-orphan")

class CourseQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    workbook_number = db.Column(db.Integer, nullable=False)
    question_count = db.Column(db.Integer, nullable=False, default=10)
    __table_args__ = (db.UniqueConstraint('course_id', 'workbook_number', name='uq_course_wb'),)

class Cohort(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=True)
    course = db.Column(db.String(10), nullable=False)
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
    role     = db.Column(db.String(50),  nullable=False)  # 'student','marker','admin'
    course   = db.Column(db.String(10),  nullable=True)   # for students
    cohort_id = db.Column(db.Integer, db.ForeignKey('cohort.id'), nullable=True)
    cohort = db.relationship('Cohort', foreign_keys=[cohort_id])

class WorkbookSubmission(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    student_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    workbook_number = db.Column(db.Integer, nullable=False)
    file_path   = db.Column(db.String(255))
    submission_time = db.Column(db.DateTime, default=now_utc_naive)
    marked      = db.Column(db.Boolean, default=False)
    score       = db.Column(db.Integer, nullable=True)
    feedback    = db.Column(db.Text, nullable=True)
    is_referral = db.Column(db.Boolean, default=False)
    referral_count = db.Column(db.Integer, default=0)  # increments when a submission is set to Referral
    # Legacy fields (kept for backward compatibility; not used with new-row reattempts)
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
# SQLite schema helper for legacy DB upgrades
# ===================================================
def ensure_sqlite_schema():
    if not db.engine.url.get_backend_name().startswith('sqlite'):
        return
    with db.engine.connect() as conn:
        try:
            cols_ws = [row['name'] for row in conn.execute(text("PRAGMA table_info(workbook_submission)")).mappings()]
            if 'corrected_submission_time' not in cols_ws:
                conn.execute(text("ALTER TABLE workbook_submission ADD COLUMN corrected_submission_time DATETIME"))
        except OperationalError:
            pass
        try:
            cols_user = [row['name'] for row in conn.execute(text("PRAGMA table_info(user)")).mappings()]
            if 'cohort_id' not in cols_user:
                conn.execute(text("ALTER TABLE user ADD COLUMN cohort_id INTEGER"))
        except OperationalError:
            pass
        conn.commit()

# ===================================================
# Course helpers
# ===================================================
def get_course_by_code(code: str | None):
    if not code:
        return None
    return Course.query.filter(func.upper(Course.code) == (code or '').upper()).first()

def get_total_workbooks(course_code: str | None) -> int:
    course = get_course_by_code(course_code)
    if course:
        return max(1, course.workbooks_count or 1)
    return COURSE_WORKBOOKS.get((course_code or '').upper(), 3)

def get_question_count(course_code: str | None, workbook_number: int) -> int:
    course = get_course_by_code(course_code)
    if course:
        cq = CourseQuestion.query.filter_by(course_id=course.id, workbook_number=workbook_number).first()
        if cq and (cq.question_count or 0) > 0:
            return cq.question_count
    return QUESTION_COUNTS.get(((course_code or '*'), workbook_number),
           QUESTION_COUNTS.get(('*', workbook_number), 10))

# ===================================================
# Login loader
# ===================================================
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# ===================================================
# Status helpers
# ===================================================
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
        item["can_reattempt"] = False
        return item

    if latest.score == get_question_count(latest.student.course, wb_number) and not latest.is_referral:
        item["label"] = "Marked Pass"
        item["badge"] = "bg-success"
        item["can_reattempt"] = False
        return item

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

    if latest.score == 0:
        if attempts_left == 0:
            item["label"] = "Failed"
            item["badge"] = "bg-dark text-white"
            item["can_reattempt"] = False
        else:
            item["label"] = "Waiting for reattempt"
            item["badge"] = "bg-danger"
            item["can_reattempt"] = True
        return item

    return item

def compute_overall_status(items, required):
    passes = 0
    fails = 0
    for it in items:
        if it["label"] == "Marked Pass":
            passes += 1
        elif it["label"] == "Failed":
            fails += 1
    if passes == required:
        return "Pass"
    if fails >= 1:
        return "Fail"
    return "In Progress"

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
    try:
        p = Path(filename)
        p = p if p.is_absolute() else (upload_root / p)
        p = p.resolve()
        if str(p).startswith(str(upload_root.resolve())) and p.exists():
            p.unlink()
    except Exception:
        pass

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
                    cohort = ch
                    break
            if not cohort:
                flash('Cohort passcode not recognized or inactive.', 'danger')
                return redirect(url_for('register'))

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

            existing = Assignment.query.filter_by(student_id=user.id).first()
            if existing:
                existing.marker_id = cohort.marker_id
            else:
                db.session.add(Assignment(student_id=user.id, marker_id=cohort.marker_id))
            db.session.commit()

            flash('Account created and cohort assigned. Please log in.', 'success')
            return redirect(url_for('login'))

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
            rel_path = save_uploaded_pdf(up_file, up_file.filename)
            latest_existing = (WorkbookSubmission.query
                               .filter_by(student_id=current_user.id, workbook_number=wb_number)
                               .order_by(WorkbookSubmission.submission_time.desc())
                               .first())
            referral_count = (latest_existing.referral_count if latest_existing else 0) or 0
            submission = WorkbookSubmission(
                student_id=current_user.id,
                workbook_number=wb_number,
                file_path=rel_path,
                referral_count=referral_count,
                marked=False,
                is_referral=False
            )
            db.session.add(submission)
            db.session.commit()
            log_student_event(current_user.id, "upload", {"workbook_number": wb_number})
            flash(f'Workbook {wb_number} uploaded.', 'success')
            return redirect(url_for('student_dashboard'))

        elif ref_file and ref_file.filename:
            # RECOMMENDED IMPROVEMENT: create a NEW submission row for reattempts
            rel_path = save_uploaded_pdf(ref_file, ref_file.filename)
            latest = (WorkbookSubmission.query
                      .filter_by(student_id=current_user.id, workbook_number=wb_number)
                      .order_by(WorkbookSubmission.submission_time.desc())
                      .first())
            if not latest:
                flash('No prior submission found for this workbook.', 'warning')
                return redirect(url_for('student_dashboard'))

            new_sub = WorkbookSubmission(
                student_id=current_user.id,
                workbook_number=wb_number,
                file_path=rel_path,
                submission_time=now_utc_naive(),
                marked=False,
                is_referral=False,
                # carry forward the referral_count (will increment again if this attempt is referred)
                referral_count=(latest.referral_count or 0)
            )
            db.session.add(new_sub)
            db.session.commit()
            log_student_event(current_user.id, "reupload", {"workbook_number": wb_number})
            flash(f'Workbook {wb_number} re-uploaded for referral.', 'success')
            return redirect(url_for('student_dashboard'))

        else:
            flash('Please choose a PDF to upload.', 'warning')
            return redirect(url_for('student_dashboard'))

    course_code = (current_user.course or '').upper()
    required = get_total_workbooks(course_code)

    start_date = current_user.cohort.start_date if (current_user.cohort and current_user.cohort.start_date) else None
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

    # Prefer new scheme (file_path), fall back to legacy corrected_submission_path if present
    raw_pdf = submission.file_path or submission.corrected_submission_path
    pdf_filename = normalize_db_file_path(raw_pdf)
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

# Serve uploaded PDFs (inline)
@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    p = (upload_root / filename).resolve()
    if not str(p).startswith(str(upload_root.resolve())) or not p.exists():
        abort(404)
    resp = send_file(p, mimetype="application/pdf", as_attachment=False, conditional=True)
    resp.headers.pop('Content-Disposition', None)
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return resp

# ===================================================
# Routes: Marker
# ===================================================
@app.route('/marker_dashboard')
@login_required
def marker_dashboard():
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    assigned_student_ids = [a.student_id for a in Assignment.query.filter_by(marker_id=current_user.id).all()]
    students = (User.query
                .filter(User.role == 'student', User.id.in_(assigned_student_ids))
                .order_by(User.username.asc())
                .all())
    users_map = {u.id: u for u in students}

    total_unsubmitted = 0
    total_to_mark = 0
    total_marked = 0
    overview_rows = []

    for s in students:
        required = get_total_workbooks(s.course)
        s_unsubmitted = required
        s_to_mark, s_marked = 0, 0
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
            "seconds_left": seconds,
            "overdue": overdue,
            "days": days,
            "hours": hours,
        }

    unmarked = (WorkbookSubmission.query
                .filter(WorkbookSubmission.student_id.in_(assigned_student_ids),
                        WorkbookSubmission.marked.is_(False))
                .order_by(WorkbookSubmission.submission_time.desc())
                .all())

    to_mark_list = []
    for sub in unmarked:
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
    to_mark_list.sort(key=lambda x: x["seconds_left"])
    to_mark_list = to_mark_list[:20]

    return render_template(
        'marker_dashboard.html',
        donut_data=donut_data,
        students_overview=overview_rows,
        to_mark_list=to_mark_list,
    )

@app.route('/marker_students')
@login_required
def marker_students():
    if current_user.role != 'marker':
        return redirect(url_for('login'))
    students = get_assigned_students_for_marker(current_user.id)
    data = []
    for s in students:
        required = get_total_workbooks(s.course)
        data.append({"student": s, "status": compute_overall_status(
            [build_workbook_item(s.id, n) for n in range(1, required + 1)], required), "required": required})
    return render_template('marker_students.html', students=data)

@app.route('/marker_view_student/<int:student_id>')
@login_required
def marker_view_student(student_id):
    if current_user.role != 'marker':
        return redirect(url_for('login'))
    if not marker_is_assigned_to_student(current_user.id, student_id):
        abort(403)

    student = db.session.get(User, student_id)
    if not student:
        abort(404)

    workbooks = WorkbookSubmission.query.filter_by(student_id=student.id).all()
    required = get_total_workbooks(student.course)
    workbooks_dict = {w.workbook_number: w for w in workbooks}

    assigned_students = get_assigned_students_for_marker(current_user.id)
    ids = [s.id for s in sorted(assigned_students, key=lambda s: s.id)]
    idx = ids.index(student.id)
    prev_id = ids[idx - 1] if idx > 0 else None
    next_id = ids[idx + 1] if idx < len(ids) - 1 else None

    return render_template('marker_view_student.html', student=student, required=required,
                           workbooks=workbooks, workbooks_dict=workbooks_dict,
                           status=compute_overall_status([build_workbook_item(student.id, n) for n in range(1, required + 1)], required),
                           now=now_utc_naive(), timedelta=timedelta, prev_id=prev_id, next_id=next_id,
                           get_marking_deadline=get_marking_deadline)

@app.route('/mark_workbook_questions/<int:submission_id>', methods=['GET', 'POST'])
@login_required
def mark_workbook_questions(submission_id):
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    submission = db.session.get(WorkbookSubmission, submission_id)
    if not submission:
        abort(404)
    if not marker_is_assigned_to_student(current_user.id, submission.student_id):
        abort(403)

    student = db.session.get(User, submission.student_id)
    if not student:
        abort(404)

    wb_num = submission.workbook_number
    q_count = get_question_count(student.course, wb_num)

    attempts_so_far = 1 + (submission.referral_count or 0)
    attempts_left = max(0, MAX_ATTEMPTS - attempts_so_far)
    final_attempt = (attempts_left == 0)

    # Find previous submissions for this workbook (excluding the current one)
    previous_submissions = (WorkbookSubmission.query
                            .filter_by(student_id=student.id, workbook_number=wb_num)
                            .filter(WorkbookSubmission.id != submission.id)
                            .order_by(WorkbookSubmission.submission_time.desc())
                            .all())

    # Use the last *marked* previous submission to decide which questions reopen
    last_prev_marked = next((s for s in previous_submissions if s.marked), None)

    previously_referred = set()
    prev_pass_comments = {}

    if last_prev_marked:
        for q in QuestionFeedback.query.filter_by(submission_id=last_prev_marked.id).all():
            if q.status == 'Refer':
                previously_referred.add(q.question_number)
            elif q.status == 'Pass':
                prev_pass_comments[q.question_number] = (q.comment or '')

    is_first_attempt = (last_prev_marked is None and (submission.referral_count or 0) == 0)

    # Which questions are open on this attempt?
    open_questions = list(range(1, q_count + 1)) if is_first_attempt else sorted(previously_referred)

    if request.method == 'POST':
        # Replace this submission's feedback (only for open questions)
        QuestionFeedback.query.filter_by(submission_id=submission.id).delete()

        for qn in open_questions:
            status = request.form.get(f"q_{qn}_status")  # 'Pass' or 'Refer' (or 'Fail' on final UI)
            comment = (request.form.get(f"q_{qn}_comment") or '').strip()
            if status == 'Fail':  # final-attempt UI label translates to Refer in storage
                status = 'Refer'
            if status in ('Pass', 'Refer'):
                db.session.add(QuestionFeedback(
                    submission_id=submission.id,
                    question_number=qn,
                    status=status,
                    comment=comment
                ))

        # Carry forward passes from the last marked attempt (so total reflects all questions)
        if not is_first_attempt and last_prev_marked:
            for qn, com in prev_pass_comments.items():
                if qn not in previously_referred:  # these were locked as already passed
                    db.session.add(QuestionFeedback(
                        submission_id=submission.id,
                        question_number=qn,
                        status='Pass',
                        comment=com
                    ))

        # Score + referral/final decisions
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

    # Build rows for the template
    rows = []
    for qn in range(1, q_count + 1):
        is_open = True if is_first_attempt else (qn in previously_referred)
        rows.append({
            'number': qn,
            'open': is_open,
            'prev_state': (None if is_first_attempt else ('Refer' if qn in previously_referred else 'Pass')),
            'prev_comment': None if is_open else prev_pass_comments.get(qn, '')
        })

    # Use current submission's file path (legacy fallback still supported)
    raw_pdf = submission.file_path or submission.corrected_submission_path
    pdf_filename = normalize_db_file_path(raw_pdf)
    is_pdf = bool(pdf_filename and pdf_filename.lower().endswith('.pdf'))

    return render_template('mark_workbook_questions.html',
                           submission=submission, student=student, wb_number=wb_num,
                           q_count=q_count, rows=rows,
                           pdf_filename=pdf_filename if is_pdf else None,
                           previously_referred=sorted(previously_referred),
                           is_first_attempt=is_first_attempt,
                           final_attempt=final_attempt)

# ===================================================
# Export Student Report
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

    required = get_total_workbooks(student.course)
    candidates = []
    for wb in range(1, required + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc()).first())
        if not latest:
            candidates.append((wb, None, "missing")); continue
        chosen = latest.file_path or latest.corrected_submission_path
        if not chosen:
            candidates.append((wb, None, "no_file")); continue
        p = Path(chosen)
        if not p.is_absolute():
            p = upload_root / chosen
        candidates.append((wb, str(p) if p.exists() else None, "ok" if p.exists() else "not_found"))

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
# Admin: Dashboards & Settings
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
        latest = max(subs, key=lambda s: s.submission_time)  # new-row reattempts: newest row is current state
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
        try:
            student_id = int(student_id); marker_id = int(marker_id)
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
        if not p.exists():
            return None, None, None
        try:
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

    # courses list from DB (preferred) falling back to constants
    db_courses = Course.query.order_by(Course.code.asc()).all()
    courses = [c.code for c in db_courses] if db_courses else sorted(COURSE_WORKBOOKS.keys())

    if request.method == 'POST':
        # ----- Read & validate POST -----
        course = (request.form.get('course') or '').strip()
        marker_id_raw = request.form.get('marker_id') or ''
        start_date_str = (request.form.get('start_date') or '').strip()
        name = (request.form.get('name') or '').strip()

        if not course:
            flash('Please choose a course.', 'warning')
            return redirect(url_for('admin_cohorts'))

        try:
            marker_id = int(marker_id_raw)
        except (TypeError, ValueError):
            flash('Please choose a marker.', 'warning')
            return redirect(url_for('admin_cohorts'))

        marker = db.session.get(User, marker_id)
        if not marker or marker.role != 'marker':
            flash('Selected marker not found.', 'danger')
            return redirect(url_for('admin_cohorts'))

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Please provide a valid start date (YYYY-MM-DD).', 'warning')
            return redirect(url_for('admin_cohorts'))

        # ----- Generate a unique passcode -----
        passcode = None
        for _ in range(10):
            candidate = generate_passcode(10)  # A–Z (no I/O), 2–9
            if not Cohort.query.filter_by(passcode=candidate).first():
                passcode = candidate
                break
        if not passcode:
            flash('Could not generate a unique passcode. Please try again.', 'danger')
            return redirect(url_for('admin_cohorts'))

        # ----- Create & commit cohort -----
        try:
            cohort = Cohort(
                name=name or f"{course} {start_date.strftime('%b %Y')}",
                course=course,
                marker_id=marker_id,
                start_date=start_date,
                passcode=passcode,
                active=True
            )
            db.session.add(cohort)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.exception("Error creating cohort")
            flash('There was a problem creating the cohort. Please try again.', 'danger')
            return redirect(url_for('admin_cohorts'))

        flash(f'Cohort created. Passcode: {passcode}', 'success')
        return redirect(url_for('admin_cohorts'))

    # ----- GET: render page -----
    cohorts = Cohort.query.order_by(Cohort.created_at.desc()).all()
    marker_map = {m.id: m for m in markers}

    # Student counts per cohort for the UI
    student_counts = {}
    try:
        for s in User.query.filter_by(role='student').all():
            if s.cohort_id:
                student_counts[s.cohort_id] = student_counts.get(s.cohort_id, 0) + 1
    except Exception:
        student_counts = {}

    return render_template(
        'admin_cohorts.html',
        cohorts=cohorts,
        markers=markers,
        marker_map=marker_map,
        courses=courses,
        student_counts=student_counts
    )

@app.route('/admin_cohorts/<int:cohort_id>/delete', methods=['POST'])
@login_required
def admin_cohorts_delete(cohort_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    cohort = db.session.get(Cohort, cohort_id)
    if not cohort:
        flash('Cohort not found.', 'danger')
        return redirect(url_for('admin_cohorts'))

    # Safety check: refuse deletion if any students are attached
    attached_students = User.query.filter_by(role='student', cohort_id=cohort.id).count()
    if attached_students > 0:
        flash(f'Cannot delete: {attached_students} student(s) are still assigned to this cohort.', 'warning')
        return redirect(url_for('admin_cohorts'))

    db.session.delete(cohort)
    db.session.commit()
    flash('Cohort deleted.', 'success')
    return redirect(url_for('admin_cohorts'))

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
# Admin: Settings (Courses / Workbooks / Questions)
# ===================================================
@app.route('/admin_settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    action = request.form.get('action')
    if request.method == 'POST' and action:
        if action == 'add_course':
            code = (request.form.get('code') or '').strip().upper()
            name = (request.form.get('name') or '').strip()
            wb_count = int(request.form.get('workbooks_count') or 1)
            if not code or not name:
                flash('Course code and name are required.', 'warning')
                return redirect(url_for('admin_settings'))
            if Course.query.filter(func.upper(Course.code) == code).first():
                flash('Course code already exists.', 'danger')
                return redirect(url_for('admin_settings'))
            course = Course(code=code, name=name, workbooks_count=max(1, wb_count))
            db.session.add(course)
            db.session.commit()
            for i in range(1, course.workbooks_count + 1):
                db.session.add(CourseQuestion(course_id=course.id, workbook_number=i, question_count=10))
            db.session.commit()
            flash('Course added.', 'success')
            return redirect(url_for('admin_settings'))

        if action == 'update_course':
            course_id = int(request.form.get('course_id') or 0)
            name = (request.form.get('name') or '').strip()
            wb_count = int(request.form.get('workbooks_count') or 1)
            course = db.session.get(Course, course_id)
            if not course:
                flash('Course not found.', 'danger'); return redirect(url_for('admin_settings'))

            old_count = course.workbooks_count
            course.name = name or course.name
            course.workbooks_count = max(1, wb_count)
            db.session.commit()

            if course.workbooks_count > old_count:
                for i in range(old_count + 1, course.workbooks_count + 1):
                    if not CourseQuestion.query.filter_by(course_id=course.id, workbook_number=i).first():
                        db.session.add(CourseQuestion(course_id=course.id, workbook_number=i, question_count=10))
                db.session.commit()
            elif course.workbooks_count < old_count:
                CourseQuestion.query.filter(
                    CourseQuestion.course_id == course.id,
                    CourseQuestion.workbook_number > course.workbooks_count
                ).delete(synchronize_session=False)
                db.session.commit()

            flash('Course updated.', 'success')
            return redirect(url_for('admin_settings'))

        if action == 'set_questions':
            course_id = int(request.form.get('course_id') or 0)
            course = db.session.get(Course, course_id)
            if not course:
                flash('Course not found.', 'danger'); return redirect(url_for('admin_settings'))
            for i in range(1, course.workbooks_count + 1):
                field = f'qcount_{i}'
                qn = int(request.form.get(field) or 0)
                qn = qn if qn > 0 else 1
                cq = CourseQuestion.query.filter_by(course_id=course.id, workbook_number=i).first()
                if not cq:
                    cq = CourseQuestion(course_id=course.id, workbook_number=i, question_count=qn)
                    db.session.add(cq)
                else:
                    cq.question_count = qn
            db.session.commit()
            flash('Question counts saved.', 'success')
            return redirect(url_for('admin_settings'))

        if action == 'delete_course':
            course_id = int(request.form.get('course_id') or 0)
            course = db.session.get(Course, course_id)
            if not course:
                flash('Course not found.', 'danger'); return redirect(url_for('admin_settings'))

            in_use = User.query.filter(User.role == 'student', func.upper(User.course) == course.code.upper()).first()
            if in_use:
                flash('Cannot delete: students are assigned to this course.', 'warning')
                return redirect(url_for('admin_settings'))

            db.session.delete(course)
            db.session.commit()
            flash('Course deleted.', 'success')
            return redirect(url_for('admin_settings'))

    courses = Course.query.order_by(Course.code.asc()).all()
    qmap = {}
    for c in courses:
        qrows = CourseQuestion.query.filter_by(course_id=c.id).order_by(CourseQuestion.workbook_number.asc()).all()
        qmap[c.id] = qrows

    return render_template('admin_settings.html', courses=courses, qmap=qmap)

# ===================================================
# Contact
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
# Admin/Marker: Upload on behalf of a student
# ===================================================
@app.route('/proxy_upload/<int:student_id>', methods=['GET', 'POST'])
@login_required
def proxy_upload(student_id):
    # Permissions: admin OR assigned marker
    if current_user.role not in ('admin', 'marker'):
        abort(403)
    if current_user.role == 'marker' and not marker_is_assigned_to_student(current_user.id, student_id):
        abort(403)

    student = db.session.get(User, student_id)
    if not student or student.role != 'student':
        abort(404)

    required = get_total_workbooks(student.course)

    if request.method == 'POST':
        try:
            wb_number = int(request.form.get('workbook_number', '0') or 0)
        except ValueError:
            wb_number = 0
        if not (1 <= wb_number <= required):
            flash('Please choose a valid workbook number.', 'warning')
            return redirect(url_for('proxy_upload', student_id=student_id))

        up_file = request.files.get('file')
        if not up_file or not up_file.filename:
            flash('Please choose a PDF to upload.', 'warning')
            return redirect(url_for('proxy_upload', student_id=student_id))

        # Save the PDF and create a NEW submission row (future-proof reattempt model)
        rel_path = save_uploaded_pdf(up_file, up_file.filename)

        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb_number)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())

        new_sub = WorkbookSubmission(
            student_id=student.id,
            workbook_number=wb_number,
            file_path=rel_path,
            submission_time=now_utc_naive(),
            marked=False,
            is_referral=False,
            referral_count=(latest.referral_count or 0) if latest else 0
        )
        db.session.add(new_sub)
        db.session.commit()

        # Log as if the student reuploaded/uploaded (so audit trail remains useful)
        log_student_event(student.id, "upload_by_staff", {
            "workbook_number": wb_number,
            "by_user_id": current_user.id,
            "by_role": current_user.role
        })

        flash(f'Uploaded PDF for {student.username} · Workbook {wb_number}.', 'success')
        # Helpful redirect: back to student overview for the marker/admin
        if current_user.role == 'marker':
            return redirect(url_for('marker_view_student', student_id=student.id))
        else:
            # admins don’t have a student detail page by default; send back to the form
            return redirect(url_for('proxy_upload', student_id=student.id))

    # Build a light summary for the page
    summary = []
    for wb in range(1, required + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())
        label = "No submission"
        attempts = 0
        status_note = ""
        if latest:
            attempts = (latest.referral_count or 0) + 1
            if not latest.marked:
                label = "Submitted (awaiting marking)"
            elif latest.is_referral and latest.marked:
                label = "Marked: Referral"
            elif latest.marked and latest.score == get_question_count(student.course, wb):
                label = "Marked: Pass"
            elif latest.marked and latest.score == 0:
                label = "Marked: Fail"
            else:
                label = "Marked"
            status_note = f"Attempt {attempts}/{MAX_ATTEMPTS}"
        summary.append({
            "wb": wb,
            "label": label,
            "status_note": status_note
        })

    return render_template('proxy_upload.html',
                           student=student,
                           required=required,
                           summary=summary)

# ===================================================
# App init / Main
# ===================================================
with app.app_context():
    db.create_all()
    ensure_sqlite_schema()
    seed_default_courses()

@login_manager.unauthorized_handler
def _unauth():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)