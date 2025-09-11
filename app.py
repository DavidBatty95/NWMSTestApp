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
from io import BytesIO
from PyPDF2 import PdfMerger, PdfReader
from zoneinfo import ZoneInfo
import os
import json
from pathlib import Path

# ===================================================
# App & Config
# ===================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ===================================================
# Constants
# ===================================================
COURSE_WORKBOOKS = {'FREC4': 3, 'SALM': 1, 'CFR': 1}
COURSE_PASSCODES = {'FREC4': 'nwmsfrec4', 'SALM': 'nwmssalm', 'CFR': 'nwmscfr'}
MARKING_DEADLINE_DAYS = 14
MAX_ATTEMPTS = 4

# Variable question counts per workbook (adjust as needed)
QUESTION_COUNTS = {
    ('FREC4', 1): 10,
    ('FREC4', 2): 10,
    ('FREC4', 3): 10,
    ('CFR', 1): 10,
    ('SALM', 1): 8,
    ('*', 1): 10,
    ('*', 2): 10,
    ('*', 3): 10,
}
def get_question_count(course: str | None, workbook_number: int) -> int:
    return QUESTION_COUNTS.get((course or '*', workbook_number),
           QUESTION_COUNTS.get(('*', workbook_number), 10))

# Display timezone for human-friendly timestamps on admin pages
DISPLAY_TZ = ZoneInfo(os.environ.get('DISPLAY_TZ', 'Europe/London'))

def _format_ts_human(ts_iso: str | None) -> str:
    """Format an ISO8601 timestamp to a human-friendly string in DISPLAY_TZ."""
    if not ts_iso:
        return "—"
    try:
        dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        dt_local = dt.astimezone(DISPLAY_TZ)
        return dt_local.strftime("%a %d %b %Y, %H:%M %Z")
    except Exception:
        return ts_iso  # fallback

# ===================================================
# Activity logging (one JSONL file per student)
# ===================================================
LOGS_DIR = Path(os.environ.get('ACTIVITY_LOGS_DIR', 'activity_logs'))
LOGS_DIR.mkdir(parents=True, exist_ok=True)

def student_log_path(student_id: int) -> Path:
    return LOGS_DIR / f"student_{student_id}.log"

def log_student_event(student_id: int, event: str, details: dict | None = None):
    """Append a JSON line to the student's log file (best-effort)."""
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
        p = student_log_path(student_id)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass

# ===================================================
# Time / Token Helpers
# ===================================================
def now_utc():
    return datetime.now(timezone.utc)

def now_utc_naive():
    return now_utc().replace(tzinfo=None)

def _get_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_reset_token(user):
    s = _get_serializer()
    return s.dumps({'uid': user.id, 'email': user.email}, salt='pw-reset')

def verify_reset_token(token, max_age=3600):
    s = _get_serializer()
    try:
        data = s.loads(token, salt='pw-reset', max_age=max_age)
        uid = data.get('uid'); email = data.get('email')
        if not uid or not email:
            return None
        user = db.session.get(User, uid)
        return user if user and user.email == email else None
    except (SignatureExpired, BadSignature):
        return None

# ===================================================
# Models
# ===================================================
class User(UserMixin, db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email    = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role     = db.Column(db.String(50),  nullable=False)   # 'student', 'marker', 'admin'
    course   = db.Column(db.String(10),  nullable=True)    # only for students

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
    corrected_submission_time = db.Column(db.DateTime, nullable=True)  # re-upload timestamp

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
# SQLite dev helper: ensure new columns exist
# ===================================================
def ensure_sqlite_schema():
    if not db.engine.url.get_backend_name().startswith('sqlite'):
        return
    with db.engine.connect() as conn:
        cols = [row['name'] for row in conn.execute(text("PRAGMA table_info(workbook_submission)")).mappings()]
        if 'corrected_submission_time' not in cols:
            conn.execute(text("ALTER TABLE workbook_submission ADD COLUMN corrected_submission_time DATETIME"))
        conn.commit()

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
# Helpers
# ===================================================
def get_student_status(student: User, required_workbooks: int) -> str:
    """
    Overall status:
      - Pass: all required workbooks are pass (score equals total questions)
      - Fail: all required workbooks are fail (explicit 0 with no referral open)
      - In Progress: otherwise
    """
    states = []
    for wb in range(1, required_workbooks + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())
        if not latest:
            states.append('pending'); continue
        # treat re-upload as awaiting marking
        if latest.corrected_submission_path and not latest.marked:
            states.append('submitted'); continue
        if not latest.marked:
            states.append('submitted'); continue
        if latest.is_referral:
            states.append('referral')
        elif latest.score is not None and latest.score == get_question_count(student.course, wb):
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
    if not filename:
        return
    if _file_is_referenced_elsewhere(filename):
        return
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        if os.path.exists(path):
            os.remove(path)
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
        course = request.form.get('course') if role == 'student' else None
        course_passcode = request.form.get('course_passcode') if role == 'student' else None

        if not username or not email or not password_raw or role not in ('student', 'marker', 'admin'):
            flash('Please provide all required fields.', 'warning')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'warning')
            return redirect(url_for('register'))

        if role == 'student':
            if not course or not course_passcode:
                flash('Course and passcode required for student registration.', 'danger')
                return redirect(url_for('register'))
            expected = COURSE_PASSCODES.get(course)
            if not expected or course_passcode.strip().lower() != expected.lower():
                flash('Invalid course passcode for selected course.', 'danger')
                return redirect(url_for('register'))

        password = generate_password_hash(password_raw)
        new_user = User(username=username, email=email, password=password, role=role, course=course)
        db.session.add(new_user)
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
        wb_number = int(request.form['workbook_number'])

        # First submission
        file = request.files.get('file')
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            latest_prev = (WorkbookSubmission.query
                           .filter_by(student_id=current_user.id, workbook_number=wb_number)
                           .order_by(WorkbookSubmission.submission_time.desc())
                           .first())
            referral_count = latest_prev.referral_count if latest_prev else 0

            sub = WorkbookSubmission(
                student_id=current_user.id,
                workbook_number=wb_number,
                file_path=filename,
                referral_count=referral_count
            )
            db.session.add(sub)
            db.session.commit()

            log_student_event(current_user.id, "upload", {
                "workbook_number": wb_number,
                "filename": filename
            })
            return redirect(url_for('student_dashboard'))

        # Reattempt upload after referral (attach to same submission)
        referral_file = request.files.get('referral_file')
        if referral_file and referral_file.filename:
            filename = secure_filename(referral_file.filename)
            referral_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            latest = (WorkbookSubmission.query
                      .filter_by(student_id=current_user.id, workbook_number=wb_number)
                      .order_by(WorkbookSubmission.submission_time.desc())
                      .first())
            if latest:
                latest.corrected_submission_path = filename
                latest.corrected_submission_time = now_utc_naive()
                # Make sure it shows as needing marking again:
                latest.marked = False
                latest.score = None
                latest.feedback = None
                # Keep referral flag until re-marked
                db.session.commit()

                log_student_event(current_user.id, "reupload", {
                    "workbook_number": wb_number,
                    "filename": filename
                })
            return redirect(url_for('student_dashboard'))

    # Build table rows
    required = COURSE_WORKBOOKS.get(current_user.course, 1)
    items = []
    for wb in range(1, required + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=current_user.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())

        # Attempts: 1 for original + referral_count reattempts already used
        attempts_so_far = 1 + (latest.referral_count or 0) if latest else 0
        attempts_left = max(0, MAX_ATTEMPTS - attempts_so_far)

        label = 'Awaiting submission'
        badge = 'bg-secondary'
        can_upload = True
        can_reattempt = False

        if latest:
            can_upload = False
            if not latest.marked:
                if latest.is_referral:
                    label = 'Referral'
                    badge = 'bg-danger'
                else:
                    label = 'Submitted'
                    badge = 'bg-warning text-dark'
            else:
                if latest.is_referral:
                    label = 'Referral'
                    badge = 'bg-danger'
                    can_reattempt = attempts_left > 0
                elif latest.score == get_question_count(current_user.course, wb):
                    label = 'Marked Pass'
                    badge = 'bg-success'
                elif latest.score == 0:
                    label = 'Marked Fail'
                    badge = 'bg-dark'
                else:
                    label = 'Marked'
                    badge = 'bg-info text-dark'

        items.append({
            'wb_number': wb,
            'label': label,
            'badge': badge,
            'latest': latest,
            'can_upload': can_upload,
            'can_reattempt': can_reattempt,
            'attempts_left': attempts_left,
            'attempts_so_far': attempts_so_far,
        })

    overall_status = get_student_status(current_user, required)

    return render_template('student_dashboard.html',
                           items=items,
                           required=required,
                           overall_status=overall_status,
                           now=now_utc_naive(),
                           timedelta=timedelta)

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

    # log view
    log_student_event(current_user.id, "view_feedback", {"workbook_number": workbook_number})

    q_items = (QuestionFeedback.query
               .filter_by(submission_id=submission.id)
               .order_by(QuestionFeedback.question_number.asc())
               .all())

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

    return render_template(
        'student_view_feedback.html',
        workbook_number=workbook_number,
        submission=submission,
        overall=overall,
        pdf_filename=pdf_filename if is_pdf else None,
        q_items=q_items,
        total=total, passed=passed
    )

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

    now = now_utc_naive()
    students = get_assigned_students_for_marker(current_user.id)

    status_counts = {"Unsubmitted": 0, "To be Marked": 0, "Marked": 0}
    pending = []

    for student in students:
        subs = (WorkbookSubmission.query
                .filter_by(student_id=student.id)
                .order_by(WorkbookSubmission.submission_time.desc())
                .all())
        if not subs:
            status_counts["Unsubmitted"] += 1
        else:
            any_unmarked = any(not s.marked for s in subs)
            status_counts["To be Marked" if any_unmarked else "Marked"] += 1

        for s in subs:
            latest_time = s.corrected_submission_time or s.submission_time
            if not s.marked:
                deadline = s.submission_time + timedelta(days=MARKING_DEADLINE_DAYS)
                time_left = deadline - now
                pending.append({
                    "student": student,
                    "submission": s,
                    "deadline": deadline,
                    "time_left": time_left,
                    "latest_time": latest_time,
                })

    pending.sort(key=lambda x: x["time_left"])
    return render_template('marker_dashboard.html', students=students,
                           status_counts=status_counts, pending=pending,
                           now=now, timedelta=timedelta, COURSE_WORKBOOKS=COURSE_WORKBOOKS)

@app.route('/marker_students')
@login_required
def marker_students():
    if current_user.role != 'marker':
        return redirect(url_for('login'))
    students = get_assigned_students_for_marker(current_user.id)
    data = []
    for s in students:
        required = COURSE_WORKBOOKS.get(s.course, 1)
        status = get_student_status(s, required)
        data.append({"student": s, "status": status, "required": required})
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
    required = COURSE_WORKBOOKS.get(student.course, 1)
    workbooks_dict = {w.workbook_number: w for w in workbooks}

    assigned_students = get_assigned_students_for_marker(current_user.id)
    students_sorted = sorted(assigned_students, key=lambda s: s.id)
    ids = [s.id for s in students_sorted]
    idx = ids.index(student.id)
    prev_id = ids[idx - 1] if idx > 0 else None
    next_id = ids[idx + 1] if idx < len(ids) - 1 else None

    return render_template('marker_view_student.html', student=student, required=required,
                           workbooks=workbooks, workbooks_dict=workbooks_dict,
                           status=get_student_status(student, required), now=now_utc_naive(),
                           timedelta=timedelta, prev_id=prev_id, next_id=next_id,
                           get_marking_deadline=get_marking_deadline)

# ---------- Question-by-question marking ----------
@app.route('/mark_workbook_questions/<int:submission_id>', methods=['GET', 'POST'])
@login_required
def mark_workbook_questions(submission_id):
    # Access control
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

    wb_num  = submission.workbook_number
    course  = student.course
    q_count = get_question_count(course, wb_num)

    # Determine attempt context (same-submission or prior row)
    existing_fb = QuestionFeedback.query.filter_by(submission_id=submission.id).all()
    has_same_submission_prior = bool(existing_fb)

    previous_submissions = (
        WorkbookSubmission.query
        .filter_by(student_id=student.id, workbook_number=wb_num)
        .filter(WorkbookSubmission.id != submission.id)
        .order_by(WorkbookSubmission.submission_time.desc())
        .all()
    )

    previously_referred = set()
    prev_pass_comments  = {}

    if has_same_submission_prior and submission.is_referral:
        for q in existing_fb:
            if q.status == 'Refer':
                previously_referred.add(q.question_number)
            elif q.status == 'Pass':
                prev_pass_comments[q.question_number] = (q.comment or '')
        is_first_attempt = False
    elif previous_submissions:
        last_prev = previous_submissions[0]
        prev_q_feedback = QuestionFeedback.query.filter_by(submission_id=last_prev.id).all()
        for q in prev_q_feedback:
            if q.status == 'Refer':
                previously_referred.add(q.question_number)
            elif q.status == 'Pass':
                prev_pass_comments[q.question_number] = (q.comment or '')
        is_first_attempt = False
    else:
        is_first_attempt = True

    open_questions = list(range(1, q_count + 1)) if is_first_attempt else sorted(previously_referred)

    # POST: save per-question feedback
    if request.method == 'POST':
        prev_pass_locked = set()
        if not is_first_attempt and has_same_submission_prior:
            for q in existing_fb:
                if q.status == 'Pass' and q.question_number not in previously_referred:
                    prev_pass_locked.add(q.question_number)

        # Clear old feedback for this submission
        QuestionFeedback.query.filter_by(submission_id=submission.id).delete()

        any_refer = False
        for qn in open_questions:
            status  = request.form.get(f"q_{qn}_status")
            comment = (request.form.get(f"q_{qn}_comment") or '').strip()
            if status not in ('Pass', 'Refer'):
                continue
            if status == 'Refer':
                any_refer = True
            db.session.add(QuestionFeedback(
                submission_id=submission.id,
                question_number=qn,
                status=status,
                comment=comment
            ))

        # Carry forward Pass for locked questions
        if not is_first_attempt:
            if has_same_submission_prior:
                for qn in sorted(prev_pass_locked):
                    db.session.add(QuestionFeedback(
                        submission_id=submission.id,
                        question_number=qn,
                        status='Pass',
                        comment=prev_pass_comments.get(qn, '')
                    ))
            else:
                last_prev = previous_submissions[0]
                prev_all = QuestionFeedback.query.filter_by(submission_id=last_prev.id).all()
                for q in prev_all:
                    if q.status == 'Pass' and q.question_number not in previously_referred:
                        db.session.add(QuestionFeedback(
                            submission_id=submission.id,
                            question_number=q.question_number,
                            status='Pass',
                            comment=q.comment or ''
                        ))

        # Finalize submission
        submission.marked = True
        all_feedback = QuestionFeedback.query.filter_by(submission_id=submission.id).all()
        total  = len(all_feedback)
        passed = sum(1 for f in all_feedback if f.status == 'Pass')
        submission.score = passed

        if passed < total:
            submission.is_referral = True
            submission.referral_count = (submission.referral_count or 0) + 1
            flash(f'Saved: {passed}/{total} questions passed. Submission set to Referral.', 'warning')
        else:
            submission.is_referral = False
            flash(f'Saved: all {passed} questions passed. Submission set to Pass.', 'success')

        db.session.commit()
        return redirect(url_for('marker_view_student', student_id=student.id))

    # GET: build rows
    pdf_filename = submission.corrected_submission_path or submission.file_path
    is_pdf = bool(pdf_filename and pdf_filename.lower().endswith('.pdf'))

    rows = []
    for qn in range(1, q_count + 1):
        is_open = True if is_first_attempt else (qn in previously_referred)
        rows.append({
            'number': qn,
            'open': is_open,
            'prev_state': (None if is_first_attempt else ('Refer' if qn in previously_referred else 'Pass')),
            'prev_comment': None if is_open else prev_pass_comments.get(qn, '')
        })

    return render_template(
        'mark_workbook_questions.html',
        submission=submission,
        student=student,
        wb_number=wb_num,
        q_count=q_count,
        rows=rows,
        pdf_filename=pdf_filename if is_pdf else None,
        previously_referred=sorted(previously_referred),
        is_first_attempt=is_first_attempt
    )

# ===================================================
# Export Student Report (merge PDFs)
# ===================================================
@app.route('/export_student_report/<int:student_id>')
@login_required
def export_student_report(student_id):
    # markers can export only for assigned students; admins can export anyone
    if current_user.role == 'marker':
        if not marker_is_assigned_to_student(current_user.id, student_id):
            abort(403)
    elif current_user.role != 'admin':
        abort(403)

    student = db.session.get(User, student_id)
    if not student:
        abort(404)

    required = COURSE_WORKBOOKS.get(student.course, 3)
    candidates = []
    for wb in range(1, required + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())
        if not latest:
            candidates.append((wb, None, "missing")); continue
        chosen = latest.corrected_submission_path or latest.file_path
        if not chosen:
            candidates.append((wb, None, "no_file")); continue
        fullpath = os.path.join(app.config['UPLOAD_FOLDER'], chosen)
        if not os.path.exists(fullpath):
            candidates.append((wb, None, "not_found")); continue
        candidates.append((wb, fullpath, "ok"))

    merger = PdfMerger()
    merged_any = False
    merged_list, skipped_list = [], []

    for wb, path, state in sorted(candidates, key=lambda t: t[0]):
        if state != "ok":
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
        msg = "No PDF workbooks could be merged."
        if skipped_list:
            msg += " Skipped: " + "; ".join(skipped_list[:6]) + ("…" if len(skipped_list) > 6 else "")
        flash(msg, "warning")
        if current_user.role == 'marker':
            return redirect(url_for('marker_view_student', student_id=student.id))
        return redirect(url_for('admin_dashboard'))

    buf = BytesIO()
    try:
        merger.write(buf)
    finally:
        try: merger.close()
        except Exception: pass
    buf.seek(0)

    if merged_list:
        flash("Merged: " + "; ".join(merged_list[:6]) + ("…" if len(merged_list) > 6 else ""), "success")
    if skipped_list:
        flash("Skipped: " + "; ".join(skipped_list[:6]) + ("…" if len(skipped_list) > 6 else ""), "info")

    download_name = f"{secure_filename(student.username or 'student')}_workbooks.pdf"
    return send_file(buf, as_attachment=True, download_name=download_name,
                     mimetype="application/pdf", max_age=0)

# ===================================================
# Routes: Admin
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

    return render_template('admin_dashboard.html', students=students, markers=markers,
                           assignments=assignments, workload=workload,
                           status_counts=status_counts)

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
            flash('Invalid selection.', 'danger')
            return redirect(url_for('admin_assign'))

        student = db.session.get(User, student_id)
        marker  = db.session.get(User, marker_id)
        if not student or student.role != 'student':
            flash('Selected student not found.', 'danger'); return redirect(url_for('admin_assign'))
        if not marker or marker.role != 'marker':
            flash('Selected marker not found.', 'danger'); return redirect(url_for('admin_assign'))

        assignment = Assignment.query.filter_by(student_id=student.id).first()
        if assignment:
            assignment.marker_id = marker.id
        else:
            db.session.add(Assignment(student_id=student.id, marker_id=marker.id))
        db.session.commit()
        flash(f'Assigned {student.username} to {marker.username}.', 'success')
        return redirect(url_for('admin_assign'))

    students = User.query.filter_by(role='student').order_by(User.username.asc()).all()
    markers  = User.query.filter_by(role='marker').order_by(User.username.asc()).all()
    current_marker_by_student = {a.student_id: a.marker_id for a in Assignment.query.all()}

    return render_template('admin_assign.html',
                           students=students, markers=markers,
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
    if assignment:
        db.session.delete(assignment)

    submissions = WorkbookSubmission.query.filter_by(student_id=student.id).all()
    for sub in submissions:
        _maybe_delete_uploaded_file(sub.file_path)
        _maybe_delete_uploaded_file(sub.corrected_submission_path)
        QuestionFeedback.query.filter_by(submission_id=sub.id).delete()
        db.session.delete(sub)

    db.session.delete(student)
    db.session.commit()
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
        if a.marker_id in assigned_counts:
            assigned_counts[a.marker_id] += 1
    return render_template('admin_delete_markers.html',
                           markers=markers, assigned_counts=assigned_counts)

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
    for a in assignments:
        db.session.delete(a)

    db.session.delete(marker)
    db.session.commit()
    flash(
        f'Marker deleted. {unassigned} student(s) are now unassigned.' if unassigned else 'Marker deleted.',
        'success'
    )
    return redirect(url_for('admin_delete_markers'))

# -------- Admin Activity log pages --------
@app.route('/admin_activity')
@login_required
def admin_activity():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    students = User.query.filter_by(role='student').order_by(User.username.asc()).all()
    rows = []
    for s in students:
        p = student_log_path(s.id)
        exists = p.exists()
        entries = 0
        last_ts = None
        if exists:
            try:
                # count lines and read last line
                with p.open("rb") as f:
                    for entries, _ in enumerate(f, 1):
                        pass
                if entries:
                    last_line = p.read_text(encoding="utf-8", errors="ignore").splitlines()[-1]
                    last_ts = json.loads(last_line).get("ts", None)
            except Exception:
                entries, last_ts = 0, None

        rows.append({
            "student": s,
            "has_log": exists,
            "entries": entries,
            "last_ts": last_ts,
            "last_ts_human": _format_ts_human(last_ts)
        })

    return render_template('admin_activity.html', rows=rows)

@app.route('/admin_activity/<int:student_id>')
@login_required
def admin_activity_student(student_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    student = db.session.get(User, student_id)
    if not student or student.role != 'student':
        abort(404)

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

    # Build simple, human-readable actions and formatted timestamps
    simple_events = []
    for e in events:
        ev = (e.get("event") or "").lower()
        wb = e.get("details", {}).get("workbook_number")
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

        simple_events.append({
            "ts": e.get("ts"),
            "formatted_ts": _format_ts_human(e.get("ts")),
            "action": action
        })

    return render_template(
        'admin_activity_student.html',
        student=student,
        events=simple_events,
        log_exists=p.exists()
    )

@app.route('/admin_activity/<int:student_id>/download')
@login_required
def admin_activity_download(student_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    p = student_log_path(student_id)
    if not p.exists():
        flash('No log file for this student.', 'info')
        return redirect(url_for('admin_activity_student', student_id=student_id))

    # Read + parse JSONL, then output simplified, formatted lines
    records = []
    try:
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                obj = json.loads(line)
                ts = obj.get("ts")
                ev = (obj.get("event") or "").lower()
                details = obj.get("details") or {}
                wb = details.get("workbook_number")

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

                records.append((ts, action))
            except Exception:
                continue
    except Exception:
        records = []

    # Newest first
    records.sort(key=lambda r: r[0] or "", reverse=True)

    # Format nicely
    lines = [f"{_format_ts_human(ts)} — {action}" for ts, action in records]
    if not lines:
        lines = ["No log entries for this student."]

    buf = BytesIO(("\n".join(lines) + "\n").encode("utf-8"))

    student = db.session.get(User, student_id)
    base = secure_filename((student.username if student else f"student_{student_id}") or f"student_{student_id}")
    filename = f"{base}_activity.txt"

    return send_file(buf, as_attachment=True, download_name=filename, mimetype="text/plain")

@app.route('/admin_activity/<int:student_id>/clear', methods=['POST'])
@login_required
def admin_activity_clear(student_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    p = student_log_path(student_id)
    try:
        if p.exists():
            p.unlink()
            flash('Log cleared for student.', 'success')
        else:
            flash('No log file to clear.', 'info')
    except Exception:
        flash('Could not clear log file.', 'danger')
    return redirect(url_for('admin_activity_student', student_id=student_id))

# ===================================================
# Main
# ===================================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_sqlite_schema()
    app.run(debug=True)