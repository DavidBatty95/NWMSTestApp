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
from sqlalchemy import or_
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime, timedelta, timezone
from io import BytesIO
from PyPDF2 import PdfMerger, PdfReader
import os

# =========================================
# App & Config
# =========================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')  # set via env in prod
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# =========================================
# Constants
# =========================================
COURSE_WORKBOOKS = {'FREC4': 3, 'SALM': 1, 'CFR': 1}
COURSE_PASSCODES = {'FREC4': 'nwmsfrec4', 'SALM': 'nwmssalm', 'CFR': 'nwmscfr'}
MARKING_DEADLINE_DAYS = 14
MAX_ATTEMPTS = 3

# =========================================
# Helpers (time / security / misc)
# =========================================
def now_utc():
    """Timezone-aware UTC now."""
    return datetime.now(timezone.utc)

def now_utc_naive():
    """UTC now but naive (no tzinfo) to match naive DB columns without migration)."""
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

# =========================================
# Models
# =========================================
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
    score       = db.Column(db.Integer, nullable=True)
    feedback    = db.Column(db.Text, nullable=True)
    is_referral = db.Column(db.Boolean, default=False)
    referral_count = db.Column(db.Integer, default=0)
    corrected_submission_path = db.Column(db.String(255), nullable=True)

    student = db.relationship('User', foreign_keys=[student_id])


class Assignment(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    marker_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# =========================================
# Login loader (SQLAlchemy 2 style)
# =========================================
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# =========================================
# Business Helpers
# =========================================
def get_student_status(student: User, required_workbooks: int) -> str:
    """
    Overall status based on per-workbook outcomes:
      - Pass: all required workbooks are marked pass (score==100, not referral)
      - Fail: all required workbooks are fail (explicit fail, not referral)
      - In Progress: anything else (referral, pending, submitted/unmarked, mixed)
    """
    states = []  # 'pass' | 'fail' | 'referral' | 'pending' | 'submitted'
    for wb in range(1, required_workbooks + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())
        if not latest:
            states.append('pending')
            continue
        if not latest.marked:
            states.append('submitted')
            continue
        if latest.is_referral:
            states.append('referral')
        elif latest.score == 100:
            states.append('pass')
        else:
            states.append('fail')

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

# =========================================
# Routes: Auth
# =========================================
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

# =========================================
# Routes: Student
# =========================================
@app.route('/student_dashboard', methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('login'))

    # Handle uploads
    if request.method == 'POST':
        wb_number = int(request.form['workbook_number'])

        # First submission
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # carry over referral_count; increment happens only on "Refer" by marker
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
            return redirect(url_for('student_dashboard'))

        # Reattempt upload after referral
        if 'referral_file' in request.files and request.files['referral_file'].filename:
            referral_file = request.files['referral_file']
            filename = secure_filename(referral_file.filename)
            referral_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            latest = (WorkbookSubmission.query
                      .filter_by(student_id=current_user.id, workbook_number=wb_number)
                      .order_by(WorkbookSubmission.submission_time.desc())
                      .first())
            if latest:
                latest.corrected_submission_path = filename
                db.session.commit()
            return redirect(url_for('student_dashboard'))

    # Build data for table
    required = COURSE_WORKBOOKS.get(current_user.course, 1)
    items = []
    for wb in range(1, required + 1):
        subs = (WorkbookSubmission.query
                .filter_by(student_id=current_user.id, workbook_number=wb)
                .order_by(WorkbookSubmission.submission_time.desc())
                .all())
        latest = subs[0] if subs else None

        status_key = 'awaiting'
        label = 'Awaiting submission'
        badge = 'bg-secondary'
        can_upload = True
        can_reattempt = False

        if latest:
            attempts_so_far = 1 + (latest.referral_count or 0)
        else:
            attempts_so_far = 0
        attempts_left = max(0, MAX_ATTEMPTS - attempts_so_far)

        if latest:
            if not latest.marked:
                status_key = 'submitted'; label = 'Submitted'; badge = 'bg-warning text-dark'; can_upload = False
            else:
                if latest.is_referral:
                    status_key = 'waiting-reattempt'; label = 'Waiting for reattempt'
                    badge = 'bg-danger'; can_upload = False; can_reattempt = attempts_left > 0
                elif latest.score == 100:
                    status_key = 'pass'; label = 'Marked Pass'; badge = 'bg-success'; can_upload = False
                else:
                    status_key = 'marked'; label = 'Marked'; badge = 'bg-info text-dark'; can_upload = False

        items.append({
            'wb_number': wb, 'status_key': status_key, 'label': label, 'badge': badge,
            'latest': latest, 'can_upload': can_upload, 'can_reattempt': can_reattempt,
            'attempts_left': attempts_left, 'attempts_so_far': attempts_so_far
        })

    overall_status = get_student_status(current_user, required)

    return render_template('student_dashboard.html',
                           items=items,
                           required=required,
                           overall_status=overall_status,
                           now=now_utc_naive(),
                           timedelta=timedelta)

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    # Optional: tighten access (owner/assigned marker/admin) if needed
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# =========================================
# Routes: Marker
# =========================================
@app.route('/marker_dashboard')
@login_required
def marker_dashboard():
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    now = now_utc_naive()
    students = get_assigned_students_for_marker(current_user.id)

    # Simple status buckets for donut
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
            if any_unmarked:
                status_counts["To be Marked"] += 1
            else:
                status_counts["Marked"] += 1

        # Queue of unmarked submissions with deadlines
        for s in subs:
            if not s.marked:
                deadline = s.submission_time + timedelta(days=MARKING_DEADLINE_DAYS)
                time_left = deadline - now
                pending.append({
                    "student": student, "submission": s,
                    "deadline": deadline, "time_left": time_left
                })

    pending.sort(key=lambda x: x["time_left"])
    return render_template('marker_dashboard.html',
                           students=students,
                           status_counts=status_counts,
                           pending=pending,
                           now=now, timedelta=timedelta,
                           COURSE_WORKBOOKS=COURSE_WORKBOOKS)

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

    return render_template('marker_view_student.html',
                           student=student,
                           required=required,
                           workbooks=workbooks,
                           workbooks_dict=workbooks_dict,
                           status=get_student_status(student, required),
                           now=now_utc_naive(),
                           timedelta=timedelta,
                           prev_id=prev_id, next_id=next_id)

@app.route('/mark_workbook/<int:submission_id>', methods=['POST'])
@login_required
def mark_workbook(submission_id):
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    submission = db.session.get(WorkbookSubmission, submission_id)
    if not submission:
        abort(404)
    if not marker_is_assigned_to_student(current_user.id, submission.student_id):
        abort(403)

    feedback = request.form.get('feedback')
    score_input = request.form.get('score')

    if score_input == "Pass":
        submission.score = 100
        submission.is_referral = False
    elif score_input == "Refer":
        submission.score = 50
        submission.is_referral = True
        submission.referral_count += 1
    elif score_input == "Fail":
        submission.score = 0
        submission.is_referral = False

    submission.feedback = feedback
    submission.marked = True

    corrected = request.files.get('corrected_file')
    if corrected and corrected.filename:
        filename = secure_filename(corrected.filename)
        corrected.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        submission.corrected_submission_path = filename

    db.session.commit()
    return redirect(url_for('marker_view_student', student_id=submission.student_id))

# =========================================
# Export Student Report (merge PDFs)
# =========================================
@app.route('/export_student_report/<int:student_id>')
@login_required
def export_student_report(student_id):
    # Only assigned marker or admin
    if current_user.role == 'marker':
        if not marker_is_assigned_to_student(current_user.id, student_id):
            abort(403)
    elif current_user.role != 'admin':
        abort(403)

    student = db.session.get(User, student_id)
    if not student:
        abort(404)

    required = COURSE_WORKBOOKS.get(student.course, 3)
    candidates = []  # (wb_no, fullpath, state)
    for wb in range(1, required + 1):
        latest = (WorkbookSubmission.query
                  .filter_by(student_id=student.id, workbook_number=wb)
                  .order_by(WorkbookSubmission.submission_time.desc())
                  .first())
        if not latest:
            candidates.append((wb, None, "missing"))
            continue

        chosen = latest.corrected_submission_path or latest.file_path
        if not chosen:
            candidates.append((wb, None, "no_file"))
            continue

        fullpath = os.path.join(app.config['UPLOAD_FOLDER'], chosen)
        if not os.path.exists(fullpath):
            candidates.append((wb, None, "not_found"))
            continue

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

        # Try fast append first
        try:
            with open(path, "rb") as fh:
                merger.append(fh)
            merged_any = True
            merged_list.append(f"WB{wb}: {os.path.basename(path)}")
        except Exception:
            # Fallback: page-by-page (handles some odd/encrypted PDFs)
            try:
                with open(path, "rb") as fh:
                    reader = PdfReader(fh, strict=False)
                    if getattr(reader, "is_encrypted", False):
                        try:
                            reader.decrypt("")  # try empty password
                        except Exception:
                            pass
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
        try:
            merger.close()
        except Exception:
            pass
    buf.seek(0)

    if merged_list:
        flash("Merged: " + "; ".join(merged_list[:6]) + ("…" if len(merged_list) > 6 else ""), "success")
    if skipped_list:
        flash("Skipped: " + "; ".join(skipped_list[:6]) + ("…" if len(skipped_list) > 6 else ""), "info")

    download_name = f"{secure_filename(student.username or 'student')}_workbooks.pdf"
    return send_file(buf, as_attachment=True, download_name=download_name,
                     mimetype="application/pdf", max_age=0)

# =========================================
# Routes: Admin
# =========================================
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    students = User.query.filter_by(role='student').all()
    markers  = User.query.filter_by(role='marker').all()
    assignments = Assignment.query.all()

    # workload: marker_id -> number of students
    workload = {m.id: 0 for m in markers}
    for a in assignments:
        workload[a.marker_id] = workload.get(a.marker_id, 0) + 1

    # status buckets for donut (Unsubmitted / Awaiting Marking / Referral / Passed)
    status_counts = {"Unsubmitted": 0, "Awaiting Marking": 0, "Referral": 0, "Passed": 0}
    for student in students:
        subs = WorkbookSubmission.query.filter_by(student_id=student.id).all()
        if not subs:
            status_counts["Unsubmitted"] += 1
            continue
        latest = max(subs, key=lambda s: s.submission_time)
        if latest.is_referral and not latest.marked:
            status_counts["Referral"] += 1
        elif not latest.marked:
            status_counts["Awaiting Marking"] += 1
        elif latest.marked and not latest.is_referral and latest.score == 100:
            status_counts["Passed"] += 1
        else:
            status_counts["Awaiting Marking"] += 1

    return render_template('admin_dashboard.html',
                           students=students,
                           markers=markers,
                           assignments=assignments,
                           workload=workload,
                           status_counts=status_counts)

# Assign students to markers (compact)
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

# Delete students
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
        db.session.delete(sub)

    db.session.delete(student)
    db.session.commit()
    flash('Student and related data deleted.', 'success')
    return redirect(url_for('admin_delete_students'))

# Delete markers
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

    # Unassign all students from this marker
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

# (Optional legacy management view)
@app.route('/view_users', methods=['GET', 'POST'])
@login_required
def view_users():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    markers = User.query.filter_by(role='marker').all()
    students = User.query.filter_by(role='student').all()
    if request.method == 'POST':
        student_id = int(request.form['student_id']); marker_id = int(request.form['marker_id'])
        assignment = Assignment.query.filter_by(student_id=student_id).first()
        if assignment:
            assignment.marker_id = marker_id
        else:
            db.session.add(Assignment(student_id=student_id, marker_id=marker_id))
        db.session.commit()
        flash("Marker assignment updated.", "success")
        return redirect(url_for('view_users'))
    assignments = {a.student_id: a.marker_id for a in Assignment.query.all()}
    return render_template('user_list.html', markers=markers, students=students, assignments=assignments)

# =========================================
# Main
# =========================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)