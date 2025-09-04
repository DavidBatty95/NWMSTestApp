from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime, timedelta
import os

# -----------------------
# App & DB Setup
# -----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # TODO: set via environment variable in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -----------------------
# Constants
# -----------------------
COURSE_WORKBOOKS = {
    'FREC4': 3,
    'SALM': 1,
    'CFR': 1
}

# Student registration passcodes (per course)
COURSE_PASSCODES = {
    'FREC4': 'nwmsfrec4',
    'SALM': 'nwmssalm',
    'CFR': 'nwmscfr'
}

# -----------------------
# Models
# -----------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'student', 'marker', 'admin'
    course = db.Column(db.String(10), nullable=True)  # only for students


class WorkbookSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    workbook_number = db.Column(db.Integer, nullable=False)
    file_path = db.Column(db.String(255))
    submission_time = db.Column(db.DateTime, default=datetime.utcnow)
    marked = db.Column(db.Boolean, default=False)
    score = db.Column(db.Integer, nullable=True)
    feedback = db.Column(db.Text, nullable=True)
    is_referral = db.Column(db.Boolean, default=False)
    referral_count = db.Column(db.Integer, default=0)
    corrected_submission_path = db.Column(db.String(255), nullable=True)

    student = db.relationship('User', foreign_keys=[student_id])


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    marker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# -----------------------
# Login loader
# -----------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------
# Helpers
# -----------------------
def get_student_status(student, required_workbooks):
    submissions = WorkbookSubmission.query.filter_by(student_id=student.id).all()
    status = "Pass"
    now = datetime.utcnow()

    for i in range(1, required_workbooks + 1):
        matching = [s for s in submissions if s.workbook_number == i]
        if not matching:
            status = "In Progress"
            continue

        latest = sorted(matching, key=lambda x: x.submission_time)[-1]
        deadline_passed = (now - latest.submission_time).days > 14 and not latest.marked
        if latest.referral_count >= 3 or deadline_passed:
            return "Fail"

        if not latest.marked or latest.is_referral:
            status = "In Progress"

    return status


def get_marking_deadline(submission):
    deadline = submission.submission_time + timedelta(days=14)
    time_left = deadline - datetime.utcnow()
    days = max(time_left.days, 0)
    hours = max(time_left.seconds // 3600, 0)
    return days, hours, deadline


def get_assigned_students_for_marker(marker_id):
    return (
        db.session.query(User)
        .join(Assignment, Assignment.student_id == User.id)
        .filter(User.role == 'student', Assignment.marker_id == marker_id)
        .all()
    )


def marker_is_assigned_to_student(marker_id, student_id):
    return Assignment.query.filter_by(marker_id=marker_id, student_id=student_id).first() is not None


def _file_is_referenced_elsewhere(filename, exclude_submission_id=None):
    if not filename:
        return False
    q = WorkbookSubmission.query.filter(
        or_(
            WorkbookSubmission.file_path == filename,
            WorkbookSubmission.corrected_submission_path == filename
        )
    )
    if exclude_submission_id is not None:
        q = q.filter(WorkbookSubmission.id != exclude_submission_id)
    return db.session.query(q.exists()).scalar()


def _maybe_delete_uploaded_file(filename):
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

# ----- Password reset helpers -----
def _get_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_reset_token(user):
    s = _get_serializer()
    return s.dumps({'uid': user.id, 'email': user.email}, salt='pw-reset')

def verify_reset_token(token, max_age=3600):
    s = _get_serializer()
    try:
        data = s.loads(token, salt='pw-reset', max_age=max_age)
        uid = data.get('uid')
        email = data.get('email')
        if not uid or not email:
            return None
        user = User.query.get(uid)
        if user and user.email == email:
            return user
        return None
    except (SignatureExpired, BadSignature):
        return None

# -----------------------
# Routes
# -----------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

# --- Auth ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip()
        password_raw = request.form.get('password') or ''
        role = request.form.get('role') or ''
        course = request.form.get('course') if role == 'student' else None
        course_passcode = request.form.get('course_passcode') if role == 'student' else None

        if not username or not email or not password_raw or role not in ('student', 'marker', 'admin'):
            flash('Please provide all required fields.', 'warning')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'warning')
            return redirect(url_for('register'))

        # Passcode validation for students
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
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'marker':
                return redirect(url_for('marker_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Password reset (publicly accessible) ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip()
        user = None
        if identifier:
            user = User.query.filter_by(email=identifier).first()
            if not user:
                user = User.query.filter_by(username=identifier).first()

        # Do not reveal whether a user exists
        if not user:
            flash('If that account exists, a reset link has been created.', 'info')
            return render_template('forgot_password.html', reset_link=None)

        token = generate_reset_token(user)
        reset_url = url_for('reset_password', token=token, _external=True)
        flash('If that account exists, a reset link has been created.', 'info')
        # Dev mode: show link on page; in production, email this instead
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

# --- Student ---
@app.route('/student_dashboard', methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('login'))

    # ---------- Handle uploads ----------
    if request.method == 'POST':
        wb_number = int(request.form['workbook_number'])

        # First submission
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Carry over referral_count; marker increments on "Refer"
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

        # Re-attempt upload after referral
        if 'referral_file' in request.files and request.files['referral_file'].filename:
            referral_file = request.files['referral_file']
            filename = secure_filename(referral_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            referral_file.save(filepath)

            latest = (WorkbookSubmission.query
                      .filter_by(student_id=current_user.id, workbook_number=wb_number)
                      .order_by(WorkbookSubmission.submission_time.desc())
                      .first())
            if latest:
                # Attach the corrected file to the latest (referred) submission
                latest.corrected_submission_path = filename
                db.session.commit()
            return redirect(url_for('student_dashboard'))

    # ---------- Build per-workbook status list ----------
    required = COURSE_WORKBOOKS.get(current_user.course, 1)
    items = []  # [{wb_number, status_key, label, badge, latest, can_upload, can_reattempt, attempts_left, attempts_so_far}]

    for wb in range(1, required + 1):
        subs = (WorkbookSubmission.query
                .filter_by(student_id=current_user.id, workbook_number=wb)
                .order_by(WorkbookSubmission.submission_time.desc())
                .all())
        latest = subs[0] if subs else None

        # Defaults
        status_key = 'awaiting'                 # Awaiting submission
        label = 'Awaiting submission'
        badge = 'bg-secondary'                  # Grey
        can_upload = True
        can_reattempt = False

        # Attempts calc: attempts_so_far = 1 (initial) + referral_count
        if latest:
            attempts_so_far = 1 + (latest.referral_count or 0)
        else:
            attempts_so_far = 0
        attempts_left = max(0, 3 - attempts_so_far)

        if latest:
            if not latest.marked:
                # Submitted, awaiting marking
                status_key = 'submitted'
                label = 'Submitted'
                badge = 'bg-warning text-dark'  # Yellow
                can_upload = False
            else:
                # Marked states
                if latest.is_referral:
                    status_key = 'waiting-reattempt'
                    label = 'Waiting for reattempt'
                    badge = 'bg-danger'          # Red
                    can_upload = False
                    can_reattempt = attempts_left > 0  # Only allow reattempts if under max
                elif latest.score == 100:
                    status_key = 'pass'
                    label = 'Marked Pass'
                    badge = 'bg-success'         # Green
                    can_upload = False
                else:
                    # Marked but not pass and not referral (fallback)
                    status_key = 'marked'
                    label = 'Marked'
                    badge = 'bg-info text-dark'
                    can_upload = False

        items.append({
            'wb_number': wb,
            'status_key': status_key,
            'label': label,
            'badge': badge,
            'latest': latest,
            'can_upload': can_upload,
            'can_reattempt': can_reattempt,
            'attempts_left': attempts_left,
            'attempts_so_far': attempts_so_far
        })

    return render_template(
        'student_dashboard.html',
        items=items,
        required=required,
        now=datetime.utcnow(),
        timedelta=timedelta
    )


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    # Optionally restrict to owner/assigned marker/admin
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Marker ---
@app.route('/marker_dashboard')
@login_required
def marker_dashboard():
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    now = datetime.utcnow()
    students = get_assigned_students_for_marker(current_user.id)

    # Donut: Unsubmitted / To be Marked / Marked
    status_counts = {
        "Unsubmitted": 0,
        "To be Marked": 0,
        "Marked": 0,
    }

    # Pending queue (unmarked submissions), sorted by least time remaining
    pending = []  # {student, submission, deadline, time_left}
    for student in students:
        subs = WorkbookSubmission.query.filter_by(student_id=student.id).order_by(WorkbookSubmission.submission_time.desc()).all()
        if not subs:
            status_counts["Unsubmitted"] += 1
            continue

        any_unmarked = any(not s.marked for s in subs)
        if any_unmarked:
            status_counts["To be Marked"] += 1
        else:
            status_counts["Marked"] += 1

        for s in subs:
            if not s.marked:
                deadline = s.submission_time + timedelta(days=14)
                time_left = deadline - now
                pending.append({
                    "student": student,
                    "submission": s,
                    "deadline": deadline,
                    "time_left": time_left,
                })

    pending.sort(key=lambda x: x["time_left"])  # overdue first

    return render_template(
        'marker_dashboard.html',
        students=students,
        status_counts=status_counts,
        pending=pending,
        now=now,
        timedelta=timedelta,
        COURSE_WORKBOOKS=COURSE_WORKBOOKS
    )


@app.route('/marker_view_student/<int:student_id>')
@login_required
def marker_view_student(student_id):
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    if not marker_is_assigned_to_student(current_user.id, student_id):
        abort(403)

    student = User.query.get_or_404(student_id)
    workbooks = WorkbookSubmission.query.filter_by(student_id=student.id).all()
    required = COURSE_WORKBOOKS.get(student.course, 1)
    workbooks_dict = {w.workbook_number: w for w in workbooks}

    # Prev/Next within assigned students
    assigned_students = get_assigned_students_for_marker(current_user.id)
    students_sorted = sorted(assigned_students, key=lambda s: s.id)
    student_ids = [s.id for s in students_sorted]
    current_index = student_ids.index(student.id)
    prev_id = student_ids[current_index - 1] if current_index > 0 else None
    next_id = student_ids[current_index + 1] if current_index < len(student_ids) - 1 else None

    return render_template(
        'marker_view_student.html',
        student=student,
        required=required,
        workbooks=workbooks,
        workbooks_dict=workbooks_dict,
        status=get_student_status(student, required),
        now=datetime.utcnow(),
        timedelta=timedelta,
        prev_id=prev_id,
        next_id=next_id
    )


@app.route('/mark_workbook/<int:submission_id>', methods=['POST'])
@login_required
def mark_workbook(submission_id):
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    submission = WorkbookSubmission.query.get_or_404(submission_id)

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
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        corrected.save(filepath)
        submission.corrected_submission_path = filename

    db.session.commit()
    return redirect(url_for('marker_view_student', student_id=submission.student_id))


@app.route('/marker_students')
@login_required
def marker_students():
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    students = get_assigned_students_for_marker(current_user.id)
    student_list = []
    for s in students:
        required = COURSE_WORKBOOKS.get(s.course, 1)
        status = get_student_status(s, required)
        student_list.append({"student": s, "status": status, "required": required})

    return render_template('marker_students.html', students=student_list)

# --- Admin: SUMMARY + status donut ---
@app.route('/admin_dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    students = User.query.filter_by(role='student').all()
    markers = User.query.filter_by(role='marker').all()
    assignments = Assignment.query.all()

    workload = {m.id: 0 for m in markers}
    for a in assignments:
        workload[a.marker_id] = workload.get(a.marker_id, 0) + 1

    status_counts = {
        "Unsubmitted": 0,
        "Awaiting Marking": 0,
        "Referral": 0,
        "Passed": 0
    }

    for student in students:
        required = COURSE_WORKBOOKS.get(student.course, 1)
        submissions = WorkbookSubmission.query.filter_by(student_id=student.id).all()

        if not submissions:
            status_counts["Unsubmitted"] += 1
            continue

        latest = max(submissions, key=lambda s: s.submission_time)
        if latest.is_referral and not latest.marked:
            status_counts["Referral"] += 1
        elif not latest.marked:
            status_counts["Awaiting Marking"] += 1
        elif latest.marked and not latest.is_referral and latest.score == 100:
            status_counts["Passed"] += 1
        else:
            status_counts["Awaiting Marking"] += 1

    return render_template(
        'admin_dashboard.html',
        students=students,
        markers=markers,
        assignments=assignments,
        workload=workload,
        status_counts=status_counts
    )

# --- Admin: ASSIGN STUDENTS ---
@app.route('/admin_assign', methods=['GET', 'POST'])
@login_required
def admin_assign():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    # POST: update an assignment
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        marker_id = request.form.get('marker_id')

        # Basic validation
        if not student_id or not marker_id:
            flash('Please choose both a student and a marker.', 'warning')
            return redirect(url_for('admin_assign'))

        try:
            student_id = int(student_id)
            marker_id = int(marker_id)
        except ValueError:
            flash('Invalid selection.', 'danger')
            return redirect(url_for('admin_assign'))

        student = User.query.get(student_id)
        marker = User.query.get(marker_id)

        if not student or student.role != 'student':
            flash('Selected student not found.', 'danger')
            return redirect(url_for('admin_assign'))
        if not marker or marker.role != 'marker':
            flash('Selected marker not found.', 'danger')
            return redirect(url_for('admin_assign'))

        # Create or update the assignment
        assignment = Assignment.query.filter_by(student_id=student.id).first()
        if assignment:
            assignment.marker_id = marker.id
        else:
            assignment = Assignment(student_id=student.id, marker_id=marker.id)
            db.session.add(assignment)

        db.session.commit()
        flash(f'Assigned {student.username} to {marker.username}.', 'success')
        return redirect(url_for('admin_assign'))

    # GET: render the page
    students = User.query.filter_by(role='student').order_by(User.username.asc()).all()
    markers = User.query.filter_by(role='marker').order_by(User.username.asc()).all()

    # Map: student_id -> marker_id for current assignments
    assignments = Assignment.query.all()
    current_marker_by_student = {a.student_id: a.marker_id for a in assignments}

    return render_template(
        'admin_assign.html',
        students=students,
        markers=markers,
        current_marker_by_student=current_marker_by_student
    )

# --- Admin: DELETE STUDENTS (page) ---
@app.route('/admin_delete_students', methods=['GET'])
@login_required
def admin_delete_students():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    students = User.query.filter_by(role='student').all()
    return render_template('admin_delete_students.html', students=students)

# --- Admin: Perform Delete ---
@app.route('/delete_student/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    if current_user.role != 'admin':
        abort(403)

    student = User.query.get_or_404(student_id)

    if student.role != 'student':
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

# --- Optional legacy combined page (kept) ---
@app.route('/view_users', methods=['GET', 'POST'])
@login_required
def view_users():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    markers = User.query.filter_by(role='marker').all()
    students = User.query.filter_by(role='student').all()

    if request.method == 'POST':
        student_id = int(request.form['student_id'])
        marker_id = int(request.form['marker_id'])
        assignment = Assignment.query.filter_by(student_id=student_id).first()
        if assignment:
            assignment.marker_id = marker_id
        else:
            assignment = Assignment(student_id=student_id, marker_id=marker_id)
            db.session.add(assignment)
        db.session.commit()
        flash("Marker assignment updated.", "success")
        return redirect(url_for('view_users'))

    assignments = {a.student_id: a.marker_id for a in Assignment.query.all()}
    return render_template('user_list.html', markers=markers, students=students, assignments=assignments)

# -----------------------
# Entrypoint
# -----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)