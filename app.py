from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, abort  # >>> NEW (abort)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

COURSE_WORKBOOKS = {
    'FREC4': 3,
    'SALM': 1,
    'CFR': 1
}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    course = db.Column(db.String(10), nullable=True)

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

    # This is the fix:
    student = db.relationship('User', foreign_keys=[student_id])

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    marker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
    days = time_left.days
    hours = time_left.seconds // 3600
    return max(days, 0), max(hours, 0), deadline

# >>> NEW: helper to get only assigned students for a given marker
def get_assigned_students_for_marker(marker_id):
    return (
        db.session.query(User)
        .join(Assignment, Assignment.student_id == User.id)
        .filter(User.role == 'student', Assignment.marker_id == marker_id)
        .all()
    )

# >>> NEW: helper to check if marker is assigned to a student
def marker_is_assigned_to_student(marker_id, student_id):
    return Assignment.query.filter_by(marker_id=marker_id, student_id=student_id).first() is not None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        course = request.form.get('course') if role == 'student' else None

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=password, role=role, course=course)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'marker':
                return redirect(url_for('marker_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/student_dashboard', methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('login'))
    workbooks = WorkbookSubmission.query.filter_by(student_id=current_user.id).all()
    required = COURSE_WORKBOOKS.get(current_user.course, 1)
    status = get_student_status(current_user, required)

    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            wb_number = int(request.form['workbook_number'])
            if file:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                existing = WorkbookSubmission.query.filter_by(student_id=current_user.id, workbook_number=wb_number).all()
                referral_count = existing[-1].referral_count + 1 if existing else 0
                submission = WorkbookSubmission(
                    student_id=current_user.id,
                    workbook_number=wb_number,
                    file_path=filename,
                    referral_count=referral_count
                )
                db.session.add(submission)
                db.session.commit()
                return redirect(url_for('student_dashboard'))
        elif 'referral_file' in request.files:
            referral_file = request.files['referral_file']
            wb_number = int(request.form['workbook_number'])
            if referral_file:
                filename = secure_filename(referral_file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                referral_file.save(filepath)
                submission = WorkbookSubmission.query.filter_by(student_id=current_user.id, workbook_number=wb_number).order_by(WorkbookSubmission.submission_time.desc()).first()
                if submission:
                    submission.corrected_submission_path = filename
                    db.session.commit()
                    return redirect(url_for('student_dashboard'))

    return render_template('student_dashboard.html', workbooks=workbooks, required=required, now=datetime.utcnow(), timedelta=timedelta, status=status)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/marker_dashboard')
@login_required
def marker_dashboard():
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    # >>> NEW: only students assigned to this marker
    students = get_assigned_students_for_marker(current_user.id)

    grouped = {}
    for student in students:
        course = student.course or "Unknown"
        grouped.setdefault(course, []).append({
            'student': student,
            'workbooks': WorkbookSubmission.query.filter_by(student_id=student.id).all(),
            'status': get_student_status(student, COURSE_WORKBOOKS.get(course, 1))
        })

    # >>> NEW: recent submissions restricted to assigned students
    student_ids = [s.id for s in students]
    if student_ids:
        recent_submissions = (
            WorkbookSubmission.query
            .filter(WorkbookSubmission.student_id.in_(student_ids))
            .order_by(WorkbookSubmission.submission_time.desc())
            .limit(10)
            .all()
        )
    else:
        recent_submissions = []

    # Create a dictionary to quickly look up usernames by ID
    users = {u.id: u for u in User.query.filter(User.id.in_(student_ids)).all()}  # >>> tightened to only needed users

    return render_template(
        'marker_dashboard.html',
        grouped=grouped,
        recent_submissions=recent_submissions,
        users=users,
        now=datetime.utcnow(),
        timedelta=timedelta,
        COURSE_WORKBOOKS=COURSE_WORKBOOKS
    )

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    students = User.query.filter_by(role='student').all()
    markers = User.query.filter_by(role='marker').all()

    if request.method == 'POST':
        student_id = request.form['student_id']
        marker_id = request.form['marker_id']
        assignment = Assignment.query.filter_by(student_id=student_id).first()
        if assignment:
            assignment.marker_id = marker_id
        else:
            assignment = Assignment(student_id=student_id, marker_id=marker_id)
            db.session.add(assignment)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    assignments = Assignment.query.all()
    return render_template('admin_dashboard.html', students=students, markers=markers, assignments=assignments)

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

@app.route('/marker_view_student/<int:student_id>')
@login_required
def marker_view_student(student_id):
    if current_user.role != 'marker':
        return redirect(url_for('login'))

    # >>> NEW: enforce assignment ownership
    if not marker_is_assigned_to_student(current_user.id, student_id):
        abort(403)

    student = User.query.get_or_404(student_id)
    workbooks = WorkbookSubmission.query.filter_by(student_id=student.id).all()
    required = COURSE_WORKBOOKS.get(student.course, 1)
    workbooks_dict = {w.workbook_number: w for w in workbooks}

    # >>> NEW: navigation limited to assigned cohort
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

    # >>> NEW: block marking if this marker isn't assigned to the student
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)