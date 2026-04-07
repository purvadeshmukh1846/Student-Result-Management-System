from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import pymysql
import pymysql.cursors
import bcrypt
from functools import wraps
from datetime import datetime, timedelta
import secrets
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Database configuration from config
DB_CONFIG = {
    'host': Config.MYSQL_HOST,
    'user': Config.MYSQL_USER,
    'password': Config.MYSQL_PASSWORD,
    'database': Config.MYSQL_DB,
    'cursorclass': pymysql.cursors.DictCursor
}

def get_db():
    return pymysql.connect(**DB_CONFIG)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Role required decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in roles:
                flash('Access denied', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role')
        
        if role == 'student':
            seat_number = request.form['seat_number']
            full_name = request.form['full_name']
            password = request.form['password']
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT s.*, u.user_id, u.full_name, u.email, u.password_hash, u.role 
                FROM students s
                JOIN users u ON s.user_id = u.user_id
                WHERE s.seat_number = %s AND u.full_name = %s
            ''', (seat_number, full_name))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                session['loggedin'] = True
                session['user_id'] = user['user_id']
                session['student_id'] = user['student_id']
                session['full_name'] = user['full_name']
                session['role'] = 'student'
                session['seat_number'] = user['seat_number']
                return redirect(url_for('student_dashboard'))
            else:
                flash('Invalid seat number, name or password', 'error')
        
        elif role == 'teacher':
            employee_id = request.form['employee_id']
            password = request.form['password']
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT t.*, u.user_id, u.full_name, u.email, u.password_hash, u.role
                FROM teachers t
                JOIN users u ON t.user_id = u.user_id
                WHERE t.employee_id = %s
            ''', (employee_id,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                session['loggedin'] = True
                session['user_id'] = user['user_id']
                session['teacher_id'] = user['teacher_id']
                session['full_name'] = user['full_name']
                session['role'] = 'teacher'
                session['employee_id'] = user['employee_id']
                return redirect(url_for('teacher_dashboard'))
            else:
                flash('Invalid employee ID or password', 'error')
        
        elif role == 'admin':
            email = request.form['email']
            password = request.form['password']
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = %s AND role = "admin"', (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                session['loggedin'] = True
                session['user_id'] = user['user_id']
                session['full_name'] = user['full_name']
                session['role'] = 'admin'
                session['email'] = user['email']
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid email or password', 'error')
    
    return render_template('login.html')

# ==================== REGISTER ====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        seat_number = request.form['seat_number']
        
        roll_number = request.form.get('roll_number')
        if roll_number == '':
            roll_number = None
        else:
            try:
                roll_number = int(roll_number)
            except ValueError:
                roll_number = None
        
        class_name = request.form.get('class')
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, role, full_name)
                VALUES (%s, %s, %s, 'student', %s)
            ''', (username, email, hashed_password.decode('utf-8'), full_name))
            user_id = cursor.lastrowid
            
            cursor.execute('''
                INSERT INTO students (user_id, seat_number, roll_number, class)
                VALUES (%s, %s, %s, %s)
            ''', (user_id, seat_number, roll_number, class_name))
            
            conn.commit()
            cursor.close()
            conn.close()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except pymysql.IntegrityError as e:
            conn.rollback()
            cursor.close()
            conn.close()
            if 'Duplicate' in str(e):
                if 'email' in str(e):
                    flash('Email already exists', 'error')
                elif 'username' in str(e):
                    flash('Username already exists', 'error')
                elif 'seat_number' in str(e):
                    flash('Seat number already exists', 'error')
                else:
                    flash('Registration failed. Duplicate entry.', 'error')
            else:
                flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

# ==================== FORGOT PASSWORD ====================
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        
        if user:
            token = secrets.token_urlsafe(16)
            expiry = datetime.now() + timedelta(minutes=30)
            cursor.execute('''
                UPDATE users 
                SET reset_token=%s, reset_token_expiry=%s 
                WHERE email=%s
            ''', (token, expiry, email))
            conn.commit()
            cursor.close()
            conn.close()
            flash(f'Password reset token generated. Use this token: {token}', 'info')
            return redirect(url_for('reset_password', token=token))
        else:
            cursor.close()
            conn.close()
            flash('Email not found in our system', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE reset_token=%s AND reset_token_expiry > NOW()', (token,))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        conn.close()
        flash('Invalid or expired token', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
        
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('UPDATE users SET password_hash=%s, reset_token=NULL, reset_token_expiry=NULL WHERE user_id=%s',
                       (hashed.decode('utf-8'), user['user_id']))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Password reset successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    cursor.close()
    conn.close()
    return render_template('reset_password.html', token=token)

# ==================== ADD TEACHER ====================
@app.route('/add-teacher', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_teacher():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        employee_id = request.form['employee_id']
        department = request.form.get('department', '')
        qualification = request.form.get('qualification', '')
        experience = request.form.get('experience', 0)
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, role, full_name)
                VALUES (%s, %s, %s, 'teacher', %s)
            ''', (username, email, hashed_password.decode('utf-8'), full_name))
            user_id = cursor.lastrowid
            
            cursor.execute('''
                INSERT INTO teachers (user_id, employee_id, department, qualification, experience)
                VALUES (%s, %s, %s, %s, %s)
            ''', (user_id, employee_id, department, qualification, experience))
            
            conn.commit()
            cursor.close()
            conn.close()
            flash('Teacher added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except pymysql.IntegrityError as e:
            conn.rollback()
            cursor.close()
            conn.close()
            flash('Error: Duplicate entry (email/username/employee_id)', 'error')
    
    return render_template('add_teacher.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

# ==================== STUDENT DASHBOARD ====================
@app.route('/student-dashboard')
@login_required
@role_required('student')
def student_dashboard():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.*, u.email, u.full_name
        FROM students s
        JOIN users u ON s.user_id = u.user_id
        WHERE s.student_id = %s
    ''', (session['student_id'],))
    student = cursor.fetchone()
    
    cursor.execute('''
        SELECT r.*, sub.subject_name, sub.subject_code, sub.max_marks
        FROM results r
        JOIN subjects sub ON r.subject_id = sub.subject_id
        WHERE r.student_id = %s
        ORDER BY sub.subject_code
    ''', (session['student_id'],))
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    
    total_marks = sum(r['marks_obtained'] for r in results) if results else 0
    total_max = sum(r['max_marks'] for r in results) if results else 0
    percentage = (total_marks / total_max * 100) if total_max > 0 else 0
    
    return render_template('student_dashboard.html', student=student, results=results,
                           total_marks=total_marks, total_max=total_max, percentage=percentage)

# ==================== TEACHER DASHBOARD ====================
@app.route('/teacher-dashboard')
@login_required
@role_required('teacher')
def teacher_dashboard():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT t.*, u.email, u.full_name
        FROM teachers t
        JOIN users u ON t.user_id = u.user_id
        WHERE t.teacher_id = %s
    ''', (session['teacher_id'],))
    teacher = cursor.fetchone()
    
    cursor.execute('''
        SELECT 
            s.student_id,
            s.seat_number,
            s.roll_number,
            s.class,
            s.section,
            u.full_name as student_name,
            COUNT(DISTINCT r.result_id) as subject_count,
            SUM(r.marks_obtained) as total_marks,
            SUM(sub.max_marks) as total_max,
            SUM(CASE WHEN r.status = 'PASS' THEN 1 ELSE 0 END) as passed_count
        FROM students s
        JOIN users u ON s.user_id = u.user_id
        LEFT JOIN results r ON s.student_id = r.student_id
        LEFT JOIN subjects sub ON r.subject_id = sub.subject_id
        GROUP BY s.student_id
        ORDER BY s.seat_number
    ''')
    students = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('teacher_dashboard.html', teacher=teacher, students=students)

# ==================== ADMIN DASHBOARD ====================
@app.route('/admin-dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) as total FROM students')
    total_students = cursor.fetchone()['total']
    cursor.execute('SELECT COUNT(*) as total FROM teachers')
    total_teachers = cursor.fetchone()['total']
    cursor.execute('SELECT COUNT(*) as total FROM users')
    total_users = cursor.fetchone()['total']
    
    cursor.execute('''
        SELECT 
            COUNT(DISTINCT CASE WHEN r.status = 'PASS' THEN s.student_id END) as passed_students,
            COUNT(DISTINCT CASE WHEN r.status = 'FAIL' THEN s.student_id END) as failed_students
        FROM students s
        LEFT JOIN results r ON s.student_id = r.student_id
    ''')
    stats = cursor.fetchone()
    
    cursor.execute('''
        SELECT grade, COUNT(*) as count
        FROM results
        GROUP BY grade
        ORDER BY FIELD(grade, 'A+','A','B+','B','C+','C','D','F')
    ''')
    grade_distribution = cursor.fetchall()
    
    cursor.execute('''
        SELECT user_id, username, email, role, full_name, created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT 10
    ''')
    recent_users = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('admin_dashboard.html',
                           total_students=total_students,
                           total_teachers=total_teachers,
                           total_users=total_users,
                           stats=stats,
                           grade_distribution=grade_distribution,
                           recent_users=recent_users)

# ==================== ADD MARKS ====================
@app.route('/add-marks', methods=['GET', 'POST'])
@login_required
@role_required('teacher')
def add_marks():
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        student_id = request.form['student_id']
        exam_term = request.form['exam_term']
        exam_year = request.form['exam_year']
        
        subject_ids = request.form.getlist('subject_id[]')
        marks_list = request.form.getlist('marks_obtained[]')
        
        success_count = 0
        error_count = 0
        
        for i in range(len(subject_ids)):
            subject_id = subject_ids[i]
            marks_obtained = float(marks_list[i]) if marks_list[i] else 0
            
            cursor.execute('SELECT * FROM subjects WHERE subject_id = %s', (subject_id,))
            subject = cursor.fetchone()
            if not subject:
                continue
            
            percentage = (marks_obtained / subject['max_marks']) * 100
            if percentage >= 90: grade = 'A+'
            elif percentage >= 80: grade = 'A'
            elif percentage >= 70: grade = 'B+'
            elif percentage >= 60: grade = 'B'
            elif percentage >= 50: grade = 'C+'
            elif percentage >= 35: grade = 'C'
            else: grade = 'F'
            
            status = 'PASS' if marks_obtained >= subject['pass_marks'] else 'FAIL'
            
            try:
                cursor.execute('''
                    INSERT INTO results (student_id, subject_id, marks_obtained, grade, status, exam_term, exam_year, entered_by, published_date)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURDATE())
                ''', (student_id, subject_id, marks_obtained, grade, status, exam_term, exam_year, session['user_id']))
                success_count += 1
            except Exception as e:
                error_count += 1
        
        conn.commit()
        cursor.close()
        conn.close()
        
        if error_count == 0:
            flash(f'{success_count} subjects marks added successfully!', 'success')
        else:
            flash(f'{success_count} subjects added, {error_count} failed.', 'warning')
        
        return redirect(url_for('teacher_dashboard'))
    
    cursor.execute('''
        SELECT s.student_id, s.seat_number, s.roll_number, s.class, u.full_name
        FROM students s
        JOIN users u ON s.user_id = u.user_id
        ORDER BY s.seat_number
    ''')
    students = cursor.fetchall()
    
    cursor.execute('SELECT * FROM subjects ORDER BY subject_code')
    subjects = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('add_marks.html', students=students, subjects=subjects)

# ==================== EDIT MARKS ====================
@app.route('/edit-marks/<int:result_id>', methods=['GET', 'POST'])
@login_required
@role_required('teacher')
def edit_marks(result_id):
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        marks_obtained = float(request.form['marks_obtained'])
        
        cursor.execute('''
            SELECT r.*, sub.max_marks, sub.pass_marks
            FROM results r
            JOIN subjects sub ON r.subject_id = sub.subject_id
            WHERE r.result_id = %s
        ''', (result_id,))
        result = cursor.fetchone()
        if not result:
            flash('Result not found', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        percentage = (marks_obtained / result['max_marks']) * 100
        if percentage >= 90: grade = 'A+'
        elif percentage >= 80: grade = 'A'
        elif percentage >= 70: grade = 'B+'
        elif percentage >= 60: grade = 'B'
        elif percentage >= 50: grade = 'C+'
        elif percentage >= 35: grade = 'C'
        else: grade = 'F'
        
        status = 'PASS' if marks_obtained >= result['pass_marks'] else 'FAIL'
        
        try:
            cursor.execute('''
                UPDATE results SET marks_obtained=%s, grade=%s, status=%s WHERE result_id=%s
            ''', (marks_obtained, grade, status, result_id))
            conn.commit()
            flash('Marks updated successfully', 'success')
            return redirect(url_for('teacher_dashboard'))
        except Exception as e:
            conn.rollback()
            flash('Error updating marks', 'error')
    
    cursor.execute('''
        SELECT r.*, s.seat_number, u.full_name as student_name, sub.subject_name, sub.subject_code, sub.max_marks
        FROM results r
        JOIN students s ON r.student_id = s.student_id
        JOIN users u ON s.user_id = u.user_id
        JOIN subjects sub ON r.subject_id = sub.subject_id
        WHERE r.result_id = %s
    ''', (result_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return render_template('edit_marks.html', result=result)

# ==================== CHECK RESULT ====================
@app.route('/check-result', methods=['POST'])
def check_result():
    seat_number = request.form['seat_number']
    return redirect(url_for('view_result', seat_number=seat_number))

@app.route('/view-result/<seat_number>')
def view_result(seat_number):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.*, u.full_name, u.email
        FROM students s
        JOIN users u ON s.user_id = u.user_id
        WHERE s.seat_number = %s
    ''', (seat_number,))
    student = cursor.fetchone()
    
    if not student:
        cursor.close()
        conn.close()
        flash('Student not found', 'error')
        return redirect(url_for('index'))
    
    cursor.execute('''
        SELECT r.*, sub.subject_name, sub.subject_code, sub.max_marks
        FROM results r
        JOIN subjects sub ON r.subject_id = sub.subject_id
        WHERE r.student_id = %s
        ORDER BY sub.subject_code
    ''', (student['student_id'],))
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    
    total_marks = sum(r['marks_obtained'] for r in results) if results else 0
    total_max = sum(r['max_marks'] for r in results) if results else 0
    percentage = (total_marks / total_max * 100) if total_max > 0 else 0
    
    return render_template('view_result.html',
                         student=student,
                         results=results,
                         total_marks=total_marks,
                         total_max=total_max,
                         percentage=percentage)

# ==================== DOWNLOAD PDF ====================
@app.route('/download-result/<seat_number>')
def download_result(seat_number):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.*, u.full_name, u.email
        FROM students s
        JOIN users u ON s.user_id = u.user_id
        WHERE s.seat_number = %s
    ''', (seat_number,))
    student = cursor.fetchone()
    
    if not student:
        cursor.close()
        conn.close()
        flash('Student not found', 'error')
        return redirect(url_for('index'))
    
    cursor.execute('''
        SELECT r.*, sub.subject_name, sub.subject_code, sub.max_marks
        FROM results r
        JOIN subjects sub ON r.subject_id = sub.subject_id
        WHERE r.student_id = %s
        ORDER BY sub.subject_code
    ''', (student['student_id'],))
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    
    total_marks = sum(r['marks_obtained'] for r in results) if results else 0
    total_max = sum(r['max_marks'] for r in results) if results else 0
    percentage = (total_marks / total_max * 100) if total_max > 0 else 0
    
    # Create PDF
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    
    p.setFont("Helvetica-Bold", 20)
    p.drawString(50, height - 50, "G. M. VEDAK COLLEGE OF SCIENCE")
    p.setFont("Helvetica", 12)
    p.drawString(50, height - 70, "(Affiliated to University of Mumbai)")
    p.drawString(50, height - 90, "TALA-MAHARASHTRA-402111")
    
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, height - 130, "STATEMENT OF MARKS")
    
    p.setFont("Helvetica", 10)
    p.drawString(50, height - 160, f"Student Name: {student['full_name']}")
    p.drawString(50, height - 175, f"Seat Number: {student['seat_number']}")
    p.drawString(50, height - 190, f"Roll Number: {student['roll_number']}")
    p.drawString(50, height - 205, f"Class: {student['class']}")
    p.drawString(300, height - 160, f"Father's Name: {student.get('father_name', 'N/A')}")
    p.drawString(300, height - 175, f"Academic Year: {student.get('academic_year', '2025-2026')}")
    
    data = [['Subject Code', 'Subject Name', 'Max Marks', 'Marks Obtained', 'Grade']]
    for r in results:
        data.append([r['subject_code'], r['subject_name'], str(r['max_marks']), 
                     str(r['marks_obtained']), r['grade']])
    data.append(['', 'TOTAL', str(total_max), str(total_marks), f"{percentage:.2f}%"])
    
    table = Table(data, colWidths=[80, 150, 70, 70, 50])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.blue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-2), colors.beige),
        ('BACKGROUND', (0,-1), (-1,-1), colors.lightblue),
        ('GRID', (0,0), (-1,-1), 1, colors.black)
    ]))
    
    table.wrapOn(p, width, height)
    table.drawOn(p, 50, height - 450)
    
    p.setFont("Helvetica", 8)
    p.drawString(50, 50, "This is a computer generated statement.")
    p.drawString(50, 35, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"Result_{seat_number}.pdf", mimetype='application/pdf')

# ==================== TOP PERFORMERS ====================
@app.route('/top-performers')
def top_performers():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            s.student_id,
            s.seat_number,
            u.full_name as student_name,
            COUNT(DISTINCT r.result_id) as subject_count,
            SUM(r.marks_obtained) as total_marks,
            SUM(sub.max_marks) as total_max,
            ROUND((SUM(r.marks_obtained)/SUM(sub.max_marks)*100),2) as percentage,
            CASE 
                WHEN AVG(r.marks_obtained) >= 90 THEN 'A+'
                WHEN AVG(r.marks_obtained) >= 80 THEN 'A'
                WHEN AVG(r.marks_obtained) >= 70 THEN 'B+'
                WHEN AVG(r.marks_obtained) >= 60 THEN 'B'
                WHEN AVG(r.marks_obtained) >= 50 THEN 'C+'
                WHEN AVG(r.marks_obtained) >= 35 THEN 'C'
                ELSE 'F'
            END as grade
        FROM students s
        JOIN users u ON s.user_id = u.user_id
        LEFT JOIN results r ON s.student_id = r.student_id
        LEFT JOIN subjects sub ON r.subject_id = sub.subject_id
        GROUP BY s.student_id
        ORDER BY total_marks DESC
        LIMIT 10
    ''')
    performers = cursor.fetchall()
    
    cursor.execute('''
        SELECT t.*, u.full_name, u.email
        FROM teachers t
        JOIN users u ON t.user_id = u.user_id
    ''')
    faculty = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('top_performers.html', performers=performers, faculty=faculty)

# ==================== PERFORMANCE ANALYTICS (दुरुस्त केलेले) ====================
@app.route('/analytics')
def analytics():
    conn = get_db()
    cursor = conn.cursor()
    
    # प्रत्येक विद्यार्थ्याचा एकूण निकाल (overall status) काढा
    cursor.execute('''
        SELECT 
            COUNT(*) as total_students,
            SUM(CASE WHEN fail_count > 0 THEN 1 ELSE 0 END) as failed_students,
            SUM(CASE WHEN fail_count = 0 AND total_subjects > 0 THEN 1 ELSE 0 END) as passed_students,
            AVG(avg_marks) as overall_average
        FROM (
            SELECT 
                s.student_id,
                COUNT(r.result_id) as total_subjects,
                SUM(CASE WHEN r.status = 'FAIL' THEN 1 ELSE 0 END) as fail_count,
                AVG(r.marks_obtained) as avg_marks
            FROM students s
            LEFT JOIN results r ON s.student_id = r.student_id
            GROUP BY s.student_id
        ) AS student_status
    ''')
    overall = cursor.fetchone()
    
    # Subject-wise performance
    cursor.execute('''
        SELECT 
            sub.subject_name,
            sub.subject_code,
            COUNT(r.result_id) as total_appeared,
            AVG(r.marks_obtained) as avg_marks,
            MAX(r.marks_obtained) as highest_marks,
            MIN(r.marks_obtained) as lowest_marks,
            SUM(CASE WHEN r.status = 'PASS' THEN 1 ELSE 0 END) as passed_count
        FROM subjects sub
        LEFT JOIN results r ON sub.subject_id = r.subject_id
        GROUP BY sub.subject_id
        ORDER BY avg_marks DESC
    ''')
    subject_performance = cursor.fetchall()
    
    # Grade distribution
    cursor.execute('''
        SELECT grade, COUNT(*) as count
        FROM results
        GROUP BY grade
        ORDER BY FIELD(grade, 'A+','A','B+','B','C+','C','D','F')
    ''')
    grade_dist = cursor.fetchall()
    
    # Class-wise performance
    cursor.execute('''
        SELECT 
            s.class,
            COUNT(DISTINCT s.student_id) as student_count,
            COUNT(r.result_id) as result_count,
            AVG(r.marks_obtained) as class_average
        FROM students s
        LEFT JOIN results r ON s.student_id = r.student_id
        GROUP BY s.class
    ''')
    class_performance = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('analytics.html',
                           overall=overall,
                           subject_performance=subject_performance,
                           grade_dist=grade_dist,
                           class_performance=class_performance)

if __name__ == '__main__':
    app.run(debug=True)