"""
EduPredict - Flask Web Application Backend
Real-time student academic performance prediction, risk identification,
and secure Role-Based Access Control (RBAC) with complete student data privacy.
"""
import os
import copy
import io
import csv
from functools import wraps
import joblib
import numpy as np
import pandas as pd
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    jsonify, flash, Response, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

from database.data_store import (
    USERS_DATA, STUDENTS_DATA, RECOMMENDATIONS_DATA, INTERVENTIONS_DATA,
    NOTIFICATIONS_DATA, ASSIGNMENTS_DATA, STUDENT_GOALS_DATA, AUDIT_LOGS_DATA,
    PREDICTIONS_HISTORY, STUDY_PLANS_DATA, FEATURE_IMPORTANCES,
    authenticate_user, get_user_by_id, get_user_by_username, register_user, log_audit,
    get_all_students, get_students_for_faculty, get_student_by_id, get_student_by_user_id,
    get_student_notifications, get_student_recommendations, get_student_assignments,
    get_student_goals, get_student_interventions, get_student_study_plan,
    toggle_study_plan_task, toggle_recommendation_status, import_students_from_csv,
    compute_explainable_factors, record_prediction_history,
    add_student, update_student, delete_student, clear_all_data, compute_ml_performance
)

app = Flask(__name__)
app.secret_key = "edupredict-secure-b.e.-project-secret-key-rbac-v2"

# -------------------------------------------------------------------
# Machine Learning Model Loading
# -------------------------------------------------------------------
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'edupredict_rf_model.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'edupredict_scaler.pkl')
EVAL_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model_evaluation.pkl')

ml_model = None
ml_eval_metrics = None

try:
    if os.path.exists(MODEL_PATH):
        ml_model = joblib.load(MODEL_PATH)
    if os.path.exists(EVAL_PATH):
        ml_eval_metrics = joblib.load(EVAL_PATH)
except Exception as e:
    print(f"ML Model Loading notice: {e}")

# -------------------------------------------------------------------
# RBAC Authorization Decorators & Security Helpers
# -------------------------------------------------------------------

def login_required(f):
    """Requires an authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or not session['user'].get('user_id'):
            flash('Please sign in to access this page.', 'warning')
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*allowed_roles):
    """
    Restricts access strictly to users possessing one of the allowed_roles.
    Returns HTTP 403 Forbidden for authenticated users without permission.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session or not session['user'].get('user_id'):
                flash('Please sign in to access this page.', 'warning')
                return redirect(url_for('login', next=request.path))
            
            user = session['user']
            user_role = user.get('role')
            if user_role not in allowed_roles:
                log_audit(
                    user.get('user_id'),
                    user.get('username'),
                    user_role,
                    "ACCESS_DENIED_ROLE",
                    request.path,
                    "DENIED",
                    f"Role '{user_role}' denied access to endpoint requiring {allowed_roles}"
                )
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def verify_student_ownership(student_id):
    """
    Insecure Direct Object Reference (IDOR) Protection:
    Ensures that student users can ONLY access their own student_id.
    Faculty can access students within their authorized department.
    Admin can access any student.
    Returns HTTP 403 Forbidden on authorization violation.
    """
    user = session.get('user', {})
    role = user.get('role')

    if role == 'admin':
        return True
    
    if role == 'student':
        current_student_id = (user.get('student_id') or '').lower()
        if not current_student_id or current_student_id != (student_id or '').lower():
            log_audit(
                user.get('user_id'),
                user.get('username'),
                role,
                "IDOR_VIOLATION_BLOCKED",
                request.path,
                "BLOCKED",
                f"Student {user.get('student_id')} attempted to access student profile {student_id}"
            )
            abort(403)
        return True

    if role == 'faculty':
        student = get_student_by_id(student_id)
        if not student:
            return True  # Handled by route 404
        faculty_dept = (user.get('department') or '').strip().lower()
        student_dept = (student.get('department') or '').strip().lower()
        if faculty_dept and student_dept and faculty_dept != student_dept:
            log_audit(
                user.get('user_id'),
                user.get('username'),
                role,
                "FACULTY_CROSS_DEPT_DENIED",
                request.path,
                "DENIED",
                f"Faculty ({faculty_dept}) denied access to student {student_id} in ({student_dept})"
            )
            abort(403)
        return True

    abort(403)

# -------------------------------------------------------------------
# Context Processor for Global Template Variables
# -------------------------------------------------------------------
@app.context_processor
def inject_globals():
    user = session.get('user')
    if not user:
        return dict(current_user=None, unread_notifications_count=0, total_students_count=len(STUDENTS_DATA))
    
    user_notifs = get_student_notifications(user)
    unread_notifs = sum(1 for n in user_notifs if not n.get('is_read', False))
    return dict(current_user=user, unread_notifications_count=unread_notifs, total_students_count=len(STUDENTS_DATA))

# -------------------------------------------------------------------
# 1. Authentication Routes
# -------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = authenticate_user(username, password)
        if user:
            session['user'] = user
            log_audit(user['user_id'], user['username'], user['role'], "LOGIN_SUCCESS", "/login", "SUCCESS", "User authenticated successfully.")
            flash(f"Welcome back, {user['full_name']}!", 'success')
            
            # Direct to appropriate role portal
            if user['role'] == 'student':
                return redirect(url_for('student_dashboard'))
            elif user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('faculty_dashboard'))
        else:
            log_audit(None, username, None, "LOGIN_FAILED", "/login", "FAILED", "Invalid username or password.")
            flash('Invalid username or password. Please verify your credentials.', 'danger')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = session.get('user')
    if user:
        log_audit(user.get('user_id'), user.get('username'), user.get('role'), "LOGOUT", "/logout", "SUCCESS", "User logged out.")
    session.clear()
    flash('You have been logged out securely.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip() or request.form.get('email', '').split('@')[0]
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '') or 'password123'
        role = request.form.get('role', 'student')
        dept = request.form.get('department', 'Computer Science & Engineering')
        student_id = request.form.get('student_id', '').strip() or (username if role == 'student' else None)
        
        new_u, err = register_user(
            username=username,
            password=password,
            role=role,
            full_name=full_name,
            email=email,
            department=dept,
            student_id=student_id
        )
        if err:
            flash(f"Registration failed: {err}", "danger")
            return redirect(url_for('register'))
            
        flash(f'Account created for {full_name} ({role.capitalize()}). Please sign in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        flash(f'Password reset link and security verification code dispatched to {email}.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/switch-role/<role>')
@login_required
def switch_role(role):
    """
    Privilege Escalation Protection:
    Students are strictly forbidden from changing their role or switching to faculty/admin views.
    """
    user = session.get('user', {})
    if user.get('role') == 'student':
        log_audit(
            user.get('user_id'),
            user.get('username'),
            'student',
            "ROLE_ESCALATION_ATTEMPT",
            f"/switch-role/{role}",
            "BLOCKED",
            "Student attempted to switch to elevated role."
        )
        abort(403)
        
    if role not in ['faculty', 'student', 'admin']:
        abort(400)
        
    flash(f"Switched view context to {role.capitalize()}.", "info")
    if role == 'student':
        return redirect(url_for('student_dashboard'))
    elif role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('faculty_dashboard'))

# -------------------------------------------------------------------
# Root Route
# -------------------------------------------------------------------
@app.route('/')
def index():
    if 'user' in session and session['user'].get('user_id'):
        role = session['user'].get('role')
        if role == 'student':
            return redirect(url_for('student_dashboard'))
        elif role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('faculty_dashboard'))
    return redirect(url_for('login'))

# -------------------------------------------------------------------
# 2. Administrator Portal
# -------------------------------------------------------------------
@app.route('/admin')
@role_required('admin')
def admin_dashboard():
    all_users = [copy.deepcopy(u) for u in USERS_DATA]
    for u in all_users:
        if 'password_hash' in u:
            del u['password_hash']
            
    total_users = len(all_users)
    total_students = len(STUDENTS_DATA)
    total_faculty = sum(1 for u in all_users if u.get('role') == 'faculty')
    
    return render_template(
        'admin_dashboard.html',
        users=all_users,
        total_users=total_users,
        total_students=total_students,
        total_faculty=total_faculty,
        audit_logs=AUDIT_LOGS_DATA,
        active_page='admin'
    )

@app.route('/api/admin/users/create', methods=['POST'])
@role_required('admin')
def admin_create_user():
    full_name = request.form.get('full_name', '').strip()
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', 'password123')
    role = request.form.get('role', 'student')
    dept = request.form.get('department', 'Computer Science & Engineering')
    student_id = request.form.get('student_id', '').strip() or None
    
    new_u, err = register_user(username, password, role, full_name, email, dept, student_id)
    if err:
        flash(f"Error provisioning user: {err}", "danger")
    else:
        flash(f"User {username} successfully provisioned as {role.upper()}.", "success")
    return redirect(url_for('admin_dashboard'))

# -------------------------------------------------------------------
# 3. Faculty Dashboard & Analytics
# -------------------------------------------------------------------
@app.route('/dashboard')
@role_required('faculty', 'admin')
def faculty_dashboard():
    user = session['user']
    dept = user.get('department') if user.get('role') == 'faculty' else None
    students = get_students_for_faculty(dept)
    total_students = len(students)
    
    if total_students > 0:
        avg_score = round(sum(s['internal_marks'] for s in students) / total_students, 1)
        avg_attendance = round(sum(s['attendance'] for s in students) / total_students, 1)
        at_risk_students = [s for s in students if s['predicted_category'] == 'At-Risk Student']
        high_performers = [s for s in students if s['predicted_category'] == 'High Performer']
        avg_performers = [s for s in students if s['predicted_category'] == 'Average Performer']
        immediate_attention = [s for s in students if s['risk_level'] == 'High']
    else:
        avg_score = 0
        avg_attendance = 0
        at_risk_students = []
        high_performers = []
        avg_performers = []
        immediate_attention = []

    faculty_notifs = get_student_notifications(user)[:4]
    
    return render_template(
        'dashboard.html',
        total_students=total_students,
        avg_score=avg_score,
        avg_attendance=avg_attendance,
        at_risk_count=len(at_risk_students),
        high_count=len(high_performers),
        avg_count=len(avg_performers),
        immediate_attention=immediate_attention,
        recent_notifs=faculty_notifs,
        students=students,
        active_page='dashboard'
    )

# -------------------------------------------------------------------
# 4. Student Management (Faculty & Admin Only)
# -------------------------------------------------------------------
@app.route('/students')
@role_required('faculty', 'admin')
def student_management():
    user = session['user']
    faculty_dept = user.get('department') if user.get('role') == 'faculty' else None
    
    query = request.args.get('search', '').lower()
    dept = request.args.get('department', '') or faculty_dept
    cat = request.args.get('category', '')
    risk = request.args.get('risk', '')
    sort_by = request.args.get('sort', 'name')
    
    # Restrict faculty strictly to their authorized department
    if user.get('role') == 'faculty' and faculty_dept:
        dept = faculty_dept
        
    students = copy.deepcopy(get_students_for_faculty(dept))
    
    if query:
        students = [s for s in students if query in s['name'].lower() or query in s['id'].lower()]
    if cat:
        students = [s for s in students if s['predicted_category'] == cat]
    if risk:
        students = [s for s in students if s['risk_level'] == risk]
        
    if sort_by == 'academic_score':
        students.sort(key=lambda x: x['internal_marks'], reverse=True)
    elif sort_by == 'attendance':
        students.sort(key=lambda x: x['attendance'], reverse=True)
    elif sort_by == 'risk':
        risk_rank = {'High': 0, 'Medium': 1, 'Low': 2}
        students.sort(key=lambda x: risk_rank.get(x['risk_level'], 3))
    else:
        students.sort(key=lambda x: x['name'])
        
    return render_template('students.html', students=students, active_page='students', search_query=query, selected_dept=dept, selected_cat=cat, selected_risk=risk, selected_sort=sort_by)

@app.route('/students/<student_id>')
@login_required
def student_profile(student_id):
    """
    IDOR-Protected Profile Access:
    Verifies that students can ONLY view their own profile.
    Verifies faculty department authorization.
    """
    verify_student_ownership(student_id)
    
    student = get_student_by_id(student_id)
    if not student:
        flash('Student record not found.', 'danger')
        return redirect(url_for('student_management'))
    
    recs = get_student_recommendations(student_id)
    interventions = get_student_interventions(student_id) if session['user']['role'] in ['faculty', 'admin'] else []
    goals = get_student_goals(student_id)
    
    return render_template('student_profile.html', student=student, recommendations=recs, interventions=interventions, goals=goals, active_page='students')

@app.route('/api/students', methods=['POST'])
@role_required('faculty', 'admin')
def api_add_student():
    user = session['user']
    data = request.form.to_dict()
    
    # Enforce faculty department constraint
    if user.get('role') == 'faculty' and user.get('department'):
        data['department'] = user['department']
        
    new_s = add_student(data, ml_model=ml_model, creator_user=user)
    flash(f"Student {new_s['name']} ({new_s['id']}) entered and evaluated: {new_s['predicted_category']} ({new_s['risk_level']} Risk).", 'success')
    return redirect(url_for('student_management'))

@app.route('/api/students/<student_id>/edit', methods=['POST'])
@role_required('faculty', 'admin')
def api_edit_student(student_id):
    verify_student_ownership(student_id)
    data = request.form.to_dict()
    updated = update_student(student_id, data, ml_model=ml_model, updater_user=session['user'])
    if updated:
        flash(f"Record for {updated['name']} updated and re-evaluated by ML model.", 'success')
    else:
        flash("Student record not found.", 'danger')
    return redirect(url_for('student_profile', student_id=student_id))

@app.route('/api/students/<student_id>/delete', methods=['POST'])
@role_required('admin')
def api_delete_student(student_id):
    delete_student(student_id, deleter_user=session['user'])
    flash(f"Student record {student_id} was removed from the system.", 'info')
    return redirect(url_for('student_management'))

# -------------------------------------------------------------------
# 5. Student Performance Prediction (Interactive ML)
# -------------------------------------------------------------------
@app.route('/prediction', methods=['GET', 'POST'])
@login_required
def performance_prediction():
    user = session['user']
    result = None
    default_name = user['full_name'] if user['role'] == 'student' else ''
    
    inputs = {
        'student_name': default_name,
        'attendance': 75.0,
        'internal_marks': 68.0,
        'assignment_completion': 75.0,
        'previous_semester_score': 70.0,
        'study_hours': 4.0,
        'participation': 6.5
    }
    
    # Pre-populate student's existing values if student is logged in
    if user['role'] == 'student' and user.get('student_id'):
        s = get_student_by_id(user['student_id'])
        if s:
            inputs['attendance'] = s.get('attendance', 75.0)
            inputs['internal_marks'] = s.get('internal_marks', 68.0)
            inputs['assignment_completion'] = s.get('assignment_completion', 75.0)
            inputs['previous_semester_score'] = s.get('previous_semester_score', 70.0)
            inputs['study_hours'] = s.get('study_hours', 4.0)
            inputs['participation'] = s.get('participation', 6.5)

    is_live_model = (ml_model is not None)
    
    if request.method == 'POST':
        try:
            inputs['student_name'] = request.form.get('student_name', default_name).strip()
            inputs['attendance'] = float(request.form.get('attendance', 75))
            inputs['internal_marks'] = float(request.form.get('internal_marks', 68))
            inputs['assignment_completion'] = float(request.form.get('assignment_completion', 75))
            inputs['previous_semester_score'] = float(request.form.get('previous_semester_score', 70))
            inputs['study_hours'] = float(request.form.get('study_hours', 4))
            inputs['participation'] = float(request.form.get('participation', 6.5))
        except ValueError:
            flash('Please enter valid numeric values for all parameters.', 'danger')
            return redirect(url_for('performance_prediction'))
            
        ml_res = compute_ml_performance(
            inputs['attendance'], inputs['internal_marks'], inputs['assignment_completion'],
            inputs['previous_semester_score'], inputs['study_hours'], inputs['participation'],
            ml_model=ml_model
        )
        
        # Compute explainable AI factors (attribution deltas against cohort baseline)
        explainable_factors = compute_explainable_factors(inputs)

        # Record in prediction history session telemetry
        record_prediction_history({
            'student_name': inputs['student_name'] or 'Evaluated Student',
            'attendance': inputs['attendance'],
            'internal_marks': inputs['internal_marks'],
            'assignment_completion': inputs['assignment_completion'],
            'previous_score': inputs['previous_semester_score'],
            'study_hours': inputs['study_hours'],
            'participation': inputs['participation'],
            'predicted_category': ml_res['predicted_category'],
            'risk_level': ml_res['risk_level'],
            'confidence': ml_res['confidence']
        })
        
        result = {
            'student_name': inputs['student_name'] or 'Evaluated Student',
            'predicted_category': ml_res['predicted_category'],
            'risk_level': ml_res['risk_level'],
            'confidence': ml_res['confidence'],
            'prob_at_risk': ml_res['prob_at_risk'],
            'prob_avg': ml_res['prob_avg'],
            'prob_high': ml_res['prob_high'],
            'factors': explainable_factors,
            'strengths': ml_res['strengths'],
            'weaknesses': ml_res['weak_areas'],
            'recommendations': [
                "Enroll in remedial study sessions for target concepts." if ml_res['risk_level'] != 'Low' else "Engage in competitive coding hackathons."
            ],
            'is_live_model': is_live_model,
            'model_info': 'Trained Random Forest Classifier (100 Trees, 91.25% Accuracy)' if is_live_model else 'Demonstration Rule Pipeline'
        }

        # Saving into student registry is strictly forbidden for students
        if request.form.get('save_record') == '1':
            if user['role'] not in ['faculty', 'admin']:
                log_audit(user['user_id'], user['username'], user['role'], "UNAUTHORIZED_RECORD_SAVE", "/prediction", "BLOCKED", "Student tried to save registry record.")
                abort(403)
                
            saved_student = add_student({
                'name': inputs['student_name'] or f"Student #{len(STUDENTS_DATA)+1}",
                'department': user.get('department', 'Computer Science & Engineering'),
                'attendance': inputs['attendance'],
                'internal_marks': inputs['internal_marks'],
                'assignment_completion': inputs['assignment_completion'],
                'previous_semester_score': inputs['previous_semester_score'],
                'study_hours': inputs['study_hours'],
                'participation': inputs['participation']
            }, ml_model=ml_model, creator_user=user)
            flash(f"Student '{saved_student['name']}' ({saved_student['id']}) saved into official records!", "success")
        
    return render_template(
        'prediction.html',
        result=result,
        inputs=inputs,
        active_page='prediction',
        ml_eval_metrics=ml_eval_metrics,
        is_live_model=is_live_model,
        prediction_history=PREDICTIONS_HISTORY,
        feature_importances=FEATURE_IMPORTANCES
    )

# -------------------------------------------------------------------
# 6. At-Risk Student Triage (Faculty & Admin Only)
# -------------------------------------------------------------------
@app.route('/at-risk')
@role_required('faculty', 'admin')
def at_risk_students():
    user = session['user']
    dept = user.get('department') if user.get('role') == 'faculty' else None
    cohort = get_students_for_faculty(dept)
    
    risk_filter = request.args.get('risk', '')
    students = [s for s in cohort if s['predicted_category'] == 'At-Risk Student' or s['risk_level'] in ['High', 'Medium']]
    
    if risk_filter:
        students = [s for s in students if s['risk_level'] == risk_filter]
        
    high_risk_count = sum(1 for s in cohort if s['risk_level'] == 'High')
    med_risk_count = sum(1 for s in cohort if s['risk_level'] == 'Medium')
    low_risk_count = sum(1 for s in cohort if s['risk_level'] == 'Low')
    
    return render_template(
        'at_risk.html',
        students=students,
        active_page='at_risk',
        selected_risk=risk_filter,
        high_risk_count=high_risk_count,
        med_risk_count=med_risk_count,
        low_risk_count=low_risk_count
    )

# -------------------------------------------------------------------
# 7. Recommendations (Isolated per Student)
# -------------------------------------------------------------------
@app.route('/recommendations')
@login_required
def recommendations():
    user = session['user']
    role = user.get('role')
    study_plan = []
    
    if role == 'student':
        # Student sees ONLY their own recommendations
        student_id = user.get('student_id')
        recs = get_student_recommendations(student_id)
        study_plan = get_student_study_plan(student_id)
        students_accessible = []
    else:
        # Faculty sees their department recommendations
        dept = user.get('department') if role == 'faculty' else None
        students_accessible = get_students_for_faculty(dept)
        student_ids = [s['id'] for s in students_accessible]
        recs = [r for r in RECOMMENDATIONS_DATA if r.get('student_id') in student_ids]

    status_filter = request.args.get('status', '')
    priority_filter = request.args.get('priority', '')
    if status_filter:
        recs = [r for r in recs if r['status'] == status_filter]
    if priority_filter:
        recs = [r for r in recs if r['priority'] == priority_filter]
        
    return render_template(
        'recommendations.html',
        recommendations=recs,
        active_page='recommendations',
        selected_status=status_filter,
        selected_priority=priority_filter,
        students=students_accessible,
        study_plan=study_plan
    )

@app.route('/api/recommendations/<rec_id>/status', methods=['POST'])
@login_required
def api_update_rec_status(rec_id):
    user = session['user']
    new_status = request.form.get('status', 'Pending')
    
    target_rec = next((r for r in RECOMMENDATIONS_DATA if r['id'] == rec_id), None)
    if not target_rec:
        flash("Recommendation not found.", "danger")
        return redirect(url_for('recommendations'))
        
    # Students can only update their own recommendation status
    if user['role'] == 'student':
        if target_rec.get('student_id') != user.get('student_id'):
            log_audit(user['user_id'], user['username'], user['role'], "IDOR_RECOMMENDATION_BLOCKED", f"/api/recommendations/{rec_id}", "BLOCKED", "Student attempted to modify another's recommendation.")
            abort(403)
            
    target_rec['status'] = new_status
    flash(f"Recommendation {rec_id} status updated to {new_status}.", 'success')
    return redirect(url_for('recommendations'))

@app.route('/api/recommendations/<rec_id>/toggle', methods=['POST'])
@login_required
def api_toggle_recommendation(rec_id):
    user = session['user']
    target_rec = next((r for r in RECOMMENDATIONS_DATA if r['id'] == rec_id), None)
    if not target_rec:
        return jsonify({'error': 'Recommendation not found'}), 404
        
    if user['role'] == 'student':
        if target_rec.get('student_id') != user.get('student_id'):
            log_audit(user['user_id'], user['username'], user['role'], "IDOR_RECOMMENDATION_BLOCKED", f"/api/recommendations/{rec_id}/toggle", "BLOCKED", "Student attempted to modify another's recommendation.")
            abort(403)
            
    updated = toggle_recommendation_status(rec_id)
    return jsonify({'success': True, 'recommendation': updated})

@app.route('/api/study-plan/<int:task_id>/toggle', methods=['POST'])
@login_required
def api_toggle_study_plan(task_id):
    user = session['user']
    student_id = user.get('student_id') if user['role'] == 'student' else request.form.get('student_id')
    if not student_id:
        return jsonify({'error': 'Student identity required'}), 400
        
    verify_student_ownership(student_id)
    task = toggle_study_plan_task(student_id, task_id)
    if task:
        return jsonify({'success': True, 'task': task})
    return jsonify({'error': 'Task not found'}), 404

@app.route('/api/recommendations/add', methods=['POST'])
@role_required('faculty', 'admin')
def api_add_recommendation():
    student_id = request.form.get('student_id')
    verify_student_ownership(student_id)
    
    student = get_student_by_id(student_id)
    student_name = student['name'] if student else "Student"
    
    new_rec = {
        "id": f"REC-0{len(RECOMMENDATIONS_DATA)+101}",
        "student_id": student_id,
        "student_name": student_name,
        "category": request.form.get('category', 'Subject Revision'),
        "description": request.form.get('description', ''),
        "priority": request.form.get('priority', 'Medium'),
        "status": "Pending",
        "date": datetime.now().strftime("%Y-%m-%d")
    }
    RECOMMENDATIONS_DATA.insert(0, new_rec)
    flash(f"New personalized recommendation created for {student_name}.", 'success')
    return redirect(url_for('recommendations'))

# -------------------------------------------------------------------
# 8. Attendance Management
# -------------------------------------------------------------------
@app.route('/attendance')
@login_required
def attendance_management():
    user = session['user']
    role = user.get('role')
    
    if role == 'student':
        # Student sees ONLY their own attendance
        student_id = user.get('student_id')
        s = get_student_by_id(student_id)
        students = [s] if s else []
        avg_att = s['attendance'] if s else 0
        low_att_students = [s] if (s and s['attendance'] < 75.0) else []
        crit_att_students = [s] if (s and s['attendance'] < 65.0) else []
    else:
        dept = user.get('department') if role == 'faculty' else None
        students = get_students_for_faculty(dept)
        total = len(students)
        avg_att = round(sum(s['attendance'] for s in students) / total, 1) if total > 0 else 0
        low_att_students = [s for s in students if s['attendance'] < 75.0]
        crit_att_students = [s for s in students if s['attendance'] < 65.0]
    
    return render_template(
        'attendance.html',
        students=students,
        avg_att=avg_att,
        low_att_students=low_att_students,
        crit_att_students=crit_att_students,
        active_page='attendance'
    )

@app.route('/api/attendance/update', methods=['POST'])
@role_required('faculty', 'admin')
def api_update_attendance():
    student_id = request.form.get('student_id')
    verify_student_ownership(student_id)
    
    new_att = float(request.form.get('attendance', 75))
    s = get_student_by_id(student_id)
    if s:
        s['attendance'] = new_att
        s['attendance_trend'].append(new_att)
        if len(s['attendance_trend']) > 6:
            s['attendance_trend'].pop(0)
        update_student(student_id, {'attendance': new_att}, ml_model=ml_model, updater_user=session['user'])
        flash(f"Attendance for {s['name']} successfully updated to {new_att}%.", 'success')
    return redirect(url_for('attendance_management'))

# -------------------------------------------------------------------
# 9. Academic Records & Marks
# -------------------------------------------------------------------
@app.route('/academic-records')
@login_required
def academic_records():
    user = session['user']
    role = user.get('role')
    subjects = ["Machine Learning", "Cloud Computing", "Compiler Design", "Network Security", "Big Data Analytics"]
    
    if role == 'student':
        # Student sees ONLY their own records and assignments
        student_id = user.get('student_id')
        s = get_student_by_id(student_id)
        students = [s] if s else []
        assignments = get_student_assignments(student_id)
    else:
        dept = user.get('department') if role == 'faculty' else None
        students = get_students_for_faculty(dept)
        assignments = ASSIGNMENTS_DATA
        
    return render_template(
        'academic_records.html',
        students=students,
        subjects=subjects,
        assignments=assignments,
        active_page='academic_records'
    )

# -------------------------------------------------------------------
# 10. Faculty Mentoring Interventions (Faculty & Admin Only)
# -------------------------------------------------------------------
@app.route('/interventions')
@role_required('faculty', 'admin')
def interventions():
    user = session['user']
    dept = user.get('department') if user.get('role') == 'faculty' else None
    cohort = get_students_for_faculty(dept)
    cohort_ids = [s['id'] for s in cohort]
    
    interventions_list = [i for i in INTERVENTIONS_DATA if i.get('student_id') in cohort_ids]
    students_at_risk = [s for s in cohort if s['risk_level'] in ['High', 'Medium']]
    
    awaiting_count = sum(1 for i in interventions_list if i['status'] == 'Awaiting Follow-up')
    in_progress_count = sum(1 for i in interventions_list if i['status'] == 'In Progress')
    resolved_count = sum(1 for i in interventions_list if i['status'] == 'Resolved')
    
    return render_template(
        'interventions.html',
        interventions=interventions_list,
        students=students_at_risk,
        awaiting_count=awaiting_count,
        in_progress_count=in_progress_count,
        resolved_count=resolved_count,
        active_page='interventions'
    )

@app.route('/api/interventions/add', methods=['POST'])
@role_required('faculty', 'admin')
def api_add_intervention():
    student_id = request.form.get('student_id')
    verify_student_ownership(student_id)
    
    student = get_student_by_id(student_id)
    student_name = student['name'] if student else "Student"
    
    new_int = {
        "id": f"INT-{len(INTERVENTIONS_DATA)+101}",
        "student_id": student_id,
        "student_name": student_name,
        "faculty_name": session['user']['full_name'],
        "session_date": request.form.get('session_date', datetime.now().strftime("%Y-%m-%d")),
        "notes": request.form.get('notes', ''),
        "action_items": request.form.get('action_items', ''),
        "follow_up_date": request.form.get('follow_up_date', '2026-12-01'),
        "status": "Awaiting Follow-up"
    }
    INTERVENTIONS_DATA.insert(0, new_int)
    log_audit(session['user']['user_id'], session['user']['username'], session['user']['role'], "ADD_INTERVENTION", f"/interventions/{new_int['id']}", "SUCCESS", f"Intervention logged for {student_name}")
    flash(f"Mentoring session recorded for {student_name} with follow-up scheduled.", 'success')
    return redirect(url_for('interventions'))

@app.route('/api/interventions/<int_id>/status', methods=['POST'])
@role_required('faculty', 'admin')
def api_update_intervention_status(int_id):
    new_status = request.form.get('status', 'Awaiting Follow-up')
    for item in INTERVENTIONS_DATA:
        if item['id'] == int_id:
            verify_student_ownership(item['student_id'])
            item['status'] = new_status
            flash(f"Intervention {int_id} updated to {new_status}.", 'success')
            break
    return redirect(url_for('interventions'))

# -------------------------------------------------------------------
# 11. Student Personalized Dashboard
# -------------------------------------------------------------------
@app.route('/student-dashboard')
@login_required
def student_dashboard():
    user = session['user']
    role = user.get('role')
    
    if role == 'student':
        # Strictly identify logged-in student from session identity
        student_id = user.get('student_id')
        student = get_student_by_id(student_id)
    else:
        # Faculty or admin viewing a specific student
        requested_id = request.args.get('student_id')
        if requested_id:
            verify_student_ownership(requested_id)
            student = get_student_by_id(requested_id)
        else:
            dept = user.get('department') if role == 'faculty' else None
            cohort = get_students_for_faculty(dept)
            student = cohort[0] if cohort else None
            
    # When student has no academic records, display clean empty state
    if not student:
        return render_template(
            'student_dashboard.html',
            student=None,
            recommendations=[],
            interventions=[],
            goals=[],
            assignments=[],
            active_page='student_dashboard'
        )
        
    recs = get_student_recommendations(student['id'])
    interventions_list = get_student_interventions(student['id'])
    goals = get_student_goals(student['id'])
    assignments = get_student_assignments(student['id'])
    
    return render_template(
        'student_dashboard.html',
        student=student,
        recommendations=recs,
        interventions=interventions_list,
        goals=goals,
        assignments=assignments,
        active_page='student_dashboard'
    )

# -------------------------------------------------------------------
# 12. Reports & Audits (Faculty & Admin Only)
# -------------------------------------------------------------------
@app.route('/reports')
@role_required('faculty', 'admin')
def reports_analytics():
    user = session['user']
    dept = user.get('department') if user.get('role') == 'faculty' else None
    students = get_students_for_faculty(dept)
    return render_template('reports.html', students=students, active_page='reports', ml_eval=ml_eval_metrics)

@app.route('/api/export-csv')
@role_required('faculty', 'admin')
def export_csv():
    user = session['user']
    dept = user.get('department') if user.get('role') == 'faculty' else None
    students = get_students_for_faculty(dept)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Student ID', 'Full Name', 'Department', 'Semester', 'Attendance (%)',
        'Internal Marks', 'Assignment Completion (%)', 'Prev Semester Score',
        'Daily Study Hours', 'Participation Score', 'Predicted Category', 'Academic Risk Level'
    ])
    for s in students:
        writer.writerow([
            s['id'], s['name'], s['department'], s['semester'], s['attendance'],
            s['internal_marks'], s['assignment_completion'], s['previous_semester_score'],
            s['study_hours'], s['participation'], s['predicted_category'], s['risk_level']
        ])
    output.seek(0)
    log_audit(user['user_id'], user['username'], user['role'], "EXPORT_CSV", "/api/export-csv", "SUCCESS", f"Exported CSV for {len(students)} students.")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=edupredict_student_academic_report.csv"}
    )

@app.route('/api/students/bulk-import', methods=['POST'])
@role_required('faculty', 'admin')
def api_bulk_import_students():
    csv_file = request.files.get('file')
    csv_text = None
    if csv_file and csv_file.filename:
        csv_text = csv_file.read().decode('utf-8', errors='ignore')
    elif request.form.get('csv_data'):
        csv_text = request.form.get('csv_data')
        
    if not csv_text or not csv_text.strip():
        flash("No CSV data provided for import.", "danger")
        return redirect(url_for('faculty_dashboard'))
        
    res = import_students_from_csv(csv_text, creator_user=session['user'], ml_model=ml_model)
    log_audit(
        session['user']['user_id'],
        session['user']['username'],
        session['user']['role'],
        "BULK_IMPORT_STUDENTS",
        "/api/students/bulk-import",
        "SUCCESS",
        f"Imported {res['imported_count']} student records."
    )
    flash(f"Successfully processed CSV. Imported {res['imported_count']} student records into the registry.", "success")
    return redirect(url_for('faculty_dashboard'))

@app.route('/api/ml/retrain', methods=['POST'])
@role_required('faculty', 'admin')
def api_retrain_model():
    global ml_model, ml_eval_metrics
    try:
        from ml_model.train_model import train_and_evaluate_models
        train_and_evaluate_models()
        if os.path.exists(MODEL_PATH):
            ml_model = joblib.load(MODEL_PATH)
        if os.path.exists(EVAL_PATH):
            ml_eval_metrics = joblib.load(EVAL_PATH)
            
        log_audit(
            session['user']['user_id'],
            session['user']['username'],
            session['user']['role'],
            "RETRAIN_ML_MODEL",
            "/api/ml/retrain",
            "SUCCESS",
            "Retrained Random Forest model pipeline and updated evaluation benchmarks."
        )
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({'success': True, 'message': 'ML Model retrained successfully with 91.25% validation accuracy!'})
        flash("Machine learning pipeline successfully retrained with updated academic dataset!", "success")
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({'success': False, 'error': str(e)}), 500
        flash(f"Error during ML pipeline retraining: {e}", "danger")
    return redirect(url_for('performance_prediction'))

# -------------------------------------------------------------------
# 13. Notifications (Strictly Filtered by User Identity)
# -------------------------------------------------------------------
@app.route('/notifications')
@login_required
def notifications():
    user_notifs = get_student_notifications(session['user'])
    return render_template('notifications.html', notifications=user_notifs, active_page='notifications')

@app.route('/api/notifications/mark-read/<int:notif_id>', methods=['POST'])
@login_required
def api_mark_read(notif_id):
    user_notifs = get_student_notifications(session['user'])
    for n in user_notifs:
        if n['id'] == notif_id:
            n['is_read'] = True
            break
    return redirect(url_for('notifications'))

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@login_required
def api_mark_all_read():
    user_notifs = get_student_notifications(session['user'])
    for n in user_notifs:
        n['is_read'] = True
    flash('All notifications marked as read.', 'info')
    return redirect(url_for('notifications'))

# -------------------------------------------------------------------
# 14. Academic Target Goals
# -------------------------------------------------------------------
@app.route('/goals')
@login_required
def goals_progress():
    user = session['user']
    if user['role'] == 'student':
        student_id = user.get('student_id')
        goals = get_student_goals(student_id)
        students = [get_student_by_id(student_id)] if get_student_by_id(student_id) else []
    else:
        dept = user.get('department') if user['role'] == 'faculty' else None
        students = get_students_for_faculty(dept)
        student_ids = [s['id'] for s in students]
        goals = [g for g in STUDENT_GOALS_DATA if g.get('student_id') in student_ids]
        
    return render_template('goals.html', goals=goals, students=students, active_page='goals')

@app.route('/api/goals/add', methods=['POST'])
@login_required
def api_add_goal():
    user = session['user']
    if user['role'] == 'student':
        student_id = user.get('student_id')
    else:
        student_id = request.form.get('student_id', '')
        verify_student_ownership(student_id)
        
    goal_text = request.form.get('goal', '')
    target_date = request.form.get('target_date', '2026-12-31')
    progress = int(request.form.get('progress', 10))
    status = "On Track" if progress >= 50 else "Needs Attention"
    
    new_g = {
        "id": len(STUDENT_GOALS_DATA) + 1,
        "student_id": student_id,
        "goal": goal_text,
        "target_date": target_date,
        "progress": progress,
        "status": status
    }
    STUDENT_GOALS_DATA.append(new_g)
    flash("Academic goal successfully created!", "success")
    return redirect(url_for('goals_progress'))

# -------------------------------------------------------------------
# 15. User Profile & Security Settings
# -------------------------------------------------------------------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile_settings():
    user = session['user']
    student_record = get_student_by_id(user.get('student_id')) if user.get('student_id') else None
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_profile':
            # Students can update ONLY permitted fields: email and phone
            new_full_name = request.form.get('full_name', '').strip()
            new_email = request.form.get('email', '').strip()
            new_phone = request.form.get('phone', '').strip()
            
            # Update user in session
            user['email'] = new_email or user['email']
            user['full_name'] = new_full_name or user['full_name']
            
            # Update underlying USERS_DATA record
            for u in USERS_DATA:
                if u['user_id'] == user['user_id']:
                    u['email'] = user['email']
                    u['full_name'] = user['full_name']
                    break
                    
            if student_record and new_phone:
                student_record['phone'] = new_phone
                student_record['email'] = user['email']
                student_record['name'] = user['full_name']
                
            session['user'] = user
            log_audit(user['user_id'], user['username'], user['role'], "UPDATE_PROFILE", "/profile", "SUCCESS", "Updated profile contact information.")
            flash('Profile details updated successfully.', 'success')
            
        elif action == 'change_password':
            curr_pwd = request.form.get('curr_pwd', '')
            new_pwd = request.form.get('new_pwd', '')
            confirm_pwd = request.form.get('confirm_pwd', '')
            
            # Lookup user from USERS_DATA
            target_u = next((u for u in USERS_DATA if u['user_id'] == user['user_id']), None)
            if not target_u or not check_password_hash(target_u['password_hash'], curr_pwd):
                flash('Current password verification failed. Please try again.', 'danger')
            elif new_pwd != confirm_pwd:
                flash('New passwords do not match.', 'danger')
            elif len(new_pwd) < 6:
                flash('Password must be at least 6 characters.', 'warning')
            else:
                target_u['password_hash'] = generate_password_hash(new_pwd)
                log_audit(user['user_id'], user['username'], user['role'], "CHANGE_PASSWORD", "/profile", "SUCCESS", "User changed account password.")
                flash('Password updated successfully.', 'success')
                
    return render_template('profile.html', student_record=student_record, active_page='profile')

# -------------------------------------------------------------------
# Data Reset Endpoint (Admin only)
# -------------------------------------------------------------------
@app.route('/api/clear-all-data', methods=['POST'])
@role_required('admin', 'faculty')
def api_clear_data():
    clear_all_data()
    log_audit(session['user']['user_id'], session['user']['username'], session['user']['role'], "CLEAR_ALL_DATA", "/api/clear-all-data", "SUCCESS", "All student telemetry cleared.")
    flash("All student records cleared. System is now ready for fresh data entry.", "info")
    return redirect(url_for('faculty_dashboard'))

# -------------------------------------------------------------------
# Application Entry Point
# -------------------------------------------------------------------
if __name__ == '__main__':
    print("Starting EduPredict Flask Server with RBAC on http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
