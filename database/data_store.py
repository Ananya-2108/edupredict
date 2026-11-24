"""
EduPredict - Secure Dynamic Data Store & Relational Identity Model
Features Role-Based Access Control (RBAC), password hashing,
data isolation, audit logging, and relationship mapping.
"""
import copy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# 1. User Identity Store (Authentication & Authorization)
# Passwords hashed with Werkzeug pbkdf2:sha256
USERS_DATA = [
    {
        "user_id": 1,
        "username": "faculty_ananya",
        "password_hash": generate_password_hash("password123"),
        "role": "faculty",
        "full_name": "Dr. Ananya Roy",
        "email": "ananya.faculty@college.edu",
        "department": "Computer Science & Engineering",
        "student_id": None,
        "created_at": "2026-09-01 09:00:00"
    },
    {
        "user_id": 2,
        "username": "faculty_rajesh",
        "password_hash": generate_password_hash("password123"),
        "role": "faculty",
        "full_name": "Dr. Rajesh Kumar",
        "email": "rajesh.faculty@college.edu",
        "department": "Electronics & Communication",
        "student_id": None,
        "created_at": "2026-09-01 09:15:00"
    },
    {
        "user_id": 3,
        "username": "STU1001",
        "password_hash": generate_password_hash("password123"),
        "role": "student",
        "full_name": "Aarav Sharma",
        "email": "aarav.sharma@college.edu",
        "department": "Computer Science & Engineering",
        "student_id": "STU1001",
        "created_at": "2026-09-05 10:00:00"
    },
    {
        "user_id": 4,
        "username": "STU1002",
        "password_hash": generate_password_hash("password123"),
        "role": "student",
        "full_name": "Priya Nair",
        "email": "priya.nair@college.edu",
        "department": "Computer Science & Engineering",
        "student_id": "STU1002",
        "created_at": "2026-09-05 10:15:00"
    },
    {
        "user_id": 5,
        "username": "STU1003",
        "password_hash": generate_password_hash("password123"),
        "role": "student",
        "full_name": "Rohit Verma",
        "email": "rohit.verma@college.edu",
        "department": "Computer Science & Engineering",
        "student_id": "STU1003",
        "created_at": "2026-11-20 11:00:00"
    },
    {
        "user_id": 99,
        "username": "admin",
        "password_hash": generate_password_hash("password123"),
        "role": "admin",
        "full_name": "Chief Academic Administrator",
        "email": "admin@edupredict.edu",
        "department": "Administration",
        "student_id": None,
        "created_at": "2026-08-15 08:00:00"
    }
]

# 2. Student Academic Telemetry (Linked to Users via user_id and student_id)
# Student A (STU1001) - High Performer (Attendance 91%, Internals 86)
# Student B (STU1002) - At-Risk Student (Attendance 58%, Internals 44)
# Student C (STU1003) - Clean/Empty state student profile (No marks/telemetry yet)
STUDENTS_DATA = [
    {
        "id": "STU1001",
        "user_id": 3,
        "name": "Aarav Sharma",
        "email": "aarav.sharma@college.edu",
        "phone": "+91 98765 43210",
        "gender": "Male",
        "department": "Computer Science & Engineering",
        "academic_year": "2026-2027",
        "semester": 7,
        "avatar": "https://api.dicebear.com/7.x/initials/svg?seed=Aarav%20Sharma",
        "attendance": 91.5,
        "internal_marks": 86.0,
        "assignment_completion": 94.0,
        "previous_semester_score": 88.5,
        "study_hours": 6.5,
        "participation": 8.5,
        "predicted_category": "High Performer",
        "risk_level": "Low",
        "confidence": 93.4,
        "prob_at_risk": 2.1,
        "prob_avg": 14.5,
        "prob_high": 83.4,
        "risk_indicators": ["Good academic discipline across all evaluated metrics"],
        "weak_areas": ["No critical vulnerabilities detected"],
        "strengths": [
            "Regular Classroom Attendance & Punctuality (91.5%)",
            "Solid theoretical & assessment fundamentals (86/100)",
            "Consistent coursework and lab submissions (94%)",
            "Disciplined daily self-study routine (6.5 hrs/day)"
        ],
        "attendance_trend": [88, 90, 92, 91, 93, 91.5],
        "subject_scores": {
            "Machine Learning": 88.0,
            "Cloud Computing": 89.0,
            "Compiler Design": 82.0,
            "Network Security": 87.0,
            "Big Data Analytics": 84.0
        },
        "history": [
            {"semester": "Sem 4", "gpa": 8.4, "attendance": 89.0},
            {"semester": "Sem 5", "gpa": 8.6, "attendance": 90.5},
            {"semester": "Sem 6", "gpa": 8.8, "attendance": 91.0}
        ]
    },
    {
        "id": "STU1002",
        "user_id": 4,
        "name": "Priya Nair",
        "email": "priya.nair@college.edu",
        "phone": "+91 98123 45678",
        "gender": "Female",
        "department": "Computer Science & Engineering",
        "academic_year": "2026-2027",
        "semester": 7,
        "avatar": "https://api.dicebear.com/7.x/initials/svg?seed=Priya%20Nair",
        "attendance": 58.0,
        "internal_marks": 44.0,
        "assignment_completion": 50.0,
        "previous_semester_score": 56.0,
        "study_hours": 2.0,
        "participation": 3.5,
        "predicted_category": "At-Risk Student",
        "risk_level": "High",
        "confidence": 91.8,
        "prob_at_risk": 84.2,
        "prob_avg": 13.1,
        "prob_high": 2.7,
        "risk_indicators": [
            "Low Attendance (58.0%) - Below required 75% limit",
            "Failing/Weak Internal Marks (44.0/100)",
            "Assignment Deficit (50.0% completed)",
            "Low Independent Study Volume (2.0 hrs/day)"
        ],
        "weak_areas": [
            "Attendance irregularity needs remediation",
            "Sub-par exam & test performance",
            "Assignment backlogs",
            "Low daily self-study hours"
        ],
        "strengths": ["Showing foundational engagement in Big Data lab"],
        "attendance_trend": [68, 64, 60, 59, 57, 58.0],
        "subject_scores": {
            "Machine Learning": 42.0,
            "Cloud Computing": 48.0,
            "Compiler Design": 38.0,
            "Network Security": 45.0,
            "Big Data Analytics": 47.0
        },
        "history": [
            {"semester": "Sem 4", "gpa": 6.8, "attendance": 72.0},
            {"semester": "Sem 5", "gpa": 6.1, "attendance": 65.0},
            {"semester": "Sem 6", "gpa": 5.6, "attendance": 60.0}
        ]
    }
]

# 3. Recommendations (Strictly tied to student_id)
RECOMMENDATIONS_DATA = [
    {
        "id": "REC-0101",
        "student_id": "STU1001",
        "student_name": "Aarav Sharma",
        "category": "Advanced Enrichment",
        "description": "Engage in research paper publication on distributed Transformer training and competitive coding hackathons.",
        "priority": "Low",
        "status": "In Progress",
        "date": "2026-10-15"
    },
    {
        "id": "REC-0102",
        "student_id": "STU1002",
        "student_name": "Priya Nair",
        "category": "Remedial Coaching",
        "description": "Attend supervised Compiler Design & Machine Learning revision blocks; submit outstanding coursework modules.",
        "priority": "High",
        "status": "Pending",
        "date": "2026-10-18"
    }
]

# 4. Faculty Interventions (Faculty-only sensitive mentoring logs)
INTERVENTIONS_DATA = [
    {
        "id": "INT-101",
        "student_id": "STU1002",
        "student_name": "Priya Nair",
        "faculty_name": "Dr. Ananya Roy",
        "session_date": "2026-10-20",
        "notes": "Discussed attendance deficit and health difficulties during midterms. Agreed on medical documentation and weekly makeup tasks.",
        "action_items": "Submit pending ML assignments 2 & 3 by Friday; attend daily morning revision slot.",
        "follow_up_date": "2026-11-10",
        "status": "Awaiting Follow-up"
    }
]

# 5. Notifications (Isolated by recipient: student_id or username or role)
NOTIFICATIONS_DATA = [
    {
        "id": 1,
        "recipient_username": "STU1001",
        "recipient_role": "student",
        "student_id": "STU1001",
        "title": "Hackathon Nomination",
        "message": "You have been shortlisted for the Inter-College Cloud Computing Hackathon based on your GPA.",
        "type": "success",
        "time": "2 hours ago",
        "is_read": False
    },
    {
        "id": 2,
        "recipient_username": "STU1002",
        "recipient_role": "student",
        "student_id": "STU1002",
        "title": "Low Attendance Alert",
        "message": "Your current attendance (58%) is critically below the 75% department threshold. Meet Dr. Ananya Roy.",
        "type": "alert",
        "time": "1 day ago",
        "is_read": False
    },
    {
        "id": 3,
        "recipient_username": "faculty_ananya",
        "recipient_role": "faculty",
        "student_id": None,
        "title": "At-Risk Cohort Notice",
        "message": "Priya Nair (STU1002) requires faculty intervention follow-up this week.",
        "type": "warning",
        "time": "3 hours ago",
        "is_read": False
    }
]

# 6. Assignments Data (Isolated per student)
ASSIGNMENTS_DATA = [
    {
        "id": 1,
        "student_id": "STU1001",
        "title": "Deep Learning Hyperparameter Optimization",
        "subject": "Machine Learning",
        "due_date": "2026-11-28",
        "status": "Completed",
        "score": 95
    },
    {
        "id": 2,
        "student_id": "STU1001",
        "title": "Lexical Analyzer in Lex/Yacc",
        "subject": "Compiler Design",
        "due_date": "2026-12-02",
        "status": "In Progress",
        "score": None
    },
    {
        "id": 3,
        "student_id": "STU1002",
        "title": "Linear Regression Lab Submission",
        "subject": "Machine Learning",
        "due_date": "2026-10-25",
        "status": "Overdue",
        "score": 40
    },
    {
        "id": 4,
        "student_id": "STU1002",
        "title": "Syntax Directed Translation Exercises",
        "subject": "Compiler Design",
        "due_date": "2026-11-30",
        "status": "Pending",
        "score": None
    }
]

# 7. Student Academic Goals (Isolated per student)
STUDENT_GOALS_DATA = [
    {
        "id": 1,
        "student_id": "STU1001",
        "goal": "Achieve Semester GPA >= 9.0 in Semester 7",
        "target_date": "2026-12-15",
        "progress": 85,
        "status": "On Track"
    },
    {
        "id": 2,
        "student_id": "STU1001",
        "goal": "Complete AWS Solutions Architect Associate Certification",
        "target_date": "2026-12-30",
        "progress": 60,
        "status": "On Track"
    },
    {
        "id": 3,
        "student_id": "STU1002",
        "goal": "Recover attendance to 75% before semester exams",
        "target_date": "2026-12-10",
        "progress": 35,
        "status": "Needs Attention"
    }
]

# 8. Activity and Security Audit Log
AUDIT_LOGS_DATA = [
    {
        "id": 1,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": 99,
        "username": "admin",
        "role": "admin",
        "action": "SYSTEM_INIT",
        "resource": "database",
        "status": "SUCCESS",
        "details": "Initialized secure RBAC identity data store with multi-student isolation."
    }
]

# ===================================================================
# Authentication & User Management Helpers
# ===================================================================

def authenticate_user(username, password):
    """
    Validates user credentials against password hash.
    Returns user dict without password hash if valid, else None.
    """
    username_clean = (username or "").strip().lower()
    for u in USERS_DATA:
        if (
            u["username"].lower() == username_clean or
            u["email"].lower() == username_clean or
            (u["student_id"] and u["student_id"].lower() == username_clean)
        ):
            if check_password_hash(u["password_hash"], password):
                user_copy = copy.deepcopy(u)
                del user_copy["password_hash"]
                return user_copy
    return None

def get_user_by_id(user_id):
    for u in USERS_DATA:
        if u["user_id"] == user_id:
            user_copy = copy.deepcopy(u)
            if "password_hash" in user_copy:
                del user_copy["password_hash"]
            return user_copy
    return None

def get_user_by_username(username):
    for u in USERS_DATA:
        if u["username"].lower() == username.lower():
            user_copy = copy.deepcopy(u)
            if "password_hash" in user_copy:
                del user_copy["password_hash"]
            return user_copy
    return None

def register_user(username, password, role, full_name, email, department="Computer Science & Engineering", student_id=None):
    """Creates a new user record with hashed password."""
    if get_user_by_username(username):
        return None, "Username already exists"
    
    new_user_id = max([u["user_id"] for u in USERS_DATA] + [0]) + 1
    new_user = {
        "user_id": new_user_id,
        "username": username.strip(),
        "password_hash": generate_password_hash(password),
        "role": role,
        "full_name": full_name.strip(),
        "email": email.strip(),
        "department": department,
        "student_id": student_id,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    USERS_DATA.append(new_user)
    
    log_audit(new_user_id, username, role, "USER_REGISTER", f"/users/{new_user_id}", "SUCCESS", f"Registered new {role} user.")
    
    user_copy = copy.deepcopy(new_user)
    del user_copy["password_hash"]
    return user_copy, None

def log_audit(user_id, username, role, action, resource, status, details=""):
    """Appends an immutable security audit event."""
    entry = {
        "id": len(AUDIT_LOGS_DATA) + 1,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user_id,
        "username": username or "anonymous",
        "role": role or "unauthenticated",
        "action": action,
        "resource": resource,
        "status": status,
        "details": details
    }
    AUDIT_LOGS_DATA.insert(0, entry)
    return entry

# ===================================================================
# Student Data Isolation Query Helpers
# ===================================================================

def get_all_students(department=None):
    """Returns all student records (for authorized admin/faculty), optionally filtered by department."""
    if not department:
        return STUDENTS_DATA
    return [s for s in STUDENTS_DATA if s.get("department", "").strip().lower() == department.strip().lower()]

def get_students_for_faculty(department=None):
    """Returns students filtered by the faculty member's authorized department."""
    if not department:
        return STUDENTS_DATA
    return [s for s in STUDENTS_DATA if s.get("department", "").strip().lower() == department.strip().lower()]

def get_student_by_id(student_id):
    """Finds a student by Student ID (e.g. STU1001)."""
    if not student_id:
        return None
    for s in STUDENTS_DATA:
        if s["id"].lower() == student_id.lower():
            return s
    return None

def get_student_by_user_id(user_id):
    """Resolves student record from the authenticated user's user_id."""
    for s in STUDENTS_DATA:
        if s.get("user_id") == user_id:
            return s
    return None

def get_student_notifications(user):
    """Filters notifications strictly for the authenticated user/student."""
    role = user.get("role")
    username = user.get("username", "").lower()
    student_id = (user.get("student_id") or "").lower()
    
    filtered = []
    for n in NOTIFICATIONS_DATA:
        n_recip = (n.get("recipient_username") or "").lower()
        n_student_id = (n.get("student_id") or "").lower()
        n_role = n.get("recipient_role")
        
        if role == "student":
            if n_student_id == student_id or n_recip == username:
                filtered.append(n)
        elif role == "faculty":
            if n_role == "faculty" and (n_recip == username or not n_recip):
                filtered.append(n)
        elif role == "admin":
            filtered.append(n)
    return filtered

def get_student_recommendations(student_id):
    """Filters recommendations exclusively for the given student_id."""
    return [r for r in RECOMMENDATIONS_DATA if r.get("student_id", "").lower() == (student_id or "").lower()]

def get_student_assignments(student_id):
    """Filters assignments exclusively for the given student_id."""
    return [a for a in ASSIGNMENTS_DATA if a.get("student_id", "").lower() == (student_id or "").lower()]

def get_student_goals(student_id):
    """Filters goals exclusively for the given student_id."""
    return [g for g in STUDENT_GOALS_DATA if g.get("student_id", "").lower() == (student_id or "").lower()]

def get_student_interventions(student_id):
    """Filters interventions for a specific student."""
    return [i for i in INTERVENTIONS_DATA if i.get("student_id", "").lower() == (student_id or "").lower()]

# ===================================================================
# ML Computation & Student CRUD
# ===================================================================

def compute_ml_performance(att, int_m, asg, prev_score, study_h, part, ml_model=None):
    """Computes performance category, risk level, confidence, and metrics."""
    predicted_category = None
    confidence = 85.0
    prob_at_risk, prob_avg, prob_high = 15.0, 70.0, 15.0

    if ml_model is not None:
        try:
            import pandas as pd
            import numpy as np
            df = pd.DataFrame([[att, int_m, asg, prev_score, study_h, part]],
                              columns=['attendance', 'internal_marks', 'assignment_completion', 'previous_semester_score', 'study_hours', 'participation'])
            pred_class = ml_model.predict(df)[0]
            probabilities = ml_model.predict_proba(df)[0]
            class_map = {0: 'At-Risk Student', 1: 'Average Performer', 2: 'High Performer'}
            predicted_category = class_map.get(pred_class, 'Average Performer')
            confidence = round(float(np.max(probabilities)) * 100, 1)
            prob_at_risk = round(float(probabilities[0]) * 100, 1)
            prob_avg = round(float(probabilities[1]) * 100, 1)
            prob_high = round(float(probabilities[2]) * 100, 1)
        except Exception:
            predicted_category = None

    if not predicted_category:
        score = (att * 0.25 + int_m * 0.35 + asg * 0.15 + prev_score * 0.15 + study_h * 1.5 + part * 0.8)
        if score < 63 or att < 65 or int_m < 50:
            predicted_category = "At-Risk Student"
            confidence = 88.5
            prob_at_risk, prob_avg, prob_high = 78.0, 18.0, 4.0
        elif score >= 80:
            predicted_category = "High Performer"
            confidence = 92.4
            prob_at_risk, prob_avg, prob_high = 3.0, 12.0, 85.0
        else:
            predicted_category = "Average Performer"
            confidence = 85.0
            prob_at_risk, prob_avg, prob_high = 15.0, 72.0, 13.0

    if predicted_category == 'At-Risk Student':
        risk_level = 'High' if (att < 60 or int_m < 42) else 'Medium'
    elif predicted_category == 'Average Performer':
        risk_level = 'Medium' if att < 75 else 'Low'
    else:
        risk_level = 'Low'

    indicators = []
    if att < 75: indicators.append(f"Low Attendance ({att}%) - Below required 75% limit")
    if int_m < 50: indicators.append(f"Failing/Weak Internal Marks ({int_m}/100)")
    if asg < 70: indicators.append(f"Assignment Deficit ({asg}% completed)")
    if study_h < 3.0: indicators.append(f"Low Independent Study Volume ({study_h} hrs/day)")
    if not indicators: indicators.append("Good academic discipline across all evaluated metrics")

    strengths = []
    weak_areas = []
    if att >= 80: strengths.append("Regular Classroom Attendance & Punctuality")
    else: weak_areas.append("Attendance irregularity needs remediation")

    if int_m >= 75: strengths.append("Solid theoretical & assessment fundamentals")
    else: weak_areas.append("Sub-par exam & test performance")

    if asg >= 80: strengths.append("Consistent coursework and lab submissions")
    else: weak_areas.append("Assignment backlogs")

    if study_h >= 4.5: strengths.append("Disciplined daily self-study routine")
    else: weak_areas.append("Low daily self-study hours")

    return {
        "predicted_category": predicted_category,
        "risk_level": risk_level,
        "confidence": confidence,
        "prob_at_risk": prob_at_risk,
        "prob_avg": prob_avg,
        "prob_high": prob_high,
        "risk_indicators": indicators,
        "strengths": strengths if strengths else ["Showing foundational engagement"],
        "weak_areas": weak_areas if weak_areas else ["No critical vulnerabilities detected"]
    }

def add_student(data, ml_model=None, creator_user=None):
    att = float(data.get("attendance", 75))
    int_m = float(data.get("internal_marks", 70))
    asg = float(data.get("assignment_completion", 75))
    prev_score = float(data.get("previous_semester_score", 70))
    study_h = float(data.get("study_hours", 4.0))
    part = float(data.get("participation", 6.0))

    ml_result = compute_ml_performance(att, int_m, asg, prev_score, study_h, part, ml_model)

    new_id = data.get("id") or f"STU{1001 + len(STUDENTS_DATA)}"
    student_name = data.get("name", "Student").strip()
    student_email = data.get("email", f"{new_id.lower()}@college.edu").strip()

    subject_scores = {
        "Machine Learning": int_m,
        "Cloud Computing": max(30, min(100, int_m + 3)),
        "Compiler Design": max(30, min(100, int_m - 4)),
        "Network Security": max(30, min(100, int_m + 1)),
        "Big Data Analytics": max(30, min(100, int_m - 2))
    }

    # Automatically create user account for student if non-existent
    user_id = data.get("user_id")
    if not user_id:
        existing_u = get_user_by_username(new_id)
        if existing_u:
            user_id = existing_u["user_id"]
        else:
            new_u, _ = register_user(
                username=new_id,
                password="password123",
                role="student",
                full_name=student_name,
                email=student_email,
                department=data.get("department", "Computer Science & Engineering"),
                student_id=new_id
            )
            user_id = new_u["user_id"]

    new_student = {
        "id": new_id,
        "user_id": user_id,
        "name": student_name,
        "email": student_email,
        "phone": data.get("phone", "+91 90000 00000"),
        "gender": data.get("gender", "Other"),
        "department": data.get("department", "Computer Science & Engineering"),
        "academic_year": data.get("academic_year", "2026-2027"),
        "semester": int(data.get("semester", 7)),
        "avatar": f"https://api.dicebear.com/7.x/initials/svg?seed={student_name}",
        "attendance": att,
        "internal_marks": int_m,
        "assignment_completion": asg,
        "previous_semester_score": prev_score,
        "study_hours": study_h,
        "participation": part,
        "predicted_category": ml_result["predicted_category"],
        "risk_level": ml_result["risk_level"],
        "confidence": ml_result["confidence"],
        "prob_at_risk": ml_result["prob_at_risk"],
        "prob_avg": ml_result["prob_avg"],
        "prob_high": ml_result["prob_high"],
        "risk_indicators": ml_result["risk_indicators"],
        "weak_areas": ml_result["weak_areas"],
        "strengths": ml_result["strengths"],
        "attendance_trend": [max(40, att - 4), max(40, att - 2), att, max(40, att + 1), max(40, att - 1), att],
        "subject_scores": subject_scores,
        "history": [
            {"semester": f"Sem {int(data.get('semester', 7)) - 1}", "gpa": round(prev_score / 10.0, 1), "attendance": att}
        ]
    }
    STUDENTS_DATA.append(new_student)

    # Initial recommendations
    rec_id = f"REC-0{len(RECOMMENDATIONS_DATA) + 1}"
    rec_cat = "Remedial Coaching" if ml_result["risk_level"] in ["High", "Medium"] else "Advanced Enrichment"
    rec_desc = "Attend targeted review sessions in core subjects." if ml_result["risk_level"] in ["High", "Medium"] else "Engage in competitive coding hackathons."
    RECOMMENDATIONS_DATA.insert(0, {
        "id": rec_id,
        "student_id": new_id,
        "student_name": student_name,
        "category": rec_cat,
        "description": rec_desc,
        "priority": "High" if ml_result["risk_level"] == "High" else "Medium",
        "status": "Pending",
        "date": datetime.now().strftime("%Y-%m-%d")
    })

    # Student personal notification
    NOTIFICATIONS_DATA.insert(0, {
        "id": len(NOTIFICATIONS_DATA) + 1,
        "recipient_username": new_id,
        "recipient_role": "student",
        "student_id": new_id,
        "title": "Welcome to EduPredict",
        "message": f"Your academic profile ({new_id}) has been created with {new_student['predicted_category']} status.",
        "type": "info",
        "time": "Just now",
        "is_read": False
    })

    if creator_user:
        log_audit(
            creator_user.get("user_id"),
            creator_user.get("username"),
            creator_user.get("role"),
            "ADD_STUDENT",
            f"/students/{new_id}",
            "SUCCESS",
            f"Added student {student_name} ({new_id})"
        )

    return new_student

def update_student(student_id, data, ml_model=None, updater_user=None):
    s = get_student_by_id(student_id)
    if not s:
        return None
    for k in ["name", "email", "phone", "gender", "department", "semester", "attendance", "internal_marks", "assignment_completion", "previous_semester_score", "study_hours", "participation"]:
        if k in data and data[k] != '':
            if k in ["attendance", "internal_marks", "assignment_completion", "previous_semester_score", "study_hours", "participation"]:
                s[k] = float(data[k])
            elif k == "semester":
                s[k] = int(data[k])
            else:
                s[k] = data[k]

    ml_res = compute_ml_performance(
        s["attendance"], s["internal_marks"], s["assignment_completion"],
        s["previous_semester_score"], s["study_hours"], s["participation"], ml_model
    )
    s["predicted_category"] = ml_res["predicted_category"]
    s["risk_level"] = ml_res["risk_level"]
    s["confidence"] = ml_res["confidence"]
    s["prob_at_risk"] = ml_res["prob_at_risk"]
    s["prob_avg"] = ml_res["prob_avg"]
    s["prob_high"] = ml_res["prob_high"]
    s["risk_indicators"] = ml_res["risk_indicators"]
    s["weak_areas"] = ml_res["weak_areas"]
    s["strengths"] = ml_res["strengths"]

    if updater_user:
        log_audit(
            updater_user.get("user_id"),
            updater_user.get("username"),
            updater_user.get("role"),
            "UPDATE_STUDENT",
            f"/students/{student_id}",
            "SUCCESS",
            f"Updated academic metrics for {s['name']}"
        )
    return s

def delete_student(student_id, deleter_user=None):
    global STUDENTS_DATA, RECOMMENDATIONS_DATA, INTERVENTIONS_DATA, STUDENT_GOALS_DATA, ASSIGNMENTS_DATA
    STUDENTS_DATA = [s for s in STUDENTS_DATA if s["id"] != student_id]
    RECOMMENDATIONS_DATA = [r for r in RECOMMENDATIONS_DATA if r.get("student_id") != student_id]
    INTERVENTIONS_DATA = [i for i in INTERVENTIONS_DATA if i.get("student_id") != student_id]
    STUDENT_GOALS_DATA = [g for g in STUDENT_GOALS_DATA if g.get("student_id") != student_id]
    ASSIGNMENTS_DATA = [a for a in ASSIGNMENTS_DATA if a.get("student_id") != student_id]

    if deleter_user:
        log_audit(
            deleter_user.get("user_id"),
            deleter_user.get("username"),
            deleter_user.get("role"),
            "DELETE_STUDENT",
            f"/students/{student_id}",
            "SUCCESS",
            f"Removed student record {student_id}"
        )
    return True

def clear_all_data():
    """Reset the application back to fresh blank state (preserves admin user)."""
    global STUDENTS_DATA, RECOMMENDATIONS_DATA, INTERVENTIONS_DATA, NOTIFICATIONS_DATA, ASSIGNMENTS_DATA, STUDENT_GOALS_DATA, PREDICTIONS_HISTORY, STUDY_PLANS_DATA, ACADEMIC_RECORDS_DATA
    STUDENTS_DATA.clear()
    RECOMMENDATIONS_DATA.clear()
    INTERVENTIONS_DATA.clear()
    NOTIFICATIONS_DATA.clear()
    ASSIGNMENTS_DATA.clear()
    STUDENT_GOALS_DATA.clear()
    PREDICTIONS_HISTORY.clear()
    STUDY_PLANS_DATA.clear()
    ACADEMIC_RECORDS_DATA.clear()

# ===================================================================
# Enterprise SaaS Extensions: Explainable AI, Study Planner, CSV Import
# ===================================================================

FEATURE_IMPORTANCES = [
    {"feature": "Internal Assessment Marks", "weight": 0.32, "pct": 32},
    {"feature": "Attendance Rate", "weight": 0.28, "pct": 28},
    {"feature": "Previous Semester Score", "weight": 0.16, "pct": 16},
    {"feature": "Assignment Completion", "weight": 0.14, "pct": 14},
    {"feature": "Daily Study Hours", "weight": 0.06, "pct": 6},
    {"feature": "Classroom Participation", "weight": 0.04, "pct": 4}
]

PREDICTIONS_HISTORY = [
    {
        "id": 1,
        "timestamp": "2026-11-24 14:30:00",
        "student_name": "Aarav Sharma",
        "student_id": "STU1001",
        "attendance": 91.5,
        "internal_marks": 86.0,
        "assignment_completion": 94.0,
        "previous_semester_score": 88.5,
        "study_hours": 6.5,
        "participation": 8.5,
        "predicted_category": "High Performer",
        "confidence": 93.4,
        "risk_level": "Low",
        "model_version": "RandomForest_v1.2"
    },
    {
        "id": 2,
        "timestamp": "2026-11-24 15:10:00",
        "student_name": "Priya Nair",
        "student_id": "STU1002",
        "attendance": 58.0,
        "internal_marks": 44.0,
        "assignment_completion": 50.0,
        "previous_semester_score": 56.0,
        "study_hours": 2.0,
        "participation": 3.5,
        "predicted_category": "At-Risk Student",
        "confidence": 91.8,
        "risk_level": "High",
        "model_version": "RandomForest_v1.2"
    }
]

STUDY_PLANS_DATA = [
    {
        "id": 1,
        "student_id": "STU1001",
        "day": "Monday",
        "subject": "Machine Learning",
        "topic": "Transformer Attention Mechanisms & Self-Attention",
        "duration_hrs": 2.0,
        "duration_hours": 2.0,
        "completed": True,
        "status": "Completed"
    },
    {
        "id": 2,
        "student_id": "STU1001",
        "day": "Wednesday",
        "subject": "Cloud Computing",
        "topic": "Kubernetes Cluster Ingress & Helm Deployments",
        "duration_hrs": 2.5,
        "duration_hours": 2.5,
        "completed": True,
        "status": "Completed"
    },
    {
        "id": 3,
        "student_id": "STU1001",
        "day": "Friday",
        "subject": "Compiler Design",
        "topic": "LR(1) Parsing Table Construction Algorithms",
        "duration_hrs": 2.0,
        "duration_hours": 2.0,
        "completed": False,
        "status": "In Progress"
    },
    {
        "id": 4,
        "student_id": "STU1002",
        "day": "Tuesday",
        "subject": "Compiler Design Remedial",
        "topic": "Context-Free Grammars & Ambiguity Removal",
        "duration_hrs": 1.5,
        "duration_hours": 1.5,
        "completed": False,
        "status": "In Progress"
    },
    {
        "id": 5,
        "student_id": "STU1002",
        "day": "Thursday",
        "subject": "Machine Learning Lab Makeup",
        "topic": "Backpropagation Calculus & Gradient Descent Drills",
        "duration_hrs": 2.0,
        "duration_hours": 2.0,
        "completed": False,
        "status": "Pending"
    }
]

def compute_explainable_factors(*args, **kwargs):
    """
    Explainable AI (XAI) feature attribution engine.
    Calculates positive and negative feature contribution deltas vs baseline cohort averages.
    Accepts either a dictionary of inputs or individual numeric values.
    """
    if len(args) == 1 and isinstance(args[0], dict):
        d = args[0]
        att = float(d.get('attendance', 75.0))
        int_m = float(d.get('internal_marks', 65.0))
        asg = float(d.get('assignment_completion', 75.0))
        prev_score = float(d.get('previous_semester_score', 70.0))
        study_h = float(d.get('study_hours', 4.0))
        part = float(d.get('participation', 6.0))
    elif len(args) >= 6:
        att, int_m, asg, prev_score, study_h, part = [float(x) for x in args[:6]]
    else:
        att = float(kwargs.get('att', kwargs.get('attendance', 75.0)))
        int_m = float(kwargs.get('int_m', kwargs.get('internal_marks', 65.0)))
        asg = float(kwargs.get('asg', kwargs.get('assignment_completion', 75.0)))
        prev_score = float(kwargs.get('prev_score', kwargs.get('previous_semester_score', 70.0)))
        study_h = float(kwargs.get('study_h', kwargs.get('study_hours', 4.0)))
        part = float(kwargs.get('part', kwargs.get('participation', 6.0)))

    baselines = {
        'attendance': (75.0, 0.28, "Attendance Rate", "%"),
        'internal_marks': (65.0, 0.32, "Internal Assessment Marks", "/100"),
        'previous_semester_score': (70.0, 0.16, "Previous Semester Score", "%"),
        'assignment_completion': (75.0, 0.14, "Assignment Completion Track", "%"),
        'study_hours': (4.0, 0.06, "Daily Independent Study", " hrs/day"),
        'participation': (6.0, 0.04, "Classroom Discussion Participation", "/10")
    }

    current_values = {
        'attendance': att,
        'internal_marks': int_m,
        'previous_semester_score': prev_score,
        'assignment_completion': asg,
        'study_hours': study_h,
        'participation': part
    }

    contributions = []
    for key, (baseline_val, weight, label, unit) in baselines.items():
        val = current_values[key]
        delta = val - baseline_val
        impact_pts = round(delta * weight, 1)
        impact_type = "Positive" if impact_pts >= 0 else "Negative"

        contributions.append({
            "factor": label,
            "feature": key,
            "label": label,
            "value": f"{val}{unit}",
            "baseline": f"{baseline_val}{unit}",
            "importance": round(weight * 100, 1),
            "impact": impact_type,
            "impact_pts": impact_pts,
            "attribution": f"{'+' if impact_pts >= 0 else ''}{impact_pts:+.1f}%",
            "desc": f"{label} is {val}{unit} (vs {baseline_val}{unit} baseline).",
            "explanation": f"{label} is {val}{unit} ({'+' if delta > 0 else ''}{round(delta, 1)} vs {baseline_val}{unit} baseline), contributing {impact_pts:+.1f} points."
        })

    contributions.sort(key=lambda x: abs(x["impact_pts"]), reverse=True)
    return contributions

def record_prediction_history(*args, **kwargs):
    """Appends to prediction audit log history."""
    if len(args) == 1 and isinstance(args[0], dict):
        d = args[0]
        student_name = d.get('student_name', 'Evaluated Student')
        student_id = d.get('student_id', '')
        att = d.get('attendance', 75)
        int_m = d.get('internal_marks', 70)
        asg = d.get('assignment_completion', 75)
        prev_score = d.get('previous_score', d.get('previous_semester_score', 70))
        study_h = d.get('study_hours', 4)
        part = d.get('participation', 6)
        predicted_cat = d.get('predicted_category', 'Average Performer')
        confidence = d.get('confidence', 90)
        risk_level = d.get('risk_level', 'Low')
    elif len(args) >= 11:
        student_name, student_id, att, int_m, asg, prev_score, study_h, part, predicted_cat, confidence, risk_level = args[:11]
    else:
        student_name = kwargs.get('student_name', 'Evaluated Student')
        student_id = kwargs.get('student_id', '')
        att = kwargs.get('attendance', kwargs.get('att', 75))
        int_m = kwargs.get('internal_marks', kwargs.get('int_m', 70))
        asg = kwargs.get('assignment_completion', kwargs.get('asg', 75))
        prev_score = kwargs.get('previous_semester_score', kwargs.get('prev_score', 70))
        study_h = kwargs.get('study_hours', kwargs.get('study_h', 4))
        part = kwargs.get('participation', kwargs.get('part', 6))
        predicted_cat = kwargs.get('predicted_category', 'Average Performer')
        confidence = kwargs.get('confidence', 90)
        risk_level = kwargs.get('risk_level', 'Low')

    new_entry = {
        "id": len(PREDICTIONS_HISTORY) + 1,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "student_name": student_name,
        "student_id": student_id,
        "attendance": att,
        "internal_marks": int_m,
        "assignment_completion": asg,
        "previous_semester_score": prev_score,
        "study_hours": study_h,
        "participation": part,
        "predicted_category": predicted_cat,
        "confidence": confidence,
        "risk_level": risk_level,
        "model_version": "RandomForest_v1.2"
    }
    PREDICTIONS_HISTORY.insert(0, new_entry)
    return new_entry

def get_student_study_plan(student_id):
    """Returns study plan items for a specific student."""
    return [p for p in STUDY_PLANS_DATA if p.get("student_id", "").lower() == (student_id or "").lower()]

def toggle_study_plan_task(arg1, arg2=None):
    """
    Toggles completion state of a student's study plan item.
    Handles both (task_id, student_id) and (student_id, task_id).
    """
    if isinstance(arg1, int):
        task_id = arg1
        student_id = arg2
    else:
        student_id = arg1
        task_id = arg2

    for p in STUDY_PLANS_DATA:
        if p["id"] == task_id:
            if student_id and p.get("student_id", "").lower() != student_id.lower():
                continue
            is_done = (p["status"] == "Completed" or p.get("completed", False))
            p["completed"] = not is_done
            p["status"] = "Completed" if p["completed"] else "In Progress"
            return p
    return None

def toggle_recommendation_status(rec_id, user=None):
    """Toggles recommendation status between 'In Progress' and 'Completed'."""
    role = user.get("role") if isinstance(user, dict) else None
    student_id = user.get("student_id") if isinstance(user, dict) else None
    for r in RECOMMENDATIONS_DATA:
        if r["id"] == rec_id:
            if role == "student" and student_id and r.get("student_id", "").lower() != student_id.lower():
                return None, "Unauthorized"
            new_status = "Completed" if r["status"] != "Completed" else "In Progress"
            r["status"] = new_status
            return r
    return None

class BulkImportResult(dict):
    def __getitem__(self, key):
        return super().__getitem__(key)
    def __iter__(self):
        yield self['imported_count']
        yield self['errors']

def import_students_from_csv(csv_content, department="Computer Science & Engineering", creator_user=None, ml_model=None):
    """Parses CSV text and adds student records."""
    imported_count = 0
    errors = []
    import csv
    import io
    
    reader = csv.DictReader(io.StringIO(csv_content.strip()))
    for row_num, row in enumerate(reader, start=2):
        try:
            name = row.get("name") or row.get("Full Name") or row.get("Student Name") or f"Student {row_num}"
            att = float(row.get("attendance") or row.get("Attendance (%)") or 75.0)
            int_m = float(row.get("internal_marks") or row.get("Internal Marks") or 70.0)
            asg = float(row.get("assignment_completion") or row.get("Assignment Completion (%)") or 75.0)
            prev = float(row.get("previous_semester_score") or row.get("Prev Semester Score") or 70.0)
            study = float(row.get("study_hours") or row.get("Daily Study Hours") or 4.0)
            part = float(row.get("participation") or row.get("Participation Score") or 6.0)
            dept = row.get("department") or department
            sem = int(row.get("semester") or 7)

            add_student({
                "name": name,
                "attendance": att,
                "internal_marks": int_m,
                "assignment_completion": asg,
                "previous_semester_score": prev,
                "study_hours": study,
                "participation": part,
                "department": dept,
                "semester": sem
            }, ml_model=ml_model, creator_user=creator_user)
            imported_count += 1
        except Exception as e:
            errors.append(f"Row {row_num}: {str(e)}")

    res = BulkImportResult({'imported_count': imported_count, 'errors': errors})
    return res


# ===================================================================
# Comprehensive Academic Management System (AMS)
# Models, Data Structures, and Business Logic
# ===================================================================

SUBJECTS_DATA = [
    # Semester 1
    {
        "subject_code": "CS101",
        "subject_name": "Engineering Mathematics I",
        "department": "Computer Science & Engineering",
        "semester": 1,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2026-2030",
        "section": "A",
        "faculty_id": "faculty_rajesh",
        "faculty_name": "Prof. Rajesh Kumar",
        "syllabus_progress": 100.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Differential Calculus", "completed": True},
            {"unit_number": 2, "title": "Linear Algebra & Matrices", "completed": True},
            {"unit_number": 3, "title": "Vector Calculus", "completed": True},
            {"unit_number": 4, "title": "Partial Differential Equations", "completed": True},
            {"unit_number": 5, "title": "Multiple Integrals", "completed": True}
        ]
    },
    {
        "subject_code": "CS102",
        "subject_name": "Problem Solving with C",
        "department": "Computer Science & Engineering",
        "semester": 1,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2026-2030",
        "section": "A",
        "faculty_id": "faculty_ananya",
        "faculty_name": "Prof. Ananya Sharma",
        "syllabus_progress": 100.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Introduction to Programming & C", "completed": True},
            {"unit_number": 2, "title": "Control Structures & Loops", "completed": True},
            {"unit_number": 3, "title": "Arrays & Strings", "completed": True},
            {"unit_number": 4, "title": "Functions & Pointers", "completed": True},
            {"unit_number": 5, "title": "Structures & File I/O", "completed": True}
        ]
    },

    # Semester 2
    {
        "subject_code": "CS201",
        "subject_name": "Engineering Mathematics II",
        "department": "Computer Science & Engineering",
        "semester": 2,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2025-2029",
        "section": "A",
        "faculty_id": "faculty_rajesh",
        "faculty_name": "Prof. Rajesh Kumar",
        "syllabus_progress": 100.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Laplace Transforms", "completed": True},
            {"unit_number": 2, "title": "Fourier Series", "completed": True},
            {"unit_number": 3, "title": "Complex Analysis", "completed": True},
            {"unit_number": 4, "title": "Numerical Methods", "completed": True},
            {"unit_number": 5, "title": "Probability Distributions", "completed": True}
        ]
    },
    {
        "subject_code": "CS202",
        "subject_name": "Data Structures & Algorithms",
        "department": "Computer Science & Engineering",
        "semester": 2,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2025-2029",
        "section": "A",
        "faculty_id": "faculty_ananya",
        "faculty_name": "Prof. Ananya Sharma",
        "syllabus_progress": 100.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Stacks & Queues", "completed": True},
            {"unit_number": 2, "title": "Linked Lists & Variants", "completed": True},
            {"unit_number": 3, "title": "Trees & Binary Search Trees", "completed": True},
            {"unit_number": 4, "title": "Graph Algorithms & Traversals", "completed": True},
            {"unit_number": 5, "title": "Hashing & Sorting Techniques", "completed": True}
        ]
    },

    # Semester 3
    {
        "subject_code": "CS301",
        "subject_name": "Object Oriented Programming (Java)",
        "department": "Computer Science & Engineering",
        "semester": 3,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2024-2028",
        "section": "A",
        "faculty_id": "faculty_ananya",
        "faculty_name": "Prof. Ananya Sharma",
        "syllabus_progress": 100.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Java Fundamentals & Classes", "completed": True},
            {"unit_number": 2, "title": "Inheritance & Polymorphism", "completed": True},
            {"unit_number": 3, "title": "Exception Handling & Packages", "completed": True},
            {"unit_number": 4, "title": "Multithreading & Synchronization", "completed": True},
            {"unit_number": 5, "title": "Generics & Collections Framework", "completed": True}
        ]
    },

    # Semester 4
    {
        "subject_code": "CS401",
        "subject_name": "Design & Analysis of Algorithms",
        "department": "Computer Science & Engineering",
        "semester": 4,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2024-2028",
        "section": "A",
        "faculty_id": "faculty_rajesh",
        "faculty_name": "Prof. Rajesh Kumar",
        "syllabus_progress": 100.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Asymptotic Analysis & Recurrences", "completed": True},
            {"unit_number": 2, "title": "Divide & Conquer Paradigm", "completed": True},
            {"unit_number": 3, "title": "Greedy Method & Spanning Trees", "completed": True},
            {"unit_number": 4, "title": "Dynamic Programming", "completed": True},
            {"unit_number": 5, "title": "Backtracking & NP-Completeness", "completed": True}
        ]
    },

    # Semester 5
    {
        "subject_code": "CS501",
        "subject_name": "Database Management Systems",
        "department": "Computer Science & Engineering",
        "semester": 5,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2023-2027",
        "section": "A",
        "faculty_id": "faculty_ananya",
        "faculty_name": "Prof. Ananya Sharma",
        "syllabus_progress": 100.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Relational Model & ER Diagrams", "completed": True},
            {"unit_number": 2, "title": "SQL & Relational Algebra", "completed": True},
            {"unit_number": 3, "title": "Normalization & Functional Dependencies", "completed": True},
            {"unit_number": 4, "title": "Transactions & Concurrency Control", "completed": True},
            {"unit_number": 5, "title": "Indexing, B-Trees & Storage", "completed": True}
        ]
    },

    # Semester 6
    {
        "subject_code": "CS601",
        "subject_name": "Software Engineering & Agile",
        "department": "Computer Science & Engineering",
        "semester": 6,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2023-2027",
        "section": "A",
        "faculty_id": "faculty_rajesh",
        "faculty_name": "Prof. Rajesh Kumar",
        "syllabus_progress": 100.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Software Development Life Cycles", "completed": True},
            {"unit_number": 2, "title": "Agile & Scrum Framework", "completed": True},
            {"unit_number": 3, "title": "Requirements Engineering & UML", "completed": True},
            {"unit_number": 4, "title": "Software Testing & QA", "completed": True},
            {"unit_number": 5, "title": "DevOps & CI/CD Pipelines", "completed": True}
        ]
    },

    # Semester 7 (Active Core Cohort)
    {
        "subject_code": "CS701",
        "subject_name": "Machine Learning",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2023-2027",
        "section": "A",
        "faculty_id": "faculty_ananya",
        "faculty_name": "Prof. Ananya Sharma",
        "syllabus_progress": 80.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Supervised Learning & Regression Models", "completed": True},
            {"unit_number": 2, "title": "Classification, Decision Trees & Random Forests", "completed": True},
            {"unit_number": 3, "title": "Support Vector Machines & Kernel Methods", "completed": True},
            {"unit_number": 4, "title": "Clustering & Dimensionality Reduction (PCA)", "completed": True},
            {"unit_number": 5, "title": "Neural Networks & Deep Learning Foundations", "completed": False}
        ]
    },
    {
        "subject_code": "CS702",
        "subject_name": "Cloud Computing",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2023-2027",
        "section": "A",
        "faculty_id": "faculty_ananya",
        "faculty_name": "Prof. Ananya Sharma",
        "syllabus_progress": 60.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Cloud Architecture & Service Models (IaaS, PaaS, SaaS)", "completed": True},
            {"unit_number": 2, "title": "Virtualization & Hypervisors", "completed": True},
            {"unit_number": 3, "title": "Containerization & Docker Orchestration", "completed": True},
            {"unit_number": 4, "title": "Kubernetes Cluster Management", "completed": False},
            {"unit_number": 5, "title": "Serverless Computing & Cloud Security", "completed": False}
        ]
    },
    {
        "subject_code": "CS703",
        "subject_name": "Compiler Design",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2023-2027",
        "section": "A",
        "faculty_id": "faculty_rajesh",
        "faculty_name": "Prof. Rajesh Kumar",
        "syllabus_progress": 80.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Lexical Analysis & Lex Tools", "completed": True},
            {"unit_number": 2, "title": "Syntax Analysis & LR Parsers", "completed": True},
            {"unit_number": 3, "title": "Syntax-Directed Translation", "completed": True},
            {"unit_number": 4, "title": "Intermediate Code Generation (3-Address Code)", "completed": True},
            {"unit_number": 5, "title": "Code Optimization & Target Code Generation", "completed": False}
        ]
    },
    {
        "subject_code": "CS704",
        "subject_name": "Network Security",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "credits": 3,
        "academic_year": "2026-2027",
        "batch": "2023-2027",
        "section": "A",
        "faculty_id": "faculty_rajesh",
        "faculty_name": "Prof. Rajesh Kumar",
        "syllabus_progress": 60.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Classical Cryptography & Symmetric Ciphers (AES/DES)", "completed": True},
            {"unit_number": 2, "title": "Public Key Cryptography & RSA", "completed": True},
            {"unit_number": 3, "title": "Hash Functions, HMAC & Digital Signatures", "completed": True},
            {"unit_number": 4, "title": "Network Authentication & Kerberos", "completed": False},
            {"unit_number": 5, "title": "Firewalls, Intrusion Detection & TLS Protocols", "completed": False}
        ]
    },
    {
        "subject_code": "CS705",
        "subject_name": "Big Data Analytics",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "credits": 3,
        "academic_year": "2026-2027",
        "batch": "2023-2027",
        "section": "A",
        "faculty_id": "faculty_ananya",
        "faculty_name": "Prof. Ananya Sharma",
        "syllabus_progress": 80.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Hadoop Architecture & HDFS Storage", "completed": True},
            {"unit_number": 2, "title": "MapReduce Distributed Processing", "completed": True},
            {"unit_number": 3, "title": "Apache Spark & Resilient Distributed Datasets", "completed": True},
            {"unit_number": 4, "title": "NoSQL Systems (MongoDB, Cassandra)", "completed": True},
            {"unit_number": 5, "title": "Streaming Data Pipelines with Apache Kafka", "completed": False}
        ]
    },
    # Electronics Department Active Semester 7
    {
        "subject_code": "EC701",
        "subject_name": "VLSI Design & Embedded Systems",
        "department": "Electronics & Communication",
        "semester": 7,
        "credits": 4,
        "academic_year": "2026-2027",
        "batch": "2023-2027",
        "section": "B",
        "faculty_id": "faculty_rajesh",
        "faculty_name": "Prof. Rajesh Kumar",
        "syllabus_progress": 60.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "CMOS Logic & Inverter Characteristics", "completed": True},
            {"unit_number": 2, "title": "MOSFET Fabrication & Layout Rules", "completed": True},
            {"unit_number": 3, "title": "Subsystem Design & Arithmetic Circuits", "completed": True},
            {"unit_number": 4, "title": "FPGA Architectures & Verilog HDL", "completed": False},
            {"unit_number": 5, "title": "Low Power VLSI Design", "completed": False}
        ]
    },

    # Semester 8
    {
        "subject_code": "CS801",
        "subject_name": "Major Project Work Phase II",
        "department": "Computer Science & Engineering",
        "semester": 8,
        "credits": 10,
        "academic_year": "2026-2027",
        "batch": "2023-2027",
        "section": "A",
        "faculty_id": "faculty_ananya",
        "faculty_name": "Prof. Ananya Sharma",
        "syllabus_progress": 20.0,
        "syllabus_topics": [
            {"unit_number": 1, "title": "Project Design Review & Architecture", "completed": True},
            {"unit_number": 2, "title": "Module Implementation & Unit Testing", "completed": False},
            {"unit_number": 3, "title": "System Integration & Validation", "completed": False},
            {"unit_number": 4, "title": "Performance Benchmarking & Evaluation", "completed": False},
            {"unit_number": 5, "title": "Final Project Thesis & Defense", "completed": False}
        ]
    }
]

ACADEMIC_RECORDS_DATA = [
    # STU1001 (Aarav Sharma - Sem 7 High Performer)
    {
        "id": "AR-1001-CS701",
        "student_id": "STU1001",
        "student_name": "Aarav Sharma",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "academic_year": "2026-2027",
        "subject_code": "CS701",
        "subject_name": "Machine Learning",
        "credits": 4,
        "internal_1": 24.0,
        "internal_2": 24.0,
        "assignment_marks": 10.0,
        "assignment_score": 10.0,
        "lab_marks": 15.0,
        "lab_score": 15.0,
        "exam_marks": 92.0,
        "semester_exam_score": 92.0,
        "total_marks": 91.6,
        "grade": "O",
        "grade_points": 10.0,
        "credits_earned": 4,
        "classes_conducted": 45,
        "classes_attended": 43,
        "attendance_pct": 95.6,
        "attendance_percentage": 95.6,
        "attendance_status": "Good Standing",
        "academic_risk": "Low"
    },
    {
        "id": "AR-1001-CS702",
        "student_id": "STU1001",
        "student_name": "Aarav Sharma",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "academic_year": "2026-2027",
        "subject_code": "CS702",
        "subject_name": "Cloud Computing",
        "credits": 4,
        "internal_1": 22.0,
        "internal_2": 23.0,
        "assignment_marks": 9.5,
        "assignment_score": 9.5,
        "lab_marks": 14.5,
        "lab_score": 14.5,
        "exam_marks": 88.0,
        "semester_exam_score": 88.0,
        "total_marks": 86.9,
        "grade": "A+",
        "grade_points": 9.0,
        "credits_earned": 4,
        "classes_conducted": 45,
        "classes_attended": 41,
        "attendance_pct": 91.1,
        "attendance_percentage": 91.1,
        "attendance_status": "Good Standing",
        "academic_risk": "Low"
    },
    {
        "id": "AR-1001-CS703",
        "student_id": "STU1001",
        "student_name": "Aarav Sharma",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "academic_year": "2026-2027",
        "subject_code": "CS703",
        "subject_name": "Compiler Design",
        "credits": 4,
        "internal_1": 21.0,
        "internal_2": 20.0,
        "assignment_marks": 9.0,
        "assignment_score": 9.0,
        "lab_marks": 14.0,
        "lab_score": 14.0,
        "exam_marks": 82.0,
        "semester_exam_score": 82.0,
        "total_marks": 78.1,
        "grade": "A",
        "grade_points": 8.0,
        "credits_earned": 4,
        "classes_conducted": 45,
        "classes_attended": 40,
        "attendance_pct": 88.9,
        "attendance_percentage": 88.9,
        "attendance_status": "Good Standing",
        "academic_risk": "Low"
    },
    {
        "id": "AR-1001-CS704",
        "student_id": "STU1001",
        "student_name": "Aarav Sharma",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "academic_year": "2026-2027",
        "subject_code": "CS704",
        "subject_name": "Network Security",
        "credits": 3,
        "internal_1": 20.0,
        "internal_2": 21.0,
        "assignment_marks": 9.0,
        "assignment_score": 9.0,
        "lab_marks": 13.5,
        "lab_score": 13.5,
        "exam_marks": 79.0,
        "semester_exam_score": 79.0,
        "total_marks": 76.7,
        "grade": "A",
        "grade_points": 8.0,
        "credits_earned": 3,
        "classes_conducted": 45,
        "classes_attended": 42,
        "attendance_pct": 93.3,
        "attendance_percentage": 93.3,
        "attendance_status": "Good Standing",
        "academic_risk": "Low"
    },
    {
        "id": "AR-1001-CS705",
        "student_id": "STU1001",
        "student_name": "Aarav Sharma",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "academic_year": "2026-2027",
        "subject_code": "CS705",
        "subject_name": "Big Data Analytics",
        "credits": 3,
        "internal_1": 23.0,
        "internal_2": 22.0,
        "assignment_marks": 10.0,
        "assignment_score": 10.0,
        "lab_marks": 14.5,
        "lab_score": 14.5,
        "exam_marks": 86.0,
        "semester_exam_score": 86.0,
        "total_marks": 82.8,
        "grade": "A+",
        "grade_points": 9.0,
        "credits_earned": 3,
        "classes_conducted": 45,
        "classes_attended": 41,
        "attendance_pct": 91.1,
        "attendance_percentage": 91.1,
        "attendance_status": "Good Standing",
        "academic_risk": "Low"
    },

    # STU1002 (Priya Nair - Sem 7 At-Risk / Critical Support)
    {
        "id": "AR-1002-CS701",
        "student_id": "STU1002",
        "student_name": "Priya Nair",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "academic_year": "2026-2027",
        "subject_code": "CS701",
        "subject_name": "Machine Learning",
        "credits": 4,
        "internal_1": 13.0,
        "internal_2": 14.0,
        "assignment_marks": 6.0,
        "assignment_score": 6.0,
        "lab_marks": 8.5,
        "lab_score": 8.5,
        "exam_marks": 52.0,
        "semester_exam_score": 52.0,
        "total_marks": 53.6,
        "grade": "B",
        "grade_points": 6.0,
        "credits_earned": 4,
        "classes_conducted": 45,
        "classes_attended": 28,
        "attendance_pct": 62.2,
        "attendance_percentage": 62.2,
        "attendance_status": "Critical Shortage",
        "academic_risk": "High"
    },
    {
        "id": "AR-1002-CS702",
        "student_id": "STU1002",
        "student_name": "Priya Nair",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "academic_year": "2026-2027",
        "subject_code": "CS702",
        "subject_name": "Cloud Computing",
        "credits": 4,
        "internal_1": 12.0,
        "internal_2": 13.0,
        "assignment_marks": 5.5,
        "assignment_score": 5.5,
        "lab_marks": 8.0,
        "lab_score": 8.0,
        "exam_marks": 54.0,
        "semester_exam_score": 54.0,
        "total_marks": 52.2,
        "grade": "B",
        "grade_points": 6.0,
        "credits_earned": 4,
        "classes_conducted": 45,
        "classes_attended": 27,
        "attendance_pct": 60.0,
        "attendance_percentage": 60.0,
        "attendance_status": "Critical Shortage",
        "academic_risk": "High"
    },
    {
        "id": "AR-1002-CS703",
        "student_id": "STU1002",
        "student_name": "Priya Nair",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "academic_year": "2026-2027",
        "subject_code": "CS703",
        "subject_name": "Compiler Design",
        "credits": 4,
        "internal_1": 8.0,
        "internal_2": 9.0,
        "assignment_marks": 4.5,
        "assignment_score": 4.5,
        "lab_marks": 6.0,
        "lab_score": 6.0,
        "exam_marks": 35.0,
        "semester_exam_score": 35.0,
        "total_marks": 39.5,
        "grade": "F",
        "grade_points": 0.0,
        "credits_earned": 0,
        "classes_conducted": 45,
        "classes_attended": 26,
        "attendance_pct": 57.8,
        "attendance_percentage": 57.8,
        "attendance_status": "Critical Shortage",
        "academic_risk": "High"
    },
    {
        "id": "AR-1002-CS704",
        "student_id": "STU1002",
        "student_name": "Priya Nair",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "academic_year": "2026-2027",
        "subject_code": "CS704",
        "subject_name": "Network Security",
        "credits": 3,
        "internal_1": 10.0,
        "internal_2": 11.0,
        "assignment_marks": 5.0,
        "assignment_score": 5.0,
        "lab_marks": 7.0,
        "lab_score": 7.0,
        "exam_marks": 48.0,
        "semester_exam_score": 48.0,
        "total_marks": 46.9,
        "grade": "C",
        "grade_points": 5.0,
        "credits_earned": 3,
        "classes_conducted": 45,
        "classes_attended": 28,
        "attendance_pct": 62.2,
        "attendance_percentage": 62.2,
        "attendance_status": "Critical Shortage",
        "academic_risk": "High"
    },
    {
        "id": "AR-1002-CS705",
        "student_id": "STU1002",
        "student_name": "Priya Nair",
        "department": "Computer Science & Engineering",
        "semester": 7,
        "academic_year": "2026-2027",
        "subject_code": "CS705",
        "subject_name": "Big Data Analytics",
        "credits": 3,
        "internal_1": 11.0,
        "internal_2": 10.0,
        "assignment_marks": 5.5,
        "assignment_score": 5.5,
        "lab_marks": 7.5,
        "lab_score": 7.5,
        "exam_marks": 49.0,
        "semester_exam_score": 49.0,
        "total_marks": 48.2,
        "grade": "C",
        "grade_points": 5.0,
        "credits_earned": 3,
        "classes_conducted": 45,
        "classes_attended": 26,
        "attendance_pct": 57.8,
        "attendance_percentage": 57.8,
        "attendance_status": "Critical Shortage",
        "academic_risk": "High"
    }
]


def calculate_grade_and_points(total_marks):
    """
    Standard university 10-point relative grading scale:
    O: 90-100 (10.0), A+: 80-89 (9.0), A: 70-79 (8.0),
    B+: 60-69 (7.0), B: 50-59 (6.0), C: 40-49 (5.0), F: <40 (0.0).
    """
    score = float(total_marks or 0.0)
    if score >= 90.0:
        return "O", 10.0
    elif score >= 80.0:
        return "A+", 9.0
    elif score >= 70.0:
        return "A", 8.0
    elif score >= 60.0:
        return "B+", 7.0
    elif score >= 50.0:
        return "B", 6.0
    elif score >= 40.0:
        return "C", 5.0
    else:
        return "F", 0.0


def get_all_subjects(department=None, semester=None):
    """
    Returns subjects filtered by department and/or semester.
    """
    results = copy.deepcopy(SUBJECTS_DATA)
    if department:
        results = [s for s in results if s.get('department', '').lower() == department.lower()]
    if semester:
        results = [s for s in results if int(s.get('semester', 0)) == int(semester)]
    return results


def get_subject_by_code(subject_code):
    """
    Finds a subject by its unique course code.
    """
    code_clean = (subject_code or '').strip().upper()
    for s in SUBJECTS_DATA:
        if s.get('subject_code', '').upper() == code_clean:
            return s
    return None


def add_subject(subject_dict):
    """
    Registers a new academic subject with validation against duplicate allocations.
    Automatically enlists standard syllabus units and initializes gradebook records.
    """
    code = (subject_dict.get('subject_code') or '').strip().upper()
    if not code:
        return None, "Subject code is mandatory."

    if get_subject_by_code(code):
        return None, f"Course code {code} is already allocated."

    name = (subject_dict.get('subject_name') or '').strip()
    dept = subject_dict.get('department') or "Computer Science & Engineering"
    sem = int(subject_dict.get('semester') or 7)
    credits = int(subject_dict.get('credits') or 4)
    ay = subject_dict.get('academic_year') or "2026-2027"
    batch = subject_dict.get('batch') or "2023-2027"
    section = subject_dict.get('section') or "A"
    faculty_id = subject_dict.get('faculty_id') or "faculty_ananya"
    faculty_name = subject_dict.get('faculty_name') or "Prof. Ananya Sharma"

    topics = [
        {"unit_number": 1, "title": f"Unit 1: Fundamentals of {name}", "completed": False},
        {"unit_number": 2, "title": f"Unit 2: Architecture & Analysis", "completed": False},
        {"unit_number": 3, "title": f"Unit 3: Core Paradigms & Methodologies", "completed": False},
        {"unit_number": 4, "title": f"Unit 4: Advanced Systems & Applications", "completed": False},
        {"unit_number": 5, "title": f"Unit 5: Industry Case Studies & Capstone", "completed": False}
    ]

    new_sub = {
        "subject_code": code,
        "subject_name": name,
        "department": dept,
        "semester": sem,
        "credits": credits,
        "academic_year": ay,
        "batch": batch,
        "section": section,
        "faculty_id": faculty_id,
        "faculty_name": faculty_name,
        "syllabus_progress": 0.0,
        "syllabus_topics": topics
    }
    SUBJECTS_DATA.append(new_sub)

    # Automatically enroll students in this department and semester
    dept_students = [s for s in STUDENTS_DATA if s.get('department') == dept and int(s.get('semester', 7)) == sem]
    for st in dept_students:
        rec_id = f"AR-{st['id']}-{code}"
        ACADEMIC_RECORDS_DATA.append({
            "id": rec_id,
            "student_id": st['id'],
            "student_name": st['name'],
            "department": dept,
            "semester": sem,
            "academic_year": ay,
            "subject_code": code,
            "subject_name": name,
            "credits": credits,
            "internal_1": 0.0,
            "internal_2": 0.0,
            "assignment_marks": 0.0,
            "assignment_score": 0.0,
            "lab_marks": 0.0,
            "lab_score": 0.0,
            "exam_marks": 0.0,
            "semester_exam_score": 0.0,
            "total_marks": 0.0,
            "grade": "F",
            "grade_points": 0.0,
            "credits_earned": 0,
            "classes_conducted": 45,
            "classes_attended": 0,
            "attendance_pct": 0.0,
            "attendance_percentage": 0.0,
            "attendance_status": "Critical Shortage",
            "academic_risk": "High"
        })

    return new_sub, None


def update_subject(subject_code, data):
    """
    Updates subject metadata.
    """
    sub = get_subject_by_code(subject_code)
    if not sub:
        return None

    if 'subject_name' in data and data['subject_name']:
        sub['subject_name'] = data['subject_name'].strip()
    if 'credits' in data:
        try:
            sub['credits'] = int(data['credits'])
        except (ValueError, TypeError):
            pass
    if 'semester' in data:
        try:
            sub['semester'] = int(data['semester'])
        except (ValueError, TypeError):
            pass
    if 'batch' in data:
        sub['batch'] = data['batch']
    if 'section' in data:
        sub['section'] = data['section']
    if 'faculty_name' in data:
        sub['faculty_name'] = data['faculty_name']

    return sub


def delete_subject(subject_code):
    """
    Removes a subject from allocation and cleans associated gradebook records.
    """
    global SUBJECTS_DATA, ACADEMIC_RECORDS_DATA
    code = (subject_code or '').strip().upper()
    SUBJECTS_DATA = [s for s in SUBJECTS_DATA if s.get('subject_code', '').upper() != code]
    ACADEMIC_RECORDS_DATA = [r for r in ACADEMIC_RECORDS_DATA if r.get('subject_code', '').upper() != code]
    return True


def update_syllabus_unit(subject_code, unit_number, completed):
    """
    Updates completion state of a syllabus unit and recalculates overall syllabus progress.
    """
    sub = get_subject_by_code(subject_code)
    if not sub:
        return None

    found = False
    for u in sub.get('syllabus_topics', []):
        if int(u.get('unit_number', 0)) == int(unit_number):
            u['completed'] = bool(completed)
            found = True
            break

    if not found:
        return None

    total_units = len(sub.get('syllabus_topics', []))
    done_units = sum(1 for u in sub.get('syllabus_topics', []) if u.get('completed'))
    sub['syllabus_progress'] = round((done_units / total_units) * 100.0, 1) if total_units > 0 else 0.0
    return sub


def get_academic_records(student_id=None, subject_code=None, department=None, semester=None):
    """
    Retrieves filtered academic assessment records.
    """
    records = copy.deepcopy(ACADEMIC_RECORDS_DATA)
    if student_id:
        records = [r for r in records if r.get('student_id', '').lower() == student_id.lower()]
    if subject_code:
        records = [r for r in records if r.get('subject_code', '').upper() == subject_code.upper()]
    if department:
        records = [r for r in records if r.get('department', '').lower() == department.lower()]
    if semester:
        records = [r for r in records if int(r.get('semester', 0)) == int(semester)]
    return records


def update_academic_record_marks(record_id_or_tuple=None, data=None, updater_user=None, **kwargs):
    """
    Updates student subject marks, recomputes total score, letter grade,
    grade points, credits earned, attendance percentage, and academic risk.
    """
    if data is None:
        data = kwargs
    elif kwargs:
        data = {**data, **kwargs}

    if record_id_or_tuple is None:
        rec_id = data.get('record_id')
        stu_id = data.get('student_id')
        sub_code = data.get('subject_code')
        if rec_id:
            record_id_or_tuple = rec_id
        elif stu_id and sub_code:
            record_id_or_tuple = (stu_id, sub_code)

    rec = None
    if isinstance(record_id_or_tuple, str):
        for r in ACADEMIC_RECORDS_DATA:
            if r.get('id') == record_id_or_tuple:
                rec = r
                break
    elif isinstance(record_id_or_tuple, (tuple, list)) and len(record_id_or_tuple) >= 2:
        stu_id, sub_code = record_id_or_tuple[:2]
        for r in ACADEMIC_RECORDS_DATA:
            if r.get('student_id', '').lower() == stu_id.lower() and r.get('subject_code', '').upper() == sub_code.upper():
                rec = r
                break

    if not rec:
        return None

    int_1 = float(data.get('internal_1', rec.get('internal_1', 0.0)))
    int_2 = float(data.get('internal_2', rec.get('internal_2', 0.0)))
    asg = float(data.get('assignment_score', data.get('assignment_marks', rec.get('assignment_marks', 0.0))))
    lab = float(data.get('lab_score', data.get('lab_marks', rec.get('lab_marks', 0.0))))
    exam = float(data.get('semester_exam_score', data.get('exam_marks', rec.get('exam_marks', 0.0))))
    conducted = int(data.get('classes_conducted', rec.get('classes_conducted', 45)))
    attended = int(data.get('classes_attended', rec.get('classes_attended', 35)))

    # Compute attendance
    att_pct = round((attended / conducted) * 100, 1) if conducted > 0 else 0.0
    if att_pct >= 75.0:
        att_status = "Good Standing"
    elif att_pct >= 65.0:
        att_status = "Borderline Warning"
    else:
        att_status = "Critical Shortage"

    # Compute weighted total marks (out of 100)
    # Internals: (int_1 + int_2) * 0.5 + Assignment + Lab + Exam * 0.3
    total_m = min(100.0, round(((int_1 + int_2) * 0.5) + asg + lab + (exam * 0.3), 1))
    grade, grade_pts = calculate_grade_and_points(total_m)
    credits = int(rec.get('credits', 4))
    credits_earned = credits if grade != 'F' else 0

    if grade == 'F' or att_pct < 65.0:
        risk = "High"
    elif grade in ['C', 'B'] or att_pct < 75.0:
        risk = "Medium"
    else:
        risk = "Low"

    rec['internal_1'] = int_1
    rec['internal_2'] = int_2
    rec['assignment_marks'] = asg
    rec['assignment_score'] = asg
    rec['lab_marks'] = lab
    rec['lab_score'] = lab
    rec['exam_marks'] = exam
    rec['semester_exam_score'] = exam
    rec['classes_conducted'] = conducted
    rec['classes_attended'] = attended
    rec['attendance_pct'] = att_pct
    rec['attendance_percentage'] = att_pct
    rec['attendance_status'] = att_status
    rec['total_marks'] = total_m
    rec['grade'] = grade
    rec['grade_points'] = grade_pts
    rec['credits_earned'] = credits_earned
    rec['academic_risk'] = risk

    # Synchronize student main record if active semester
    student = get_student_by_id(rec['student_id'])
    if student and int(student.get('semester', 7)) == int(rec.get('semester', 7)):
        if 'subject_scores' not in student or not isinstance(student['subject_scores'], dict):
            student['subject_scores'] = {}
        student['subject_scores'][rec['subject_name']] = total_m

    if updater_user:
        log_audit(
            updater_user.get("user_id"),
            updater_user.get("username"),
            updater_user.get("role"),
            "UPDATE_STUDENT_MARKS",
            f"/academic-records/{rec['id']}",
            "SUCCESS",
            f"Updated marks for {rec['student_name']} in {rec['subject_code']} (Total: {total_m}, Grade: {grade}, Att: {att_pct}%)"
        )

    return rec


def calculate_student_semester_summary(student_id, semester=None):
    """
    Computes registered credits, earned credits, weighted SGPA,
    average attendance, passed and failed subject counts, and institutional standing.
    """
    records = get_academic_records(student_id=student_id, semester=semester)
    if not records:
        return {
            "registered_credits": 0,
            "total_registered_credits": 0,
            "earned_credits": 0,
            "total_earned_credits": 0,
            "sgpa": 0.0,
            "avg_attendance": 0.0,
            "average_attendance": 0.0,
            "subjects_count": 0,
            "passed_count": 0,
            "failed_count": 0,
            "failed_courses": 0,
            "standing": "No Records",
            "records": []
        }

    total_reg = sum(int(r.get('credits', 0)) for r in records)
    total_earned = sum(int(r.get('credits_earned', 0)) for r in records)
    weighted_pts = sum(float(r.get('credits', 0)) * float(r.get('grade_points', 0.0)) for r in records)
    sgpa = round(weighted_pts / total_reg, 2) if total_reg > 0 else 0.0
    avg_att = round(sum(float(r.get('attendance_percentage', r.get('attendance_pct', 0.0))) for r in records) / len(records), 1)
    passed = sum(1 for r in records if r.get('grade') != 'F')
    failed = sum(1 for r in records if r.get('grade') == 'F')

    standing = "Good Standing"
    if failed > 0 and avg_att < 65.0:
        standing = "Critical Academic Review"
    elif failed > 0:
        standing = "Academic Warning (Backlog)"
    elif avg_att < 75.0:
        standing = "Attendance Shortage"

    return {
        "registered_credits": total_reg,
        "total_registered_credits": total_reg,
        "earned_credits": total_earned,
        "total_earned_credits": total_earned,
        "sgpa": sgpa,
        "avg_attendance": avg_att,
        "average_attendance": avg_att,
        "subjects_count": len(records),
        "passed_count": passed,
        "failed_count": failed,
        "failed_courses": failed,
        "standing": standing,
        "records": records
    }


def get_students_needing_academic_support(semester=None, department=None):
    """
    Identifies learners requiring targeted academic support:
    Students with course backlogs (Grade 'F'), failing total marks (<40), or attendance < 75%.
    """
    dept_students = get_all_students(department=department)
    support_list = []

    for s in dept_students:
        s_id = s.get('id')
        sem = semester or s.get('semester', 7)
        records = get_academic_records(student_id=s_id, semester=sem)
        if not records:
            continue

        reasons = []
        failing_courses = [r for r in records if r.get('grade') == 'F']
        low_att_courses = [r for r in records if float(r.get('attendance_percentage', r.get('attendance_pct', 0.0))) < 75.0]

        if failing_courses:
            reasons.append(f"Course Backlog in {len(failing_courses)} subjects: " + ", ".join(r['subject_code'] for r in failing_courses))

        if low_att_courses:
            reasons.append(f"Attendance Shortage in {len(low_att_courses)} subjects (&lt; 75%)")

        summary = calculate_student_semester_summary(s_id, sem)
        if summary.get('sgpa', 10.0) < 6.0:
            reasons.append(f"Low Semester GPA ({summary.get('sgpa'):.2f} / 10.0)")

        if reasons:
            support_list.append({
                "student_id": s_id,
                "student_name": s.get('name'),
                "department": s.get('department'),
                "semester": sem,
                "sgpa": summary.get('sgpa'),
                "average_attendance": summary.get('average_attendance'),
                "reasons": reasons,
                "standing": summary.get('standing')
            })

    return support_list
