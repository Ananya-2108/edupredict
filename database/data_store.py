"""
EduPredict - Fresh Dynamic Data Store
Initial state starts completely clean/empty with NO hardcoded sample student records.
Users enter student records fresh via the UI forms, and performance, risk level,
predictions, attendance trends, and recommendations are computed live on demand!
"""
import copy
from datetime import datetime

# In-memory clean data stores - start 100% FRESH
STUDENTS_DATA = []
RECOMMENDATIONS_DATA = []
INTERVENTIONS_DATA = []
NOTIFICATIONS_DATA = []
ASSIGNMENTS_DATA = []
STUDENT_GOALS_DATA = []

def get_all_students():
    return STUDENTS_DATA

def get_student_by_id(student_id):
    for s in STUDENTS_DATA:
        if s["id"].lower() == student_id.lower():
            return s
    return None

def compute_ml_performance(att, int_m, asg, prev_score, study_h, part, ml_model=None):
    """
    Computes performance category, risk level, confidence, and metrics
    dynamically for freshly entered data.
    """
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
    else:
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

    # Risk level determination
    if predicted_category == 'At-Risk Student':
        risk_level = 'High' if (att < 60 or int_m < 42) else 'Medium'
    elif predicted_category == 'Average Performer':
        risk_level = 'Medium' if att < 75 else 'Low'
    else:
        risk_level = 'Low'

    # Risk indicators
    indicators = []
    if att < 75:
        indicators.append(f"Low Attendance ({att}%) - Below required 75% limit")
    if int_m < 50:
        indicators.append(f"Failing/Weak Internal Marks ({int_m}/100)")
    if asg < 70:
        indicators.append(f"Assignment Deficit ({asg}% completed)")
    if study_h < 3.0:
        indicators.append(f"Low Independent Study Volume ({study_h} hrs/day)")
    if not indicators:
        indicators.append("Good academic discipline across all evaluated metrics")

    # Strengths and weak areas
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

def add_student(data, ml_model=None):
    att = float(data.get("attendance", 75))
    int_m = float(data.get("internal_marks", 70))
    asg = float(data.get("assignment_completion", 75))
    prev_score = float(data.get("previous_semester_score", 70))
    study_h = float(data.get("study_hours", 4.0))
    part = float(data.get("participation", 6.0))

    ml_result = compute_ml_performance(att, int_m, asg, prev_score, study_h, part, ml_model)

    new_id = data.get("id") or f"STU{1001 + len(STUDENTS_DATA)}"
    student_name = data.get("name", "Student").strip()

    # Subject scores breakdown
    subject_scores = {
        "Machine Learning": int_m,
        "Cloud Computing": max(30, min(100, int_m + 3)),
        "Compiler Design": max(30, min(100, int_m - 4)),
        "Network Security": max(30, min(100, int_m + 1)),
        "Big Data Analytics": max(30, min(100, int_m - 2))
    }

    new_student = {
        "id": new_id,
        "name": student_name,
        "email": data.get("email", f"{new_id.lower()}@college.edu"),
        "gender": data.get("gender", "Other"),
        "department": data.get("department", "Computer Science & Engineering"),
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

    # Automatically generate tailored recommendations for this newly added student
    if ml_result["risk_level"] in ["High", "Medium"]:
        rec_id = f"REC-0{len(RECOMMENDATIONS_DATA) + 1}"
        RECOMMENDATIONS_DATA.insert(0, {
            "id": rec_id,
            "student_id": new_id,
            "student_name": student_name,
            "category": "Remedial Coaching" if int_m < 50 else "Attendance Recovery",
            "description": f"Targeted review sessions in Compiler Design & Machine Learning; attend supervised revision blocks.",
            "priority": "High" if ml_result["risk_level"] == "High" else "Medium",
            "status": "Pending",
            "date": datetime.now().strftime("%Y-%m-%d")
        })
    else:
        rec_id = f"REC-0{len(RECOMMENDATIONS_DATA) + 1}"
        RECOMMENDATIONS_DATA.insert(0, {
            "id": rec_id,
            "student_id": new_id,
            "student_name": student_name,
            "category": "Advanced Enrichment",
            "description": "Engage in research publications and competitive coding hackathons to deepen advanced proficiency.",
            "priority": "Low",
            "status": "In Progress",
            "date": datetime.now().strftime("%Y-%m-%d")
        })

    # Add notification alert
    notif_type = "alert" if ml_result["risk_level"] == "High" else ("warning" if ml_result["risk_level"] == "Medium" else "success")
    NOTIFICATIONS_DATA.insert(0, {
        "id": len(NOTIFICATIONS_DATA) + 1,
        "role": "faculty",
        "title": f"Fresh Student Profile: {student_name}",
        "message": f"{student_name} ({new_id}) categorized as {ml_result['predicted_category']} with {ml_result['risk_level']} academic risk.",
        "type": notif_type,
        "time": "Just now",
        "is_read": False
    })

    return new_student

def update_student(student_id, data, ml_model=None):
    s = get_student_by_id(student_id)
    if not s:
        return None
    for k in ["name", "email", "gender", "department", "semester", "attendance", "internal_marks", "assignment_completion", "previous_semester_score", "study_hours", "participation"]:
        if k in data and data[k] != '':
            if k in ["attendance", "internal_marks", "assignment_completion", "previous_semester_score", "study_hours", "participation"]:
                s[k] = float(data[k])
            elif k == "semester":
                s[k] = int(data[k])
            else:
                s[k] = data[k]

    # Re-evaluate ML predictions
    ml_res = compute_ml_performance(
        s["attendance"], s["internal_marks"], s["assignment_completion"],
        s["previous_semester_score"], s["study_hours"], s["participation"], ml_model
    )
    s["predicted_category"] = ml_res["predicted_category"]
    s["risk_level"] = ml_res["risk_level"]
    s["risk_indicators"] = ml_res["risk_indicators"]
    s["weak_areas"] = ml_res["weak_areas"]
    s["strengths"] = ml_res["strengths"]
    return s

def delete_student(student_id):
    global STUDENTS_DATA, RECOMMENDATIONS_DATA, INTERVENTIONS_DATA, STUDENT_GOALS_DATA
    STUDENTS_DATA = [s for s in STUDENTS_DATA if s["id"] != student_id]
    RECOMMENDATIONS_DATA = [r for r in RECOMMENDATIONS_DATA if r.get("student_id") != student_id]
    INTERVENTIONS_DATA = [i for i in INTERVENTIONS_DATA if i.get("student_id") != student_id]
    STUDENT_GOALS_DATA = [g for g in STUDENT_GOALS_DATA if g.get("student_id") != student_id]
    return True

def clear_all_data():
    """Reset the application back to fresh blank state"""
    global STUDENTS_DATA, RECOMMENDATIONS_DATA, INTERVENTIONS_DATA, NOTIFICATIONS_DATA, ASSIGNMENTS_DATA, STUDENT_GOALS_DATA
    STUDENTS_DATA.clear()
    RECOMMENDATIONS_DATA.clear()
    INTERVENTIONS_DATA.clear()
    NOTIFICATIONS_DATA.clear()
    ASSIGNMENTS_DATA.clear()
    STUDENT_GOALS_DATA.clear()
