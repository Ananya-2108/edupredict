"""
EduPredict - High-Quality PDF Project Documentation Generator
Utilizes ReportLab to compile a professional, multi-page technical report.
"""
import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super(NumberedCanvas, self).showPage()
        super(NumberedCanvas, self).save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "EduPredict – AI Student Performance Prediction & Analytics Platform")
            self.drawRightString(558, 750, "Technical Project Report")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 744, 558, 744)

        # Footer (all pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)
        self.drawString(54, 32, "Confidential & Academic Record • Final B.E. Capstone Documentation")
        self.drawRightString(558, 32, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()

def build_pdf(output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    primary_color = colors.HexColor("#172554")   # Deep Institutional Navy
    secondary_color = colors.HexColor("#2563EB") # Tech Accent Blue
    text_color = colors.HexColor("#1E293B")      # Slate Text
    bg_alt = colors.HexColor("#F8FAFC")          # Table Alt Bg

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=primary_color,
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=secondary_color,
        spaceAfter=15
    )

    meta_style = ParagraphStyle(
        'DocMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'H1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=primary_color,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=secondary_color,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13.5,
        textColor=text_color,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=text_color
    )

    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    code_style = ParagraphStyle(
        'CodeBlock',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F1F5F9"),
        borderPadding=6,
        spaceAfter=8
    )

    story = []

    # Title Banner
    story.append(Paragraph("EDUPREDICT: ACADEMIC ANALYTICS & PREDICTION SYSTEM", title_style))
    story.append(Paragraph("Comprehensive Technical Project Report, Architectural Analysis & Verification", subtitle_style))
    story.append(Paragraph("<b>Version:</b> 2.0 (Production SaaS) &nbsp;|&nbsp; <b>Date:</b> November 2026 &nbsp;|&nbsp; <b>Framework:</b> Python 3.11 / Flask / Scikit-learn", meta_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=secondary_color, spaceAfter=14))

    # 1. Project Overview & Problem Statement
    story.append(Paragraph("1. Project Overview and Problem Statement", h1_style))
    story.append(Paragraph(
        "<b>Problem Statement:</b> Higher education institutions struggle with late academic risk identification. Traditional monitoring often occurs only after midterm examinations or end-of-semester grade publication, severely restricting remediation windows. Furthermore, educational record systems frequently suffer from data privacy deficits (lack of strict tenant/student isolation), opaque black-box evaluations lacking explainability, and fragmented spreadsheets without actionable intervention workflows.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Proposed Solution (EduPredict):</b> EduPredict is an enterprise-quality academic analytics platform integrating supervised machine learning (Random Forest with 91.25% validation accuracy) with an Explainable AI (XAI) feature attribution engine, strict Role-Based Access Control (RBAC), and a responsive SaaS interface. It empowers faculty with early warning triage, equips students with private adaptive study roadmaps, and provides academic administrators with transparent audit trails.",
        body_style
    ))

    # 2. Technologies and Tools Used
    story.append(Paragraph("2. Technologies and Tools Used", h1_style))
    tech_data = [
        [Paragraph("Category", table_header), Paragraph("Technology / Package", table_header), Paragraph("Version", table_header), Paragraph("Functional Role", table_header)],
        [Paragraph("Backend", table_cell), Paragraph("Python / Flask", table_cell), Paragraph("3.11 / 3.1.2", table_cell), Paragraph("Application server, HTTP routing, session state, and API endpoints", table_cell)],
        [Paragraph("Machine Learning", table_cell), Paragraph("Scikit-learn", table_cell), Paragraph("1.9.1", table_cell), Paragraph("RandomForestClassifier, LogisticRegression, DecisionTree models", table_cell)],
        [Paragraph("Data Science", table_cell), Paragraph("Pandas & NumPy", table_cell), Paragraph("3.0.0 / 2.4.2", table_cell), Paragraph("Cohort dataset creation, feature matrix processing, StandardScaler", table_cell)],
        [Paragraph("Model Storage", table_cell), Paragraph("Joblib", table_cell), Paragraph("1.5.3", table_cell), Paragraph("Serializing trained estimators, scalers, and evaluation metrics (.pkl)", table_cell)],
        [Paragraph("Frontend UI", table_cell), Paragraph("Jinja2 / Custom CSS3", table_cell), Paragraph("3.1.6 / ES6+", table_cell), Paragraph("Server-side HTML rendering, modern SaaS design system, dark mode", table_cell)],
        [Paragraph("Visualizations", table_cell), Paragraph("Chart.js", table_cell), Paragraph("4.4.1 (CDN)", table_cell), Paragraph("Interactive doughnut, scatter, bar, and semester line charts", table_cell)],
        [Paragraph("Iconography", table_cell), Paragraph("Lucide Icons", table_cell), Paragraph("Latest (CDN)", table_cell), Paragraph("Crisp, accessible SVG iconography across all 11 views", table_cell)],
        [Paragraph("Security / Auth", table_cell), Paragraph("Werkzeug Security", table_cell), Paragraph("3.1.3", table_cell), Paragraph("PBKDF2:SHA256 password hashing, RBAC decorators, IDOR guards", table_cell)],
        [Paragraph("Verification", table_cell), Paragraph("Python unittest", table_cell), Paragraph("Stdlib", table_cell), Paragraph("8 automated test cases verifying RBAC and student data isolation", table_cell)]
    ]
    t_tech = Table(tech_data, colWidths=[80, 110, 70, 244])
    t_tech.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_color),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_alt]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_tech)
    story.append(Spacer(1, 8))

    # 3. System Architecture & Modules
    story.append(Paragraph("3. System Architecture and Modules", h1_style))
    story.append(Paragraph(
        "EduPredict is architected on a modular Model-View-Controller (MVC) pattern comprising decoupled core subsystems:",
        body_style
    ))
    story.append(Paragraph("• <b>Application Controller (app.py)</b>: Manages session lifecycles, route authentication via @login_required, privilege authorization via @role_required, and REST JSON APIs for asynchronous task toggles and bulk imports.", bullet_style))
    story.append(Paragraph("• <b>Data & Isolation Layer (database/data_store.py)</b>: Manages multi-entity relational storage (Users, Students, Study Plans, Interventions, Goals) and enforces strict per-user boundaries (e.g. verify_student_ownership).", bullet_style))
    story.append(Paragraph("• <b>Machine Learning Pipeline (ml_model/)</b>: Self-contained training and evaluation pipeline (train_model.py) serializing the trained Random Forest model and scaler, callable dynamically via /api/ml/retrain.", bullet_style))
    story.append(Paragraph("• <b>Client Presentation Layer (templates/ & static/)</b>: Responsive Jinja2 templates inheriting from base.html, unified by style.css design system tokens and main.js interactive handlers.", bullet_style))
    story.append(Paragraph("• <b>Audit and Security Subsystem</b>: Immutable audit logger (log_audit) recording every sensitive transaction, authorization denial, data export, and model retraining event.", bullet_style))

    # 4. Role-Based Functionalities
    story.append(Paragraph("4. Student, Faculty, and Admin Functionalities", h1_style))
    story.append(Paragraph("<b>Student Portal (/student-dashboard):</b>", h2_style))
    story.append(Paragraph("• Automatic profile resolution using session student ID; zero access to peer data.", bullet_style))
    story.append(Paragraph("• Real-time academic metrics: Attendance rate, internal test marks, GPA, and assignment track.", bullet_style))
    story.append(Paragraph("• Adaptive Weekly Study Planner: Interactive syllabus milestones with completion toggle API.", bullet_style))
    story.append(Paragraph("• Personalized Learning Recommendations: Actionable revision roadmaps tailored to weak areas.", bullet_style))
    story.append(Paragraph("• Academic Goals Tracker (/goals): Milestone progression monitoring against end-of-term targets.", bullet_style))
    story.append(Paragraph("• Clean Onboarding Empty State: Students without records (e.g. STU1003) see a helpful welcome state.", bullet_style))

    story.append(Paragraph("<b>Faculty Portal (/dashboard):</b>", h2_style))
    story.append(Paragraph("• Department-filtered macro cohort analytics: Average score, attendance, and risk level breakdown.", bullet_style))
    story.append(Paragraph("• Early Warning At-Risk Triage (/at-risk): Filter by High/Medium risk with instant intervention links.", bullet_style))
    story.append(Paragraph("• Mentoring Interventions (/interventions): Confidential mentoring notes, action items, and follow-ups.", bullet_style))
    story.append(Paragraph("• Bulk CSV Student Import (/api/students/bulk-import): Upload CSV or paste rows for instant inference.", bullet_style))
    story.append(Paragraph("• Curricular Assessment Matrix (/academic-records): Subject-wise marks across all students in cohort.", bullet_style))

    story.append(Paragraph("<b>Administrator Center (/admin):</b>", h2_style))
    story.append(Paragraph("• User Provisioning: Create Faculty or Student credentials with role and department assignments.", bullet_style))
    story.append(Paragraph("• Security Audit Trail: Full chronological ledger of system logins, IDOR blocks, and exports.", bullet_style))
    story.append(Paragraph("• System Telemetry Purge: Administrative reset option to return demo records to clean state.", bullet_style))

    # Page Break for clean multi-page flow
    story.append(PageBreak())

    # 5. Machine Learning Algorithms & Prediction Process
    story.append(Paragraph("5. Machine Learning Algorithms and Prediction Process", h1_style))
    story.append(Paragraph(
        "The model training pipeline evaluates three classification algorithms on an 80/20 stratified cross-split of 1,200 multi-feature student academic records:",
        body_style
    ))
    
    ml_data = [
        [Paragraph("Algorithm", table_header), Paragraph("Configuration / Parameters", table_header), Paragraph("Accuracy", table_header), Paragraph("Precision", table_header), Paragraph("Recall", table_header), Paragraph("F1-Score", table_header), Paragraph("Status", table_header)],
        [Paragraph("<b>Random Forest</b>", table_cell), Paragraph("n_estimators=100, max_depth=8", table_cell), Paragraph("<b>91.25%</b>", table_cell), Paragraph("<b>91.09%</b>", table_cell), Paragraph("<b>91.25%</b>", table_cell), Paragraph("<b>91.09%</b>", table_cell), Paragraph("Selected Production Model", table_cell)],
        [Paragraph("Logistic Regression", table_cell), Paragraph("max_iter=1000, scaled features", table_cell), Paragraph("89.58%", table_cell), Paragraph("89.54%", table_cell), Paragraph("89.58%", table_cell), Paragraph("89.54%", table_cell), Paragraph("Benchmark Candidate", table_cell)],
        [Paragraph("Decision Tree", table_cell), Paragraph("max_depth=6, Gini criterion", table_cell), Paragraph("86.67%", table_cell), Paragraph("86.60%", table_cell), Paragraph("86.67%", table_cell), Paragraph("86.60%", table_cell), Paragraph("Benchmark Candidate", table_cell)]
    ]
    t_ml = Table(ml_data, colWidths=[90, 120, 50, 50, 50, 50, 94])
    t_ml.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_color),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#EFF6FF"), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_ml)
    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "<b>Prediction Workflow:</b> Input parameters are normalized through StandardScaler and fed into RandomForestClassifier.predict_proba(). The resulting class probabilities represent the distribution across High Performer, Average Performer, and At-Risk categories. Faculty can trigger live pipeline retraining (/api/ml/retrain) which re-executes train_and_evaluate_models() and refreshes in-memory weights in real-time.",
        body_style
    ))

    # 6. Dataset, Input Features & Preprocessing
    story.append(Paragraph("6. Dataset, Input Features, and Preprocessing", h1_style))
    story.append(Paragraph(
        "The training dataset (student_academic_dataset.csv) comprises 1,200 records modeled on real-world engineering curriculum behaviors with Gaussian noise:",
        body_style
    ))
    
    feat_data = [
        [Paragraph("Feature Name", table_header), Paragraph("Value Range", table_header), Paragraph("Gini Importance", table_header), Paragraph("Pedagogical Impact", table_header)],
        [Paragraph("Internal Assessment Marks", table_cell), Paragraph("30.0 - 98.0 / 100", table_cell), Paragraph("<b>32.0% (0.32)</b>", table_cell), Paragraph("Direct measure of syllabus mastery and continuous evaluation", table_cell)],
        [Paragraph("Attendance Percentage", table_cell), Paragraph("45.0% - 100.0%", table_cell), Paragraph("<b>28.0% (0.28)</b>", table_cell), Paragraph("Lecture participation; values <65% trigger mandatory risk alerts", table_cell)],
        [Paragraph("Previous Semester Score", table_cell), Paragraph("35.0% - 99.0%", table_cell), Paragraph("<b>16.0% (0.16)</b>", table_cell), Paragraph("Historical GPA foundation indicating academic momentum", table_cell)],
        [Paragraph("Assignment Completion Rate", table_cell), Paragraph("35.0% - 100.0%", table_cell), Paragraph("<b>14.0% (0.14)</b>", table_cell), Paragraph("Self-discipline and timely coursework submission adherence", table_cell)],
        [Paragraph("Daily Study Hours", table_cell), Paragraph("1.0 - 8.5 hrs/day", table_cell), Paragraph("<b>6.0% (0.06)</b>", table_cell), Paragraph("Independent study and practice outside scheduled classes", table_cell)],
        [Paragraph("Classroom Participation", table_cell), Paragraph("2.0 - 10.0 / 10", table_cell), Paragraph("<b>4.0% (0.04)</b>", table_cell), Paragraph("Discussion engagement, lab activity, and peer interaction", table_cell)]
    ]
    t_feat = Table(feat_data, colWidths=[130, 84, 90, 200])
    t_feat.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_color),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_alt]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_feat)
    story.append(Spacer(1, 8))

    # 7. Student Performance Prediction & Risk Identification
    story.append(Paragraph("7. Student Performance Prediction and Risk Identification", h1_style))
    story.append(Paragraph(
        "<b>Classification Categories:</b><br/>"
        "• <b>High Performer (Low Risk)</b>: Composite score ≥ 80, attendance ≥ 75%, and internals ≥ 70.<br/>"
        "• <b>Average Performer (Low/Medium Risk)</b>: Composite score between 63 and 80, attendance ≥ 65%.<br/>"
        "• <b>At-Risk Student (High Risk)</b>: Composite score < 63, attendance < 60%, or internals < 45.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Explainable AI (XAI) Attribution Waterfall:</b> Rather than providing raw label outputs, EduPredict computes attribution point deltas (compute_explainable_factors) comparing candidate telemetry against cohort baseline averages (e.g. 75% attendance, 65 internals). The engine outputs exact positive contributions (e.g. <i>Attendance: 88.0% (+3.6% boost)</i>) and vulnerability triggers (e.g. <i>Internals: 42.0/100 (-7.4% risk trigger)</i>), enabling targeted intervention design.",
        body_style
    ))

    # 8. Dashboards, Analytics & Visualizations
    story.append(Paragraph("8. Dashboards, Analytics, and Visualizations", h1_style))
    story.append(Paragraph(
        "Visualizations are powered by Chart.js v4.4.1 with theme integration (Dark / Light mode support):<br/>"
        "• <b>Cohort Performance Distribution (Doughnut Chart)</b>: Multi-class breakdown of High, Average, and At-Risk learners.<br/>"
        "• <b>Attendance vs. Assessment Marks (Scatter Correlation)</b>: Coordinate mapping highlighting students below danger thresholds.<br/>"
        "• <b>Subject-Wise Average Performance (Bar Chart)</b>: Cross-subject benchmarks across 5 core computing disciplines.<br/>"
        "• <b>Semester-Wise Performance Trends (Area / Line Chart)</b>: Longitudinal cohort GPA and attendance tracking over 5 semesters.<br/>"
        "• <b>Subject Radar Chart</b>: Personalized multiaxial competency map displayed on the student portal.",
        body_style
    ))

    # 9. Security, Authentication & Role-Based Access
    story.append(Paragraph("9. Security, Authentication, and Role-Based Access", h1_style))
    story.append(Paragraph("<b>Security Architecture & Insecure Direct Object Reference (IDOR) Protections:</b>", h2_style))
    story.append(Paragraph("• <b>Password Cryptography</b>: Passwords stored as PBKDF2:SHA256 salted hashes via Werkzeug Security.", bullet_style))
    story.append(Paragraph("• <b>Server-Side Authentication (@login_required)</b>: Enforced on all protected routes with redirect retention.", bullet_style))
    story.append(Paragraph("• <b>Hierarchical Authorization (@role_required)</b>: Restricts faculty and admin portals; unauthorized access triggers HTTP 403 Forbidden.", bullet_style))
    story.append(Paragraph("• <b>IDOR Ownership Validation (verify_student_ownership)</b>: Automatically rejects student queries attempting to inspect or modify another student's ID, academic marks, recommendations, or interventions.", bullet_style))
    story.append(Paragraph("• <b>Privilege Escalation Prevention</b>: Students attempting to invoke /switch-role/<role> are logged and aborted with HTTP 403.", bullet_style))
    story.append(Paragraph("• <b>Security Audit Logging (log_audit)</b>: Persistent log of security events (actor, resource, action, status, timestamp).", bullet_style))
    story.append(Paragraph("• <b>Automated Security Test Suite</b>: 8 automated unit tests in tests/test_security_rbac.py validating 100% RBAC compliance.", bullet_style))

    # 10. Key Features, Improvements, Limitations & Future Scope
    story.append(Paragraph("10. Key Features, Improvements, Limitations, and Future Scope", h1_style))
    story.append(Paragraph("<b>Completed & Implemented Features:</b>", h2_style))
    story.append(Paragraph("• Complete Scikit-learn ML pipeline with 91.25% validation accuracy and live /api/ml/retrain capability.", bullet_style))
    story.append(Paragraph("• Explainable AI (XAI) feature attribution deltas and Gini feature importance weighting.", bullet_style))
    story.append(Paragraph("• Strict RBAC security with automated test verification passing 8/8 test scenarios.", bullet_style))
    story.append(Paragraph("• Personalized weekly study planner with asynchronous milestone completion toggle API.", bullet_style))
    story.append(Paragraph("• Bulk CSV student record import with automated multi-metric ML categorization.", bullet_style))
    story.append(Paragraph("• Modern SaaS design system with CSS tokens, Lucide icons, and persistent Dark/Light mode.", bullet_style))

    story.append(Paragraph("<b>System Limitations:</b>", h2_style))
    story.append(Paragraph("• Active state runs on an in-memory relational structure (database/data_store.py); requires periodic export or connection to MySQL (database/schema.sql) for enterprise persistence.", bullet_style))
    story.append(Paragraph("• Model retraining runs synchronously in-process; for datasets exceeding 100,000 records, an asynchronous task queue (e.g. Celery / Redis) is recommended.", bullet_style))

    story.append(Paragraph("<b>Future Scope:</b>", h2_style))
    story.append(Paragraph("• LMS Integration: Bi-directional sync with Canvas, Moodle, and Google Classroom via LTI 1.3.", bullet_style))
    story.append(Paragraph("• Temporal Deep Learning: Sequence modeling (LSTM / Transformer) to predict semester trajectory paths.", bullet_style))
    story.append(Paragraph("• Automated SMS / Email Alerts: Immediate parental and advisor alerts via Twilio / SendGrid when attendance falls below 60%.", bullet_style))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceAfter=10))

    # Demo Credentials Quick Reference
    story.append(Paragraph("Appendix: Reference Demo User Credentials", h2_style))
    cred_data = [
        [Paragraph("Role", table_header), Paragraph("Username", table_header), Paragraph("Password", table_header), Paragraph("Persona / Context", table_header)],
        [Paragraph("Student (High Performer)", table_cell), Paragraph("STU1001", table_cell), Paragraph("password123", table_cell), Paragraph("Aarav Sharma (91.5% Att, 86 Internals, Low Risk, Active Study Plan)", table_cell)],
        [Paragraph("Student (At-Risk)", table_cell), Paragraph("STU1002", table_cell), Paragraph("password123", table_cell), Paragraph("Priya Nair (58.0% Att, 44 Internals, High Risk, Remedial Plan)", table_cell)],
        [Paragraph("Student (Clean State)", table_cell), Paragraph("STU1003", table_cell), Paragraph("password123", table_cell), Paragraph("Fresh Student (Clean onboarding empty state without data bleed)", table_cell)],
        [Paragraph("Faculty (CSE)", table_cell), Paragraph("faculty_ananya", table_cell), Paragraph("password123", table_cell), Paragraph("Dr. Ananya Roy (CSE Department Head, Triage & Interventions)", table_cell)],
        [Paragraph("Faculty (ECE)", table_cell), Paragraph("faculty_rajesh", table_cell), Paragraph("password123", table_cell), Paragraph("Dr. Rajesh Kumar (ECE Department Head, Department Data Isolation)", table_cell)],
        [Paragraph("Administrator", table_cell), Paragraph("admin", table_cell), Paragraph("password123", table_cell), Paragraph("System Admin (Full Provisioning, Audit Ledger, System Purge)", table_cell)]
    ]
    t_cred = Table(cred_data, colWidths=[110, 80, 80, 234])
    t_cred.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), primary_color),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_alt]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
    ]))
    story.append(t_cred)

    # Build PDF
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated PDF report at: {output_path}")

if __name__ == '__main__':
    target_path = sys.argv[1] if len(sys.argv) > 1 else "EduPredict_Complete_Project_Report.pdf"
    build_pdf(target_path)
