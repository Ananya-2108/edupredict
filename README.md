# EduPredict – AI-Powered Student Performance Prediction & Academic Analytics SaaS

EduPredict is an enterprise-grade academic analytics and machine learning SaaS platform designed to predict undergraduate student outcomes, identify at-risk learners early, and provide Explainable AI (XAI) attributions, adaptive study roadmaps, and secure Role-Based Access Control (RBAC).

---

## 🚀 Key Highlights & Architectural Features

1. **Role-Based Portals & Strict Data Isolation**:
   - **Student Portal**: Strictly isolated view of individual attendance, marks, radar analytics, target goals, and adaptive weekly study plans with task check-offs. Protected against Insecure Direct Object References (IDOR).
   - **Faculty Portal**: Department-level macro cohort analytics, early warning risk triage, intervention scheduling, subject score matrices, and bulk student CSV imports.
   - **Administrator Center**: Institutional overview, user provisioning, and tamper-evident security audit logging.

2. **Machine Learning Pipeline & Explainable AI (XAI)**:
   - **Algorithm Comparison**: Multi-model evaluation comparing Random Forest (**91.25% Acc**, 91.09% F1), Logistic Regression (89.58% Acc), and Decision Trees (86.67% Acc).
   - **Gini Feature Importances**: Transparent feature weighting (Internal Marks: 32%, Attendance: 28%, Previous Semester: 16%, Assignments: 14%, Study Hours: 6%, Participation: 4%).
   - **Explainable AI (XAI) Attribution**: Real-time delta waterfall quantifying how individual parameters positively or negatively impact predicted outcomes against cohort baselines.
   - **Real-Time Retraining**: One-click retraining endpoint (`/api/ml/retrain`) updating models and evaluation benchmarks without server restarts.
   - **Session Prediction Telemetry**: Audit log capturing interactive simulation runs.

3. **Premium SaaS Design System & UI/UX**:
   - **Palette**: Primary `#172554`, Secondary `#2563EB`, Background `#F8FAFC`, Surface `#FFFFFF`, Success `#16A34A`, Warning `#F59E0B`, Danger `#DC2626`, Text `#1E293B`.
   - **Typography & Icons**: Inter typography with unified Lucide icon set.
   - **Dark / Light Mode**: Theme toggle with instant `localStorage` persistence and zero-flicker init.
   - **Interactive Visualizations**: Chart.js doughnut, scatter, bar, and area charts.
   - **Responsive Navigation**: Collapsible sidebar, animated counters, accessible modal dialogs, and toast notification toasts.

4. **Security & Data Integrity**:
   - Automated unit test suite (`tests/test_security_rbac.py`) covering 8 critical security scenarios: authentication, RBAC authorization, student data privacy, IDOR prevention, CSRF-safe JSON endpoints, and audit logging.
   - Password hashing using Werkzeug PBKDF2:SHA256.

---

## 💻 Tech Stack
- **Backend**: Python 3.9+, Flask, Jinja2, Werkzeug
- **Machine Learning**: Scikit-learn, Pandas, NumPy, Joblib
- **Frontend**: HTML5, CSS3 (Custom SaaS Design Tokens), JavaScript (ES6+), Chart.js, Lucide Icons
- **Database**: In-memory relational store with full schema for MySQL / MariaDB in `database/schema.sql`

---

## 🛠️ Quick Local Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/Ananya-2108/edupredict.git
cd edupredict
```

### 2. Configure Virtual Environment & Install Dependencies
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Run RBAC Security Test Suite
```bash
python -m unittest discover tests
```

### 4. Launch Application
```bash
python app.py
```
By default, the server runs on `http://127.0.0.1:5000`.

---

## 🔑 Demo Login Credentials

| Role | Username | Password | Notes |
| :--- | :--- | :--- | :--- |
| **Student (High Performer)** | `STU1001` | `password123` | Aarav Sharma (91.5% Attendance, 86 Internals) |
| **Student (At-Risk)** | `STU1002` | `password123` | Priya Nair (58.0% Attendance, 44 Internals) |
| **Student (Clean Onboarding)** | `STU1003` | `password123` | Fresh Student (Clean empty state) |
| **Faculty (CSE)** | `faculty_ananya` | `password123` | Dr. Ananya Roy (CSE Department) |
| **Faculty (ECE)** | `faculty_rajesh` | `password123` | Dr. Rajesh Kumar (ECE Department) |
| **Administrator** | `admin` | `password123` | System Administrator (Full Audit Logs) |

---

## 📊 Application Navigation Overview

- `/student-dashboard` — Personalized student self-monitoring, radar analytics, and target goals.
- `/dashboard` — Faculty Department Dashboard with cohort distribution and telemetry charts.
- `/prediction` — Interactive ML Performance Prediction engine with XAI attribution deltas.
- `/at-risk` — Early warning triage and risk classification breakdown.
- `/recommendations` — Personalized learning recommendations and weekly adaptive study planner.
- `/attendance` — Attendance registers, trends, and threshold monitoring.
- `/academic-records` — Subject marks matrix and assignment submissions.
- `/interventions` — Faculty mentoring logs and scheduled follow-ups.
- `/admin` — User provisioning and tamper-evident audit logs.
- `/reports` — Model validation report, ground truth alignment, and CSV export.
- `/profile` — Contact profile settings and secure password updates.
