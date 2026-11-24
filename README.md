# EduPredict – Intelligent Student Performance Prediction System
**Final-Year B.E. Computer Science & Engineering Project**

EduPredict is a modern, responsive educational web application designed to predict student academic outcomes, identify at-risk learners early, and provide actionable, personalized learning recommendations and faculty interventions.

---

## 🚀 Key Highlights & Architectural Features

1. **Role-Based Portals**:
   - **Faculty Portal**: Macro-level class analytics, at-risk triage, intervention scheduling, grade management, and predictive reports.
   - **Student Portal**: Personalized GPA tracking, subject radar analytics, study goal tracker, and customized revision roadmaps.
2. **Machine Learning Pipeline**:
   - Random Forest Classifier trained on 6 academic behavioral features (Internal marks, attendance, assignment completion, previous semester scores, daily study hours, classroom participation).
   - Scikit-learn model evaluation metrics comparing Random Forest (91.25% Acc), Logistic Regression (89.58% Acc), and Decision Trees (86.67% Acc).
3. **Design System**:
   - Navy Blue (`#0f172a`, `#1e293b`), Crisp White, and Teal (`#0d9488`, `#14b8a6`) SaaS aesthetic.
   - Chart.js interactive visualizations for subject mastery, attendance vs. score correlations, and semester trends.
   - Responsive sidebar with mobile drawer toggle and modal dialogs.
4. **Data Management & MySQL Schema**:
   - Out-of-the-box in-memory data store with 22+ realistic fictional student profiles across CSE semesters.
   - Ready-to-import MySQL database schema in `database/schema.sql` with normalized tables for Users, Students, Attendance, Marks, Predictions, Recommendations, and Interventions.

---

## 💻 Tech Stack
- **Backend**: Python Flask, Jinja2
- **Machine Learning**: Scikit-learn, Pandas, NumPy, Joblib
- **Frontend**: HTML5, CSS3 (Modern Flexbox & CSS Grid), JavaScript (ES6+), Bootstrap Icons, Chart.js
- **Database**: MySQL / MariaDB compatible schema (with built-in failover Python mock store)

---

## 🛠️ Quick Local Setup Instructions

### 1. Prerequisites
- Python 3.9+ installed (`python --version`)
- pip package manager

### 2. Verify / Install Dependencies
If needed, install the required packages:
```bash
pip install flask scikit-learn pandas numpy joblib
```

### 3. Launch Application
In the project root directory, run:
```bash
python app.py
```
By default, the server starts on `http://127.0.0.1:5000`.

### 4. Demo Login Credentials
- **Faculty Portal**:
  - Role: **Faculty**
  - Username: `faculty_ananya` (or any username)
  - Password: `password123`
- **Student Portal**:
  - Role: **Student**
  - Username: `STU1001` (Aarav Sharma) or `STU1002` (Priya Nair)
  - Password: `password123`

---

## 📊 Application Navigation Overview

- `/dashboard` — Faculty Macro Dashboard with statistics and trends.
- `/students` — Comprehensive student records table with search, filters, and CRUD modals.
- `/prediction` — Interactive ML Performance Prediction engine with contribution factors.
- `/at-risk` — At-risk student identification, triage, and follow-up logging.
- `/recommendations` — Personalized learning recommendations and status manager.
- `/attendance` — Monthly attendance trackers, low attendance alerts, and updates.
- `/academic-records` — Subject marks, assignments, and semester progress tracking.
- `/interventions` — Faculty mentoring notes, action items, and follow-up calendar.
- `/student-dashboard` — Personalized student interface (self-monitoring & progress).
- `/reports` — Comparative charts, model evaluation benchmarks, print view, and CSV export.
- `/goals` — Academic milestones and daily study hour progress monitoring.
- `/notifications` — Alert feed for attendance drops, upcoming deadlines, and risk warnings.
- `/profile` — User profile settings, account security, and notification preferences.
