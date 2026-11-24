-- EduPredict - Database Schema and Seed Data
-- Target Database: MySQL / MariaDB compatible

CREATE DATABASE IF NOT EXISTS edupredict_db;
USE edupredict_db;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    role ENUM('faculty', 'student', 'admin') NOT NULL DEFAULT 'student',
    full_name VARCHAR(120) NOT NULL,
    department VARCHAR(100) DEFAULT 'Computer Science & Engineering',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Students Table
CREATE TABLE IF NOT EXISTS students (
    student_id VARCHAR(20) PRIMARY KEY,
    user_id INT,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(120) NOT NULL,
    department VARCHAR(100) DEFAULT 'Computer Science & Engineering',
    semester INT DEFAULT 7,
    attendance_pct DECIMAL(5,2) NOT NULL,
    internal_marks DECIMAL(5,2) NOT NULL,
    assignment_pct DECIMAL(5,2) NOT NULL,
    prev_semester_score DECIMAL(5,2) NOT NULL,
    daily_study_hours DECIMAL(4,2) NOT NULL,
    classroom_participation DECIMAL(4,2) NOT NULL,
    predicted_category ENUM('High Performer', 'Average Performer', 'At-Risk Student') NOT NULL,
    risk_level ENUM('Low', 'Medium', 'High') NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- 3. Attendance Records
CREATE TABLE IF NOT EXISTS attendance (
    record_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL,
    date DATE NOT NULL,
    status ENUM('Present', 'Absent', 'Late') NOT NULL,
    subject VARCHAR(100) NOT NULL,
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE
);

-- 4. Academic Marks
CREATE TABLE IF NOT EXISTS academic_marks (
    mark_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL,
    semester INT NOT NULL,
    subject_code VARCHAR(20) NOT NULL,
    subject_name VARCHAR(100) NOT NULL,
    internal_assessment_1 DECIMAL(5,2),
    internal_assessment_2 DECIMAL(5,2),
    assignment_score DECIMAL(5,2),
    total_score DECIMAL(5,2),
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE
);

-- 5. Assignments
CREATE TABLE IF NOT EXISTS assignments (
    assignment_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL,
    title VARCHAR(150) NOT NULL,
    subject VARCHAR(100) NOT NULL,
    due_date DATE NOT NULL,
    status ENUM('Completed', 'Pending', 'Overdue') NOT NULL,
    score DECIMAL(5,2),
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE
);

-- 6. Performance Predictions
CREATE TABLE IF NOT EXISTS predictions (
    prediction_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL,
    predicted_category VARCHAR(50) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    confidence_score DECIMAL(5,2),
    model_version VARCHAR(50) DEFAULT 'RandomForest_v1.0',
    prediction_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_live_prediction BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE
);

-- 7. Recommendations
CREATE TABLE IF NOT EXISTS recommendations (
    recommendation_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL,
    category VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    priority ENUM('High', 'Medium', 'Low') NOT NULL,
    status ENUM('Pending', 'In Progress', 'Completed') DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE
);

-- 8. Faculty Interventions
CREATE TABLE IF NOT EXISTS faculty_interventions (
    intervention_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL,
    faculty_name VARCHAR(120) NOT NULL,
    session_date DATE NOT NULL,
    notes TEXT NOT NULL,
    action_items TEXT,
    follow_up_date DATE,
    status ENUM('Awaiting Follow-up', 'In Progress', 'Resolved') DEFAULT 'Awaiting Follow-up',
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE
);

-- 9. Notifications
CREATE TABLE IF NOT EXISTS notifications (
    notification_id INT AUTO_INCREMENT PRIMARY KEY,
    recipient_role ENUM('faculty', 'student', 'all') NOT NULL,
    student_id VARCHAR(20),
    title VARCHAR(150) NOT NULL,
    message TEXT NOT NULL,
    type ENUM('alert', 'warning', 'info', 'success') NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 10. Security & Access Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    username VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    status ENUM('SUCCESS', 'FAILED', 'BLOCKED', 'DENIED') NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- 11. Subjects Management
CREATE TABLE IF NOT EXISTS subjects (
    subject_id INT AUTO_INCREMENT PRIMARY KEY,
    subject_code VARCHAR(20) NOT NULL,
    subject_name VARCHAR(150) NOT NULL,
    department VARCHAR(100) NOT NULL,
    semester INT NOT NULL,
    credits INT NOT NULL DEFAULT 4,
    academic_year VARCHAR(20) DEFAULT '2026-2027',
    batch VARCHAR(20) DEFAULT '2023-2027',
    section VARCHAR(10) DEFAULT 'A',
    faculty_id VARCHAR(100),
    faculty_name VARCHAR(120),
    syllabus_progress INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_subject_alloc (subject_code, department, semester, section)
);

-- 12. Subject-wise Student Examination & Continuous Assessment Records
CREATE TABLE IF NOT EXISTS subject_academic_records (
    record_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL,
    subject_code VARCHAR(20) NOT NULL,
    semester INT NOT NULL,
    academic_year VARCHAR(20) DEFAULT '2026-2027',
    internal_1 DECIMAL(5,2) DEFAULT 0.0,
    internal_2 DECIMAL(5,2) DEFAULT 0.0,
    assignment_marks DECIMAL(5,2) DEFAULT 0.0,
    lab_marks DECIMAL(5,2) DEFAULT 0.0,
    exam_marks DECIMAL(5,2) DEFAULT 0.0,
    total_marks DECIMAL(5,2) DEFAULT 0.0,
    grade VARCHAR(5) DEFAULT 'F',
    grade_points DECIMAL(4,2) DEFAULT 0.0,
    credits_earned INT DEFAULT 0,
    classes_conducted INT DEFAULT 45,
    classes_attended INT DEFAULT 0,
    attendance_pct DECIMAL(5,2) DEFAULT 0.0,
    attendance_status ENUM('Good Standing', 'Borderline Warning', 'Critical Shortage') DEFAULT 'Critical Shortage',
    academic_risk ENUM('Low', 'Medium', 'High') DEFAULT 'High',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE
);

-- 13. Subject Syllabus Units
CREATE TABLE IF NOT EXISTS syllabus_units (
    unit_id INT AUTO_INCREMENT PRIMARY KEY,
    subject_code VARCHAR(20) NOT NULL,
    unit_number INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    is_completed BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
