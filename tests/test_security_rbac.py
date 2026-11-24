"""
EduPredict - Automated Security & RBAC Test Suite
Tests all 8 mandatory security and data isolation scenarios.
"""
import unittest
import sys
import os

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from database.data_store import (
    STUDENTS_DATA, USERS_DATA, authenticate_user,
    get_student_by_id, get_student_recommendations, get_student_assignments
)

class TestEduPredictSecurityRBAC(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

    def login(self, username, password="password123"):
        return self.client.post('/login', data={
            'username': username,
            'password': password
        }, follow_redirects=True)

    # ---------------------------------------------------------------
    # Scenario 1: Student A logs in and sees only Student A's records
    # ---------------------------------------------------------------
    def test_01_student_a_isolation(self):
        res = self.login("STU1001", "password123")
        self.assertEqual(res.status_code, 200)
        
        # Access student dashboard
        dash = self.client.get('/student-dashboard')
        self.assertEqual(dash.status_code, 200)
        content = dash.get_data(as_text=True)
        
        # Must see Student A's data
        self.assertIn("Aarav Sharma", content)
        self.assertIn("STU1001", content)
        self.assertIn("91.5%", content) # Student A attendance
        
        # Must NOT see Student B's data
        self.assertNotIn("Priya Nair", content)
        self.assertNotIn("STU1002", content)
        self.assertNotIn("58.0%", content) # Student B attendance

    # ---------------------------------------------------------------
    # Scenario 2: Student B logs in and sees only Student B's records
    # ---------------------------------------------------------------
    def test_02_student_b_isolation(self):
        res = self.login("STU1002", "password123")
        self.assertEqual(res.status_code, 200)
        
        dash = self.client.get('/student-dashboard')
        self.assertEqual(dash.status_code, 200)
        content = dash.get_data(as_text=True)
        
        # Must see Student B's data
        self.assertIn("Priya Nair", content)
        self.assertIn("STU1002", content)
        self.assertIn("58.0%", content) # Student B attendance
        
        # Must NOT see Student A's data
        self.assertNotIn("Aarav Sharma", content)
        self.assertNotIn("STU1001", content)
        self.assertNotIn("91.5%", content)

    # ---------------------------------------------------------------
    # Scenario 3: Student A attempts to access Student B's profile
    # ---------------------------------------------------------------
    def test_03_student_a_access_student_b_profile_idor(self):
        self.login("STU1001", "password123")
        
        # Student A accesses Student A's own profile -> Allowed (200)
        own_res = self.client.get('/students/STU1001')
        self.assertEqual(own_res.status_code, 200)
        
        # Student A attempts to access Student B's profile via URL -> 403 Forbidden!
        target_res = self.client.get('/students/STU1002')
        self.assertEqual(target_res.status_code, 403)

    # ---------------------------------------------------------------
    # Scenario 4: Student A attempts to edit Student B's records via API
    # ---------------------------------------------------------------
    def test_04_student_a_api_access_student_b_forbidden(self):
        self.login("STU1001", "password123")
        
        # Student attempts to call POST /api/students/STU1002/edit -> 403 Forbidden!
        edit_res = self.client.post('/api/students/STU1002/edit', data={
            'internal_marks': 99
        })
        self.assertEqual(edit_res.status_code, 403)

    # ---------------------------------------------------------------
    # Scenario 5: Student A attempts to modify Student B's attendance
    # ---------------------------------------------------------------
    def test_05_student_a_modify_attendance_forbidden(self):
        self.login("STU1001", "password123")
        
        # Student calls /api/attendance/update -> 403 Forbidden!
        att_res = self.client.post('/api/attendance/update', data={
            'student_id': 'STU1002',
            'attendance': 95.0
        })
        self.assertEqual(att_res.status_code, 403)

    # ---------------------------------------------------------------
    # Scenario 6: Student attempts to change role to faculty
    # ---------------------------------------------------------------
    def test_06_student_privilege_escalation_forbidden(self):
        self.login("STU1001", "password123")
        
        # Student attempts to call /switch-role/faculty -> 403 Forbidden!
        switch_res = self.client.get('/switch-role/faculty')
        self.assertEqual(switch_res.status_code, 403)

        # Student attempts to directly open /dashboard (Faculty view) -> 403 Forbidden!
        faculty_dash = self.client.get('/dashboard')
        self.assertEqual(faculty_dash.status_code, 403)

    # ---------------------------------------------------------------
    # Scenario 7: Faculty attempts to access unauthorized department
    # ---------------------------------------------------------------
    def test_07_faculty_cross_department_forbidden(self):
        # faculty_rajesh is in Electronics & Communication
        self.login("faculty_rajesh", "password123")
        
        # Student STU1001 is in Computer Science & Engineering
        # Faculty Rajesh tries to access CSE student STU1001 -> 403 Forbidden!
        cross_res = self.client.get('/students/STU1001')
        self.assertEqual(cross_res.status_code, 403)

    # ---------------------------------------------------------------
    # Scenario 8: Unauthenticated users attempt protected access
    # ---------------------------------------------------------------
    def test_08_unauthenticated_requests_redirected(self):
        # Clear session
        with self.client.session_transaction() as sess:
            sess.clear()
            
        protected_urls = [
            '/dashboard',
            '/student-dashboard',
            '/students',
            '/attendance',
            '/academic-records',
            '/interventions',
            '/admin',
            '/profile'
        ]
        
        for url in protected_urls:
            res = self.client.get(url)
            # Unauthenticated requests redirect to /login with 302
            self.assertEqual(res.status_code, 302, f"Failed on {url}")
            self.assertIn('/login', res.headers['Location'])

    # ---------------------------------------------------------------
    # Scenario 9: Student cannot add, edit or delete academic subjects
    # ---------------------------------------------------------------
    def test_09_student_cannot_add_or_alter_subjects(self):
        self.login("STU1001", "password123")
        
        # Student tries to add a subject -> 403
        add_res = self.client.post('/api/subjects/add', data={
            'subject_code': 'HACK999',
            'subject_name': 'Hacking 101',
            'department': 'Computer Science',
            'semester': 7,
            'credits': 4
        })
        self.assertEqual(add_res.status_code, 403)

        # Student tries to edit a subject -> 403
        edit_res = self.client.post('/api/subjects/CS701/update', data={
            'subject_name': 'Modified'
        })
        self.assertEqual(edit_res.status_code, 403)

        # Student tries to delete a subject -> 403
        del_res = self.client.post('/api/subjects/CS701/delete')
        self.assertEqual(del_res.status_code, 403)

    # ---------------------------------------------------------------
    # Scenario 10: Student cannot alter assessment marks
    # ---------------------------------------------------------------
    def test_10_student_cannot_update_marks(self):
        self.login("STU1001", "password123")

        # Student tries to update their own or another's marks -> 403
        mark_res = self.client.post('/api/academic-records/marks/update', json={
            'student_id': 'STU1001',
            'subject_code': 'CS701',
            'internal_1': 25,
            'internal_2': 25,
            'semester_exam_score': 100
        })
        self.assertEqual(mark_res.status_code, 403)

    # ---------------------------------------------------------------
    # Scenario 11: Student academic records IDOR isolation
    # ---------------------------------------------------------------
    def test_11_student_academic_records_idor_isolation(self):
        self.login("STU1001", "password123")

        # STU1001 attempts to view STU1002's records via query params
        res = self.client.get('/academic-records?student_id=STU1002&semester=7')
        self.assertEqual(res.status_code, 200)
        content = res.get_data(as_text=True)

        # Must only render STU1001's courses, not STU1002's
        self.assertIn("CS701", content)
        # STU1002 has F in CS703 with 38 marks
        self.assertNotIn("Priya Nair (STU1002)", content)

    # ---------------------------------------------------------------
    # Scenario 12: Faculty AMS subject & marks management
    # ---------------------------------------------------------------
    def test_12_faculty_ams_subject_and_mark_management(self):
        # faculty_ananya is CSE faculty
        self.login("faculty_ananya", "password123")

        # 1. Update marks for CSE student STU1001 in CS701
        res = self.client.post('/api/academic-records/marks/update', json={
            'student_id': 'STU1001',
            'subject_code': 'CS701',
            'internal_1': 24,
            'internal_2': 24,
            'assignment_score': 10,
            'lab_score': 15,
            'semester_exam_score': 95,
            'classes_attended': 45,
            'classes_conducted': 45
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['record']['grade'], 'A')
        self.assertEqual(data['record']['grade_points'], 8.0)

        # 2. Toggle syllabus unit
        syl_res = self.client.post('/api/subjects/CS701/syllabus', json={
            'unit_number': 1,
            'completed': True
        })
        self.assertEqual(syl_res.status_code, 200)

        # 3. Faculty cannot alter subjects in ECE department
        ece_edit = self.client.post('/api/subjects/EC701/update', json={'subject_name': 'Hacked ECE'})
        self.assertEqual(ece_edit.status_code, 403)

    # ---------------------------------------------------------------
    # Scenario 13: Export CSV and PDF reports
    # ---------------------------------------------------------------
    def test_13_academic_reports_export_csv_and_pdf(self):
        self.login("STU1001", "password123")

        # CSV Export
        csv_res = self.client.get('/api/academic-records/export-csv?semester=7')
        self.assertEqual(csv_res.status_code, 200)
        self.assertEqual(csv_res.mimetype, 'text/csv')
        self.assertIn('attachment;', csv_res.headers['Content-Disposition'])

        # PDF Export
        pdf_res = self.client.get('/api/academic-records/export-pdf?semester=7')
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.mimetype, 'application/pdf')
        self.assertTrue(pdf_res.data.startswith(b'%PDF'))

if __name__ == '__main__':
    unittest.main()
