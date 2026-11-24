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

if __name__ == '__main__':
    unittest.main()
