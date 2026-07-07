"""
Retest for brute-force lockout fix (iteration_4).
Verifies the 4 scenarios from the review request against admin@takeoverscan.io.
"""
import os
import pytest
import requests
from pymongo import MongoClient

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')
ADMIN_EMAIL = os.environ.get('TEST_ADMIN_EMAIL', 'admin@takeoverscan.io')
ADMIN_PASSWORD = os.environ.get('TEST_ADMIN_PASSWORD', 'Admin@Scan2026')
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'test_database')


@pytest.fixture(scope='module')
def db():
    return MongoClient(MONGO_URL)[DB_NAME]


@pytest.fixture(autouse=True)
def _clean(db):
    db.login_attempts.delete_many({})
    yield
    db.login_attempts.delete_many({})


def _login(email, password):
    return requests.post(f'{BASE_URL}/api/auth/login',
                         json={'email': email, 'password': password}, timeout=15)


class TestBruteForceLockoutAdmin:
    # Scenario 1: 6th wrong attempt returns 429
    def test_5_wrong_then_429_on_6th(self):
        for i in range(5):
            r = _login(ADMIN_EMAIL, f'WrongPassword{i}!')
            assert r.status_code == 401, f'attempt {i+1} expected 401, got {r.status_code}'
        r6 = _login(ADMIN_EMAIL, 'WrongPasswordFinal!')
        assert r6.status_code == 429, f'expected 429 on 6th, got {r6.status_code}: {r6.text}'
        assert 'Too many failed attempts' in r6.text

    # Scenario 2: after lockout triggers, correct password also blocked (429)
    def test_correct_password_blocked_after_lockout(self):
        for i in range(5):
            _login(ADMIN_EMAIL, f'BadPw{i}!')
        # 6th with WRONG - trigger lockout
        r6 = _login(ADMIN_EMAIL, 'StillBad!')
        assert r6.status_code == 429
        # 7th with CORRECT password should still be blocked
        r_correct = _login(ADMIN_EMAIL, ADMIN_PASSWORD)
        assert r_correct.status_code == 429, \
            f'correct password should be blocked during lockout, got {r_correct.status_code}'

    # Scenario 3: clearing lockout allows admin login with correct password
    def test_admin_login_succeeds_after_clearing_lockout(self, db):
        for i in range(6):
            _login(ADMIN_EMAIL, 'nope!')
        # Lockout should be active
        r_blocked = _login(ADMIN_EMAIL, ADMIN_PASSWORD)
        assert r_blocked.status_code == 429
        # Clear lockout
        db.login_attempts.delete_many({})
        r_ok = _login(ADMIN_EMAIL, ADMIN_PASSWORD)
        assert r_ok.status_code == 200, f'expected 200 after clearing, got {r_ok.status_code}: {r_ok.text}'
        data = r_ok.json()
        assert data['user']['email'] == ADMIN_EMAIL
        assert data['user']['role'] == 'admin'

    # Scenario 4: failed logins to a DIFFERENT email do NOT lock out admin
    def test_wrong_password_to_other_email_does_not_lock_admin(self):
        other = 'not-admin-xyz@example.com'
        # 5 wrong attempts on other email (may also lock the other email — that's expected)
        for i in range(5):
            r = _login(other, 'nope!')
            assert r.status_code == 401, f'other-email attempt {i+1}: {r.status_code}'
        # Admin correct password should still work — lockout is per-email, not global
        r_admin = _login(ADMIN_EMAIL, ADMIN_PASSWORD)
        assert r_admin.status_code == 200, \
            f'admin should not be locked by other-email attempts, got {r_admin.status_code}: {r_admin.text}'
