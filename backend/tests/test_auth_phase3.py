"""
Phase 3 auth tests: register/login/logout/me/refresh + multi-tenant scoping.
Uses live backend via REACT_APP_BACKEND_URL. Cookie-based auth via requests.Session.
"""
import os
import time
import uuid
import pytest
import requests
from pymongo import MongoClient

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://language-arabic-38.preview.emergentagent.com').rstrip('/')
ADMIN_EMAIL = os.environ.get('TEST_ADMIN_EMAIL', 'admin@takeoverscan.io')
ADMIN_PASSWORD = os.environ.get('TEST_ADMIN_PASSWORD', 'Admin@Scan2026')
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'test_database')


@pytest.fixture(scope='module')
def db():
    return MongoClient(MONGO_URL)[DB_NAME]


@pytest.fixture(autouse=True)
def _clear_lockouts(db):
    db.login_attempts.delete_many({})
    yield


def _new_email():
    return f'test_{uuid.uuid4().hex[:10]}@example.com'


# ========= Register =========
class TestRegister:
    def test_register_valid(self):
        s = requests.Session()
        email = _new_email()
        r = s.post(f'{BASE_URL}/api/auth/register', json={'email': email, 'password': 'Password1!', 'name': 'Test'})
        assert r.status_code == 200, r.text
        data = r.json()
        assert 'access_token' in data and isinstance(data['access_token'], str)
        assert data['user']['email'] == email
        assert data['user']['role'] == 'user'
        # httpOnly cookies set
        assert 'access_token' in s.cookies
        assert 'refresh_token' in s.cookies

    def test_register_duplicate(self):
        s = requests.Session()
        email = _new_email()
        r1 = s.post(f'{BASE_URL}/api/auth/register', json={'email': email, 'password': 'Password1!'})
        assert r1.status_code == 200
        r2 = requests.post(f'{BASE_URL}/api/auth/register', json={'email': email, 'password': 'Password1!'})
        assert r2.status_code == 400

    def test_register_short_password(self):
        r = requests.post(f'{BASE_URL}/api/auth/register', json={'email': _new_email(), 'password': 'short'})
        assert r.status_code == 422


# ========= Login =========
class TestLogin:
    def test_login_admin(self):
        s = requests.Session()
        r = s.post(f'{BASE_URL}/api/auth/login', json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD})
        assert r.status_code == 200, r.text
        data = r.json()
        assert data['user']['role'] == 'admin'
        assert data['user']['email'] == ADMIN_EMAIL
        assert 'access_token' in s.cookies
        assert 'refresh_token' in s.cookies

    def test_login_wrong_password(self):
        r = requests.post(f'{BASE_URL}/api/auth/login', json={'email': ADMIN_EMAIL, 'password': 'WrongPass123!'})
        assert r.status_code == 401

    def test_bruteforce_lockout(self, db):
        # Use a unique email so we don't interfere with other tests
        email = _new_email()
        # Register user
        s = requests.Session()
        r = s.post(f'{BASE_URL}/api/auth/register', json={'email': email, 'password': 'Password1!'})
        assert r.status_code == 200
        # Clear any lockout entries just for safety
        db.login_attempts.delete_many({})
        # 5 wrong attempts
        for i in range(5):
            r = requests.post(f'{BASE_URL}/api/auth/login', json={'email': email, 'password': 'wrong'})
            assert r.status_code == 401, f'attempt {i}: {r.status_code}'
        # 6th should be 429
        r = requests.post(f'{BASE_URL}/api/auth/login', json={'email': email, 'password': 'wrong'})
        assert r.status_code == 429, f'expected 429, got {r.status_code} - {r.text}'
        # cleanup
        db.login_attempts.delete_many({})


# ========= /me + logout + refresh =========
class TestSession:
    def test_me_authenticated(self):
        s = requests.Session()
        r = s.post(f'{BASE_URL}/api/auth/login', json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD})
        assert r.status_code == 200
        r2 = s.get(f'{BASE_URL}/api/auth/me')
        assert r2.status_code == 200
        assert r2.json()['email'] == ADMIN_EMAIL
        assert r2.json()['role'] == 'admin'

    def test_me_unauthenticated(self):
        r = requests.get(f'{BASE_URL}/api/auth/me')
        assert r.status_code == 401

    def test_logout_clears_cookies(self, db):
        db.login_attempts.delete_many({})
        s = requests.Session()
        r = s.post(f'{BASE_URL}/api/auth/login', json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD})
        assert r.status_code == 200
        assert 'access_token' in s.cookies
        r2 = s.post(f'{BASE_URL}/api/auth/logout')
        assert r2.status_code == 200
        # After logout, /me should return 401
        r3 = s.get(f'{BASE_URL}/api/auth/me')
        assert r3.status_code == 401

    def test_refresh(self, db):
        db.login_attempts.delete_many({})
        s = requests.Session()
        r = s.post(f'{BASE_URL}/api/auth/login', json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD})
        assert r.status_code == 200
        # capture old cookie for reference (refresh may or may not rotate it)
        _ = s.cookies.get('access_token')
        time.sleep(1)
        r2 = s.post(f'{BASE_URL}/api/auth/refresh')
        assert r2.status_code == 200, r2.text
        data = r2.json()
        assert 'access_token' in data
        # Optional: token may or may not differ if generated same second; ensure valid via /me
        r3 = s.get(f'{BASE_URL}/api/auth/me')
        assert r3.status_code == 200


# ========= Multi-tenant scan scoping =========
class TestMultiTenantScans:
    def test_guest_scan_stores_guest_owner(self):
        payload = {'domain': f'ex-{uuid.uuid4().hex[:6]}.example.com', 'sources': ['crtsh']}
        r = requests.post(f'{BASE_URL}/api/scans', json=payload)
        assert r.status_code in (200, 201), r.text
        rd = r.json()
        scan_id = rd.get('id') or rd.get('scan_id') or (rd.get('scan') or {}).get('id')
        assert scan_id, rd
        # Guest listing should include our scan (or not include user-owned ones)
        r2 = requests.get(f'{BASE_URL}/api/scans')
        assert r2.status_code == 200
        payload_out = r2.json()
        scans = payload_out['scans'] if isinstance(payload_out, dict) else payload_out
        ids = [s.get('id') for s in scans]
        assert scan_id in ids

    def test_user_scan_stores_user_owner_and_scoping(self, db):
        db.login_attempts.delete_many({})
        s = requests.Session()
        email = _new_email()
        r = s.post(f'{BASE_URL}/api/auth/register', json={'email': email, 'password': 'Password1!'})
        assert r.status_code == 200
        user_id = r.json()['user']['id']

        payload = {'domain': f'ex-{uuid.uuid4().hex[:6]}.example.com', 'sources': ['crtsh']}
        rc = s.post(f'{BASE_URL}/api/scans', json=payload)
        assert rc.status_code in (200, 201), rc.text
        rd = rc.json()
        scan_id = rd.get('id') or rd.get('scan_id') or (rd.get('scan') or {}).get('id')
        assert scan_id, rd

        # DB check: owner_id set to user_id
        doc = db.scans.find_one({'id': scan_id})
        assert doc is not None, f'scan {scan_id} not found in db'
        assert doc.get('owner_id') == user_id, f"owner_id mismatch: {doc.get('owner_id')} vs {user_id}"

        # user list only sees their own scans
        rl = s.get(f'{BASE_URL}/api/scans')
        assert rl.status_code == 200
        lst = rl.json()
        scans = lst['scans'] if isinstance(lst, dict) else lst
        for sc in scans:
            # every scan visible must belong to this user
            assert sc.get('owner_id') in (user_id, None), f"user leaked: saw scan owned by {sc.get('owner_id')}"
        assert scan_id in [x.get('id') for x in scans]

    def test_admin_sees_all_scans(self):
        s = requests.Session()
        r = s.post(f'{BASE_URL}/api/auth/login', json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD})
        assert r.status_code == 200
        r2 = s.get(f'{BASE_URL}/api/scans')
        assert r2.status_code == 200
        lst = r2.json()
        scans = lst['scans'] if isinstance(lst, dict) else lst
        assert len(scans) >= 1
        rguest = requests.get(f'{BASE_URL}/api/scans')
        guest_lst = rguest.json()
        guest_scans = guest_lst['scans'] if isinstance(guest_lst, dict) else guest_lst
        assert len(scans) >= len(guest_scans)

    def test_bulk_scan_stores_owner(self, db):
        db.login_attempts.delete_many({})
        s = requests.Session()
        email = _new_email()
        r = s.post(f'{BASE_URL}/api/auth/register', json={'email': email, 'password': 'Password1!'})
        assert r.status_code == 200
        user_id = r.json()['user']['id']
        domains = [f'bulk-{uuid.uuid4().hex[:6]}.example.com', f'bulk-{uuid.uuid4().hex[:6]}.example.org']
        rb = s.post(f'{BASE_URL}/api/scans/bulk', json={'domains': domains, 'sources': ['crtsh']})
        assert rb.status_code in (200, 201), rb.text
        # Verify at least one scan document has owner_id=user_id
        time.sleep(1)
        docs = list(db.scans.find({'owner_id': user_id}))
        assert len(docs) >= 1


# ========= Backwards compatibility of other endpoints =========
class TestBackwardsCompat:
    def test_root(self):
        r = requests.get(f'{BASE_URL}/api/')
        assert r.status_code == 200
        assert r.json().get('services') == 183

    def test_services_unauth(self):
        r = requests.get(f'{BASE_URL}/api/services')
        assert r.status_code == 200
        payload = r.json()
        services = payload['services'] if isinstance(payload, dict) else payload
        assert len(services) == 183

    def test_playbooks_unauth(self):
        r = requests.get(f'{BASE_URL}/api/playbooks')
        assert r.status_code == 200
        payload = r.json()
        pbs = payload['playbooks'] if isinstance(payload, dict) else payload
        assert len(pbs) >= 1

    def test_sources_unauth(self):
        r = requests.get(f'{BASE_URL}/api/sources')
        assert r.status_code == 200
