"""v7.9 Commercial Wave backend tests — billing + workspaces + light regression."""
import os
import secrets
import requests
import pytest

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://language-arabic-38.preview.emergentagent.com').rstrip('/')


def _fresh_email():
    return f'test_{secrets.token_hex(6)}@cyberscope-test.io'


def _register(session, email=None, password='Passw0rd!Strong'):
    email = email or _fresh_email()
    r = session.post(f'{BASE_URL}/api/auth/register', json={'email': email, 'password': password, 'name': email.split('@')[0]})
    assert r.status_code == 200, f'register failed: {r.status_code} {r.text}'
    return email, password


@pytest.fixture
def anon():
    return requests.Session()


@pytest.fixture
def user():
    s = requests.Session()
    email, _ = _register(s)
    s.email = email
    return s


@pytest.fixture
def user2():
    s = requests.Session()
    email, _ = _register(s)
    s.email = email
    return s


# ----------------------- BILLING -----------------------
class TestBillingTiers:
    def test_tiers_public(self, anon):
        r = anon.get(f'{BASE_URL}/api/billing/tiers')
        assert r.status_code == 200
        data = r.json()
        tiers = {t['id']: t for t in data['tiers']}
        assert set(tiers) == {'free', 'pro', 'enterprise', 'lifetime'}
        for t in tiers.values():
            assert isinstance(t.get('features'), list) and len(t['features']) > 0
            assert 'quota_scans_per_month' in t

    def test_status_anonymous(self, anon):
        r = anon.get(f'{BASE_URL}/api/billing/status')
        assert r.status_code == 200
        data = r.json()
        assert data['authenticated'] is False
        assert data['tier'] == 'free'
        assert data['stripe_status'] is None

    def test_status_after_register(self, user):
        r = user.get(f'{BASE_URL}/api/billing/status')
        assert r.status_code == 200
        data = r.json()
        assert data['authenticated'] is True
        assert data['tier'] == 'free'

    def test_checkout_requires_auth(self, anon):
        r = anon.post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'pro'})
        assert r.status_code == 401

    def test_checkout_free_rejected(self, user):
        r = user.post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'free'})
        assert r.status_code == 400

    def test_checkout_pro_demo(self, user):
        r = user.post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'pro'})
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get('demo') is True
        assert 'url' in data and 'success=1' in data['url']
        # persistence
        s = user.get(f'{BASE_URL}/api/billing/status').json()
        assert s['tier'] == 'pro'
        assert s['stripe_status'] == 'demo_active'

    def test_checkout_lifetime_demo(self, user2):
        r = user2.post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'lifetime'})
        assert r.status_code == 200, r.text
        assert r.json().get('demo') is True
        s = user2.get(f'{BASE_URL}/api/billing/status').json()
        assert s['tier'] == 'lifetime'
        assert s['stripe_status'] == 'demo_lifetime'


# ----------------------- WORKSPACES -----------------------
class TestWorkspaces:
    def test_create_and_list(self, user):
        r = user.post(f'{BASE_URL}/api/workspaces', json={'name': 'TEST_ws_' + secrets.token_hex(3)})
        assert r.status_code == 200, r.text
        ws = r.json()
        assert ws['role'] == 'owner'
        wid = ws['id']

        r2 = user.get(f'{BASE_URL}/api/workspaces')
        assert r2.status_code == 200
        wss = r2.json()['workspaces']
        assert any(w['id'] == wid and w['role'] == 'owner' for w in wss)

        r3 = user.get(f'{BASE_URL}/api/workspaces/{wid}')
        assert r3.status_code == 200
        detail = r3.json()
        assert detail['workspace']['id'] == wid
        assert len(detail['members']) == 1
        assert detail['pending_invites'] == []

    def test_invite_new_email_returns_token(self, user):
        wid = user.post(f'{BASE_URL}/api/workspaces', json={'name': 'TEST_inv'}).json()['id']
        new_email = _fresh_email()
        r = user.post(f'{BASE_URL}/api/workspaces/{wid}/invite', json={'email': new_email, 'role': 'analyst'})
        assert r.status_code == 200, r.text
        data = r.json()
        assert data['added'] is False
        assert 'invite_token' in data

        # accept with matching email
        invitee = requests.Session()
        _register(invitee, email=new_email)
        r2 = invitee.post(f'{BASE_URL}/api/workspaces/invites/{data["invite_token"]}/accept')
        assert r2.status_code == 200

        # accept with mismatch should 403
        wid2 = user.post(f'{BASE_URL}/api/workspaces', json={'name': 'TEST_inv2'}).json()['id']
        tok = user.post(f'{BASE_URL}/api/workspaces/{wid2}/invite', json={'email': _fresh_email()}).json()['invite_token']
        other = requests.Session()
        _register(other)  # different email
        r3 = other.post(f'{BASE_URL}/api/workspaces/invites/{tok}/accept')
        assert r3.status_code == 403

    def test_invite_existing_user_directly_added(self, user, user2):
        wid = user.post(f'{BASE_URL}/api/workspaces', json={'name': 'TEST_direct'}).json()['id']
        r = user.post(f'{BASE_URL}/api/workspaces/{wid}/invite', json={'email': user2.email, 'role': 'viewer'})
        assert r.status_code == 200
        data = r.json()
        assert data['added'] is True
        assert 'user_id' in data

    def test_role_update_and_owner_protection(self, user, user2):
        wid = user.post(f'{BASE_URL}/api/workspaces', json={'name': 'TEST_roles'}).json()['id']
        add = user.post(f'{BASE_URL}/api/workspaces/{wid}/invite', json={'email': user2.email, 'role': 'viewer'}).json()
        uid = add['user_id']
        # promote to admin
        r = user.patch(f'{BASE_URL}/api/workspaces/{wid}/members/{uid}', json={'role': 'admin'})
        assert r.status_code == 200
        # owner cannot be re-roled
        owner_id = [m for m in user.get(f'{BASE_URL}/api/workspaces/{wid}').json()['members'] if m['role'] == 'owner'][0]['user_id']
        r2 = user.patch(f'{BASE_URL}/api/workspaces/{wid}/members/{owner_id}', json={'role': 'admin'})
        assert r2.status_code == 400

    def test_remove_member_and_owner_protection(self, user, user2):
        wid = user.post(f'{BASE_URL}/api/workspaces', json={'name': 'TEST_rm'}).json()['id']
        add = user.post(f'{BASE_URL}/api/workspaces/{wid}/invite', json={'email': user2.email, 'role': 'viewer'}).json()
        uid = add['user_id']
        r = user.delete(f'{BASE_URL}/api/workspaces/{wid}/members/{uid}')
        assert r.status_code == 200
        # cannot remove owner
        owner_id = [m for m in user.get(f'{BASE_URL}/api/workspaces/{wid}').json()['members'] if m['role'] == 'owner'][0]['user_id']
        r2 = user.delete(f'{BASE_URL}/api/workspaces/{wid}/members/{owner_id}')
        assert r2.status_code == 400

    def test_comments_flow(self, user):
        wid = user.post(f'{BASE_URL}/api/workspaces', json={'name': 'TEST_cmt'}).json()['id']
        scan_id = 'scan_abc123'
        r = user.post(f'{BASE_URL}/api/workspaces/{wid}/comments', json={'scan_id': scan_id, 'body': 'hi there'})
        assert r.status_code == 200, r.text
        assert r.json()['body'] == 'hi there'
        r2 = user.get(f'{BASE_URL}/api/workspaces/{wid}/comments/{scan_id}')
        assert r2.status_code == 200
        assert len(r2.json()['comments']) >= 1

    def test_assignments_flow(self, user):
        wid = user.post(f'{BASE_URL}/api/workspaces', json={'name': 'TEST_asg'}).json()['id']
        me = user.get(f'{BASE_URL}/api/auth/me').json()
        uid = me['user']['id'] if 'user' in me else me['id']
        r = user.post(f'{BASE_URL}/api/workspaces/{wid}/assign', json={'scan_id': 's1', 'assignee_id': uid, 'note': 'go'})
        assert r.status_code == 200, r.text
        r2 = user.get(f'{BASE_URL}/api/workspaces/{wid}/assignments')
        assert r2.status_code == 200
        rows = r2.json()['assignments']
        assert any(a['scan_id'] == 's1' for a in rows)

    def test_viewer_cannot_invite_or_delete(self, user, user2):
        # user owns ws, invites user2 as viewer
        wid = user.post(f'{BASE_URL}/api/workspaces', json={'name': 'TEST_perm'}).json()['id']
        user.post(f'{BASE_URL}/api/workspaces/{wid}/invite', json={'email': user2.email, 'role': 'viewer'})
        r = user2.post(f'{BASE_URL}/api/workspaces/{wid}/invite', json={'email': _fresh_email(), 'role': 'analyst'})
        assert r.status_code == 403
        r2 = user2.delete(f'{BASE_URL}/api/workspaces/{wid}')
        assert r2.status_code == 403


# ----------------------- REGRESSION -----------------------
class TestRegression:
    @pytest.mark.parametrize('path', [
        '/api/vuln/info',
        '/api/stats',
        '/api/vuln/weaponry/status',
    ])
    def test_get_smoke(self, anon, path):
        r = anon.get(f'{BASE_URL}{path}')
        assert r.status_code in (200, 401), f'{path} → {r.status_code}'

    def test_landing_download_artifact(self, anon):
        r = anon.get(f'{BASE_URL}/cyberscope-v7.8.0.tar.gz', allow_redirects=True)
        assert r.status_code == 200
        r2 = anon.get(f'{BASE_URL}/cyberscope-v7.9.0.tar.gz', allow_redirects=True)
        assert r2.status_code == 200
