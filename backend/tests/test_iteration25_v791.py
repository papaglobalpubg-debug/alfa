"""Backend tests for CyberScope v7.9.1 (iteration 25).
Focus: 5-tier billing, real Stripe checkout (no auto-demo), gated tarball download.
"""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://language-arabic-38.preview.emergentagent.com').rstrip('/')


@pytest.fixture(scope='module')
def anon_client():
    s = requests.Session()
    s.headers.update({'Content-Type': 'application/json'})
    return s


@pytest.fixture(scope='module')
def fresh_user():
    """Register a fresh user and return an authenticated session."""
    s = requests.Session()
    s.headers.update({
        'Content-Type': 'application/json',
        'Referer': f'{BASE_URL}/pricing',
        'Origin': BASE_URL,
    })
    email = f'TEST_v791_{uuid.uuid4().hex[:10]}@example.com'
    password = 'TestPass!2026'
    r = s.post(f'{BASE_URL}/api/auth/register', json={
        'email': email, 'password': password, 'name': 'T25 User'
    })
    assert r.status_code in (200, 201), f'register failed: {r.status_code} {r.text[:200]}'
    # Some auth impls set cookies on register; ensure login sets them
    r2 = s.post(f'{BASE_URL}/api/auth/login', json={'email': email, 'password': password})
    assert r2.status_code == 200, f'login failed: {r2.status_code} {r2.text[:200]}'
    return {'session': s, 'email': email, 'password': password}


# ---------- /api/billing/tiers ----------
class TestTiers:
    def test_five_tiers_with_correct_prices(self, anon_client):
        r = anon_client.get(f'{BASE_URL}/api/billing/tiers')
        assert r.status_code == 200
        data = r.json()
        tiers = data.get('tiers', [])
        ids = [t['id'] for t in tiers]
        assert ids == ['free', 'pro', 'pro_plus', 'enterprise', 'lifetime'], f'got ids {ids}'
        prices = {t['id']: t['price_cents'] for t in tiers}
        assert prices == {'free': 0, 'pro': 900, 'pro_plus': 1900, 'enterprise': 4900, 'lifetime': 19900}

    def test_downloadable_only_for_enterprise_lifetime(self, anon_client):
        r = anon_client.get(f'{BASE_URL}/api/billing/tiers')
        tiers = {t['id']: t for t in r.json()['tiers']}
        for tid in ('free', 'pro', 'pro_plus'):
            assert tiers[tid]['downloadable'] is False, f'{tid} should not be downloadable'
        for tid in ('enterprise', 'lifetime'):
            assert tiers[tid]['downloadable'] is True, f'{tid} should be downloadable'


# ---------- /api/billing/checkout ----------
class TestCheckout:
    def test_checkout_unauthenticated_returns_401(self, anon_client):
        r = anon_client.post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'pro'})
        assert r.status_code == 401, f'expected 401, got {r.status_code}: {r.text[:200]}'

    def test_checkout_free_tier_returns_400(self, fresh_user):
        r = fresh_user['session'].post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'free'})
        assert r.status_code == 400

    def test_checkout_pro_returns_real_stripe_url(self, fresh_user):
        r = fresh_user['session'].post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'pro'})
        assert r.status_code == 200, f'{r.status_code}: {r.text[:300]}'
        data = r.json()
        assert 'url' in data
        assert data['url'].startswith('https://checkout.stripe.com/'), f'got url: {data["url"]}'
        # NO demo mode
        assert data.get('demo') is not True, 'checkout must not return demo:true with real Stripe key'

    def test_checkout_pro_plus_real_stripe(self, fresh_user):
        r = fresh_user['session'].post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'pro_plus'})
        assert r.status_code == 200, f'{r.status_code}: {r.text[:300]}'
        assert r.json()['url'].startswith('https://checkout.stripe.com/')

    def test_checkout_enterprise_real_stripe(self, fresh_user):
        r = fresh_user['session'].post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'enterprise'})
        assert r.status_code == 200
        assert r.json()['url'].startswith('https://checkout.stripe.com/')

    def test_checkout_lifetime_real_stripe(self, fresh_user):
        r = fresh_user['session'].post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'lifetime'})
        assert r.status_code == 200
        assert r.json()['url'].startswith('https://checkout.stripe.com/')

    def test_checkout_does_not_upgrade_tier(self, fresh_user):
        # Fire a checkout for pro
        fresh_user['session'].post(f'{BASE_URL}/api/billing/checkout', json={'tier': 'pro'})
        # billing/status should still be free
        r = fresh_user['session'].get(f'{BASE_URL}/api/billing/status')
        assert r.status_code == 200
        data = r.json()
        assert data['tier'] == 'free', f'tier changed without payment! Got {data}'


# ---------- /api/billing/download-allowed ----------
class TestDownloadAllowed:
    def test_free_user_download_locked(self, fresh_user):
        r = fresh_user['session'].get(f'{BASE_URL}/api/billing/download-allowed')
        assert r.status_code == 200
        data = r.json()
        assert data['allowed'] is False
        assert data['tier'] == 'free'
        assert data['reason'] == 'tier_locked'


# ---------- /api/downloads/cyberscope.tar.gz ----------
class TestGatedDownload:
    def test_download_no_auth_returns_401(self, anon_client):
        r = anon_client.get(f'{BASE_URL}/api/downloads/cyberscope.tar.gz', allow_redirects=False)
        assert r.status_code == 401, f'{r.status_code}: {r.text[:200]}'

    def test_download_free_user_returns_403(self, fresh_user):
        r = fresh_user['session'].get(f'{BASE_URL}/api/downloads/cyberscope.tar.gz', allow_redirects=False)
        assert r.status_code == 403, f'{r.status_code}: {r.text[:200]}'
        assert 'Enterprise' in r.text or 'tier' in r.text.lower()

    def test_tarball_exists_on_disk(self):
        assert os.path.exists('/app/backend/artifacts/cyberscope-v7.9.0.tar.gz')


# ---------- Regression: vuln weaponry status ----------
class TestVulnRegression:
    def test_vuln_info_still_works(self, anon_client):
        r = anon_client.get(f'{BASE_URL}/api/vuln/info')
        assert r.status_code == 200
        data = r.json()
        assert data.get('available') is True
        # v7.8 baseline preserved (per test statement — 12 attack modules regression is at /api/vuln/weaponry/status; fall back to info)
        assert 'modules' in data
        assert len(data['modules']) >= 12


# ---------- Regression: workspaces ----------
class TestWorkspacesRegression:
    def test_create_and_list_workspace(self, fresh_user):
        s = fresh_user['session']
        r = s.post(f'{BASE_URL}/api/workspaces', json={'name': 'TEST_v791_ws'})
        assert r.status_code in (200, 201), f'{r.status_code}: {r.text[:200]}'
        wid = r.json().get('id') or r.json().get('workspace', {}).get('id')
        assert wid, f'no id in response: {r.json()}'
        r2 = s.get(f'{BASE_URL}/api/workspaces')
        assert r2.status_code == 200
        names = [w.get('name') for w in r2.json().get('workspaces', [])]
        assert 'TEST_v791_ws' in names
