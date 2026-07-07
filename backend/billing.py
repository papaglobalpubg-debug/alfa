"""
Stripe billing router — v7.9 Commercial Wave.

Multi-tier subscription + one-time payments (Free / Pro / Enterprise / Lifetime).
Uses inline `price_data` (no pre-created Price IDs required) so the demo works
out-of-the-box with any Stripe test key.

Endpoints
---------
GET  /api/billing/tiers                 → static catalog (safe for anon)
GET  /api/billing/status                → current user's tier / status
POST /api/billing/checkout              → create Stripe Checkout session
POST /api/billing/portal                → open Stripe Customer Portal
POST /api/billing/webhook               → Stripe webhook (signature-verified)
POST /api/billing/downgrade             → cancel active subscription
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import stripe
from fastapi import APIRouter, HTTPException, Request, Header
from pydantic import BaseModel, ConfigDict


# ---------------- Static catalog ----------------
TIERS: Dict[str, Dict[str, Any]] = {
    'free': {
        'id': 'free',
        'name': 'Free Recon',
        'price_cents': 0,
        'interval': None,
        'quota_scans_per_month': 5,
        'quota_targets': 1,
        'downloadable': False,
        'features': [
            '5 vulnerability scans / month',
            '1 monitored target',
            'Core attack modules (XSS, SQLi, SSRF-lite)',
            'Community payload arsenal',
        ],
        'blurb': 'Perfect for solo researchers exploring their own assets.',
    },
    'pro': {
        'id': 'pro',
        'name': 'Pro',
        'price_cents': 900,
        'interval': 'month',
        'quota_scans_per_month': 100,
        'quota_targets': 5,
        'downloadable': False,
        'features': [
            '100 scans / month · 5 targets',
            'All 54 attack modules',
            'Deep crawler v2 (Playwright)',
            'Continuous monitors',
        ],
        'blurb': 'For serious hunters getting started.',
    },
    'pro_plus': {
        'id': 'pro_plus',
        'name': 'Pro+',
        'price_cents': 1900,
        'interval': 'month',
        'quota_scans_per_month': 500,
        'quota_targets': 25,
        'downloadable': False,
        'features': [
            '500 scans / month · 25 targets',
            'Everything in Pro',
            'AI Autopilot + FP Killer (Claude Sonnet 4.6)',
            'CVE live sync + Threat Intel briefs',
            'Priority queue',
        ],
        'blurb': 'Most popular for full-time bug bounty hunters.',
        'popular': True,
    },
    'enterprise': {
        'id': 'enterprise',
        'name': 'Enterprise',
        'price_cents': 4900,
        'interval': 'month',
        'quota_scans_per_month': 5000,
        'quota_targets': 500,
        'downloadable': True,
        'features': [
            'Everything in Pro+',
            'Team workspaces + RBAC + assignments',
            'White-label reports · custom branding',
            'Public API + Python / JS SDK',
            'Compliance mapping (SOC2 · PCI-DSS · HIPAA · ISO27001)',
            'Downloadable self-host tarball',
        ],
        'blurb': 'For MSSPs and internal red teams.',
    },
    'lifetime': {
        'id': 'lifetime',
        'name': 'Lifetime',
        'price_cents': 19900,
        'interval': None,
        'quota_scans_per_month': 5000,
        'quota_targets': 500,
        'downloadable': True,
        'features': [
            'One-time payment · no subscription',
            'All Enterprise features locked in forever',
            'All future killer attack modules included',
            'Downloadable self-host tarball',
            'Founding-member Discord access',
        ],
        'blurb': 'Buy once. Own it forever.',
        'accent': 'amber',
    },
}


class CheckoutRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    tier: str


def _tier_from_price_meta(mode: str, unit_amount: int, interval: Optional[str]) -> str:
    """Map a Stripe line-item back to our internal tier key."""
    if mode == 'payment' and unit_amount == TIERS['lifetime']['price_cents']:
        return 'lifetime'
    if interval == 'month':
        if unit_amount == TIERS['pro']['price_cents']:
            return 'pro'
        if unit_amount == TIERS['pro_plus']['price_cents']:
            return 'pro_plus'
        if unit_amount == TIERS['enterprise']['price_cents']:
            return 'enterprise'
    return 'free'


def make_router(get_db, get_current_user, get_optional_user):
    """Build the FastAPI billing router. Wires callables from server.py."""
    router = APIRouter(prefix='/api/billing', tags=['billing'])

    stripe.api_key = os.environ.get('STRIPE_API_KEY', '')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET', '')

    def _frontend_url(request: Request) -> str:
        override = os.environ.get('FRONTEND_URL', '').strip()
        if override:
            return override.rstrip('/')
        from urllib.parse import urlparse
        # Prefer Referer (browser-visible page URL) over Origin (which can be the
        # internal cluster host in some proxied setups).
        for header in ('referer', 'origin'):
            v = request.headers.get(header, '').strip()
            if v:
                u = urlparse(v)
                if u.scheme and u.netloc:
                    return f'{u.scheme}://{u.netloc}'
        # Last-resort fallback so non-browser callers (curl / tests) still work.
        try:
            base = str(request.base_url).rstrip('/')
            if base:
                return base
        except Exception:
            pass
        return 'https://cyberscope.io'

    @router.get('/tiers')
    async def list_tiers():
        return {'tiers': list(TIERS.values())}

    @router.get('/status')
    async def billing_status(request: Request):
        db = get_db()
        user = await get_optional_user(request, db)
        if not user:
            return {'authenticated': False, 'tier': 'free', 'stripe_status': None}
        billing = await db.billing.find_one({'user_id': user['id']}) or {}
        return {
            'authenticated': True,
            'tier': billing.get('tier') or user.get('tier') or 'free',
            'stripe_status': billing.get('stripe_status'),
            'stripe_customer_id': billing.get('stripe_customer_id'),
            'current_period_end': billing.get('current_period_end'),
            'cancel_at_period_end': billing.get('cancel_at_period_end', False),
        }

    @router.post('/checkout')
    async def create_checkout(payload: CheckoutRequest, request: Request):
        tier_key = payload.tier.lower().strip()
        if tier_key not in TIERS or tier_key == 'free':
            raise HTTPException(400, f'Unknown or non-billable tier: {tier_key}')

        db = get_db()
        user = await get_current_user(request, db)
        tier = TIERS[tier_key]
        frontend = _frontend_url(request)
        is_lifetime = tier['interval'] is None
        mode = 'payment' if is_lifetime else 'subscription'

        # ---- DEMO MODE ----
        # Only active when explicitly requested via BILLING_DEMO_MODE=1.
        # With a real Stripe key we ALWAYS go through Stripe Checkout so nothing
        # is "activated" without an actual payment.
        _demo = os.environ.get('BILLING_DEMO_MODE', '').strip() == '1'
        if _demo:
            now = datetime.now(timezone.utc).isoformat()
            update = {
                'user_id': user['id'],
                'tier': tier_key,
                'stripe_status': 'demo_active' if not is_lifetime else 'demo_lifetime',
                'stripe_customer_id': f'demo_cus_{user["id"][:12]}',
                'updated_at': now,
                'demo_mode': True,
            }
            if is_lifetime:
                update['lifetime_purchased_at'] = now
            await db.billing.update_one({'user_id': user['id']}, {'$set': update}, upsert=True)
            await db.users.update_one({'id': user['id']}, {'$set': {'tier': tier_key}})
            return {
                'url': f'{frontend}/billing?success=1&tier={tier_key}&demo=1',
                'session_id': 'demo_session',
                'demo': True,
            }

        if not stripe.api_key:
            raise HTTPException(500, 'Stripe is not configured (STRIPE_API_KEY missing)')

        # Inline price data — works without pre-created Stripe Products.
        price_data: Dict[str, Any] = {
            'currency': 'usd',
            'unit_amount': tier['price_cents'],
            'product_data': {
                'name': f'CyberScope · {tier["name"]}',
                'description': tier['blurb'],
            },
        }
        if not is_lifetime:
            price_data['recurring'] = {'interval': tier['interval']}

        session_params: Dict[str, Any] = {
            'mode': mode,
            'line_items': [{'price_data': price_data, 'quantity': 1}],
            'success_url': f'{frontend}/billing?success=1&tier={tier_key}',
            'cancel_url': f'{frontend}/pricing?canceled=1',
            'client_reference_id': user['id'],
            'metadata': {'user_id': user['id'], 'tier': tier_key},
        }
        # Attach or create Stripe Customer
        billing = await db.billing.find_one({'user_id': user['id']}) or {}
        if billing.get('stripe_customer_id'):
            session_params['customer'] = billing['stripe_customer_id']
        else:
            session_params['customer_email'] = user.get('email')

        try:
            session = stripe.checkout.Session.create(**session_params)
        except stripe.error.StripeError as e:
            raise HTTPException(400, f'stripe_error: {e.user_message or str(e)}')

        return {'url': session.url, 'session_id': session.id}

    @router.post('/portal')
    async def create_portal(request: Request):
        if not stripe.api_key:
            raise HTTPException(500, 'Stripe is not configured')
        db = get_db()
        user = await get_current_user(request, db)
        billing = await db.billing.find_one({'user_id': user['id']}) or {}
        cust = billing.get('stripe_customer_id')
        if not cust:
            raise HTTPException(400, 'No active billing customer yet — checkout first.')
        frontend = _frontend_url(request)
        try:
            portal = stripe.billing_portal.Session.create(
                customer=cust, return_url=f'{frontend}/billing',
            )
        except stripe.error.StripeError as e:
            raise HTTPException(400, f'stripe_error: {e.user_message or str(e)}')
        return {'url': portal.url}

    @router.post('/downgrade')
    async def downgrade(request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        billing = await db.billing.find_one({'user_id': user['id']}) or {}
        sub_id = billing.get('stripe_subscription_id')
        if not sub_id:
            raise HTTPException(400, 'No active subscription to cancel')
        try:
            sub = stripe.Subscription.modify(sub_id, cancel_at_period_end=True)
        except stripe.error.StripeError as e:
            raise HTTPException(400, f'stripe_error: {e.user_message or str(e)}')
        await db.billing.update_one(
            {'user_id': user['id']},
            {'$set': {'cancel_at_period_end': True, 'updated_at': datetime.now(timezone.utc).isoformat()}},
            upsert=True,
        )
        return {'ok': True, 'cancels_at': sub.current_period_end}

    @router.post('/webhook')
    async def stripe_webhook(request: Request, stripe_signature: str = Header(None, alias='stripe-signature')):
        payload = await request.body()
        event: Dict[str, Any]
        if webhook_secret:
            try:
                event = stripe.Webhook.construct_event(payload, stripe_signature, webhook_secret)
            except (ValueError, stripe.error.SignatureVerificationError):
                raise HTTPException(400, 'Invalid signature')
        else:
            # Dev mode — parse without verification (WARN)
            import json
            try:
                event = json.loads(payload)
            except Exception:
                raise HTTPException(400, 'bad payload')

        db = get_db()
        etype = event.get('type', '')
        obj = event.get('data', {}).get('object', {}) or {}
        now = datetime.now(timezone.utc).isoformat()

        if etype == 'checkout.session.completed':
            user_id = obj.get('client_reference_id') or (obj.get('metadata') or {}).get('user_id')
            tier = (obj.get('metadata') or {}).get('tier') or 'pro'
            mode = obj.get('mode')
            customer = obj.get('customer')
            subscription_id = obj.get('subscription')
            if user_id:
                update: Dict[str, Any] = {
                    'user_id': user_id,
                    'tier': tier,
                    'stripe_customer_id': customer,
                    'stripe_status': 'active' if mode == 'subscription' else 'paid',
                    'updated_at': now,
                }
                if subscription_id:
                    update['stripe_subscription_id'] = subscription_id
                if mode == 'payment':
                    update['lifetime_purchased_at'] = now
                await db.billing.update_one({'user_id': user_id}, {'$set': update}, upsert=True)
                await db.users.update_one({'id': user_id}, {'$set': {'tier': tier}})

        elif etype in ('customer.subscription.updated', 'customer.subscription.created'):
            customer = obj.get('customer')
            status = obj.get('status')
            cape = obj.get('cancel_at_period_end', False)
            cpe = obj.get('current_period_end')
            # infer tier from unit_amount
            tier = 'pro'
            try:
                item = (obj.get('items') or {}).get('data', [None])[0] or {}
                price = item.get('price') or {}
                tier = _tier_from_price_meta('subscription', price.get('unit_amount', 0), (price.get('recurring') or {}).get('interval'))
            except Exception:
                pass
            update = {
                'stripe_status': status,
                'stripe_subscription_id': obj.get('id'),
                'cancel_at_period_end': cape,
                'current_period_end': cpe,
                'updated_at': now,
            }
            if status in ('active', 'trialing'):
                update['tier'] = tier
            elif status in ('canceled', 'incomplete_expired', 'unpaid'):
                update['tier'] = 'free'
            await db.billing.update_one({'stripe_customer_id': customer}, {'$set': update}, upsert=True)
            if update.get('tier'):
                doc = await db.billing.find_one({'stripe_customer_id': customer})
                if doc and doc.get('user_id'):
                    await db.users.update_one({'id': doc['user_id']}, {'$set': {'tier': update['tier']}})

        elif etype == 'customer.subscription.deleted':
            customer = obj.get('customer')
            await db.billing.update_one(
                {'stripe_customer_id': customer},
                {'$set': {'stripe_status': 'canceled', 'tier': 'free', 'updated_at': now}},
            )
            doc = await db.billing.find_one({'stripe_customer_id': customer})
            if doc and doc.get('user_id'):
                await db.users.update_one({'id': doc['user_id']}, {'$set': {'tier': 'free'}})

        return {'received': True, 'type': etype}

    @router.get('/download-allowed')
    async def download_allowed(request: Request):
        """Returns whether the current user is allowed to download the self-host
        tarball. Only Enterprise and Lifetime tiers unlock it."""
        db = get_db()
        user = await get_optional_user(request, db)
        if not user:
            return {'allowed': False, 'reason': 'auth_required', 'tier': 'guest'}
        billing = await db.billing.find_one({'user_id': user['id']}) or {}
        tier = billing.get('tier') or user.get('tier') or 'free'
        info = TIERS.get(tier, {})
        return {
            'allowed': bool(info.get('downloadable')),
            'tier': tier,
            'reason': None if info.get('downloadable') else 'tier_locked',
        }

    return router
