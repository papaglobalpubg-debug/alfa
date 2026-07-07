"""
Public API + API-key auth (v7.9.2)

Enterprise / Lifetime users can generate scoped API keys and use them to
integrate CyberScope with their CI/CD, IDE extensions, or Python/JS SDKs.

Endpoints
---------
GET    /api/pub/keys                    List my API keys (masked)
POST   /api/pub/keys                    Create a new key (name, scopes)
DELETE /api/pub/keys/{id}               Revoke a key

Public (API-key authenticated) endpoints:
GET    /api/pub/v1/info                 Version + tier + rate limit info
POST   /api/pub/v1/scan                 Kick off a vuln scan
GET    /api/pub/v1/scan/{id}            Retrieve status + findings
GET    /api/pub/v1/scan/{id}/triage     Run AI triple-model triage
"""
from __future__ import annotations

import asyncio
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field


ALLOWED_TIERS = ('enterprise', 'lifetime')


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


class CreateKeyRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    name: str = Field(min_length=2, max_length=80)
    scopes: List[str] = Field(default_factory=lambda: ['scan.read', 'scan.write'])


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    target: str
    depth: str = 'medium'
    modules: Optional[List[str]] = None


async def _auth_by_api_key(db, request: Request) -> Dict[str, Any]:
    """Resolve the caller from an X-API-Key header (or `?api_key=` query)."""
    key = request.headers.get('X-API-Key', '').strip()
    if not key:
        key = request.query_params.get('api_key', '').strip()
    if not key:
        raise HTTPException(401, 'api_key_required')
    if not key.startswith('cs_'):
        raise HTTPException(401, 'invalid_key_format')
    doc = await db.api_keys.find_one({'hash': _hash(key), 'revoked': {'$ne': True}})
    if not doc:
        raise HTTPException(401, 'invalid_or_revoked_key')
    user = await db.users.find_one({'id': doc['user_id']})
    if not user:
        raise HTTPException(401, 'orphan_key')
    # Enforce tier
    billing = await db.billing.find_one({'user_id': user['id']}) or {}
    tier = billing.get('tier') or user.get('tier') or 'free'
    if tier not in ALLOWED_TIERS and user.get('role') != 'admin':
        raise HTTPException(403, f'api_requires_enterprise_or_lifetime · your_tier={tier}')
    # Update last_used
    await db.api_keys.update_one({'_id': doc['_id']},
                                  {'$set': {'last_used_at': _now()}, '$inc': {'requests': 1}})
    # Rate limit per API key (sliding window).
    try:
        from public_api_rate import public_api_limiter
        allowed, retry_after = public_api_limiter.check(doc.get('id', key))
        if not allowed:
            raise HTTPException(
                429,
                f'rate_limited · retry_after={retry_after}s'
            )
    except HTTPException:
        raise
    except Exception:
        pass
    return {'user': user, 'key_doc': doc, 'tier': tier}


def make_router(get_db, get_current_user, get_optional_user, create_vuln_scan_fn):
    """Build the public API router. `create_vuln_scan_fn(payload, owner_id)` is
    a callable from server.py that queues a scan and returns its id."""
    router = APIRouter(prefix='/api/pub', tags=['public-api'])

    # ------------- Key management (auth cookie required) -------------

    @router.get('/keys')
    async def list_keys(request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        rows = await db.api_keys.find(
            {'user_id': user['id'], 'revoked': {'$ne': True}},
            {'_id': 0, 'hash': 0}
        ).sort('created_at', -1).to_list(50)
        return {'keys': rows}

    @router.post('/keys')
    async def create_key(payload: CreateKeyRequest, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        billing = await db.billing.find_one({'user_id': user['id']}) or {}
        tier = billing.get('tier') or user.get('tier') or 'free'
        if tier not in ALLOWED_TIERS and user.get('role') != 'admin':
            raise HTTPException(403,
                f'API keys require Enterprise or Lifetime plan (your tier: {tier}). Upgrade at /pricing.')
        raw = 'cs_' + secrets.token_urlsafe(32)
        key_id = secrets.token_hex(8)
        doc = {
            'id':         key_id,
            'user_id':    user['id'],
            'name':       payload.name.strip(),
            'scopes':     payload.scopes or ['scan.read', 'scan.write'],
            'hash':       _hash(raw),
            'preview':    raw[:8] + '…' + raw[-4:],
            'created_at': _now(),
            'requests':   0,
            'revoked':    False,
        }
        await db.api_keys.insert_one(dict(doc))
        doc.pop('hash', None)
        return {**doc, 'key': raw, 'warning': 'Store this secret — it will not be shown again.'}

    @router.delete('/keys/{key_id}')
    async def revoke_key(key_id: str, request: Request):
        db = get_db()
        user = await get_current_user(request, db)
        r = await db.api_keys.update_one(
            {'id': key_id, 'user_id': user['id']},
            {'$set': {'revoked': True, 'revoked_at': _now()}})
        if r.matched_count == 0:
            raise HTTPException(404, 'key_not_found')
        return {'ok': True}

    # ------------- Public v1 (API-key authenticated) -------------

    @router.get('/v1/info')
    async def api_info(request: Request):
        db = get_db()
        ctx = await _auth_by_api_key(db, request)
        return {
            'version': '7.9.2',
            'tier': ctx['tier'],
            'user_email': ctx['user'].get('email'),
            'rate_limit_per_hour': 1000 if ctx['tier'] == 'lifetime' else 500,
            'endpoints': [
                'POST /api/pub/v1/scan',
                'GET  /api/pub/v1/scan/{id}',
                'GET  /api/pub/v1/scan/{id}/triage',
            ],
        }

    @router.post('/v1/scan')
    async def api_create_scan(payload: ScanRequest, request: Request):
        db = get_db()
        ctx = await _auth_by_api_key(db, request)
        scan_id = await create_vuln_scan_fn(
            {'target': payload.target, 'depth': payload.depth, 'modules': payload.modules},
            ctx['user']['id'])
        try:
            from audit import record_event
            await record_event(
                db,
                actor_id=ctx['user']['id'],
                actor_email=ctx['user'].get('email', ''),
                action='api_scan_created',
                target=payload.target,
                ip=request.client.host if request.client else '',
                extra={'scan_id': scan_id, 'depth': payload.depth},
            )
        except Exception:
            pass
        return {'scan_id': scan_id, 'status_url': f'/api/pub/v1/scan/{scan_id}'}

    @router.get('/v1/scan/{scan_id}')
    async def api_get_scan(scan_id: str, request: Request):
        db = get_db()
        ctx = await _auth_by_api_key(db, request)
        scan = await db.vuln_scans.find_one(
            {'id': scan_id, 'owner_id': ctx['user']['id']}, {'_id': 0})
        if not scan:
            raise HTTPException(404, 'scan_not_found')
        return scan

    @router.get('/v1/scan/{scan_id}/triage')
    async def api_triage_scan(scan_id: str, request: Request, max_items: int = 20):
        db = get_db()
        ctx = await _auth_by_api_key(db, request)
        scan = await db.vuln_scans.find_one(
            {'id': scan_id, 'owner_id': ctx['user']['id']}, {'_id': 0})
        if not scan:
            raise HTTPException(404, 'scan_not_found')
        from vuln.ai_prioritizer import triage_findings
        return await triage_findings(scan.get('findings') or [], max_items=max_items)

    return router
